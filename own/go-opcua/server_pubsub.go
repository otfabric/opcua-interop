// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/pubsub/security"
	"github.com/otfabric/go-opcua/pubsub/sks"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// pubsubFile is the file of --pubsub-config (§14.1).
type pubsubFile struct {
	Configuration  json.RawMessage `json:"configuration"`
	SecurityGroups []pubsubGroup   `json:"securityGroups"`
	ServeSKS       bool            `json:"serveSks"`
	SKSClient      *pubsubSKS      `json:"sksClient"`
	DeltaFrames    bool            `json:"deltaFrames"`
	MQTT           *pubsubMQTT     `json:"mqtt"`
}

type pubsubGroup struct {
	ID         string      `json:"securityGroupId"`
	PolicyURI  string      `json:"securityPolicyUri"`
	LifetimeMS *float64    `json:"keyLifetimeMs"`
	MaxFuture  *uint32     `json:"maxFutureKeyCount"`
	MaxPast    *uint32     `json:"maxPastKeyCount"`
	Keys       []pubsubKey `json:"keys"`
}

type pubsubKey struct {
	TokenID uint32 `json:"tokenId"`
	Key     []byte `json:"key"`
}

type pubsubSKS struct {
	EndpointURL string `json:"endpointUrl"`
	PolicyURI   string `json:"securityPolicyUri"`
	Mode        string `json:"securityMode"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

type pubsubMQTT struct {
	ProtocolVersion string `json:"protocolVersion"`
}

func loadPubSubFile(path string) (*pubsubFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	file := &pubsubFile{}
	if err := d.Decode(file); err != nil {
		return nil, err
	}
	if len(file.Configuration) == 0 {
		return nil, errors.New("no configuration")
	}
	if file.MQTT != nil {
		switch file.MQTT.ProtocolVersion {
		case "3.1.1", "5.0":
		default:
			return nil, fmt.Errorf("mqtt.protocolVersion %q: go-opcua has 3.1.1 and 5.0", file.MQTT.ProtocolVersion)
		}
	}
	return file, nil
}

// pubsubOptions are the options of the runtime. An Error state and the recovery from
// it are logged: go-opcua retries a failed component itself (§14.10 has the adapter
// do so for open62541).
func pubsubOptions() []pubsub.Option {
	inError := map[pubsub.ComponentID]bool{}
	return []pubsub.Option{
		pubsub.WithEventHandler(func(ev pubsub.Event) {
			if ev.Type != pubsub.EventStateChanged {
				return
			}
			name, state := ev.Component.Name, ev.Component.State
			switch {
			case state == ua.PubSubStateError:
				inError[ev.Component.ID] = true
				fmt.Fprintf(os.Stderr, "pubsub: %s is in Error: %v\n", name, ev.Err)
			case inError[ev.Component.ID] && state == ua.PubSubStateOperational:
				delete(inError, ev.Component.ID)
				fmt.Fprintf(os.Stderr, "pubsub: %s re-enabled (Operational)\n", name)
			}
		}),
		pubsub.WithDiscovery(pubsub.DiscoveryOptions{MinInterval: 500 * time.Millisecond}),
	}
}

// resolveNamespaces replaces "nsu=<uri>;" by "ns=<index>;" in every string of a JSON
// value: go-opcua's PubSub configuration holds NodeIds, not ExpandedNodeIds, and the
// index of the fixture's namespace is only known once it exists.
func resolveNamespaces(v any, index map[string]uint16) (any, error) {
	switch t := v.(type) {
	case string:
		if !strings.HasPrefix(t, "nsu=") {
			return t, nil
		}
		uri, rest, ok := strings.Cut(strings.TrimPrefix(t, "nsu="), ";")
		if !ok {
			return nil, fmt.Errorf("%s: malformed", t)
		}
		ns, known := index[uri]
		if !known {
			return nil, fmt.Errorf("%s: unknown namespace", t)
		}
		return fmt.Sprintf("ns=%d;%s", ns, rest), nil
	case []any:
		for i := range t {
			next, err := resolveNamespaces(t[i], index)
			if err != nil {
				return nil, err
			}
			t[i] = next
		}
	case map[string]any:
		for k := range t {
			next, err := resolveNamespaces(t[k], index)
			if err != nil {
				return nil, err
			}
			t[k] = next
		}
	}
	return v, nil
}

// parsePubSubConfiguration decodes `configuration` (§14.2).
func parsePubSubConfiguration(raw []byte, index map[string]uint16) (*ua.PubSubConfigurationDataType, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	resolved, err := resolveNamespaces(v, index)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(resolved)
	if err != nil {
		return nil, err
	}
	cfg := &ua.PubSubConfigurationDataType{}
	if err := ua.DecodeJSON(b, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// moveUnicastAddress gives a connection the destination its writer group names. The
// contract's unicast publisher has it in DatagramWriterGroupTransport2DataType
// (§14.4). go-opcua refuses an Address there (pubsub/config.go:669): a connection is
// one destination. Two destinations on a connection, or a connection that also
// receives on another address, are refused rather than dropped.
func moveUnicastAddress(conn *ua.PubSubConnectionDataType) error {
	var destination *ua.NetworkAddressURLDataType
	for _, wg := range conn.WriterGroups {
		if wg.TransportSettings == nil {
			continue
		}
		ts, ok := wg.TransportSettings.Value.(*ua.DatagramWriterGroupTransport2DataType)
		if !ok || ts.Address == nil || ts.Address.Value == nil {
			continue
		}
		addr, ok := ts.Address.Value.(*ua.NetworkAddressURLDataType)
		if !ok {
			return fmt.Errorf("connection %q: writer group %q: address of type %T", conn.Name, wg.Name, ts.Address.Value)
		}
		if destination != nil && destination.URL != addr.URL {
			return fmt.Errorf("connection %q: two unicast destinations: go-opcua has one per connection", conn.Name)
		}
		destination = addr
		wg.TransportSettings = nil
	}
	if destination == nil {
		return nil
	}
	if len(conn.ReaderGroups) > 0 {
		return fmt.Errorf("connection %q: a unicast destination on a connection with readers: go-opcua has one address per connection", conn.Name)
	}
	conn.Address = ua.NewExtensionObject(destination)
	return nil
}

// keyFramesOnly makes every writer send KeyFrames, unless deltaFrames asks for delta
// frames (§14.1, false by default).
func keyFramesOnly(conn *ua.PubSubConnectionDataType) {
	for _, wg := range conn.WriterGroups {
		for _, w := range wg.DataSetWriters {
			w.KeyFrameCount = 1
		}
	}
}

// applyMQTTVersion selects the MQTT version of every broker connection (§14.1).
func applyMQTTVersion(conn *ua.PubSubConnectionDataType, version string) {
	if strings.Contains(conn.TransportProfileURI, "-mqtt-") {
		pubsub.SetMQTTVersion(conn, version)
	}
}

// configurePubSub builds the runtime from the file, before the server starts: the
// methods of the SKS must be there at Start, and the information model is built then.
// Keys pulled from a remote SKS arrive later (startSKSClient).
func configurePubSub(s *server.Server, a *addressSpace, file *pubsubFile) error {
	rt := s.PubSub()
	if rt == nil {
		return errors.New("no runtime")
	}
	cfg, err := parsePubSubConfiguration(file.Configuration, map[string]uint16{a.uri: a.ns.ID(), "http://opcfoundation.org/UA/": 0})
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if err := configureKeys(s, rt, file); err != nil {
		return err
	}
	known := map[string]bool{}
	for _, g := range file.SecurityGroups {
		known[g.ID] = true
	}
	for _, ds := range cfg.PublishedDataSets {
		if _, err := rt.AddPublishedDataSet(ds); err != nil {
			return err
		}
	}
	for _, conn := range cfg.Connections {
		if err := moveUnicastAddress(conn); err != nil {
			return err
		}
		if !file.DeltaFrames {
			keyFramesOnly(conn)
		}
		if file.MQTT != nil {
			applyMQTTVersion(conn, file.MQTT.ProtocolVersion)
		}
		if err := checkGroups(conn, known); err != nil {
			return err
		}
		if _, err := rt.AddConnection(conn); err != nil {
			return err
		}
	}
	return nil
}

// checkGroups refuses a SecurityGroupId the file does not list (§14.1).
func checkGroups(conn *ua.PubSubConnectionDataType, known map[string]bool) error {
	check := func(group, id string) error {
		if id != "" && !known[id] {
			return fmt.Errorf("group %q: SecurityGroupId %q is not in securityGroups", group, id)
		}
		return nil
	}
	for _, g := range conn.WriterGroups {
		if err := check(g.Name, g.SecurityGroupID); err != nil {
			return err
		}
	}
	for _, g := range conn.ReaderGroups {
		if err := check(g.Name, g.SecurityGroupID); err != nil {
			return err
		}
	}
	return nil
}

const defaultPubSubPolicy = "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR"

// configureKeys sets the source of the keys of every group (§14.5): static, this
// server's SKS, or a ring for SetSecurityKeys. Groups a remote SKS serves get their
// keys in startSKSClient.
func configureKeys(s *server.Server, rt *pubsub.PubSub, file *pubsubFile) error {
	var service *security.KeyService
	var rings *security.KeyRings
	for i := range file.SecurityGroups {
		g := &file.SecurityGroups[i]
		if g.ID == "" {
			return errors.New("a security group without securityGroupId")
		}
		if g.PolicyURI == "" {
			g.PolicyURI = defaultPubSubPolicy
		}
		policy, err := security.PolicyByURI(g.PolicyURI)
		if err != nil {
			return fmt.Errorf("security group %q: %w", g.ID, err)
		}
		switch {
		case len(g.Keys) > 0:
			ring := security.NewKeyRing(g.ID, policy)
			if err := ring.SetKeys(g.PolicyURI, g.Keys[0].TokenID, [][]byte{g.Keys[0].Key}, 0, 0); err != nil {
				return fmt.Errorf("security group %q: %w", g.ID, err)
			}
			rt.SetKeySource(g.ID, ring)
		case file.ServeSKS:
			if service == nil {
				service = security.NewKeyService()
			}
			if err := service.AddSecurityGroup(g.config()); err != nil {
				return fmt.Errorf("security group %q: %w", g.ID, err)
			}
			ks, err := service.KeySource(g.ID)
			if err != nil {
				return fmt.Errorf("security group %q: %w", g.ID, err)
			}
			rt.SetKeySource(g.ID, ks)
		case file.SKSClient != nil:
		default:
			if rings == nil {
				rings = &security.KeyRings{}
			}
			ring := security.NewKeyRing(g.ID, policy)
			rings.Add(ring)
			rt.SetKeySource(g.ID, ring)
		}
	}
	if service != nil {
		if _, err := s.EnableSecurityKeyService(service); err != nil {
			return err
		}
	}
	if rings != nil {
		// §14.6 asks for an encrypted session, not for a user: go-opcua's default is
		// stricter and refuses an anonymous caller.
		anyCaller := func(context.Context, *security.Caller, security.Operation, string) error { return nil }
		return s.EnableSecurityKeyPush(rings, server.SKSAuthorizer(anyCaller))
	}
	return nil
}

func (g *pubsubGroup) config() security.SecurityGroupConfig {
	cfg := security.SecurityGroupConfig{SecurityGroupID: g.ID, SecurityPolicyURI: g.PolicyURI, KeyLifetime: time.Minute, MaxFutureKeyCount: 2, MaxPastKeyCount: 1}
	if g.LifetimeMS != nil {
		cfg.KeyLifetime = time.Duration(*g.LifetimeMS * float64(time.Millisecond))
	}
	if g.MaxFuture != nil {
		cfg.MaxFutureKeyCount = *g.MaxFuture
	}
	if g.MaxPast != nil {
		cfg.MaxPastKeyCount = *g.MaxPast
	}
	return cfg
}

// startSKSClient pulls the keys of the groups without keys from the remote SKS. The
// SKS may start later: the first GetSecurityKeys is retried every 2 s (§14.1).
func startSKSClient(ctx context.Context, rt *pubsub.PubSub, f *serverFlags, file *pubsubFile) error {
	if file.SKSClient == nil || file.ServeSKS {
		return nil
	}
	dial, err := sksDialer(f, file.SKSClient)
	if err != nil {
		return err
	}
	for _, g := range file.SecurityGroups {
		if len(g.Keys) > 0 {
			continue
		}
		go func() {
			for ctx.Err() == nil {
				source, err := sks.NewKeySource(ctx, sks.Config{SecurityGroupID: g.ID, Dial: dial})
				if err == nil {
					rt.SetKeySource(g.ID, source)
					fmt.Fprintln(os.Stderr, "pubsub: keys of", g.ID, "pulled from", file.SKSClient.EndpointURL)
					return
				}
				fmt.Fprintf(os.Stderr, "pubsub: GetSecurityKeys of %s: %v\n", g.ID, err)
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			}
		}()
	}
	return nil
}

// sksDialer opens a session with the SKS: the application identity is the server's,
// trust is <pki-dir>/trusted/certs (§14.1).
func sksDialer(f *serverFlags, c *pubsubSKS) (func(context.Context) (*opcua.Client, error), error) {
	if f.certificate == "" || f.privateKey == "" {
		return nil, errors.New("sksClient needs --certificate and --private-key")
	}
	cert, err := readDER(f.certificate)
	if err != nil {
		return nil, err
	}
	key, err := readKey(f.privateKey)
	if err != nil {
		return nil, err
	}
	trustedDER, err := trustedCertificates(f.pkiDir)
	if err != nil {
		return nil, err
	}
	trusted := make([]*x509.Certificate, 0, len(trustedDER))
	for _, der := range trustedDER {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, parsed)
	}
	policy := "Basic256Sha256"
	if c.PolicyURI != "" {
		policy = c.PolicyURI
	}
	policy = ua.FormatSecurityPolicyURI(policy)
	mode := ua.MessageSecurityModeSignAndEncrypt
	if c.Mode != "" {
		mode = ua.MessageSecurityModeFromString(c.Mode)
	}
	return func(ctx context.Context) (*opcua.Client, error) {
		endpoints, err := opcua.GetEndpoints(ctx, c.EndpointURL)
		if err != nil {
			return nil, err
		}
		var chosen *ua.EndpointDescription
		for _, ep := range endpoints {
			if ep.SecurityPolicyURI == policy && ep.SecurityMode == mode {
				chosen = ep
				break
			}
		}
		if chosen == nil {
			return nil, fmt.Errorf("%s: no endpoint %s %s", c.EndpointURL, policy, mode)
		}
		opts := []opcua.Option{opcua.Certificate(cert), opcua.PrivateKeySigner(key), opcua.TrustedCertificates(trusted...), opcua.AutoReconnect(false)}
		if c.Username != "" {
			opts = append(opts, opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeUserName), opcua.AuthUsername(c.Username, c.Password))
		} else {
			opts = append(opts, opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous())
		}
		client, err := opcua.NewClient(c.EndpointURL, opts...)
		if err != nil {
			return nil, err
		}
		if err := client.Connect(ctx); err != nil {
			return nil, err
		}
		return client, nil
	}, nil
}
