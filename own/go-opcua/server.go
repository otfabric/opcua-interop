// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// fixture is the part of fixtures/schema/opcua-fixture.schema.json this adapter
// realises.
type fixture struct {
	ID     string `json:"id"`
	Server struct {
		ApplicationURI  string `json:"applicationUri"`
		ProductURI      string `json:"productUri"`
		ApplicationName string `json:"applicationName"`
	} `json:"server"`
	Endpoint struct {
		Path string `json:"path"`
		Port int    `json:"port"`
	} `json:"endpoint"`
	Namespaces []struct {
		URI string `json:"uri"`
	} `json:"namespaces"`
	Nodes     []fixtureNode `json:"nodes"`
	Behaviors []struct {
		Target    string      `json:"target"`
		Kind      string      `json:"kind"`
		Initial   json.Number `json:"initial"`
		Increment float64     `json:"increment"`
		Minimum   float64     `json:"minimum"`
		Maximum   float64     `json:"maximum"`
		Interval  int64       `json:"intervalMs"`
	} `json:"behaviors"`
	Users []struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"users"`
	SecurityProfiles []struct {
		Policy string `json:"securityPolicy"`
		Mode   string `json:"securityMode"`
	} `json:"securityProfiles"`
}

type fixtureNode struct {
	NodeClass       string       `json:"nodeClass"`
	NodeID          string       `json:"nodeId"`
	BrowseName      string       `json:"browseName"`
	DisplayName     string       `json:"displayName"`
	Description     string       `json:"description"`
	ParentNodeID    string       `json:"parentNodeId"`
	ReferenceType   string       `json:"referenceType"`
	TypeDefinition  string       `json:"typeDefinition"`
	DataType        string       `json:"dataType"`
	ValueRank       int32        `json:"valueRank"`
	ArrayDimensions []int        `json:"arrayDimensions"`
	AccessLevel     []string     `json:"accessLevel"`
	InitialValue    any          `json:"initialValue"`
	MethodBehavior  string       `json:"methodBehavior"`
	InputArguments  []fixtureArg `json:"inputArguments"`
	OutputArguments []fixtureArg `json:"outputArguments"`
	EURange         *ua.Range    `json:"euRange"`
}

type fixtureArg struct {
	Name        string `json:"name"`
	DataType    string `json:"dataType"`
	ValueRank   int32  `json:"valueRank"`
	Description string `json:"description"`
}

func loadFixture(path string) (*fixture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.UseNumber() // 64-bit integers keep their digits.
	var fx fixture
	if err := dec.Decode(&fx); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(fx.Namespaces) == 0 {
		return nil, fmt.Errorf("%s: no namespace", path)
	}
	return &fx, nil
}

// initialValue converts a fixture value to a Go value of the node's type.
func initialValue(n *fixtureNode) (any, error) {
	if arr, ok := n.InitialValue.([]any); ok {
		items := make([]string, len(arr))
		for i, item := range arr {
			items[i] = fmt.Sprint(item)
		}
		if len(n.ArrayDimensions) == 2 {
			return matrix(n.DataType, items, n.ArrayDimensions)
		}
		return parseArray(n.DataType, items)
	}
	return parseLiteral(n.DataType, fmt.Sprint(n.InitialValue))
}

// matrix is a two-dimensional array in row-major order, which is how the fixture
// and go-opcua lay it out. The fixture has Double matrices only.
func matrix(dataType string, items []string, dims []int) (any, error) {
	if dataType != "Double" || dims[0]*dims[1] != len(items) {
		return nil, fmt.Errorf("matrix of %d %s, dimensions %v", len(items), dataType, dims)
	}
	out := make([][]float64, dims[0])
	for r := range out {
		out[r] = make([]float64, dims[1])
		for c := range out[r] {
			v, err := parseLiteral("Double", items[r*dims[1]+c])
			if err != nil {
				return nil, err
			}
			out[r][c] = v.(float64)
		}
	}
	return out, nil
}

// addressSpace builds the fixture's nodes. Everything in the fixture exists, but
// only what print-capabilities declares has behaviour: Events.Source, for example,
// is an object that emits nothing.
type addressSpace struct {
	s   *server.Server
	ns  *server.NodeNameSpace
	uri string
	// values are the current values of the nodes with a behaviour.
	mu     sync.Mutex
	values map[string]*ua.DataValue
}

// nodeID resolves a fixture NodeId: nsu= of the model namespace, or namespace 0.
func (a *addressSpace) nodeID(s string) (*ua.NodeID, error) {
	if rest, ok := strings.CutPrefix(s, "nsu="+a.uri+";"); ok {
		return ua.ParseNodeID(fmt.Sprintf("ns=%d;%s", a.ns.ID(), rest))
	}
	return ua.ParseNodeID(s)
}

func (a *addressSpace) build(fx *fixture) error {
	for i := range fx.Nodes {
		if err := a.addNode(fx, &fx.Nodes[i]); err != nil {
			return fmt.Errorf("node %s: %w", fx.Nodes[i].NodeID, err)
		}
	}
	return nil
}

func (a *addressSpace) addNode(fx *fixture, n *fixtureNode) error {
	nodeID, err := a.nodeID(n.NodeID)
	if err != nil {
		return err
	}
	_, name, ok := strings.Cut(n.BrowseName, ":")
	if !ok {
		name = n.BrowseName
	}

	var node *server.Node
	switch n.NodeClass {
	case "Object":
		node = server.NewFolderNode(nodeID, name)
	case "Method":
		node = server.NewFolderNode(nodeID, name)
		node.SetNodeClass(ua.NodeClassMethod)
		_ = node.SetAttribute(ua.AttributeIDExecutable, server.DataValueFromValue(true))
		_ = node.SetAttribute(ua.AttributeIDUserExecutable, server.DataValueFromValue(true))
	case "Variable":
		if node, err = a.newVariable(fx, nodeID, name, n); err != nil {
			return err
		}
	default:
		return errors.New("unknown node class " + n.NodeClass)
	}
	if n.DisplayName != "" {
		node.SetDisplayName(n.DisplayName, "en")
	}
	node.SetDescription(n.Description, "en")
	a.ns.AddNode(node)

	parentID, err := a.nodeID(n.ParentNodeID)
	if err != nil {
		return err
	}
	parent := a.s.Node(parentID)
	if parent == nil {
		return errors.New("no parent node " + n.ParentNodeID)
	}
	var refType server.RefType = server.RefTypeIDOrganizes
	if n.ReferenceType == "HasComponent" {
		refType = server.RefTypeIDHasComponent
	}
	parent.AddRef(node, refType, true)
	if n.TypeDefinition != "" {
		typeID, err := a.nodeID(n.TypeDefinition)
		if err != nil {
			return err
		}
		if typ := a.s.Node(typeID); typ != nil {
			node.AddRef(typ, id.HasTypeDefinition, true)
		}
	}
	if n.EURange != nil {
		a.addEURange(node, n.EURange)
	}
	if n.NodeClass == "Method" {
		a.addMethod(parentID, nodeID, node, n)
	}
	return nil
}

func (a *addressSpace) newVariable(fx *fixture, nodeID *ua.NodeID, name string, n *fixtureNode) (*server.Node, error) {
	var value any
	var err error
	key := nodeID.StringID()
	switch {
	case key == "Diagnostics.AdapterName":
		value = adapterName
	case key == "Diagnostics.StackVersion":
		value = upstreamVersion
	case key == "Diagnostics.FixtureId":
		value = fx.ID
	case key == "DataValues.GoodWithTimestamps":
		v, parseErr := initialValue(n)
		if parseErr != nil {
			return nil, parseErr
		}
		value = func() *ua.DataValue {
			now := time.Now()
			return &ua.DataValue{
				EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
				Value:        ua.MustVariant(v), SourceTimestamp: now, ServerTimestamp: now,
			}
		}
	default:
		if value, err = initialValue(n); err != nil {
			return nil, err
		}
	}
	if a.hasBehavior(fx, n.NodeID) {
		initial := server.DataValueFromValue(value)
		a.setValue(key, initial)
		value = func() *ua.DataValue { return a.value(key) }
	}
	node := server.NewVariableNode(nodeID, name, value)
	set := func(attr ua.AttributeID, v any) error { return node.SetAttribute(attr, server.DataValueFromValue(v)) }
	var access byte
	for _, level := range n.AccessLevel {
		switch level {
		case "CurrentRead":
			access |= byte(ua.AccessLevelTypeCurrentRead)
		case "CurrentWrite":
			access |= byte(ua.AccessLevelTypeCurrentWrite)
		}
	}
	dataType, ok := builtInTypes[n.DataType]
	if !ok {
		return nil, errors.New("unknown data type " + n.DataType)
	}
	for attr, v := range map[ua.AttributeID]any{
		ua.AttributeIDAccessLevel:     access,
		ua.AttributeIDUserAccessLevel: access,
		ua.AttributeIDValueRank:       n.ValueRank,
		ua.AttributeIDDataType:        ua.NewNumericExpandedNodeID(0, dataType),
	} {
		if err := set(attr, v); err != nil {
			return nil, err
		}
	}
	return node, nil
}

func (a *addressSpace) hasBehavior(fx *fixture, target string) bool {
	for _, b := range fx.Behaviors {
		if b.Target == target {
			return true
		}
	}
	return false
}

func (a *addressSpace) setValue(key string, dv *ua.DataValue) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.values[key] = dv
}

func (a *addressSpace) value(key string) *ua.DataValue {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.values[key]
}

// addEURange is the EURange property of an analog item: what makes the server
// accept a percent deadband (Part 8 §5.3.2.3, §7.2).
func (a *addressSpace) addEURange(node *server.Node, r *ua.Range) {
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(ua.NewExtensionObject(r))}
	prop := server.NewNode(
		ua.NewStringNodeID(a.ns.ID(), node.ID().StringID()+".EURange"),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:   server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName:  server.DataValueFromValue(attrs.BrowseName("EURange")),
			ua.AttributeIDDisplayName: server.DataValueFromValue(attrs.DisplayName("EURange", "en")),
			ua.AttributeIDDataType:    server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Range)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
	a.ns.AddNode(prop)
	node.AddRef(prop, id.HasProperty, true)
}

// addMethod registers the handler of a fixture method, and its argument properties.
func (a *addressSpace) addMethod(object, method *ua.NodeID, node *server.Node, n *fixtureNode) {
	a.addArguments(node, "InputArguments", n.InputArguments)
	a.addArguments(node, "OutputArguments", n.OutputArguments)
	a.s.RegisterMethod(object, method, methodHandler(n.MethodBehavior, len(n.InputArguments)))
}

func (a *addressSpace) addArguments(method *server.Node, prop string, args []fixtureArg) {
	if len(args) == 0 {
		return
	}
	objects := make([]*ua.ExtensionObject, len(args))
	for i, arg := range args {
		objects[i] = ua.NewExtensionObject(&ua.Argument{
			Name: arg.Name, DataType: ua.NewNumericNodeID(0, builtInTypes[arg.DataType]), ValueRank: arg.ValueRank,
			Description: ua.NewLocalizedTextWithLocale(arg.Description, "en"),
		})
	}
	value := &ua.DataValue{EncodingMask: ua.DataValueValue, Value: ua.MustVariant(objects)}
	node := server.NewNode(
		ua.NewStringNodeID(a.ns.ID(), method.ID().StringID()+"."+prop),
		map[ua.AttributeID]*ua.DataValue{
			ua.AttributeIDNodeClass:  server.DataValueFromValue(uint32(ua.NodeClassVariable)),
			ua.AttributeIDBrowseName: server.DataValueFromValue(attrs.BrowseName(prop)),
			ua.AttributeIDDataType:   server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Argument)),
		},
		nil,
		func() *ua.DataValue { return value },
	)
	a.ns.AddNode(node)
	method.AddRef(node, id.HasProperty, true)
}

// methodHandler is the method of docs/FIXTURES.md "Methods".
func methodHandler(behavior string, inputs int) server.MethodHandler {
	return func(_ context.Context, _, _ *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		if len(args) != inputs {
			return nil, ua.StatusBadArgumentsMissing
		}
		switch behavior {
		case "Add":
			a, okA := args[0].Value().(int32)
			b, okB := args[1].Value().(int32)
			if okA && okB {
				return []*ua.Variant{ua.MustVariant(a + b)}, ua.StatusOK
			}
		case "Multiply":
			a, okA := args[0].Value().(float64)
			b, okB := args[1].Value().(float64)
			if okA && okB {
				return []*ua.Variant{ua.MustVariant(a * b)}, ua.StatusOK
			}
		case "Echo":
			if s, ok := args[0].Value().(string); ok {
				return []*ua.Variant{ua.MustVariant(s)}, ua.StatusOK
			}
		case "NoArguments":
			return []*ua.Variant{ua.MustVariant(true)}, ua.StatusOK
		case "MultipleOutputs":
			if v, ok := args[0].Value().(int32); ok {
				return []*ua.Variant{ua.MustVariant(v * 2), ua.MustVariant(fmt.Sprint(v))}, ua.StatusOK
			}
		case "Fail":
			return nil, ua.StatusBadInternalError
		}
		return nil, ua.StatusBadInvalidArgument
	}
}

// startBehaviors runs the value generators of the fixture until ctx ends.
func (a *addressSpace) startBehaviors(ctx context.Context, fx *fixture) error {
	for _, b := range fx.Behaviors {
		nodeID, err := a.nodeID(b.Target)
		if err != nil {
			return err
		}
		key := nodeID.StringID()
		current := a.value(key)
		if current == nil {
			return errors.New("behavior of a node that is not a variable: " + b.Target)
		}
		switch b.Kind {
		case "fixed-status":
			status, err := b.Initial.Int64()
			if err != nil {
				return err
			}
			a.setValue(key, &ua.DataValue{EncodingMask: ua.DataValueValue | ua.DataValueStatusCode, Value: current.Value, Status: ua.StatusCode(status)})
			continue
		case "counter", "toggle", "ramp":
		default:
			return errors.New("unknown behavior " + b.Kind)
		}
		value := current.Value.Value()
		var step func() any
		switch b.Kind {
		case "counter":
			step = func() any { value = value.(int64) + int64(b.Increment); return value }
		case "toggle":
			step = func() any { value = !value.(bool); return value }
		case "ramp":
			step = func() any {
				next := value.(float64) + b.Increment
				if next > b.Maximum {
					next = b.Minimum
				}
				value = next
				return value
			}
		}
		go func() {
			ticker := time.NewTicker(time.Duration(b.Interval) * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now := time.Now()
					a.setValue(key, &ua.DataValue{
						EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp | ua.DataValueServerTimestamp,
						Value:        ua.MustVariant(step()), SourceTimestamp: now, ServerTimestamp: now,
					})
					a.s.ChangeNotification(nodeID)
				}
			}
		}()
	}
	return nil
}

// serverFlags are the flags of §11 this adapter has. Any other, such as
// --pubsub-config or --lds, is refused with exit 2.
type serverFlags struct {
	fixture, bindAddress, advertisedHost, endpointPath string
	readyFile, pkiDir, certificate, privateKey, eccDir string
	bindPort, advertisedPort                           int
}

func parseServerFlags(args []string) (*serverFlags, map[string]bool, error) {
	f := &serverFlags{}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&f.fixture, "fixture", "", "fixture file")
	fs.StringVar(&f.bindAddress, "bind-address", "0.0.0.0", "bind address")
	fs.IntVar(&f.bindPort, "bind-port", 0, "bind port (default: from the fixture)")
	fs.StringVar(&f.advertisedHost, "advertised-host", "localhost", "host name in endpoint URLs")
	fs.IntVar(&f.advertisedPort, "advertised-port", 0, "port in endpoint URLs (default: the bind port)")
	fs.StringVar(&f.endpointPath, "endpoint-path", "", "URL path (default: from the fixture)")
	fs.StringVar(&f.readyFile, "ready-file", "/run/opcua-interop/ready", "readiness file")
	fs.StringVar(&f.pkiDir, "pki-dir", "/run/opcua-interop/pki", "PKI directory")
	fs.StringVar(&f.certificate, "certificate", "", "server certificate")
	fs.StringVar(&f.privateKey, "private-key", "", "server private key")
	fs.StringVar(&f.eccDir, "ecc-dir", "", "accepted and ignored: no ECC policies in this adapter")
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if f.fixture == "" {
		return nil, nil, errors.New("--fixture is required")
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	return f, set, nil
}

func runServer(args []string) int {
	f, set, err := parseServerFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return exitInput
	}
	fx, err := loadFixture(f.fixture)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		return exitFixture
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	s, cleanup, code := startServer(ctx, f, fx)
	if code != exitOK {
		return code
	}
	defer cleanup()

	port := f.advertisedPort
	if port == 0 {
		port = s.Port()
	}
	path := f.endpointPath
	if path == "" {
		path = fx.Endpoint.Path
	}
	ready := map[string]any{"ready": true, "adapter": adapterName, "fixture": fx.ID, "endpoint": fmt.Sprintf("opc.tcp://%s:%d%s", f.advertisedHost, port, path)}
	_ = os.Remove(f.readyFile)
	if err := writeReady(f.readyFile, ready); err != nil {
		fmt.Fprintln(os.Stderr, "ready file:", err)
		if set["ready-file"] {
			return exitInternal
		}
	} else {
		defer func() { _ = os.Remove(f.readyFile) }()
	}
	fmt.Fprintln(os.Stderr, "serving", ready["endpoint"], "with go-opcua", upstreamVersion)
	<-ctx.Done()
	return exitOK
}

// startServer builds and starts the server; the cleanup stops it.
func startServer(ctx context.Context, f *serverFlags, fx *fixture) (*server.Server, func(), int) {
	bindPort := f.bindPort
	if bindPort == 0 {
		bindPort = fx.Endpoint.Port
	}
	advertisedPort := f.advertisedPort
	if advertisedPort == 0 {
		advertisedPort = bindPort
	}
	opts := []server.Option{
		server.ListenOn(fmt.Sprintf("%s:%d", f.bindAddress, bindPort)),
		server.EndPoint(f.advertisedHost, advertisedPort),
		server.InsecureNoSecurity(),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.EnableAuthMode(ua.UserTokenTypeUserName),
		server.AllowUsernameOnNone(),
		server.WithUsernameValidator(func(username, password string) error {
			for _, u := range fx.Users {
				if u.Username == username && subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) == 1 {
					return nil
				}
			}
			return ua.StatusBadUserAccessDenied
		}),
		server.ServerName(fx.Server.ApplicationName),
		server.ProductName("go-opcua"),
		server.ManufacturerName("OT Fabric"),
		server.SoftwareVersion(upstreamVersion),
	}
	if f.eccDir != "" {
		fmt.Fprintln(os.Stderr, "--ecc-dir ignored: no ECC policies in this adapter")
	}
	if f.certificate != "" && f.privateKey != "" {
		secure, err := securityOptions(f, fx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "security:", err)
			return nil, nil, exitInternal
		}
		opts = append(opts, secure...)
	} else {
		opts = append(opts, server.ApplicationURI(fx.Server.ApplicationURI))
	}
	s, err := server.New(opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return nil, nil, exitInternal
	}
	a := &addressSpace{s: s, ns: server.NewNodeNameSpace(s, fx.Namespaces[0].URI), uri: fx.Namespaces[0].URI, values: map[string]*ua.DataValue{}}
	if err := a.build(fx); err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		return nil, nil, exitFixture
	}
	if err := s.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return nil, nil, exitInternal
	}
	if err := a.startBehaviors(ctx, fx); err != nil {
		_ = s.Close()
		fmt.Fprintln(os.Stderr, "fixture:", err)
		return nil, nil, exitFixture
	}
	return s, func() { _ = s.Close() }, exitOK
}

// securityOptions gives the secure endpoints: the RSA profiles of the fixture that
// this adapter declares. Trust is by <pki-dir>/trusted/certs (§11).
func securityOptions(f *serverFlags, fx *fixture) ([]server.Option, error) {
	cert, err := readDER(f.certificate)
	if err != nil {
		return nil, err
	}
	key, err := readRSAKey(f.privateKey)
	if err != nil {
		return nil, err
	}
	opts := []server.Option{server.Certificate(cert), server.PrivateKey(key)}
	for _, p := range fx.SecurityProfiles {
		if p.Policy == "None" || !slices.Contains(securityProfiles, securityProfile{p.Policy, p.Mode}) {
			continue
		}
		opts = append(opts, server.EnableSecurity(p.Policy, ua.MessageSecurityModeFromString(p.Mode)))
	}
	var trusted [][]byte
	files, err := filepath.Glob(filepath.Join(f.pkiDir, "trusted", "certs", "*"))
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		der, err := readDER(file)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, der)
	}
	return append(opts, server.WithClientCertificateTrustList(trusted...)), nil
}

// writeReady writes the readiness file by renaming a temporary file (§10).
func writeReady(path string, content map[string]any) error {
	b, err := json.Marshal(content)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
