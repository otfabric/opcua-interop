// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	opcua "github.com/otfabric/go-opcua"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uacp"
)

// isReverse says that this command waits for the server's ReverseHello.
func (g *globals) isReverse() bool { return g.reverseListen > 0 }

// isTLS says that --endpoint is a transport over TLS (§9).
func (g *globals) isTLS() bool {
	scheme, _, _ := strings.Cut(strings.ToLower(g.endpoint), "://")
	switch scheme {
	case "opc.wss", "wss", "opc.https", "https":
		return true
	}
	return false
}

// dialURL is what go-opcua connects to: nothing with a reverse connection, where
// the URL the server announces is used.
func (g *globals) dialURL() string {
	if g.isReverse() {
		return ""
	}
	return g.endpoint
}

// connectTime is the budget of connecting: on a reverse connection, the wait for
// the server.
func (g *globals) connectTime() time.Duration {
	if g.isReverse() {
		return time.Duration(g.reverseTimeoutMS) * time.Millisecond
	}
	return seconds(g.connect)
}

// tlsConfig validates the server's TLS certificate against --trust-list and accepts
// any without it (§9). Host names are not compared: the contract asks for the chain,
// and the certificates of the test PKI name other hosts than the containers.
func (g *globals) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // #nosec G402 -- see above
	if len(g.trust) == 0 {
		return cfg, nil
	}
	pool := x509.NewCertPool()
	for _, path := range g.trust {
		der, err := readDER(path)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		pool.AddCert(cert)
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	return cfg, nil
}

// connectionOptions are the options of every connection of this command, also of
// discovery. The reverse listener outlives one connection: with a security policy
// the endpoints are read on the first and the session runs on the next.
func (g *globals) connectionOptions(ctx context.Context) ([]opcua.Option, error) {
	opts := []opcua.Option{opcua.DialTimeout(g.connectTime())}
	if g.isReverse() {
		if g.listener == nil {
			l, err := uacp.ListenReverse(ctx, fmt.Sprintf("0.0.0.0:%d", g.reverseListen), &uacp.ReverseListenerConfig{})
			if err != nil {
				return nil, err
			}
			g.listener = l
		}
		opts = append(opts, opcua.ReverseConnectListener(g.listener))
	}
	if g.isTLS() {
		cfg, err := g.tlsConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, opcua.TLSConfig(cfg))
	}
	return opts, nil
}

// close ends what the command opened besides its connections.
func (g *globals) close() {
	if g.listener != nil {
		_ = g.listener.Close()
	}
}

// classifyWait is classifyConnect, except that running out of time waiting for a
// server to dial in is a timeout (§1).
func (g *globals) classifyWait(err error) outcome {
	if g.isReverse() {
		if res := classify(err); res.exit == exitTimeout {
			return res
		}
	}
	return classifyConnect(err)
}

// selectEndpoint finds the endpoint of exactly the requested policy, mode and
// transport (§9). There is never a fallback.
func (g *globals) selectEndpoint(endpoints []*ua.EndpointDescription) *ua.EndpointDescription {
	wantPolicy, wantMode := ua.FormatSecurityPolicyURI(g.policy), ua.MessageSecurityModeFromString(g.mode)
	wantProfile := ua.TransportProfileUATCP
	if !g.isReverse() {
		wantProfile = ua.TransportProfileForURL(g.endpoint)
	}
	for _, ep := range endpoints {
		profile := ep.TransportProfileURI
		if profile == "" {
			profile = ua.TransportProfileForURL(ep.EndpointURL)
		}
		if ep.SecurityPolicyURI == wantPolicy && ep.SecurityMode == wantMode && profile == wantProfile {
			return ep
		}
	}
	return nil
}

// identityOptions are the user identity of the session.
func (g *globals) identityOptions(chosen *ua.EndpointDescription) ([]opcua.Option, error) {
	switch {
	case g.userCert != "":
		cert, err := readDER(g.userCert)
		if err != nil {
			return nil, err
		}
		key, err := readKey(g.userKey)
		if err != nil {
			return nil, err
		}
		return []opcua.Option{opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeCertificate), opcua.AuthCertificate(cert), opcua.AuthPrivateKeySigner(key)}, nil
	case g.userSet:
		return []opcua.Option{opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeUserName), opcua.AuthUsername(g.user, g.password)}, nil
	}
	return []opcua.Option{opcua.SecurityFromEndpoint(chosen, ua.UserTokenTypeAnonymous), opcua.AuthAnonymous()}, nil
}

// trustOptions are the certificates the application certificate of the server is
// checked against. §9: without --trust-list every certificate is accepted.
func (g *globals) trustOptions() ([]opcua.Option, error) {
	if len(g.trust) == 0 {
		return []opcua.Option{opcua.InsecureSkipVerify()}, nil
	}
	certs := make([]*x509.Certificate, 0, len(g.trust))
	for _, path := range g.trust {
		der, err := readDER(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	return []opcua.Option{opcua.TrustedCertificates(certs...)}, nil
}

// clientOptions are the options of the session on the chosen endpoint.
func (g *globals) clientOptions(ctx context.Context, chosen *ua.EndpointDescription) ([]opcua.Option, error) {
	opts, err := g.connectionOptions(ctx)
	if err != nil {
		return nil, err
	}
	opts = append(opts, opcua.RequestTimeout(seconds(g.request)), opcua.AutoReconnect(false))
	if g.lifetimeMS > 0 {
		opts = append(opts, opcua.Lifetime(time.Duration(g.lifetimeMS)*time.Millisecond))
	}
	if g.policy == "None" {
		opts = append(opts, opcua.InsecureNoSecurity())
	}
	if g.cert != "" && g.key != "" {
		cert, err := readDER(g.cert)
		if err != nil {
			return nil, err
		}
		key, err := readKey(g.key)
		if err != nil {
			return nil, err
		}
		opts = append(opts, opcua.Certificate(cert), opcua.PrivateKeySigner(key))
	}
	trust, err := g.trustOptions()
	if err != nil {
		return nil, err
	}
	identity, err := g.identityOptions(chosen)
	if err != nil {
		return nil, err
	}
	return append(append(opts, trust...), identity...), nil
}

// dial selects the endpoint of exactly the requested policy and mode (§9) and
// connects to --endpoint, not to the URL the server advertises: a server behind a
// published port knows itself under another name.
func (g *globals) dial(ctx context.Context) (*opcua.Client, *outcome) {
	base, err := g.connectionOptions(ctx)
	if err != nil {
		res := failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
		return nil, &res
	}
	endpoints, err := opcua.GetEndpoints(ctx, g.dialURL(), base...)
	if err != nil {
		res := g.classifyWait(err)
		return nil, &res
	}
	chosen := g.selectEndpoint(endpoints)
	if chosen == nil {
		res := failure(exitConnect, "transport", fmt.Sprintf("the server has no endpoint %s/%s of this transport", g.policy, g.mode), ua.StatusBadSecurityPolicyRejected)
		return nil, &res
	}
	if !g.isReverse() {
		chosen.EndpointURL = g.endpoint
	}
	opts, err := g.clientOptions(ctx, chosen)
	if err != nil {
		res := failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
		return nil, &res
	}
	c, err := opcua.NewClient(g.dialURL(), opts...)
	if err != nil {
		res := failure(exitInternal, "internal", err.Error(), ua.StatusBadInternalError)
		return nil, &res
	}
	if err := c.Connect(ctx); err != nil {
		res := g.classifyWait(err)
		return nil, &res
	}
	if res := g.checkServerURI(ctx, c); res != nil {
		_ = c.Close(ctx)
		return nil, res
	}
	return c, nil
}

// serverArrayNode is Server.ServerArray (Part 5).
const serverArrayNode = 2254

// checkServerURI is --reverse-server-uri: ServerArray[0] of the server that dialled
// in (§1).
func (g *globals) checkServerURI(ctx context.Context, c *opcua.Client) *outcome {
	if g.reverseServerURI == "" {
		return nil
	}
	v, err := c.Node(ua.NewNumericNodeID(0, serverArrayNode)).Value(ctx)
	if err == nil {
		if uris, ok := v.Value().([]string); ok && len(uris) > 0 && uris[0] == g.reverseServerURI {
			return nil
		}
		err = errors.New("the server that connected is not " + g.reverseServerURI)
	}
	res := failure(exitConnect, "transport", err.Error(), ua.StatusBadServerURIInvalid)
	return &res
}

// classifyConnect is classify for the time before a session exists, where running
// out of time is a transport failure (§3: hello timeout).
func classifyConnect(err error) outcome {
	res := classify(err)
	if res.exit == exitTimeout {
		return failure(exitConnect, "transport", err.Error(), res.status)
	}
	return res
}

// logClose reports a failed disconnect where it does not disturb the document.
func logClose(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "close:", err)
	}
}
