// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/otfabric/go-opcua/gds/gdsserver"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
)

// serverFlags are the flags of §11 this adapter has. Any other, such as
// --pubsub-config or --lds, is refused with exit 2.
type serverFlags struct {
	fixture, bindAddress, advertisedHost, endpointPath string
	readyFile, pkiDir, certificate, privateKey, eccDir string
	bindPort, advertisedPort                           int
	httpsPort, wssPort                                 int
	reverseConnect                                     repeated
	reverseIntervalMS                                  int64
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
	fs.StringVar(&f.eccDir, "ecc-dir", "", "directory with ecc-<curve>/cert.crt and cert.key")
	fs.IntVar(&f.httpsPort, "https-port", 0, "also serve opc.https on this port")
	fs.IntVar(&f.wssPort, "wss-port", 0, "also serve opc.wss on this port")
	fs.Var(&f.reverseConnect, "reverse-connect", "dial this client and send ReverseHello, repeatable")
	fs.Int64Var(&f.reverseIntervalMS, "reverse-connect-interval-ms", 1000, "retry interval of --reverse-connect")
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
	var directory *gdsserver.GDS
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
		server.WithRoleMapper(roleMapper(fx, func() *gdsserver.GDS { return directory })),
		server.ServerName(fx.Server.ApplicationName),
		server.ProductName("go-opcua"),
		server.ManufacturerName("OT Fabric"),
		server.SoftwareVersion(upstreamVersion),
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
	transports, err := transportOptions(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "transport:", err)
		return nil, nil, exitInternal
	}
	opts = append(append(opts, transports...), reverseOptions(f)...)
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
	if err := a.addFeatures(); err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		return nil, nil, exitFixture
	}
	if fx.hasGDSRole() {
		if directory, err = attachGDS(s); err != nil {
			fmt.Fprintln(os.Stderr, "gds:", err)
			return nil, nil, exitInternal
		}
	}
	if err := s.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return nil, nil, exitInternal
	}
	err = a.startBehaviors(ctx, fx)
	if err == nil {
		err = a.emitEvents(ctx)
	}
	if err != nil {
		_ = s.Close()
		fmt.Fprintln(os.Stderr, "fixture:", err)
		return nil, nil, exitFixture
	}
	return s, func() {
		if directory != nil {
			directory.Close()
		}
		_ = s.Close()
	}, exitOK
}

// eccCurves name the certificate directory of a policy (§1).
var eccCurves = map[string]string{
	"ECC_nistP256": "nistp256", "ECC_nistP256_AesGcm": "nistp256", "ECC_nistP256_ChaChaPoly": "nistp256",
	"ECC_nistP384": "nistp384", "ECC_brainpoolP256r1": "brainpoolp256r1", "ECC_brainpoolP384r1": "brainpoolp384r1",
	"ECC_curve25519": "curve25519", "ECC_curve448": "curve448",
}

// securityOptions gives the secure endpoints: the profiles of the fixture that this
// adapter declares. An ECC profile needs the certificate of its curve in --ecc-dir
// (§11). Trust is by <pki-dir>/trusted/certs, managed by push (§15).
func securityOptions(f *serverFlags, fx *fixture) ([]server.Option, error) {
	cert, err := readDER(f.certificate)
	if err != nil {
		return nil, err
	}
	key, err := readKey(f.privateKey)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New(f.privateKey + ": --private-key is the RSA identity; ECC identities come from --ecc-dir")
	}
	opts := []server.Option{server.Certificate(cert), server.PrivateKey(rsaKey)}
	identities := map[string]bool{}
	for _, p := range fx.SecurityProfiles {
		if p.Policy == "None" || !slices.Contains(securityProfiles, securityProfile{p.Policy, p.Mode}) {
			continue
		}
		if curve, isECC := eccCurves[p.Policy]; isECC {
			if f.eccDir == "" {
				continue
			}
			dir := filepath.Join(f.eccDir, "ecc-"+curve)
			if _, err := os.Stat(filepath.Join(dir, "cert.crt")); err != nil {
				continue
			}
			if !identities[curve] {
				identity, err := eccIdentity(dir)
				if err != nil {
					return nil, err
				}
				opts = append(opts, identity)
				identities[curve] = true
			}
		}
		opts = append(opts, server.EnableSecurity(p.Policy, ua.MessageSecurityModeFromString(p.Mode)))
	}
	trusted, err := trustedCertificates(f.pkiDir)
	if err != nil {
		return nil, err
	}
	// The DefaultUserTokenGroup validates a user certificate before this is asked: this
	// fixture has no certificate users, so any that passed is test-user.
	validator := server.X509UserValidator(func([]byte) error { return nil })
	return append(opts, server.WithPushManagement(pushManagement(trusted)),
		server.EnableAuthMode(ua.UserTokenTypeCertificate), server.WithX509UserValidator(validator)), nil
}

func eccIdentity(dir string) (server.Option, error) {
	cert, err := readDER(filepath.Join(dir, "cert.crt"))
	if err != nil {
		return nil, err
	}
	key, err := readKey(filepath.Join(dir, "cert.key"))
	if err != nil {
		return nil, err
	}
	return server.ApplicationIdentity(cert, key), nil
}

// transportOptions are the opc.https and opc.wss listeners (§11). TLS uses the RSA
// application certificate, go-opcua's default.
func transportOptions(f *serverFlags) ([]server.Option, error) {
	if f.httpsPort == 0 && f.wssPort == 0 {
		return nil, nil
	}
	if f.certificate == "" || f.privateKey == "" {
		return nil, errors.New("--https-port and --wss-port need --certificate and --private-key")
	}
	var opts []server.Option
	if f.httpsPort != 0 {
		opts = append(opts, server.HTTPSEndPoint(f.advertisedHost, f.httpsPort), server.ListenHTTPSOn(fmt.Sprintf("%s:%d", f.bindAddress, f.httpsPort)))
	}
	if f.wssPort != 0 {
		opts = append(opts, server.WebSocketEndPoint(f.advertisedHost, f.wssPort), server.ListenWebSocketOn(fmt.Sprintf("%s:%d", f.bindAddress, f.wssPort)))
	}
	return opts, nil
}

// reverseOptions dial --reverse-connect clients. The ReverseHello names the first
// endpoint: what GetEndpoints answers, without --endpoint-path, because a client says
// Hello with the URL it selected and the server compares it (open62541 does).
func reverseOptions(f *serverFlags) []server.Option {
	interval := time.Duration(f.reverseIntervalMS) * time.Millisecond
	opts := make([]server.Option, len(f.reverseConnect))
	for i, client := range f.reverseConnect {
		opts[i] = server.WithReverseConnect(client, server.ReverseConnectRetryInterval(interval, interval))
	}
	return opts
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
