// SPDX-License-Identifier: MIT

// Command opcua-interop is the opcua-interop-otfabric image: go-opcua behind the
// client command contract (docs/CLIENT_CONTRACT.md).
//
// It is OT Fabric's own stack, not an independent implementation: results
// against it are never independent evidence for go-opcua (README.md). It covers a
// core subset of the contract, and print-capabilities declares which.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const adapterName = "otfabric"

// Set with -ldflags by the Dockerfile.
var (
	adapterVersion   = "dev"
	upstreamVersion  = "dev"
	upstreamRevision = "dev"
)

// Exit codes (docs/CLIENT_CONTRACT.md §5).
const (
	exitOK       = 0
	exitInput    = 2
	exitConnect  = 3
	exitService  = 4
	exitFixture  = 5
	exitInternal = 6
	exitTimeout  = 7
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: opcua-interop server|client|print-capabilities|version")
		return exitInput
	}
	switch args[0] {
	case "server":
		return runServer(args[1:])
	case "client":
		return runClient(args[1:], out)
	case "print-capabilities":
		if err := writeJSON(out, capabilities()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitInternal
		}
		return exitOK
	case "version":
		fmt.Fprintf(out, "%s %s (go-opcua %s, commit %s)\n", adapterName, adapterVersion, upstreamVersion, upstreamRevision)
		return exitOK
	}
	fmt.Fprintln(os.Stderr, "opcua-interop: unknown command", args[0])
	return exitInput
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// securityProfile is one {policy, mode} pair, usable by the client and the server.
type securityProfile struct {
	Policy string `json:"policy"`
	Mode   string `json:"mode"`
}

// securityProfiles are the RSA policies of the fixture and the test PKI. The ECC
// policies are not part of this image's subset.
var securityProfiles = []securityProfile{
	{"None", "None"},
	{"Basic256Sha256", "Sign"},
	{"Basic256Sha256", "SignAndEncrypt"},
	{"Aes128_Sha256_RsaOaep", "SignAndEncrypt"},
	{"Aes256_Sha256_RsaPss", "SignAndEncrypt"},
}

// capabilities is the document of docs/CLIENT_CONTRACT.md §13. It lists what this
// adapter does, not what go-opcua can do. Anything else counts as not declared and
// is refused with exit 2.
func capabilities() map[string]any {
	return map[string]any{
		"schemaVersion": "1.0",
		"adapter":       map[string]any{"name": adapterName, "version": adapterVersion},
		"stack":         map[string]any{"name": "go-opcua", "version": upstreamVersion},
		"upstream": map[string]any{
			"name":              "go-opcua",
			"version":           upstreamVersion,
			"revision":          upstreamRevision,
			"independentEngine": false,
		},
		"fixtureSchemaVersions": []string{"1.0"},
		"roles":                 []string{"client", "server"},
		"transports":            []string{"opc.tcp"},
		"encodings":             []string{"binary"},
		"clientOperations":      []string{"endpoints", "find-servers", "read", "write", "browse", "call", "subscribe", "register-nodes"},
		"clientFeatures":        []string{"channel-lifetime", "deadband"},
		"serverFeatures":        []string{"deadband", "percent-deadband"},
		"pubsub": map[string]any{
			"supported":        false,
			"reason":           "not in the subset of this adapter (own/go-opcua/README.md)",
			"transports":       []string{},
			"encodings":        []string{},
			"roles":            []string{},
			"securityPolicies": []string{},
			"sks":              map[string]bool{"server": false, "pull": false, "push": false},
			"informationModel": false,
			"codecOps":         []string{},
		},
		"serverServices": []string{
			"GetEndpoints", "FindServers", "CreateSession", "ActivateSession", "CloseSession",
			"Browse", "BrowseNext", "RegisterNodes", "UnregisterNodes", "Read", "Write", "Call",
			"CreateSubscription", "DeleteSubscriptions", "CreateMonitoredItems", "DeleteMonitoredItems", "Publish",
		},
		"securityProfiles": securityProfiles,
		"userTokenTypes":   []string{"Anonymous", "UserName"},
	}
}
