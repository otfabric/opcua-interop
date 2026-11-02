// SPDX-License-Identifier: MIT

package main

// securityProfile is one {policy, mode} pair, usable by the client and the server.
type securityProfile struct {
	Policy string `json:"policy"`
	Mode   string `json:"mode"`
}

// securityProfiles are the policies of the fixture and the test PKI.
var securityProfiles = []securityProfile{
	{"None", "None"},
	{"Basic256Sha256", "Sign"},
	{"Basic256Sha256", "SignAndEncrypt"},
	{"Aes128_Sha256_RsaOaep", "SignAndEncrypt"},
	{"Aes256_Sha256_RsaPss", "SignAndEncrypt"},
	{"ECC_nistP256", "Sign"},
	{"ECC_nistP256", "SignAndEncrypt"},
	{"ECC_nistP384", "Sign"},
	{"ECC_nistP384", "SignAndEncrypt"},
	{"ECC_brainpoolP256r1", "SignAndEncrypt"},
	{"ECC_brainpoolP384r1", "SignAndEncrypt"},
	{"ECC_curve25519", "SignAndEncrypt"},
	{"ECC_curve448", "SignAndEncrypt"},
	{"ECC_nistP256_AesGcm", "SignAndEncrypt"},
	{"ECC_nistP256_ChaChaPoly", "SignAndEncrypt"},
}

// capabilities is the document of docs/CAPABILITIES.md. It lists what this
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
		"transports":            []string{"opc.tcp", "opc.https", "opc.wss"},
		"encodings":             []string{"binary"},
		"codec":                 codecInfo(),
		"clientOperations": []string{
			"endpoints", "find-servers", "read", "write", "browse", "call", "subscribe", "register-nodes",
			"event-subscribe", "alarms", "history-read", "history-read-events", "history-update-events", "codec",
		},
		"clientFeatures": []string{
			"channel-lifetime", "deadband", "reverse-listen", "ecc-security", "ecc-user-token", "x509-user-token",
			"transport-https", "transport-wss", "codec-json", "codec-json-verbose", "codec-xml",
		},
		"serverFeatures": []string{
			"deadband", "percent-deadband", "reverse-connect", "ecc-security", "ecc-user-token", "x509-user-token",
			"transport-https", "transport-wss", "alarms", "history-events", "history-events-update",
		},
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
			"HistoryRead", "HistoryUpdate",
		},
		"securityProfiles": securityProfiles,
		"userTokenTypes":   []string{"Anonymous", "UserName", "X509"},
	}
}
