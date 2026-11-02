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
			"push", "gds-pull", "pubsub-discover",
		},
		"clientFeatures": []string{
			"channel-lifetime", "deadband", "reverse-listen", "ecc-security", "ecc-user-token", "x509-user-token",
			"transport-https", "transport-wss", "codec-json", "codec-json-verbose", "codec-xml",
			"push-groups", "push-certificates", "push-transaction-diagnostics", "codec-pubsub",
		},
		"serverFeatures": []string{
			"deadband", "percent-deadband", "reverse-connect", "ecc-security", "ecc-user-token", "x509-user-token",
			"transport-https", "transport-wss", "alarms", "history-events", "history-events-update",
			"push-management", "gds-pull", "pubsub",
		},
		"pubsub": pubsubCapabilities(),
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

// pubsubCapabilities is §14.11: what scripts/pubsub-smoke.sh runs for this image.
func pubsubCapabilities() map[string]any {
	const profile = "http://opcfoundation.org/UA-Profile/Transport/pubsub-"
	const policy = "http://opcfoundation.org/UA/SecurityPolicy#PubSub-"
	return map[string]any{
		"supported":           true,
		"serverFlag":          "--pubsub-config",
		"roles":               []string{"publisher", "subscriber"},
		"transports":          []string{"udp-uadp", "mqtt-uadp", "mqtt-json"},
		"transportProfiles":   []string{profile + "udp-uadp", profile + "mqtt-uadp", profile + "mqtt-json"},
		"udp":                 map[string]bool{"unicast": true, "multicast": true},
		"mqttVersions":        []string{"3.1.1", "5.0"},
		"encodings":           []string{"uadp", "json"},
		"fieldEncodings":      []string{"Variant", "DataValue", "RawData"},
		"dataSetMessageTypes": map[string][]string{"uadp": {"KeyFrame", "DeltaFrame", "KeepAlive"}, "json": {"KeyFrame"}},
		"publishedDataSets":   []string{"PublishedDataItems"},
		"subscribedDataSets":  []string{"TargetVariables"},
		"securityPolicies":    []string{policy + "Aes128-CTR", policy + "Aes256-CTR"},
		"securityModes":       []string{"None", "SignAndEncrypt"},
		"securityEncodings":   []string{"uadp"},
		"keySources":          []string{"static", "sks-pull", "sks-push", "sks-server"},
		"sks": map[string]any{"server": true, "pull": true, "push": true,
			"methods": []string{"GetSecurityKeys", "SetSecurityKeys", "AddSecurityGroup"}},
		"informationModel":        true,
		"informationModelMethods": []string{"AddConnection", "RemoveConnection"},
		"discovery": map[string]any{"layout": "dotnet", "respond": []string{"DataSetMetaData", "DataSetWriterConfiguration"},
			"probe": []string{"DataSetMetaData", "DataSetWriterConfiguration"}, "clientOperation": "pubsub-discover"},
		"codecOps":      pubsubCodecOps,
		"codecSecurity": false,
	}
}
