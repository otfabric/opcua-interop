// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Text.Json.Nodes;

namespace OpcUaInterop
{
    /// <summary>print-capabilities (docs/CLIENT_CONTRACT.md §13, schemas/capabilities.schema.json).</summary>
    internal static class Capabilities
    {
        public const string AdapterVersion = "0.18.0";

        /// <summary>The UA-.NETStandard package version the adapter runs on.</summary>
        public static string StackVersion
        {
            get
            {
                string v = typeof(Opc.Ua.Server.StandardServer).Assembly
                    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
                if (string.IsNullOrEmpty(v))
                {
                    return "unknown";
                }
                int plus = v.IndexOf('+');
                return plus > 0 ? v[..plus] : v;
            }
        }

        public static string Document()
        {
            var profiles = new JsonArray();
            foreach ((string p, string m) in new[]
            {
                ("None", "None"),
                ("Basic256Sha256", "Sign"),
                ("Basic256Sha256", "SignAndEncrypt"),
                ("Aes128_Sha256_RsaOaep", "SignAndEncrypt"),
                ("Aes256_Sha256_RsaPss", "SignAndEncrypt")
            })
            {
                profiles.Add(new JsonObject { ["policy"] = p, ["mode"] = m });
            }

            var o = new JsonObject
            {
                ["schemaVersion"] = "1.0",
                ["adapter"] = new JsonObject { ["name"] = Result.Adapter, ["version"] = AdapterVersion },
                ["stack"] = new JsonObject { ["name"] = "opcfoundation-uanetstandard", ["version"] = StackVersion },
                ["fixtureSchemaVersions"] = Json.Strings(["1.0"]),
                ["roles"] = Json.Strings(["client", "server"]),
                ["transports"] = Json.Strings(["opc.tcp", "opc.https", "opc.wss"]),
                ["encodings"] = Json.Strings(["binary"]),
                ["clientOperations"] = Json.Strings(ClientCommand.Operations),
                // Not listed: reverse-listen (ReverseConnectManager not wired), ecc-security /
                // ecc-user-token (2.0.1 does not accept the test PKI's RSA-CA-signed ECC
                // certificates).
                ["clientFeatures"] = Json.Strings([
                    "channel-lifetime", "deadband", "application-uri", "register-server2",
                    "codec-json", "codec-xml", "codec-json-verbose", "codec-pubsub",
                    // --endpoint opc.https://… / opc.wss://… (https-uabinary, wss-uasc-uabinary)
                    "transport-https", "transport-wss",
                    // client push: --group, the Part 12 1.05 methods, TransactionDiagnostics (§15)
                    "push-groups", "push-certificates", "push-transaction-diagnostics"]),
                // Not listed: reverse-connect, lds, mdns, ecc-security (see above).
                // transport-https / transport-wss: --https-port / --wss-port (needs --certificate)
                ["serverFeatures"] = Json.Strings(["deadband", "percent-deadband", "register-with", "node-management", "pubsub",
                    "transport-https", "transport-wss", "alarms", "push-management",
                    "alarms-105", "auditing", "pubsub-multicast-loopback",
                    // s=History.Events: HistoryRead / HistoryUpdate of events (stack historian, in memory)
                    "history-events", "history-events-update"]),
                ["codec"] = new JsonObject
                {
                    ["formats"] = Json.Strings(["json", "xml"]),
                    ["jsonVersion"] = "1.05",
                    ["jsonModes"] = Json.Strings(["compact", "verbose"]),
                    ["xmlEncodeUnsupported"] = new JsonArray(),
                    ["xmlDecodeUnsupported"] = new JsonArray()
                },
                ["pubsub"] = PubSub(),
                ["serverServices"] = Json.Strings([
                    "GetEndpoints", "FindServers", "Browse", "BrowseNext", "TranslateBrowsePathsToNodeIds",
                    "Read", "Write", "Call", "RegisterNodes", "UnregisterNodes", "AddNodes", "DeleteNodes",
                    "CreateSubscription", "ModifySubscription", "SetPublishingMode", "Publish", "Republish",
                    "TransferSubscriptions", "DeleteSubscriptions", "CreateMonitoredItems", "ModifyMonitoredItems",
                    "SetMonitoringMode", "SetTriggering", "DeleteMonitoredItems", "HistoryRead", "HistoryUpdate"]),
                ["securityProfiles"] = profiles,
                ["userTokenTypes"] = Json.Strings(["Anonymous", "UserName"])
            };
            return Json.Serialize(o);
        }

        /// <summary>The PubSub block (docs/CLIENT_CONTRACT.md §14.11, .NET: §14.13).</summary>
        private static JsonObject PubSub() => new()
        {
            ["supported"] = true,
            ["serverFlag"] = "--pubsub-config",
            ["roles"] = Json.Strings(["publisher", "subscriber"]),
            ["transports"] = Json.Strings(["udp-uadp", "mqtt-uadp", "mqtt-json"]),
            ["transportProfiles"] = Json.Strings([
                "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp",
                "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp",
                "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json"]),
            ["udp"] = new JsonObject { ["unicast"] = true, ["multicast"] = true },
            ["mqttVersions"] = Json.Strings(["5.0", "3.1.1", "3.1"]),
            ["encodings"] = Json.Strings(["uadp", "json"]),
            ["fieldEncodings"] = Json.Strings(["Variant", "DataValue", "RawData"]),
            ["dataSetMessageTypes"] = new JsonObject
            {
                ["uadp"] = Json.Strings(["KeyFrame", "DeltaFrame", "KeepAlive"]),
                ["json"] = Json.Strings(["KeyFrame", "DeltaFrame", "KeepAlive"])
            },
            ["publishedDataSets"] = Json.Strings(["PublishedDataItems"]),
            ["subscribedDataSets"] = Json.Strings(["TargetVariables"]),
            ["securityPolicies"] = Json.Strings([
                "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR",
                "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR"]),
            ["securityModes"] = Json.Strings(["None", "Sign", "SignAndEncrypt"]),
            ["securityEncodings"] = Json.Strings(["uadp"]),
            ["keySources"] = Json.Strings(["static"]),
            ["sks"] = new JsonObject { ["server"] = false, ["pull"] = false, ["push"] = false },
            ["informationModel"] = false,
            ["chunking"] = true,
            ["discovery"] = new JsonObject
            {
                ["layout"] = "dotnet",
                ["respond"] = Json.Strings(["DataSetMetaData", "DataSetWriterConfiguration"]),
                ["probe"] = Json.Strings(["DataSetMetaData", "DataSetWriterConfiguration"]),
                ["clientOperation"] = "pubsub-discover"
            },
            ["codecOps"] = Json.Strings(PubSubCodec.Operations),
            ["codecSecurity"] = false
        };
    }
}
