// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Text.Json.Nodes;

namespace OpcUaInterop
{
    /// <summary>print-capabilities (docs/CLIENT_CONTRACT.md §13, schemas/capabilities.schema.json).</summary>
    internal static class Capabilities
    {
        public const string AdapterVersion = "0.9.0";

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
                ["transports"] = Json.Strings(["opc.tcp"]),
                ["encodings"] = Json.Strings(["binary"]),
                ["clientOperations"] = Json.Strings(ClientCommand.Operations),
                // Not listed: reverse-listen (ReverseConnectManager not wired), ecc-security /
                // ecc-user-token (2.0.1 does not accept the test PKI's RSA-CA-signed ECC
                // certificates), codec-pubsub (PubSub not wired).
                ["clientFeatures"] = Json.Strings([
                    "channel-lifetime", "deadband", "application-uri", "register-server2",
                    "codec-json", "codec-xml", "codec-json-verbose"]),
                // Not listed: reverse-connect, lds, mdns, pubsub (not wired), ecc-security (see above).
                ["serverFeatures"] = Json.Strings(["deadband", "percent-deadband", "register-with", "node-management"]),
                ["codec"] = new JsonObject
                {
                    ["formats"] = Json.Strings(["json", "xml"]),
                    ["jsonVersion"] = "1.05",
                    ["jsonModes"] = Json.Strings(["compact", "verbose"]),
                    ["xmlEncodeUnsupported"] = new JsonArray(),
                    ["xmlDecodeUnsupported"] = new JsonArray()
                },
                ["pubsub"] = new JsonObject
                {
                    ["supported"] = false,
                    ["reason"] = "UA-.NETStandard 2.0.1 ships a PubSub runtime (Opc.Ua.PubSub, .Udp, .Mqtt), but this adapter does not implement the --pubsub-config / codec pubsub-* contract (§14) yet",
                    ["transports"] = new JsonArray(),
                    ["encodings"] = new JsonArray(),
                    ["roles"] = new JsonArray(),
                    ["securityPolicies"] = new JsonArray(),
                    ["sks"] = new JsonObject { ["server"] = false, ["pull"] = false, ["push"] = false },
                    ["informationModel"] = false,
                    ["codecOps"] = new JsonArray()
                },
                ["serverServices"] = Json.Strings([
                    "GetEndpoints", "FindServers", "Browse", "BrowseNext", "TranslateBrowsePathsToNodeIds",
                    "Read", "Write", "Call", "RegisterNodes", "UnregisterNodes", "AddNodes", "DeleteNodes",
                    "CreateSubscription", "ModifySubscription", "SetPublishingMode", "Publish", "Republish",
                    "TransferSubscriptions", "DeleteSubscriptions", "CreateMonitoredItems", "ModifyMonitoredItems",
                    "SetMonitoringMode", "SetTriggering", "DeleteMonitoredItems", "HistoryRead"]),
                ["securityProfiles"] = profiles,
                ["userTokenTypes"] = Json.Strings(["Anonymous", "UserName"])
            };
            return Json.Serialize(o);
        }
    }
}
