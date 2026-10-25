// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Text.Json.Nodes;

namespace OpcUaInterop
{
    /// <summary>print-capabilities (docs/CLIENT_CONTRACT.md §13, §16; schemas/capabilities.schema.json).</summary>
    internal static class Capabilities
    {
        public const string AdapterVersion = "0.15.0";

        /// <summary>The UA-.NETStandard release the csproj pins.</summary>
        public const string PinnedStackVersion = "2.0.1";

        /// <summary>The UA-.NETStandard package version the adapter runs on.</summary>
        public static string StackVersion
        {
            get
            {
                Assembly asm = typeof(Opc.Ua.Gds.Server.ApplicationsNodeManager).Assembly;
                string v = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
                if (string.IsNullOrEmpty(v))
                {
                    v = asm.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
                }
                if (string.IsNullOrEmpty(v))
                {
                    return "unknown";
                }
                int plus = v.IndexOf('+');
                return plus > 0 ? v[..plus] : v;
            }
        }

        /// <summary>The (policy, mode) pairs the server offers and the client dials.</summary>
        public static readonly (string Policy, string Mode)[] SecurityProfiles =
        [
            ("None", "None"),
            ("Basic256Sha256", "Sign"),
            ("Basic256Sha256", "SignAndEncrypt"),
            ("Aes128_Sha256_RsaOaep", "SignAndEncrypt"),
            ("Aes256_Sha256_RsaPss", "SignAndEncrypt")
        ];

        public static string Document()
        {
            var profiles = new JsonArray();
            foreach ((string p, string m) in SecurityProfiles)
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
                ["clientOperations"] = Json.Strings(GdsClientCommand.Operations),
                ["clientFeatures"] = Json.Strings(["application-uri"]),
                // The server is a Global Discovery Server (Part 12 §6 Directory, §7.9 pull
                // certificate management), not the fixture address space.
                ["serverFeatures"] = Json.Strings(["gds-pull"]),
                ["pubsub"] = new JsonObject
                {
                    ["supported"] = false,
                    ["reason"] = "the GDS adapter has no PubSub (see the dotnet adapter)",
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
                    "Read", "Write", "Call", "RegisterNodes", "UnregisterNodes",
                    "CreateSubscription", "ModifySubscription", "SetPublishingMode", "Publish", "Republish",
                    "TransferSubscriptions", "DeleteSubscriptions", "CreateMonitoredItems", "ModifyMonitoredItems",
                    "SetMonitoringMode", "SetTriggering", "DeleteMonitoredItems"]),
                ["securityProfiles"] = profiles,
                ["userTokenTypes"] = Json.Strings(["Anonymous", "UserName"])
            };
            return Json.Serialize(o);
        }
    }
}
