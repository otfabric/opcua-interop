// SPDX-License-Identifier: MIT
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpcUaInterop
{
    /// <summary>The fixture model (fixtures/schema/opcua-fixture.schema.json), fields the adapter uses.</summary>
    internal sealed class Fixture
    {
        [JsonPropertyName("schemaVersion")] public string SchemaVersion { get; set; }
        [JsonPropertyName("id")] public string Id { get; set; }
        [JsonPropertyName("server")] public ServerInfo Server { get; set; } = new();
        [JsonPropertyName("endpoint")] public EndpointInfo Endpoint { get; set; } = new();
        [JsonPropertyName("namespaces")] public List<NamespaceInfo> Namespaces { get; set; } = [];
        [JsonPropertyName("nodes")] public List<NodeDef> Nodes { get; set; } = [];
        [JsonPropertyName("behaviors")] public List<BehaviorDef> Behaviors { get; set; } = [];
        [JsonPropertyName("securityProfiles")] public List<SecurityProfileDef> SecurityProfiles { get; set; } = [];
        [JsonPropertyName("users")] public List<UserDef> Users { get; set; } = [];

        public sealed class ServerInfo
        {
            [JsonPropertyName("applicationUri")] public string ApplicationUri { get; set; } = "urn:otfabric:opcua-interop:server";
            [JsonPropertyName("productUri")] public string ProductUri { get; set; } = "urn:otfabric:opcua-interop";
            [JsonPropertyName("applicationName")] public string ApplicationName { get; set; } = "OTFabric OPC UA Compatibility Server";
        }

        public sealed class EndpointInfo
        {
            [JsonPropertyName("path")] public string Path { get; set; } = "/";
            [JsonPropertyName("port")] public int Port { get; set; } = 4840;
        }

        public sealed class NamespaceInfo
        {
            [JsonPropertyName("alias")] public string Alias { get; set; }
            [JsonPropertyName("uri")] public string Uri { get; set; }
        }

        public sealed class NodeDef
        {
            [JsonPropertyName("nodeClass")] public string NodeClass { get; set; }
            [JsonPropertyName("nodeId")] public string NodeId { get; set; }
            [JsonPropertyName("browseName")] public string BrowseName { get; set; }
            [JsonPropertyName("displayName")] public string DisplayName { get; set; }
            [JsonPropertyName("description")] public string Description { get; set; }
            [JsonPropertyName("parentNodeId")] public string ParentNodeId { get; set; }
            [JsonPropertyName("referenceType")] public string ReferenceType { get; set; }
            [JsonPropertyName("typeDefinition")] public string TypeDefinition { get; set; }
            [JsonPropertyName("dataType")] public string DataType { get; set; }
            [JsonPropertyName("valueRank")] public int ValueRank { get; set; } = -1;
            [JsonPropertyName("arrayDimensions")] public List<int> ArrayDimensions { get; set; } = [];
            [JsonPropertyName("accessLevel")] public List<string> AccessLevel { get; set; } = [];
            [JsonPropertyName("initialValue")] public JsonElement? InitialValue { get; set; }
            [JsonPropertyName("euRange")] public EuRangeDef EuRange { get; set; }
            [JsonPropertyName("methodBehavior")] public string MethodBehavior { get; set; }
            [JsonPropertyName("inputArguments")] public List<ArgumentDef> InputArguments { get; set; } = [];
            [JsonPropertyName("outputArguments")] public List<ArgumentDef> OutputArguments { get; set; } = [];
        }

        public sealed class EuRangeDef
        {
            [JsonPropertyName("low")] public double Low { get; set; }
            [JsonPropertyName("high")] public double High { get; set; }
        }

        public sealed class ArgumentDef
        {
            [JsonPropertyName("name")] public string Name { get; set; }
            [JsonPropertyName("dataType")] public string DataType { get; set; }
            [JsonPropertyName("description")] public string Description { get; set; }
            [JsonPropertyName("valueRank")] public int ValueRank { get; set; } = -1;
        }

        public sealed class BehaviorDef
        {
            [JsonPropertyName("target")] public string Target { get; set; }
            [JsonPropertyName("kind")] public string Kind { get; set; }
            [JsonPropertyName("initial")] public double Initial { get; set; }
            [JsonPropertyName("increment")] public double Increment { get; set; } = 1.0;
            [JsonPropertyName("minimum")] public double Minimum { get; set; }
            [JsonPropertyName("maximum")] public double Maximum { get; set; } = 100.0;
            [JsonPropertyName("intervalMs")] public int IntervalMs { get; set; } = 250;
        }

        public sealed class SecurityProfileDef
        {
            [JsonPropertyName("securityPolicy")] public string SecurityPolicy { get; set; }
            [JsonPropertyName("securityMode")] public string SecurityMode { get; set; }
        }

        public sealed class UserDef
        {
            [JsonPropertyName("username")] public string Username { get; set; }
            [JsonPropertyName("password")] public string Password { get; set; }
            [JsonPropertyName("roles")] public List<string> Roles { get; set; } = [];
        }

        public static Fixture Load(string path)
        {
            string text = File.ReadAllText(path);
            Fixture f = JsonSerializer.Deserialize<Fixture>(text) ?? throw new InvalidDataException("empty fixture");
            Validate(f);
            return f;
        }

        /// <summary>Structural checks (the adapters' common subset of the JSON schema).</summary>
        public static void Validate(Fixture f)
        {
            if (f.SchemaVersion != "1.0")
            {
                throw new InvalidDataException("unsupported fixture schemaVersion: " + f.SchemaVersion);
            }
            if (string.IsNullOrEmpty(f.Id))
            {
                throw new InvalidDataException("fixture id missing");
            }
            if (f.Namespaces.Count == 0 || string.IsNullOrEmpty(f.Namespaces[0].Uri))
            {
                throw new InvalidDataException("fixture declares no namespace");
            }
            var seen = new HashSet<string>();
            foreach (NodeDef n in f.Nodes)
            {
                if (string.IsNullOrEmpty(n.NodeId) || string.IsNullOrEmpty(n.BrowseName))
                {
                    throw new InvalidDataException("node without nodeId / browseName");
                }
                if (!seen.Add(n.NodeId))
                {
                    throw new InvalidDataException("duplicate nodeId " + n.NodeId);
                }
                if (n.NodeClass is not ("Object" or "Variable" or "Method"))
                {
                    throw new InvalidDataException("unsupported nodeClass " + n.NodeClass + " (" + n.NodeId + ")");
                }
            }
        }
    }
}
