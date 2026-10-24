// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Opc.Ua;
using Opc.Ua.PubSub.Application;
using Opc.Ua.PubSub.Configuration;
using Opc.Ua.PubSub.DataSets;
using Opc.Ua.PubSub.Diagnostics;
using Opc.Ua.PubSub.Encoding;
using Opc.Ua.PubSub.Encoding.Uadp;
using Opc.Ua.PubSub.MetaData;
using Opc.Ua.PubSub.Mqtt;
using Opc.Ua.PubSub.Scheduling;
using Opc.Ua.PubSub.Security;
using Opc.Ua.PubSub.Security.Policies;
using Opc.Ua.PubSub.Transports;
using Opc.Ua.PubSub.Udp;
using PubSubJsonDecoder = Opc.Ua.PubSub.Encoding.Json.JsonDecoder;
using PubSubJsonEncoder = Opc.Ua.PubSub.Encoding.Json.JsonEncoder;

namespace OpcUaInterop
{
    /// <summary>A --pubsub-config file the adapter cannot apply (the server exits 1).</summary>
    internal sealed class PubSubConfigException : Exception
    {
        public PubSubConfigException(string message) : base(message) { }
    }

    /// <summary>
    /// server --pubsub-config (docs/CLIENT_CONTRACT.md §14, .NET specifics in §14.13): the
    /// Opc.Ua.PubSub runtime of UA-.NETStandard next to the fixture server. PublishedDataItems
    /// sample the fixture variables, TargetVariables write them. The configuration is decoded
    /// with the stack's JSON decoder and adapted where Opc.Ua.PubSub 2.0.1 differs from the
    /// contract (see Normalize).
    /// </summary>
    internal sealed class PubSubServer : IAsyncDisposable
    {
        private static readonly string[] s_members =
            ["configuration", "securityGroups", "serveSks", "sksClient", "deltaFrames", "mqtt"];

        /// <summary>
        /// Opc.Ua.PubSub rejects a DataSetReader MessageReceiveTimeout of 0; the contract uses 0 for
        /// "no timeout". One day stands in for it.
        /// </summary>
        private const double NoReceiveTimeoutMs = 86_400_000;

        /// <summary>The KeyNonce of PubSub-Aes128-CTR / PubSub-Aes256-CTR (Part 14 §8.3.2): 4 bytes.</summary>
        private const int KeyNonceLength = 4;

        /// <summary>
        /// Opc.Ua.PubSub requires a SecurityKeyServices entry on a secured group although static keys
        /// never contact it; this endpoint is a placeholder that is never connected.
        /// </summary>
        private const string StaticKeysPlaceholder = "opc.tcp://localhost:4840/opcua-interop/static-keys";

        private readonly PubSubApplication m_app;
        private readonly ServiceProvider m_services;
        private readonly List<IDisposable> m_disposables;

        private PubSubServer(PubSubApplication app, ServiceProvider services, List<IDisposable> disposables)
        {
            m_app = app;
            m_services = services;
            m_disposables = disposables;
        }

        public IPubSubApplication Application => m_app;

        /// <summary>Parses, applies and starts the configuration of the file.</summary>
        public static async Task<PubSubServer> StartAsync(
            string path, InteropServer server, ITelemetryContext telemetry, CancellationToken ct = default)
        {
            JsonObject root;
            try
            {
                root = JsonNode.Parse(File.ReadAllText(path)) as JsonObject
                    ?? throw new PubSubConfigException("the file is not a JSON object");
            }
            catch (JsonException e)
            {
                throw new PubSubConfigException("malformed JSON: " + e.Message);
            }
            foreach (KeyValuePair<string, JsonNode> m in root)
            {
                if (!s_members.Contains(m.Key))
                {
                    throw new PubSubConfigException("unknown member \"" + m.Key + "\"");
                }
            }
            if (root["serveSks"] is JsonValue sks && sks.GetValue<bool>())
            {
                throw new PubSubConfigException(
                    "\"serveSks\" is not supported: Opc.Ua.PubSub 2.0.1 has no Security Key Service usable without its hosted server (§14.13)");
            }
            if (root["sksClient"] != null)
            {
                throw new PubSubConfigException(
                    "\"sksClient\" is not supported by the .NET adapter (§14.13): only static keys");
            }
            bool deltaFrames = root["deltaFrames"] is JsonValue df && df.GetValue<bool>();
            MqttProtocolVersion mqttVersion = ParseMqttVersion(root["mqtt"]);
            Dictionary<string, (IPubSubSecurityPolicy Policy, byte[] Key, uint TokenId)> groups = ParseSecurityGroups(root["securityGroups"]);

            if (root["configuration"] is not JsonObject cfgJson)
            {
                throw new PubSubConfigException("missing \"configuration\"");
            }
            IServiceMessageContext context = server.CurrentInstance.MessageContext;
            PubSubConfigurationDataType cfg = Decode(cfgJson.ToJsonString(), context);
            Normalize(cfg, deltaFrames, groups);
            if (mqttVersion != MqttProtocolVersion.V500)
            {
                // MqttBrokerTransport sets the MQTT 5 ContentType on every publication and the
                // MQTTnet client refuses it below 5.0: every publish would fail. Subscribing works.
                foreach (PubSubConnectionDataType c in cfg.Connections)
                {
                    if (c.WriterGroups.Count > 0 && c.TransportProfileUri is Profiles.PubSubMqttUadpTransport or Profiles.PubSubMqttJsonTransport)
                    {
                        throw new PubSubConfigException("connection " + c.Name + ": publishing needs mqtt.protocolVersion 5.0 (§14.13)");
                    }
                }
            }

            InteropNodeManager nodes = server.Interop;
            var sources = new Dictionary<string, IPublishedDataSetSource>(StringComparer.Ordinal);
            foreach (PublishedDataSetDataType pds in cfg.PublishedDataSets)
            {
                sources[pds.Name] = new FixtureDataSetSource(pds, nodes);
            }
            var sinks = new Dictionary<string, ISubscribedDataSetSink>(StringComparer.Ordinal);
            foreach (PubSubConnectionDataType c in cfg.Connections)
            {
                foreach (ReaderGroupDataType rg in c.ReaderGroups)
                {
                    foreach (DataSetReaderDataType r in rg.DataSetReaders)
                    {
                        if (r.SubscribedDataSet.TryGetValue(out TargetVariablesDataType tv) && tv != null)
                        {
                            sinks[r.Name] = new TargetVariablesSink(tv, new FixtureTargetWriter(nodes));
                        }
                    }
                }
            }

            var disposables = new List<IDisposable>();
            var keyProviders = new List<IPubSubSecurityKeyProvider>();
            foreach (KeyValuePair<string, (IPubSubSecurityPolicy Policy, byte[] Key, uint TokenId)> g in groups)
            {
                if (g.Value.Key == null)
                {
                    throw new PubSubConfigException("SecurityGroup \"" + g.Key + "\" has no \"keys\": only static keys are supported (§14.13)");
                }
                var ring = new PubSubSecurityKeyRing(g.Key, TimeProvider.System);
                ring.SetCurrent(SplitKey(g.Value.Policy, g.Value.Key, g.Value.TokenId));
                disposables.Add(ring);
                keyProviders.Add(new StaticSecurityKeyProvider(g.Key, ring));
            }

            // MqttClientAdapterFactory (the MQTTnet client) is internal to Opc.Ua.PubSub.Mqtt and only
            // reachable through its DI registration.
            var services = new ServiceCollection();
            services.AddOpcUa().AddPubSub(pb => pb.AddMqttTransport(o => o.ProtocolVersion = mqttVersion));
            ServiceProvider sp = services.BuildServiceProvider();
            IMqttClientFactory mqttClients = sp.GetRequiredService<IMqttClientFactory>();
            var mqttOptions = Options.Create(new MqttConnectionOptions { ProtocolVersion = mqttVersion });
            var tp = TimeProvider.System;
            var diagnostics = new PubSubDiagnostics(PubSubDiagnosticsLevel.Low, tp);
            IPubSubTransportFactory[] transports =
            [
                new UdpPubSubTransportFactory(Options.Create(PubSubServer.UdpOptions()), diagnostics),
                new MqttReaderTopicsFactory(new MqttPubSubTransportFactory(Profiles.PubSubMqttUadpTransport, mqttClients, mqttOptions, null, diagnostics)),
                new MqttReaderTopicsFactory(new MqttPubSubTransportFactory(Profiles.PubSubMqttJsonTransport, mqttClients, mqttOptions, null, diagnostics))
            ];
            IPubSubSecurityPolicy[] policies = [.. PubSubSecurityPolicyRegistry.Default.Policies];
            IPubSubSecurityWrapperResolver resolver = keyProviders.Count == 0
                ? null
                : new PubSubSecurityWrapperResolver(
                    keyProviders, telemetry, tp, null,
                    (_, groupId) => groups.TryGetValue(groupId, out var g) ? g.Policy : null,
                    policies: policies);

            PubSubApplication app;
            try
            {
                // Built like PubSubApplicationBuilder.Build(), which offers no way to pass the
                // maxNetworkMessageSizeResolver: with it a WriterGroup's MaxNetworkMessageSize
                // makes the connection send chunk NetworkMessages.
                app = new PubSubApplication(
                    PubSubConfigurationSnapshot.Create(cfg, tp),
                    transports,
                    [new UadpEncoder(), new PubSubJsonEncoder()],
                    [new UadpDecoder(), new PubSubJsonDecoder()],
                    policies,
                    new PubSubScheduler(telemetry, tp),
                    new DataSetMetaDataRegistry(),
                    diagnostics,
                    telemetry,
                    tp,
                    sources,
                    sinks,
                    resolver,
                    MaxNetworkMessageSize);
                await app.StartAsync(ct).ConfigureAwait(false);
            }
            catch (Exception)
            {
                await sp.DisposeAsync().ConfigureAwait(false);
                throw;
            }
            Console.Error.WriteLine("[dotnet] info: pubsub: configuration applied (" + Summary(cfg) + ")");
            return new PubSubServer(app, sp, disposables);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await m_app.StopAsync().ConfigureAwait(false);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] warn: pubsub stop: " + e.Message);
            }
            await m_app.DisposeAsync().ConfigureAwait(false);
            await m_services.DisposeAsync().ConfigureAwait(false);
            foreach (IDisposable d in m_disposables)
            {
                d.Dispose();
            }
        }

        // ------------------------------------------------------------------
        // the file
        // ------------------------------------------------------------------

        /// <summary>Decodes a PubSubConfigurationDataType in the OPC UA 1.05 JSON encoding (§14.2).</summary>
        public static PubSubConfigurationDataType Decode(string json, IServiceMessageContext context)
        {
            var cfg = new PubSubConfigurationDataType();
            try
            {
                // ParseStrict off: ExtensionObjects in the {"UaTypeId", "UaBody"} form are accepted
                // besides the 1.05 in-situ form.
                using var d = new JsonDecoder(json, context, new JsonDecoderOptions { ParseStrict = false });
                cfg.Decode(d);
            }
            catch (Exception e) when (e is ServiceResultException or JsonException or FormatException)
            {
                throw new PubSubConfigException("configuration: " + e.Message);
            }
            CheckBodies(cfg);
            return cfg;
        }

        /// <summary>Every ExtensionObject must have been decoded into its structure.</summary>
        private static void CheckBodies(PubSubConfigurationDataType cfg)
        {
            void Check(ExtensionObject eo, string where)
            {
                if (!eo.IsNull && eo.Body is not IEncodeable)
                {
                    throw new PubSubConfigException(where + ": ExtensionObject " + eo.TypeId + " could not be decoded");
                }
            }
            foreach (PublishedDataSetDataType pds in cfg.PublishedDataSets)
            {
                Check(pds.DataSetSource, "PublishedDataSet " + pds.Name + " DataSetSource");
            }
            foreach (PubSubConnectionDataType c in cfg.Connections)
            {
                Check(c.Address, "Connection " + c.Name + " Address");
                Check(c.TransportSettings, "Connection " + c.Name + " TransportSettings");
                foreach (WriterGroupDataType wg in c.WriterGroups)
                {
                    Check(wg.TransportSettings, "WriterGroup " + wg.Name + " TransportSettings");
                    Check(wg.MessageSettings, "WriterGroup " + wg.Name + " MessageSettings");
                    foreach (DataSetWriterDataType w in wg.DataSetWriters)
                    {
                        Check(w.TransportSettings, "DataSetWriter " + w.Name + " TransportSettings");
                        Check(w.MessageSettings, "DataSetWriter " + w.Name + " MessageSettings");
                    }
                }
                foreach (ReaderGroupDataType rg in c.ReaderGroups)
                {
                    Check(rg.TransportSettings, "ReaderGroup " + rg.Name + " TransportSettings");
                    Check(rg.MessageSettings, "ReaderGroup " + rg.Name + " MessageSettings");
                    foreach (DataSetReaderDataType r in rg.DataSetReaders)
                    {
                        Check(r.TransportSettings, "DataSetReader " + r.Name + " TransportSettings");
                        Check(r.MessageSettings, "DataSetReader " + r.Name + " MessageSettings");
                        Check(r.SubscribedDataSet, "DataSetReader " + r.Name + " SubscribedDataSet");
                    }
                }
            }
        }

        private static MqttProtocolVersion ParseMqttVersion(JsonNode node)
        {
            if (node == null)
            {
                return MqttProtocolVersion.V500;
            }
            string v = node is JsonObject o && o["protocolVersion"] is JsonValue pv ? pv.ToString() : null;
            return v switch
            {
                null => MqttProtocolVersion.V500,
                "5" or "5.0" => MqttProtocolVersion.V500,
                "3.1.1" => MqttProtocolVersion.V311,
                "3.1" => MqttProtocolVersion.V310,
                _ => throw new PubSubConfigException("mqtt.protocolVersion must be \"5.0\", \"3.1.1\" or \"3.1\"")
            };
        }

        private static Dictionary<string, (IPubSubSecurityPolicy, byte[], uint)> ParseSecurityGroups(JsonNode node)
        {
            var groups = new Dictionary<string, (IPubSubSecurityPolicy, byte[], uint)>(StringComparer.Ordinal);
            if (node == null)
            {
                return groups;
            }
            if (node is not JsonArray arr)
            {
                throw new PubSubConfigException("\"securityGroups\" must be an array");
            }
            foreach (JsonNode g in arr)
            {
                if (g is not JsonObject o || o["securityGroupId"] is not JsonValue idv)
                {
                    throw new PubSubConfigException("securityGroups[]: missing \"securityGroupId\"");
                }
                string id = idv.ToString();
                string uri = o["securityPolicyUri"]?.ToString() ?? PubSubSecurityPolicyUri.PubSubAes256Ctr;
                IPubSubSecurityPolicy policy = PubSubSecurityPolicyRegistry.Default.GetByUri(uri);
                if (policy == null || uri == PubSubSecurityPolicyUri.None)
                {
                    throw new PubSubConfigException("securityGroups[" + id + "]: unknown securityPolicyUri " + uri);
                }
                byte[] key = null;
                uint tokenId = 0;
                if (o["keys"] is JsonArray keys && keys.Count > 0)
                {
                    JsonObject first = keys[0] as JsonObject ?? throw new PubSubConfigException("securityGroups[" + id + "].keys[0] is not an object");
                    tokenId = first["tokenId"]?.GetValue<uint>() ?? throw new PubSubConfigException("securityGroups[" + id + "].keys[0]: missing tokenId");
                    try
                    {
                        key = Convert.FromBase64String(first["key"]?.ToString() ?? string.Empty);
                    }
                    catch (FormatException)
                    {
                        throw new PubSubConfigException("securityGroups[" + id + "].keys[0].key is not Base64");
                    }
                    int want = policy.SigningKeyLength + policy.EncryptingKeyLength + KeyNonceLength;
                    if (key.Length != want)
                    {
                        throw new PubSubConfigException("securityGroups[" + id + "].keys[0].key has " + key.Length +
                            " bytes, " + uri + " needs " + want);
                    }
                }
                groups[id] = (policy, key, tokenId);
            }
            return groups;
        }

        /// <summary>SigningKey ‖ EncryptingKey ‖ KeyNonce, as GetSecurityKeys returns it.</summary>
        private static PubSubSecurityKey SplitKey(IPubSubSecurityPolicy policy, byte[] key, uint tokenId)
        {
            int s = policy.SigningKeyLength;
            int e = policy.EncryptingKeyLength;
            return new PubSubSecurityKey(
                tokenId,
                ByteString.From(key[..s]),
                ByteString.From(key[s..(s + e)]),
                ByteString.From(key[(s + e)..]),
                DateTimeUtc.Now,
                TimeSpan.FromDays(3650));
        }

        // ------------------------------------------------------------------
        // contract → Opc.Ua.PubSub
        // ------------------------------------------------------------------

        /// <summary>
        /// Adapts the contract configuration to Opc.Ua.PubSub 2.0.1 (§14.13): MQTT URL scheme,
        /// the receive-all UDP address, the WriterGroup unicast destination (a connection of its
        /// own), MessageReceiveTimeout 0, KeepAliveTime, static-key SecurityKeyServices and
        /// DeltaFrames.
        /// </summary>
        public static void Normalize(
            PubSubConfigurationDataType cfg,
            bool deltaFrames,
            IReadOnlyDictionary<string, (IPubSubSecurityPolicy Policy, byte[] Key, uint TokenId)> groups)
        {
            var connections = new List<PubSubConnectionDataType>();
            foreach (PubSubConnectionDataType c in cfg.Connections)
            {
                bool udp = c.TransportProfileUri == Profiles.PubSubUdpUadpTransport;
                if (c.Address.TryGetValue(out NetworkAddressUrlDataType addr) && addr != null && addr.Url != null)
                {
                    if (addr.Url.StartsWith("opc.mqtt://", StringComparison.OrdinalIgnoreCase))
                    {
                        addr.Url = "mqtt://" + addr.Url["opc.mqtt://".Length..];
                    }
                    if (udp)
                    {
                        addr.Url = ReceiveAll(addr.Url);
                    }
                    c.Address = new ExtensionObject(addr);
                }
                var keep = new List<WriterGroupDataType>();
                var split = new List<PubSubConnectionDataType>();
                foreach (WriterGroupDataType wg in c.WriterGroups)
                {
                    if (wg.KeepAliveTime < wg.PublishingInterval)
                    {
                        wg.KeepAliveTime = wg.PublishingInterval;
                    }
                    wg.SecurityKeyServices = SecurityKeyServices(wg.SecurityMode, wg.SecurityGroupId, groups);
                    if (wg.SecurityKeyServices.Count == 0)
                    {
                        wg.SecurityGroupId = null;
                    }
                    if (!deltaFrames)
                    {
                        foreach (DataSetWriterDataType w in wg.DataSetWriters)
                        {
                            w.KeyFrameCount = 1;
                        }
                    }
                    string dest = udp && wg.TransportSettings.TryGetValue(out DatagramWriterGroupTransport2DataType dt) && dt != null &&
                        dt.Address.TryGetValue(out NetworkAddressUrlDataType da) && da != null && !string.IsNullOrEmpty(da.Url)
                        ? da.Url
                        : null;
                    if (dest == null)
                    {
                        keep.Add(wg);
                        continue;
                    }
                    // Opc.Ua.PubSub sends to the connection address only: the WriterGroup's unicast
                    // destination becomes a send-only connection of its own (same PublisherId).
                    split.Add(new PubSubConnectionDataType
                    {
                        Name = c.Name + "/" + wg.Name,
                        Enabled = c.Enabled,
                        PublisherId = c.PublisherId,
                        TransportProfileUri = c.TransportProfileUri,
                        Address = new ExtensionObject(new NetworkAddressUrlDataType { Url = dest, NetworkInterface = addr?.NetworkInterface }),
                        ConnectionProperties = c.ConnectionProperties,
                        TransportSettings = c.TransportSettings,
                        WriterGroups = [wg],
                        ReaderGroups = []
                    });
                }
                c.WriterGroups = [.. keep];
                foreach (ReaderGroupDataType rg in c.ReaderGroups)
                {
                    rg.SecurityKeyServices = SecurityKeyServices(rg.SecurityMode, rg.SecurityGroupId, groups);
                    if (rg.SecurityKeyServices.Count == 0)
                    {
                        rg.SecurityGroupId = null;
                    }
                    foreach (DataSetReaderDataType r in rg.DataSetReaders)
                    {
                        if (r.MessageReceiveTimeout <= 0)
                        {
                            r.MessageReceiveTimeout = NoReceiveTimeoutMs;
                        }
                        // security is per ReaderGroup in the contract
                        r.SecurityMode = MessageSecurityMode.Invalid;
                        r.SecurityGroupId = null;
                        r.SecurityKeyServices = [];
                    }
                }
                if (udp && keep.Count > 0 && c.ReaderGroups.Count == 0 && addr != null && (IsWildcard(addr.Url) || IsMulticast(addr.Url)))
                {
                    // A publisher on a receive-all or multicast address: Opc.Ua.PubSub opens a
                    // connection without ReaderGroups send-only. An empty ReaderGroup makes it
                    // receive on the port (and join the group), so it answers discovery probes.
                    c.ReaderGroups = [new ReaderGroupDataType { Name = c.Name + "/probes", Enabled = true, DataSetReaders = [] }];
                }
                if (keep.Count > 0 || c.ReaderGroups.Count > 0 || split.Count == 0)
                {
                    connections.Add(c);
                }
                connections.AddRange(split);
            }
            cfg.Connections = [.. connections];
        }

        private static ArrayOf<EndpointDescription> SecurityKeyServices(
            MessageSecurityMode mode,
            string groupId,
            IReadOnlyDictionary<string, (IPubSubSecurityPolicy Policy, byte[] Key, uint TokenId)> groups)
        {
            if (mode is not (MessageSecurityMode.Sign or MessageSecurityMode.SignAndEncrypt))
            {
                return [];
            }
            if (string.IsNullOrEmpty(groupId) || !groups.ContainsKey(groupId))
            {
                throw new PubSubConfigException("SecurityGroupId \"" + groupId + "\" is not in \"securityGroups\"");
            }
            return [new EndpointDescription { EndpointUrl = StaticKeysPlaceholder }];
        }

        /// <summary>opc.udp://localhost:p (receive-all in the contract) → opc.udp://0.0.0.0:p.</summary>
        private static string ReceiveAll(string url)
        {
            const string scheme = "opc.udp://";
            if (!url.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            {
                return url;
            }
            string rest = url[scheme.Length..];
            if (rest.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase))
            {
                return scheme + "0.0.0.0" + rest["localhost".Length..];
            }
            if (rest.StartsWith(':'))
            {
                return scheme + "0.0.0.0" + rest;
            }
            return url;
        }

        private static bool IsMulticast(string url) =>
            Uri.TryCreate(url, UriKind.Absolute, out Uri u) &&
            System.Net.IPAddress.TryParse(u.Host.Trim('[', ']'), out System.Net.IPAddress ip) &&
            (ip.IsIPv6Multicast || (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && ip.GetAddressBytes()[0] is >= 224 and <= 239));

        /// <summary>
        /// The UDP transport options of the adapter. UdpTransportOptions.Ttl defaults to 1 and the
        /// stack applies it to unicast datagrams too (IP_TTL), so a datagram that crosses a router —
        /// a container publishing to the Docker host through its gateway — is dropped on the way.
        /// 64 is the usual unicast default of Linux and open62541.
        /// </summary>
        internal static UdpTransportOptions UdpOptions() => new() { Ttl = 64 };

        private static bool IsWildcard(string url) =>
            url.StartsWith("opc.udp://0.0.0.0:", StringComparison.OrdinalIgnoreCase) ||
            url.StartsWith("opc.udp://[::]:", StringComparison.OrdinalIgnoreCase);

        /// <summary>The smallest MaxNetworkMessageSize of the connection's WriterGroups (0 = no chunking).</summary>
        private static int MaxNetworkMessageSize(PubSubConnectionDataType c)
        {
            uint min = 0;
            foreach (WriterGroupDataType wg in c.WriterGroups)
            {
                if (wg.MaxNetworkMessageSize > 0 && (min == 0 || wg.MaxNetworkMessageSize < min))
                {
                    min = wg.MaxNetworkMessageSize;
                }
            }
            return (int)Math.Min(min, int.MaxValue);
        }

        private static string Summary(PubSubConfigurationDataType cfg)
        {
            int wgs = 0, writers = 0, rgs = 0, readers = 0;
            foreach (PubSubConnectionDataType c in cfg.Connections)
            {
                wgs += c.WriterGroups.Count;
                rgs += c.ReaderGroups.Count;
                foreach (WriterGroupDataType wg in c.WriterGroups)
                {
                    writers += wg.DataSetWriters.Count;
                }
                foreach (ReaderGroupDataType rg in c.ReaderGroups)
                {
                    readers += rg.DataSetReaders.Count;
                }
            }
            return string.Create(CultureInfo.InvariantCulture,
                $"{cfg.PublishedDataSets.Count} PublishedDataSets, {cfg.Connections.Count} connections, {wgs} WriterGroups, {writers} DataSetWriters, {rgs} ReaderGroups, {readers} DataSetReaders");
        }
    }

    /// <summary>A PublishedDataItems data set sampled from the fixture variables.</summary>
    internal sealed class FixtureDataSetSource : IPublishedDataSetSource
    {
        private readonly PublishedDataSetDataType m_pds;
        private readonly InteropNodeManager m_nodes;
        private readonly ArrayOf<PublishedVariableDataType> m_items;

        public FixtureDataSetSource(PublishedDataSetDataType pds, InteropNodeManager nodes)
        {
            m_pds = pds;
            m_nodes = nodes;
            if (pds.DataSetSource.IsNull)
            {
                m_items = [];
            }
            else if (pds.DataSetSource.TryGetValue(out PublishedDataItemsDataType items) && items != null)
            {
                m_items = items.PublishedData;
            }
            else
            {
                throw new PubSubConfigException("PublishedDataSet " + pds.Name + ": only PublishedDataItemsDataType is supported");
            }
        }

        /// <summary>The configured DataSetMetaData; without fields, one per published variable.</summary>
        public DataSetMetaDataType BuildMetaData()
        {
            DataSetMetaDataType md = m_pds.DataSetMetaData ?? new DataSetMetaDataType { Name = m_pds.Name };
            if (md.Fields.Count == 0 && m_items.Count > 0)
            {
                var fields = new List<FieldMetaData>();
                foreach (PublishedVariableDataType pv in m_items)
                {
                    BaseDataVariableState v = m_nodes.FindVariable(pv.PublishedVariable);
                    Variant value = v?.Value ?? Variant.Null;
                    fields.Add(new FieldMetaData
                    {
                        Name = v?.BrowseName.Name ?? pv.PublishedVariable.ToString(),
                        BuiltInType = (byte)Canonical.BuiltInId(value),
                        DataType = v?.DataType ?? DataTypeIds.BaseDataType,
                        ValueRank = v?.ValueRank ?? ValueRanks.Scalar,
                        DataSetFieldId = new Uuid(Guid.NewGuid())
                    });
                }
                md.Fields = [.. fields];
            }
            md.ConfigurationVersion ??= new ConfigurationVersionDataType();
            return md;
        }

        public ValueTask<PublishedDataSetSnapshot> SampleAsync(DataSetMetaDataType metaData, CancellationToken cancellationToken = default)
        {
            var fields = new List<DataSetField>(m_items.Count);
            for (int i = 0; i < m_items.Count; i++)
            {
                PublishedVariableDataType pv = m_items[i];
                DataValue dv = pv.AttributeId is 0 or Attributes.Value
                    ? m_nodes.ReadValue(pv.PublishedVariable)
                    : new DataValue(Variant.Null, StatusCodes.BadAttributeIdInvalid, DateTimeUtc.MinValue, DateTimeUtc.Now);
                fields.Add(new DataSetField
                {
                    Name = metaData != null && i < metaData.Fields.Count ? metaData.Fields[i].Name ?? string.Empty : string.Empty,
                    FieldIndex = i,
                    Value = dv.WrappedValue,
                    StatusCode = dv.StatusCode,
                    SourceTimestamp = dv.SourceTimestamp,
                    ServerTimestamp = dv.ServerTimestamp
                });
            }
            return new ValueTask<PublishedDataSetSnapshot>(new PublishedDataSetSnapshot(
                metaData?.ConfigurationVersion ?? new ConfigurationVersionDataType(),
                [.. fields],
                DateTimeUtc.Now));
        }
    }

    /// <summary>TargetVariables writes into the fixture variables.</summary>
    internal sealed class FixtureTargetWriter : ITargetVariableWriter
    {
        private readonly InteropNodeManager m_nodes;

        public FixtureTargetWriter(InteropNodeManager nodes)
        {
            m_nodes = nodes;
        }

        public ValueTask<StatusCode> WriteAsync(NodeId nodeId, uint attributeId, string writeIndexRange, DataValue value, CancellationToken cancellationToken = default)
        {
            StatusCode sc = string.IsNullOrEmpty(writeIndexRange)
                ? m_nodes.WriteValue(nodeId, attributeId == 0 ? Attributes.Value : attributeId, value)
                : StatusCodes.BadIndexRangeInvalid;
            if (StatusCode.IsBad(sc))
            {
                Console.Error.WriteLine("[dotnet] warn: pubsub: write " + nodeId + ": " + StatusNames.Name(sc.Code));
            }
            return new ValueTask<StatusCode>(sc);
        }
    }

    /// <summary>
    /// Opc.Ua.PubSub.Mqtt 2.0.1 subscribes only the default discovery topics
    /// (opcua/&lt;enc&gt;/metadata|application|…/#), never the QueueName of a DataSetReader, so
    /// a subscriber would receive nothing. This factory adds the BrokerDataSetReaderTransport
    /// (and ReaderGroup) QueueNames to MqttBrokerTransport.Subscriptions before it is opened.
    /// </summary>
    internal sealed class MqttReaderTopicsFactory : IPubSubTransportFactory
    {
        private readonly IPubSubTransportFactory m_inner;

        public MqttReaderTopicsFactory(IPubSubTransportFactory inner)
        {
            m_inner = inner;
        }

        public string TransportProfileUri => m_inner.TransportProfileUri;

        public IPubSubTransport Create(PubSubConnectionDataType connection, ITelemetryContext telemetry, TimeProvider timeProvider)
        {
            IPubSubTransport t = m_inner.Create(connection, telemetry, timeProvider);
            if (t is MqttBrokerTransport mqtt)
            {
                foreach (ReaderGroupDataType rg in connection.ReaderGroups)
                {
                    Add(mqtt, rg.TransportSettings);
                    foreach (DataSetReaderDataType r in rg.DataSetReaders)
                    {
                        Add(mqtt, r.TransportSettings);
                    }
                }
            }
            return t;
        }

        private static void Add(MqttBrokerTransport mqtt, ExtensionObject settings)
        {
            if (!settings.TryGetValue(out BrokerDataSetReaderTransportDataType b) || b == null || string.IsNullOrEmpty(b.QueueName))
            {
                return;
            }
            MqttQualityOfService qos = b.RequestedDeliveryGuarantee switch
            {
                BrokerTransportQualityOfService.BestEffort or BrokerTransportQualityOfService.AtMostOnce => MqttQualityOfService.AtMostOnce,
                BrokerTransportQualityOfService.ExactlyOnce => MqttQualityOfService.ExactlyOnce,
                BrokerTransportQualityOfService.AtLeastOnce => MqttQualityOfService.AtLeastOnce,
                _ => mqtt.Options.Topics.DefaultQos
            };
            if (mqtt.Subscriptions.All(s => s.Topic != b.QueueName))
            {
                mqtt.Subscriptions.Add(new MqttTopicFilter(b.QueueName, qos));
            }
        }
    }
}
