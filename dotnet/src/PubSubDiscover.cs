// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Opc.Ua;
using Opc.Ua.PubSub.Application;
using Opc.Ua.PubSub.Configuration;
using Opc.Ua.PubSub.DataSets;
using Opc.Ua.PubSub.Diagnostics;
using Opc.Ua.PubSub.Encoding;
using Opc.Ua.PubSub.Encoding.Uadp;
using Opc.Ua.PubSub.MetaData;
using Opc.Ua.PubSub.Scheduling;
using Opc.Ua.PubSub.Security.Policies;
using Opc.Ua.PubSub.Transports;
using Opc.Ua.PubSub.Udp;

namespace OpcUaInterop
{
    /// <summary>
    /// client pubsub-discover (docs/CLIENT_CONTRACT.md §14.13): a UADP discovery probe of
    /// Opc.Ua.PubSub (IPubSubApplication.RequestDiscoveryAsync) on a datagram connection, and the
    /// announcements that answered it.
    /// </summary>
    internal static class PubSubDiscover
    {
        private const string Op = "pubsub-discover";

        public static async Task<int> RunAsync(Args a)
        {
            string url = a.Get("--url") ?? throw new InputException("missing --url opc.udp://<host>:<port>");
            if (!url.StartsWith("opc.udp://", StringComparison.OrdinalIgnoreCase))
            {
                throw new InputException("--url must be an opc.udp:// address");
            }
            string typeName = a.Get("--type") ?? "DataSetMetaData";
            UadpDiscoveryType type = typeName switch
            {
                "DataSetMetaData" => UadpDiscoveryType.DataSetMetaData,
                "DataSetWriterConfiguration" => UadpDiscoveryType.DataSetWriterConfiguration,
                _ => throw new InputException("--type must be DataSetMetaData or DataSetWriterConfiguration")
            };
            var ids = new List<ushort>();
            foreach (string s in (a.Get("--writer-ids") ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                ids.Add(ushort.TryParse(s, System.Globalization.NumberStyles.None, Inv.C, out ushort id)
                    ? id
                    : throw new InputException("--writer-ids: invalid DataSetWriterId " + s));
            }
            int timeoutMs = a.GetInt("--timeout-ms", 3000);
            Variant publisherId = a.Get("--publisher-id") is string pid
                ? new Variant(ushort.TryParse(pid, System.Globalization.NumberStyles.None, Inv.C, out ushort p)
                    ? p
                    : throw new InputException("--publisher-id must be a UInt16"))
                : Variant.Null;

            // One connection without groups: Opc.Ua.PubSub opens it for sending and receiving on
            // the port of --url and sends the probe to --url.
            var cfg = new PubSubConfigurationDataType
            {
                Enabled = true,
                PublishedDataSets = [],
                Connections =
                [
                    new PubSubConnectionDataType
                    {
                        Name = "Discover",
                        Enabled = true,
                        PublisherId = publisherId,
                        TransportProfileUri = Profiles.PubSubUdpUadpTransport,
                        Address = new ExtensionObject(new NetworkAddressUrlDataType { Url = url }),
                        WriterGroups = [],
                        ReaderGroups = []
                    }
                ]
            };
            ITelemetryContext telemetry = Telemetry.Create("dotnet");
            TimeProvider tp = TimeProvider.System;
            var diagnostics = new PubSubDiagnostics(PubSubDiagnosticsLevel.Low, tp);
            await using var app = new PubSubApplication(
                PubSubConfigurationSnapshot.Create(cfg, tp),
                [new UdpPubSubTransportFactory(Options.Create(PubSubServer.UdpOptions()), diagnostics)],
                [new UadpEncoder()],
                [new UadpDecoder()],
                [.. PubSubSecurityPolicyRegistry.Default.Policies],
                new PubSubScheduler(telemetry, tp),
                new DataSetMetaDataRegistry(),
                diagnostics,
                telemetry,
                tp);
            await app.StartAsync().ConfigureAwait(false);
            PubSubDiscoveryResult r;
            try
            {
                r = await app.RequestDiscoveryAsync(
                    new PubSubDiscoveryRequest { DiscoveryType = type, DataSetWriterIds = [.. ids] },
                    TimeSpan.FromMilliseconds(timeoutMs)).ConfigureAwait(false);
            }
            finally
            {
                await app.StopAsync().ConfigureAwait(false);
            }

            var o = new JsonObject
            {
                ["url"] = url,
                ["type"] = typeName,
                ["dataSetWriterIds"] = new JsonArray([.. ids.Select(x => (JsonNode)JsonValue.Create(x))]),
                ["dataSetMetaData"] = Json.Arr(r.DataSetMetaDataEntries.ToArray().Select(MetaDataJson)),
                ["writerConfigurations"] = Json.Arr(r.WriterConfigurations.ToArray().Select(WriterJson))
            };
            int found = r.DataSetMetaDataEntries.Count + r.WriterConfigurations.Count;
            var result = new Result(Op).Add(o);
            if (found == 0)
            {
                result.Success(false).ServiceResult(StatusCodes.BadTimeout).Error("timeout", "no announcement within " + timeoutMs + " ms");
                result.Print();
                return 7;
            }
            result.Print();
            return 0;
        }

        private static JsonNode MetaDataJson(PubSubDataSetMetaDataDiscoveryResult m)
        {
            var o = new JsonObject
            {
                ["publisherId"] = PubSubCodec.DescribePublisherId(m.PublisherId, false),
                ["writerGroupId"] = m.WriterGroupId,
                ["dataSetWriterId"] = m.DataSetWriterId,
                ["statusCode"] = StatusNames.Json(m.StatusCode)
            };
            if (m.DataSetMetaData is DataSetMetaDataType md)
            {
                o["metaData"] = new JsonObject
                {
                    ["name"] = md.Name,
                    ["configurationVersion"] = md.ConfigurationVersion == null ? null : new JsonObject
                    {
                        ["majorVersion"] = md.ConfigurationVersion.MajorVersion,
                        ["minorVersion"] = md.ConfigurationVersion.MinorVersion
                    },
                    ["fields"] = Json.Arr(md.Fields.ToArray().Select(f => (JsonNode)new JsonObject
                    {
                        ["name"] = f.Name,
                        ["builtInType"] = f.BuiltInType,
                        ["dataType"] = Canonical.NodeId(f.DataType),
                        ["valueRank"] = f.ValueRank
                    }))
                };
            }
            return o;
        }

        private static JsonNode WriterJson(PubSubDataSetWriterConfigurationDiscoveryResult w)
        {
            var o = new JsonObject
            {
                ["publisherId"] = PubSubCodec.DescribePublisherId(w.PublisherId, false),
                ["writerGroupId"] = w.WriterGroupId,
                ["dataSetWriterIds"] = new JsonArray([.. w.DataSetWriterIds.ToArray().Select(x => (JsonNode)JsonValue.Create(x))]),
                ["statusCode"] = StatusNames.Json(w.StatusCode)
            };
            if (w.WriterConfiguration is WriterGroupDataType g)
            {
                o["writerGroup"] = new JsonObject
                {
                    ["name"] = g.Name,
                    ["writerGroupId"] = g.WriterGroupId,
                    ["publishingInterval"] = g.PublishingInterval,
                    ["dataSetWriters"] = Json.Arr(g.DataSetWriters.ToArray().Select(d => (JsonNode)new JsonObject
                    {
                        ["name"] = d.Name,
                        ["dataSetWriterId"] = d.DataSetWriterId,
                        ["dataSetName"] = d.DataSetName
                    }))
                };
            }
            return o;
        }
    }
}
