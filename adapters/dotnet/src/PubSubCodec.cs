// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.PubSub.Diagnostics;
using Opc.Ua.PubSub.Encoding;
using Opc.Ua.PubSub.Encoding.Json;
using Opc.Ua.PubSub.Encoding.Uadp;
using Opc.Ua.PubSub.MetaData;
using PubSubJsonDecoder = Opc.Ua.PubSub.Encoding.Json.JsonDecoder;
using PubSubJsonEncoder = Opc.Ua.PubSub.Encoding.Json.JsonEncoder;
using JsonNetworkMessage = Opc.Ua.PubSub.Encoding.Json.JsonNetworkMessage;
using JsonDataSetMessage = Opc.Ua.PubSub.Encoding.Json.JsonDataSetMessage;
using UaJsonDecoder = Opc.Ua.JsonDecoder;

namespace OpcUaInterop
{
    /// <summary>
    /// codec pubsub-uadp-encode | -decode | pubsub-json-encode | -decode (docs/CONTAINER_CONTRACT.md
    /// §14.9): Opc.Ua.PubSub's UadpEncoder / UadpDecoder / JsonEncoder / JsonDecoder on the
    /// NetworkMessage description. .NET specifics in §14.13.
    /// </summary>
    internal static class PubSubCodec
    {
        private const string Op = "codec";

        public static readonly string[] Operations =
            ["pubsub-uadp-encode", "pubsub-uadp-decode", "pubsub-json-encode", "pubsub-json-decode"];

        /// <summary>A codec failure of the stack (exit 4, serviceResult = the status).</summary>
        private sealed class CodecFailure : Exception
        {
            public CodecFailure(StatusCode code, string message) : base(message)
            {
                Code = code;
            }

            public StatusCode Code { get; }
        }

        public static async Task<int> RunAsync(string action, Args a)
        {
            if (!Operations.Contains(action))
            {
                throw new InputException("unknown codec operation " + action);
            }
            string doc = CodecCommand.ReadDocument(a);
            string metaText = a.Get("--metadata");
            if (metaText == null && a.Get("--metadata-file") is string mf)
            {
                metaText = File.ReadAllText(mf);
            }
            MetaData meta = MetaData.Parse(metaText);
            bool uadp = action.StartsWith("pubsub-uadp", StringComparison.Ordinal);
            var o = new JsonObject { ["action"] = action, ["mapping"] = uadp ? "uadp" : "json" };
            try
            {
                if (action.EndsWith("-encode", StringComparison.Ordinal))
                {
                    JsonObject desc = ParseObject(doc, "description");
                    PubSubNetworkMessage nm = uadp ? ToUadp(desc, meta) : ToJson(desc);
                    // UADP needs DataSetMetaData for RawData; JSON without --metadata stays self-describing
                    // (JsonEncoder drops UaType for fields that match the metadata).
                    if (meta.IsEmpty && uadp)
                    {
                        meta = MetaData.FromMessage(nm);
                    }
                    byte[] bytes = await EncodeAsync(nm, meta).ConfigureAwait(false);
                    o["statusCode"] = StatusNames.Json(StatusCodes.Good);
                    o["encoded"] = uadp ? Convert.ToBase64String(bytes) : Encoding.UTF8.GetString(bytes);
                    o["length"] = bytes.Length;
                }
                else
                {
                    byte[] input = uadp ? FromBase64(doc) : Encoding.UTF8.GetBytes(doc);
                    PubSubNetworkMessage nm = await DecodeAsync(input, uadp, meta).ConfigureAwait(false);
                    o["statusCode"] = StatusNames.Json(StatusCodes.Good);
                    o["networkMessage"] = uadp ? DescribeUadp((UadpNetworkMessage)nm, meta) : DescribeJson((JsonNetworkMessage)nm, meta);
                    try
                    {
                        byte[] re = await EncodeAsync(nm, meta.IsEmpty && uadp ? MetaData.FromMessage(nm) : meta).ConfigureAwait(false);
                        o["reencoded"] = uadp ? Convert.ToBase64String(re) : Encoding.UTF8.GetString(re);
                        o["reencodeStatusCode"] = StatusNames.Json(StatusCodes.Good);
                    }
                    catch (Exception e) when (e is not InputException)
                    {
                        o["reencoded"] = null;
                        o["reencodeStatusCode"] = StatusNames.Json(Status(e));
                    }
                }
            }
            catch (InputException)
            {
                throw;
            }
            catch (Exception e)
            {
                StatusCode sc = Status(e);
                o["statusCode"] = StatusNames.Json(sc);
                new Result(Op).Success(false).ServiceResult(sc).Add(o).Error("service", e.Message).Print();
                return 4;
            }
            new Result(Op).Add(o).Print();
            return 0;
        }

        /// <summary>Decodes a UADP NetworkMessage and encodes it again (self-test).</summary>
        internal static async Task<string> ReencodeUadpAsync(string base64)
        {
            PubSubNetworkMessage nm = await DecodeAsync(FromBase64(base64), true, MetaData.Parse(null)).ConfigureAwait(false);
            return Convert.ToBase64String(await EncodeAsync(nm, MetaData.FromMessage(nm)).ConfigureAwait(false));
        }

        /// <summary>Encodes a UADP NetworkMessage description (self-test).</summary>
        internal static async Task<string> EncodeUadpAsync(string description)
        {
            MetaData meta = MetaData.Parse(null);
            PubSubNetworkMessage nm = ToUadp(ParseObject(description, "description"), meta);
            return Convert.ToBase64String(await EncodeAsync(nm, MetaData.FromMessage(nm)).ConfigureAwait(false));
        }

        private static StatusCode Status(Exception e) => e switch
        {
            CodecFailure f => f.Code,
            ServiceResultException sre => sre.StatusCode,
            _ => StatusCodes.BadEncodingError
        };

        private static JsonObject ParseObject(string text, string what)
        {
            try
            {
                return JsonNode.Parse(text) as JsonObject ?? throw new InputException(what + " is not a JSON object");
            }
            catch (JsonException e)
            {
                throw new InputException("malformed " + what + ": " + e.Message);
            }
        }

        private static byte[] FromBase64(string text)
        {
            try
            {
                return Convert.FromBase64String(text.Trim());
            }
            catch (FormatException)
            {
                throw new InputException("the UADP NetworkMessage is not Base64");
            }
        }

        private static PubSubNetworkMessageContext Context(MetaData meta) =>
            new(Codec.Context, meta, new PubSubDiagnostics(PubSubDiagnosticsLevel.Low), TimeProvider.System);

        private static async Task<byte[]> EncodeAsync(PubSubNetworkMessage nm, MetaData meta)
        {
            INetworkMessageEncoder enc = nm is UadpNetworkMessage ? new UadpEncoder() : new PubSubJsonEncoder();
            ReadOnlyMemory<byte> b = await enc.EncodeAsync(nm, Context(meta)).ConfigureAwait(false);
            return b.ToArray();
        }

        private static async Task<PubSubNetworkMessage> DecodeAsync(byte[] input, bool uadp, MetaData meta)
        {
            if (uadp)
            {
                if (!UadpDecoder.TryReadOuterPrefix(input, out _, out bool secured, out bool chunk, out _, out _))
                {
                    throw new CodecFailure(StatusCodes.BadDecodingError, "not a UADP NetworkMessage");
                }
                if (secured)
                {
                    throw new CodecFailure(StatusCodes.BadNotImplemented,
                        "UadpDecoder decodes a secured NetworkMessage only through the security wrapper (keys); the codec has none");
                }
                if (chunk)
                {
                    throw new CodecFailure(StatusCodes.BadNotImplemented,
                        "chunk NetworkMessages are reassembled by the connection, not by UadpDecoder");
                }
            }
            INetworkMessageDecoder dec = uadp ? new UadpDecoder() : new PubSubJsonDecoder();
            PubSubNetworkMessage nm = await dec.TryDecodeAsync(input, Context(meta)).ConfigureAwait(false);
            return nm switch
            {
                null => throw new CodecFailure(StatusCodes.BadDecodingError, "the stack rejected the NetworkMessage"),
                UadpNetworkMessage or JsonNetworkMessage => nm,
                _ => throw new CodecFailure(StatusCodes.BadNotImplemented, "not a DataSetMessage NetworkMessage: " + nm.GetType().Name)
            };
        }

        // ------------------------------------------------------------------
        // description → NetworkMessage
        // ------------------------------------------------------------------

        private static UadpNetworkMessage ToUadp(JsonObject d, MetaData meta)
        {
            UadpNetworkMessageContentMask mask = 0;
            if (d["version"] is JsonNode v && v.GetValue<int>() != 1)
            {
                throw new CodecFailure(StatusCodes.BadNotImplemented, "UadpEncoder supports UADP version 1 only");
            }
            if (d["security"] != null || d["securityFooter"] != null)
            {
                throw new CodecFailure(StatusCodes.BadNotImplemented,
                    "UadpEncoder writes the SecurityHeader only through the security wrapper (keys); the codec has none");
            }
            if (d["chunk"] is JsonNode ch && ch.GetValue<bool>())
            {
                throw new CodecFailure(StatusCodes.BadNotImplemented, "chunk NetworkMessages are produced by the connection");
            }
            PublisherId pid = PublisherId.Null;
            if (d["publisherId"] is JsonObject p)
            {
                pid = ParsePublisherId(p);
                mask |= UadpNetworkMessageContentMask.PublisherId;
            }
            Uuid classId = Uuid.Empty;
            if (d["dataSetClassId"] is JsonNode cid)
            {
                classId = new Uuid(Guid.Parse(cid.GetValue<string>()));
                mask |= UadpNetworkMessageContentMask.DataSetClassId;
            }
            ushort? wg = null;
            uint groupVersion = 0;
            ushort nmn = 0, seq = 0;
            if (d["groupHeader"] is JsonObject g)
            {
                mask |= UadpNetworkMessageContentMask.GroupHeader;
                if (g["writerGroupId"] is JsonNode x)
                {
                    wg = x.GetValue<ushort>();
                    mask |= UadpNetworkMessageContentMask.WriterGroupId;
                }
                if (g["groupVersion"] is JsonNode gv)
                {
                    groupVersion = gv.GetValue<uint>();
                    mask |= UadpNetworkMessageContentMask.GroupVersion;
                }
                if (g["networkMessageNumber"] is JsonNode n)
                {
                    nmn = n.GetValue<ushort>();
                    mask |= UadpNetworkMessageContentMask.NetworkMessageNumber;
                }
                if (g["sequenceNumber"] is JsonNode s)
                {
                    seq = s.GetValue<ushort>();
                    mask |= UadpNetworkMessageContentMask.SequenceNumber;
                }
            }
            if (d["payloadHeader"] is not JsonNode ph || ph.GetValue<bool>())
            {
                mask |= UadpNetworkMessageContentMask.PayloadHeader;
            }
            DateTimeUtc ts = default;
            if (d["timestamp"] is JsonNode t)
            {
                ts = ParseTime(t);
                mask |= UadpNetworkMessageContentMask.Timestamp;
            }
            ushort pico = 0;
            if (d["picoseconds"] is JsonNode pc)
            {
                pico = pc.GetValue<ushort>();
                mask |= UadpNetworkMessageContentMask.PicoSeconds;
            }
            var promoted = new List<DataSetField>();
            if (d["promotedFields"] is JsonArray pf)
            {
                mask |= UadpNetworkMessageContentMask.PromotedFields;
                foreach (JsonNode f in pf)
                {
                    promoted.Add(new DataSetField { Value = FieldValue((JsonObject)f) });
                }
            }
            var messages = new List<PubSubDataSetMessage>();
            foreach (JsonNode m in d["messages"] as JsonArray ?? [])
            {
                messages.Add(ToUadpMessage((JsonObject)m));
            }
            return new UadpNetworkMessage
            {
                ContentMask = mask,
                PublisherId = pid,
                WriterGroupId = wg,
                GroupVersion = groupVersion,
                NetworkMessageNumber = nmn,
                SequenceNumber = seq,
                DataSetClassId = classId,
                Timestamp = ts,
                PicoSeconds = pico,
                PromotedFields = [.. promoted],
                DataSetMessages = [.. messages]
            };
        }

        private static UadpDataSetMessage ToUadpMessage(JsonObject m)
        {
            if (m["valid"] is JsonNode valid && !valid.GetValue<bool>())
            {
                throw new CodecFailure(StatusCodes.BadNotImplemented, "UadpEncoder always sets DataSetFlags1 MessageIsValid");
            }
            UadpDataSetMessageContentMask mask = 0;
            PubSubDataSetMessageType type = MessageType(m["messageType"]?.GetValue<string>() ?? "KeyFrame");
            PubSubFieldEncoding enc = FieldEncoding(m["fieldEncoding"]?.GetValue<string>() ?? "Variant");
            uint seq = 0;
            if (m["sequenceNumber"] is JsonNode s)
            {
                seq = s.GetValue<uint>();
                mask |= UadpDataSetMessageContentMask.SequenceNumber;
            }
            DateTimeUtc ts = default;
            if (m["timestamp"] is JsonNode t)
            {
                ts = ParseTime(t);
                mask |= UadpDataSetMessageContentMask.Timestamp;
            }
            ushort pico = 0;
            if (m["picoseconds"] is JsonNode p)
            {
                pico = p.GetValue<ushort>();
                mask |= UadpDataSetMessageContentMask.PicoSeconds;
            }
            StatusCode status = StatusCodes.Good;
            if (m["status"] is JsonNode st)
            {
                status = new StatusCode(st.GetValue<uint>() << 16);
                mask |= UadpDataSetMessageContentMask.Status;
            }
            var cv = new ConfigurationVersionDataType();
            if (m["configVersion"] is JsonObject c)
            {
                if (c["majorVersion"] is JsonNode mj)
                {
                    cv.MajorVersion = mj.GetValue<uint>();
                    mask |= UadpDataSetMessageContentMask.MajorVersion;
                }
                if (c["minorVersion"] is JsonNode mn)
                {
                    cv.MinorVersion = mn.GetValue<uint>();
                    mask |= UadpDataSetMessageContentMask.MinorVersion;
                }
            }
            return new UadpDataSetMessage
            {
                DataSetWriterId = m["dataSetWriterId"]?.GetValue<ushort>() ?? 0,
                MessageType = type,
                FieldEncoding = enc,
                ContentMask = mask,
                SequenceNumber = seq,
                Timestamp = ts,
                PicoSeconds = pico,
                Status = status,
                MetaDataVersion = cv,
                Fields = [.. Fields(m["fields"] as JsonArray, enc)]
            };
        }

        private static JsonNetworkMessage ToJson(JsonObject d)
        {
            JsonNetworkMessageContentMask mask = JsonNetworkMessageContentMask.NetworkMessageHeader |
                JsonNetworkMessageContentMask.DataSetMessageHeader;
            PublisherId pid = PublisherId.Null;
            if (d["publisherId"] is JsonObject p)
            {
                pid = ParsePublisherId(p);
                mask |= JsonNetworkMessageContentMask.PublisherId;
            }
            Uuid classId = Uuid.Empty;
            if (d["dataSetClassId"] is JsonNode cid)
            {
                classId = new Uuid(Guid.Parse(cid.GetValue<string>()));
                mask |= JsonNetworkMessageContentMask.DataSetClassId;
            }
            var messages = new List<PubSubDataSetMessage>();
            foreach (JsonNode n in d["messages"] as JsonArray ?? [])
            {
                var m = (JsonObject)n;
                PubSubDataSetMessageType type = MessageType(m["messageType"]?.GetValue<string>() ?? "KeyFrame");
                if (type == PubSubDataSetMessageType.Event)
                {
                    throw new CodecFailure(StatusCodes.BadNotImplemented, "Event DataSetMessages");
                }
                PubSubFieldEncoding enc = FieldEncoding(m["fieldEncoding"]?.GetValue<string>() ?? "Variant");
                JsonDataSetMessageContentMask dm = JsonDataSetMessageContentMask.MessageType;
                if (m["dataSetWriterId"] != null)
                {
                    dm |= JsonDataSetMessageContentMask.DataSetWriterId;
                }
                uint seq = 0;
                if (m["sequenceNumber"] is JsonNode s)
                {
                    seq = s.GetValue<uint>();
                    dm |= JsonDataSetMessageContentMask.SequenceNumber;
                }
                DateTimeUtc ts = default;
                if (m["timestamp"] is JsonNode t)
                {
                    ts = ParseTime(t);
                    dm |= JsonDataSetMessageContentMask.Timestamp;
                }
                StatusCode status = StatusCodes.Good;
                if (m["status"] is JsonNode st)
                {
                    status = new StatusCode(st.GetValue<uint>());
                    dm |= JsonDataSetMessageContentMask.Status;
                }
                var cv = new ConfigurationVersionDataType();
                if (m["configVersion"] is JsonObject c)
                {
                    cv.MajorVersion = c["majorVersion"]?.GetValue<uint>() ?? 0;
                    cv.MinorVersion = c["minorVersion"]?.GetValue<uint>() ?? 0;
                    dm |= JsonDataSetMessageContentMask.MetaDataVersion;
                }
                messages.Add(new JsonDataSetMessage
                {
                    DataSetWriterId = m["dataSetWriterId"]?.GetValue<ushort>() ?? 0,
                    MessageType = type,
                    ContentMask = dm,
                    SequenceNumber = seq,
                    Timestamp = ts,
                    Status = status,
                    MetaDataVersion = cv,
                    Fields = [.. Fields(m["fields"] as JsonArray, enc)]
                });
            }
            return new JsonNetworkMessage
            {
                MessageId = d["messageId"]?.GetValue<string>() ?? string.Empty,
                ContentMask = mask,
                PublisherId = pid,
                DataSetClassId = classId,
                DataSetMessages = [.. messages]
            };
        }

        private static List<DataSetField> Fields(JsonArray fields, PubSubFieldEncoding enc)
        {
            var list = new List<DataSetField>();
            if (fields == null)
            {
                return list;
            }
            for (int i = 0; i < fields.Count; i++)
            {
                var f = (JsonObject)fields[i];
                var field = new DataSetField
                {
                    Name = f["name"]?.GetValue<string>() ?? string.Empty,
                    FieldIndex = f["index"]?.GetValue<int>() ?? -1,
                    Value = FieldValue(f),
                    Encoding = enc
                };
                if (enc == PubSubFieldEncoding.DataValue)
                {
                    field = field with
                    {
                        StatusCode = f["statusCode"] switch
                        {
                            JsonObject sc => new StatusCode(sc["code"]?.GetValue<uint>() ?? 0),
                            JsonValue n => new StatusCode(n.GetValue<uint>()),
                            _ => StatusCodes.Good
                        },
                        SourceTimestamp = f["sourceTimestamp"] is JsonNode st ? ParseTime(st) : default,
                        SourcePicoSeconds = f["sourcePicoseconds"]?.GetValue<ushort>() ?? 0,
                        ServerTimestamp = f["serverTimestamp"] is JsonNode sv ? ParseTime(sv) : default,
                        ServerPicoSeconds = f["serverPicoseconds"]?.GetValue<ushort>() ?? 0
                    };
                }
                list.Add(field);
            }
            return list;
        }

        private static Variant FieldValue(JsonObject f)
        {
            string type = f["dataType"]?.GetValue<string>() ?? throw new InputException("field without dataType");
            int[] dims = f["arrayDimensions"] is JsonArray a ? [.. a.Select(x => x.GetValue<int>())] : null;
            return CanonicalValue.Parse(type, f["value"], dims);
        }

        private static PublisherId ParsePublisherId(JsonObject p)
        {
            string type = p["type"]?.GetValue<string>() ?? throw new InputException("publisherId without type");
            JsonNode v = p["value"] ?? throw new InputException("publisherId without value");
            string text = v is JsonValue jv && jv.TryGetValue(out string s) ? s : v.ToJsonString();
            return type switch
            {
                "Byte" => PublisherId.FromByte(byte.Parse(text, Inv.C)),
                "UInt16" => PublisherId.FromUInt16(ushort.Parse(text, Inv.C)),
                "UInt32" => PublisherId.FromUInt32(uint.Parse(text, Inv.C)),
                "UInt64" => PublisherId.FromUInt64(ulong.Parse(text, Inv.C)),
                "String" => PublisherId.FromString(text),
                _ => throw new InputException("unknown publisherId type " + type)
            };
        }

        private static PubSubDataSetMessageType MessageType(string s) => s switch
        {
            "KeyFrame" => PubSubDataSetMessageType.KeyFrame,
            "DeltaFrame" => PubSubDataSetMessageType.DeltaFrame,
            "KeepAlive" => PubSubDataSetMessageType.KeepAlive,
            "Event" => PubSubDataSetMessageType.Event,
            _ => throw new InputException("unknown messageType " + s)
        };

        private static PubSubFieldEncoding FieldEncoding(string s) => s switch
        {
            "Variant" => PubSubFieldEncoding.Variant,
            "RawData" => PubSubFieldEncoding.RawData,
            "DataValue" => PubSubFieldEncoding.DataValue,
            _ => throw new InputException("unknown fieldEncoding " + s)
        };

        private static DateTimeUtc ParseTime(JsonNode t) =>
            new(DateTime.Parse(t.GetValue<string>(), Inv.C, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal));

        // ------------------------------------------------------------------
        // NetworkMessage → description
        // ------------------------------------------------------------------

        private static JsonObject DescribeUadp(UadpNetworkMessage nm, MetaData meta)
        {
            UadpNetworkMessageContentMask m = nm.ContentMask;
            var d = new JsonObject { ["mapping"] = "uadp", ["version"] = (int)nm.UadpVersion };
            if ((m & UadpNetworkMessageContentMask.PublisherId) != 0)
            {
                d["publisherId"] = DescribePublisherId(nm.PublisherId, false);
            }
            if ((m & UadpNetworkMessageContentMask.DataSetClassId) != 0)
            {
                d["dataSetClassId"] = nm.DataSetClassId.Guid.ToString("D");
            }
            if ((m & UadpNetworkMessageContentMask.GroupHeader) != 0)
            {
                var g = new JsonObject();
                if ((m & UadpNetworkMessageContentMask.WriterGroupId) != 0)
                {
                    g["writerGroupId"] = nm.WriterGroupId ?? 0;
                }
                if ((m & UadpNetworkMessageContentMask.GroupVersion) != 0)
                {
                    g["groupVersion"] = nm.GroupVersion;
                }
                if ((m & UadpNetworkMessageContentMask.NetworkMessageNumber) != 0)
                {
                    g["networkMessageNumber"] = nm.NetworkMessageNumber;
                }
                if ((m & UadpNetworkMessageContentMask.SequenceNumber) != 0)
                {
                    g["sequenceNumber"] = nm.SequenceNumber;
                }
                d["groupHeader"] = g;
            }
            bool payloadHeader = (m & UadpNetworkMessageContentMask.PayloadHeader) != 0;
            d["payloadHeader"] = payloadHeader;
            if ((m & UadpNetworkMessageContentMask.Timestamp) != 0)
            {
                d["timestamp"] = Canonical.Time7(nm.Timestamp);
            }
            if ((m & UadpNetworkMessageContentMask.PicoSeconds) != 0)
            {
                d["picoseconds"] = nm.PicoSeconds;
            }
            if ((m & UadpNetworkMessageContentMask.PromotedFields) != 0)
            {
                d["promotedFields"] = Json.Arr(nm.PromotedFields.ToArray().Select(f => DescribeField(f, null, null, false)));
            }
            d["chunk"] = false;
            var msgs = new JsonArray();
            foreach (PubSubDataSetMessage dsm in nm.DataSetMessages)
            {
                var u = (UadpDataSetMessage)dsm;
                var o = new JsonObject();
                if (payloadHeader)
                {
                    o["dataSetWriterId"] = u.DataSetWriterId;
                }
                o["messageType"] = u.MessageType.ToString();
                o["fieldEncoding"] = u.FieldEncoding.ToString();
                o["valid"] = true;
                UadpDataSetMessageContentMask dm = u.ContentMask;
                if ((dm & UadpDataSetMessageContentMask.SequenceNumber) != 0)
                {
                    o["sequenceNumber"] = u.SequenceNumber & 0xFFFF;
                }
                if ((dm & UadpDataSetMessageContentMask.Timestamp) != 0)
                {
                    o["timestamp"] = Canonical.Time7(u.Timestamp);
                }
                if ((dm & UadpDataSetMessageContentMask.PicoSeconds) != 0)
                {
                    o["picoseconds"] = u.PicoSeconds;
                }
                if ((dm & UadpDataSetMessageContentMask.Status) != 0)
                {
                    o["status"] = u.Status.Code >> 16;
                }
                if ((dm & (UadpDataSetMessageContentMask.MajorVersion | UadpDataSetMessageContentMask.MinorVersion)) != 0)
                {
                    var cv = new JsonObject();
                    if ((dm & UadpDataSetMessageContentMask.MajorVersion) != 0)
                    {
                        cv["majorVersion"] = u.MetaDataVersion.MajorVersion;
                    }
                    if ((dm & UadpDataSetMessageContentMask.MinorVersion) != 0)
                    {
                        cv["minorVersion"] = u.MetaDataVersion.MinorVersion;
                    }
                    o["configVersion"] = cv;
                }
                DescribeFields(o, u.MessageType, u.Fields, meta.Names(payloadHeader ? u.DataSetWriterId : (ushort)0),
                    u.FieldEncoding == PubSubFieldEncoding.DataValue);
                msgs.Add(o);
            }
            d["messages"] = msgs;
            return d;
        }

        private static JsonObject DescribeJson(JsonNetworkMessage nm, MetaData meta)
        {
            var d = new JsonObject { ["mapping"] = "json" };
            if (!string.IsNullOrEmpty(nm.MessageId))
            {
                d["messageId"] = nm.MessageId;
            }
            if (!nm.PublisherId.IsNull || (nm.ContentMask & JsonNetworkMessageContentMask.PublisherId) != 0)
            {
                d["publisherId"] = DescribePublisherId(nm.PublisherId, true);
            }
            if (nm.DataSetClassId != Uuid.Empty)
            {
                d["dataSetClassId"] = nm.DataSetClassId.Guid.ToString("D");
            }
            var msgs = new JsonArray();
            foreach (PubSubDataSetMessage dsm in nm.DataSetMessages)
            {
                var j = (JsonDataSetMessage)dsm;
                JsonDataSetMessageContentMask dm = j.ContentMask;
                var o = new JsonObject
                {
                    ["dataSetWriterId"] = j.DataSetWriterId,
                    ["messageType"] = j.MessageType.ToString(),
                    ["fieldEncoding"] = "DataValue",
                    ["valid"] = true
                };
                if ((dm & JsonDataSetMessageContentMask.SequenceNumber) != 0)
                {
                    o["sequenceNumber"] = j.SequenceNumber;
                }
                if ((dm & JsonDataSetMessageContentMask.Timestamp) != 0)
                {
                    o["timestamp"] = Canonical.Time7(j.Timestamp);
                }
                if ((dm & JsonDataSetMessageContentMask.Status) != 0)
                {
                    o["status"] = j.Status.Code;
                }
                if ((dm & JsonDataSetMessageContentMask.MetaDataVersion) != 0)
                {
                    o["configVersion"] = new JsonObject
                    {
                        ["majorVersion"] = j.MetaDataVersion.MajorVersion,
                        ["minorVersion"] = j.MetaDataVersion.MinorVersion
                    };
                }
                DescribeFields(o, j.MessageType, j.Fields, meta.Names(j.DataSetWriterId), true);
                msgs.Add(o);
            }
            d["messages"] = msgs;
            return d;
        }

        private static void DescribeFields(JsonObject o, PubSubDataSetMessageType type, ArrayOf<DataSetField> fields, IReadOnlyList<string> names, bool withDV)
        {
            if (type is PubSubDataSetMessageType.KeepAlive or PubSubDataSetMessageType.Event || fields.Count == 0)
            {
                return;
            }
            var arr = new JsonArray();
            for (int i = 0; i < fields.Count; i++)
            {
                DataSetField f = fields[i];
                int index = type == PubSubDataSetMessageType.DeltaFrame ? (f.FieldIndex >= 0 ? f.FieldIndex : i) : i;
                string name = !string.IsNullOrEmpty(f.Name) ? f.Name : names != null && index < names.Count ? names[index] : null;
                arr.Add(DescribeField(f, name, type == PubSubDataSetMessageType.DeltaFrame ? index : null, withDV));
            }
            o["fields"] = arr;
        }

        private static JsonObject DescribeField(DataSetField f, string name, int? index, bool withDV)
        {
            var o = new JsonObject();
            if (!string.IsNullOrEmpty(name))
            {
                o["name"] = name;
            }
            if (index is int i)
            {
                o["index"] = i;
            }
            Variant v = f.Value;
            o["dataType"] = v.IsNull ? "Null" : Canonical.DataTypeName(v);
            o["builtInType"] = Canonical.BuiltInId(v);
            if (Canonical.Dimensions(v) is int[] dims)
            {
                o["arrayDimensions"] = Canonical.DimsJson(dims);
            }
            o["value"] = Canonical.Value(v);
            if (withDV)
            {
                if (f.StatusCode.Code != 0)
                {
                    o["statusCode"] = StatusNames.Json(f.StatusCode);
                }
                if (Canonical.HasTime(f.SourceTimestamp))
                {
                    o["sourceTimestamp"] = Canonical.Time7(f.SourceTimestamp);
                }
                if (f.SourcePicoSeconds != 0)
                {
                    o["sourcePicoseconds"] = f.SourcePicoSeconds;
                }
                if (Canonical.HasTime(f.ServerTimestamp))
                {
                    o["serverTimestamp"] = Canonical.Time7(f.ServerTimestamp);
                }
                if (f.ServerPicoSeconds != 0)
                {
                    o["serverPicoseconds"] = f.ServerPicoSeconds;
                }
            }
            return o;
        }

        internal static JsonObject DescribePublisherId(PublisherId p, bool json)
        {
            string type;
            JsonNode value;
            if (p.TryGetString(out string s))
            {
                // JSON carries numeric PublisherIds as strings: a decimal one is reported as UInt64 (§14.9)
                if (json && s.Length > 0 && s.All(char.IsAsciiDigit) && ulong.TryParse(s, NumberStyles.None, Inv.C, out ulong n))
                {
                    return Json.Obj(("type", JsonValue.Create("UInt64")), ("value", JsonValue.Create(n.ToString(Inv.C))));
                }
                type = "String";
                value = JsonValue.Create(s);
            }
            else if (p.TryGetByte(out byte b) && p.Type == PublisherIdType.Byte)
            {
                type = json ? "UInt64" : "Byte";
                value = json ? JsonValue.Create(((ulong)b).ToString(Inv.C)) : JsonValue.Create(b);
            }
            else if (p.Type == PublisherIdType.UInt16 && p.TryGetUInt16(out ushort u16))
            {
                type = json ? "UInt64" : "UInt16";
                value = json ? JsonValue.Create(((ulong)u16).ToString(Inv.C)) : JsonValue.Create(u16);
            }
            else if (p.Type == PublisherIdType.UInt32 && p.TryGetUInt32(out uint u32))
            {
                type = json ? "UInt64" : "UInt32";
                value = json ? JsonValue.Create(((ulong)u32).ToString(Inv.C)) : JsonValue.Create(u32);
            }
            else if (p.TryGetUInt64(out ulong u64))
            {
                type = "UInt64";
                value = JsonValue.Create(u64.ToString(Inv.C));
            }
            else
            {
                type = p.Type.ToString();
                value = JsonValue.Create(p.ToString());
            }
            return Json.Obj(("type", JsonValue.Create(type)), ("value", value));
        }

        // ------------------------------------------------------------------
        // --metadata
        // ------------------------------------------------------------------

        /// <summary>
        /// The --metadata of the codec as the stack's metadata registry: the same DataSetMetaData
        /// for every key, or one per DataSetWriterId.
        /// </summary>
        private sealed class MetaData : IDataSetMetaDataRegistry
        {
            private readonly DataSetMetaDataType m_all;
            private readonly Dictionary<ushort, DataSetMetaDataType> m_byWriter;

            private MetaData(DataSetMetaDataType all, Dictionary<ushort, DataSetMetaDataType> byWriter)
            {
                m_all = all;
                m_byWriter = byWriter ?? [];
            }

            public bool IsEmpty => m_all == null && m_byWriter.Count == 0;

            public static MetaData Parse(string text)
            {
                if (string.IsNullOrWhiteSpace(text))
                {
                    return new MetaData(null, null);
                }
                JsonNode n;
                try
                {
                    n = JsonNode.Parse(text);
                }
                catch (JsonException e)
                {
                    throw new InputException("malformed --metadata: " + e.Message);
                }
                if (n is JsonArray arr)
                {
                    var map = new Dictionary<ushort, DataSetMetaDataType>();
                    foreach (JsonNode e in arr)
                    {
                        ushort w = e?["dataSetWriterId"]?.GetValue<ushort>() ?? throw new InputException("--metadata[]: missing dataSetWriterId");
                        map[w] = DecodeMeta(e["metaData"]?.ToJsonString() ?? throw new InputException("--metadata[]: missing metaData"));
                    }
                    return new MetaData(null, map);
                }
                return new MetaData(DecodeMeta(text), null);
            }

            /// <summary>Metadata built from the field values of the message (encode without --metadata).</summary>
            public static MetaData FromMessage(PubSubNetworkMessage nm)
            {
                var map = new Dictionary<ushort, DataSetMetaDataType>();
                foreach (PubSubDataSetMessage dsm in nm.DataSetMessages)
                {
                    if (map.ContainsKey(dsm.DataSetWriterId) || dsm.MessageType != PubSubDataSetMessageType.KeyFrame)
                    {
                        continue;
                    }
                    var fields = new List<FieldMetaData>();
                    for (int i = 0; i < dsm.Fields.Count; i++)
                    {
                        Variant v = dsm.Fields[i].Value;
                        int[] dims = Canonical.Dimensions(v);
                        fields.Add(new FieldMetaData
                        {
                            Name = string.IsNullOrEmpty(dsm.Fields[i].Name) ? "Field" + i.ToString(Inv.C) : dsm.Fields[i].Name,
                            BuiltInType = (byte)Canonical.BuiltInId(v),
                            DataType = new NodeId((uint)Canonical.BuiltInId(v)),
                            ValueRank = dims != null ? dims.Length : Canonical.ValueRank(v),
                            ArrayDimensions = dims != null ? [.. dims.Select(x => (uint)x)] : []
                        });
                    }
                    map[dsm.DataSetWriterId] = new DataSetMetaDataType { Name = "codec", Fields = [.. fields] };
                }
                return new MetaData(null, map);
            }

            private static DataSetMetaDataType DecodeMeta(string json)
            {
                var md = new DataSetMetaDataType();
                try
                {
                    using var d = new UaJsonDecoder(json, Codec.Context, new JsonDecoderOptions { ParseStrict = false });
                    md.Decode(d);
                }
                catch (Exception e) when (e is ServiceResultException or JsonException or FormatException)
                {
                    throw new InputException("--metadata: " + e.Message);
                }
                return md;
            }

            public DataSetMetaDataType For(ushort writerId) =>
                m_byWriter.TryGetValue(writerId, out DataSetMetaDataType md) ? md : m_all;

            public IReadOnlyList<string> Names(ushort writerId) =>
                For(writerId) is DataSetMetaDataType md ? [.. md.Fields.ToArray().Select(f => f.Name)] : null;

            public MetaDataMatchResult TryGet(in DataSetMetaDataKey key, out DataSetMetaDataType metaData)
            {
                metaData = For(key.DataSetWriterId);
                return metaData == null ? MetaDataMatchResult.NotFound : MetaDataMatchResult.Match;
            }

            public void Register(in DataSetMetaDataKey key, DataSetMetaDataType metaData)
            {
                // the codec's metadata is fixed
            }

            public void Remove(in DataSetMetaDataKey key)
            {
            }

            public ArrayOf<DataSetMetaDataKey> Keys => [];

#pragma warning disable CS0067 // never raised: the codec's metadata does not change
            public event EventHandler<DataSetMetaDataChangedEventArgs> MetaDataChanged;
#pragma warning restore CS0067
        }
    }

    /// <summary>Canonical value encoding (§7) → Variant, for the PubSub codec descriptions.</summary>
    internal static class CanonicalValue
    {
        public static Variant Parse(string dataType, JsonNode value, int[] dims)
        {
            if (dataType == "Null" || value == null && dataType is not ("Float" or "Double"))
            {
                return Variant.Null;
            }
            if (value is JsonArray arr)
            {
                var literal = new JsonArray();
                foreach (JsonNode e in arr)
                {
                    literal.Add(JsonValue.Create(Literal(dataType, e)));
                }
                return ValueParser.Parse(dataType + "[]", literal.ToJsonString(), dims);
            }
            return ValueParser.Parse(dataType, Literal(dataType, value), null);
        }

        /// <summary>The §12 literal of one canonical scalar.</summary>
        private static string Literal(string dataType, JsonNode v)
        {
            switch (dataType)
            {
                case "Float" or "Double" when v == null:
                    return "NaN";
                case "StatusCode":
                    return (v is JsonObject sc ? sc["code"] : v)?.ToString() ?? "0";
                case "QualifiedName":
                    return (v?["ns"]?.ToString() ?? "0") + ":" + (v?["name"]?.ToString() ?? string.Empty);
                case "LocalizedText":
                    return (v?["locale"]?.ToString() ?? string.Empty) + ":" + (v?["text"]?.ToString() ?? string.Empty);
                case "Boolean":
                    return v.GetValue<bool>() ? "true" : "false";
                default:
                    return v is JsonValue jv && jv.TryGetValue(out string s) ? s : v.ToJsonString();
            }
        }
    }
}
