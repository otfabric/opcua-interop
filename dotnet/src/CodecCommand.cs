// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// "client codec": the stack's OPC UA 1.05 JSON encoder / decoder (JsonEncoder / JsonDecoder,
    /// compact and verbose options), its XML encoder / decoder and the binary encoding as reference.
    /// </summary>
    internal static class CodecCommand
    {
        private const string Op = "codec";

        public static async Task<int> RunAsync(Args a)
        {
            string[] raw = a.Raw;
            string first = raw.Length > 0 ? raw[0] : null;
            if (first != null && first.StartsWith("pubsub-", StringComparison.Ordinal))
            {
                throw new InputException("codec " + first + ": PubSub NetworkMessage coding is not wired in this adapter");
            }
            string mode = a.Get("--json-mode") ?? "compact";
            if (mode is not ("compact" or "verbose"))
            {
                throw new InputException("--json-mode must be compact or verbose");
            }
            if (first == "encode")
            {
                var rest = new Args(raw[1..]);
                if (rest.Get("--node") != null)
                {
                    return await EncodeNodeAsync(rest, mode).ConfigureAwait(false);
                }
                return EncodeLiteral(rest, mode);
            }
            if (first == "decode")
            {
                var rest = new Args(raw[1..]);
                return Decode(rest, rest.Get("--format") ?? throw new InputException("missing --format"), mode);
            }
            if (a.Get("--decode") != null)
            {
                return Decode(a, a.Get("--decode"), mode);
            }
            if (a.Get("--node") != null)
            {
                return await ShortFormAsync(a, mode).ConfigureAwait(false);
            }
            throw new InputException("usage: codec encode|decode ... | codec --endpoint <url> --node <id> | codec --decode json|xml --type <T>");
        }

        // ------------------------------------------------------------------
        // documents
        // ------------------------------------------------------------------

        private static JsonEncoderOptions Options(string mode) =>
            mode == "verbose" ? JsonEncoderOptions.Verbose : JsonEncoderOptions.Compact;

        /// <summary>Encodes one field "V" and returns the JSON text of its value.</summary>
        private static string Json(string mode, Action<IEncoder> write)
        {
            using var e = new JsonEncoder(Codec.Context, Options(mode));
            write(e);
            string text = e.CloseAndReturnText();
            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.TryGetProperty("V", out JsonElement v) ? v.GetRawText() : "null";
        }

        private static string Xml(Action<XmlEncoder> write)
        {
            using var e = new XmlEncoder(Codec.Context);
            e.PushNamespace(Namespaces.OpcUaXsd);
            write(e);
            e.PopNamespace();
            // the stack indents its XML; the document is emitted without insignificant
            // whitespace (Eclipse Milo 1.1.8's XML decoder reads an indented Variant as null)
            return System.Xml.Linq.XElement.Parse(e.CloseAndReturnText()).ToString(System.Xml.Linq.SaveOptions.DisableFormatting);
        }

        private static string Binary(Action<IEncoder> write)
        {
            using var e = new BinaryEncoder(Codec.Context);
            write(e);
            return Convert.ToBase64String(e.CloseAndReturnBuffer() ?? []);
        }

        private static void WriteScalar(IEncoder e, string name, Variant v)
        {
            switch (v.TypeInfo.BuiltInType)
            {
                case BuiltInType.Boolean: e.WriteBoolean(name, v.GetBoolean()); break;
                case BuiltInType.SByte: e.WriteSByte(name, v.GetSByte()); break;
                case BuiltInType.Byte: e.WriteByte(name, v.GetByte()); break;
                case BuiltInType.Int16: e.WriteInt16(name, v.GetInt16()); break;
                case BuiltInType.UInt16: e.WriteUInt16(name, v.GetUInt16()); break;
                case BuiltInType.Int32: e.WriteInt32(name, v.GetInt32()); break;
                case BuiltInType.UInt32: e.WriteUInt32(name, v.GetUInt32()); break;
                case BuiltInType.Int64: e.WriteInt64(name, v.GetInt64()); break;
                case BuiltInType.UInt64: e.WriteUInt64(name, v.GetUInt64()); break;
                case BuiltInType.Float: e.WriteFloat(name, v.GetFloat()); break;
                case BuiltInType.Double: e.WriteDouble(name, v.GetDouble()); break;
                case BuiltInType.String: e.WriteString(name, v.GetString()); break;
                case BuiltInType.DateTime: e.WriteDateTime(name, v.GetDateTime()); break;
                case BuiltInType.Guid: e.WriteGuid(name, v.GetGuid()); break;
                case BuiltInType.ByteString: e.WriteByteString(name, v.GetByteString()); break;
                case BuiltInType.XmlElement: e.WriteXmlElement(name, v.GetXmlElement()); break;
                case BuiltInType.NodeId: e.WriteNodeId(name, v.GetNodeId()); break;
                case BuiltInType.ExpandedNodeId: e.WriteExpandedNodeId(name, v.GetExpandedNodeId()); break;
                case BuiltInType.StatusCode: e.WriteStatusCode(name, v.GetStatusCode()); break;
                case BuiltInType.QualifiedName: e.WriteQualifiedName(name, v.GetQualifiedName()); break;
                case BuiltInType.LocalizedText: e.WriteLocalizedText(name, v.GetLocalizedText()); break;
                case BuiltInType.ExtensionObject: e.WriteExtensionObject(name, v.GetExtensionObject()); break;
                case BuiltInType.DataValue: e.WriteDataValue(name, v.GetDataValue()); break;
                case BuiltInType.DiagnosticInfo:
                    e.WriteDiagnosticInfo(name, v.AsBoxedObject() as DiagnosticInfo);
                    break;
                default: e.WriteVariant(name, v); break;
            }
        }

        private static Variant ReadScalar(IDecoder d, string name, BuiltInType bt) => bt switch
        {
            BuiltInType.Boolean => new Variant(d.ReadBoolean(name)),
            BuiltInType.SByte => new Variant(d.ReadSByte(name)),
            BuiltInType.Byte => new Variant(d.ReadByte(name)),
            BuiltInType.Int16 => new Variant(d.ReadInt16(name)),
            BuiltInType.UInt16 => new Variant(d.ReadUInt16(name)),
            BuiltInType.Int32 => new Variant(d.ReadInt32(name)),
            BuiltInType.UInt32 => new Variant(d.ReadUInt32(name)),
            BuiltInType.Int64 => new Variant(d.ReadInt64(name)),
            BuiltInType.UInt64 => new Variant(d.ReadUInt64(name)),
            BuiltInType.Float => new Variant(d.ReadFloat(name)),
            BuiltInType.Double => new Variant(d.ReadDouble(name)),
            BuiltInType.String => new Variant(d.ReadString(name)),
            BuiltInType.DateTime => new Variant(d.ReadDateTime(name)),
            BuiltInType.Guid => new Variant(d.ReadGuid(name)),
            BuiltInType.ByteString => new Variant(d.ReadByteString(name)),
            BuiltInType.XmlElement => new Variant(d.ReadXmlElement(name)),
            BuiltInType.NodeId => new Variant(d.ReadNodeId(name)),
            BuiltInType.ExpandedNodeId => new Variant(d.ReadExpandedNodeId(name)),
            BuiltInType.StatusCode => new Variant(d.ReadStatusCode(name)),
            BuiltInType.QualifiedName => new Variant(d.ReadQualifiedName(name)),
            BuiltInType.LocalizedText => new Variant(d.ReadLocalizedText(name)),
            BuiltInType.ExtensionObject => new Variant(d.ReadExtensionObject(name)),
            BuiltInType.DataValue => new Variant(d.ReadDataValue(name)),
            BuiltInType.DiagnosticInfo => new Variant(d.ReadDiagnosticInfo(name), new TypeInfo(BuiltInType.DiagnosticInfo, ValueRanks.Scalar)),
            _ => d.ReadVariant(name)
        };

        private static (JsonNode Doc, StatusCode Status) Try(Func<string> produce)
        {
            try
            {
                return (JsonValue.Create(produce()), StatusCodes.Good);
            }
            catch (ServiceResultException e)
            {
                return (null, e.StatusCode);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] info: codec: " + e.GetType().Name + ": " + e.Message);
                return (null, StatusCodes.BadEncodingError);
            }
        }

        private static void PutVariantFields(JsonObject o, Variant v)
        {
            if (v.IsNull)
            {
                o["dataType"] = "Null";
                o["builtInType"] = 0;
                o["valueRank"] = -1;
                o["value"] = null;
                return;
            }
            o["dataType"] = Canonical.DataTypeName(v);
            o["builtInType"] = Canonical.BuiltInId(v);
            int rank = Canonical.ValueRank(v);
            o["valueRank"] = rank;
            int[] dims = Canonical.Dimensions(v);
            if (dims != null)
            {
                o["arrayDimensions"] = Canonical.DimsJson(dims);
            }
            o["value"] = Canonical.Value(v);
        }

        // ------------------------------------------------------------------
        // short form: read nodes, report every document
        // ------------------------------------------------------------------

        private static async Task<int> ShortFormAsync(Args a, string mode)
        {
            ClientContext c = await ClientContext.CreateAsync(a).ConfigureAwait(false);
            try
            {
                await c.ConnectAsync().ConfigureAwait(false);
                var ids = a.All("--node").Select(c.Node).ToList();
                ReadResponse resp = await c.Session.ReadAsync(c.Header(), 0, TimestampsToReturn.Both,
                    new ArrayOf<ReadValueId>(ids.Select(n => new ReadValueId { NodeId = n, AttributeId = Attributes.Value }).ToArray()),
                    CancellationToken.None).ConfigureAwait(false);
                var r = new Result(Op);
                bool ok = true;
                for (int i = 0; i < ids.Count; i++)
                {
                    DataValue dv = resp.Results[i];
                    var o = new JsonObject
                    {
                        ["nodeId"] = Canonical.NodeId(ids[i]),
                        ["statusCode"] = StatusNames.Json(dv.StatusCode)
                    };
                    if (StatusCode.IsBad(dv.StatusCode))
                    {
                        o["json"] = null;
                        o["xml"] = null;
                        ok = false;
                        r.Add(o);
                        continue;
                    }
                    Variant v = dv.WrappedValue;
                    o["dataType"] = Canonical.DataTypeName(v);
                    o["builtInType"] = Canonical.BuiltInId(v);
                    o["valueRank"] = Canonical.ValueRank(v);
                    o["value"] = Canonical.Value(v);
                    (JsonNode json, StatusCode jsc) = Try(() => Json(mode, e => e.WriteVariant("V", v)));
                    o["json"] = json;
                    o["xml"] = Try(() => Xml(e => e.WriteVariant("Variant", v))).Doc;
                    o["dataValueJson"] = Try(() => Json(mode, e => e.WriteDataValue("V", dv))).Doc;
                    o["dataValueXml"] = Try(() => Xml(e => e.WriteDataValue("DataValue", dv))).Doc;
                    o["binary"] = Try(() => Binary(e => e.WriteVariant(null, v))).Doc;
                    o["dataValueBinary"] = Try(() => Binary(e => e.WriteDataValue(null, dv))).Doc;
                    if (json == null)
                    {
                        ok = false;
                        Console.Error.WriteLine("[dotnet] warn: JSON encoding of " + ids[i] + " failed: " + StatusNames.Name(jsc.Code));
                    }
                    r.Add(o);
                }
                r.Success(ok);
                r.Print();
                return ok ? 0 : 4;
            }
            finally
            {
                await c.DisposeAsync().ConfigureAwait(false);
            }
        }

        // ------------------------------------------------------------------
        // encode
        // ------------------------------------------------------------------

        private static int EncodeLiteral(Args a, string mode)
        {
            string format = a.Get("--format") ?? throw new InputException("missing --format");
            if (format is not ("json" or "xml"))
            {
                throw new InputException("--format must be json or xml");
            }
            string type = a.Get("--type") ?? throw new InputException("missing --type");
            string value = a.Get("--value") ?? throw new InputException("missing --value");
            int[] dims = a.Get("--dimensions")?.Split(',').Select(s => int.Parse(s, Inv.C)).ToArray();
            Variant v = ValueParser.Parse(type, value, dims);
            DataValue dv = BuildDataValue(a, v);
            return Encoded(format, mode, "literal", null, v, dv);
        }

        private static DataValue BuildDataValue(Args a, Variant v)
        {
            var dv = new DataValue(v);
            string st = a.Get("--status");
            if (st != null)
            {
                uint code = st.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    ? uint.Parse(st.AsSpan(2), NumberStyles.HexNumber, Inv.C)
                    : uint.Parse(st, Inv.C);
                dv = dv.WithStatus(new StatusCode(code));
            }
            string src = a.Get("--source-timestamp");
            if (src != null)
            {
                dv = dv.WithSourceTimestamp(new DateTimeUtc(DateTime.Parse(src, Inv.C, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal)));
            }
            string srv = a.Get("--server-timestamp");
            if (srv != null)
            {
                dv = dv.WithServerTimestamp(new DateTimeUtc(DateTime.Parse(srv, Inv.C, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal)));
            }
            int sp = a.GetInt("--source-picoseconds", -1);
            if (sp >= 0)
            {
                dv = dv.WithSourcePicoseconds((ushort)sp);
            }
            int vp = a.GetInt("--server-picoseconds", -1);
            if (vp >= 0)
            {
                dv = dv.WithServerPicoseconds((ushort)vp);
            }
            return dv;
        }

        private static async Task<int> EncodeNodeAsync(Args a, string mode)
        {
            string format = a.Get("--format") ?? throw new InputException("missing --format");
            ClientContext c = await ClientContext.CreateAsync(a).ConfigureAwait(false);
            try
            {
                await c.ConnectAsync().ConfigureAwait(false);
                NodeId id = c.Node(a.Get("--node"));
                ReadResponse resp = await c.Session.ReadAsync(c.Header(), 0, TimestampsToReturn.Both,
                    new ArrayOf<ReadValueId>(new[] { new ReadValueId { NodeId = id, AttributeId = Attributes.Value } }),
                    CancellationToken.None).ConfigureAwait(false);
                DataValue dv = resp.Results[0];
                if (StatusCode.IsBad(dv.StatusCode))
                {
                    new Result(Op).ServiceResult(dv.StatusCode).Error("service", "read failed").Print();
                    return 4;
                }
                return Encoded(format, mode, "node", id, dv.WrappedValue, dv);
            }
            finally
            {
                await c.DisposeAsync().ConfigureAwait(false);
            }
        }

        private static int Encoded(string format, string mode, string source, NodeId? node, Variant v, DataValue dv)
        {
            var o = new JsonObject { ["action"] = "encode", ["format"] = format };
            if (format == "json")
            {
                o["jsonMode"] = mode;
            }
            o["source"] = source;
            if (node != null)
            {
                o["nodeId"] = Canonical.NodeId(node.Value);
            }
            PutVariantFields(o, v);
            o["dataValue"] = Canonical.DataValueJson(dv);
            bool scalar = v.TypeInfo.IsScalar && !v.IsNull;
            Func<Action<IEncoder>, Action<XmlEncoder>, string, (JsonNode, StatusCode)> doc = (j, x, name) =>
                format == "json" ? Try(() => Json(mode, j)) : Try(() => Xml(x));
            (JsonNode variantDoc, StatusCode variantSc) = doc(e => e.WriteVariant("V", v), e => e.WriteVariant("Variant", v), "Variant");
            (JsonNode dvDoc, StatusCode dvSc) = doc(e => e.WriteDataValue("V", dv), e => e.WriteDataValue("DataValue", dv), "DataValue");
            var encoded = new JsonObject { ["variant"] = variantDoc, ["dataValue"] = dvDoc };
            var codes = new JsonObject { ["variant"] = StatusNames.Json(variantSc), ["dataValue"] = StatusNames.Json(dvSc) };
            var binary = new JsonObject
            {
                ["variant"] = Try(() => Binary(e => e.WriteVariant(null, v))).Doc,
                ["dataValue"] = Try(() => Binary(e => e.WriteDataValue(null, dv))).Doc
            };
            if (scalar)
            {
                string tn = Canonical.TypeName((int)v.TypeInfo.BuiltInType);
                (JsonNode valueDoc, StatusCode valueSc) = doc(e => WriteScalar(e, "V", v), e => WriteScalar(e, tn, v), tn);
                encoded["value"] = valueDoc;
                codes["value"] = StatusNames.Json(valueSc);
                binary["value"] = Try(() => Binary(e => WriteScalar(e, null, v))).Doc;
            }
            o["encoded"] = encoded;
            o["statusCodes"] = codes;
            o["binary"] = binary;
            bool ok = variantDoc != null;
            var r = new Result(Op).Success(ok).ServiceResult(variantSc).Add(o);
            if (!ok)
            {
                r.Error("service", "the stack cannot encode the Variant");
            }
            r.Print();
            return ok ? 0 : 4;
        }

        // ------------------------------------------------------------------
        // decode
        // ------------------------------------------------------------------

        private static string ReadDocument(Args a)
        {
            string text = a.Get("--document");
            if (text == null)
            {
                string file = a.Get("--input");
                text = file != null ? File.ReadAllText(file) : Console.In.ReadToEnd();
            }
            return text.TrimEnd();
        }

        private static int Decode(Args a, string format, string mode)
        {
            if (format is not ("json" or "xml"))
            {
                throw new InputException("decode format must be json or xml");
            }
            string type = a.Get("--type") ?? throw new InputException("missing --type");
            BuiltInType bt = type == "Variant" ? BuiltInType.Variant : type == "DataValue" ? BuiltInType.DataValue : ValueParser.BuiltIn(type);
            if ((int)bt <= 0 || (int)bt > 25)
            {
                throw new InputException("unknown --type " + type);
            }
            string doc = ReadDocument(a);
            var o = new JsonObject { ["action"] = "decode", ["format"] = format };
            if (format == "json")
            {
                o["jsonMode"] = mode;
            }
            o["type"] = type;

            Variant v;
            DataValue dv = default;
            try
            {
                if (format == "json")
                {
                    using var d = new JsonDecoder("{\"V\":" + doc + "}", Codec.Context);
                    if (bt == BuiltInType.DataValue)
                    {
                        dv = d.ReadDataValue("V");
                        v = dv.WrappedValue;
                    }
                    else
                    {
                        v = bt == BuiltInType.Variant ? d.ReadVariant("V") : ReadScalar(d, "V", bt);
                    }
                }
                else
                {
                    string element = bt == BuiltInType.Variant ? "Variant" : bt == BuiltInType.DataValue ? "DataValue" : type;
                    using var reader = XmlReader.Create(new StringReader(doc), new XmlReaderSettings { IgnoreWhitespace = true });
                    reader.MoveToContent();
                    string ns = reader.NamespaceURI;
                    using var d = new XmlDecoder(reader, Codec.Context);
                    d.PushNamespace(ns ?? string.Empty);
                    if (bt == BuiltInType.DataValue)
                    {
                        dv = d.ReadDataValue(element);
                        v = dv.WrappedValue;
                    }
                    else
                    {
                        v = bt == BuiltInType.Variant ? d.ReadVariant(element) : ReadScalar(d, element, bt);
                    }
                }
            }
            catch (Exception e)
            {
                StatusCode sc = e is ServiceResultException sre ? sre.StatusCode : StatusCodes.BadDecodingError;
                o["statusCode"] = StatusNames.Json(sc);
                new Result(Op).Success(false).ServiceResult(sc).Add(o).Error("service", e.Message).Print();
                return 4;
            }
            o["statusCode"] = StatusNames.Json(StatusCodes.Good);
            PutVariantFields(o, v);
            if (bt == BuiltInType.DataValue)
            {
                o["dataValue"] = Canonical.DataValueJson(dv);
                o["binary"] = Try(() => Binary(e => e.WriteDataValue(null, dv))).Doc;
                o["reencoded"] = format == "json"
                    ? Try(() => Json(mode, e => e.WriteDataValue("V", dv))).Doc
                    : Try(() => Xml(e => e.WriteDataValue("DataValue", dv))).Doc;
            }
            else if (bt == BuiltInType.Variant)
            {
                o["binary"] = Try(() => Binary(e => e.WriteVariant(null, v))).Doc;
                o["reencoded"] = format == "json"
                    ? Try(() => Json(mode, e => e.WriteVariant("V", v))).Doc
                    : Try(() => Xml(e => e.WriteVariant("Variant", v))).Doc;
            }
            else
            {
                o["binary"] = Try(() => Binary(e => WriteScalar(e, null, v))).Doc;
                o["reencoded"] = format == "json"
                    ? Try(() => Json(mode, e => WriteScalar(e, "V", v))).Doc
                    : Try(() => Xml(e => WriteScalar(e, type, v))).Doc;
            }
            new Result(Op).Add(o).Print();
            return 0;
        }
    }
}
