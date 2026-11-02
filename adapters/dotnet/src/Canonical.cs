// SPDX-License-Identifier: MIT
using System;
using System.Collections;
using System.Text;
using System.Text.Json.Nodes;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// Canonical result encoding of docs/CONTAINER_CONTRACT.md §6 (NodeIds) and §7 (values).
    /// </summary>
    internal static class Canonical
    {
        private static readonly string[] s_typeNames =
        [
            "Null", "Boolean", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
            "Float", "Double", "String", "DateTime", "Guid", "ByteString", "XmlElement", "NodeId",
            "ExpandedNodeId", "StatusCode", "QualifiedName", "LocalizedText", "ExtensionObject",
            "DataValue", "Variant", "DiagnosticInfo"
        ];

        public static string TypeName(int builtInType) =>
            builtInType >= 0 && builtInType < s_typeNames.Length ? s_typeNames[builtInType] : "Unknown";

        public static int TypeId(string name)
        {
            for (int i = 0; i < s_typeNames.Length; i++)
            {
                if (s_typeNames[i] == name)
                {
                    return i;
                }
            }
            return -1;
        }

        /// <summary>The built-in type id of a Variant (Enumeration → Int32; null → 0).</summary>
        public static int BuiltInId(Variant v)
        {
            if (v.IsNull)
            {
                return 0;
            }
            BuiltInType bt = v.TypeInfo.BuiltInType;
            if (bt == BuiltInType.Enumeration)
            {
                return (int)BuiltInType.Int32;
            }
            int id = (int)bt;
            return id is > 0 and <= 25 ? id : 0;
        }

        /// <summary>dataType name used in results ("Unknown" for an empty Variant, like Milo).</summary>
        public static string DataTypeName(Variant v)
        {
            int id = BuiltInId(v);
            return id == 0 ? "Unknown" : TypeName(id);
        }

        public static string NodeId(NodeId n)
        {
            if (n.IsNull && n.IdType == IdType.Numeric)
            {
                return "i=0";
            }
            string prefix = n.NamespaceIndex == 0 ? string.Empty : "ns=" + n.NamespaceIndex.ToString(Inv.C) + ";";
            switch (n.IdType)
            {
                case IdType.Numeric:
                    n.TryGetValue(out uint num);
                    return prefix + "i=" + num.ToString(Inv.C);
                case IdType.String:
                    n.TryGetValue(out string s);
                    return prefix + "s=" + s;
                case IdType.Guid:
                    n.TryGetValue(out Guid g);
                    return prefix + "g=" + g.ToString("D").ToLowerInvariant();
                case IdType.Opaque:
                    n.TryGetValue(out ByteString b);
                    return prefix + "b=" + Convert.ToBase64String(b.Span);
                default:
                    return n.ToString();
            }
        }

        public static string ExpandedNodeId(ExpandedNodeId e)
        {
            var sb = new StringBuilder();
            if (e.ServerIndex != 0)
            {
                sb.Append("svr=").Append(e.ServerIndex.ToString(Inv.C)).Append(';');
            }
            if (!string.IsNullOrEmpty(e.NamespaceUri))
            {
                sb.Append("nsu=").Append(e.NamespaceUri).Append(';');
            }
            else if (e.NamespaceIndex != 0)
            {
                sb.Append("ns=").Append(e.NamespaceIndex.ToString(Inv.C)).Append(';');
            }
            switch (e.IdType)
            {
                case IdType.Numeric:
                    e.TryGetValue(out uint num);
                    sb.Append("i=").Append(num.ToString(Inv.C));
                    break;
                case IdType.String:
                    e.TryGetValue(out string s);
                    sb.Append("s=").Append(s);
                    break;
                case IdType.Guid:
                    e.TryGetValue(out Guid g);
                    sb.Append("g=").Append(g.ToString("D").ToLowerInvariant());
                    break;
                case IdType.Opaque:
                    e.TryGetValue(out ByteString b);
                    sb.Append("b=").Append(Convert.ToBase64String(b.Span));
                    break;
            }
            return sb.ToString();
        }

        /// <summary>A local NodeId from a (local) ExpandedNodeId.</summary>
        public static NodeId Local(ExpandedNodeId e) => e.InnerNodeId;

        public static string Time(DateTimeUtc t) =>
            t.ToDateTime().ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", Inv.C);

        public static string Time7(DateTimeUtc t) =>
            t.ToDateTime().ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", Inv.C);

        public static bool HasTime(DateTimeUtc t) => !t.IsNull && t.ToDateTime() > new DateTime(1601, 1, 2, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>value rank of a Variant: -1 scalar, 1 array, n matrix.</summary>
        public static int ValueRank(Variant v)
        {
            if (v.IsNull)
            {
                return -1;
            }
            object boxed = v.AsBoxedObject(Variant.BoxingBehavior.LegacyWithMatrix);
            if (boxed is Matrix m)
            {
                return m.Dimensions.Length > 1 ? m.Dimensions.Length : 1;
            }
            if (boxed is Array && v.TypeInfo.BuiltInType != BuiltInType.ByteString)
            {
                return 1;
            }
            return v.TypeInfo.IsArray ? 1 : -1;
        }

        public static int[] Dimensions(Variant v)
        {
            if (v.IsNull)
            {
                return null;
            }
            return v.AsBoxedObject(Variant.BoxingBehavior.LegacyWithMatrix) is Matrix m && m.Dimensions.Length > 1
                ? m.Dimensions
                : null;
        }

        /// <summary>Canonical JSON of a Variant payload (§7). Matrices are flattened (row-major).</summary>
        public static JsonNode Value(Variant v)
        {
            if (v.IsNull)
            {
                return null;
            }
            BuiltInType bt = v.TypeInfo.BuiltInType;
            if (v.TypeInfo.IsScalar)
            {
                return Boxed(v.AsBoxedObject(Variant.BoxingBehavior.Legacy), bt);
            }
            object boxed = v.AsBoxedObject(Variant.BoxingBehavior.LegacyWithMatrix);
            if (boxed is Matrix m)
            {
                return Flatten(m.Elements, bt);
            }
            if (boxed is Array arr)
            {
                return Flatten(arr, bt);
            }
            boxed = v.AsBoxedObject(Variant.BoxingBehavior.Legacy);
            return boxed is Array a2 ? Flatten(a2, bt) : Boxed(boxed, bt);
        }

        public static JsonNode Boxed(object val, BuiltInType bt = BuiltInType.Null)
        {
            switch (val)
            {
                case null:
                    return null;
                case Matrix m:
                    return Flatten(m.Elements, m.TypeInfo.BuiltInType);
                case byte[] bytes when bt == BuiltInType.ByteString:
                    return JsonValue.Create(Convert.ToBase64String(bytes));
                case byte[] bytes:
                    var ba = new JsonArray();
                    foreach (byte b in bytes)
                    {
                        ba.Add(JsonValue.Create(b));
                    }
                    return ba;
                case string s:
                    return JsonValue.Create(s);
                case Array arr:
                    return Flatten(arr, bt);
                case Variant inner:
                    if (inner.IsNull)
                    {
                        return null;
                    }
                    var vo = new JsonObject
                    {
                        ["dataType"] = DataTypeName(inner),
                        ["builtInType"] = BuiltInId(inner)
                    };
                    vo["value"] = Value(inner);
                    return vo;
                default:
                    return Scalar(val);
            }
        }

        private static JsonArray Flatten(Array arr, BuiltInType bt)
        {
            var a = new JsonArray();
            foreach (object el in arr)
            {
                if (el is Array inner && !(el is byte[] && bt == BuiltInType.ByteString))
                {
                    foreach (JsonNode n in Flatten(inner, bt))
                    {
                        a.Add(n?.DeepClone());
                    }
                }
                else
                {
                    a.Add(Boxed(el, bt));
                }
            }
            return a;
        }

        public static JsonNode Scalar(object val)
        {
            switch (val)
            {
                case null:
                    return null;
                case bool b:
                    return JsonValue.Create(b);
                case sbyte sb:
                    return JsonValue.Create(sb);
                case byte by:
                    return JsonValue.Create(by);
                case short i16:
                    return JsonValue.Create(i16);
                case ushort u16:
                    return JsonValue.Create(u16);
                case int i32:
                    return JsonValue.Create(i32);
                case uint u32:
                    return JsonValue.Create(u32);
                case long i64:
                    return JsonValue.Create(i64.ToString(Inv.C));
                case ulong u64:
                    return JsonValue.Create(u64.ToString(Inv.C));
                case float f:
                    return float.IsFinite(f) ? JsonValue.Create(f) : null;
                case double d:
                    return double.IsFinite(d) ? JsonValue.Create(d) : null;
                case string s:
                    return JsonValue.Create(s);
                case DateTimeUtc t:
                    return JsonValue.Create(Time(t));
                case DateTime dt:
                    return JsonValue.Create(Time(new DateTimeUtc(dt)));
                case Uuid u:
                    return JsonValue.Create(u.Guid.ToString("D").ToLowerInvariant());
                case Guid g:
                    return JsonValue.Create(g.ToString("D").ToLowerInvariant());
                case ByteString bs:
                    return bs.IsNull ? null : JsonValue.Create(Convert.ToBase64String(bs.Span));
                case XmlElement x:
                    return x.IsNull ? null : JsonValue.Create(x.OuterXml);
                case NodeId n:
                    return JsonValue.Create(NodeId(n));
                case ExpandedNodeId e:
                    return JsonValue.Create(ExpandedNodeId(e));
                case StatusCode sc:
                    return StatusNames.Json(sc);
                case QualifiedName qn:
                    return Json.Obj(("ns", JsonValue.Create((int)qn.NamespaceIndex)), ("name", JsonValue.Create(qn.Name ?? string.Empty)));
                case LocalizedText lt:
                    return Json.Obj(("locale", JsonValue.Create(lt.Locale ?? string.Empty)), ("text", JsonValue.Create(lt.Text ?? string.Empty)));
                case ExtensionObject eo:
                    return ExtensionObjectJson(eo);
                case DataValue dv:
                    return DataValueJson(dv);
                case DiagnosticInfo di:
                    return DiagnosticInfoJson(di);
                case EnumValue ev:
                    return JsonValue.Create(Convert.ToInt32(ev.ToObject(), Inv.C));
                case Enum en:
                    return JsonValue.Create(Convert.ToInt32(en, Inv.C));
                default:
                    return JsonValue.Create(Convert.ToString(val, Inv.C));
            }
        }

        public static JsonNode ExtensionObjectJson(ExtensionObject eo)
        {
            if (eo.IsNull)
            {
                return null;
            }
            var o = new JsonObject { ["typeId"] = ExpandedNodeId(eo.TypeId) };
            switch (eo.Body)
            {
                case ByteString bs:
                    o["encoding"] = "binary";
                    o["body"] = Convert.ToBase64String(bs.Span);
                    break;
                case byte[] raw:
                    o["encoding"] = "binary";
                    o["body"] = Convert.ToBase64String(raw);
                    break;
                case XmlElement x:
                    o["encoding"] = "xml";
                    o["body"] = x.OuterXml ?? string.Empty;
                    break;
                case IEncodeable enc:
                    o["encoding"] = "binary";
                    o["dataTypeName"] = enc.GetType().Name;
                    try
                    {
                        o["body"] = Convert.ToBase64String(Codec.EncodeBinaryBody(enc));
                    }
                    catch
                    {
                        o["body"] = string.Empty;
                    }
                    break;
                default:
                    o["encoding"] = "json";
                    o["body"] = Convert.ToString(eo.Body, Inv.C);
                    break;
            }
            return o;
        }

        public static JsonObject DataValueJson(DataValue dv)
        {
            var m = new JsonObject();
            if (!dv.WrappedValue.IsNull)
            {
                m["dataType"] = DataTypeName(dv.WrappedValue);
                m["builtInType"] = BuiltInId(dv.WrappedValue);
                int[] dims = Dimensions(dv.WrappedValue);
                if (dims != null)
                {
                    m["arrayDimensions"] = DimsJson(dims);
                }
                m["value"] = Value(dv.WrappedValue);
            }
            if (dv.StatusCode.Code != 0)
            {
                m["statusCode"] = StatusNames.Json(dv.StatusCode);
            }
            if (!dv.SourceTimestamp.IsNull)
            {
                m["sourceTimestamp"] = Time7(dv.SourceTimestamp);
            }
            if (dv.SourcePicoseconds != 0)
            {
                m["sourcePicoseconds"] = (int)dv.SourcePicoseconds;
            }
            if (!dv.ServerTimestamp.IsNull)
            {
                m["serverTimestamp"] = Time7(dv.ServerTimestamp);
            }
            if (dv.ServerPicoseconds != 0)
            {
                m["serverPicoseconds"] = (int)dv.ServerPicoseconds;
            }
            return m;
        }

        public static JsonArray DimsJson(int[] dims)
        {
            var a = new JsonArray();
            foreach (int d in dims)
            {
                a.Add(JsonValue.Create(d));
            }
            return a;
        }

        public static JsonObject DiagnosticInfoJson(DiagnosticInfo di)
        {
            var m = new JsonObject();
            if (di == null)
            {
                return m;
            }
            if (di.SymbolicId >= 0)
            {
                m["symbolicId"] = di.SymbolicId;
            }
            if (di.NamespaceUri >= 0)
            {
                m["namespaceUri"] = di.NamespaceUri;
            }
            if (di.LocalizedText >= 0)
            {
                m["localizedText"] = di.LocalizedText;
            }
            if (di.Locale >= 0)
            {
                m["locale"] = di.Locale;
            }
            if (di.AdditionalInfo != null)
            {
                m["additionalInfo"] = di.AdditionalInfo;
            }
            if (di.InnerStatusCode.Code != 0)
            {
                m["innerStatusCode"] = StatusNames.Json(di.InnerStatusCode);
            }
            if (di.InnerDiagnosticInfo != null)
            {
                m["innerDiagnosticInfo"] = DiagnosticInfoJson(di.InnerDiagnosticInfo);
            }
            return m;
        }

        /// <summary>The usual (value, dataType, builtInType) triple of a result item.</summary>
        public static void PutValue(JsonObject o, Variant v, bool valueFirst = false)
        {
            if (valueFirst)
            {
                o["value"] = Value(v);
                o["dataType"] = DataTypeName(v);
                o["builtInType"] = BuiltInId(v);
            }
            else
            {
                o["dataType"] = DataTypeName(v);
                o["builtInType"] = BuiltInId(v);
                o["value"] = Value(v);
            }
        }

        public static void Ignore(IEnumerable _) { }
    }
}
