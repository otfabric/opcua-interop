// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>NodeId input parsing (docs/CONTAINER_CONTRACT.md §8).</summary>
    internal static class NodeIds
    {
        /// <summary>Parses i=, ns=N;x= forms; nsu= is resolved through <paramref name="resolveNs"/>.</summary>
        public static NodeId Parse(string s, Func<string, int> resolveNs = null)
        {
            if (string.IsNullOrEmpty(s))
            {
                throw new InputException("empty NodeId");
            }
            if (s.StartsWith("nsu=", StringComparison.Ordinal))
            {
                int semi = s.IndexOf(';', 4);
                if (semi < 0)
                {
                    throw new InputException("malformed NodeId: '" + s + "'");
                }
                string uri = s.Substring(4, semi - 4);
                if (resolveNs == null)
                {
                    throw new InputException("nsu= form needs a session to resolve: '" + s + "'");
                }
                int idx = resolveNs(uri);
                if (idx < 0)
                {
                    throw new InputException("unknown namespace URI: " + uri);
                }
                return Identifier((ushort)idx, s.Substring(semi + 1), s);
            }
            if (s.StartsWith("ns=", StringComparison.Ordinal))
            {
                int semi = s.IndexOf(';');
                if (semi < 0 || !ushort.TryParse(s.AsSpan(3, semi - 3), NumberStyles.None, Inv.C, out ushort ns))
                {
                    throw new InputException("malformed NodeId: '" + s + "'");
                }
                return Identifier(ns, s.Substring(semi + 1), s);
            }
            return Identifier(0, s, s);
        }

        private static NodeId Identifier(ushort ns, string rest, string original)
        {
            if (rest.Length < 2 || rest[1] != '=')
            {
                throw new InputException("malformed NodeId: '" + original + "'");
            }
            string id = rest.Substring(2);
            switch (rest[0])
            {
                case 'i':
                    if (!uint.TryParse(id, NumberStyles.None, Inv.C, out uint num))
                    {
                        throw new InputException("malformed NodeId: '" + original + "'");
                    }
                    return new NodeId(num, ns);
                case 's':
                    return new NodeId(id, ns);
                case 'g':
                    if (!Guid.TryParse(id, out Guid g))
                    {
                        throw new InputException("malformed NodeId: '" + original + "'");
                    }
                    return new NodeId(g, ns);
                case 'b':
                    try
                    {
                        return new NodeId(ByteString.From(Convert.FromBase64String(id)), ns);
                    }
                    catch (FormatException)
                    {
                        throw new InputException("malformed NodeId: '" + original + "'");
                    }
                default:
                    throw new InputException("malformed NodeId: '" + original + "'");
            }
        }
    }

    /// <summary>Value literals (docs/CONTAINER_CONTRACT.md §12).</summary>
    internal static class ValueParser
    {
        public static readonly string[] ScalarTypes =
        [
            "Boolean", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
            "Float", "Double", "String", "DateTime", "Guid", "ByteString", "XmlElement", "NodeId",
            "ExpandedNodeId", "StatusCode", "QualifiedName", "LocalizedText", "ExtensionObject",
            "DataValue", "Variant", "DiagnosticInfo"
        ];

        public static bool Supports(string type)
        {
            string t = type.EndsWith("[]", StringComparison.Ordinal) ? type[..^2] : type;
            return ScalarTypes.Contains(t);
        }

        /// <summary>
        /// Lenient parsing used by write / call: an unknown type or malformed literal becomes a String
        /// (the server answers), as the reference adapters do.
        /// </summary>
        public static Variant ParseLenient(string type, string literal)
        {
            try
            {
                if (Supports(type))
                {
                    return Parse(type, literal, null);
                }
            }
            catch (Exception)
            {
                // fall through
            }
            return new Variant(literal);
        }

        /// <summary>Strict parsing (codec encode): throws InputException.</summary>
        public static Variant Parse(string type, string literal, int[] dimensions)
        {
            if (type.EndsWith("[]", StringComparison.Ordinal))
            {
                string el = type[..^2];
                if (!ScalarTypes.Contains(el))
                {
                    throw new InputException("unknown type: " + type);
                }
                List<string> items = SplitArray(literal);
                var values = new List<object>(items.Count);
                foreach (string it in items)
                {
                    values.Add(ParseScalarObject(el, it));
                }
                Array typed = ToTypedArray(el, values);
                if (dimensions != null && dimensions.Length > 1)
                {
                    int product = 1;
                    foreach (int d in dimensions)
                    {
                        product *= d;
                    }
                    if (product != typed.Length)
                    {
                        throw new InputException("--dimensions do not match the number of elements");
                    }
                    return new Variant(new Matrix(typed, BuiltIn(el), dimensions));
                }
                return ArrayVariant(el, typed);
            }
            if (!ScalarTypes.Contains(type))
            {
                throw new InputException("unknown type: " + type);
            }
            return ScalarVariant(type, ParseScalarObject(type, literal));
        }

        public static BuiltInType BuiltIn(string name) => (BuiltInType)Canonical.TypeId(name);

        private static List<string> SplitArray(string literal)
        {
            literal ??= string.Empty;
            string t = literal.Trim();
            if (t.Length == 0)
            {
                return [];
            }
            if (t.StartsWith('['))
            {
                try
                {
                    using var doc = JsonDocument.Parse(t);
                    var list = new List<string>();
                    foreach (JsonElement e in doc.RootElement.EnumerateArray())
                    {
                        list.Add(e.ValueKind == JsonValueKind.String ? e.GetString() : e.GetRawText());
                    }
                    return list;
                }
                catch (JsonException)
                {
                    // fall back to comma splitting
                }
            }
            return literal.Split(',').Select(x => x.Trim()).ToList();
        }

        private static object ParseScalarObject(string type, string s)
        {
            s ??= string.Empty;
            try
            {
                switch (type)
                {
                    case "Boolean":
                        if (s == "1" || s.Equals("true", StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                        if (s == "0" || s.Equals("false", StringComparison.OrdinalIgnoreCase))
                        {
                            return false;
                        }
                        throw new InputException("invalid Boolean literal: " + s);
                    case "SByte": return sbyte.Parse(s, NumberStyles.Integer, Inv.C);
                    case "Byte": return byte.Parse(s, NumberStyles.Integer, Inv.C);
                    case "Int16": return short.Parse(s, NumberStyles.Integer, Inv.C);
                    case "UInt16": return ushort.Parse(s, NumberStyles.Integer, Inv.C);
                    case "Int32": return int.Parse(s, NumberStyles.Integer, Inv.C);
                    case "UInt32": return uint.Parse(s, NumberStyles.Integer, Inv.C);
                    case "Int64": return long.Parse(s, NumberStyles.Integer, Inv.C);
                    case "UInt64": return ulong.Parse(s, NumberStyles.Integer, Inv.C);
                    case "Float": return float.Parse(Special(s), NumberStyles.Float, Inv.C);
                    case "Double": return double.Parse(Special(s), NumberStyles.Float, Inv.C);
                    case "String": return s;
                    case "DateTime":
                        return new DateTimeUtc(DateTime.Parse(s, Inv.C, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal));
                    case "Guid": return new Uuid(Guid.Parse(s));
                    case "ByteString": return ByteString.From(Convert.FromBase64String(s));
                    case "XmlElement": return XmlElement.From(s);
                    case "NodeId":
                        if (s.StartsWith("nsu=", StringComparison.Ordinal))
                        {
                            throw new InputException("NodeId literal must not use nsu=");
                        }
                        return NodeIds.Parse(s);
                    case "ExpandedNodeId": return ParseExpanded(s);
                    case "StatusCode":
                        return new StatusCode(s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                            ? uint.Parse(s.AsSpan(2), NumberStyles.HexNumber, Inv.C)
                            : uint.Parse(s, NumberStyles.Integer, Inv.C));
                    case "QualifiedName":
                        {
                            int c = s.IndexOf(':');
                            if (c > 0 && ushort.TryParse(s.AsSpan(0, c), NumberStyles.None, Inv.C, out ushort ns))
                            {
                                return new QualifiedName(s[(c + 1)..], ns);
                            }
                            return new QualifiedName(s, 0);
                        }
                    case "LocalizedText":
                        {
                            int c = s.IndexOf(':');
                            if (c >= 0)
                            {
                                string loc = s[..c];
                                return new LocalizedText(loc.Length == 0 ? null : loc, s[(c + 1)..]);
                            }
                            return new LocalizedText(s);
                        }
                    case "ExtensionObject":
                        {
                            int bar = s.IndexOf('|');
                            if (bar < 0)
                            {
                                throw new InputException("ExtensionObject literal is <typeId>|<base64>");
                            }
                            NodeId typeId = NodeIds.Parse(s[..bar]);
                            return new ExtensionObject(new ExpandedNodeId(typeId), ByteString.From(Convert.FromBase64String(s[(bar + 1)..])));
                        }
                    case "DataValue":
                        {
                            (string t, string lit) = SplitTyped(s);
                            return new DataValue(Parse(t, lit, null));
                        }
                    case "Variant":
                        {
                            (string t, string lit) = SplitTyped(s);
                            return Parse(t, lit, null);
                        }
                    case "DiagnosticInfo": return ParseDiagnosticInfo(s);
                }
            }
            catch (InputException)
            {
                throw;
            }
            catch (Exception e) when (e is FormatException or OverflowException or ArgumentException)
            {
                throw new InputException("invalid " + type + " literal '" + s + "': " + e.Message);
            }
            throw new InputException("unknown type: " + type);
        }

        private static string Special(string s) => s switch
        {
            "NaN" => "NaN",
            "Infinity" or "+Infinity" or "INF" => "Infinity",
            "-Infinity" or "-INF" => "-Infinity",
            _ => s
        };

        private static (string, string) SplitTyped(string s)
        {
            int c = s.IndexOf(':');
            if (c <= 0)
            {
                throw new InputException("expected <Type>:<literal>, got '" + s + "'");
            }
            return (s[..c], s[(c + 1)..]);
        }

        public static ExpandedNodeId ParseExpanded(string s)
        {
            uint server = 0;
            string rest = s;
            if (rest.StartsWith("svr=", StringComparison.Ordinal))
            {
                int semi = rest.IndexOf(';');
                server = uint.Parse(rest.AsSpan(4, semi - 4), NumberStyles.None, Inv.C);
                rest = rest[(semi + 1)..];
            }
            string nsUri = null;
            if (rest.StartsWith("nsu=", StringComparison.Ordinal))
            {
                int semi = rest.IndexOf(';');
                nsUri = rest.Substring(4, semi - 4);
                rest = rest[(semi + 1)..];
            }
            NodeId inner = NodeIds.Parse(rest);
            var e = new ExpandedNodeId(inner);
            if (nsUri != null)
            {
                e = e.WithNamespaceUri(nsUri);
            }
            if (server != 0)
            {
                e = e.WithServerIndex(server);
            }
            return e;
        }

        private static DiagnosticInfo ParseDiagnosticInfo(string s)
        {
            var di = new DiagnosticInfo();
            foreach (string part in s.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = part.IndexOf('=');
                if (eq <= 0)
                {
                    throw new InputException("DiagnosticInfo literal is key=value;...");
                }
                string k = part[..eq];
                string v = part[(eq + 1)..];
                switch (k)
                {
                    case "symbolicId": di.SymbolicId = int.Parse(v, Inv.C); break;
                    case "namespaceUri": di.NamespaceUri = int.Parse(v, Inv.C); break;
                    case "localizedText": di.LocalizedText = int.Parse(v, Inv.C); break;
                    case "locale": di.Locale = int.Parse(v, Inv.C); break;
                    case "additionalInfo": di.AdditionalInfo = v; break;
                    case "innerStatusCode": di.InnerStatusCode = (StatusCode)ParseScalarObject("StatusCode", v); break;
                    default: throw new InputException("unknown DiagnosticInfo key: " + k);
                }
            }
            return di;
        }

        private static Array ToTypedArray(string el, List<object> values)
        {
            Type t = values.Count > 0 ? values[0].GetType() : ClrType(el);
            if (el == "Variant")
            {
                t = typeof(Variant);
            }
            var arr = Array.CreateInstance(t, values.Count);
            for (int i = 0; i < values.Count; i++)
            {
                arr.SetValue(values[i], i);
            }
            return arr;
        }

        private static Type ClrType(string el) => el switch
        {
            "Boolean" => typeof(bool),
            "SByte" => typeof(sbyte),
            "Byte" => typeof(byte),
            "Int16" => typeof(short),
            "UInt16" => typeof(ushort),
            "Int32" => typeof(int),
            "UInt32" => typeof(uint),
            "Int64" => typeof(long),
            "UInt64" => typeof(ulong),
            "Float" => typeof(float),
            "Double" => typeof(double),
            "String" => typeof(string),
            "DateTime" => typeof(DateTimeUtc),
            "Guid" => typeof(Uuid),
            "ByteString" => typeof(ByteString),
            "XmlElement" => typeof(XmlElement),
            "NodeId" => typeof(NodeId),
            "ExpandedNodeId" => typeof(ExpandedNodeId),
            "StatusCode" => typeof(StatusCode),
            "QualifiedName" => typeof(QualifiedName),
            "LocalizedText" => typeof(LocalizedText),
            "ExtensionObject" => typeof(ExtensionObject),
            "DataValue" => typeof(DataValue),
            "Variant" => typeof(Variant),
            "DiagnosticInfo" => typeof(DiagnosticInfo),
            _ => typeof(object)
        };

        public static Variant ScalarVariant(string type, object v) => v switch
        {
            bool b => new Variant(b),
            sbyte sb => new Variant(sb),
            byte by => new Variant(by),
            short i16 => new Variant(i16),
            ushort u16 => new Variant(u16),
            int i32 => new Variant(i32),
            uint u32 => new Variant(u32),
            long i64 => new Variant(i64),
            ulong u64 => new Variant(u64),
            float f => new Variant(f),
            double d => new Variant(d),
            string s => new Variant(s),
            DateTimeUtc t => new Variant(t),
            Uuid u => new Variant(u),
            ByteString bs => new Variant(bs),
            XmlElement x => new Variant(x),
            NodeId n => new Variant(n),
            ExpandedNodeId e => new Variant(e),
            StatusCode sc => new Variant(sc),
            QualifiedName qn => new Variant(qn),
            LocalizedText lt => new Variant(lt),
            ExtensionObject eo => new Variant(eo),
            DataValue dv => new Variant(dv),
            Variant inner => inner,
            DiagnosticInfo di => new Variant(di, new TypeInfo(BuiltInType.DiagnosticInfo, ValueRanks.Scalar)),
            _ => throw new InputException("unsupported " + type)
        };

        public static Variant ArrayVariant(string el, Array a) => el switch
        {
            "Boolean" => new Variant(new ArrayOf<bool>((bool[])a)),
            "SByte" => new Variant(new ArrayOf<sbyte>((sbyte[])a)),
            "Byte" => new Variant(new ArrayOf<byte>((byte[])a)),
            "Int16" => new Variant(new ArrayOf<short>((short[])a)),
            "UInt16" => new Variant(new ArrayOf<ushort>((ushort[])a)),
            "Int32" => new Variant(new ArrayOf<int>((int[])a)),
            "UInt32" => new Variant(new ArrayOf<uint>((uint[])a)),
            "Int64" => new Variant(new ArrayOf<long>((long[])a)),
            "UInt64" => new Variant(new ArrayOf<ulong>((ulong[])a)),
            "Float" => new Variant(new ArrayOf<float>((float[])a)),
            "Double" => new Variant(new ArrayOf<double>((double[])a)),
            "String" => new Variant(new ArrayOf<string>((string[])a)),
            "DateTime" => new Variant(new ArrayOf<DateTimeUtc>((DateTimeUtc[])a)),
            "Guid" => new Variant(new ArrayOf<Uuid>((Uuid[])a)),
            "ByteString" => new Variant(new ArrayOf<ByteString>((ByteString[])a)),
            "XmlElement" => new Variant(new ArrayOf<XmlElement>((XmlElement[])a)),
            "NodeId" => new Variant(new ArrayOf<NodeId>((NodeId[])a)),
            "ExpandedNodeId" => new Variant(new ArrayOf<ExpandedNodeId>((ExpandedNodeId[])a)),
            "StatusCode" => new Variant(new ArrayOf<StatusCode>((StatusCode[])a)),
            "QualifiedName" => new Variant(new ArrayOf<QualifiedName>((QualifiedName[])a)),
            "LocalizedText" => new Variant(new ArrayOf<LocalizedText>((LocalizedText[])a)),
            "ExtensionObject" => new Variant(new ArrayOf<ExtensionObject>((ExtensionObject[])a)),
            "DataValue" => new Variant(new ArrayOf<DataValue>((DataValue[])a)),
            "Variant" => new Variant(new ArrayOf<Variant>((Variant[])a)),
            _ => new Variant(a, new TypeInfo(BuiltIn(el), ValueRanks.OneDimension))
        };
    }
}
