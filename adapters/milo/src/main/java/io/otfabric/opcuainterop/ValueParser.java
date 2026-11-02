package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.DiagnosticInfo;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExpandedNodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.Matrix;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.XmlElement;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UByte;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;

import java.lang.reflect.Array;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Literal values for all 25 OPC UA built-in types, 1-D arrays ({@code Type[]})
 * and matrices ({@code Type[]} plus dimensions). The literal grammar is the
 * one of docs/CONTAINER_CONTRACT.md §12 and is shared with the open62541 adapter.
 */
final class ValueParser {

    private ValueParser() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Built-in type name -> Java class used by Milo, in built-in type id order. */
    private static final Map<String, Class<?>> TYPES = new LinkedHashMap<>();
    private static final Map<String, Integer> IDS = new LinkedHashMap<>();

    private static void def(String name, int id, Class<?> cls) {
        TYPES.put(name, cls);
        IDS.put(name, id);
    }

    static {
        def("Boolean", 1, Boolean.class);
        def("SByte", 2, Byte.class);
        def("Byte", 3, UByte.class);
        def("Int16", 4, Short.class);
        def("UInt16", 5, UShort.class);
        def("Int32", 6, Integer.class);
        def("UInt32", 7, UInteger.class);
        def("Int64", 8, Long.class);
        def("UInt64", 9, ULong.class);
        def("Float", 10, Float.class);
        def("Double", 11, Double.class);
        def("String", 12, String.class);
        def("DateTime", 13, DateTime.class);
        def("Guid", 14, UUID.class);
        def("ByteString", 15, ByteString.class);
        def("XmlElement", 16, XmlElement.class);
        def("NodeId", 17, NodeId.class);
        def("ExpandedNodeId", 18, ExpandedNodeId.class);
        def("StatusCode", 19, StatusCode.class);
        def("QualifiedName", 20, QualifiedName.class);
        def("LocalizedText", 21, LocalizedText.class);
        def("ExtensionObject", 22, ExtensionObject.class);
        def("DataValue", 23, DataValue.class);
        def("Variant", 24, Variant.class);
        def("DiagnosticInfo", 25, DiagnosticInfo.class);
    }

    static boolean isBuiltIn(String name) {
        return name != null && TYPES.containsKey(name);
    }

    static int builtInId(String name) {
        Integer id = IDS.get(name);
        return id != null ? id : 0;
    }

    /** Built-in type name of a scalar, array element or matrix element class. */
    static String typeNameOf(Class<?> cls) {
        for (Map.Entry<String, Class<?>> e : TYPES.entrySet()) {
            if (e.getValue().isAssignableFrom(cls)) return e.getKey();
        }
        if (cls == boolean.class) return "Boolean";
        if (cls == byte.class) return "SByte";
        if (cls == short.class) return "Int16";
        if (cls == int.class) return "Int32";
        if (cls == long.class) return "Int64";
        if (cls == float.class) return "Float";
        if (cls == double.class) return "Double";
        return "Unknown";
    }

    /** True when {@code typeStr} is {@code Type} or {@code Type[]} for a built-in type. */
    static boolean supports(String typeStr) {
        if (typeStr == null) return false;
        return isBuiltIn(typeStr.endsWith("[]") ? typeStr.substring(0, typeStr.length() - 2) : typeStr);
    }

    /**
     * Parse a literal.
     *
     * @throws IllegalArgumentException with a message for the result's error object.
     */
    static Variant parse(String typeStr, String val, String dims) {
        if (typeStr == null || typeStr.isEmpty()) throw new IllegalArgumentException("missing type");
        boolean isArray = typeStr.endsWith("[]");
        String name = isArray ? typeStr.substring(0, typeStr.length() - 2) : typeStr;
        Class<?> cls = TYPES.get(name);
        if (cls == null) throw new IllegalArgumentException("unknown type '" + typeStr + "'");
        if (val == null) val = "";

        if (!isArray) {
            if (dims != null && !dims.isEmpty()) {
                throw new IllegalArgumentException("--dimensions requires an array type (" + name + "[])");
            }
            Object v = scalar(name, val);
            // A scalar Variant literal is the inner value itself (Part 6 §5.1.2).
            return (v instanceof Variant inner) ? inner : new Variant(v);
        }

        List<String> items = splitArray(val);
        Object arr = Array.newInstance(cls, items.size());
        for (int i = 0; i < items.size(); i++) {
            Array.set(arr, i, scalar(name, items.get(i)));
        }
        if (dims == null || dims.isEmpty()) return new Variant(arr);

        List<String> dl = splitArray(dims);
        int[] d = new int[dl.size()];
        long product = 1;
        for (int i = 0; i < d.length; i++) {
            d[i] = Integer.parseInt(dl.get(i).trim());
            product *= d[i];
        }
        if (d.length == 0 || product != items.size()) {
            throw new IllegalArgumentException(
                "--dimensions product does not match the " + items.size() + " array elements");
        }
        return new Variant(new Matrix(arr, d));
    }

    private static List<String> splitArray(String val) {
        List<String> out = new ArrayList<>();
        if (val == null || val.isEmpty()) return out;
        if (val.trim().startsWith("[")) {
            try {
                JsonNode arr = MAPPER.readTree(val);
                if (!arr.isArray()) throw new IllegalArgumentException("invalid array literal");
                for (JsonNode el : arr) out.add(el.isTextual() ? el.asText() : el.toString());
                return out;
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalArgumentException("invalid array literal");
            }
        }
        int start = 0;
        for (int i = 0; i <= val.length(); i++) {
            if (i == val.length() || val.charAt(i) == ',') {
                out.add(val.substring(start, i));
                start = i + 1;
            }
        }
        return out;
    }

    static DateTime parseDateTime(String lit) {
        try {
            Instant t = Instant.parse(lit);
            long ticks = (t.getEpochSecond() + 11644473600L) * 10_000_000L + t.getNano() / 100;
            return new DateTime(ticks);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid DateTime literal '" + lit + "' (want RFC 3339 UTC)");
        }
    }

    private static String[] splitTyped(String lit, String what) {
        int colon = lit.indexOf(':');
        if (colon <= 0) throw new IllegalArgumentException("invalid " + what + " literal (want <Type>:<value>)");
        return new String[] {lit.substring(0, colon), lit.substring(colon + 1)};
    }

    static Object scalar(String type, String lit) {
        try {
            switch (type) {
                case "Boolean": return "true".equals(lit) || "1".equals(lit);
                case "SByte":   return Byte.parseByte(lit);
                case "Byte":    return UByte.valueOf(Integer.parseInt(lit));
                case "Int16":   return Short.parseShort(lit);
                case "UInt16":  return UShort.valueOf(Integer.parseInt(lit));
                case "Int32":   return Integer.parseInt(lit);
                case "UInt32":  return UInteger.valueOf(Long.parseLong(lit));
                case "Int64":   return Long.parseLong(lit);
                case "UInt64":  return ULong.valueOf(lit);
                case "Float":   return (float) parseDouble(lit);
                case "Double":  return parseDouble(lit);
                case "String":  return lit;
                case "DateTime": return parseDateTime(lit);
                case "Guid":    return UUID.fromString(lit);
                case "ByteString": return ByteString.of(Base64.getDecoder().decode(lit));
                case "XmlElement": return XmlElement.of(lit);
                case "NodeId":  return NodeId.parse(lit);
                case "ExpandedNodeId": return ExpandedNodeId.parse(lit);
                case "StatusCode": return new StatusCode(Long.decode(lit));
                case "QualifiedName": {
                    int colon = lit.indexOf(':');
                    if (colon < 0) return new QualifiedName(0, lit);
                    return new QualifiedName(Integer.parseInt(lit.substring(0, colon)), lit.substring(colon + 1));
                }
                case "LocalizedText": {
                    int colon = lit.indexOf(':');
                    if (colon < 0) return new LocalizedText(null, lit);
                    String locale = lit.substring(0, colon);
                    return new LocalizedText(locale.isEmpty() ? null : locale, lit.substring(colon + 1));
                }
                case "ExtensionObject": {
                    int bar = lit.indexOf('|');
                    if (bar <= 0) {
                        throw new IllegalArgumentException(
                            "invalid ExtensionObject literal (want <typeId>|<base64 body>)");
                    }
                    NodeId typeId = NodeId.parse(lit.substring(0, bar));
                    byte[] body = Base64.getDecoder().decode(lit.substring(bar + 1));
                    return ExtensionObject.of(ByteString.of(body), typeId);
                }
                case "DataValue": {
                    String[] tv = splitTyped(lit, "DataValue");
                    return DataValue.valueOnly(parse(tv[0], tv[1], null));
                }
                case "Variant": {
                    String[] tv = splitTyped(lit, "Variant");
                    return parse(tv[0], tv[1], null);
                }
                case "DiagnosticInfo": return diagnosticInfo(lit);
                default:
                    throw new IllegalArgumentException("unsupported type '" + type + "'");
            }
        } catch (IllegalArgumentException e) {
            if (e instanceof NumberFormatException) {
                throw new IllegalArgumentException("invalid " + type + " literal '" + lit + "'");
            }
            if (e.getMessage() != null && e.getMessage().startsWith("invalid ")) throw e;
            if (e.getMessage() != null && (e.getMessage().startsWith("unknown type")
                    || e.getMessage().startsWith("unsupported type")
                    || e.getMessage().startsWith("--dimensions"))) throw e;
            throw new IllegalArgumentException("invalid " + type + " literal '" + lit + "'");
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("invalid " + type + " literal '" + lit + "'");
        }
    }

    private static double parseDouble(String lit) {
        switch (lit) {
            case "NaN":       return Double.NaN;
            case "Infinity":  return Double.POSITIVE_INFINITY;
            case "-Infinity": return Double.NEGATIVE_INFINITY;
            default:          return Double.parseDouble(lit);
        }
    }

    private static DiagnosticInfo diagnosticInfo(String lit) {
        int symbolicId = -1, namespaceUri = -1, localizedText = -1, locale = -1;
        String additionalInfo = null;
        StatusCode inner = null;
        for (String tok : lit.split(";")) {
            if (tok.isEmpty()) continue;
            int eq = tok.indexOf('=');
            if (eq <= 0) throw new IllegalArgumentException("invalid DiagnosticInfo literal (want key=value;...)");
            String key = tok.substring(0, eq);
            String val = tok.substring(eq + 1);
            switch (key) {
                case "symbolicId":      symbolicId = Integer.parseInt(val); break;
                case "namespaceUri":    namespaceUri = Integer.parseInt(val); break;
                case "localizedText":   localizedText = Integer.parseInt(val); break;
                case "locale":          locale = Integer.parseInt(val); break;
                case "additionalInfo":  additionalInfo = val; break;
                case "innerStatusCode": inner = new StatusCode(Long.decode(val)); break;
                default:
                    throw new IllegalArgumentException("invalid DiagnosticInfo literal (want key=value;...)");
            }
        }
        return new DiagnosticInfo(namespaceUri, symbolicId, locale, localizedText, additionalInfo, inner, null);
    }
}
