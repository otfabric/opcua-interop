package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;

import java.util.*;

public class ResultBuilder {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    static final String ADAPTER = "milo";
    static final String SCHEMA_VERSION = "1.0";

    private final String operation;
    private boolean success = true;
    private Map<String, Object> serviceResult = statusCodeJson(StatusCode.GOOD);
    private final List<Object> results = new ArrayList<>();
    private Map<String, Object> error = null;

    public ResultBuilder(String operation) {
        this.operation = operation;
    }

    public ResultBuilder success(boolean s) { this.success = s; return this; }
    public ResultBuilder serviceResult(StatusCode sc) { this.serviceResult = statusCodeJson(sc); return this; }
    public ResultBuilder serviceResult(long code) { this.serviceResult = statusCodeJson(new StatusCode(code)); return this; }
    public ResultBuilder addResult(Object r) { this.results.add(r); return this; }
    public ResultBuilder error(String category, String message) {
        this.success = false;
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("category", category);
        e.put("message", message);
        this.error = e;
        return this;
    }

    public Map<String, Object> build() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schemaVersion", SCHEMA_VERSION);
        out.put("adapter",       ADAPTER);
        out.put("operation",     operation);
        out.put("success",       success);
        out.put("serviceResult", serviceResult);
        out.put("results",       results);
        out.put("error",         error);
        return out;
    }

    public String toJson() {
        try { return MAPPER.writeValueAsString(build()); }
        catch (Exception e) { return "{\"error\":\"serialization failed\"}"; }
    }

    /** Structured status code: {"name":"Good","code":0,"severity":"Good"} */
    public static Map<String, Object> statusCodeJson(StatusCode sc) {
        long value = sc.getValue();
        String name = StatusCodes.lookup(value)
                .map(arr -> arr[0])
                .orElse(sc.isGood() ? "Good" : sc.isUncertain() ? "Uncertain" : "Bad");
        String severity = sc.isGood() ? "Good" : sc.isUncertain() ? "Uncertain" : "Bad";
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name",     name);
        m.put("code",     value);
        m.put("severity", severity);
        return m;
    }

    /** NodeId to canonical compact string: "i=85", "ns=1;s=Scalars", etc. */
    public static String nodeIdToString(org.eclipse.milo.opcua.stack.core.types.builtin.NodeId nid) {
        int ns = nid.getNamespaceIndex().intValue();
        Object id = nid.getIdentifier();
        if (id instanceof org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger) {
            long v = ((org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger) id).longValue();
            return (ns == 0) ? "i=" + v : "ns=" + ns + ";i=" + v;
        } else if (id instanceof String) {
            return "ns=" + ns + ";s=" + id;
        } else if (id instanceof java.util.UUID) {
            return "ns=" + ns + ";g=" + id.toString().toLowerCase();
        } else if (id instanceof org.eclipse.milo.opcua.stack.core.types.builtin.ByteString) {
            byte[] bytes = ((org.eclipse.milo.opcua.stack.core.types.builtin.ByteString) id).bytes();
            return "ns=" + ns + ";b=" + (bytes != null ? java.util.Base64.getEncoder().encodeToString(bytes) : "");
        }
        return nid.toParseableString();
    }

    /** Value encoding per CLIENT_CONTRACT §7 */
    public static Object encodeVariantValue(org.eclipse.milo.opcua.stack.core.types.builtin.Variant v) {
        if (v == null || v.isNull()) return null;
        Object val = v.getValue();
        if (val instanceof Long)   return val.toString();
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong)
                                   return val.toString();
        if (val instanceof Float) {
            float f = (Float) val;
            return Float.isFinite(f) ? val : null;
        }
        if (val instanceof Double) {
            double d = (Double) val;
            return Double.isFinite(d) ? val : null;
        }
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.DateTime) {
            return ((org.eclipse.milo.opcua.stack.core.types.builtin.DateTime) val)
                    .getJavaInstant().toString();
        }
        if (val instanceof java.util.UUID) {
            return val.toString().toLowerCase();
        }
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.ByteString) {
            byte[] bytes = ((org.eclipse.milo.opcua.stack.core.types.builtin.ByteString) val).bytes();
            return bytes != null ? java.util.Base64.getEncoder().encodeToString(bytes) : null;
        }
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.NodeId) {
            return nodeIdToString((org.eclipse.milo.opcua.stack.core.types.builtin.NodeId) val);
        }
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName) {
            var qn = (org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName) val;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ns",   qn.getNamespaceIndex().intValue());
            m.put("name", qn.getName());
            return m;
        }
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText) {
            var lt = (org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText) val;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("locale", lt.getLocale() != null ? lt.getLocale() : "");
            m.put("text",   lt.getText()   != null ? lt.getText()   : "");
            return m;
        }
        if (val instanceof StatusCode) {
            return statusCodeJson((StatusCode) val);
        }
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.XmlElement) {
            return ((org.eclipse.milo.opcua.stack.core.types.builtin.XmlElement) val).getFragment();
        }
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.Matrix) {
            return ((org.eclipse.milo.opcua.stack.core.types.builtin.Matrix) val).nestedArrayValue();
        }
        return val;
    }

    /** Get the OPC UA built-in type name from a Variant. */
    public static String builtInTypeName(org.eclipse.milo.opcua.stack.core.types.builtin.Variant v) {
        if (v == null || v.isNull()) return "Unknown";
        Object val = v.getValue();
        if (val instanceof Boolean)   return "Boolean";
        if (val instanceof Byte)      return "SByte";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UByte) return "Byte";
        if (val instanceof Short)     return "Int16";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort) return "UInt16";
        if (val instanceof Integer)   return "Int32";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger) return "UInt32";
        if (val instanceof Long)      return "Int64";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong) return "UInt64";
        if (val instanceof Float)     return "Float";
        if (val instanceof Double)    return "Double";
        if (val instanceof String)    return "String";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.DateTime) return "DateTime";
        if (val instanceof java.util.UUID) return "Guid";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.ByteString) return "ByteString";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.NodeId) return "NodeId";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName) return "QualifiedName";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText) return "LocalizedText";
        if (val instanceof StatusCode) return "StatusCode";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.XmlElement) return "XmlElement";
        if (val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.Matrix) return "Unknown";
        return "Unknown";
    }

    /** Get built-in type integer from type name (per OPC UA Part 6 §5.1.2). */
    public static int builtInTypeId(String name) {
        switch (name) {
            case "Boolean":       return 1;
            case "SByte":         return 2;
            case "Byte":          return 3;
            case "Int16":         return 4;
            case "UInt16":        return 5;
            case "Int32":         return 6;
            case "UInt32":        return 7;
            case "Int64":         return 8;
            case "UInt64":        return 9;
            case "Float":         return 10;
            case "Double":        return 11;
            case "String":        return 12;
            case "DateTime":      return 13;
            case "Guid":          return 14;
            case "ByteString":    return 15;
            case "XmlElement":    return 16;
            case "NodeId":        return 17;
            case "StatusCode":    return 19;
            case "QualifiedName": return 20;
            case "LocalizedText": return 21;
            default:              return 0;
        }
    }
}
