package io.otfabric.opcuainterop;

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
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Canonical result-value encoding (docs/CONTAINER_CONTRACT.md §7) for every
 * built-in type, arrays and matrices. Used by the {@code codec} command; the
 * older commands keep {@link ResultBuilder#encodeVariantValue}.
 */
final class Canonical {

    private Canonical() {}

    /** Element class of a scalar, array or matrix value. */
    static Class<?> elementClass(Object val) {
        if (val instanceof Matrix m) {
            Object el = m.getElements();
            return el != null ? componentOf(el.getClass()) : Object.class;
        }
        return componentOf(val.getClass());
    }

    private static Class<?> componentOf(Class<?> c) {
        while (c.isArray()) c = c.getComponentType();
        return c;
    }

    /** Adds dataType, builtInType, valueRank, [arrayDimensions] and value. */
    static void putVariantFields(Map<String, Object> out, Variant v) {
        if (v == null || v.isNull()) {
            out.put("dataType", "Null");
            out.put("builtInType", 0);
            out.put("valueRank", -1);
            out.put("value", null);
            return;
        }
        Object val = v.getValue();
        String name = ValueParser.typeNameOf(elementClass(val));
        if ("Unknown".equals(name)) name = elementClass(val).getSimpleName();
        out.put("dataType", name);
        out.put("builtInType", ValueParser.builtInId(name));
        if (val instanceof Matrix m) {
            int[] dims = m.getDimensions();
            if (dims.length > 1) {
                out.put("valueRank", dims.length);
                List<Integer> dl = new ArrayList<>();
                for (int d : dims) dl.add(d);
                out.put("arrayDimensions", dl);
            } else {
                out.put("valueRank", 1);
            }
        } else {
            out.put("valueRank", val.getClass().isArray() ? 1 : -1);
        }
        out.put("value", value(val));
    }

    static Map<String, Object> dataValue(DataValue dv) {
        Map<String, Object> m = new LinkedHashMap<>();
        Variant v = dv.getValue();
        if (v != null && v.isNotNull()) {
            Map<String, Object> vf = new LinkedHashMap<>();
            putVariantFields(vf, v);
            m.put("dataType", vf.get("dataType"));
            m.put("builtInType", vf.get("builtInType"));
            if (vf.containsKey("arrayDimensions")) m.put("arrayDimensions", vf.get("arrayDimensions"));
            m.put("value", vf.get("value"));
        }
        // Milo's DataValue always carries a StatusCode; Good is the "absent" value.
        if (dv.getStatusCode() != null && dv.getStatusCode().getValue() != 0L) {
            m.put("statusCode", ResultBuilder.statusCodeJson(dv.getStatusCode()));
        }
        if (dv.getSourceTime() != null) m.put("sourceTimestamp", timestamp(dv.getSourceTime()));
        if (dv.getSourcePicoseconds() != null) m.put("sourcePicoseconds", dv.getSourcePicoseconds().intValue());
        if (dv.getServerTime() != null) m.put("serverTimestamp", timestamp(dv.getServerTime()));
        if (dv.getServerPicoseconds() != null) m.put("serverPicoseconds", dv.getServerPicoseconds().intValue());
        return m;
    }

    private static String timestamp(DateTime t) {
        return t.getJavaInstant().toString();
    }

    /** Canonical JSON-ready representation of a Variant payload. */
    static Object value(Object val) {
        if (val == null) return null;
        if (val instanceof Matrix m) {
            Object el = m.getElements();
            return el == null ? null : flatten(el, new ArrayList<>());
        }
        if (val.getClass().isArray()) return flatten(val, new ArrayList<>());

        if (val instanceof Long || val instanceof ULong) return val.toString();
        if (val instanceof Float f) return Float.isFinite(f) ? f : null;
        if (val instanceof Double d) return Double.isFinite(d) ? d : null;
        if (val instanceof DateTime t) return t.getJavaInstant().toString();
        if (val instanceof UUID) return val.toString().toLowerCase();
        if (val instanceof ByteString bs) {
            return bs.bytes() != null ? Base64.getEncoder().encodeToString(bs.bytes()) : null;
        }
        if (val instanceof XmlElement x) return x.getFragment();
        if (val instanceof NodeId n) return ResultBuilder.nodeIdToString(n);
        if (val instanceof ExpandedNodeId e) return expandedNodeId(e);
        if (val instanceof StatusCode sc) return ResultBuilder.statusCodeJson(sc);
        if (val instanceof QualifiedName qn) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ns", qn.getNamespaceIndex().intValue());
            m.put("name", qn.getName() != null ? qn.getName() : "");
            return m;
        }
        if (val instanceof LocalizedText lt) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("locale", lt.getLocale() != null ? lt.getLocale() : "");
            m.put("text", lt.getText() != null ? lt.getText() : "");
            return m;
        }
        if (val instanceof ExtensionObject eo) return extensionObject(eo);
        if (val instanceof DataValue dv) return dataValue(dv);
        if (val instanceof Variant inner) {
            if (inner.isNull()) return null;
            Map<String, Object> vf = new LinkedHashMap<>();
            putVariantFields(vf, inner);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("dataType", vf.get("dataType"));
            m.put("builtInType", vf.get("builtInType"));
            m.put("value", vf.get("value"));
            return m;
        }
        if (val instanceof DiagnosticInfo di) return diagnosticInfo(di);
        if (val instanceof Number || val instanceof Boolean || val instanceof String) return val;
        return String.valueOf(val);
    }

    private static List<Object> flatten(Object arr, List<Object> out) {
        int n = Array.getLength(arr);
        for (int i = 0; i < n; i++) {
            Object el = Array.get(arr, i);
            if (el != null && el.getClass().isArray()) flatten(el, out);
            else out.add(value(el));
        }
        return out;
    }

    private static String expandedNodeId(ExpandedNodeId e) {
        StringBuilder sb = new StringBuilder();
        if (e.getServerIndex() != null && e.getServerIndex().longValue() != 0) {
            sb.append("svr=").append(e.getServerIndex().longValue()).append(';');
        }
        if (e.getNamespaceUri() != null && !e.getNamespaceUri().isEmpty()) {
            sb.append("nsu=").append(e.getNamespaceUri()).append(';');
        } else if (e.getNamespaceIndex() != null && e.getNamespaceIndex().intValue() != 0) {
            sb.append("ns=").append(e.getNamespaceIndex().intValue()).append(';');
        }
        Object id = e.getIdentifier();
        if (id instanceof String) sb.append("s=").append(id);
        else if (id instanceof UUID) sb.append("g=").append(id.toString().toLowerCase());
        else if (id instanceof ByteString bs) {
            sb.append("b=").append(bs.bytes() != null ? Base64.getEncoder().encodeToString(bs.bytes()) : "");
        } else sb.append("i=").append(id);
        return sb.toString();
    }

    private static Object extensionObject(ExtensionObject eo) {
        Object body = eo.getBody();
        if (body == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("typeId", ResultBuilder.nodeIdToString(eo.getEncodingOrTypeId()));
        if (body instanceof ByteString bs) {
            m.put("encoding", "binary");
            m.put("body", bs.bytes() != null ? Base64.getEncoder().encodeToString(bs.bytes()) : "");
        } else if (body instanceof XmlElement x) {
            m.put("encoding", "xml");
            m.put("body", x.getFragment() != null ? x.getFragment() : "");
        } else {
            m.put("encoding", "json");
            m.put("body", String.valueOf(body));
        }
        return m;
    }

    private static Map<String, Object> diagnosticInfo(DiagnosticInfo di) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (di.symbolicId() >= 0) m.put("symbolicId", di.symbolicId());
        if (di.namespaceUri() >= 0) m.put("namespaceUri", di.namespaceUri());
        if (di.localizedText() >= 0) m.put("localizedText", di.localizedText());
        if (di.locale() >= 0) m.put("locale", di.locale());
        if (di.additionalInfo() != null) m.put("additionalInfo", di.additionalInfo());
        if (di.innerStatusCode() != null) m.put("innerStatusCode", ResultBuilder.statusCodeJson(di.innerStatusCode()));
        if (di.innerDiagnosticInfo() != null) m.put("innerDiagnosticInfo", diagnosticInfo(di.innerDiagnosticInfo()));
        return m;
    }
}
