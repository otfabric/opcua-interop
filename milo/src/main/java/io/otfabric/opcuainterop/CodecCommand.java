package io.otfabric.opcuainterop;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NamespaceTable;
import org.eclipse.milo.opcua.stack.core.ServerTable;
import org.eclipse.milo.opcua.stack.core.channel.EncodingLimits;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingManager;
import org.eclipse.milo.opcua.stack.core.types.DataTypeManager;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaSerializationException;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.UaDecoder;
import org.eclipse.milo.opcua.stack.core.encoding.UaEncoder;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryEncoder;
import org.eclipse.milo.opcua.stack.core.encoding.json.OpcUaJsonDecoder;
import org.eclipse.milo.opcua.stack.core.encoding.json.OpcUaJsonEncoder;
import org.eclipse.milo.opcua.stack.core.encoding.xml.OpcUaXmlDecoder;
import org.eclipse.milo.opcua.stack.core.encoding.xml.OpcUaXmlEncoder;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.DiagnosticInfo;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExpandedNodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.XmlElement;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UByte;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadValueId;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * {@code client codec} — OPC UA JSON / XML DataEncoding of built-in values,
 * done by Milo's stack-level encoders ({@code milo-encoding-json},
 * {@code milo-encoding-xml}). Same command line and result shapes as the
 * open62541 adapter; see docs/CLIENT_CONTRACT.md.
 *
 * Milo implements the OPC UA 1.05 JSON encoding in both of its modes, so
 * {@code --json-mode compact|verbose} is honoured.
 */
final class CodecCommand {

    private CodecCommand() {}

    private static final String OP = "codec";
    /**
     * Encoding context of the current invocation. The OPC UA 1.05 JSON encoding
     * writes namespace URIs, so NodeIds / QualifiedNames with a namespace index
     * other than 0 can only be encoded when the namespace table knows the URI:
     * for values read from a server it is the server's NamespaceArray, for
     * literals it is built from the repeatable {@code --namespace-uri} flag
     * (index 1, 2, ...).
     */
    private static EncodingContext CTX = DefaultEncodingContext.INSTANCE;

    private static EncodingContext contextWith(NamespaceTable table) {
        final EncodingContext base = DefaultEncodingContext.INSTANCE;
        return new EncodingContext() {
            @Override public DataTypeManager getDataTypeManager() { return base.getDataTypeManager(); }
            @Override public EncodingManager getEncodingManager() { return base.getEncodingManager(); }
            @Override public EncodingLimits getEncodingLimits() { return base.getEncodingLimits(); }
            @Override public NamespaceTable getNamespaceTable() { return table; }
            @Override public ServerTable getServerTable() { return base.getServerTable(); }
        };
    }

    private static void useNamespaceFlags(String[] args) {
        List<String> uris = findAll(args, "--namespace-uri");
        if (uris.isEmpty()) return;
        NamespaceTable table = new NamespaceTable();
        for (String uri : uris) table.add(uri);
        CTX = contextWith(table);
    }
    private static final String USAGE =
        "usage: codec encode --format json|xml (--type <T> --value <v> | --endpoint <url> --node <id>)"
        + " | codec decode --format json|xml --type <T>"
        + " | codec --endpoint <url> --node <id> [--node ...]"
        + " | codec --decode json|xml --type <T>";

    /** A document, or the status that prevented it. */
    private static final class Doc {
        final String text;
        final StatusCode status;
        Doc(String text, StatusCode status) { this.text = text; this.status = status; }
        boolean ok() { return status.isGood(); }
    }

    static int run(String[] args) throws Exception {
        if (args.length < 1) return usage(USAGE);
        useNamespaceFlags(args);
        if ("encode".equals(args[0])) return encode(args);
        if ("decode".equals(args[0])) return decode(args);
        if (find(args, "--decode") != null) return decode(args);
        if (find(args, "--node") != null) return nodes(args);
        return usage(USAGE);
    }

    private static int usage(String msg) {
        System.out.println(new ResultBuilder(OP).serviceResult(StatusCodes.Bad_InvalidArgument)
            .error("input", msg).toJson());
        return 2;
    }

    private static String find(String[] args, String flag) {
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) return args[i + 1];
        }
        return null;
    }

    private static List<String> findAll(String[] args, String flag) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) out.add(args[i + 1]);
        }
        return out;
    }

    private static String format(String[] args) {
        String f = find(args, "--format");
        if (f == null) f = find(args, "--decode");
        return ("json".equals(f) || "xml".equals(f)) ? f : null;
    }

    private static OpcUaJsonEncoder.Encoding jsonMode(String[] args) {
        String m = find(args, "--json-mode");
        if (m == null || "compact".equals(m)) return OpcUaJsonEncoder.Encoding.COMPACT;
        if ("verbose".equals(m)) return OpcUaJsonEncoder.Encoding.VERBOSE;
        return null;
    }

    private static String modeName(OpcUaJsonEncoder.Encoding mode) {
        return mode == OpcUaJsonEncoder.Encoding.VERBOSE ? "verbose" : "compact";
    }

    // ---------------------------------------------------------------------
    // Typed encode / decode against the stack's UaEncoder / UaDecoder
    // ---------------------------------------------------------------------

    private static void encodeTyped(UaEncoder enc, String field, String type, Object v) {
        switch (type) {
            case "Boolean":         enc.encodeBoolean(field, (Boolean) v); break;
            case "SByte":           enc.encodeSByte(field, (Byte) v); break;
            case "Byte":            enc.encodeByte(field, (UByte) v); break;
            case "Int16":           enc.encodeInt16(field, (Short) v); break;
            case "UInt16":          enc.encodeUInt16(field, (UShort) v); break;
            case "Int32":           enc.encodeInt32(field, (Integer) v); break;
            case "UInt32":          enc.encodeUInt32(field, (UInteger) v); break;
            case "Int64":           enc.encodeInt64(field, (Long) v); break;
            case "UInt64":          enc.encodeUInt64(field, (ULong) v); break;
            case "Float":           enc.encodeFloat(field, (Float) v); break;
            case "Double":          enc.encodeDouble(field, (Double) v); break;
            case "String":          enc.encodeString(field, (String) v); break;
            case "DateTime":        enc.encodeDateTime(field, (DateTime) v); break;
            case "Guid":            enc.encodeGuid(field, (UUID) v); break;
            case "ByteString":      enc.encodeByteString(field, (ByteString) v); break;
            case "XmlElement":      enc.encodeXmlElement(field, (XmlElement) v); break;
            case "NodeId":          enc.encodeNodeId(field, (NodeId) v); break;
            case "ExpandedNodeId":  enc.encodeExpandedNodeId(field, (ExpandedNodeId) v); break;
            case "StatusCode":      enc.encodeStatusCode(field, (StatusCode) v); break;
            case "QualifiedName":   enc.encodeQualifiedName(field, (QualifiedName) v); break;
            case "LocalizedText":   enc.encodeLocalizedText(field, (LocalizedText) v); break;
            case "ExtensionObject": enc.encodeExtensionObject(field, (ExtensionObject) v); break;
            case "DataValue":       enc.encodeDataValue(field, (DataValue) v); break;
            case "Variant":         enc.encodeVariant(field, (Variant) v); break;
            case "DiagnosticInfo":  enc.encodeDiagnosticInfo(field, (DiagnosticInfo) v); break;
            default:
                throw new UaSerializationException(StatusCodes.Bad_EncodingError, "unsupported type " + type);
        }
    }

    private static Object decodeTyped(UaDecoder dec, String field, String type) {
        switch (type) {
            case "Boolean":         return dec.decodeBoolean(field);
            case "SByte":           return dec.decodeSByte(field);
            case "Byte":            return dec.decodeByte(field);
            case "Int16":           return dec.decodeInt16(field);
            case "UInt16":          return dec.decodeUInt16(field);
            case "Int32":           return dec.decodeInt32(field);
            case "UInt32":          return dec.decodeUInt32(field);
            case "Int64":           return dec.decodeInt64(field);
            case "UInt64":          return dec.decodeUInt64(field);
            case "Float":           return dec.decodeFloat(field);
            case "Double":          return dec.decodeDouble(field);
            case "String":          return dec.decodeString(field);
            case "DateTime":        return dec.decodeDateTime(field);
            case "Guid":            return dec.decodeGuid(field);
            case "ByteString":      return dec.decodeByteString(field);
            case "XmlElement":      return dec.decodeXmlElement(field);
            case "NodeId":          return dec.decodeNodeId(field);
            case "ExpandedNodeId":  return dec.decodeExpandedNodeId(field);
            case "StatusCode":      return dec.decodeStatusCode(field);
            case "QualifiedName":   return dec.decodeQualifiedName(field);
            case "LocalizedText":   return dec.decodeLocalizedText(field);
            case "ExtensionObject": return dec.decodeExtensionObject(field);
            case "DataValue":       return dec.decodeDataValue(field);
            case "Variant":         return dec.decodeVariant(field);
            case "DiagnosticInfo":  return dec.decodeDiagnosticInfo(field);
            default:
                throw new UaSerializationException(StatusCodes.Bad_DecodingError, "unsupported type " + type);
        }
    }

    private static StatusCode statusOf(Throwable t, long fallback) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof UaSerializationException use) return use.getStatusCode();
        }
        return new StatusCode(fallback);
    }

    private static Doc encodeDoc(String fmt, OpcUaJsonEncoder.Encoding mode, String type, Object v) {
        try {
            if ("json".equals(fmt)) {
                OpcUaJsonEncoder enc = new OpcUaJsonEncoder(CTX);
                enc.setEncoding(mode);
                encodeTyped(enc, null, type, v);
                return new Doc(enc.getOutputString(), StatusCode.GOOD);
            }
            try (OpcUaXmlEncoder enc = new OpcUaXmlEncoder(CTX)) {
                encodeTyped(enc, type, type, v);
                return new Doc(enc.getOutputString(), StatusCode.GOOD);
            }
        } catch (Throwable t) {
            return new Doc(null, statusOf(t, StatusCodes.Bad_EncodingError));
        }
    }

    private static String binary(String type, Object v) {
        ByteBuf buf = Unpooled.buffer();
        try {
            OpcUaBinaryEncoder enc = new OpcUaBinaryEncoder(CTX).setBuffer(buf);
            encodeTyped(enc, null, type, v);
            return Base64.getEncoder().encodeToString(ByteBufUtil.getBytes(buf));
        } catch (Throwable t) {
            return null;
        } finally {
            buf.release();
        }
    }

    private static boolean isScalar(Variant v) {
        if (v == null || v.isNull()) return false;
        Object val = v.getValue();
        return !val.getClass().isArray()
            && !(val instanceof org.eclipse.milo.opcua.stack.core.types.builtin.Matrix);
    }

    // ---------------------------------------------------------------------
    // encode
    // ---------------------------------------------------------------------

    private static int encode(String[] args) throws Exception {
        String fmt = format(args);
        if (fmt == null) return usage("codec encode: --format json|xml is required");
        OpcUaJsonEncoder.Encoding mode = jsonMode(args);
        if (mode == null) return usage("--json-mode must be compact or verbose");

        String nodeStr  = find(args, "--node");
        String typeStr  = find(args, "--type");
        String valStr   = find(args, "--value");
        String endpoint = find(args, "--endpoint");

        DataValue dv;
        NodeId nodeId = null;
        if (nodeStr != null) {
            if (typeStr != null || valStr != null) return usage("codec encode: use either --node or --type/--value");
            if (endpoint == null) return usage("codec encode --node requires --endpoint");
            long cto = ClientCommand.connectTimeoutMs(args);
            long rto = ClientCommand.requestTimeoutMs(args);
            OpcUaClient client = ClientCommand.connectClient(endpoint, cto, rto, args);
            try {
                nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);
                CTX = contextWith(client.readNamespaceTable());
                ReadResponse resp = client.read(0.0, TimestampsToReturn.Both,
                    List.of(new ReadValueId(nodeId, AttributeId.Value.uid(), null, null)));
                dv = resp.getResults()[0];
            } finally {
                ClientCommand.safeDisconnect(client, ClientCommand.disconnectTimeoutMs(args));
            }
            if (dv.getStatusCode() != null && dv.getStatusCode().isBad()) {
                System.out.println(new ResultBuilder(OP).serviceResult(dv.getStatusCode())
                    .error("service", "Read of --node failed").toJson());
                return 4;
            }
        } else {
            if (typeStr == null || valStr == null) {
                return usage("codec encode: --type and --value (or --node) are required");
            }
            Variant v;
            try {
                v = ValueParser.parse(typeStr, valStr, find(args, "--dimensions"));
            } catch (IllegalArgumentException e) {
                return usage(e.getMessage());
            }
            DataValue.Builder b = DataValue.newValue().setValue(v).setStatus(StatusCode.GOOD);
            try {
                String s;
                if ((s = find(args, "--status")) != null) b.setStatus(new StatusCode(Long.decode(s)));
                if ((s = find(args, "--source-timestamp")) != null) b.setSourceTime(ValueParser.parseDateTime(s));
                if ((s = find(args, "--server-timestamp")) != null) b.setServerTime(ValueParser.parseDateTime(s));
                if ((s = find(args, "--source-picoseconds")) != null) {
                    b.setSourcePicoseconds(UShort.valueOf(Integer.parseInt(s)));
                }
                if ((s = find(args, "--server-picoseconds")) != null) {
                    b.setServerPicoseconds(UShort.valueOf(Integer.parseInt(s)));
                }
            } catch (IllegalArgumentException e) {
                return usage("invalid DataValue flag: " + e.getMessage());
            }
            dv = b.build();
        }

        Variant v = dv.getValue() != null ? dv.getValue() : Variant.NULL_VALUE;
        boolean scalar = isScalar(v);
        String scalarType = scalar ? ValueParser.typeNameOf(v.getValue().getClass()) : null;
        if (scalar && !ValueParser.isBuiltIn(scalarType)) scalar = false;

        Doc docVariant = encodeDoc(fmt, mode, "Variant", v);
        Doc docDataValue = encodeDoc(fmt, mode, "DataValue", dv);
        Doc docValue = scalar ? encodeDoc(fmt, mode, scalarType, v.getValue()) : null;

        Map<String, Object> item = new LinkedHashMap<>();
        item.put("action", "encode");
        item.put("format", fmt);
        if ("json".equals(fmt)) item.put("jsonMode", modeName(mode));
        item.put("source", nodeId != null ? "node" : "literal");
        if (nodeId != null) item.put("nodeId", ResultBuilder.nodeIdToString(nodeId));
        Canonical.putVariantFields(item, v);
        item.put("dataValue", Canonical.dataValue(dv));

        Map<String, Object> encoded = new LinkedHashMap<>();
        Map<String, Object> statuses = new LinkedHashMap<>();
        Map<String, Object> bin = new LinkedHashMap<>();
        if (scalar) {
            encoded.put("value", docValue.text);
            statuses.put("value", ResultBuilder.statusCodeJson(docValue.status));
            bin.put("value", binary(scalarType, v.getValue()));
        }
        encoded.put("variant", docVariant.text);
        encoded.put("dataValue", docDataValue.text);
        statuses.put("variant", ResultBuilder.statusCodeJson(docVariant.status));
        statuses.put("dataValue", ResultBuilder.statusCodeJson(docDataValue.status));
        bin.put("variant", binary("Variant", v));
        bin.put("dataValue", binary("DataValue", dv));
        item.put("encoded", encoded);
        item.put("statusCodes", statuses);
        item.put("binary", bin);

        ResultBuilder rb = new ResultBuilder(OP).serviceResult(docVariant.status).addResult(item);
        if (!docVariant.ok()) rb.error("service", "encoding failed");
        System.out.println(rb.toJson());
        return docVariant.ok() ? 0 : 4;
    }

    // ---------------------------------------------------------------------
    // decode
    // ---------------------------------------------------------------------

    private static String stripProlog(String xml) {
        String s = xml.trim();
        while (s.startsWith("<?") || s.startsWith("<!--")) {
            int end = s.startsWith("<?") ? s.indexOf("?>") : s.indexOf("-->");
            if (end < 0) break;
            s = s.substring(end + (s.startsWith("<?") ? 2 : 3)).trim();
        }
        return s;
    }

    private static int decode(String[] args) throws Exception {
        String fmt = format(args);
        if (fmt == null) return usage("codec decode: --format json|xml is required");
        OpcUaJsonEncoder.Encoding mode = jsonMode(args);
        if (mode == null) return usage("--json-mode must be compact or verbose");
        String type = find(args, "--type");
        if (type == null) return usage("codec decode: --type <BuiltInType|Variant|DataValue> is required");
        if (!ValueParser.isBuiltIn(type)) {
            return usage("unknown --type '" + type + "' (arrays are decoded as Variant)");
        }

        String doc = find(args, "--document");
        if (doc == null) {
            String input = find(args, "--input");
            byte[] raw;
            try {
                raw = input != null ? Files.readAllBytes(Paths.get(input)) : System.in.readAllBytes();
            } catch (Exception e) {
                return usage("cannot read the input document");
            }
            doc = new String(raw, StandardCharsets.UTF_8);
        }
        doc = doc.stripTrailing();
        if (doc.isEmpty()) return usage("empty input document (stdin, --input or --document)");

        Object value = null;
        StatusCode sc = StatusCode.GOOD;
        try {
            if ("json".equals(fmt)) {
                value = decodeTyped(new OpcUaJsonDecoder(CTX, doc), null, type);
            } else {
                // Milo's XML decoder starts at the document element; a null field
                // name accepts it whatever its name / namespace prefix is.
                OpcUaXmlDecoder dec = new OpcUaXmlDecoder(CTX, stripProlog(doc));
                value = decodeTyped(dec, null, type);
            }
        } catch (Throwable t) {
            sc = statusOf(t, StatusCodes.Bad_DecodingError);
        }
        boolean ok = sc.isGood();

        Map<String, Object> item = new LinkedHashMap<>();
        item.put("action", "decode");
        item.put("format", fmt);
        if ("json".equals(fmt)) item.put("jsonMode", modeName(mode));
        item.put("type", type);
        item.put("statusCode", ResultBuilder.statusCodeJson(sc));
        if (ok) {
            if ("Variant".equals(type)) {
                Canonical.putVariantFields(item, (Variant) value);
            } else if ("DataValue".equals(type)) {
                DataValue dv = (DataValue) value;
                Canonical.putVariantFields(item, dv.getValue());
                item.put("dataValue", Canonical.dataValue(dv));
            } else {
                item.put("dataType", type);
                item.put("builtInType", ValueParser.builtInId(type));
                item.put("valueRank", -1);
                item.put("value", Canonical.value(value));
            }
            item.put("binary", binary(type, value));
            item.put("reencoded", encodeDoc(fmt, mode, type, value).text);
        }
        ResultBuilder rb = new ResultBuilder(OP).serviceResult(sc).addResult(item);
        if (!ok) rb.error("service", "decoding failed");
        System.out.println(rb.toJson());
        return ok ? 0 : 4;
    }

    // ---------------------------------------------------------------------
    // short form: codec --endpoint <url> --node <id> [--node ...]
    // ---------------------------------------------------------------------

    private static int nodes(String[] args) throws Exception {
        String endpoint = find(args, "--endpoint");
        List<String> nodeStrs = findAll(args, "--node");
        if (endpoint == null || nodeStrs.isEmpty()) {
            return usage("usage: codec --endpoint <url> --node <nodeId> [--node ...]");
        }
        OpcUaJsonEncoder.Encoding mode = jsonMode(args);
        if (mode == null) return usage("--json-mode must be compact or verbose");
        long cto = ClientCommand.connectTimeoutMs(args);
        long rto = ClientCommand.requestTimeoutMs(args);

        List<NodeId> ids = new ArrayList<>();
        DataValue[] dvs;
        OpcUaClient client = ClientCommand.connectClient(endpoint, cto, rto, args);
        try {
            CTX = contextWith(client.readNamespaceTable());
            List<ReadValueId> rvis = new ArrayList<>();
            for (String s : nodeStrs) {
                NodeId id = NodeIdParser.resolveWithClient(s, client, rto);
                ids.add(id);
                rvis.add(new ReadValueId(id, AttributeId.Value.uid(), null, null));
            }
            dvs = client.read(0.0, TimestampsToReturn.Both, rvis).getResults();
        } finally {
            ClientCommand.safeDisconnect(client, ClientCommand.disconnectTimeoutMs(args));
        }

        ResultBuilder rb = new ResultBuilder(OP);
        boolean ok = true;
        StatusCode emit = StatusCode.GOOD;
        for (int i = 0; i < ids.size(); i++) {
            DataValue dv = dvs[i];
            StatusCode item = dv.getStatusCode() != null ? dv.getStatusCode() : StatusCode.GOOD;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("nodeId", ResultBuilder.nodeIdToString(ids.get(i)));
            m.put("statusCode", ResultBuilder.statusCodeJson(item));
            if (!item.isBad()) {
                Variant v = dv.getValue() != null ? dv.getValue() : Variant.NULL_VALUE;
                Canonical.putVariantFields(m, v);
                Doc json = encodeDoc("json", mode, "Variant", v);
                m.put("json", json.text);
                m.put("xml", encodeDoc("xml", mode, "Variant", v).text);
                m.put("dataValueJson", encodeDoc("json", mode, "DataValue", dv).text);
                m.put("dataValueXml", encodeDoc("xml", mode, "DataValue", dv).text);
                m.put("binary", binary("Variant", v));
                m.put("dataValueBinary", binary("DataValue", dv));
                if (!json.ok()) {
                    ok = false;
                    if (emit.isGood()) emit = json.status;
                }
            } else {
                m.put("json", null);
                m.put("xml", null);
                ok = false;
                if (emit.isGood()) emit = item;
            }
            rb.addResult(m);
        }
        rb.serviceResult(emit);
        if (!ok) rb.error("service", "read or encoding failed");
        System.out.println(rb.toJson());
        return ok ? 0 : 4;
    }
}
