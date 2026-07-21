package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.api.config.OpcUaClientConfig;
import org.eclipse.milo.opcua.stack.client.DiscoveryClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseResultMask;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class ClientCommand {

    private static final Logger LOG = LoggerFactory.getLogger(ClientCommand.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static int run(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: client <endpoints|read|write|browse> ...");
            return 1;
        }
        String sub = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        try {
            switch (sub) {
                case "endpoints": return cmdEndpoints(rest);
                case "read":      return cmdRead(rest);
                case "write":     return cmdWrite(rest);
                case "browse":    return cmdBrowse(rest);
                default:
                    System.err.println("unknown client subcommand: " + sub);
                    return 1;
            }
        } catch (Exception e) {
            printError(e.getMessage());
            return 3;
        }
    }

    // -------------------------------------------------------------------------
    // endpoints
    // -------------------------------------------------------------------------

    private static int cmdEndpoints(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        if (endpointUrl == null) {
            System.err.println("usage: client endpoints --endpoint <url>");
            return 1;
        }

        try {
            List<EndpointDescription> eps = DiscoveryClient.getEndpoints(endpointUrl).get();
            List<Map<String, Object>> results = new ArrayList<>();
            for (EndpointDescription ep : eps) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("url",            ep.getEndpointUrl());
                m.put("securityPolicy", ep.getSecurityPolicyUri());
                m.put("securityMode",   ep.getSecurityMode().toString());
                results.add(m);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("operation", "endpoints");
            out.put("success", true);
            out.put("results", results);
            System.out.println(MAPPER.writeValueAsString(out));
            return 0;
        } catch (Exception e) {
            printError(e.getMessage());
            return 3;
        }
    }

    // -------------------------------------------------------------------------
    // read
    // -------------------------------------------------------------------------

    private static int cmdRead(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        if (endpointUrl == null || nodeStr == null) {
            System.err.println("usage: client read --endpoint <url> --node <nodeId>");
            return 1;
        }

        OpcUaClient client = connectClient(endpointUrl);
        try {
            NodeId nodeId = clientResolveNodeId(client, nodeStr);
            DataValue dv  = client.readValue(0.0, TimestampsToReturn.Both, nodeId).get();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("nodeId", nodeStr);
            result.put("statusCode", statusName(dv.getStatusCode()));
            result.put("dataType",   getDataTypeName(dv));
            result.put("value",      variantToJson(dv.getValue()));
            if (dv.getSourceTime() != null) {
                result.put("sourceTimestamp", dv.getSourceTime().getJavaInstant().toString());
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("operation", "read");
            out.put("success",   dv.getStatusCode().isGood());
            out.put("results",   Collections.singletonList(result));
            System.out.println(MAPPER.writeValueAsString(out));
            return dv.getStatusCode().isGood() ? 0 : 3;
        } finally {
            client.disconnect().get();
        }
    }

    // -------------------------------------------------------------------------
    // write
    // -------------------------------------------------------------------------

    private static int cmdWrite(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        String typeStr     = findArg(args, "--type");
        String valStr      = findArg(args, "--value");
        if (endpointUrl == null || nodeStr == null || typeStr == null || valStr == null) {
            System.err.println("usage: client write --endpoint <url> --node <nodeId> --type <T> --value <V>");
            return 1;
        }

        OpcUaClient client = connectClient(endpointUrl);
        try {
            NodeId nodeId = clientResolveNodeId(client, nodeStr);
            Variant  var  = buildWriteVariant(typeStr, valStr);
            DataValue dv  = new DataValue(var);
            StatusCode sc = client.writeValue(nodeId, dv).get();

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("operation",     "write");
            out.put("success",       sc.isGood());
            out.put("serviceResult", statusName(sc));
            out.put("nodeId",        nodeStr);
            System.out.println(MAPPER.writeValueAsString(out));
            return sc.isGood() ? 0 : 3;
        } finally {
            client.disconnect().get();
        }
    }

    // -------------------------------------------------------------------------
    // browse
    // -------------------------------------------------------------------------

    private static int cmdBrowse(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        if (endpointUrl == null || nodeStr == null) {
            System.err.println("usage: client browse --endpoint <url> --node <nodeId>");
            return 1;
        }

        OpcUaClient client = connectClient(endpointUrl);
        try {
            NodeId nodeId = clientResolveNodeId(client, nodeStr);
            BrowseDescription bd = new BrowseDescription(
                    nodeId,
                    BrowseDirection.Forward,
                    Identifiers.HierarchicalReferences,
                    true,
                    UInteger.valueOf(0xFF),
                    UInteger.valueOf(BrowseResultMask.All.getValue()));
            BrowseResult result = client.browse(bd).get();

            List<Map<String, Object>> refs = new ArrayList<>();
            ReferenceDescription[] rdArr = result.getReferences();
            if (rdArr != null) {
                for (ReferenceDescription rd : rdArr) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("nodeId",      rd.getNodeId().toParseableString());
                    m.put("browseName",  rd.getBrowseName().getName());
                    m.put("displayName", rd.getDisplayName().getText());
                    m.put("nodeClass",   rd.getNodeClass().toString());
                    refs.add(m);
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("operation",  "browse");
            out.put("success",    result.getStatusCode().isGood());
            out.put("nodeId",     nodeStr);
            out.put("references", refs);
            System.out.println(MAPPER.writeValueAsString(out));
            return result.getStatusCode().isGood() ? 0 : 3;
        } finally {
            client.disconnect().get();
        }
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static OpcUaClient connectClient(String endpointUrl) throws Exception {
        List<EndpointDescription> eps = DiscoveryClient.getEndpoints(endpointUrl).get();
        EndpointDescription endpoint = eps.stream()
                .filter(e -> SecurityPolicy.None.getUri().equals(e.getSecurityPolicyUri()))
                .findFirst()
                .orElse(eps.isEmpty() ? null : eps.get(0));

        if (endpoint == null) throw new RuntimeException("No endpoint found at " + endpointUrl);

        OpcUaClientConfig config = OpcUaClientConfig.builder()
                .setEndpoint(endpoint)
                .setApplicationUri("urn:otfabric:opcua-interop:milo-client")
                .setApplicationName(LocalizedText.english("opcua-interop milo client"))
                .build();

        OpcUaClient client = OpcUaClient.create(config);
        client.connect().get();
        return client;
    }

    private static NodeId clientResolveNodeId(OpcUaClient client, String nodeStr) throws Exception {
        if (nodeStr.startsWith("nsu=")) {
            int semi = nodeStr.indexOf(';', 4);
            if (semi < 0) return NodeId.NULL_VALUE;
            String uri  = nodeStr.substring(4, semi);
            String rest = nodeStr.substring(semi + 1);

            int nsIdx = lookupNamespaceIndex(client, uri);

            if (rest.startsWith("s=")) return new NodeId(nsIdx, rest.substring(2));
            if (rest.startsWith("i=")) return new NodeId(nsIdx, UInteger.valueOf(rest.substring(2)));
        }
        if (nodeStr.startsWith("ns=")) {
            int semi = nodeStr.indexOf(';');
            if (semi < 0) return NodeId.NULL_VALUE;
            int ns   = Integer.parseInt(nodeStr.substring(3, semi));
            String rest = nodeStr.substring(semi + 1);
            if (rest.startsWith("s=")) return new NodeId(ns, rest.substring(2));
            if (rest.startsWith("i=")) return new NodeId(ns, UInteger.valueOf(rest.substring(2)));
        }
        if (nodeStr.startsWith("i=")) {
            return new NodeId(0, UInteger.valueOf(nodeStr.substring(2)));
        }
        return NodeId.NULL_VALUE;
    }

    private static int lookupNamespaceIndex(OpcUaClient client, String uri) throws Exception {
        DataValue dv = client.readValue(0.0, TimestampsToReturn.Neither,
                Identifiers.Server_NamespaceArray).get();
        if (dv.getValue() != null && dv.getValue().getValue() instanceof String[]) {
            String[] namespaces = (String[]) dv.getValue().getValue();
            for (int i = 0; i < namespaces.length; i++) {
                if (uri.equals(namespaces[i])) return i;
            }
        }
        return 1;
    }

    private static Variant buildWriteVariant(String typeStr, String val) {
        switch (typeStr) {
            case "Boolean":  return new Variant(Boolean.parseBoolean(val) || "1".equals(val));
            case "SByte":    return new Variant(Byte.parseByte(val));
            case "Byte":     return new Variant(UByte.valueOf(Integer.parseInt(val)));
            case "Int16":    return new Variant(Short.parseShort(val));
            case "UInt16":   return new Variant(UShort.valueOf(Integer.parseInt(val)));
            case "Int32":    return new Variant(Integer.parseInt(val));
            case "UInt32":   return new Variant(UInteger.valueOf(Long.parseLong(val)));
            case "Int64":    return new Variant(Long.parseLong(val));
            case "UInt64":   return new Variant(ULong.valueOf(val));
            case "Float":    return new Variant(Float.parseFloat(val));
            case "Double":   return new Variant(Double.parseDouble(val));
            case "String":   return new Variant(val);
            default:         return new Variant(val);
        }
    }

    private static Object variantToJson(Variant v) {
        if (v == null || v.isNull()) return null;
        Object value = v.getValue();
        if (value instanceof Long || value instanceof ULong) return value.toString();
        return value;
    }

    private static String getDataTypeName(DataValue dv) {
        if (dv.getValue() == null || dv.getValue().isNull()) return "Unknown";
        Object val = dv.getValue().getValue();
        if (val instanceof Boolean)  return "Boolean";
        if (val instanceof Byte)     return "SByte";
        if (val instanceof UByte)    return "Byte";
        if (val instanceof Short)    return "Int16";
        if (val instanceof UShort)   return "UInt16";
        if (val instanceof Integer)  return "Int32";
        if (val instanceof UInteger) return "UInt32";
        if (val instanceof Long)     return "Int64";
        if (val instanceof ULong)    return "UInt64";
        if (val instanceof Float)    return "Float";
        if (val instanceof Double)   return "Double";
        if (val instanceof String)   return "String";
        if (val instanceof DateTime) return "DateTime";
        if (val instanceof UUID)     return "Guid";
        if (val instanceof ByteString) return "ByteString";
        return "Unknown";
    }

    private static String statusName(StatusCode sc) {
        if (sc == null) return "Unknown";
        if (sc.isGood())      return "Good";
        if (sc.isUncertain()) return "Uncertain";
        return "Bad";
    }

    private static void printError(String msg) {
        try {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("operation", "error");
            out.put("success",   false);
            out.put("error",     msg);
            System.out.println(MAPPER.writeValueAsString(out));
        } catch (Exception ignored) {
            System.out.println("{\"operation\":\"error\",\"success\":false}");
        }
    }

    private static String findArg(String[] args, String flag) {
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) return args[i + 1];
        }
        return null;
    }
}
