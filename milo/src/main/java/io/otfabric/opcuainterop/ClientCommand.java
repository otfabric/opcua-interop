package io.otfabric.opcuainterop;

import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaMonitoredItem;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaSubscription;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseResultMask;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MonitoringMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

public class ClientCommand {

    private static final Logger LOG = LoggerFactory.getLogger(ClientCommand.class);

    /** Thrown when no matching endpoint is found — maps to exit 3. */
    private static class TransportException extends Exception {
        public TransportException(String msg) { super(msg); }
    }

    public static int run(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: client <endpoints|read|write|browse|call|subscribe> ...");
            return 1;
        }
        String op = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);

        try {
            switch (op) {
                case "endpoints": return cmdEndpoints(rest);
                case "read":      return cmdRead(rest);
                case "write":     return cmdWrite(rest);
                case "browse":    return cmdBrowse(rest);
                case "call":      return cmdCall(rest);
                case "subscribe": return cmdSubscribe(rest);
                default:
                    System.err.println("unknown client subcommand: " + op);
                    return 1;
            }
        } catch (NodeIdParser.InvalidNodeIdException | NodeIdParser.UnknownNamespaceException e) {
            System.out.println(new ResultBuilder(op).error("input", e.getMessage()).toJson());
            return 2;
        } catch (TransportException e) {
            System.out.println(new ResultBuilder(op).error("transport", e.getMessage()).toJson());
            return 3;
        } catch (org.eclipse.milo.opcua.stack.core.UaServiceFaultException e) {
            StatusCode sc = e.getStatusCode();
            System.out.println(new ResultBuilder(op).success(false).serviceResult(sc)
                    .error("service", e.getMessage()).toJson());
            return 4;
        } catch (UaException e) {
            Throwable cause = e.getCause();
            if (cause instanceof org.eclipse.milo.opcua.stack.core.UaServiceFaultException) {
                StatusCode sc = ((org.eclipse.milo.opcua.stack.core.UaServiceFaultException) cause).getStatusCode();
                System.out.println(new ResultBuilder(op).success(false).serviceResult(sc)
                        .error("service", cause.getMessage()).toJson());
                return 4;
            }
            String msg = e.getMessage();
            System.out.println(new ResultBuilder(op).error("transport", msg).toJson());
            return 3;
        } catch (Exception e) {
            System.out.println(new ResultBuilder(op).error("internal", e.getMessage()).toJson());
            return 6;
        }
    }

    // -------------------------------------------------------------------------
    // endpoints
    // -------------------------------------------------------------------------

    private static int cmdEndpoints(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        if (endpointUrl == null) {
            System.out.println(new ResultBuilder("endpoints").error("input", "missing --endpoint").toJson());
            return 2;
        }
        long rto = requestTimeoutMs(args);

        List<EndpointDescription> eps = DiscoveryClient.getEndpoints(endpointUrl).get(rto, MILLISECONDS);
        ResultBuilder rb = new ResultBuilder("endpoints");
        for (EndpointDescription ep : eps) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("url",            ep.getEndpointUrl());
            m.put("securityPolicy", ep.getSecurityPolicyUri());
            m.put("securityMode",   ep.getSecurityMode().toString());
            rb.addResult(m);
        }
        System.out.println(rb.toJson());
        return 0;
    }

    // -------------------------------------------------------------------------
    // read
    // -------------------------------------------------------------------------

    private static int cmdRead(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        List<String> nodeStrs = findAllArgs(args, "--node");
        if (endpointUrl == null || nodeStrs.isEmpty()) {
            System.out.println(new ResultBuilder("read").error("input", "missing --endpoint or --node").toJson());
            return 2;
        }
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto);
        try {
            List<NodeId> nodeIds = new ArrayList<>();
            for (String ns : nodeStrs) {
                nodeIds.add(NodeIdParser.resolveWithClient(ns, client, rto));
            }

            List<DataValue> dvs = client.readValues(0.0, TimestampsToReturn.Both, nodeIds);

            ResultBuilder rb = new ResultBuilder("read");
            boolean anyBad = false;

            for (int i = 0; i < nodeIds.size(); i++) {
                DataValue dv = dvs.get(i);
                String typeName = ResultBuilder.builtInTypeName(dv.getValue());
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("nodeId",      ResultBuilder.nodeIdToString(nodeIds.get(i)));
                result.put("statusCode",  ResultBuilder.statusCodeJson(dv.getStatusCode()));
                result.put("dataType",    typeName);
                result.put("builtInType", ResultBuilder.builtInTypeId(typeName));
                result.put("value",       ResultBuilder.encodeVariantValue(dv.getValue()));
                if (dv.getSourceTime() != null && dv.getSourceTime().getJavaInstant() != null
                        && dv.getSourceTime().getJavaTime() != 0) {
                    result.put("sourceTimestamp", dv.getSourceTime().getJavaInstant().toString());
                }
                rb.addResult(result);
                if (!dv.getStatusCode().isGood()) anyBad = true;
            }

            if (nodeIds.size() == 1) {
                rb.serviceResult(dvs.get(0).getStatusCode());
            }
            if (anyBad) rb.success(false);

            System.out.println(rb.toJson());
            return anyBad ? 4 : 0;
        } finally {
            safeDisconnect(client, dto);
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
            System.out.println(new ResultBuilder("write").error("input", "missing required flags for write").toJson());
            return 2;
        }
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);
            Variant var   = buildWriteVariant(typeStr, valStr);
            // Build a write DataValue with only the Value field.
            // - Explicit StatusCode.GOOD (not null): avoids NPE in Milo's encoder which calls
            //   statusCode.getValue() unconditionally, but a Good status won't set HasStatus=1.
            // - Explicit null timestamps: the default DataValue(Variant) constructor sets
            //   sourceTime=DateTime.now(), which sets HasSourceTimestamp=1.  open62541 rejects
            //   writes that include any timestamp/status field with BadWriteNotSupported.
            DataValue writeDataValue = new DataValue(var, StatusCode.GOOD, null, null);
            List<StatusCode> scList = client.writeValues(List.of(nodeId), List.of(writeDataValue));
            StatusCode sc = scList.get(0);

            Map<String, Object> writeResult = new LinkedHashMap<>();
            writeResult.put("nodeId",     ResultBuilder.nodeIdToString(nodeId));
            writeResult.put("statusCode", ResultBuilder.statusCodeJson(sc));

            System.out.println(new ResultBuilder("write")
                    .success(sc.isGood())
                    .serviceResult(sc)
                    .addResult(writeResult)
                    .toJson());
            return sc.isGood() ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // browse
    // -------------------------------------------------------------------------

    private static int cmdBrowse(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        if (nodeStr == null) nodeStr = "i=85";
        if (endpointUrl == null) {
            System.out.println(new ResultBuilder("browse").error("input", "missing --endpoint").toJson());
            return 2;
        }
        long maxRefs = parseLongArg(args, "--max-refs", 0);
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);

            BrowseDescription bd = new BrowseDescription(
                    nodeId,
                    BrowseDirection.Forward,
                    Identifiers.HierarchicalReferences,
                    true,
                    UInteger.valueOf(0xFF),
                    UInteger.valueOf(BrowseResultMask.All.getValue()));

            BrowseResult firstResult = client.browse(bd);
            List<ReferenceDescription> allRefs = new ArrayList<>(
                    Arrays.asList(firstResult.getReferences() != null
                            ? firstResult.getReferences() : new ReferenceDescription[0]));

            ByteString contPoint = firstResult.getContinuationPoint();
            while (contPoint != null && contPoint.bytes() != null && contPoint.bytes().length > 0) {
                RequestHeader header = new RequestHeader(
                        NodeId.NULL_VALUE,
                        DateTime.now(),
                        UInteger.valueOf(0),
                        UInteger.valueOf(0),
                        null,
                        UInteger.valueOf((int) Math.min(rto, Integer.MAX_VALUE)),
                        null);
                BrowseNextRequest req = new BrowseNextRequest(header, false, new ByteString[]{contPoint});
                BrowseNextResponse resp = (BrowseNextResponse) client.sendRequest(req);
                BrowseResult next = resp.getResults()[0];
                if (next.getReferences() != null) allRefs.addAll(Arrays.asList(next.getReferences()));
                contPoint = next.getContinuationPoint();
            }

            ResultBuilder rb = new ResultBuilder("browse")
                    .serviceResult(firstResult.getStatusCode())
                    .success(firstResult.getStatusCode().isGood());

            for (ReferenceDescription rd : allRefs) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("referenceTypeId", ResultBuilder.nodeIdToString(rd.getReferenceTypeId()));
                m.put("isForward",       rd.getIsForward());
                m.put("nodeId",          ResultBuilder.nodeIdToString(
                        expandedToLocalNodeId(rd.getNodeId())));
                Map<String, Object> bn = new LinkedHashMap<>();
                bn.put("ns",   rd.getBrowseName().getNamespaceIndex().intValue());
                bn.put("name", rd.getBrowseName().getName());
                m.put("browseName", bn);
                Map<String, Object> dn = new LinkedHashMap<>();
                dn.put("locale", rd.getDisplayName().getLocale() != null ? rd.getDisplayName().getLocale() : "");
                dn.put("text",   rd.getDisplayName().getText()   != null ? rd.getDisplayName().getText()   : "");
                m.put("displayName", dn);
                m.put("nodeClass", rd.getNodeClass().toString());
                rb.addResult(m);
            }

            System.out.println(rb.toJson());
            return firstResult.getStatusCode().isGood() ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // call
    // -------------------------------------------------------------------------

    private static int cmdCall(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String objectStr   = findArg(args, "--object");
        String methodStr   = findArg(args, "--method");
        if (endpointUrl == null || objectStr == null || methodStr == null) {
            System.out.println(new ResultBuilder("call")
                .error("input", "missing --endpoint, --object, or --method").toJson());
            return 2;
        }
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        List<Variant> inputVariants = new ArrayList<>();
        for (int i = 0; i < args.length - 1; i++) {
            if ("--input".equals(args[i])) {
                String spec = args[i + 1];
                int colon = spec.indexOf(':');
                if (colon > 0) {
                    String type = spec.substring(0, colon);
                    String val  = spec.substring(colon + 1);
                    inputVariants.add(buildWriteVariant(type, val));
                }
            }
        }

        OpcUaClient client = connectClient(endpointUrl, cto, rto);
        try {
            NodeId objectNodeId = NodeIdParser.resolveWithClient(objectStr, client, rto);
            NodeId methodNodeId = NodeIdParser.resolveWithClient(methodStr, client, rto);

            Variant[] inputs = inputVariants.toArray(new Variant[0]);
            CallMethodRequest req = new CallMethodRequest(objectNodeId, methodNodeId, inputs);
            CallResponse callResponse = client.call(List.of(req));

            CallMethodResult methodResult = callResponse.getResults()[0];
            StatusCode methodSc = methodResult.getStatusCode();
            Variant[] outputs = methodResult.getOutputArguments();

            List<Object> outArgs = new ArrayList<>();
            if (outputs != null) {
                for (Variant v : outputs) {
                    outArgs.add(ResultBuilder.encodeVariantValue(v));
                }
            }

            Map<String, Object> resultItem = new LinkedHashMap<>();
            resultItem.put("objectNodeId",    ResultBuilder.nodeIdToString(objectNodeId));
            resultItem.put("methodNodeId",    ResultBuilder.nodeIdToString(methodNodeId));
            resultItem.put("statusCode",      ResultBuilder.statusCodeJson(methodSc));
            resultItem.put("outputArguments", outArgs);

            System.out.println(new ResultBuilder("call")
                .success(methodSc.isGood())
                .serviceResult(methodSc)
                .addResult(resultItem)
                .toJson());
            return methodSc.isGood() ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // subscribe
    // -------------------------------------------------------------------------

    private static int cmdSubscribe(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        if (endpointUrl == null || nodeStr == null) {
            System.out.println(new ResultBuilder("subscribe")
                .error("input", "missing --endpoint or --node").toJson());
            return 2;
        }
        long   cto    = connectTimeoutMs(args);
        long   rto    = requestTimeoutMs(args);
        long   dto    = disconnectTimeoutMs(args);
        double piMs   = parseDoubleArg(args, "--publishing-interval-ms", 500.0);
        double siMs   = parseDoubleArg(args, "--sampling-interval-ms",   100.0);
        int    nWanted = parseIntArg(args,   "--notifications", 5);
        long   toMs   = parseLongArg(args,   "--timeout-ms",   10000L);

        OpcUaClient client = connectClient(endpointUrl, cto, rto);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);

            OpcUaSubscription subscription = new OpcUaSubscription(client, piMs);
            subscription.create();

            ReadValueId readValueId = new ReadValueId(
                nodeId,
                AttributeId.Value.uid(),
                null,
                QualifiedName.NULL_VALUE);
            OpcUaMonitoredItem monItem = new OpcUaMonitoredItem(readValueId);
            monItem.setSamplingInterval(siMs);
            monItem.setQueueSize(uint(10));

            subscription.addMonitoredItem(monItem);
            subscription.createMonitoredItems();

            StatusCode monSc = monItem.getCreateResult().orElse(StatusCode.GOOD);

            List<Map<String, Object>> notifications =
                Collections.synchronizedList(new ArrayList<>());
            CountDownLatch latch = new CountDownLatch(nWanted);
            AtomicInteger seqRef = new AtomicInteger(0);
            boolean timedOut = false;

            if (monSc.isGood()) {
                monItem.setDataValueListener((item, dv) -> {
                    if (notifications.size() >= nWanted) return;
                    Map<String, Object> n = new LinkedHashMap<>();
                    int seq = seqRef.incrementAndGet();
                    n.put("sequenceNumber", seq);
                    String typeName = ResultBuilder.builtInTypeName(dv.getValue());
                    n.put("value",       ResultBuilder.encodeVariantValue(dv.getValue()));
                    n.put("dataType",    typeName);
                    n.put("builtInType", ResultBuilder.builtInTypeId(typeName));
                    StatusCode dvSc = dv.getStatusCode() != null
                        ? dv.getStatusCode() : StatusCode.GOOD;
                    n.put("statusCode",  ResultBuilder.statusCodeJson(dvSc));
                    if (dv.getSourceTime() != null && dv.getSourceTime().getJavaTime() != 0) {
                        n.put("sourceTimestamp",
                            dv.getSourceTime().getJavaInstant().toString());
                    }
                    notifications.add(n);
                    latch.countDown();
                });

                timedOut = !latch.await(toMs, MILLISECONDS);
            }

            Map<String, Object> resultItem = new LinkedHashMap<>();
            resultItem.put("nodeId", ResultBuilder.nodeIdToString(nodeId));
            resultItem.put("monitoredItemStatusCode", ResultBuilder.statusCodeJson(monSc));
            resultItem.put("notifications", new ArrayList<>(notifications));

            ResultBuilder rb = new ResultBuilder("subscribe")
                .success(monSc.isGood() && !timedOut)
                .serviceResult(monSc)
                .addResult(resultItem);
            if (timedOut) {
                rb.error("timeout", "timeout waiting for notifications");
            }
            System.out.println(rb.toJson());

            try {
                subscription.delete();
            } catch (Exception ignored) {}

            return timedOut ? 7 : (monSc.isGood() ? 0 : 4);
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static OpcUaClient connectClient(String endpointUrl, long connectTimeoutMs, long requestTimeoutMs)
            throws Exception {
        List<EndpointDescription> eps = DiscoveryClient.getEndpoints(endpointUrl)
                .get(connectTimeoutMs, MILLISECONDS);

        EndpointDescription endpoint = eps.stream()
                .filter(e -> SecurityPolicy.None.getUri().equals(e.getSecurityPolicyUri())
                          && MessageSecurityMode.None.equals(e.getSecurityMode()))
                .findFirst()
                .orElse(null);

        if (endpoint == null) {
            throw new TransportException(
                    "no endpoint with SecurityPolicy=None and MessageSecurityMode=None at " + endpointUrl);
        }

        // The server's advertised endpoint URL may not be reachable from inside a
        // client container (e.g. it says "localhost" but that resolves to the client's
        // own loopback). Replace it with the URL we actually used for discovery so
        // the TCP connection goes to the right host.
        endpoint = new EndpointDescription(
                endpointUrl,
                endpoint.getServer(),
                endpoint.getServerCertificate(),
                endpoint.getSecurityMode(),
                endpoint.getSecurityPolicyUri(),
                endpoint.getUserIdentityTokens(),
                endpoint.getTransportProfileUri(),
                endpoint.getSecurityLevel());

        OpcUaClientConfig config = OpcUaClientConfig.builder()
                .setEndpoint(endpoint)
                .setApplicationUri("urn:otfabric:opcua-interop:milo-client")
                .setApplicationName(LocalizedText.english("opcua-interop milo client"))
                .setRequestTimeout(UInteger.valueOf(requestTimeoutMs))
                .build();

        OpcUaClient client = OpcUaClient.create(config);
        client.connect();
        return client;
    }

    private static void safeDisconnect(OpcUaClient client, long timeoutMs) {
        try {
            client.disconnect();
        } catch (Exception e) {
            LOG.warn("Error during disconnect: {}", e.getMessage());
        }
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

    private static String findArg(String[] args, String flag) {
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) return args[i + 1];
        }
        return null;
    }

    private static List<String> findAllArgs(String[] args, String flag) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) result.add(args[i + 1]);
        }
        return result;
    }

    private static long parseLongArg(String[] args, String flag, long defaultVal) {
        String val = findArg(args, flag);
        if (val == null) return defaultVal;
        try { return Long.parseLong(val); } catch (NumberFormatException e) { return defaultVal; }
    }

    private static double parseDoubleArg(String[] args, String flag, double defaultVal) {
        String val = findArg(args, flag);
        if (val == null) return defaultVal;
        try { return Double.parseDouble(val); } catch (NumberFormatException e) { return defaultVal; }
    }

    private static int parseIntArg(String[] args, String flag, int defaultVal) {
        String val = findArg(args, flag);
        if (val == null) return defaultVal;
        try { return Integer.parseInt(val); } catch (NumberFormatException e) { return defaultVal; }
    }

    private static long connectTimeoutMs(String[] args)    { return parseLongArg(args, "--connect-timeout",    5) * 1000; }
    private static long requestTimeoutMs(String[] args)    { return parseLongArg(args, "--request-timeout",    5) * 1000; }
    private static long disconnectTimeoutMs(String[] args) { return parseLongArg(args, "--disconnect-timeout", 2) * 1000; }

    /**
     * Convert a local ExpandedNodeId (no namespace URI form) to a NodeId.
     * Browse results always use numeric namespace indices, so no NamespaceTable is needed.
     */
    private static NodeId expandedToLocalNodeId(ExpandedNodeId eId) {
        if (eId == null) return NodeId.NULL_VALUE;
        UShort nsIdx = eId.getNamespaceIndex();
        int ns = nsIdx != null ? nsIdx.intValue() : 0;
        Object id = eId.getIdentifier();
        if (id instanceof UInteger)           return new NodeId(ns, (UInteger) id);
        if (id instanceof String)             return new NodeId(ns, (String) id);
        if (id instanceof java.util.UUID)     return new NodeId(ns, (java.util.UUID) id);
        if (id instanceof ByteString)         return new NodeId(ns, (ByteString) id);
        return NodeId.NULL_VALUE;
    }
}
