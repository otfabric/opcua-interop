package io.otfabric.opcuainterop;

import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfigBuilder;
import org.eclipse.milo.opcua.sdk.client.OpcUaSession;
import org.eclipse.milo.opcua.sdk.client.subscriptions.CreateMonitoredItemsWithTimestamps;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaMonitoredItem;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaSubscription;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.DefaultServerCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.FileBasedCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.FileBasedTrustListManager;
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

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

public class ClientCommand {

    private static final Logger LOG = LoggerFactory.getLogger(ClientCommand.class);

    static {
        if (Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /** Thrown when no matching endpoint is found — maps to exit 3. */
    private static class TransportException extends Exception {
        public TransportException(String msg) { super(msg); }
    }

    public static int run(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: client <endpoints|read|write|browse|call|subscribe"
                + "|subscription-lifecycle|event-subscribe|history-read"
                + "|republish|transfer-subscriptions> ...");
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
                case "subscription-lifecycle": return cmdSubscriptionLifecycle(rest);
                case "event-subscribe":        return cmdEventSubscribe(rest);
                case "history-read":           return cmdHistoryRead(rest);
                case "republish":              return cmdRepublish(rest);
                case "transfer-subscriptions": return cmdTransferSubscriptions(rest);
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

        String indexRange = findArg(args, "--index-range");
        TimestampsToReturn timestamps = parseTimestamps(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            List<NodeId> nodeIds = new ArrayList<>();
            List<ReadValueId> readIds = new ArrayList<>();
            for (String ns : nodeStrs) {
                NodeId nodeId = NodeIdParser.resolveWithClient(ns, client, rto);
                nodeIds.add(nodeId);
                readIds.add(new ReadValueId(
                        nodeId,
                        AttributeId.Value.uid(),
                        indexRange,
                        null));
            }

            ReadResponse readResp = client.read(0.0, timestamps, readIds);
            DataValue[] dvs = readResp.getResults();

            ResultBuilder rb = new ResultBuilder("read");
            boolean anyBad = false;

            for (int i = 0; i < nodeIds.size(); i++) {
                DataValue dv = dvs[i];
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
                rb.serviceResult(dvs[0].getStatusCode());
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
        List<String> nodeStrs = findAllArgs(args, "--node");
        List<String> typeStrs = findAllArgs(args, "--type");
        List<String> valStrs  = findAllArgs(args, "--value");
        if (endpointUrl == null || nodeStrs.isEmpty() || typeStrs.isEmpty() || valStrs.isEmpty()
                || nodeStrs.size() != typeStrs.size() || nodeStrs.size() != valStrs.size()) {
            System.out.println(new ResultBuilder("write").error("input",
                    "write requires equal counts of --node, --type, and --value").toJson());
            return 2;
        }
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        String indexRange = findArg(args, "--index-range");

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            List<WriteValue> writeValues = new ArrayList<>();
            List<NodeId> nodeIds = new ArrayList<>();
            for (int i = 0; i < nodeStrs.size(); i++) {
                NodeId nodeId = NodeIdParser.resolveWithClient(nodeStrs.get(i), client, rto);
                nodeIds.add(nodeId);
                Variant var = buildWriteVariant(typeStrs.get(i), valStrs.get(i));
                // Value-only DataValue (no StatusCode / timestamps EncodingMask bits).
                DataValue dv = DataValue.valueOnly(var);
                writeValues.add(new WriteValue(
                        nodeId,
                        AttributeId.Value.uid(),
                        indexRange,
                        dv));
            }

            WriteResponse writeResp = client.write(writeValues);
            StatusCode[] scList = writeResp.getResults();

            ResultBuilder rb = new ResultBuilder("write");
            boolean anyBad = false;
            StatusCode firstBad = StatusCode.GOOD;
            for (int i = 0; i < nodeIds.size(); i++) {
                StatusCode sc = scList[i];
                Map<String, Object> writeResult = new LinkedHashMap<>();
                writeResult.put("nodeId", ResultBuilder.nodeIdToString(nodeIds.get(i)));
                writeResult.put("statusCode", ResultBuilder.statusCodeJson(sc));
                rb.addResult(writeResult);
                if (!sc.isGood()) {
                    anyBad = true;
                    if (firstBad.isGood()) firstBad = sc;
                }
            }
            if (nodeIds.size() == 1) {
                rb.serviceResult(scList[0]);
            } else if (anyBad) {
                rb.serviceResult(firstBad);
            }
            if (anyBad) rb.success(false);

            System.out.println(rb.toJson());
            return anyBad ? 4 : 0;
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
        long nodeClassMask = parseLongArg(args, "--node-class-mask", 0);
        // IncludeSubtypes defaults to true; pass --include-subtypes false for exact match.
        boolean includeSubtypes = !hasFlagValue(args, "--include-subtypes", "false")
                && !hasFlagValue(args, "--include-subtypes", "0");
        long resultMask = parseLongArg(args, "--result-mask", BrowseResultMask.All.getValue());
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);

            BrowseDescription bd = new BrowseDescription(
                    nodeId,
                    BrowseDirection.Forward,
                    Identifiers.HierarchicalReferences,
                    includeSubtypes,
                    UInteger.valueOf(nodeClassMask),
                    UInteger.valueOf(resultMask));

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

            StatusCode browseSc = firstResult.getStatusCode();
            ResultBuilder rb = new ResultBuilder("browse")
                    .serviceResult(browseSc)
                    .success(browseSc.isGood());

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

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
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
        int    queueSize    = parseIntArg(args, "--queue-size",    1);
        boolean discardOld = !hasFlagValue(args, "--discard-oldest", "false");
        TimestampsToReturn timestamps = parseTimestamps(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);

            OpcUaSubscription subscription = new OpcUaSubscription(client, piMs);
            subscription.create();

            UInteger subId  = subscription.getSubscriptionId().orElse(uint(0));
            double   rpi    = subscription.getRevisedPublishingInterval().orElse(0.0);
            UInteger rlt    = subscription.getRevisedLifetimeCount().orElse(uint(0));
            UInteger rmk    = subscription.getRevisedMaxKeepAliveCount().orElse(uint(0));

            ReadValueId readValueId = new ReadValueId(
                nodeId,
                AttributeId.Value.uid(),
                null,
                QualifiedName.NULL_VALUE);
            OpcUaMonitoredItem monItem = new OpcUaMonitoredItem(readValueId);
            monItem.setSamplingInterval(siMs);
            monItem.setQueueSize(uint(Math.max(1, queueSize)));
            monItem.setDiscardOldest(discardOld);

            subscription.addMonitoredItem(monItem);
            // OpcUaSubscription.createMonitoredItems() hardcodes Both; pass --timestamps.
            StatusCode monSc = CreateMonitoredItemsWithTimestamps.create(
                client, subscription, monItem, timestamps);

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
                    if (dv.getServerTime() != null && dv.getServerTime().getJavaTime() != 0) {
                        n.put("serverTimestamp",
                            dv.getServerTime().getJavaInstant().toString());
                    }
                    notifications.add(n);
                    latch.countDown();
                });

                timedOut = !latch.await(toMs, MILLISECONDS);
            }

            Map<String, Object> resultItem = new LinkedHashMap<>();
            resultItem.put("nodeId", ResultBuilder.nodeIdToString(nodeId));
            resultItem.put("subscriptionId", subId.longValue());
            resultItem.put("revisedPublishingInterval", rpi);
            resultItem.put("revisedLifetimeCount", rlt.longValue());
            resultItem.put("revisedMaxKeepAliveCount", rmk.longValue());
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
    // subscription-lifecycle
    // -------------------------------------------------------------------------

    private static int cmdSubscriptionLifecycle(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        String scenario    = findArg(args, "--scenario");
        if (endpointUrl == null || nodeStr == null || scenario == null) {
            System.out.println(new ResultBuilder("subscription-lifecycle")
                .error("input", "missing --endpoint, --node, or --scenario").toJson());
            return 2;
        }
        long cto  = connectTimeoutMs(args);
        long rto  = requestTimeoutMs(args);
        long dto  = disconnectTimeoutMs(args);
        long toMs = parseLongArg(args, "--timeout-ms", 15000L);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);
            switch (scenario) {
                case "revise":           return slcRevise(client, nodeId, rto, toMs);
                case "publishing-mode":  return slcPublishingMode(client, nodeId, rto, toMs);
                case "monitoring-mode":  return slcMonitoringMode(client, nodeId, rto, toMs);
                case "delete":           return slcDelete(client, nodeId, rto, toMs);
                default:
                    System.out.println(new ResultBuilder("subscription-lifecycle")
                        .error("input", "unknown scenario: " + scenario).toJson());
                    return 2;
            }
        } finally {
            safeDisconnect(client, dto);
        }
    }

    private static int slcRevise(OpcUaClient client, NodeId nodeId, long rto, long toMs)
            throws Exception {
        OpcUaSubscription sub = new OpcUaSubscription(client, 1.0);
        sub.setLifetimeCount(uint(5));
        sub.setMaxKeepAliveCount(uint(10));
        sub.create();

        UInteger subId = sub.getSubscriptionId().orElse(uint(0));
        double   rpi   = sub.getRevisedPublishingInterval().orElse(0.0);
        UInteger rlt   = sub.getRevisedLifetimeCount().orElse(uint(0));
        UInteger rmk   = sub.getRevisedMaxKeepAliveCount().orElse(uint(0));

        try { sub.delete(); } catch (Exception ignored) {}

        boolean ok = rlt.longValue() >= 3L * rmk.longValue() && rpi >= 10.0;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subscriptionId",              subId.longValue());
        result.put("requestedPublishingInterval", 1);
        result.put("requestedLifetimeCount",      5);
        result.put("requestedMaxKeepAliveCount",  10);
        result.put("revisedPublishingInterval",   rpi);
        result.put("revisedLifetimeCount",        rlt.longValue());
        result.put("revisedMaxKeepAliveCount",    rmk.longValue());

        System.out.println(new ResultBuilder("subscription-lifecycle")
            .success(ok).addResult(result).toJson());
        return ok ? 0 : 4;
    }

    private static int slcPublishingMode(OpcUaClient client, NodeId nodeId, long rto, long toMs)
            throws Exception {
        OpcUaSubscription sub = new OpcUaSubscription(client, 500.0);
        sub.create();

        UInteger subId = sub.getSubscriptionId().orElse(uint(0));
        double   rpi   = sub.getRevisedPublishingInterval().orElse(0.0);
        UInteger rlt   = sub.getRevisedLifetimeCount().orElse(uint(0));
        UInteger rmk   = sub.getRevisedMaxKeepAliveCount().orElse(uint(0));

        ReadValueId rvId = new ReadValueId(nodeId, AttributeId.Value.uid(), null,
            QualifiedName.NULL_VALUE);
        OpcUaMonitoredItem monItem = new OpcUaMonitoredItem(rvId);
        monItem.setSamplingInterval(100.0);
        monItem.setQueueSize(uint(3));
        monItem.setDiscardOldest(true);
        sub.addMonitoredItem(monItem);
        StatusCode monSc = CreateMonitoredItemsWithTimestamps.create(
            client, sub, monItem, TimestampsToReturn.Source);

        if (!monSc.isGood()) {
            try { sub.delete(); } catch (Exception ignored) {}
            System.out.println(new ResultBuilder("subscription-lifecycle")
                .success(false).serviceResult(monSc)
                .error("service", "CreateMonitoredItem failed").toJson());
            return 4;
        }

        List<Integer> notifValues = Collections.synchronizedList(new ArrayList<>());
        AtomicBoolean overflow    = new AtomicBoolean(false);
        CountDownLatch initLatch  = new CountDownLatch(1);

        monItem.setDataValueListener((item, dv) -> {
            if (initLatch.getCount() > 0) { initLatch.countDown(); return; }
            Variant v = dv.getValue();
            if (v != null && v.getValue() instanceof Integer) {
                notifValues.add((Integer) v.getValue());
            }
            if (dv.getStatusCode() != null &&
                (dv.getStatusCode().getValue() & 0x480L) != 0) {
                overflow.set(true);
            }
        });

        initLatch.await(500, MILLISECONDS);

        /* SetPublishingMode false, clear list */
        sub.setPublishingMode(false);
        notifValues.clear();

        /* Write 1..5 */
        for (int v = 1; v <= 5; v++) {
            WriteValue wv = new WriteValue(nodeId, AttributeId.Value.uid(), null,
                DataValue.valueOnly(new Variant(Integer.valueOf(v))));
            client.write(List.of(wv));
        }
        Thread.sleep(200);

        /* SetPublishingMode true; collect queued notifications */
        sub.setPublishingMode(true);
        long collectMs = Math.max(2000L, Math.min(toMs - 2000L, 5000L));
        Thread.sleep(collectMs);

        try { sub.delete(); } catch (Exception ignored) {}

        List<Integer> values = new ArrayList<>(notifValues);
        int nv = values.size();
        if (nv < 5) overflow.set(true);

        boolean ok = false;
        if (nv >= 3) {
            ok = values.get(nv-3) == 3 && values.get(nv-2) == 4 && values.get(nv-1) == 5;
        } else if (nv >= 1) {
            ok = values.get(nv-1) == 5;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subscriptionId",            subId.longValue());
        result.put("revisedPublishingInterval", rpi);
        result.put("revisedLifetimeCount",      rlt.longValue());
        result.put("revisedMaxKeepAliveCount",  rmk.longValue());
        result.put("overflow",                  overflow.get());
        result.put("values",                    values);

        System.out.println(new ResultBuilder("subscription-lifecycle")
            .success(ok).addResult(result).toJson());
        return ok ? 0 : 4;
    }

    private static int slcMonitoringMode(OpcUaClient client, NodeId nodeId, long rto, long toMs)
            throws Exception {
        OpcUaSubscription sub = new OpcUaSubscription(client, 100.0);
        sub.create();
        UInteger subId = sub.getSubscriptionId().orElse(uint(0));

        ReadValueId rvId = new ReadValueId(nodeId, AttributeId.Value.uid(), null,
            QualifiedName.NULL_VALUE);
        OpcUaMonitoredItem monItem = new OpcUaMonitoredItem(rvId);
        monItem.setSamplingInterval(100.0);
        monItem.setQueueSize(uint(5));
        monItem.setDiscardOldest(true);
        sub.addMonitoredItem(monItem);
        StatusCode monSc = CreateMonitoredItemsWithTimestamps.create(
            client, sub, monItem, TimestampsToReturn.Source);

        if (!monSc.isGood()) {
            try { sub.delete(); } catch (Exception ignored) {}
            System.out.println(new ResultBuilder("subscription-lifecycle")
                .success(false).serviceResult(monSc)
                .error("service", "CreateMonitoredItem failed").toJson());
            return 4;
        }

        AtomicInteger notifCount = new AtomicInteger(0);
        CountDownLatch initLatch = new CountDownLatch(1);

        monItem.setDataValueListener((item, dv) -> {
            if (initLatch.getCount() > 0) { initLatch.countDown(); return; }
            notifCount.incrementAndGet();
        });

        initLatch.await(500, MILLISECONDS);

        /* DISABLED: write 100; wait 300ms; expect 0 notifications */
        int baseCount = notifCount.get();
        sub.setMonitoringMode(MonitoringMode.Disabled, List.of(monItem));
        WriteValue wvDisabled = new WriteValue(nodeId, AttributeId.Value.uid(), null,
            DataValue.valueOnly(new Variant(Integer.valueOf(100))));
        client.write(List.of(wvDisabled));
        Thread.sleep(300);
        int disabledCount = notifCount.get() - baseCount;

        /* SAMPLING: write 101, 102; wait 300ms; expect 0 publish notifications */
        int beforeSampling = notifCount.get();
        sub.setMonitoringMode(MonitoringMode.Sampling, List.of(monItem));
        client.write(List.of(new WriteValue(nodeId, AttributeId.Value.uid(), null,
            DataValue.valueOnly(new Variant(Integer.valueOf(101))))));
        client.write(List.of(new WriteValue(nodeId, AttributeId.Value.uid(), null,
            DataValue.valueOnly(new Variant(Integer.valueOf(102))))));
        Thread.sleep(300);
        int samplingCount = notifCount.get() - beforeSampling;

        /* REPORTING: write 103; collect >= 1 notification */
        int beforeReporting = notifCount.get();
        sub.setMonitoringMode(MonitoringMode.Reporting, List.of(monItem));
        client.write(List.of(new WriteValue(nodeId, AttributeId.Value.uid(), null,
            DataValue.valueOnly(new Variant(Integer.valueOf(103))))));
        long collectMs = Math.max(2000L, Math.min(toMs - 2000L, 5000L));
        Thread.sleep(collectMs);
        int reportingCount = notifCount.get() - beforeReporting;

        try { sub.delete(); } catch (Exception ignored) {}

        boolean ok = (disabledCount == 0) && (reportingCount >= 1);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subscriptionId", subId.longValue());

        List<Map<String, Object>> steps = new ArrayList<>();
        Map<String, Object> stepD = new LinkedHashMap<>();
        stepD.put("mode", "Disabled");  stepD.put("notificationCount", disabledCount);
        steps.add(stepD);
        Map<String, Object> stepS = new LinkedHashMap<>();
        stepS.put("mode", "Sampling");  stepS.put("notificationCount", samplingCount);
        steps.add(stepS);
        Map<String, Object> stepR = new LinkedHashMap<>();
        stepR.put("mode", "Reporting"); stepR.put("notificationCount", reportingCount);
        steps.add(stepR);
        result.put("modeSteps", steps);

        System.out.println(new ResultBuilder("subscription-lifecycle")
            .success(ok).addResult(result).toJson());
        return ok ? 0 : 4;
    }

    private static int slcDelete(OpcUaClient client, NodeId nodeId, long rto, long toMs)
            throws Exception {
        OpcUaSubscription sub = new OpcUaSubscription(client, 500.0);
        sub.create();

        UInteger subId = sub.getSubscriptionId().orElse(uint(0));

        ReadValueId rvId = new ReadValueId(nodeId, AttributeId.Value.uid(), null,
            QualifiedName.NULL_VALUE);
        OpcUaMonitoredItem monItem = new OpcUaMonitoredItem(rvId);
        sub.addMonitoredItem(monItem);
        StatusCode monSc = CreateMonitoredItemsWithTimestamps.create(
            client, sub, monItem, TimestampsToReturn.Source);

        if (!monSc.isGood()) {
            try { sub.delete(); } catch (Exception ignored) {}
            System.out.println(new ResultBuilder("subscription-lifecycle")
                .success(false).serviceResult(monSc)
                .error("service", "CreateMonitoredItem failed").toJson());
            return 4;
        }

        UInteger monId = monItem.getMonitoredItemId().orElse(uint(0));

        /* DeleteMonitoredItems: first then second */
        DeleteMonitoredItemsResponse dmResp1 =
            client.deleteMonitoredItems(subId, List.of(monId));
        StatusCode delMon1 = (dmResp1.getResults() != null && dmResp1.getResults().length > 0)
            ? dmResp1.getResults()[0] : StatusCode.GOOD;

        StatusCode delMon2;
        try {
            DeleteMonitoredItemsResponse dmResp2 =
                client.deleteMonitoredItems(subId, List.of(monId));
            delMon2 = (dmResp2.getResults() != null && dmResp2.getResults().length > 0)
                ? dmResp2.getResults()[0] : StatusCode.GOOD;
        } catch (UaException e) {
            delMon2 = e.getStatusCode();
        }

        /* DeleteSubscriptions: first then second */
        DeleteSubscriptionsResponse dsResp1 = client.deleteSubscriptions(List.of(subId));
        StatusCode delSub1 = (dsResp1.getResults() != null && dsResp1.getResults().length > 0)
            ? dsResp1.getResults()[0] : StatusCode.GOOD;

        StatusCode delSub2;
        try {
            DeleteSubscriptionsResponse dsResp2 = client.deleteSubscriptions(List.of(subId));
            delSub2 = (dsResp2.getResults() != null && dsResp2.getResults().length > 0)
                ? dsResp2.getResults()[0] : StatusCode.GOOD;
        } catch (UaException e) {
            delSub2 = e.getStatusCode();
        }

        boolean ok = delMon2.isBad() && delSub2.isBad();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subscriptionId", subId.longValue());

        Map<String, Object> delMon = new LinkedHashMap<>();
        delMon.put("first",  ResultBuilder.statusCodeJson(delMon1));
        delMon.put("second", ResultBuilder.statusCodeJson(delMon2));
        result.put("deleteMonitoredItem", delMon);

        Map<String, Object> delSub = new LinkedHashMap<>();
        delSub.put("first",  ResultBuilder.statusCodeJson(delSub1));
        delSub.put("second", ResultBuilder.statusCodeJson(delSub2));
        result.put("deleteSubscription", delSub);

        System.out.println(new ResultBuilder("subscription-lifecycle")
            .success(ok).addResult(result).toJson());
        return ok ? 0 : 4;
    }

    // -------------------------------------------------------------------------
    // event-subscribe
    // -------------------------------------------------------------------------

    private static int cmdEventSubscribe(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        if (endpointUrl == null || nodeStr == null) {
            System.out.println(new ResultBuilder("event-subscribe")
                .error("input", "missing --endpoint or --node").toJson());
            return 2;
        }
        long   cto      = connectTimeoutMs(args);
        long   rto      = requestTimeoutMs(args);
        long   dto      = disconnectTimeoutMs(args);
        double piMs     = parseDoubleArg(args, "--publishing-interval-ms", 500.0);
        int    nEvents  = parseIntArg(args, "--events", 1);
        long   toMs     = parseLongArg(args, "--timeout-ms", 10000L);
        int    queueSz  = parseIntArg(args, "--queue-size", 10);

        String[] fieldNames = {
            "EventId", "EventType", "SourceName", "Message", "Severity", "Time"
        };

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);

            // Build BaseEvent EventFilter select clauses
            SimpleAttributeOperand[] selectClauses =
                    new SimpleAttributeOperand[fieldNames.length];
            for (int i = 0; i < fieldNames.length; i++) {
                selectClauses[i] = new SimpleAttributeOperand(
                    Identifiers.BaseEventType,
                    new QualifiedName[]{ new QualifiedName(0, fieldNames[i]) },
                    AttributeId.Value.uid(),
                    null);
            }
            EventFilter eventFilter = new EventFilter(
                selectClauses,
                new ContentFilter(new ContentFilterElement[0]));

            ExtensionObject filterEO = ExtensionObject.encode(
                client.getStaticEncodingContext(), eventFilter);

            MonitoringParameters monParams = new MonitoringParameters(
                uint(1),
                0.0,
                filterEO,
                uint(Math.max(1, queueSz)),
                true);

            // CreateSubscription via raw service (no Milo publish loop)
            CreateSubscriptionResponse csResp =
                (CreateSubscriptionResponse) client.sendRequest(
                    new CreateSubscriptionRequest(newRequestHeader(client, rto), piMs,
                        uint(10000), uint(10), uint(0), true,
                        ubyte(0)));
            StatusCode csStatus = csResp.getResponseHeader().getServiceResult();
            if (!csStatus.isGood()) {
                System.out.println(new ResultBuilder("event-subscribe")
                    .success(false).serviceResult(csStatus)
                    .error("service", "CreateSubscription failed").toJson());
                return 4;
            }
            UInteger subId = csResp.getSubscriptionId();
            double   rpi   = csResp.getRevisedPublishingInterval();

            // CreateMonitoredItems with EventFilter
            MonitoredItemCreateRequest monReq = new MonitoredItemCreateRequest(
                new ReadValueId(nodeId, AttributeId.EventNotifier.uid(),
                    null, QualifiedName.NULL_VALUE),
                MonitoringMode.Reporting,
                monParams);

            CreateMonitoredItemsResponse cmResp =
                (CreateMonitoredItemsResponse) client.sendRequest(
                    new CreateMonitoredItemsRequest(newRequestHeader(client, rto),
                        subId, TimestampsToReturn.Both,
                        new MonitoredItemCreateRequest[]{ monReq }));
            StatusCode monSc = StatusCode.GOOD;
            UInteger   monId = uint(1); // client handle assigned above
            if (cmResp.getResults() != null && cmResp.getResults().length > 0) {
                monSc = cmResp.getResults()[0].getStatusCode();
            }

            // Collect events via manual Publish loop
            List<Variant[]> collectedEvents =
                Collections.synchronizedList(new ArrayList<>());
            boolean timedOut = false;

            if (monSc.isGood()) {
                long deadline = System.currentTimeMillis() + toMs;
                List<SubscriptionAcknowledgement> acks = new ArrayList<>();

                while (collectedEvents.size() < nEvents) {
                    long remaining = deadline - System.currentTimeMillis();
                    if (remaining <= 0) { timedOut = true; break; }

                    PublishResponse pubResp;
                    try {
                        pubResp = (PublishResponse) client.sendRequest(
                            new PublishRequest(
                                newRequestHeader(client, Math.min(remaining + 2000, rto + 2000)),
                                acks.toArray(new SubscriptionAcknowledgement[0])));
                    } catch (Exception e) {
                        if (System.currentTimeMillis() >= deadline) timedOut = true;
                        break;
                    }

                    acks.clear();
                    NotificationMessage nm = pubResp.getNotificationMessage();
                    if (nm != null) {
                        UInteger seq = nm.getSequenceNumber();
                        if (seq != null && pubResp.getSubscriptionId() != null) {
                            acks.add(new SubscriptionAcknowledgement(
                                pubResp.getSubscriptionId(), seq));
                        }
                        if (nm.getNotificationData() != null) {
                            for (ExtensionObject eo : nm.getNotificationData()) {
                                Object decoded = eo.decode(
                                    client.getStaticEncodingContext());
                                if (decoded instanceof EventNotificationList) {
                                    EventFieldList[] evts =
                                        ((EventNotificationList) decoded).getEvents();
                                    if (evts != null) {
                                        for (EventFieldList ev : evts) {
                                            // client handle 1 was assigned in MonitoringParameters
                                            if (monId.equals(ev.getClientHandle())) {
                                                Variant[] fields = ev.getEventFields();
                                                collectedEvents.add(
                                                    fields != null ? fields : new Variant[0]);
                                                if (collectedEvents.size() >= nEvents) break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (!timedOut && collectedEvents.size() < nEvents)
                    timedOut = (System.currentTimeMillis() >= deadline);
            }

            // Delete subscription
            try {
                client.sendRequest(new DeleteSubscriptionsRequest(
                    newRequestHeader(client, dto), new UInteger[]{ subId }));
            } catch (Exception ignored) {}

            // Build result
            List<Map<String, Object>> eventList = new ArrayList<>();
            int seqNum = 0;
            for (Variant[] vs : collectedEvents) {
                seqNum++;
                List<Map<String, Object>> fields = new ArrayList<>();
                for (int i = 0; i < Math.min(vs.length, fieldNames.length); i++) {
                    String typeName = ResultBuilder.builtInTypeName(vs[i]);
                    Map<String, Object> fld = new LinkedHashMap<>();
                    fld.put("name",        fieldNames[i]);
                    fld.put("dataType",    typeName);
                    fld.put("builtInType", ResultBuilder.builtInTypeId(typeName));
                    fld.put("value",       ResultBuilder.encodeVariantValue(vs[i]));
                    fields.add(fld);
                }
                Map<String, Object> evt = new LinkedHashMap<>();
                evt.put("sequenceNumber", seqNum);
                evt.put("fields", fields);
                eventList.add(evt);
            }

            Map<String, Object> resultItem = new LinkedHashMap<>();
            resultItem.put("nodeId",                    ResultBuilder.nodeIdToString(nodeId));
            resultItem.put("subscriptionId",            subId.longValue());
            resultItem.put("revisedPublishingInterval", rpi);
            resultItem.put("monitoredItemStatusCode",   ResultBuilder.statusCodeJson(monSc));
            resultItem.put("selectClauses",             Arrays.asList(fieldNames));
            resultItem.put("events",                    eventList);

            ResultBuilder rb = new ResultBuilder("event-subscribe")
                .success(monSc.isGood() && !timedOut)
                .serviceResult(monSc)
                .addResult(resultItem);
            if (timedOut) rb.error("timeout", "timeout waiting for events");
            System.out.println(rb.toJson());
            return timedOut ? 7 : (monSc.isGood() ? 0 : 4);
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // history-read
    // -------------------------------------------------------------------------

    private static int cmdHistoryRead(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String nodeStr     = findArg(args, "--node");
        String startStr    = findArg(args, "--start");
        String endStr      = findArg(args, "--end");
        if (endpointUrl == null || nodeStr == null || startStr == null || endStr == null) {
            System.out.println(new ResultBuilder("history-read")
                .error("input", "missing --endpoint, --node, --start, or --end").toJson());
            return 2;
        }
        long   cto         = connectTimeoutMs(args);
        long   rto         = requestTimeoutMs(args);
        long   dto         = disconnectTimeoutMs(args);
        int    numValues   = parseIntArg(args, "--num-values", 0);
        String cpStr       = findArg(args, "--continuation-point");
        boolean releaseCp  = hasFlagValue(args, "--release-continuation-point", "true");
        boolean retBounds  = hasFlagValue(args, "--return-bounds", "true");
        TimestampsToReturn ts = parseTimestamps(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);

            // Convert RFC 3339 strings to OPC UA DateTime
            DateTime startTime = instantToDateTime(Instant.parse(startStr));
            DateTime endTime   = instantToDateTime(Instant.parse(endStr));

            ReadRawModifiedDetails readDetails = new ReadRawModifiedDetails(
                false,
                startTime,
                endTime,
                UInteger.valueOf(numValues),
                retBounds);

            ExtensionObject histDetails = ExtensionObject.encode(
                client.getStaticEncodingContext(), readDetails);

            ByteString continuationPoint = (cpStr != null && !cpStr.isEmpty())
                ? ByteString.of(java.util.Base64.getDecoder().decode(cpStr))
                : ByteString.NULL_VALUE;

            HistoryReadValueId hvId = new HistoryReadValueId(
                nodeId, null, QualifiedName.NULL_VALUE, continuationPoint);

            HistoryReadResponse resp = (HistoryReadResponse) client.sendRequest(
                new HistoryReadRequest(
                    newRequestHeader(client, rto),
                    histDetails,
                    ts,
                    releaseCp,
                    new HistoryReadValueId[]{ hvId }));

            StatusCode svcSc  = resp.getResponseHeader().getServiceResult();
            StatusCode itemSc = StatusCode.GOOD;
            String     cpOut  = null;
            List<Map<String, Object>> valuesList = new ArrayList<>();

            if (svcSc.isGood() && resp.getResults() != null && resp.getResults().length > 0) {
                HistoryReadResult hr = resp.getResults()[0];
                itemSc = hr.getStatusCode() != null ? hr.getStatusCode() : StatusCode.GOOD;

                ByteString cp = hr.getContinuationPoint();
                if (cp != null && cp.bytes() != null && cp.bytes().length > 0) {
                    cpOut = java.util.Base64.getEncoder().encodeToString(cp.bytes());
                }

                ExtensionObject histDataEO = hr.getHistoryData();
                if (histDataEO != null) {
                    Object decoded = histDataEO.decode(client.getStaticEncodingContext());
                    if (decoded instanceof HistoryData) {
                        DataValue[] dvs = ((HistoryData) decoded).getDataValues();
                        if (dvs != null) {
                            for (DataValue dv : dvs) {
                                Map<String, Object> v = new LinkedHashMap<>();
                                String typeName = ResultBuilder.builtInTypeName(dv.getValue());
                                v.put("value",       ResultBuilder.encodeVariantValue(dv.getValue()));
                                v.put("dataType",    typeName);
                                v.put("builtInType", ResultBuilder.builtInTypeId(typeName));
                                v.put("statusCode",  ResultBuilder.statusCodeJson(
                                    dv.getStatusCode() != null
                                        ? dv.getStatusCode() : StatusCode.GOOD));
                                if (dv.getSourceTime() != null
                                        && dv.getSourceTime().getJavaTime() != 0) {
                                    v.put("sourceTimestamp",
                                        dv.getSourceTime().getJavaInstant().toString());
                                }
                                if (dv.getServerTime() != null
                                        && dv.getServerTime().getJavaTime() != 0) {
                                    v.put("serverTimestamp",
                                        dv.getServerTime().getJavaInstant().toString());
                                }
                                valuesList.add(v);
                            }
                        }
                    }
                }
            }

            Map<String, Object> resultItem = new LinkedHashMap<>();
            resultItem.put("nodeId",            ResultBuilder.nodeIdToString(nodeId));
            resultItem.put("statusCode",        ResultBuilder.statusCodeJson(itemSc));
            resultItem.put("continuationPoint", cpOut);
            resultItem.put("values",            valuesList);

            boolean ok = svcSc.isGood() && itemSc.isGood();
            StatusCode emitSc = svcSc.isGood() ? itemSc : svcSc;
            System.out.println(new ResultBuilder("history-read")
                .success(ok).serviceResult(emitSc).addResult(resultItem).toJson());
            return ok ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // republish
    // -------------------------------------------------------------------------

    private static int cmdRepublish(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String subIdStr    = findArg(args, "--subscription-id");
        String seqStr      = findArg(args, "--sequence-number");
        if (endpointUrl == null || subIdStr == null || seqStr == null) {
            System.out.println(new ResultBuilder("republish")
                .error("input",
                    "missing --endpoint, --subscription-id, or --sequence-number").toJson());
            return 2;
        }
        long     cto    = connectTimeoutMs(args);
        long     rto    = requestTimeoutMs(args);
        long     dto    = disconnectTimeoutMs(args);
        UInteger subId  = uint((int) Long.parseLong(subIdStr));
        UInteger seqNum = uint((int) Long.parseLong(seqStr));

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            RepublishResponse resp = (RepublishResponse) client.sendRequest(
                new RepublishRequest(newRequestHeader(client, rto), subId, seqNum));

            StatusCode sc = resp.getResponseHeader().getServiceResult();
            boolean ok = sc.isGood();

            Map<String, Object> resultItem = new LinkedHashMap<>();
            resultItem.put("subscriptionId",           subId.longValue());
            resultItem.put("retransmitSequenceNumber", seqNum.longValue());
            if (ok) {
                NotificationMessage nm = resp.getNotificationMessage();
                if (nm != null) {
                    resultItem.put("sequenceNumber",
                        nm.getSequenceNumber() != null ? nm.getSequenceNumber().longValue() : 0L);
                    if (nm.getPublishTime() != null && nm.getPublishTime().getJavaTime() != 0) {
                        resultItem.put("publishTime",
                            nm.getPublishTime().getJavaInstant().toString());
                    }
                    int ndCount = nm.getNotificationData() != null
                        ? nm.getNotificationData().length : 0;
                    resultItem.put("notificationDataCount", ndCount);
                }
            }

            System.out.println(new ResultBuilder("republish")
                .success(ok).serviceResult(sc).addResult(resultItem).toJson());
            return ok ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // transfer-subscriptions
    // -------------------------------------------------------------------------

    private static int cmdTransferSubscriptions(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        List<String> subIdStrs = findAllArgs(args, "--subscription-id");
        if (endpointUrl == null || subIdStrs.isEmpty()) {
            System.out.println(new ResultBuilder("transfer-subscriptions")
                .error("input",
                    "missing --endpoint or --subscription-id").toJson());
            return 2;
        }
        long    cto          = connectTimeoutMs(args);
        long    rto          = requestTimeoutMs(args);
        long    dto          = disconnectTimeoutMs(args);
        boolean sendInitial  = hasFlagValue(args, "--send-initial-values", "true");

        UInteger[] subIds = subIdStrs.stream()
            .map(s -> uint((int) Long.parseLong(s)))
            .toArray(UInteger[]::new);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            TransferSubscriptionsResponse resp =
                (TransferSubscriptionsResponse) client.sendRequest(
                    new TransferSubscriptionsRequest(
                        newRequestHeader(client, rto), subIds, sendInitial));

            StatusCode sc = resp.getResponseHeader().getServiceResult();
            boolean ok = sc.isGood();
            TransferResult[] results = resp.getResults();

            List<Map<String, Object>> resultList = new ArrayList<>();
            if (sc.isGood() && results != null) {
                for (int i = 0; i < results.length; i++) {
                    TransferResult r = results[i];
                    StatusCode rSc = r.getStatusCode() != null
                        ? r.getStatusCode() : StatusCode.GOOD;
                    if (!rSc.isGood()) ok = false;

                    List<Long> seqNums = new ArrayList<>();
                    if (r.getAvailableSequenceNumbers() != null) {
                        for (UInteger sn : r.getAvailableSequenceNumbers()) {
                            seqNums.add(sn.longValue());
                        }
                    }

                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("subscriptionId",           subIds[i].longValue());
                    m.put("statusCode",               ResultBuilder.statusCodeJson(rSc));
                    m.put("availableSequenceNumbers", seqNums);
                    resultList.add(m);
                }
            }

            ResultBuilder rb = new ResultBuilder("transfer-subscriptions")
                .success(ok).serviceResult(sc);
            for (Map<String, Object> r : resultList) rb.addResult(r);
            System.out.println(rb.toJson());
            return ok ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static OpcUaClient connectClient(String endpointUrl, long connectTimeoutMs, long requestTimeoutMs)
            throws Exception {
        return connectClient(endpointUrl, connectTimeoutMs, requestTimeoutMs,
                             /* args */ null);
    }

    /**
     * Connect to an OPC UA server, selecting an endpoint matching the requested
     * security policy and mode.  When {@code args} contains --security-policy and
     * --security-mode flags, they override the default None/None.
     */
    private static OpcUaClient connectClient(String endpointUrl,
                                              long connectTimeoutMs,
                                              long requestTimeoutMs,
                                              String[] args) throws Exception {
        String policyName = args != null ? findArg(args, "--security-policy") : null;
        String modeName   = args != null ? findArg(args, "--security-mode")   : null;
        String certFile   = args != null ? findArg(args, "--certificate")     : null;
        String keyFile    = args != null ? findArg(args, "--private-key")     : null;
        String username   = args != null ? findArg(args, "--username")        : null;
        String password   = args != null ? findArg(args, "--password")        : null;
        List<String> trustFiles = args != null ? findAllArgs(args, "--trust-list") : List.of();

        if (policyName == null) policyName = "None";
        if (modeName   == null) modeName   = "None";

        SecurityPolicy       reqPolicy = toMiloSecurityPolicy(policyName);
        MessageSecurityMode  reqMode   = toMiloSecurityMode(modeName);

        List<EndpointDescription> eps = DiscoveryClient.getEndpoints(endpointUrl)
                .get(connectTimeoutMs, MILLISECONDS);

        final SecurityPolicy  fPolicy = reqPolicy;
        final MessageSecurityMode fMode = reqMode;
        EndpointDescription endpoint = eps.stream()
                .filter(e -> fPolicy.getUri().equals(e.getSecurityPolicyUri())
                          && fMode.equals(e.getSecurityMode()))
                .findFirst()
                .orElse(null);

        if (endpoint == null) {
            throw new TransportException(
                    "no endpoint with SecurityPolicy=" + policyName +
                    " and MessageSecurityMode=" + modeName + " at " + endpointUrl);
        }

        // Replace the advertised URL with the discovery URL so the TCP connection
        // reaches the right host (avoids container hostname resolution issues).
        endpoint = new EndpointDescription(
                endpointUrl,
                endpoint.getServer(),
                endpoint.getServerCertificate(),
                endpoint.getSecurityMode(),
                endpoint.getSecurityPolicyUri(),
                endpoint.getUserIdentityTokens(),
                endpoint.getTransportProfileUri(),
                endpoint.getSecurityLevel());

        OpcUaClientConfigBuilder cfgBuilder = OpcUaClientConfig.builder()
                .setEndpoint(endpoint)
                .setApplicationUri("urn:otfabric:opcua-interop:client:milo")
                .setApplicationName(LocalizedText.english("opcua-interop milo client"))
                .setRequestTimeout(UInteger.valueOf(requestTimeoutMs));

        // Load client certificate and key when using a secure channel
        if (certFile != null && keyFile != null && reqMode != MessageSecurityMode.None) {
            try {
                X509Certificate clientCert = loadCertificate(certFile);
                PrivateKey      clientKey  = loadPrivateKey(keyFile);
                cfgBuilder.setCertificate(clientCert)
                          .setCertificateChain(new X509Certificate[]{clientCert})
                          .setKeyPair(new KeyPair(clientCert.getPublicKey(), clientKey));

                // Trust list for server certificate validation
                if (!trustFiles.isEmpty()) {
                    // Write trusted certs to a temp directory for FileBasedTrustListManager
                    Path trustTempDir = Files.createTempDirectory("milo-client-trust-");
                    Path trustedCertsDir = trustTempDir.resolve("trusted/certs");
                    Files.createDirectories(trustedCertsDir);
                    Files.createDirectories(trustTempDir.resolve("trusted/crl"));
                    Files.createDirectories(trustTempDir.resolve("issuers/certs"));
                    Files.createDirectories(trustTempDir.resolve("rejected/certs"));
                    for (int i = 0; i < trustFiles.size(); i++) {
                        byte[] certBytes = Files.readAllBytes(Paths.get(trustFiles.get(i)));
                        Files.write(trustedCertsDir.resolve("trust-" + i + ".crt"), certBytes);
                    }
                    var tlm = FileBasedTrustListManager.createAndInitialize(trustTempDir);
                    var quarantine = FileBasedCertificateQuarantine.create(
                            trustTempDir.resolve("rejected/certs"));
                    var validator = new DefaultServerCertificateValidator(tlm, quarantine);
                    cfgBuilder.setCertificateValidator(validator);
                }
            } catch (Exception e) {
                throw new TransportException("failed to load client certificate/key: " + e.getMessage());
            }
        }

        // Set user identity token
        if (username != null) {
            cfgBuilder.setIdentityProvider(
                    new org.eclipse.milo.opcua.sdk.client.identity.UsernameProvider(
                            username, password != null ? password : ""));
        }

        OpcUaClient client = OpcUaClient.create(cfgBuilder.build());
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
            case "Int32[]": {
                // Comma-separated Int32 array, e.g. --type Int32[] --value 1,2,3
                String[] parts = val.split(",");
                Integer[] arr = new Integer[parts.length];
                for (int i = 0; i < parts.length; i++) {
                    arr[i] = Integer.parseInt(parts[i].trim());
                }
                return new Variant(arr);
            }
            default:         return new Variant(val);
        }
    }

    private static TimestampsToReturn parseTimestamps(String[] args) {
        String ts = findArg(args, "--timestamps");
        if (ts == null) return TimestampsToReturn.Both;
        switch (ts) {
            case "Source":  return TimestampsToReturn.Source;
            case "Server":  return TimestampsToReturn.Server;
            case "Neither": return TimestampsToReturn.Neither;
            case "Both":
            default:        return TimestampsToReturn.Both;
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

    /** Returns true unless the flag is explicitly present with the given value. */
    private static boolean hasFlagValue(String[] args, String flag, String value) {
        String val = findArg(args, flag);
        return val != null && val.equalsIgnoreCase(value);
    }

    private static long connectTimeoutMs(String[] args)    { return parseLongArg(args, "--connect-timeout",    5) * 1000; }
    private static long requestTimeoutMs(String[] args)    { return parseLongArg(args, "--request-timeout",    5) * 1000; }
    private static long disconnectTimeoutMs(String[] args) { return parseLongArg(args, "--disconnect-timeout", 2) * 1000; }

    /**
     * Build a RequestHeader with the active session AuthenticationToken.
     * Raw {@code client.sendRequest(...)} calls do not inject the token; a NULL
     * token makes CreateMonitoredItems fail ownership checks on go-opcua.
     */
    private static RequestHeader newRequestHeader(OpcUaClient client, long timeoutMs)
            throws UaException {
        NodeId auth = NodeId.NULL_VALUE;
        if (client != null) {
            OpcUaSession session = client.getSession();
            if (session != null && session.getAuthenticationToken() != null) {
                auth = session.getAuthenticationToken();
            }
        }
        return new RequestHeader(
            auth,
            DateTime.now(),
            UInteger.valueOf(0),
            UInteger.valueOf(0),
            null,
            UInteger.valueOf((int) Math.min(timeoutMs, Integer.MAX_VALUE)),
            null);
    }

    /** Convert java.time.Instant to OPC UA DateTime (100-ns ticks since 1601-01-01). */
    private static DateTime instantToDateTime(Instant instant) {
        // OPC UA epoch offset: 116444736000000000 100-ns ticks from 1601-01-01 to 1970-01-01
        final long OPC_UA_EPOCH_OFFSET_MILLIS = 11644473600000L;
        long javaMs = instant.toEpochMilli();
        long javaOpcNs100 = (javaMs + OPC_UA_EPOCH_OFFSET_MILLIS) * 10_000L;
        return new DateTime(javaOpcNs100);
    }

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

    // ── Security helpers (shared with ServerCommand logic) ────────────────

    private static X509Certificate loadCertificate(String path) throws Exception {
        byte[] raw = Files.readAllBytes(Paths.get(path));
        String pem = new String(raw).trim();
        if (pem.startsWith("-----")) {
            String b64 = pem
                    .replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");
            raw = java.util.Base64.getDecoder().decode(b64);
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(raw));
    }

    private static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] raw = Files.readAllBytes(Paths.get(path));
        String pem = new String(raw).trim();
        if (pem.contains("BEGIN PRIVATE KEY")) {
            String b64 = pem
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            return KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(b64)));
        }
        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            String b64 = pem
                    .replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replaceAll("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] pkcs1 = java.util.Base64.getDecoder().decode(b64);
            return KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(pkcs1ToPkcs8(pkcs1)));
        }
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw));
    }

    private static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        byte[] oid = new byte[]{ 0x06, 0x09,
            0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00 };
        byte[] alg     = encodeSeq(oid);
        byte[] keyData = encodeTag((byte)0x04, pkcs1);
        byte[] inner   = concat(new byte[]{0x02, 0x01, 0x00}, alg, keyData);
        return encodeSeq(inner);
    }

    private static byte[] encodeSeq(byte[] c)          { return encodeTag((byte)0x30, c); }
    private static byte[] encodeTag(byte tag, byte[] c) {
        int len = c.length;
        byte[] lb = len < 128 ? new byte[]{(byte)len}
                  : len < 256 ? new byte[]{(byte)0x81, (byte)len}
                  : new byte[]{(byte)0x82, (byte)(len >> 8), (byte)(len & 0xff)};
        byte[] r = new byte[1 + lb.length + len];
        r[0] = tag;
        System.arraycopy(lb, 0, r, 1, lb.length);
        System.arraycopy(c,  0, r, 1 + lb.length, len);
        return r;
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0; for (byte[] a : arrays) total += a.length;
        byte[] r = new byte[total]; int pos = 0;
        for (byte[] a : arrays) { System.arraycopy(a, 0, r, pos, a.length); pos += a.length; }
        return r;
    }

    private static SecurityPolicy toMiloSecurityPolicy(String name) {
        if (name == null) return SecurityPolicy.None;
        switch (name) {
            case "Basic128Rsa15":         return SecurityPolicy.Basic128Rsa15;
            case "Basic256":              return SecurityPolicy.Basic256;
            case "Basic256Sha256":        return SecurityPolicy.Basic256Sha256;
            case "Aes128_Sha256_RsaOaep": return SecurityPolicy.Aes128_Sha256_RsaOaep;
            case "Aes256_Sha256_RsaPss":  return SecurityPolicy.Aes256_Sha256_RsaPss;
            default:                      return SecurityPolicy.None;
        }
    }

    private static MessageSecurityMode toMiloSecurityMode(String name) {
        if (name == null) return MessageSecurityMode.None;
        switch (name) {
            case "Sign":           return MessageSecurityMode.Sign;
            case "SignAndEncrypt": return MessageSecurityMode.SignAndEncrypt;
            default:               return MessageSecurityMode.None;
        }
    }
}
