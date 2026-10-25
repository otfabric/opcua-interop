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
import org.eclipse.milo.opcua.stack.core.types.enumerated.FilterOperator;
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
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;

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

    /** Invalid or unsupported command-line input — maps to exit 2. */
    static class InputException extends Exception {
        public InputException(String msg) { super(msg); }
    }

    /** Security policy names this adapter accepts (Milo 1.1.8 has no ECC policies). */
    private static final Set<String> KNOWN_POLICIES = Set.of(
        "None", "Basic128Rsa15", "Basic256", "Basic256Sha256",
        "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss");

    /** Reject features Eclipse Milo 1.1.8 does not implement instead of ignoring the flag. */
    private static void rejectUnsupported(String[] args) throws InputException {
        if (findArg(args, "--reverse-listen") != null || findArg(args, "--reverse-server-uri") != null) {
            throw new InputException(
                "--reverse-listen: reverse connect (ReverseHello) is not implemented by Eclipse Milo 1.1.8");
        }
        String policy = findArg(args, "--security-policy");
        if (policy != null && !KNOWN_POLICIES.contains(policy)) {
            throw new InputException("--security-policy " + policy
                + " is not supported by Eclipse Milo 1.1.8"
                + (policy.startsWith("ECC_") ? " (no ECC security policies)" : ""));
        }
    }

    public static int run(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: client <endpoints|find-servers|read|write|browse|translate|"
                + "call|subscribe|subscription-lifecycle|event-subscribe|alarms|history-read|"
                + "republish|transfer-subscriptions|register-nodes|node-management|"
                + "find-servers-on-network|register-server|push|gds-pull|codec> ...");
            return 1;
        }
        String op = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);

        try {
            rejectUnsupported(rest);
            switch (op) {
                case "endpoints":    return cmdEndpoints(rest);
                case "find-servers": return cmdFindServers(rest);
                case "read":         return cmdRead(rest);
                case "write":        return cmdWrite(rest);
                case "browse":       return cmdBrowse(rest);
                case "translate":    return cmdTranslate(rest);
                case "call":         return cmdCall(rest);
                case "subscribe":    return cmdSubscribe(rest);
                case "subscription-lifecycle": return cmdSubscriptionLifecycle(rest);
                case "event-subscribe":        return cmdEventSubscribe(rest);
                case "alarms":                 return cmdAlarms(rest);
                case "history-read":           return cmdHistoryRead(rest);
                case "republish":              return cmdRepublish(rest);
                case "transfer-subscriptions": return cmdTransferSubscriptions(rest);
                case "register-nodes":         return cmdRegisterNodes(rest);
                case "node-management":        return cmdNodeManagement(rest);
                case "find-servers-on-network": return cmdFindServersOnNetwork(rest);
                case "register-server":        return cmdRegisterServer(rest);
                case "push":                   return PushCommand.cmdPush(rest);
                case "gds-pull":               return PushCommand.cmdGdsPull(rest);
                case "codec":                  return CodecCommand.run(rest);
                default:
                    System.err.println("unknown client subcommand: " + op);
                    return 1;
            }
        } catch (NodeIdParser.InvalidNodeIdException | NodeIdParser.UnknownNamespaceException e) {
            System.out.println(new ResultBuilder(op).error("input", e.getMessage()).toJson());
            return 2;
        } catch (InputException e) {
            System.out.println(new ResultBuilder(op)
                .serviceResult(org.eclipse.milo.opcua.stack.core.StatusCodes.Bad_InvalidArgument)
                .error("input", e.getMessage()).toJson());
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
            LOG.error("client op {} failed", op, e);
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
    // find-servers
    // -------------------------------------------------------------------------

    private static int cmdFindServers(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        if (endpointUrl == null) {
            System.out.println(new ResultBuilder("find-servers").error("input", "missing --endpoint").toJson());
            return 2;
        }
        long rto = requestTimeoutMs(args);

        List<ApplicationDescription> apps =
                DiscoveryClient.findServers(endpointUrl).get(rto, MILLISECONDS);
        ResultBuilder rb = new ResultBuilder("find-servers");
        for (ApplicationDescription app : apps) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("applicationUri", app.getApplicationUri() != null ? app.getApplicationUri() : "");
            Map<String, Object> name = new LinkedHashMap<>();
            LocalizedText an = app.getApplicationName();
            name.put("locale", an != null && an.getLocale() != null ? an.getLocale() : "");
            name.put("text",   an != null && an.getText()   != null ? an.getText()   : "");
            m.put("applicationName", name);
            m.put("productUri", app.getProductUri() != null ? app.getProductUri() : "");
            List<String> urls = new ArrayList<>();
            if (app.getDiscoveryUrls() != null) {
                for (String u : app.getDiscoveryUrls()) {
                    if (u != null) urls.add(u);
                }
            }
            m.put("discoveryUrls", urls);
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
    // translate
    // -------------------------------------------------------------------------

    private static int cmdTranslate(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String startStr    = findArg(args, "--starting-node");
        String pathStr     = findArg(args, "--path");
        if (startStr == null) startStr = "i=85";
        if (endpointUrl == null) {
            System.out.println(new ResultBuilder("translate").error("input", "missing --endpoint").toJson());
            return 2;
        }
        if (pathStr == null || pathStr.isEmpty()) {
            System.out.println(new ResultBuilder("translate").error("input", "missing --path").toJson());
            return 2;
        }

        int ns = (int) parseLongArg(args, "--namespace", 0);
        String[] segments = Arrays.stream(pathStr.split("\\."))
                .filter(s -> !s.isEmpty())
                .toArray(String[]::new);
        if (segments.length == 0) {
            System.out.println(new ResultBuilder("translate").error("input", "empty --path").toJson());
            return 2;
        }

        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId startingNode = NodeIdParser.resolveWithClient(startStr, client, rto);

            RelativePathElement[] elements = new RelativePathElement[segments.length];
            for (int i = 0; i < segments.length; i++) {
                elements[i] = new RelativePathElement(
                        Identifiers.HierarchicalReferences,
                        false,
                        true,
                        new QualifiedName(ns, segments[i]));
            }
            BrowsePath browsePath = new BrowsePath(startingNode, new RelativePath(elements));
            TranslateBrowsePathsToNodeIdsResponse resp =
                    client.translateBrowsePaths(Collections.singletonList(browsePath));

            StatusCode serviceSc = resp.getResponseHeader().getServiceResult();
            BrowsePathResult[] results = resp.getResults();
            StatusCode pathSc = (results != null && results.length > 0)
                    ? results[0].getStatusCode() : serviceSc;
            boolean ok = serviceSc.isGood() && pathSc.isGood();

            ResultBuilder rb = new ResultBuilder("translate")
                    .serviceResult(serviceSc)
                    .success(ok);

            if (serviceSc.isGood() && results != null && results.length > 0) {
                BrowsePathResult bpr = results[0];
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("statusCode", ResultBuilder.statusCodeJson(bpr.getStatusCode()));
                List<String> targets = new ArrayList<>();
                if (bpr.getTargets() != null) {
                    for (BrowsePathTarget t : bpr.getTargets()) {
                        targets.add(ResultBuilder.nodeIdToString(expandedToLocalNodeId(t.getTargetId())));
                    }
                }
                item.put("targets", targets);
                rb.addResult(item);
            }

            System.out.println(rb.toJson());
            return ok ? 0 : 4;
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

        // DataChangeFilter: --deadband-absolute | --deadband-percent, --trigger.
        String dbAbs = findArg(args, "--deadband-absolute");
        String dbPct = findArg(args, "--deadband-percent");
        String trig  = findArg(args, "--trigger");
        boolean useFilter = dbAbs != null || dbPct != null || trig != null;
        String triggerName = trig != null ? trig : "StatusValue";
        String deadbandName = dbAbs != null ? "Absolute" : dbPct != null ? "Percent" : "None";
        double deadbandValue = 0.0;
        DataChangeFilter dcFilter = null;
        if (useFilter) {
            if (dbAbs != null && dbPct != null) {
                throw new InputException("--deadband-absolute and --deadband-percent are mutually exclusive");
            }
            org.eclipse.milo.opcua.stack.core.types.enumerated.DataChangeTrigger trigger;
            switch (triggerName) {
                case "Status":
                    trigger = org.eclipse.milo.opcua.stack.core.types.enumerated.DataChangeTrigger.Status; break;
                case "StatusValue":
                    trigger = org.eclipse.milo.opcua.stack.core.types.enumerated.DataChangeTrigger.StatusValue; break;
                case "StatusValueTimestamp":
                    trigger = org.eclipse.milo.opcua.stack.core.types.enumerated.DataChangeTrigger.StatusValueTimestamp; break;
                default:
                    throw new InputException("--trigger must be Status, StatusValue or StatusValueTimestamp");
            }
            try {
                deadbandValue = dbAbs != null ? Double.parseDouble(dbAbs)
                              : dbPct != null ? Double.parseDouble(dbPct) : 0.0;
            } catch (NumberFormatException e) {
                throw new InputException("invalid deadband value");
            }
            long deadbandType = dbAbs != null ? 1 : dbPct != null ? 2 : 0;
            dcFilter = new DataChangeFilter(trigger, uint(deadbandType), deadbandValue);
        }

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
            if (dcFilter != null) monItem.setFilter(dcFilter);

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
            if (useFilter) {
                // Only present when a DataChangeFilter was requested, so the result
                // of unfiltered subscriptions is unchanged.
                resultItem.put("monitoredItemId", monItem.getMonitoredItemId().orElse(uint(0)).longValue());
                resultItem.put("revisedSamplingInterval", monItem.getRevisedSamplingInterval().orElse(0.0));
                resultItem.put("revisedQueueSize", monItem.getRevisedQueueSize().orElse(uint(0)).longValue());
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("trigger", triggerName);
                f.put("deadbandType", deadbandName);
                f.put("deadbandValue", deadbandValue);
                resultItem.put("filter", f);
                ExtensionObject fr = monItem.getFilterResult().orElse(null);
                if (fr == null || fr.getBody() == null
                        || fr.getEncodingOrTypeId() == null || fr.getEncodingOrTypeId().isNull()) {
                    resultItem.put("filterResult", null);
                } else {
                    Map<String, Object> frm = new LinkedHashMap<>();
                    frm.put("typeId", ResultBuilder.nodeIdToString(fr.getEncodingOrTypeId()));
                    resultItem.put("filterResult", frm);
                }
            }
            resultItem.put("notifications", new ArrayList<>(notifications));

            ResultBuilder rb = new ResultBuilder("subscribe")
                .success(monSc.isGood() && !timedOut)
                .serviceResult(monSc)
                .addResult(resultItem);
            if (timedOut) {
                rb.error("timeout", "timeout waiting for notifications");
            } else if (!monSc.isGood()) {
                rb.error("service", "CreateMonitoredItems rejected the monitored item");
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
        // 0 = report every change: the queue-window assertions must not depend
        // on how a server throttles samples within a sampling interval.
        monItem.setSamplingInterval(0.0);
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
        // 0 = report every change: the queue-window assertions must not depend
        // on how a server throttles samples within a sampling interval.
        monItem.setSamplingInterval(0.0);
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
        String ofTypeStr = findArg(args, "--of-type");
        String minSevStr = findArg(args, "--min-severity");

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
            ContentFilter where = buildEventWhereClause(
                client, ofTypeStr, minSevStr);
            EventFilter eventFilter = new EventFilter(selectClauses, where);

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
    // alarms (Part 9: ConditionRefresh, Acknowledge, Confirm, AddComment)
    // -------------------------------------------------------------------------

    private static final long BAD_TIMEOUT = 0x800A0000L;
    private static final long BAD_NODEID_UNKNOWN = 0x80340000L;
    private static final NodeId REFRESH_START_EVENT = new NodeId(0, uint(2787));
    private static final NodeId REFRESH_END_EVENT = new NodeId(0, uint(2788));

    /** `--acknowledge` alone, or `--acknowledge true|false`. */
    static boolean presenceFlag(String[] args, String flag) {
        for (int i = 0; i < args.length; i++) {
            if (flag.equals(args[i])) {
                if (i + 1 < args.length) {
                    String n = args[i + 1].toLowerCase(Locale.ROOT);
                    if (n.equals("false") || n.equals("0") || n.equals("no")) return false;
                }
                return true;
            }
        }
        return false;
    }

    /** The 16 select clauses of the contract (§4 `alarms`), in order. */
    static SimpleAttributeOperand[] alarmSelectClauses() {
        Object[][] spec = {
            {2041, new String[]{"EventId"}},
            {2041, new String[]{"EventType"}},
            {2041, new String[]{"SourceNode"}},
            {2041, new String[]{"SourceName"}},
            {2041, new String[]{"Time"}},
            {2041, new String[]{"Message"}},
            {2041, new String[]{"Severity"}},
            {2782, new String[]{"ConditionName"}},
            {2782, new String[]{"BranchId"}},
            {2782, new String[]{"Retain"}},
            {2782, new String[]{"EnabledState", "Id"}},
            {2782, new String[]{"Comment"}},
            {2881, new String[]{"AckedState", "Id"}},
            {2881, new String[]{"ConfirmedState", "Id"}},
            {2915, new String[]{"ActiveState", "Id"}},
        };
        SimpleAttributeOperand[] out = new SimpleAttributeOperand[spec.length + 1];
        for (int i = 0; i < spec.length; i++) {
            String[] path = (String[]) spec[i][1];
            QualifiedName[] qn = new QualifiedName[path.length];
            for (int j = 0; j < path.length; j++) qn[j] = new QualifiedName(0, path[j]);
            out[i] = new SimpleAttributeOperand(new NodeId(0, uint((Integer) spec[i][0])), qn,
                AttributeId.Value.uid(), null);
        }
        // ConditionId: ConditionType, empty BrowsePath, AttributeId NodeId (Part 9 §5.5.2)
        out[spec.length] = new SimpleAttributeOperand(new NodeId(0, uint(2782)), new QualifiedName[0],
            AttributeId.NodeId.uid(), null);
        return out;
    }

    private static Object alarmField(Variant[] f, int i) {
        if (f == null || i >= f.length || f[i] == null || f[i].isNull()) return null;
        Object v = f[i].getValue();
        if (v instanceof StatusCode || v.getClass().isArray()) return null;
        return v;
    }

    private static String alarmNodeId(Variant[] f, int i) {
        Object v = alarmField(f, i);
        if (v instanceof ExpandedNodeId) {
            return null; // event fields carry NodeIds; a non-local ExpandedNodeId is not a ConditionId
        }
        return v instanceof NodeId ? ResultBuilder.nodeIdToString((NodeId) v) : null;
    }

    private static String alarmText(Variant[] f, int i) {
        Object v = alarmField(f, i);
        if (v instanceof LocalizedText) return ((LocalizedText) v).getText();
        return v instanceof String ? (String) v : null;
    }

    private static Boolean alarmBool(Variant[] f, int i) {
        Object v = alarmField(f, i);
        return v instanceof Boolean ? (Boolean) v : null;
    }

    /** ConditionEntry of the contract (key order fixed). */
    static Map<String, Object> conditionEntry(Variant[] f) {
        Map<String, Object> e = new LinkedHashMap<>();
        Object eid = alarmField(f, 0);
        Object src = alarmField(f, 3);
        Object cn = alarmField(f, 7);
        Object time = alarmField(f, 4);
        Object sev = alarmField(f, 6);
        e.put("conditionId",   alarmNodeId(f, 15));
        e.put("eventId",       eid instanceof ByteString && ((ByteString) eid).bytes() != null
                ? Base64.getEncoder().encodeToString(((ByteString) eid).bytes()) : null);
        e.put("eventType",     alarmNodeId(f, 1));
        e.put("sourceNode",    alarmNodeId(f, 2));
        e.put("sourceName",    src instanceof String ? src : null);
        e.put("conditionName", cn instanceof String ? cn : null);
        // the OPC UA null DateTime (1601-01-01, encoded 0) is null
        e.put("time",          time instanceof DateTime && ((DateTime) time).getUtcTime() > 0
                ? ((DateTime) time).getJavaInstant().toString() : null);
        e.put("message",       alarmText(f, 5));
        e.put("severity",      sev instanceof UShort ? ((UShort) sev).intValue() : null);
        e.put("retain",        alarmBool(f, 9));
        e.put("enabled",       alarmBool(f, 10));
        e.put("acked",         alarmBool(f, 12));
        e.put("confirmed",     alarmBool(f, 13));
        e.put("active",        alarmBool(f, 14));
        e.put("comment",       alarmText(f, 11));
        return e;
    }

    /** Raw Publish loop state for the alarms command (single-threaded). */
    private static final class AlarmEvents {
        final OpcUaClient client;
        final long rto;
        final long deadline;
        final List<Variant[]> fields = new ArrayList<>();
        final List<Map<String, Object>> entries = new ArrayList<>();
        final Map<String, Map<String, Object>> latest = new HashMap<>();
        final List<SubscriptionAcknowledgement> acks = new ArrayList<>();

        AlarmEvents(OpcUaClient client, long rto, long deadline) {
            this.client = client;
            this.rto = rto;
            this.deadline = deadline;
        }

        /** One Publish; false when the deadline has passed or Publish failed. */
        boolean pump() {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) return false;
            PublishResponse resp;
            try {
                resp = (PublishResponse) client.sendRequest(new PublishRequest(
                    newRequestHeader(client, Math.min(remaining + 2000, rto + 2000)),
                    acks.toArray(new SubscriptionAcknowledgement[0])));
            } catch (Exception e) {
                return false;
            }
            acks.clear();
            NotificationMessage nm = resp.getNotificationMessage();
            if (nm == null || nm.getNotificationData() == null || nm.getNotificationData().length == 0) {
                return true;
            }
            if (nm.getSequenceNumber() != null && resp.getSubscriptionId() != null) {
                acks.add(new SubscriptionAcknowledgement(resp.getSubscriptionId(), nm.getSequenceNumber()));
            }
            for (ExtensionObject eo : nm.getNotificationData()) {
                Object decoded = eo.decode(client.getStaticEncodingContext());
                if (!(decoded instanceof EventNotificationList)) continue;
                EventFieldList[] evts = ((EventNotificationList) decoded).getEvents();
                if (evts == null) continue;
                for (EventFieldList ev : evts) {
                    if (!uint(1).equals(ev.getClientHandle())) continue;
                    Variant[] f = ev.getEventFields() != null ? ev.getEventFields() : new Variant[0];
                    Map<String, Object> entry = conditionEntry(f);
                    fields.add(f);
                    entries.add(entry);
                    if (entry.get("conditionId") != null) {
                        latest.put((String) entry.get("conditionId"), entry);
                    }
                }
            }
            return true;
        }

        Map<String, Object> waitFor(int from, java.util.function.Predicate<Map<String, Object>> p) {
            int idx = from;
            while (true) {
                while (idx < entries.size()) {
                    Map<String, Object> e = entries.get(idx++);
                    if (p.test(e)) return e;
                }
                if (!pump()) return null;
            }
        }
    }

    private static StatusCode callStatus(OpcUaClient client, NodeId obj, NodeId method, Variant[] in) {
        try {
            CallResponse resp = client.call(List.of(new CallMethodRequest(obj, method, in)));
            return resp.getResults()[0].getStatusCode();
        } catch (UaException e) {
            return e.getStatusCode();
        } catch (Exception e) {
            Throwable c = e.getCause();
            if (c instanceof UaException) return ((UaException) c).getStatusCode();
            return new StatusCode(org.eclipse.milo.opcua.stack.core.StatusCodes.Bad_UnexpectedError);
        }
    }

    private static int cmdAlarms(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        if (endpointUrl == null) {
            throw new InputException("missing --endpoint");
        }
        String nodeStr  = Optional.ofNullable(findArg(args, "--node")).orElse("i=2253");
        String condName = findArg(args, "--condition-name");
        boolean doAck     = presenceFlag(args, "--acknowledge");
        boolean doConfirm = presenceFlag(args, "--confirm");
        boolean doComment = presenceFlag(args, "--add-comment");
        String comment  = Optional.ofNullable(findArg(args, "--comment")).orElse("interop-comment");
        long   toMs     = parseLongArg(args, "--timeout-ms", 15000L);
        double piMs     = parseDoubleArg(args, "--publishing-interval-ms", 200.0);
        long   cto      = connectTimeoutMs(args);
        long   rto      = requestTimeoutMs(args);
        long   dto      = disconnectTimeoutMs(args);
        if (!nodeStr.startsWith("nsu=")) {
            NodeIdParser.parse(nodeStr);
        } else if (nodeStr.indexOf(';', 4) < 0) {
            throw new NodeIdParser.InvalidNodeIdException("malformed nsu= NodeId (missing ';'): " + nodeStr);
        }

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);
            long deadline = System.currentTimeMillis() + toMs;
            EventFilter filter = new EventFilter(alarmSelectClauses(), new ContentFilter(new ContentFilterElement[0]));
            ExtensionObject filterEO = ExtensionObject.encode(client.getStaticEncodingContext(), filter);

            // keep-alives well inside the request timeout, so no Publish times out locally
            long keepAlive = Math.max(1, Math.min(20, (long) (rto / 2 / Math.max(piMs, 1))));
            CreateSubscriptionResponse csResp = (CreateSubscriptionResponse) client.sendRequest(
                new CreateSubscriptionRequest(newRequestHeader(client, rto), piMs,
                    uint(Math.max(keepAlive * 10, 30)), uint(keepAlive), uint(0), true, ubyte(0)));
            StatusCode csStatus = csResp.getResponseHeader().getServiceResult();
            if (!csStatus.isGood()) {
                System.out.println(new ResultBuilder("alarms").success(false).serviceResult(csStatus)
                    .error("service", "CreateSubscription failed").toJson());
                return 4;
            }
            UInteger subId = csResp.getSubscriptionId();

            MonitoredItemCreateRequest monReq = new MonitoredItemCreateRequest(
                new ReadValueId(nodeId, AttributeId.EventNotifier.uid(), null, QualifiedName.NULL_VALUE),
                MonitoringMode.Reporting,
                new MonitoringParameters(uint(1), 0.0, filterEO, uint(1000), true));
            CreateMonitoredItemsResponse cmResp = (CreateMonitoredItemsResponse) client.sendRequest(
                new CreateMonitoredItemsRequest(newRequestHeader(client, rto), subId, TimestampsToReturn.Both,
                    new MonitoredItemCreateRequest[]{monReq}));
            StatusCode monSc = cmResp.getResponseHeader().getServiceResult();
            if (cmResp.getResults() != null && cmResp.getResults().length > 0) {
                monSc = cmResp.getResults()[0].getStatusCode();
            }

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("nodeId", ResultBuilder.nodeIdToString(nodeId));
            item.put("subscriptionId", subId.longValue());
            item.put("monitoredItemStatusCode", ResultBuilder.statusCodeJson(monSc));
            Map<String, Object> refresh = new LinkedHashMap<>();
            refresh.put("statusCode", ResultBuilder.statusCodeJson(monSc));
            refresh.put("startSeen", false);
            refresh.put("endSeen", false);
            item.put("refresh", refresh);
            item.put("conditions", new ArrayList<>());
            item.put("target", null);
            item.put("acknowledge", null);
            item.put("confirm", null);
            item.put("addComment", null);
            ResultBuilder rb = new ResultBuilder("alarms").addResult(item);
            int rc = alarmsRun(client, rto, deadline, subId, monSc, condName,
                new boolean[]{doAck, doConfirm, doComment}, comment, item, refresh, rb);
            try {
                client.sendRequest(new DeleteSubscriptionsRequest(newRequestHeader(client, dto),
                    new UInteger[]{subId}));
            } catch (Exception ignored) {}
            System.out.println(rb.toJson());
            return rc;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    private static int alarmsRun(OpcUaClient client, long rto, long deadline, UInteger subId, StatusCode monSc,
            String condName, boolean[] wanted, String comment,
            Map<String, Object> item, Map<String, Object> refresh, ResultBuilder rb) throws Exception {
        if (!monSc.isGood()) {
            rb.success(false).serviceResult(monSc)
                .error("service", "CreateMonitoredItems rejected the event monitored item");
            return 4;
        }
        AlarmEvents ev = new AlarmEvents(client, rto, deadline);

        // ConditionRefresh (Part 9 §5.5.7) on ConditionType; notifications that
        // arrive meanwhile are queued by the server and come with the next Publish.
        int idx = ev.entries.size();
        StatusCode refreshSc = callStatus(client, new NodeId(0, uint(2782)), new NodeId(0, uint(3875)),
            new Variant[]{new Variant(subId)});
        refresh.put("statusCode", ResultBuilder.statusCodeJson(refreshSc));
        if (!refreshSc.isGood()) {
            rb.success(false).serviceResult(refreshSc).error("service", "ConditionRefresh failed");
            return 4;
        }
        Map<String, Map<String, Object>> conditions = new LinkedHashMap<>();
        boolean end = false;
        while (!end) {
            while (idx < ev.entries.size() && !end) {
                Variant[] f = ev.fields.get(idx);
                Map<String, Object> e = ev.entries.get(idx);
                idx++;
                Object et = alarmField(f, 1);
                if (REFRESH_START_EVENT.equals(et)) {
                    refresh.put("startSeen", true);
                } else if (REFRESH_END_EVENT.equals(et)) {
                    end = true;
                } else if (e.get("conditionId") != null) {
                    conditions.put((String) e.get("conditionId"), e);
                }
            }
            if (!end && !ev.pump()) break;
        }
        refresh.put("endSeen", end);
        List<Map<String, Object>> conds = new ArrayList<>(conditions.values());
        item.put("conditions", conds);
        if (!end) {
            rb.success(false).serviceResult(BAD_TIMEOUT).error("timeout", "timeout waiting for the RefreshEndEvent");
            return 7;
        }

        Map<String, Object> target = null;
        for (Map<String, Object> e : conds) {
            boolean match = condName != null ? condName.equals(e.get("conditionName"))
                                             : Boolean.TRUE.equals(e.get("retain"));
            if (match) { target = e; break; }
        }
        item.put("target", target);
        if (target == null) {
            if (wanted[0] || wanted[1] || wanted[2]) {
                rb.success(false).serviceResult(BAD_NODEID_UNKNOWN)
                    .error("service", "no matching condition in the ConditionRefresh");
                return 4;
            }
            return 0;
        }

        String cidStr = (String) target.get("conditionId");
        NodeId cid = NodeIdParser.parse(cidStr);
        Variant ltV = new Variant(new LocalizedText("en", comment));
        String[] keys = {"acknowledge", "confirm", "addComment"};
        int[] methods = {9111, 9113, 9029};
        for (int a = 0; a < keys.length; a++) {
            if (!wanted[a]) continue;
            String key = keys[a];
            NodeId method = new NodeId(0, uint(methods[a]));
            Map<String, Object> latest = ev.latest.getOrDefault(cidStr, target);
            String eidB64 = (String) latest.get("eventId");
            ByteString eid = eidB64 != null ? ByteString.of(Base64.getDecoder().decode(eidB64)) : ByteString.NULL_VALUE;
            Variant[] in = {new Variant(eid), ltV};
            int mark = ev.entries.size();
            StatusCode sc = callStatus(client, cid, method, in);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("statusCode", ResultBuilder.statusCodeJson(sc));
            out.put("event", null);
            if (a == 0) out.put("repeatStatusCode", null);
            item.put(key, out);
            if (!sc.isGood()) {
                rb.success(false).serviceResult(sc).error("service", key + " failed");
                return 4;
            }
            final int ai = a;
            Map<String, Object> got = ev.waitFor(mark, e -> cidStr.equals(e.get("conditionId")) && (
                ai == 0 ? Boolean.TRUE.equals(e.get("acked"))
                : ai == 1 ? Boolean.TRUE.equals(e.get("confirmed"))
                : comment.equals(e.get("comment"))));
            out.put("event", got);
            if (a == 0) {
                // the same, now stale EventId again (BadConditionBranchAlreadyAcked / BadEventIdUnknown)
                out.put("repeatStatusCode", ResultBuilder.statusCodeJson(callStatus(client, cid, method, in)));
            }
            if (got == null) {
                rb.success(false).serviceResult(BAD_TIMEOUT).error("timeout", "timeout waiting for the " + key + " event");
                return 7;
            }
        }
        return 0;
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
                .error("input", "missing --endpoint, --node, --start, or --end"
                    + " [--scenario continue]").toJson());
            return 2;
        }
        long   cto         = connectTimeoutMs(args);
        long   rto         = requestTimeoutMs(args);
        long   dto         = disconnectTimeoutMs(args);
        int    numValues   = parseIntArg(args, "--num-values", 0);
        String cpStr       = findArg(args, "--continuation-point");
        boolean releaseCp  = hasFlagValue(args, "--release-continuation-point", "true");
        boolean retBounds  = hasFlagValue(args, "--return-bounds", "true");
        String scenario    = findArg(args, "--scenario");
        TimestampsToReturn ts = parseTimestamps(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId nodeId = NodeIdParser.resolveWithClient(nodeStr, client, rto);
            DateTime startTime = instantToDateTime(Instant.parse(startStr));
            DateTime endTime   = instantToDateTime(Instant.parse(endStr));

            if ("continue".equals(scenario)) {
                return historyReadContinueScenario(
                    client, rto, nodeId, startTime, endTime, numValues, retBounds, ts);
            }

            HistoryPage page = historyReadOnce(
                client, rto, nodeId, startTime, endTime, numValues, retBounds, ts,
                cpStr, releaseCp);

            Map<String, Object> resultItem = new LinkedHashMap<>();
            resultItem.put("nodeId",            ResultBuilder.nodeIdToString(nodeId));
            resultItem.put("statusCode",        ResultBuilder.statusCodeJson(page.itemSc));
            resultItem.put("continuationPoint", page.cpOut);
            resultItem.put("values",            page.values);

            boolean ok = page.svcSc.isGood() && page.itemSc.isGood();
            StatusCode emitSc = page.svcSc.isGood() ? page.itemSc : page.svcSc;
            System.out.println(new ResultBuilder("history-read")
                .success(ok).serviceResult(emitSc).addResult(resultItem).toJson());
            return ok ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    private static final class HistoryPage {
        final StatusCode svcSc;
        final StatusCode itemSc;
        final String cpOut;
        final List<Map<String, Object>> values;
        HistoryPage(StatusCode svcSc, StatusCode itemSc, String cpOut,
                    List<Map<String, Object>> values) {
            this.svcSc = svcSc; this.itemSc = itemSc; this.cpOut = cpOut; this.values = values;
        }
    }

    private static HistoryPage historyReadOnce(
            OpcUaClient client, long rto, NodeId nodeId,
            DateTime startTime, DateTime endTime, int numValues, boolean retBounds,
            TimestampsToReturn ts, String cpStr, boolean releaseCp) throws Exception {

        ReadRawModifiedDetails readDetails = new ReadRawModifiedDetails(
            false, startTime, endTime, UInteger.valueOf(Math.max(0, numValues)), retBounds);
        ExtensionObject histDetails = ExtensionObject.encode(
            client.getStaticEncodingContext(), readDetails);

        ByteString continuationPoint = (cpStr != null && !cpStr.isEmpty())
            ? ByteString.of(java.util.Base64.getDecoder().decode(cpStr))
            : ByteString.NULL_VALUE;

        HistoryReadValueId hvId = new HistoryReadValueId(
            nodeId, null, QualifiedName.NULL_VALUE, continuationPoint);

        HistoryReadResponse resp = (HistoryReadResponse) client.sendRequest(
            new HistoryReadRequest(
                newRequestHeader(client, rto), histDetails, ts, releaseCp,
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
            if (histDataEO != null && !histDataEO.isNull()) {
                try {
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
                                    dv.getStatusCode() != null ? dv.getStatusCode() : StatusCode.GOOD));
                                if (dv.getSourceTime() != null && dv.getSourceTime().getJavaTime() != 0) {
                                    v.put("sourceTimestamp",
                                        dv.getSourceTime().getJavaInstant().toString());
                                }
                                if (dv.getServerTime() != null && dv.getServerTime().getJavaTime() != 0) {
                                    v.put("serverTimestamp",
                                        dv.getServerTime().getJavaInstant().toString());
                                }
                                valuesList.add(v);
                            }
                        }
                    }
                } catch (RuntimeException decodeEx) {
                    // Release / empty pages may carry a null-typed ExtensionObject (i=0).
                    LOG.debug("HistoryData decode skipped: {}", decodeEx.getMessage());
                }
            }
        }
        return new HistoryPage(svcSc, itemSc, cpOut, valuesList);
    }

    /**
     * Single-session page → continue → release → reuse-after-release baseline
     * for history.read.continuation peer evidence.
     */
    private static int historyReadContinueScenario(
            OpcUaClient client, long rto, NodeId nodeId,
            DateTime startTime, DateTime endTime, int numValues, boolean retBounds,
            TimestampsToReturn ts) throws Exception {

        if (numValues <= 0) numValues = 2;

        List<Map<String, Object>> pages = new ArrayList<>();
        String cp = null;
        StatusCode lastItem = StatusCode.GOOD;
        StatusCode lastSvc = StatusCode.GOOD;

        // First page + follow continuation until cleared (cap pages for safety).
        for (int i = 0; i < 8; i++) {
            HistoryPage page = historyReadOnce(
                client, rto, nodeId, startTime, endTime, numValues, retBounds, ts,
                cp, false);
            lastSvc = page.svcSc;
            lastItem = page.itemSc;
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("values", page.values);
            p.put("continuationPoint", page.cpOut);
            p.put("statusCode", ResultBuilder.statusCodeJson(page.itemSc));
            pages.add(p);
            if (!page.svcSc.isGood() || !page.itemSc.isGood()) break;
            if (page.cpOut == null || page.cpOut.isEmpty()) break;
            cp = page.cpOut;
        }

        StatusCode releaseSc = StatusCode.GOOD;
        StatusCode reuseSc = StatusCode.GOOD;
        if (cp != null && !cp.isEmpty()) {
            HistoryPage released = historyReadOnce(
                client, rto, nodeId, startTime, endTime, numValues, retBounds, ts,
                cp, true);
            releaseSc = released.svcSc.isGood() ? released.itemSc : released.svcSc;

            HistoryPage reuse = historyReadOnce(
                client, rto, nodeId, startTime, endTime, numValues, retBounds, ts,
                cp, false);
            reuseSc = reuse.svcSc.isGood() ? reuse.itemSc : reuse.svcSc;
        } else if (!pages.isEmpty()) {
            // Final page already cleared CP; release of empty CP should still be Good/no-op.
            HistoryPage released = historyReadOnce(
                client, rto, nodeId, startTime, endTime, numValues, retBounds, ts,
                null, true);
            releaseSc = released.svcSc.isGood() ? released.itemSc : released.svcSc;
            // Reuse of a cleared/empty CP: attempt with last non-null CP from earlier pages.
            String lastCp = null;
            for (int i = pages.size() - 1; i >= 0; i--) {
                Object v = pages.get(i).get("continuationPoint");
                if (v instanceof String && !((String) v).isEmpty()) { lastCp = (String) v; break; }
            }
            if (lastCp != null) {
                HistoryPage reuse = historyReadOnce(
                    client, rto, nodeId, startTime, endTime, numValues, retBounds, ts,
                    lastCp, false);
                reuseSc = reuse.svcSc.isGood() ? reuse.itemSc : reuse.svcSc;
            }
        }

        Map<String, Object> resultItem = new LinkedHashMap<>();
        resultItem.put("scenario", "continue");
        resultItem.put("nodeId", ResultBuilder.nodeIdToString(nodeId));
        resultItem.put("pages", pages);
        resultItem.put("releaseStatusCode", ResultBuilder.statusCodeJson(releaseSc));
        resultItem.put("reuseAfterReleaseStatusCode", ResultBuilder.statusCodeJson(reuseSc));

        boolean ok = lastSvc.isGood() && lastItem.isGood() && !pages.isEmpty();
        System.out.println(new ResultBuilder("history-read")
            .success(ok).serviceResult(lastSvc.isGood() ? lastItem : lastSvc)
            .addResult(resultItem).toJson());
        return ok ? 0 : 4;
    }

    private static ContentFilter buildEventWhereClause(
            OpcUaClient client, String ofTypeStr, String minSevStr) throws Exception {
        List<ContentFilterElement> elements = new ArrayList<>();
        var enc = client.getStaticEncodingContext();

        if (ofTypeStr != null && !ofTypeStr.isEmpty()) {
            NodeId typeId = NodeIdParser.resolveWithClient(ofTypeStr, client, 5000);
            LiteralOperand lit = new LiteralOperand(new Variant(typeId));
            elements.add(new ContentFilterElement(
                FilterOperator.OfType,
                new ExtensionObject[]{ ExtensionObject.encode(enc, lit) }));
        }
        if (minSevStr != null && !minSevStr.isEmpty()) {
            int minSev = Integer.parseInt(minSevStr);
            SimpleAttributeOperand sevOp = new SimpleAttributeOperand(
                Identifiers.BaseEventType,
                new QualifiedName[]{ new QualifiedName(0, "Severity") },
                AttributeId.Value.uid(),
                null);
            LiteralOperand lit = new LiteralOperand(new Variant(ushort(minSev)));
            elements.add(new ContentFilterElement(
                FilterOperator.GreaterThanOrEqual,
                new ExtensionObject[]{
                    ExtensionObject.encode(enc, sevOp),
                    ExtensionObject.encode(enc, lit)
                }));
        }
        if (elements.size() == 2) {
            ElementOperand a = new ElementOperand(uint(0));
            ElementOperand b = new ElementOperand(uint(1));
            elements.add(new ContentFilterElement(
                FilterOperator.And,
                new ExtensionObject[]{
                    ExtensionObject.encode(enc, a),
                    ExtensionObject.encode(enc, b)
                }));
        }
        return new ContentFilter(elements.toArray(new ContentFilterElement[0]));
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
    static OpcUaClient connectClient(String endpointUrl,
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

        // Short requested lifetimes force SecurityToken renewals during the
        // command (Milo renews at 75% of the revised lifetime).
        final long channelLifetimeMs = args != null ? parseLongArg(args, "--channel-lifetime-ms", 0) : 0;
        OpcUaClient client = OpcUaClient.create(cfgBuilder.build(), transport -> {
            if (channelLifetimeMs > 0) {
                transport.setChannelLifetime(UInteger.valueOf(channelLifetimeMs));
            }
        });
        client.connect();
        return client;
    }

    // -------------------------------------------------------------------------
    // find-servers-on-network (FindServersOnNetwork against an LDS-ME)
    // -------------------------------------------------------------------------

    private static int cmdFindServersOnNetwork(String[] args) throws Exception {
        final String op = "find-servers-on-network";
        String endpointUrl = findArg(args, "--endpoint");
        if (endpointUrl == null) {
            System.out.println(new ResultBuilder(op).error("input", "missing --endpoint").toJson());
            return 2;
        }
        long rto = requestTimeoutMs(args);
        long start = parseLongArg(args, "--starting-record-id", 0);
        long max   = parseLongArg(args, "--max-records", 0);
        String[] caps = findAllArgs(args, "--capability").toArray(new String[0]);

        Object resp;
        try (DiscoveryOps.Channel ch = DiscoveryOps.open(endpointUrl, connectTimeoutMs(args))) {
            resp = DiscoveryOps.findServersOnNetwork(ch, start, max, caps, rto);
        }
        if (resp instanceof StatusCode sc) {
            System.out.println(new ResultBuilder(op).serviceResult(sc)
                .error("service", "FindServersOnNetwork failed").toJson());
            return 4;
        }
        FindServersOnNetworkResponse r = (FindServersOnNetworkResponse) resp;
        StatusCode sc = r.getResponseHeader().getServiceResult();
        if (sc != null && !sc.isGood()) {
            System.out.println(new ResultBuilder(op).serviceResult(sc)
                .error("service", "FindServersOnNetwork failed").toJson());
            return 4;
        }
        ResultBuilder rb = new ResultBuilder(op);
        String reset = r.getLastCounterResetTime() != null && r.getLastCounterResetTime().getUtcTime() != 0
            ? r.getLastCounterResetTime().getJavaInstant().toString() : null;
        if (r.getServers() != null) {
            for (ServerOnNetwork son : r.getServers()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("recordId", son.getRecordId().longValue());
                m.put("serverName", son.getServerName() != null ? son.getServerName() : "");
                m.put("discoveryUrl", son.getDiscoveryUrl() != null ? son.getDiscoveryUrl() : "");
                m.put("serverCapabilities", son.getServerCapabilities() != null
                    ? Arrays.asList(son.getServerCapabilities()) : List.of());
                if (reset != null) m.put("lastCounterResetTime", reset);
                rb.addResult(m);
            }
        }
        System.out.println(rb.toJson());
        return 0;
    }

    // -------------------------------------------------------------------------
    // register-server (RegisterServer2 with fallback to RegisterServer)
    // -------------------------------------------------------------------------

    private static int cmdRegisterServer(String[] args) throws Exception {
        final String op = "register-server";
        String endpointUrl = findArg(args, "--endpoint");
        String serverUri   = findArg(args, "--server-uri");
        List<String> urls  = findAllArgs(args, "--discovery-url");
        if (endpointUrl == null || serverUri == null || urls.isEmpty()) {
            System.out.println(new ResultBuilder(op).error("input",
                "usage: register-server --endpoint <lds-url> --server-uri <uri>"
                + " --discovery-url <url> [--discovery-url ...] [--server-name <text>]"
                + " [--product-uri <uri>] [--server-type Server|Client|ClientAndServer|DiscoveryServer]"
                + " [--online true|false] [--service auto|RegisterServer2|RegisterServer]"
                + " [--mdns-name <name>] [--capability <cap> ...]").toJson());
            return 2;
        }
        String name       = findArg(args, "--server-name");
        String nameLocale = findArg(args, "--server-name-locale");
        String productUri = findArg(args, "--product-uri");
        String service    = findArg(args, "--service");
        String mdnsName   = findArg(args, "--mdns-name");
        String typeStr    = findArg(args, "--server-type");
        if (name == null) name = serverUri;
        if (nameLocale == null) nameLocale = "en";
        if (service == null) service = "auto";
        if (typeStr == null) typeStr = "Server";
        org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType appType;
        try {
            appType = org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType.valueOf(typeStr);
        } catch (IllegalArgumentException e) {
            throw new InputException("invalid --service or --server-type");
        }
        if (!List.of("auto", "RegisterServer2", "RegisterServer").contains(service)) {
            throw new InputException("invalid --service or --server-type");
        }
        boolean online = !hasFlagValue(args, "--online", "false");
        String[] caps = findAllArgs(args, "--capability").toArray(new String[0]);

        RegisteredServer rs = new RegisteredServer(
            serverUri, productUri != null ? productUri : "",
            new LocalizedText[] {new LocalizedText(nameLocale, name)},
            appType, findArg(args, "--gateway-server-uri"),
            urls.toArray(new String[0]), findArg(args, "--semaphore-file"), online);

        DiscoveryOps.RegisterResult res;
        try (DiscoveryOps.Channel ch = DiscoveryOps.open(endpointUrl, connectTimeoutMs(args))) {
            res = DiscoveryOps.register(ch, rs, mdnsName != null ? mdnsName : name, caps,
                                        service, requestTimeoutMs(args));
        }

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("service", res.service);
        m.put("serverUri", serverUri);
        m.put("isOnline", online);
        m.put("statusCode", ResultBuilder.statusCodeJson(res.status));
        m.put("fallback", res.fallback);
        if (res.registerServer2Status != null) {
            m.put("registerServer2StatusCode", ResultBuilder.statusCodeJson(res.registerServer2Status));
        }
        List<Object> cfg = new ArrayList<>();
        for (StatusCode c : res.configurationResults) {
            cfg.add(ResultBuilder.statusCodeJson(c != null ? c : StatusCode.GOOD));
        }
        m.put("configurationResults", cfg);

        ResultBuilder rb = new ResultBuilder(op).serviceResult(res.status).addResult(m);
        if (!res.ok()) rb.error("service", res.service + " failed");
        System.out.println(rb.toJson());
        return res.ok() ? 0 : 4;
    }

    // -------------------------------------------------------------------------
    // register-nodes: RegisterNodes -> Read via registered alias -> UnregisterNodes
    // -------------------------------------------------------------------------

    private static int cmdRegisterNodes(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        List<String> nodeStrs = findAllArgs(args, "--node");
        if (endpointUrl == null || nodeStrs.isEmpty()) {
            System.out.println(new ResultBuilder("register-nodes")
                    .error("input", "missing --endpoint or --node").toJson());
            return 2;
        }
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            List<NodeId> nodeIds = new ArrayList<>();
            for (String ns : nodeStrs) {
                nodeIds.add(NodeIdParser.resolveWithClient(ns, client, rto));
            }

            RegisterNodesResponse regResp = client.registerNodes(nodeIds);
            NodeId[] registered = regResp.getRegisteredNodeIds();
            if (registered == null || registered.length != nodeIds.size()) {
                System.out.println(new ResultBuilder("register-nodes").success(false)
                        .serviceResult(new StatusCode(0x80010000L))
                        .error("service", "RegisterNodes returned an unexpected number of ids").toJson());
                return 4;
            }

            List<ReadValueId> readIds = new ArrayList<>();
            for (NodeId r : registered) {
                readIds.add(new ReadValueId(r, AttributeId.Value.uid(), null, null));
            }
            DataValue[] dvs = client.read(0.0, TimestampsToReturn.Source, readIds).getResults();

            UnregisterNodesResponse unregResp = client.unregisterNodes(Arrays.asList(registered));
            StatusCode unregSc = unregResp.getResponseHeader().getServiceResult();

            ResultBuilder rb = new ResultBuilder("register-nodes");
            boolean anyBad = !unregSc.isGood();
            StatusCode firstBad = unregSc.isGood() ? null : unregSc;
            for (int i = 0; i < nodeIds.size(); i++) {
                DataValue dv = dvs[i];
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("nodeId",           ResultBuilder.nodeIdToString(nodeIds.get(i)));
                result.put("registeredNodeId", ResultBuilder.nodeIdToString(registered[i]));
                result.put("statusCode",       ResultBuilder.statusCodeJson(dv.getStatusCode()));
                if (dv.getStatusCode().isGood()) {
                    String typeName = ResultBuilder.builtInTypeName(dv.getValue());
                    result.put("dataType",    typeName);
                    result.put("builtInType", ResultBuilder.builtInTypeId(typeName));
                    result.put("value",       ResultBuilder.encodeVariantValue(dv.getValue()));
                } else {
                    anyBad = true;
                    if (firstBad == null) firstBad = dv.getStatusCode();
                }
                result.put("unregisterStatusCode", ResultBuilder.statusCodeJson(unregSc));
                rb.addResult(result);
            }
            if (firstBad != null) rb.serviceResult(firstBad);
            if (anyBad) rb.success(false);
            System.out.println(rb.toJson());
            return anyBad ? 4 : 0;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    // -------------------------------------------------------------------------
    // node-management: AddNodes (Int32 Variable) -> Read -> DeleteNodes -> Read
    // -------------------------------------------------------------------------

    private static int cmdNodeManagement(String[] args) throws Exception {
        String endpointUrl = findArg(args, "--endpoint");
        String parentStr   = findArg(args, "--parent");
        String nodeStr     = findArg(args, "--node");
        String browseName  = findArg(args, "--browse-name");
        if (endpointUrl == null || parentStr == null || nodeStr == null) {
            System.out.println(new ResultBuilder("node-management")
                    .error("input", "missing --endpoint, --parent or --node").toJson());
            return 2;
        }
        if (browseName == null) browseName = "InteropAdded";
        int value = parseIntArg(args, "--value", 42);
        long cto = connectTimeoutMs(args);
        long rto = requestTimeoutMs(args);
        long dto = disconnectTimeoutMs(args);

        OpcUaClient client = connectClient(endpointUrl, cto, rto, args);
        try {
            NodeId parentId = NodeIdParser.resolveWithClient(parentStr, client, rto);
            NodeId newId    = NodeIdParser.resolveWithClient(nodeStr, client, rto);

            // AccessLevel | DataType | DisplayName | UserAccessLevel | ValueRank | Value
            UInteger specified = uint(1 | 16 | 64 | 65536 | 524288 | 2097152);
            VariableAttributes attrs = new VariableAttributes(
                    specified,
                    LocalizedText.english(browseName),
                    LocalizedText.NULL_VALUE,
                    uint(0), uint(0),
                    new Variant(value),
                    Identifiers.Int32,
                    -1,
                    null,
                    ubyte(3), ubyte(3),
                    0.0,
                    false);

            AddNodesItem item = new AddNodesItem(
                    parentId.expanded(),
                    Identifiers.HasComponent,
                    newId.expanded(),
                    new QualifiedName(newId.getNamespaceIndex(), browseName),
                    org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass.Variable,
                    ExtensionObject.encode(client.getStaticEncodingContext(), attrs),
                    Identifiers.BaseDataVariableType.expanded());

            AddNodesResult[] addResults = client.addNodes(List.of(item)).getResults();
            StatusCode addSc = (addResults != null && addResults.length == 1)
                    ? addResults[0].getStatusCode() : new StatusCode(0x80010000L);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("parentNodeId",    ResultBuilder.nodeIdToString(parentId));
            result.put("requestedNodeId", ResultBuilder.nodeIdToString(newId));
            result.put("addStatusCode",   ResultBuilder.statusCodeJson(addSc));

            boolean ok = false;
            StatusCode emit = addSc;
            if (addSc.isGood()) {
                NodeId added = addResults[0].getAddedNodeId();
                result.put("addedNodeId", ResultBuilder.nodeIdToString(added));

                List<ReadValueId> rid = List.of(new ReadValueId(added, AttributeId.Value.uid(), null, null));
                DataValue dv = client.read(0.0, TimestampsToReturn.Source, rid).getResults()[0];
                result.put("readStatusCode", ResultBuilder.statusCodeJson(dv.getStatusCode()));
                boolean valueMatches = false;
                if (dv.getStatusCode().isGood()) {
                    String typeName = ResultBuilder.builtInTypeName(dv.getValue());
                    result.put("dataType",    typeName);
                    result.put("builtInType", ResultBuilder.builtInTypeId(typeName));
                    result.put("value",       ResultBuilder.encodeVariantValue(dv.getValue()));
                    Object v = dv.getValue().getValue();
                    valueMatches = (v instanceof Integer) && ((Integer) v) == value;
                }

                StatusCode[] delResults = client.deleteNodes(
                        List.of(new DeleteNodesItem(added, true))).getResults();
                StatusCode delSc = (delResults != null && delResults.length == 1)
                        ? delResults[0] : new StatusCode(0x80010000L);
                result.put("deleteStatusCode", ResultBuilder.statusCodeJson(delSc));

                DataValue gone = client.read(0.0, TimestampsToReturn.Source, rid).getResults()[0];
                result.put("readAfterDeleteStatusCode", ResultBuilder.statusCodeJson(gone.getStatusCode()));

                ok = dv.getStatusCode().isGood() && valueMatches && delSc.isGood()
                        && gone.getStatusCode().isBad();
                if (!dv.getStatusCode().isGood()) emit = dv.getStatusCode();
                else if (!delSc.isGood()) emit = delSc;
            }

            ResultBuilder rb = new ResultBuilder("node-management");
            rb.addResult(result);
            rb.serviceResult(emit);
            if (!ok) rb.success(false);
            System.out.println(rb.toJson());
            return ok ? 0 : 4;
        } finally {
            safeDisconnect(client, dto);
        }
    }

    static void safeDisconnect(OpcUaClient client, long timeoutMs) {
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
            default:
                // Every other built-in type and Type[] array: shared literal grammar.
                if (ValueParser.supports(typeStr)) return ValueParser.parse(typeStr, val, null);
                return new Variant(val);
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

    static String findArg(String[] args, String flag) {
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) return args[i + 1];
        }
        return null;
    }

    static List<String> findAllArgs(String[] args, String flag) {
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

    static long connectTimeoutMs(String[] args)    { return parseLongArg(args, "--connect-timeout",    5) * 1000; }
    static long requestTimeoutMs(String[] args)    { return parseLongArg(args, "--request-timeout",    5) * 1000; }
    static long disconnectTimeoutMs(String[] args) { return parseLongArg(args, "--disconnect-timeout", 2) * 1000; }

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
