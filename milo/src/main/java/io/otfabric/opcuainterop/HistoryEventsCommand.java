package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.FilterOperator;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PerformUpdateType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.*;

import java.time.Instant;
import java.util.*;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;

/**
 * client history-read-events / history-update-events (docs/CLIENT_CONTRACT.md):
 * HistoryRead with ReadEventDetails, HistoryUpdate with UpdateEventDetails /
 * DeleteEventDetails, sent as generic services (Milo 1.1.8 has no event
 * history helpers on its client).
 */
final class HistoryEventsCommand {

    private HistoryEventsCommand() {}

    static final List<String> DEFAULT_SELECT = List.of(
        "EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Resolves a NodeId string (nsu= needs the session's namespace table). */
    interface Resolver {
        NodeId resolve(String s) throws Exception;
    }

    // ── shared builders (unit-tested) ────────────────────────────────────────

    /** `A/B` → [A, B]; a segment `ns:Name` is a QualifiedName in namespace ns. */
    static QualifiedName[] browsePath(String path) throws ClientCommand.InputException {
        if (path == null || path.isEmpty()) throw new ClientCommand.InputException("empty --select path");
        String[] segs = path.split("/", -1);
        QualifiedName[] out = new QualifiedName[segs.length];
        for (int i = 0; i < segs.length; i++) {
            String s = segs[i];
            if (s.isEmpty()) throw new ClientCommand.InputException("empty segment in --select path '" + path + "'");
            int colon = s.indexOf(':');
            if (colon > 0 && s.substring(0, colon).chars().allMatch(Character::isDigit)) {
                int ns;
                try {
                    ns = Integer.parseInt(s.substring(0, colon));
                } catch (NumberFormatException e) {
                    throw new ClientCommand.InputException("bad namespace in --select path '" + path + "'");
                }
                if (ns > 65535) throw new ClientCommand.InputException("bad namespace in --select path '" + path + "'");
                out[i] = new QualifiedName(ns, s.substring(colon + 1));
            } else {
                out[i] = new QualifiedName(0, s);
            }
        }
        return out;
    }

    static SimpleAttributeOperand[] selectClauses(List<String> paths) throws ClientCommand.InputException {
        SimpleAttributeOperand[] out = new SimpleAttributeOperand[paths.size()];
        for (int i = 0; i < paths.size(); i++) {
            out[i] = new SimpleAttributeOperand(
                Identifiers.BaseEventType, browsePath(paths.get(i)), AttributeId.Value.uid(), null);
        }
        return out;
    }

    /**
     * WhereClause: OfType and/or Severity ≥ n. With both, element 0 is the
     * root And over elements 1 and 2 (Part 4 §7.7.1); none → empty filter.
     */
    static ContentFilter whereClause(EncodingContext enc, NodeId ofType, Integer minSeverity) {
        List<ContentFilterElement> leaves = new ArrayList<>();
        if (ofType != null) {
            leaves.add(new ContentFilterElement(FilterOperator.OfType,
                new ExtensionObject[]{ ExtensionObject.encode(enc, new LiteralOperand(new Variant(ofType))) }));
        }
        if (minSeverity != null) {
            SimpleAttributeOperand sev = new SimpleAttributeOperand(Identifiers.BaseEventType,
                new QualifiedName[]{ new QualifiedName(0, "Severity") }, AttributeId.Value.uid(), null);
            leaves.add(new ContentFilterElement(FilterOperator.GreaterThanOrEqual,
                new ExtensionObject[]{
                    ExtensionObject.encode(enc, sev),
                    ExtensionObject.encode(enc, new LiteralOperand(new Variant(ushort(minSeverity))))
                }));
        }
        List<ContentFilterElement> els = new ArrayList<>();
        if (leaves.size() == 2) {
            els.add(new ContentFilterElement(FilterOperator.And, new ExtensionObject[]{
                ExtensionObject.encode(enc, new ElementOperand(uint(1))),
                ExtensionObject.encode(enc, new ElementOperand(uint(2)))
            }));
        }
        els.addAll(leaves);
        return new ContentFilter(els.toArray(new ContentFilterElement[0]));
    }

    static PerformUpdateType perform(String s) throws ClientCommand.InputException {
        if (s == null) throw new ClientCommand.InputException("missing --perform insert|replace|update|delete");
        switch (s.toLowerCase(Locale.ROOT)) {
            case "insert":  return PerformUpdateType.Insert;
            case "replace": return PerformUpdateType.Replace;
            case "update":  return PerformUpdateType.Update;
            case "delete":  return PerformUpdateType.Remove;
            default: throw new ClientCommand.InputException("--perform must be insert, replace, update or delete");
        }
    }

    static String performName(PerformUpdateType p) {
        return p == PerformUpdateType.Remove ? "Delete" : p.name();
    }

    static TimestampsToReturn timestamps(String s) throws ClientCommand.InputException {
        if (s == null) return TimestampsToReturn.Both;
        switch (s.toLowerCase(Locale.ROOT)) {
            case "source":  return TimestampsToReturn.Source;
            case "server":  return TimestampsToReturn.Server;
            case "both":    return TimestampsToReturn.Both;
            case "neither": return TimestampsToReturn.Neither;
            default: throw new ClientCommand.InputException("--timestamps must be source, server, both or neither");
        }
    }

    static List<JsonNode> parseEvents(List<String> raw) throws ClientCommand.InputException {
        List<JsonNode> out = new ArrayList<>();
        for (String r : raw) {
            JsonNode n;
            try {
                n = MAPPER.readTree(r);
            } catch (Exception e) {
                throw new ClientCommand.InputException("--event is not JSON: " + e.getMessage());
            }
            if (n == null || !n.isObject()) throw new ClientCommand.InputException("--event must be a JSON object");
            out.add(n);
        }
        return out;
    }

    /** --select, else the keys of the --event objects in first-seen order. */
    static List<String> updateSelect(List<String> select, List<JsonNode> events) {
        if (!select.isEmpty()) return select;
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        for (JsonNode e : events) e.fieldNames().forEachRemaining(keys::add);
        return new ArrayList<>(keys);
    }

    static HistoryEventFieldList eventFieldList(List<String> select, JsonNode ev, Resolver r)
            throws Exception {
        Variant[] f = new Variant[select.size()];
        for (int i = 0; i < select.size(); i++) {
            JsonNode v = ev.get(select.get(i));
            f[i] = v == null ? Variant.NULL_VALUE : eventValue(select.get(i), v, r);
        }
        return new HistoryEventFieldList(f);
    }

    /** `{"type":T,"value":V}` in §7 encoding, or a bare JSON value (String / Int32 / Double / Boolean). */
    static Variant eventValue(String key, JsonNode n, Resolver r) throws Exception {
        if (n.isNull()) return Variant.NULL_VALUE;
        if (!n.isObject() || !n.has("type")) {
            if (n.isTextual()) return new Variant(n.asText());
            if (n.isBoolean()) return new Variant(n.asBoolean());
            if (n.isIntegralNumber()) return new Variant(n.asInt());
            if (n.isNumber()) return new Variant(n.asDouble());
            throw new ClientCommand.InputException("--event " + key + ": give {\"type\":…,\"value\":…}");
        }
        String type = n.get("type").asText();
        JsonNode v = n.get("value");
        if (v == null || v.isNull()) return Variant.NULL_VALUE;
        try {
            switch (type) {
                case "ByteString":
                    return new Variant(ByteString.of(Base64.getDecoder().decode(v.asText())));
                case "DateTime":
                    return new Variant(ValueParser.parseDateTime(v.asText()));
                case "NodeId":
                    return new Variant(r.resolve(v.asText()));
                case "LocalizedText": {
                    if (v.isTextual()) return new Variant(new LocalizedText(null, v.asText()));
                    JsonNode loc = v.get("locale"), txt = v.get("text");
                    return new Variant(new LocalizedText(
                        loc == null || loc.isNull() || loc.asText().isEmpty() ? null : loc.asText(),
                        txt == null || txt.isNull() ? null : txt.asText()));
                }
                case "QualifiedName":
                    return new Variant(new QualifiedName(v.path("ns").asInt(0), v.path("name").asText()));
                case "String":
                    return new Variant(v.asText());
                default:
                    if (!ValueParser.supports(type)) {
                        throw new ClientCommand.InputException("--event " + key + ": unknown type " + type);
                    }
                    return ValueParser.parse(type, v.isTextual() ? v.asText() : v.toString(), null);
            }
        } catch (ClientCommand.InputException e) {
            throw e;
        } catch (NodeIdParser.InvalidNodeIdException | NodeIdParser.UnknownNamespaceException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new ClientCommand.InputException("--event " + key + ": " + e.getMessage());
        }
    }

    static List<Map<String, Object>> eventsJson(List<String> select, HistoryEventFieldList[] events) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (events == null) return out;
        for (HistoryEventFieldList ev : events) {
            Variant[] vs = ev.getEventFields() != null ? ev.getEventFields() : new Variant[0];
            List<Map<String, Object>> fields = new ArrayList<>();
            for (int i = 0; i < select.size(); i++) {
                Variant v = i < vs.length ? vs[i] : Variant.NULL_VALUE;
                Map<String, Object> fld = new LinkedHashMap<>();
                fld.put("name", select.get(i));
                if (v == null || v.isNull()) {
                    fld.put("dataType", "Null");
                    fld.put("builtInType", 0);
                    fld.put("value", null);
                } else {
                    String tn = ResultBuilder.builtInTypeName(v);
                    fld.put("dataType", tn);
                    fld.put("builtInType", ResultBuilder.builtInTypeId(tn));
                    fld.put("value", ResultBuilder.encodeVariantValue(v));
                }
                fields.add(fld);
            }
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("fields", fields);
            out.add(e);
        }
        return out;
    }

    // ── history-read-events ──────────────────────────────────────────────────

    private static final class Page {
        StatusCode svc = StatusCode.GOOD;
        StatusCode item = StatusCode.GOOD;
        String cp;
        List<Map<String, Object>> events = new ArrayList<>();
    }

    private static DateTime dateArg(String[] args, String flag) throws ClientCommand.InputException {
        String s = ClientCommand.findArg(args, flag);
        if (s == null) return DateTime.NULL_VALUE;
        try {
            Instant.parse(s);
            return ValueParser.parseDateTime(s);
        } catch (Exception e) {
            throw new ClientCommand.InputException("invalid " + flag + ": " + s);
        }
    }

    private static int intArg(String[] args, String flag, int def) throws ClientCommand.InputException {
        String s = ClientCommand.findArg(args, flag);
        if (s == null) return def;
        try {
            int v = Integer.parseInt(s);
            if (v < 0) throw new NumberFormatException();
            return v;
        } catch (NumberFormatException e) {
            throw new ClientCommand.InputException(flag + " must be a non-negative integer");
        }
    }

    static int cmdRead(String[] args) throws Exception {
        final String op = "history-read-events";
        String endpoint = ClientCommand.findArg(args, "--endpoint");
        List<String> nodes = ClientCommand.findAllArgs(args, "--node");
        if (endpoint == null || nodes.isEmpty()) {
            throw new ClientCommand.InputException("missing --endpoint or --node");
        }
        DateTime start = dateArg(args, "--start");
        DateTime end = dateArg(args, "--end");
        int num = intArg(args, "--num-values", 0);
        int maxPages = intArg(args, "--max-pages", 8);
        List<String> select = ClientCommand.findAllArgs(args, "--select");
        if (select.isEmpty()) select = DEFAULT_SELECT;
        SimpleAttributeOperand[] clauses = selectClauses(select);
        String ofTypeStr = ClientCommand.findArg(args, "--of-type");
        String minSevStr = ClientCommand.findArg(args, "--min-severity");
        Integer minSev = null;
        if (minSevStr != null) {
            try {
                minSev = Integer.parseInt(minSevStr);
                if (minSev < 0 || minSev > 65535) throw new NumberFormatException();
            } catch (NumberFormatException e) {
                throw new ClientCommand.InputException("--min-severity must be 0..65535");
            }
        }
        String cpStr = ClientCommand.findArg(args, "--continuation-point");
        byte[] cpIn = null;
        if (cpStr != null) {
            try {
                cpIn = Base64.getDecoder().decode(cpStr);
            } catch (IllegalArgumentException e) {
                throw new ClientCommand.InputException("--continuation-point is not Base64");
            }
        }
        boolean release = ClientCommand.presenceFlag(args, "--release-continuation-point");
        TimestampsToReturn ts = timestamps(ClientCommand.findArg(args, "--timestamps"));
        String scenario = ClientCommand.findArg(args, "--scenario");
        if (scenario != null && !scenario.equals("continue")) {
            throw new ClientCommand.InputException("unknown --scenario " + scenario);
        }
        if (ofTypeStr != null) NodeIdParser.parse(ofTypeStr.startsWith("nsu=") ? "i=0" : ofTypeStr);
        for (String n : nodes) if (!n.startsWith("nsu=")) NodeIdParser.parse(n);

        long cto = ClientCommand.connectTimeoutMs(args);
        long rto = ClientCommand.requestTimeoutMs(args);
        long dto = ClientCommand.disconnectTimeoutMs(args);
        OpcUaClient client = ClientCommand.connectClient(endpoint, cto, rto, args);
        try {
            List<NodeId> ids = new ArrayList<>();
            for (String n : nodes) ids.add(NodeIdParser.resolveWithClient(n, client, rto));
            NodeId ofType = ofTypeStr != null ? NodeIdParser.resolveWithClient(ofTypeStr, client, rto) : null;
            EncodingContext enc = client.getStaticEncodingContext();
            EventFilter filter = new EventFilter(clauses, whereClause(enc, ofType, minSev));
            ReadEventDetails details = new ReadEventDetails(uint(num), start, end, filter);
            ExtensionObject det = ExtensionObject.encode(enc, details);

            ResultBuilder rb = new ResultBuilder(op);
            boolean ok = true;
            StatusCode emit = StatusCode.GOOD;
            if ("continue".equals(scenario)) {
                if (num <= 0) {
                    num = 2;
                    det = ExtensionObject.encode(enc, new ReadEventDetails(uint(num), start, end, filter));
                }
                for (NodeId id : ids) {
                    List<Map<String, Object>> pages = new ArrayList<>();
                    String cp = null;
                    Page last = null;
                    for (int i = 0; i < Math.max(1, maxPages); i++) {
                        Page p = read(client, rto, det, ts, false, List.of(id), cp == null ? null : Base64.getDecoder().decode(cp), select).get(0);
                        last = p;
                        Map<String, Object> pm = new LinkedHashMap<>();
                        pm.put("statusCode", ResultBuilder.statusCodeJson(p.item));
                        pm.put("continuationPoint", p.cp);
                        pm.put("events", p.events);
                        pages.add(pm);
                        if (!p.svc.isGood() || !p.item.isGood() || p.cp == null) break;
                        cp = p.cp;
                    }
                    // Release the last continuation point seen, then try to reuse it.
                    String lastCp = null;
                    for (int i = pages.size() - 1; i >= 0 && lastCp == null; i--) {
                        Object v = pages.get(i).get("continuationPoint");
                        if (v instanceof String s && !s.isEmpty()) lastCp = s;
                    }
                    if (lastCp == null && cp != null) lastCp = cp;
                    StatusCode releaseSc = StatusCode.GOOD, reuseSc = StatusCode.GOOD;
                    if (lastCp != null) {
                        byte[] b = Base64.getDecoder().decode(lastCp);
                        Page rel = read(client, rto, det, ts, true, List.of(id), b, select).get(0);
                        releaseSc = rel.svc.isGood() ? rel.item : rel.svc;
                        Page re = read(client, rto, det, ts, false, List.of(id), b, select).get(0);
                        reuseSc = re.svc.isGood() ? re.item : re.svc;
                    } else {
                        Page rel = read(client, rto, det, ts, true, List.of(id), null, select).get(0);
                        releaseSc = rel.svc.isGood() ? rel.item : rel.svc;
                    }
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("scenario", "continue");
                    item.put("nodeId", ResultBuilder.nodeIdToString(id));
                    item.put("selectClauses", select);
                    item.put("pages", pages);
                    item.put("releaseStatusCode", ResultBuilder.statusCodeJson(releaseSc));
                    item.put("reuseAfterReleaseStatusCode", ResultBuilder.statusCodeJson(reuseSc));
                    rb.addResult(item);
                    StatusCode s = last.svc.isGood() ? last.item : last.svc;
                    if (!last.svc.isGood() || !last.item.isGood()) {
                        ok = false;
                        emit = s;
                    } else if (emit.isGood() && ok) {
                        emit = s;
                    }
                }
            } else {
                List<Page> res = read(client, rto, det, ts, release, ids, cpIn, select);
                for (int i = 0; i < ids.size(); i++) {
                    Page p = res.get(i);
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("nodeId", ResultBuilder.nodeIdToString(ids.get(i)));
                    item.put("statusCode", ResultBuilder.statusCodeJson(p.item));
                    item.put("continuationPoint", p.cp);
                    item.put("selectClauses", select);
                    item.put("events", p.events);
                    rb.addResult(item);
                    if (!p.svc.isGood()) {
                        ok = false;
                        emit = p.svc;
                    } else if (!p.item.isGood()) {
                        if (ok) emit = p.item;
                        ok = false;
                    } else if (ok && i == 0) {
                        emit = p.item;
                    }
                }
            }
            rb.success(ok).serviceResult(emit);
            if (!ok) rb.error("service", "HistoryRead returned a Bad status");
            System.out.println(rb.toJson());
            return ok ? 0 : 4;
        } finally {
            ClientCommand.safeDisconnect(client, dto);
        }
    }

    /** One HistoryRead for all nodes (the same continuation point for each). */
    private static List<Page> read(OpcUaClient client, long rto, ExtensionObject details, TimestampsToReturn ts,
                                   boolean release, List<NodeId> ids, byte[] cp, List<String> select)
            throws Exception {
        HistoryReadValueId[] nodes = new HistoryReadValueId[ids.size()];
        for (int i = 0; i < ids.size(); i++) {
            nodes[i] = new HistoryReadValueId(ids.get(i), null, QualifiedName.NULL_VALUE,
                cp == null ? ByteString.NULL_VALUE : ByteString.of(cp));
        }
        HistoryReadResponse resp = (HistoryReadResponse) client.sendRequest(new HistoryReadRequest(
            ClientCommand.newRequestHeader(client, rto), details, ts, release, nodes));
        StatusCode svc = resp.getResponseHeader().getServiceResult();
        List<Page> out = new ArrayList<>();
        HistoryReadResult[] rs = resp.getResults();
        for (int i = 0; i < ids.size(); i++) {
            Page p = new Page();
            p.svc = svc;
            if (svc.isGood() && rs != null && i < rs.length) {
                HistoryReadResult r = rs[i];
                p.item = r.getStatusCode() != null ? r.getStatusCode() : StatusCode.GOOD;
                ByteString c = r.getContinuationPoint();
                if (c != null && c.bytes() != null && c.bytes().length > 0) {
                    p.cp = Base64.getEncoder().encodeToString(c.bytes());
                }
                ExtensionObject hd = r.getHistoryData();
                if (hd != null && !hd.isNull()) {
                    try {
                        Object d = hd.decode(client.getStaticEncodingContext());
                        if (d instanceof HistoryEvent he) p.events = eventsJson(select, he.getEvents());
                    } catch (RuntimeException e) {
                        // A release or empty page may carry an ExtensionObject without a type.
                    }
                }
            } else if (svc.isGood()) {
                p.item = new StatusCode(org.eclipse.milo.opcua.stack.core.StatusCodes.Bad_UnexpectedError);
            }
            out.add(p);
        }
        return out;
    }

    // ── history-update-events ────────────────────────────────────────────────

    static int cmdUpdate(String[] args) throws Exception {
        final String op = "history-update-events";
        String endpoint = ClientCommand.findArg(args, "--endpoint");
        String node = ClientCommand.findArg(args, "--node");
        if (endpoint == null || node == null) throw new ClientCommand.InputException("missing --endpoint or --node");
        PerformUpdateType perform = perform(ClientCommand.findArg(args, "--perform"));
        List<JsonNode> events = parseEvents(ClientCommand.findAllArgs(args, "--event"));
        List<String> select = updateSelect(ClientCommand.findAllArgs(args, "--select"), events);
        List<byte[]> eventIds = new ArrayList<>();
        for (String s : ClientCommand.findAllArgs(args, "--event-id")) {
            try {
                eventIds.add(Base64.getDecoder().decode(s));
            } catch (IllegalArgumentException e) {
                throw new ClientCommand.InputException("--event-id is not Base64: " + s);
            }
        }
        if (perform == PerformUpdateType.Remove) {
            if (eventIds.isEmpty()) throw new ClientCommand.InputException("--perform delete needs --event-id");
        } else {
            if (events.isEmpty()) throw new ClientCommand.InputException("--perform " + performName(perform).toLowerCase(Locale.ROOT) + " needs --event");
            if (select.isEmpty()) throw new ClientCommand.InputException("no --select paths");
        }
        SimpleAttributeOperand[] clauses = selectClauses(select);
        if (!node.startsWith("nsu=")) NodeIdParser.parse(node);
        // Offline validation of the event values (nsu= NodeIds resolve after connecting).
        for (JsonNode ev : events) eventFieldList(select, ev, s -> s.startsWith("nsu=") ? NodeId.NULL_VALUE : NodeIdParser.parse(s));

        long cto = ClientCommand.connectTimeoutMs(args);
        long rto = ClientCommand.requestTimeoutMs(args);
        long dto = ClientCommand.disconnectTimeoutMs(args);
        OpcUaClient client = ClientCommand.connectClient(endpoint, cto, rto, args);
        try {
            NodeId id = NodeIdParser.resolveWithClient(node, client, rto);
            EncodingContext enc = client.getStaticEncodingContext();
            ExtensionObject det;
            if (perform == PerformUpdateType.Remove) {
                ByteString[] ids = eventIds.stream().map(ByteString::of).toArray(ByteString[]::new);
                det = ExtensionObject.encode(enc, new DeleteEventDetails(id, ids));
            } else {
                HistoryEventFieldList[] data = new HistoryEventFieldList[events.size()];
                for (int i = 0; i < events.size(); i++) {
                    data[i] = eventFieldList(select, events.get(i), s -> NodeIdParser.resolveWithClient(s, client, rto));
                }
                EventFilter filter = new EventFilter(clauses, new ContentFilter(new ContentFilterElement[0]));
                det = ExtensionObject.encode(enc, new UpdateEventDetails(id, perform, filter, data));
            }
            HistoryUpdateResponse resp = (HistoryUpdateResponse) client.sendRequest(new HistoryUpdateRequest(
                ClientCommand.newRequestHeader(client, rto), new ExtensionObject[]{ det }));
            StatusCode svc = resp.getResponseHeader().getServiceResult();
            StatusCode item = StatusCode.GOOD;
            List<Map<String, Object>> opResults = new ArrayList<>();
            HistoryUpdateResult[] rs = resp.getResults();
            if (svc.isGood()) {
                if (rs != null && rs.length > 0) {
                    item = rs[0].getStatusCode() != null ? rs[0].getStatusCode() : StatusCode.GOOD;
                    if (rs[0].getOperationResults() != null) {
                        for (StatusCode sc : rs[0].getOperationResults()) opResults.add(ResultBuilder.statusCodeJson(sc));
                    }
                } else {
                    item = new StatusCode(org.eclipse.milo.opcua.stack.core.StatusCodes.Bad_UnexpectedError);
                }
            }
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("nodeId", ResultBuilder.nodeIdToString(id));
            r.put("performUpdateType", performName(perform));
            r.put("statusCode", ResultBuilder.statusCodeJson(svc.isGood() ? item : svc));
            r.put("operationResults", opResults);
            boolean ok = svc.isGood() && item.isGood();
            ResultBuilder rb = new ResultBuilder(op).success(ok).serviceResult(svc.isGood() ? item : svc).addResult(r);
            if (!ok) rb.error("service", "HistoryUpdate returned a Bad status");
            System.out.println(rb.toJson());
            return ok ? 0 : 4;
        } finally {
            ClientCommand.safeDisconnect(client, dto);
        }
    }
}
