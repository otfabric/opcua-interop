"""`client history-read-events` / `client history-update-events`
(docs/CONTAINER_CONTRACT.md §1, §4): HistoryRead with ReadEventDetails and
HistoryUpdate with UpdateEventDetails / DeleteEventDetails (Part 11 §6.5.2,
§6.9.4, §6.9.7), built by hand: asyncua's Node.read_event_history sends no
StartTime / EndTime / NumValuesPerNode and follows continuation points itself."""

from __future__ import annotations

import base64
import json

from asyncua import ua
from asyncua.ua.uaerrors import UaStatusCodeError

from .common import (
    Args,
    InputError,
    Result,
    is_good,
    nodeid_str,
    parse_datetime,
    parse_nodeid_syntax,
    parse_scalar,
    status_json,
    variant_fields,
    _SCALAR_TYPES,
)

BASE_EVENT_TYPE = 2041
DEFAULT_SELECT = ["EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"]
PERFORM = {
    "insert": ua.PerformUpdateType.Insert,
    "replace": ua.PerformUpdateType.Replace,
    "update": ua.PerformUpdateType.Update,
    "delete": ua.PerformUpdateType.Remove,
}
PERFORM_NAME = {"insert": "Insert", "replace": "Replace", "update": "Update", "delete": "Delete"}
TIMESTAMPS = {
    "source": ua.TimestampsToReturn.Source,
    "server": ua.TimestampsToReturn.Server,
    "both": ua.TimestampsToReturn.Both,
    "neither": ua.TimestampsToReturn.Neither,
}
DEFAULT_MAX_PAGES = 8


# ── Flag → request pieces ──────────────────────────────────────────────────────


def browse_path(path: str) -> list[ua.QualifiedName]:
    """`/`-separated browse path from BaseEventType; `ns:Name` segments for other namespaces."""
    if not path or path.startswith("/") or path.endswith("/"):
        raise InputError(f"--select: malformed browse path '{path}'")
    out = []
    for seg in path.split("/"):
        if not seg:
            raise InputError(f"--select: malformed browse path '{path}'")
        ns, sep, name = seg.partition(":")
        if sep and ns.isdigit() and name:
            out.append(ua.QualifiedName(name, int(ns)))
        else:
            out.append(ua.QualifiedName(seg, 0))
    return out


def select_clause(path: str) -> ua.SimpleAttributeOperand:
    return ua.SimpleAttributeOperand(
        TypeDefinitionId=ua.NodeId(BASE_EVENT_TYPE),
        BrowsePath=browse_path(path),
        AttributeId=ua.AttributeIds.Value,
    )


def where_clause(of_type: ua.NodeId | None, min_severity: int | None) -> ua.ContentFilter:
    """OfType and/or Severity ≥ n; with both, element 0 (the root, Part 4
    §7.7.1) is And(1, 2)."""
    elements = []
    if of_type is not None:
        elements.append(ua.ContentFilterElement(
            FilterOperator=ua.FilterOperator.OfType,
            FilterOperands=[ua.LiteralOperand(Value=ua.Variant(of_type, ua.VariantType.NodeId))],
        ))
    if min_severity is not None:
        elements.append(ua.ContentFilterElement(
            FilterOperator=ua.FilterOperator.GreaterThanOrEqual,
            FilterOperands=[
                select_clause("Severity"),
                ua.LiteralOperand(Value=ua.Variant(min_severity, ua.VariantType.UInt16)),
            ],
        ))
    if len(elements) == 2:
        elements.insert(0, ua.ContentFilterElement(
            FilterOperator=ua.FilterOperator.And,
            FilterOperands=[ua.ElementOperand(Index=1), ua.ElementOperand(Index=2)],
        ))
    return ua.ContentFilter(Elements=elements)


def _b64(flag: str, s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise InputError(f"{flag} is not Base64: '{s}'")


def _release_flag(args: Args) -> bool:
    """`--release-continuation-point` alone, or with true|false."""
    if not args.has("--release-continuation-point"):
        return False
    i = args.argv.index("--release-continuation-point")
    nxt = args.argv[i + 1].lower() if i + 1 < len(args.argv) else ""
    return nxt not in ("false", "0", "no")


def _timestamps(args: Args) -> ua.TimestampsToReturn:
    v = args.get("--timestamps", "both")
    if v.lower() not in TIMESTAMPS:
        raise InputError("--timestamps must be source, server, both or neither")
    return TIMESTAMPS[v.lower()]


def _event_value(path: str, spec) -> ua.Variant:
    """One `--event` member: `{"type":T,"value":V}` with V in §7 encoding, or a bare JSON value."""
    if isinstance(spec, dict) and "type" in spec:
        t, v = spec["type"], spec.get("value")
        if v is None:
            return ua.Variant(None)
        if t.endswith("[]"):
            if not isinstance(v, list):
                raise InputError(f"--event {path}: {t} needs a JSON array")
            base = t[:-2]
            return ua.Variant([_typed_scalar(path, base, x) for x in v], _vtype(path, base), is_array=True)
        return ua.Variant(_typed_scalar(path, t, v), _vtype(path, t))
    if spec is None:
        return ua.Variant(None)
    if isinstance(spec, bool):
        return ua.Variant(spec, ua.VariantType.Boolean)
    if isinstance(spec, int):
        return ua.Variant(spec, ua.VariantType.Int32)
    if isinstance(spec, float):
        return ua.Variant(spec, ua.VariantType.Double)
    if isinstance(spec, str):
        return ua.Variant(spec, ua.VariantType.String)
    if isinstance(spec, dict) and "text" in spec:
        return ua.Variant(ua.LocalizedText(spec.get("text"), spec.get("locale") or None), ua.VariantType.LocalizedText)
    raise InputError(f"--event {path}: cannot infer a type, give {{\"type\":…,\"value\":…}}")


def _vtype(path: str, t: str) -> ua.VariantType:
    if t not in _SCALAR_TYPES or t in ("Variant", "DataValue", "DiagnosticInfo"):
        raise InputError(f"--event {path}: unsupported type '{t}'")
    return _SCALAR_TYPES[t]


def _typed_scalar(path: str, t: str, v):
    _vtype(path, t)
    if t == "LocalizedText":
        if isinstance(v, dict):
            return ua.LocalizedText(v.get("text"), v.get("locale") or None)
        return ua.LocalizedText(str(v))
    if t == "QualifiedName" and isinstance(v, dict):
        return ua.QualifiedName(v.get("name"), int(v.get("ns", 0)))
    if t == "StatusCode" and isinstance(v, dict):
        return ua.StatusCode(int(v.get("code", 0)))
    if t == "Boolean" and isinstance(v, bool):
        return v
    if isinstance(v, (dict, list)):
        raise InputError(f"--event {path}: a {t} value must be a JSON scalar")
    try:
        return parse_scalar(t, v if isinstance(v, str) else json.dumps(v))
    except InputError as e:
        raise InputError(f"--event {path}: {e}")


def parse_events(raw: list[str]) -> list[dict]:
    out = []
    for s in raw:
        try:
            obj = json.loads(s)
        except ValueError as e:
            raise InputError(f"--event is not JSON: {e}")
        if not isinstance(obj, dict):
            raise InputError("--event must be a JSON object keyed by select path")
        out.append(obj)
    return out


def event_field_list(paths: list[str], ev: dict) -> ua.HistoryEventFieldList:
    unknown = [k for k in ev if k not in paths]
    if unknown:
        raise InputError(f"--event: {', '.join(unknown)} not in --select")
    return ua.HistoryEventFieldList(EventFields=[_event_value(p, ev[p]) if p in ev else ua.Variant(None) for p in paths])


# ── Result shapes ──────────────────────────────────────────────────────────────


def events_json(paths: list[str], data) -> list[dict]:
    events = []
    for fl in getattr(data, "Events", None) or []:
        fields = []
        vals = fl.EventFields or []
        # By index; a server that returns fewer fields gives fewer (no padding).
        for name, v in zip(paths, vals):
            f = {"name": name}
            f.update(variant_fields(v))
            fields.append(f)
        events.append({"fields": fields})
    return events


# ── history-read-events ────────────────────────────────────────────────────────


class _Reader:
    def __init__(self, conn, details: ua.ReadEventDetails, ts: ua.TimestampsToReturn, paths: list[str]):
        self.conn, self.details, self.ts, self.paths = conn, details, ts, paths

    async def page(self, nids: list[ua.NodeId], cps: list[bytes | None], release: bool):
        """(service status, [(item status, cp b64|None, events)])."""
        p = ua.HistoryReadParameters()
        p.HistoryReadDetails = self.details
        p.TimestampsToReturn = self.ts
        p.ReleaseContinuationPoints = release
        p.NodesToRead = [ua.HistoryReadValueId(NodeId=n, ContinuationPoint=c) for n, c in zip(nids, cps)]
        try:
            res = await self.conn.session.history_read(p)
        except UaStatusCodeError as e:
            return ua.StatusCode(e.code), [(ua.StatusCode(), None, []) for _ in nids]
        items = []
        for i in range(len(nids)):
            h = res[i] if i < len(res) else ua.HistoryReadResult()
            cp = base64.b64encode(h.ContinuationPoint).decode() if h.ContinuationPoint else None
            items.append((h.StatusCode or ua.StatusCode(), cp, events_json(self.paths, h.HistoryData)))
        return ua.StatusCode(), items


async def cmd_history_read_events(args: Args, r: Result, conn_cls) -> int:
    nodes = args.all("--node")
    if not nodes:
        raise InputError("missing --node (usage: history-read-events --endpoint <url> --node <id> [--node …]"
                         " [--start rfc3339] [--end rfc3339] [--num-values n] [--select path]…"
                         " [--of-type nodeId] [--min-severity n] [--continuation-point b64]"
                         " [--release-continuation-point] [--timestamps …] [--scenario continue [--max-pages n]])")
    try:
        start = parse_datetime(args.get("--start")) if args.get("--start") else None
        end = parse_datetime(args.get("--end")) if args.get("--end") else None
    except ValueError as e:
        raise InputError(f"invalid --start / --end: {e}")
    num = args.int("--num-values", 0)
    if num < 0:
        raise InputError("--num-values must not be negative")
    paths = args.all("--select") or list(DEFAULT_SELECT)
    selects = [select_clause(p) for p in paths]
    of_type_s, min_sev_s = args.get("--of-type"), args.get("--min-severity")
    min_sev = None
    if min_sev_s is not None:
        try:
            min_sev = int(min_sev_s)
        except ValueError:
            raise InputError("--min-severity must be an integer")
        if not 0 <= min_sev <= 65535:
            raise InputError("--min-severity must be 0..65535")
    cp_s = args.get("--continuation-point")
    cp = _b64("--continuation-point", cp_s) if cp_s else None
    release = _release_flag(args)
    scenario = args.get("--scenario")
    if scenario is not None and scenario != "continue":
        raise InputError(f"unknown --scenario {scenario}")
    max_pages = args.int("--max-pages", DEFAULT_MAX_PAGES)
    if max_pages < 1:
        raise InputError("--max-pages must be at least 1")
    if release and cp is None:
        raise InputError("--release-continuation-point needs --continuation-point")
    if cp is not None and len(nodes) > 1:
        raise InputError("--continuation-point takes one --node")
    ts = _timestamps(args)
    for n in nodes:
        parse_nodeid_syntax(n)
    if of_type_s:
        parse_nodeid_syntax(of_type_s)

    conn = conn_cls(args)
    await conn.connect()
    try:
        nids = [await conn.resolve(n) for n in nodes]
        of_type = await conn.resolve(of_type_s) if of_type_s else None
        d = ua.ReadEventDetails()
        d.NumValuesPerNode = num
        # An omitted --start / --end is the null DateTime (0 on the wire, Part 6 §5.2.2.5).
        d.StartTime = start or ua.get_win_epoch()
        d.EndTime = end or ua.get_win_epoch()
        d.Filter = ua.EventFilter(SelectClauses=selects, WhereClause=where_clause(of_type, min_sev))
        rd = _Reader(conn, d, ts, paths)

        if scenario == "continue":
            if num == 0:
                d.NumValuesPerNode = 2
            ok = True
            last_service = ua.StatusCode()
            for nid in nids:
                svc, item = await _continue(rd, nid, max_pages, r)
                if not is_good(svc):
                    last_service = svc
                ok = ok and is_good(svc) and not _bad(item)
            r.set_service(last_service if not is_good(last_service) else ua.StatusCode())
            r.success = ok
            return 0 if ok else 4

        svc, items = await rd.page(nids, [cp] * len(nids), release)
        ok = is_good(svc)
        for nid, (sc, cp_out, events) in zip(nids, items):
            r.add({
                "nodeId": nodeid_str(nid),
                "statusCode": status_json(sc),
                "continuationPoint": cp_out,
                "selectClauses": paths,
                "events": events,
            })
            ok = ok and not _bad(sc)
        r.set_service(svc if not is_good(svc) else _first_bad(items))
        r.success = ok
        return 0 if ok else 4
    finally:
        await conn.close()


def _bad(sc) -> bool:
    return (int(getattr(sc, "value", sc) or 0) >> 31) & 1 == 1


def _first_bad(items) -> ua.StatusCode:
    for sc, _, _ in items:
        if _bad(sc):
            return sc
    return ua.StatusCode()


async def _continue(rd: _Reader, nid: ua.NodeId, max_pages: int, r: Result):
    """Pages of one node in one session until no continuation point (or
    --max-pages), then release the last continuation point the node returned
    and read with it once more (both null when it returned none)."""
    pages = []
    cur = None
    last_cp = None
    svc, item, cp_out = ua.StatusCode(), ua.StatusCode(), None
    for _ in range(max_pages):
        svc, items = await rd.page([nid], [cur], False)
        item, cp_out, events = items[0]
        if not is_good(svc):
            item = svc
        pages.append({"statusCode": status_json(item), "continuationPoint": cp_out, "events": events})
        if not is_good(svc) or _bad(item) or not cp_out:
            break
        cur = base64.b64decode(cp_out)
        last_cp = cur
    release_sc = reuse_sc = None
    if last_cp is not None:
        s, it = await rd.page([nid], [last_cp], True)
        release_sc = status_json(it[0][0] if is_good(s) else s)
        s, it = await rd.page([nid], [last_cp], False)
        reuse_sc = status_json(it[0][0] if is_good(s) else s)
    r.add({
        "scenario": "continue",
        "nodeId": nodeid_str(nid),
        "statusCode": status_json(item),
        "continuationPoint": cp_out,
        "selectClauses": rd.paths,
        "events": [e for p in pages for e in p["events"]],
        "pages": pages,
        "releaseStatusCode": release_sc,
        "reuseAfterReleaseStatusCode": reuse_sc,
    })
    return svc, item


# ── history-update-events ──────────────────────────────────────────────────────


async def cmd_history_update_events(args: Args, r: Result, conn_cls) -> int:
    node = args.get("--node")
    perform = (args.get("--perform") or "").lower()
    if not node or perform not in PERFORM:
        raise InputError("missing --node or --perform insert|replace|update|delete (usage: history-update-events"
                         " --endpoint <url> --node <id> --perform insert|replace|update|delete"
                         " [--select path]… --event <json>… | --event-id <b64>…)")
    parse_nodeid_syntax(node)
    if perform == "delete":
        ids = [_b64("--event-id", s) for s in args.all("--event-id")]
        if not ids:
            raise InputError("--perform delete needs --event-id")
        build = lambda nid: ua.DeleteEventDetails(NodeId=nid, EventIds=ids)  # noqa: E731
    else:
        events = parse_events(args.all("--event"))
        if not events:
            raise InputError(f"--perform {perform} needs --event")
        paths = args.all("--select")
        if not paths:
            for ev in events:
                for k in ev:
                    if k not in paths:
                        paths.append(k)
        selects = [select_clause(p) for p in paths]
        data = [event_field_list(paths, ev) for ev in events]

        def build(nid):
            return ua.UpdateEventDetails(
                NodeId=nid,
                PerformInsertReplace=PERFORM[perform],
                Filter=ua.EventFilter(SelectClauses=selects, WhereClause=ua.ContentFilter()),
                EventData=data,
            )

    conn = conn_cls(args)
    await conn.connect()
    try:
        nid = await conn.resolve(node)
        p = ua.HistoryUpdateParameters(HistoryUpdateDetails=[build(nid)])
        try:
            res = await conn.session.history_update(p)
        except UaStatusCodeError as e:
            r.set_service(e.code).fail("service", f"HistoryUpdate: {e}")
            return 4
        h = res[0] if res else ua.HistoryUpdateResult(StatusCode=ua.StatusCode(ua.StatusCodes.BadUnexpectedError))
        sc = h.StatusCode or ua.StatusCode()
        r.add({
            "nodeId": nodeid_str(nid),
            "performUpdateType": PERFORM_NAME[perform],
            "statusCode": status_json(sc),
            "operationResults": [status_json(x) for x in (h.OperationResults or [])],
        })
        r.set_service(sc if _bad(sc) else ua.StatusCode())
        if _bad(sc):
            r.success = False
            return 4
        return 0
    finally:
        await conn.close()
