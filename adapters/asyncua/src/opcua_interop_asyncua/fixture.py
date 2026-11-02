"""Fixture loading / validation and the asyncua address space built from it."""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import logging

from asyncua import Server, ua
from asyncua.common.events import Event
from asyncua.server.history import HistoryDict
from asyncua.server.monitored_item_service import WhereClauseEvaluator

from .common import ADAPTER, log, parse_datetime, stack_version

MODEL_NODE_PREFIX = "nsu="

_DATATYPES = {
    "Boolean": (ua.VariantType.Boolean, 1),
    "SByte": (ua.VariantType.SByte, 2),
    "Byte": (ua.VariantType.Byte, 3),
    "Int16": (ua.VariantType.Int16, 4),
    "UInt16": (ua.VariantType.UInt16, 5),
    "Int32": (ua.VariantType.Int32, 6),
    "UInt32": (ua.VariantType.UInt32, 7),
    "Int64": (ua.VariantType.Int64, 8),
    "UInt64": (ua.VariantType.UInt64, 9),
    "Float": (ua.VariantType.Float, 10),
    "Double": (ua.VariantType.Double, 11),
    "String": (ua.VariantType.String, 12),
    "DateTime": (ua.VariantType.DateTime, 13),
    "Guid": (ua.VariantType.Guid, 14),
    "ByteString": (ua.VariantType.ByteString, 15),
    "XmlElement": (ua.VariantType.XmlElement, 16),
    "NodeId": (ua.VariantType.NodeId, 17),
    "StatusCode": (ua.VariantType.StatusCode, 19),
    "QualifiedName": (ua.VariantType.QualifiedName, 20),
    "LocalizedText": (ua.VariantType.LocalizedText, 21),
}

_REFTYPES = {
    "Organizes": ua.ObjectIds.Organizes,
    "HasComponent": ua.ObjectIds.HasComponent,
    "HasProperty": ua.ObjectIds.HasProperty,
    "HasSubtype": ua.ObjectIds.HasSubtype,
    "HasTypeDefinition": ua.ObjectIds.HasTypeDefinition,
    "Aggregates": ua.ObjectIds.Aggregates,
}

_ACCESS_BITS = {
    "CurrentRead": 1,
    "CurrentWrite": 2,
    "HistoryRead": 4,
    "HistoryWrite": 8,
    "SemanticChange": 16,
    "StatusWrite": 32,
    "TimestampWrite": 64,
}

EVENTS_SOURCE = "Events.Source"
HISTORY_TEMPERATURE = "History.Temperature"
HISTORY_FOLDER = "History"
HISTORY_EVENTS = "History.Events"
_HISTORY_EVENTS_BASE = datetime(2026, 7, 24, 10, 0, 0, tzinfo=timezone.utc)


class History(HistoryDict):
    """asyncua's in-memory history (HistoryDict) with two changes for event
    history reads, which asyncua leaves to the storage (HistoryStorageInterface
    gets the EventFilter and returns a continuation point):

    - the WhereClause is applied, with asyncua's own WhereClauseEvaluator (the
      one of event monitored items: OfType compares the EventType exactly);
    - NumValuesPerNode cuts with a continuation point (the Time of the next
      event; asyncua's HistoryManager resumes the read from that time, start
      inclusive) instead of dropping the rest.

    Everything else is asyncua's (asyncua/README.md "Historical events")."""

    def __init__(self, server: Server | None = None):
        super().__init__()
        self._server = server

    async def read_event_history(self, source_id, start, end, nb_values, evfilter):
        results, cont = await super().read_event_history(source_id, start, end, 0, evfilter)
        where = getattr(evfilter, "WhereClause", None)
        if where is not None and where.Elements and self._server is not None:
            ev = WhereClauseEvaluator(logging.getLogger(__name__), self._server.iserver.aspace, where)
            results = [e for e in results if ev.eval(e)]
        if nb_values and len(results) > nb_values:
            return results[:nb_values], results[nb_values].Time
        return results, cont


def history_event(source: ua.NodeId, i: int) -> Event:
    """Seed event i of History.Events (CONTAINER_CONTRACT.md, docs/FIXTURES.md)."""
    t = _HISTORY_EVENTS_BASE + timedelta(seconds=5 * i)
    ev = Event(emitting_node=source)
    ev.add_property("EventId", f"hist-evt-{i}".encode(), ua.VariantType.ByteString)
    ev.add_property("EventType", ua.NodeId(ua.ObjectIds.SystemEventType if i == 3 else ua.ObjectIds.BaseEventType), ua.VariantType.NodeId)
    ev.add_property("SourceNode", source, ua.VariantType.NodeId)
    ev.add_property("SourceName", HISTORY_EVENTS, ua.VariantType.String)
    ev.add_property("Time", t, ua.VariantType.DateTime)
    ev.add_property("ReceiveTime", t, ua.VariantType.DateTime)
    ev.add_property("Message", ua.LocalizedText(f"history-event-{i}", "en"), ua.VariantType.LocalizedText)
    ev.add_property("Severity", 100 * (i + 1), ua.VariantType.UInt16)
    return ev


class FixtureError(Exception):
    pass


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    validate(data)
    return data


def validate(data: dict) -> None:
    """Structural checks (the JSON Schema is validated by scripts/validate-fixtures.py)."""
    if not isinstance(data, dict):
        raise FixtureError("fixture is not a JSON object")
    if data.get("schemaVersion") != "1.0":
        raise FixtureError(f"unsupported schemaVersion {data.get('schemaVersion')!r}")
    for key in ("id", "namespaces", "nodes"):
        if key not in data:
            raise FixtureError(f"missing {key}")
    if not data["namespaces"]:
        raise FixtureError("namespaces is empty")
    ids = set()
    for n in data["nodes"]:
        for key in ("nodeClass", "nodeId", "browseName"):
            if key not in n:
                raise FixtureError(f"node without {key}: {n}")
        if n["nodeId"] in ids:
            raise FixtureError(f"duplicate nodeId {n['nodeId']}")
        ids.add(n["nodeId"])
        if n["nodeClass"] == "Variable" and n.get("dataType") not in _DATATYPES:
            raise FixtureError(f"{n['nodeId']}: unsupported dataType {n.get('dataType')!r}")
    for b in data.get("behaviors", []) or []:
        if b.get("target") not in ids:
            raise FixtureError(f"behavior target {b.get('target')} is not a fixture node")


def _short_id(fixture_id: str) -> str:
    """'nsu=<uri>;s=Scalar.Int32' -> 'Scalar.Int32'."""
    return fixture_id.split(";s=", 1)[1] if ";s=" in fixture_id else fixture_id


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _scalar(value, dtype: str):
    vt = _DATATYPES[dtype][0]
    if value is None:
        return None
    if dtype == "Boolean":
        return bool(value) if not isinstance(value, str) else value.lower() == "true"
    if vt in (
        ua.VariantType.SByte,
        ua.VariantType.Byte,
        ua.VariantType.Int16,
        ua.VariantType.UInt16,
        ua.VariantType.Int32,
        ua.VariantType.UInt32,
        ua.VariantType.Int64,
        ua.VariantType.UInt64,
    ):
        return int(value)
    if dtype in ("Float", "Double"):
        return float(value)
    if dtype == "String":
        return str(value)
    if dtype == "DateTime":
        return parse_datetime(str(value))
    if dtype == "Guid":
        return uuid.UUID(str(value))
    if dtype == "ByteString":
        return base64.b64decode(str(value)) if value else b""
    if dtype == "XmlElement":
        return ua.XmlElement(str(value))
    if dtype == "NodeId":
        return ua.NodeId.from_string(str(value))
    if dtype == "QualifiedName":
        s = str(value)
        if ":" in s:
            ns, name = s.split(":", 1)
            return ua.QualifiedName(name, int(ns))
        return ua.QualifiedName(s, 0)
    if dtype == "LocalizedText":
        s = str(value)
        if ":" in s:
            loc, text = s.split(":", 1)
            return ua.LocalizedText(text, loc)
        return ua.LocalizedText(s)
    if dtype == "StatusCode":
        return ua.StatusCode(int(value))
    return value


def build_variant(value, dtype: str, value_rank: int, dims: list[int] | None) -> ua.Variant:
    vt = _DATATYPES[dtype][0]
    if value_rank >= 2 and isinstance(value, list) and dims and len(dims) >= 2:
        flat = [_scalar(v, dtype) for v in value]
        # nest row-major according to the dimensions
        def nest(items, ds):
            if len(ds) == 1:
                return items
            step = len(items) // ds[0]
            return [nest(items[i * step : (i + 1) * step], ds[1:]) for i in range(ds[0])]

        return ua.Variant(nest(flat, dims), vt, Dimensions=list(dims), is_array=True)
    if value_rank >= 1 and isinstance(value, list):
        return ua.Variant([_scalar(v, dtype) for v in value], vt, is_array=True)
    return ua.Variant(_scalar(value, dtype), vt)


class AddressSpaceBuilder:
    def __init__(self, server: Server, fixture: dict, history):
        self.server = server
        self.fixture = fixture
        self.history = history
        self.ns_uri = fixture["namespaces"][0]["uri"]
        self.ns_idx = 0
        self.nodes: dict[str, ua.NodeId] = {}
        self.defs: dict[str, dict] = {}
        self.write_only_values: dict[ua.NodeId, ua.DataValue] = {}
        self._tasks: list[asyncio.Task] = []
        self._events_source: ua.NodeId | None = None
        self._history_events: ua.NodeId | None = None

    # ── NodeId resolution ──────────────────────────────────────────────────

    def resolve(self, s: str) -> ua.NodeId:
        if s.startswith("nsu="):
            uri, rest = s[4:].split(";", 1)
            ns = self.ns_idx if uri == self.ns_uri else 0
            if rest.startswith("s="):
                return ua.NodeId(rest[2:], ns, ua.NodeIdType.String)
            if rest.startswith("i="):
                return ua.NodeId(int(rest[2:]), ns)
            raise ValueError(f"unsupported fixture NodeId {s}")
        return ua.NodeId.from_string(s)

    def qname(self, s: str) -> ua.QualifiedName:
        if ":" in s:
            ns, name = s.split(":", 1)
            try:
                n = int(ns)
                # Fixture browse names use the fixture's namespace position (1 = first namespace).
                return ua.QualifiedName(name, self.ns_idx if n == 1 else n)
            except ValueError:
                pass
        return ua.QualifiedName(s, self.ns_idx)

    # ── Build ──────────────────────────────────────────────────────────────

    async def build(self) -> None:
        self.ns_idx = await self.server.register_namespace(self.ns_uri)
        log(f"namespace {self.ns_uri} = {self.ns_idx}")
        for nd in self.fixture["nodes"]:
            try:
                await self._add(nd)
            except Exception as e:  # noqa: BLE001
                raise RuntimeError(f"cannot create {nd['nodeId']}: {e}") from e
        await self._history_events_node()
        await self._fill_diagnostics()

    async def _add_item(self, item: ua.AddNodesItem) -> ua.NodeId:
        res = await self.server.iserver.isession.add_nodes([item])
        res[0].StatusCode.check()
        return res[0].AddedNodeId

    async def _add(self, nd: dict) -> None:
        nid = self.resolve(nd["nodeId"])
        parent = self.resolve(nd.get("parentNodeId", "i=85"))
        item = ua.AddNodesItem()
        item.RequestedNewNodeId = nid
        item.BrowseName = self.qname(nd["browseName"])
        item.ParentNodeId = parent
        item.ReferenceTypeId = ua.NodeId(_REFTYPES.get(nd.get("referenceType", "Organizes"), ua.ObjectIds.Organizes))
        short = _short_id(nd["nodeId"])
        dn = ua.LocalizedText(nd.get("displayName", short), "en")
        desc = ua.LocalizedText(nd.get("description", ""), "en")
        cls = nd["nodeClass"]

        if cls == "Variable":
            dtype = nd["dataType"]
            vt, dt_id = _DATATYPES[dtype]
            rank = int(nd.get("valueRank", -1))
            dims = nd.get("arrayDimensions")
            access = 0
            for a in nd.get("accessLevel", ["CurrentRead"]):
                access |= _ACCESS_BITS.get(a, 0)
            item.NodeClass = ua.NodeClass.Variable
            item.TypeDefinition = self.resolve(nd["typeDefinition"]) if nd.get("typeDefinition") else ua.NodeId(
                ua.ObjectIds.BaseDataVariableType
            )
            variant = build_variant(nd.get("initialValue"), dtype, rank, dims)
            attrs = ua.VariableAttributes()
            attrs.DisplayName = dn
            attrs.Description = desc
            attrs.DataType = ua.NodeId(dt_id)
            attrs.ValueRank = rank
            if dims is not None:
                attrs.ArrayDimensions = [int(d) for d in dims]
            attrs.Value = variant
            attrs.AccessLevel = access
            attrs.UserAccessLevel = access
            attrs.Historizing = short == HISTORY_TEMPERATURE
            attrs.MinimumSamplingInterval = 0.0
            item.NodeAttributes = attrs
            await self._add_item(item)
            now = _now()
            dv = ua.DataValue(variant, SourceTimestamp=now, ServerTimestamp=now)
            await self.server.write_attribute_value(nid, dv)
            if access & 1 == 0:
                # asyncua's Read service does not check AccessLevel.CurrentRead:
                # the fixture's write-only node is served by the adapter
                # (value callback answering BadNotReadable, setter keeping the value).
                self._make_write_only(nid, dv)
            if nd.get("euRange"):
                await self._add_eurange(nid, nd["euRange"])
            if short == HISTORY_TEMPERATURE:
                await self._historize(nid)
        elif cls == "Method":
            item.NodeClass = ua.NodeClass.Method
            attrs = ua.MethodAttributes()
            attrs.DisplayName = dn
            attrs.Description = desc
            attrs.Executable = True
            attrs.UserExecutable = True
            item.NodeAttributes = attrs
            await self._add_item(item)
            await self._add_arguments(nid, "InputArguments", nd.get("inputArguments") or [])
            await self._add_arguments(nid, "OutputArguments", nd.get("outputArguments") or [])
            from .methods import make_method

            self.server.iserver.isession.add_method_callback(nid, make_method(nd.get("methodBehavior"), nd))
        else:
            item.NodeClass = ua.NodeClass.Object
            item.TypeDefinition = self.resolve(nd["typeDefinition"]) if nd.get("typeDefinition") else ua.NodeId(
                ua.ObjectIds.FolderType
            )
            attrs = ua.ObjectAttributes()
            attrs.DisplayName = dn
            attrs.Description = desc
            if short == EVENTS_SOURCE:
                attrs.EventNotifier = 1  # SubscribeToEvents
                self._events_source = nid
            if short == HISTORY_EVENTS:
                attrs.EventNotifier = 0x05  # SubscribeToEvents | HistoryRead (no HistoryUpdate in asyncua)
                self._history_events = nid
            item.NodeAttributes = attrs
            await self._add_item(item)
        self.nodes[nd["nodeId"]] = nid
        self.defs[nd["nodeId"]] = nd

    def _make_write_only(self, nid: ua.NodeId, dv: ua.DataValue) -> None:
        self.write_only_values[nid] = dv

        def getter(nodeid, attr):
            return ua.DataValue(StatusCode=ua.StatusCode(ua.StatusCodes.BadNotReadable))

        def setter(nodedata, attr, value):
            self.write_only_values[nid] = value

        self.server.set_attribute_value_callback(nid, getter)
        self.server.set_attribute_value_setter(nid, setter)

    async def _add_eurange(self, owner: ua.NodeId, eu: dict) -> None:
        pid = ua.NodeId(f"{owner.Identifier}.EURange", self.ns_idx, ua.NodeIdType.String)
        item = ua.AddNodesItem()
        item.RequestedNewNodeId = pid
        item.BrowseName = ua.QualifiedName("EURange", 0)
        item.ParentNodeId = owner
        item.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasProperty)
        item.NodeClass = ua.NodeClass.Variable
        item.TypeDefinition = ua.NodeId(ua.ObjectIds.PropertyType)
        attrs = ua.VariableAttributes()
        attrs.DisplayName = ua.LocalizedText("EURange")
        attrs.DataType = ua.NodeId(ua.ObjectIds.Range)
        attrs.ValueRank = -1
        rng = ua.Range(Low=float(eu["low"]), High=float(eu["high"]))
        attrs.Value = ua.Variant(rng, ua.VariantType.ExtensionObject)
        attrs.AccessLevel = 1
        attrs.UserAccessLevel = 1
        item.NodeAttributes = attrs
        await self._add_item(item)

    async def _add_arguments(self, method: ua.NodeId, name: str, defs: list[dict]) -> None:
        if not defs:
            return
        args = []
        for d in defs:
            a = ua.Argument()
            a.Name = d.get("name", "")
            a.DataType = ua.NodeId(_DATATYPES[d["dataType"]][1]) if d.get("dataType") in _DATATYPES else ua.NodeId(24)
            a.ValueRank = int(d.get("valueRank", -1))
            a.ArrayDimensions = []
            a.Description = ua.LocalizedText(d.get("description", ""))
            args.append(a)
        item = ua.AddNodesItem()
        item.RequestedNewNodeId = ua.NodeId(f"{method.Identifier}.{name}", self.ns_idx, ua.NodeIdType.String)
        item.BrowseName = ua.QualifiedName(name, 0)
        item.ParentNodeId = method
        item.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasProperty)
        item.NodeClass = ua.NodeClass.Variable
        item.TypeDefinition = ua.NodeId(ua.ObjectIds.PropertyType)
        attrs = ua.VariableAttributes()
        attrs.DisplayName = ua.LocalizedText(name)
        attrs.DataType = ua.NodeId(ua.ObjectIds.Argument)
        attrs.ValueRank = 1
        attrs.ArrayDimensions = [0]
        attrs.Value = ua.Variant(args, ua.VariantType.ExtensionObject, is_array=True)
        attrs.AccessLevel = 1
        attrs.UserAccessLevel = 1
        item.NodeAttributes = attrs
        await self._add_item(item)

    async def _historize(self, nid: ua.NodeId) -> None:
        """History.Temperature: five fixed raw samples 20..24 at 2026-07-24T10:00:00Z
        step 5 s, served by asyncua's own in-memory history backend (HistoryDict)."""
        await self.history.new_historized_node(nid, period=None)
        base = datetime(2026, 7, 24, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            ts = base + timedelta(seconds=5 * i)
            await self.history.save_node_value(
                nid, ua.DataValue(ua.Variant(20.0 + i, ua.VariantType.Double), SourceTimestamp=ts, ServerTimestamp=ts)
            )

    @property
    def history_events(self) -> ua.NodeId | None:
        return self._history_events

    async def _history_events_node(self) -> None:
        """History.Events: the Object (Organizes from History) unless the
        fixture has it, and its five seed events written into the history
        storage under its NodeId (asyncua's own historize_node_event would
        subscribe to live events and store them under the Server object)."""
        if self._history_events is None:
            parent = next((nid for fid, nid in self.nodes.items() if _short_id(fid) == HISTORY_FOLDER), None)
            if parent is None:
                return
            nid = ua.NodeId(HISTORY_EVENTS, self.ns_idx, ua.NodeIdType.String)
            item = ua.AddNodesItem()
            item.RequestedNewNodeId = nid
            item.BrowseName = ua.QualifiedName(HISTORY_EVENTS, self.ns_idx)
            item.ParentNodeId = parent
            item.ReferenceTypeId = ua.NodeId(ua.ObjectIds.Organizes)
            item.NodeClass = ua.NodeClass.Object
            item.TypeDefinition = ua.NodeId(ua.ObjectIds.BaseObjectType)
            attrs = ua.ObjectAttributes()
            attrs.DisplayName = ua.LocalizedText(HISTORY_EVENTS, "en")
            attrs.Description = ua.LocalizedText("Event history: five seeded events", "en")
            attrs.EventNotifier = 0x05
            item.NodeAttributes = attrs
            await self._add_item(item)
            self._history_events = nid
        if self.history is None:
            return
        nid = self._history_events
        await self.history.new_historized_event(nid, [], None, 0)
        for i in range(5):
            await self.history.save_event(history_event(nid, i))

    async def _fill_diagnostics(self) -> None:
        values = {"Diagnostics.AdapterName": ADAPTER, "Diagnostics.StackVersion": f"asyncua {stack_version()}"}
        for fid, nid in self.nodes.items():
            short = _short_id(fid)
            if short in values:
                now = _now()
                await self.server.write_attribute_value(
                    nid, ua.DataValue(ua.Variant(values[short], ua.VariantType.String), SourceTimestamp=now, ServerTimestamp=now)
                )

    # ── Behaviors ──────────────────────────────────────────────────────────

    async def start_behaviors(self) -> None:
        for b in self.fixture.get("behaviors", []) or []:
            nid = self.nodes.get(b["target"])
            nd = self.defs.get(b["target"])
            if nid is None or nd is None:
                continue
            kind = b.get("kind")
            vt = _DATATYPES[nd["dataType"]][0]
            if kind == "fixed-status":
                cur = self.server.read_attribute_value(nid)
                now = _now()
                await self.server.write_attribute_value(
                    nid,
                    ua.DataValue(cur.Value, StatusCode=ua.StatusCode(int(b["initial"])), SourceTimestamp=now, ServerTimestamp=now),
                )
            elif kind in ("counter", "toggle", "ramp"):
                self._tasks.append(asyncio.create_task(self._run_behavior(nid, vt, b)))
            else:
                log(f"warn: unknown behavior kind {kind!r}")
        if self._events_source is not None:
            self._tasks.append(asyncio.create_task(self._emit_events()))

    async def _run_behavior(self, nid: ua.NodeId, vt: ua.VariantType, b: dict) -> None:
        kind = b["kind"]
        interval = float(b.get("intervalMs", 1000)) / 1000.0
        state = b.get("initial", 0)
        if kind == "counter":
            state = int(state)
        elif kind == "ramp":
            state = float(state)
        else:
            state = False
        loop = asyncio.get_running_loop()
        next_t = loop.time()
        while True:
            if kind == "counter":
                val = state
                state = state + int(b.get("increment", 1))
            elif kind == "toggle":
                state = not state
                val = state
            else:
                val = state
                state = state + float(b.get("increment", 1.0))
                if state > float(b.get("maximum", 100.0)):
                    state = float(b.get("minimum", 0.0))
            now = _now()
            try:
                await self.server.write_attribute_value(
                    nid, ua.DataValue(ua.Variant(val, vt), SourceTimestamp=now, ServerTimestamp=now)
                )
            except Exception as e:  # noqa: BLE001
                log(f"warn: behavior on {nid.to_string()} failed: {e}")
            next_t += interval
            await asyncio.sleep(max(0.0, next_t - loop.time()))

    async def _emit_events(self) -> None:
        gen = await self.server.get_event_generator(ua.ObjectIds.BaseEventType, emitting_node=self._events_source)
        await asyncio.sleep(0.5)
        while True:
            try:
                gen.event.Severity = 500
                gen.event.Message = ua.LocalizedText("peer-event", "en")
                gen.event.SourceName = "Events.Source"
                await gen.trigger()
            except Exception as e:  # noqa: BLE001
                log(f"warn: BaseEvent emission failed: {e}")
            await asyncio.sleep(2.0)

    async def stop_behaviors(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
