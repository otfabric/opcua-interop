"""`client` subcommands on the asyncua (opcua-asyncio) client
(docs/CLIENT_CONTRACT.md §1–§9)."""

from __future__ import annotations

import asyncio
import base64
import time

from asyncua import Client, ua
from asyncua.crypto import security_policies as sp
from asyncua.crypto import uacrypto
from asyncua.ua.uaerrors import UaStatusCodeError

from . import pki, push
from .common import (
    Args,
    AdapterError,
    InputError,
    Result,
    ServiceError,
    TransportError,
    file_format,
    fmt_datetime,
    is_bad,
    is_good,
    lenient_variant,
    local_nodeid,
    log,
    make_nodeid,
    nodeid_str,
    parse_datetime,
    parse_nodeid_syntax,
    sc_value,
    status_json,
    ts_present,
    variant_fields,
    variant_value,
)

OPERATIONS = [
    "endpoints",
    "find-servers",
    "read",
    "write",
    "browse",
    "translate",
    "call",
    "subscribe",
    "subscription-lifecycle",
    "event-subscribe",
    "alarms",
    "history-read",
    "republish",
    "transfer-subscriptions",
    "register-nodes",
    "node-management",
    "find-servers-on-network",
    "register-server",
    "push",
    "gds-pull",
]

POLICIES = {
    "None": sp.SecurityPolicyNone,
    "Basic128Rsa15": sp.SecurityPolicyBasic128Rsa15,
    "Basic256": sp.SecurityPolicyBasic256,
    "Basic256Sha256": sp.SecurityPolicyBasic256Sha256,
    "Aes128_Sha256_RsaOaep": sp.SecurityPolicyAes128Sha256RsaOaep,
    "Aes256_Sha256_RsaPss": sp.SecurityPolicyAes256Sha256RsaPss,
}

MODES = {
    "None": ua.MessageSecurityMode.None_,
    "Sign": ua.MessageSecurityMode.Sign,
    "SignAndEncrypt": ua.MessageSecurityMode.SignAndEncrypt,
}

DEFAULT_APP_URI = "urn:otfabric:opcua-interop:client:asyncua"
BAD_TIMEOUT = 0x800A0000
BAD_UNEXPECTED = 0x80010000
UNSUPPORTED_SERVICE = (0x800B0000, 0x80400000, 0x803D0000)  # BadServiceUnsupported, BadNotImplemented, BadNotSupported

TIMESTAMPS = {
    "Source": ua.TimestampsToReturn.Source,
    "Server": ua.TimestampsToReturn.Server,
    "Both": ua.TimestampsToReturn.Both,
    "Neither": ua.TimestampsToReturn.Neither,
}


def _timestamps(args: Args) -> ua.TimestampsToReturn:
    v = args.get("--timestamps", "Both")
    if v not in TIMESTAMPS:
        raise InputError("--timestamps must be Source, Server, Both or Neither")
    return TIMESTAMPS[v]


def _status_code(exc: BaseException) -> int:
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return code
    return BAD_UNEXPECTED


# ── Connection ────────────────────────────────────────────────────────────────


class Conn:
    def __init__(self, args: Args):
        self.args = args
        self.endpoint = args.get("--endpoint")
        if not self.endpoint:
            raise InputError("missing --endpoint")
        self.cto = args.float("--connect-timeout", 5.0)
        self.rto = args.float("--request-timeout", 5.0)
        self.dto = args.float("--disconnect-timeout", 2.0)
        self.policy = args.get("--security-policy", "None")
        self.mode = args.get("--security-mode", "None")
        if self.policy not in POLICIES:
            extra = " (no ECC security policies)" if self.policy.startswith("ECC_") else ""
            raise InputError(f"--security-policy {self.policy} is not supported by asyncua{extra}")
        if self.mode not in MODES:
            raise InputError(f"--security-mode must be None, Sign or SignAndEncrypt, got {self.mode}")
        if (self.policy == "None") != (self.mode == "None"):
            raise InputError(f"--security-policy {self.policy} with --security-mode {self.mode}")
        self.cert = args.get("--certificate")
        self.key = args.get("--private-key")
        if self.policy != "None" and not (self.cert and self.key):
            raise InputError("--certificate and --private-key are required with a non-None --security-policy")
        self.trust = args.all("--trust-list")
        self.username = args.get("--username")
        self.password = args.get("--password")
        self.lifetime = args.int("--channel-lifetime-ms", 0)
        self.app_uri_flag = args.get("--application-uri")
        self.client: Client | None = None
        self.ns_array: list[str] | None = None

    @property
    def session(self):
        return self.client.uaclient.session

    def _new_client(self) -> Client:
        c = Client(self.endpoint, timeout=self.rto)
        c.name = "opcua-interop asyncua client"
        c.description = c.name
        c.application_uri = DEFAULT_APP_URI
        c.product_uri = "urn:otfabric:opcua-interop:asyncua"
        return c

    async def endpoints(self) -> list[ua.EndpointDescription]:
        c = self._new_client()
        try:
            return await asyncio.wait_for(c.connect_and_get_server_endpoints(), self.cto + self.rto)
        except (OSError, ConnectionError) as e:
            raise TransportError(f"cannot connect to {self.endpoint}: {e}", BAD_UNEXPECTED)
        except asyncio.TimeoutError:
            raise TransportError(f"timeout connecting to {self.endpoint}", BAD_TIMEOUT)

    async def _cert_uri(self) -> str | None:
        try:
            return pki.application_uri(pki.load_certificate(self.cert))
        except (OSError, ValueError):
            return None

    async def connect(self) -> "Conn":
        eps = await self.endpoints()
        policy_cls = POLICIES[self.policy]
        mode = MODES[self.mode]
        chosen = next(
            (e for e in eps if e.SecurityPolicyUri == policy_cls.URI and e.SecurityMode == mode),
            None,
        )
        if chosen is None:
            raise TransportError(
                f"no endpoint with SecurityPolicy={self.policy} and MessageSecurityMode={self.mode} at {self.endpoint}"
            )
        c = self._new_client()
        if self.lifetime > 0:
            c.secure_channel_timeout = self.lifetime
        if self.cert and self.key:
            uri = self.app_uri_flag or await self._cert_uri()
            if uri:
                c.application_uri = uri
        elif self.app_uri_flag:
            c.application_uri = self.app_uri_flag
        if self.policy != "None":
            try:
                await c.set_security(
                    policy_cls,
                    uacrypto.CertProperties(self.cert, extension=file_format(self.cert)),
                    uacrypto.CertProperties(self.key, extension=file_format(self.key)),
                    server_certificate=pki.leaf_certificate(chosen.ServerCertificate),
                    mode=mode,
                )
            except Exception as e:  # noqa: BLE001
                raise AdapterError(f"cannot use the client certificate / key: {e}")
            if self.trust:
                c.certificate_validator = await pki.client_validator(self.trust)
        if self.username is not None:
            c.set_user(self.username)
            c.set_password(self.password or "")
        try:
            await asyncio.wait_for(c.connect(), self.cto + self.rto)
        except UaStatusCodeError as e:
            await _quiet_disconnect(c)
            raise ServiceError(f"connect: {e}", e.code)
        except asyncio.TimeoutError:
            await _quiet_disconnect(c)
            raise TransportError(f"timeout connecting to {self.endpoint}", BAD_TIMEOUT)
        except (OSError, ConnectionError, ua.UaError) as e:
            await _quiet_disconnect(c)
            raise TransportError(f"connect to {self.endpoint} failed: {e}", _status_code(e))
        self.client = c
        return self

    async def close(self) -> None:
        if self.client is not None:
            try:
                await asyncio.wait_for(self.client.disconnect(), self.dto + 1)
            except Exception as e:  # noqa: BLE001
                log(f"warn: disconnect: {e!r}")

    async def resolve(self, s: str) -> ua.NodeId:
        uri, ns, ident, t = parse_nodeid_syntax(s)
        if uri is not None:
            if self.ns_array is None:
                self.ns_array = await self.client.get_namespace_array()
            if uri not in self.ns_array:
                raise InputError(f"unknown namespace URI: {uri}")
            ns = self.ns_array.index(uri)
        return make_nodeid(ident, ns, t)


async def _quiet_disconnect(c: Client) -> None:
    try:
        await asyncio.wait_for(c.disconnect(), 2)
    except Exception:  # noqa: BLE001
        pass


# ── Subscription helper ───────────────────────────────────────────────────────


class Sub:
    """A subscription on the asyncua session; publish results go to a queue."""

    def __init__(self, conn: Conn):
        self.conn = conn
        self.queue: asyncio.Queue = asyncio.Queue()
        self.result: ua.CreateSubscriptionResult | None = None

    def _cb(self, publish_result):
        self.queue.put_nowait(publish_result)

    async def create(self, interval: float, lifetime: int | None = None, keepalive: int | None = None) -> "Sub":
        p = ua.CreateSubscriptionParameters()
        p.RequestedPublishingInterval = interval
        p.RequestedMaxKeepAliveCount = keepalive if keepalive is not None else self.conn.client.get_keepalive_count(interval)
        p.RequestedLifetimeCount = lifetime if lifetime is not None else 10000
        p.MaxNotificationsPerPublish = 0
        p.PublishingEnabled = True
        p.Priority = 0
        self.result = await self.conn.session.create_subscription(p, self._cb)
        return self

    @property
    def id(self) -> int:
        return int(self.result.SubscriptionId)

    async def monitor(self, nodeid, *, handle=1, sampling=100.0, queue=1, discard=True, flt=None,
                      ts=ua.TimestampsToReturn.Both, attr=ua.AttributeIds.Value) -> ua.MonitoredItemCreateResult:
        req = ua.MonitoredItemCreateRequest()
        req.ItemToMonitor = ua.ReadValueId(NodeId=nodeid, AttributeId=attr)
        req.MonitoringMode = ua.MonitoringMode.Reporting
        mp = ua.MonitoringParameters()
        mp.ClientHandle = handle
        mp.SamplingInterval = sampling
        mp.Filter = flt
        mp.QueueSize = queue
        mp.DiscardOldest = discard
        req.RequestedParameters = mp
        params = ua.CreateMonitoredItemsParameters()
        params.SubscriptionId = self.id
        params.TimestampsToReturn = ts
        params.ItemsToCreate = [req]
        res = await self.conn.session.create_monitored_items(params)
        return res[0]

    async def next(self, timeout: float):
        try:
            return await asyncio.wait_for(self.queue.get(), max(0.0, timeout))
        except asyncio.TimeoutError:
            return None

    async def delete(self) -> None:
        try:
            await self.conn.session.delete_subscriptions([self.id])
        except Exception:  # noqa: BLE001
            pass


def _datachanges(publish_result, handle: int | None = None):
    for nd in publish_result.NotificationMessage.NotificationData or []:
        if isinstance(nd, ua.DataChangeNotification):
            for mi in nd.MonitoredItems or []:
                if handle is None or mi.ClientHandle == handle:
                    yield mi.Value


def _events(publish_result, handle: int):
    for nd in publish_result.NotificationMessage.NotificationData or []:
        if isinstance(nd, ua.EventNotificationList):
            for ev in nd.Events or []:
                if ev.ClientHandle == handle:
                    yield ev.EventFields or []


def _dv_item(dv: ua.DataValue) -> dict:
    item = variant_fields(dv.Value)
    item["statusCode"] = status_json(dv.StatusCode)
    if ts_present(dv.SourceTimestamp):
        item["sourceTimestamp"] = fmt_datetime(dv.SourceTimestamp)
    if ts_present(dv.ServerTimestamp):
        item["serverTimestamp"] = fmt_datetime(dv.ServerTimestamp)
    return item


async def _write_int32(conn: Conn, nodeid, v: int) -> None:
    p = ua.WriteParameters()
    p.NodesToWrite = [
        ua.WriteValue(
            NodeId=nodeid,
            AttributeId=ua.AttributeIds.Value,
            Value=ua.DataValue(ua.Variant(v, ua.VariantType.Int32), StatusCode=None),
        )
    ]
    await conn.session.write(p)


# ── Commands ──────────────────────────────────────────────────────────────────


async def cmd_endpoints(args: Args, r: Result) -> int:
    conn = Conn(args)
    for e in await conn.endpoints():
        r.add({"url": e.EndpointUrl, "securityPolicy": e.SecurityPolicyUri, "securityMode": e.SecurityMode.name.rstrip("_")})
    return 0


async def cmd_find_servers(args: Args, r: Result) -> int:
    conn = Conn(args)
    c = conn._new_client()
    try:
        apps = await asyncio.wait_for(c.connect_and_find_servers(), conn.cto + conn.rto)
    except (OSError, ConnectionError) as e:
        raise TransportError(f"cannot connect to {conn.endpoint}: {e}")
    except asyncio.TimeoutError:
        raise TransportError(f"timeout connecting to {conn.endpoint}", BAD_TIMEOUT)
    for a in apps:
        name = a.ApplicationName or ua.LocalizedText()
        r.add({
            "applicationUri": a.ApplicationUri or "",
            "applicationName": {"locale": name.Locale or "", "text": name.Text or ""},
            "productUri": a.ProductUri or "",
            "discoveryUrls": [u for u in (a.DiscoveryUrls or []) if u is not None],
        })
    return 0


async def cmd_read(args: Args, r: Result) -> int:
    nodes = args.all("--node")
    if not nodes:
        raise InputError("missing --endpoint or --node")
    conn = Conn(args)
    for n in nodes:
        parse_nodeid_syntax(n)
    await conn.connect()
    try:
        ids = [await conn.resolve(n) for n in nodes]
        p = ua.ReadParameters()
        p.MaxAge = 0
        p.TimestampsToReturn = _timestamps(args)
        p.NodesToRead = [ua.ReadValueId(NodeId=i, AttributeId=ua.AttributeIds.Value, IndexRange=args.get("--index-range")) for i in ids]
        dvs = await conn.session.read(p)
        any_bad = False
        for nid, dv in zip(ids, dvs):
            item = {"nodeId": nodeid_str(nid), "statusCode": status_json(dv.StatusCode)}
            item.update(variant_fields(dv.Value))
            if ts_present(dv.SourceTimestamp):
                item["sourceTimestamp"] = fmt_datetime(dv.SourceTimestamp)
            if ts_present(dv.ServerTimestamp):
                item["serverTimestamp"] = fmt_datetime(dv.ServerTimestamp)
            r.add(item)
            if not is_good(dv.StatusCode):
                any_bad = True
        if len(ids) == 1:
            r.set_service(dvs[0].StatusCode)
        if any_bad:
            r.success = False
            return 4
        return 0
    finally:
        await conn.close()


async def cmd_write(args: Args, r: Result) -> int:
    nodes, types, values = args.all("--node"), args.all("--type"), args.all("--value")
    if not nodes or len(nodes) != len(types) or len(nodes) != len(values):
        raise InputError("write requires equal counts of --node, --type, and --value")
    conn = Conn(args)
    for n in nodes:
        parse_nodeid_syntax(n)
    await conn.connect()
    try:
        ids = [await conn.resolve(n) for n in nodes]
        p = ua.WriteParameters()
        p.NodesToWrite = [
            ua.WriteValue(
                NodeId=i,
                AttributeId=ua.AttributeIds.Value,
                IndexRange=args.get("--index-range"),
                Value=ua.DataValue(lenient_variant(t, v), StatusCode=None),
            )
            for i, t, v in zip(ids, types, values)
        ]
        res = await conn.session.write(p)
        first_bad = None
        for nid, sc in zip(ids, res):
            r.add({"nodeId": nodeid_str(nid), "statusCode": status_json(sc)})
            if not is_good(sc) and first_bad is None:
                first_bad = sc
        if len(ids) == 1:
            r.set_service(res[0])
        elif first_bad is not None:
            r.set_service(first_bad)
        if first_bad is not None:
            r.success = False
            return 4
        return 0
    finally:
        await conn.close()


async def cmd_browse(args: Args, r: Result) -> int:
    node = args.get("--node", "i=85")
    parse_nodeid_syntax(node)
    conn = Conn(args)
    await conn.connect()
    try:
        nid = await conn.resolve(node)
        bd = ua.BrowseDescription()
        bd.NodeId = nid
        bd.BrowseDirection = ua.BrowseDirection.Forward
        bd.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HierarchicalReferences)
        bd.IncludeSubtypes = args.get("--include-subtypes", "true").lower() not in ("false", "0")
        bd.NodeClassMask = args.int("--node-class-mask", 0)
        bd.ResultMask = args.int("--result-mask", 63)
        p = ua.BrowseParameters()
        p.View = ua.ViewDescription()
        p.RequestedMaxReferencesPerNode = args.int("--max-refs", 0)
        p.NodesToBrowse = [bd]
        first = (await conn.session.browse(p))[0]
        refs = list(first.References or [])
        cp = first.ContinuationPoint
        while cp:
            np = ua.BrowseNextParameters()
            np.ReleaseContinuationPoints = False
            np.ContinuationPoints = [cp]
            nxt = (await conn.session.browse_next(np))[0]
            refs.extend(nxt.References or [])
            cp = nxt.ContinuationPoint
            if not is_good(nxt.StatusCode):
                break
        r.set_service(first.StatusCode)
        for rd in refs:
            bn = rd.BrowseName or ua.QualifiedName()
            dn = rd.DisplayName or ua.LocalizedText()
            r.add({
                "referenceTypeId": nodeid_str(rd.ReferenceTypeId),
                "isForward": bool(rd.IsForward),
                "nodeId": nodeid_str(local_nodeid(rd.NodeId)),
                "browseName": {"ns": int(bn.NamespaceIndex or 0), "name": bn.Name or ""},
                "displayName": {"locale": dn.Locale or "", "text": dn.Text or ""},
                "nodeClass": ua.NodeClass(rd.NodeClass).name if rd.NodeClass else "Unspecified",
            })
        if not is_good(first.StatusCode):
            r.success = False
            return 4
        return 0
    finally:
        await conn.close()


async def cmd_translate(args: Args, r: Result) -> int:
    start = args.get("--starting-node", "i=85")
    path = args.get("--path")
    if not path:
        raise InputError("missing --path")
    segs = [s for s in path.split(".") if s]
    if not segs:
        raise InputError("empty --path")
    ns = args.int("--namespace", 0)
    parse_nodeid_syntax(start)
    conn = Conn(args)
    await conn.connect()
    try:
        sid = await conn.resolve(start)
        rp = ua.RelativePath()
        rp.Elements = [
            ua.RelativePathElement(
                ReferenceTypeId=ua.NodeId(ua.ObjectIds.HierarchicalReferences),
                IsInverse=False,
                IncludeSubtypes=True,
                TargetName=ua.QualifiedName(s, ns),
            )
            for s in segs
        ]
        bp = ua.BrowsePath(StartingNode=sid, RelativePath=rp)
        res = (await conn.session.translate_browsepaths_to_nodeids([bp]))[0]
        r.add({"statusCode": status_json(res.StatusCode), "targets": [nodeid_str(local_nodeid(t.TargetId)) for t in res.Targets or []]})
        if not is_good(res.StatusCode):
            r.success = False
            return 4
        return 0
    finally:
        await conn.close()


async def cmd_call(args: Args, r: Result) -> int:
    obj, meth = args.get("--object"), args.get("--method")
    if not obj or not meth:
        raise InputError("missing --endpoint, --object, or --method")
    inputs = []
    for spec in args.all("--input"):
        t, sep, v = spec.partition(":")
        if sep:
            inputs.append(lenient_variant(t, v))
    parse_nodeid_syntax(obj)
    parse_nodeid_syntax(meth)
    conn = Conn(args)
    await conn.connect()
    try:
        oid, mid = await conn.resolve(obj), await conn.resolve(meth)
        req = ua.CallMethodRequest(ObjectId=oid, MethodId=mid, InputArguments=inputs)
        res = (await conn.session.call([req]))[0]
        r.set_service(res.StatusCode)
        r.add({
            "objectNodeId": nodeid_str(oid),
            "methodNodeId": nodeid_str(mid),
            "statusCode": status_json(res.StatusCode),
            "outputArguments": [variant_value(v) for v in res.OutputArguments or []],
        })
        if not is_good(res.StatusCode):
            r.success = False
            return 4
        return 0
    finally:
        await conn.close()


TRIGGERS = {
    "Status": ua.DataChangeTrigger.Status,
    "StatusValue": ua.DataChangeTrigger.StatusValue,
    "StatusValueTimestamp": ua.DataChangeTrigger.StatusValueTimestamp,
}


async def cmd_subscribe(args: Args, r: Result) -> int:
    node = args.get("--node")
    if not node:
        raise InputError("missing --endpoint or --node")
    pi = args.float("--publishing-interval-ms", 500.0)
    si = args.float("--sampling-interval-ms", 100.0)
    want = args.int("--notifications", 5)
    timeout_ms = args.int("--timeout-ms", 10000)
    qs = args.int("--queue-size", 1)
    discard = args.bool("--discard-oldest", True)
    ts = _timestamps(args)
    db_abs, db_pct, trig = args.get("--deadband-absolute"), args.get("--deadband-percent"), args.get("--trigger")
    use_filter = db_abs is not None or db_pct is not None or trig is not None
    flt = None
    trig_name = trig or "StatusValue"
    db_name = "Absolute" if db_abs is not None else "Percent" if db_pct is not None else "None"
    db_value = 0.0
    if use_filter:
        if db_abs is not None and db_pct is not None:
            raise InputError("--deadband-absolute and --deadband-percent are mutually exclusive")
        if trig_name not in TRIGGERS:
            raise InputError("--trigger must be Status, StatusValue or StatusValueTimestamp")
        try:
            db_value = float(db_abs if db_abs is not None else db_pct if db_pct is not None else 0.0)
        except ValueError:
            raise InputError("invalid deadband value")
        flt = ua.DataChangeFilter()
        flt.Trigger = TRIGGERS[trig_name]
        flt.DeadbandType = 1 if db_abs is not None else 2 if db_pct is not None else 0
        flt.DeadbandValue = db_value
    parse_nodeid_syntax(node)
    conn = Conn(args)
    await conn.connect()
    try:
        nid = await conn.resolve(node)
        sub = await Sub(conn).create(pi)
        mres = await sub.monitor(nid, sampling=si, queue=max(1, qs), discard=discard, flt=flt, ts=ts)
        notes: list[dict] = []
        timed_out = False
        if is_good(mres.StatusCode):
            deadline = time.monotonic() + timeout_ms / 1000.0
            while len(notes) < want:
                pr = await sub.next(deadline - time.monotonic())
                if pr is None:
                    timed_out = True
                    break
                for dv in _datachanges(pr, 1):
                    if len(notes) >= want:
                        break
                    item = {"sequenceNumber": len(notes) + 1}
                    item.update(variant_fields(dv.Value))
                    item["statusCode"] = status_json(dv.StatusCode)
                    if ts_present(dv.SourceTimestamp):
                        item["sourceTimestamp"] = fmt_datetime(dv.SourceTimestamp)
                    if ts_present(dv.ServerTimestamp):
                        item["serverTimestamp"] = fmt_datetime(dv.ServerTimestamp)
                    notes.append(item)
        res = sub.result
        item = {
            "nodeId": nodeid_str(nid),
            "subscriptionId": int(res.SubscriptionId),
            "revisedPublishingInterval": float(res.RevisedPublishingInterval),
            "revisedLifetimeCount": int(res.RevisedLifetimeCount),
            "revisedMaxKeepAliveCount": int(res.RevisedMaxKeepAliveCount),
            "monitoredItemStatusCode": status_json(mres.StatusCode),
        }
        if use_filter:
            item["monitoredItemId"] = int(mres.MonitoredItemId or 0)
            item["revisedSamplingInterval"] = float(mres.RevisedSamplingInterval or 0.0)
            item["revisedQueueSize"] = int(mres.RevisedQueueSize or 0)
            item["filter"] = {"trigger": trig_name, "deadbandType": db_name, "deadbandValue": db_value}
            fr = mres.FilterResult
            if fr is None or (isinstance(fr, ua.ExtensionObject) and fr.TypeId.Identifier == 0):
                item["filterResult"] = None
            else:
                tid = fr.TypeId if isinstance(fr, ua.ExtensionObject) else ua.extension_object_typeids.get(type(fr).__name__)
                item["filterResult"] = {"typeId": nodeid_str(tid) if tid is not None else type(fr).__name__}
        item["notifications"] = notes
        r.add(item)
        r.set_service(mres.StatusCode)
        await sub.delete()
        if timed_out:
            r.fail("timeout", "timeout waiting for notifications")
            return 7
        if not is_good(mres.StatusCode):
            r.fail("service", "CreateMonitoredItems rejected the monitored item")
            return 4
        return 0
    finally:
        await conn.close()


async def _set_publishing(conn: Conn, sub: Sub, enabled: bool):
    p = ua.SetPublishingModeParameters()
    p.PublishingEnabled = enabled
    p.SubscriptionIds = [sub.id]
    return await conn.session.set_publishing_mode(p)


async def _set_monitoring(conn: Conn, sub: Sub, mid: int, mode: ua.MonitoringMode):
    p = ua.SetMonitoringModeParameters()
    p.SubscriptionId = sub.id
    p.MonitoringMode = mode
    p.MonitoredItemIds = [mid]
    return await conn.session.set_monitoring_mode(p)


async def _drain(sub: Sub, seconds: float, handle: int = 1) -> list[ua.DataValue]:
    out = []
    deadline = time.monotonic() + seconds
    while True:
        rem = deadline - time.monotonic()
        if rem <= 0:
            break
        pr = await sub.next(rem)
        if pr is None:
            break
        out.extend(_datachanges(pr, handle))
    return out


async def cmd_subscription_lifecycle(args: Args, r: Result) -> int:
    node, scenario = args.get("--node"), args.get("--scenario")
    if not node or not scenario:
        raise InputError("missing --endpoint, --node, or --scenario")
    if scenario not in ("revise", "publishing-mode", "monitoring-mode", "delete"):
        raise InputError(f"unknown scenario: {scenario}")
    timeout_ms = args.int("--timeout-ms", 15000)
    collect = max(2.0, min(timeout_ms / 1000.0 - 2.0, 5.0))
    parse_nodeid_syntax(node)
    conn = Conn(args)
    await conn.connect()
    try:
        nid = await conn.resolve(node)
        if scenario == "revise":
            sub = await Sub(conn).create(1.0, lifetime=5, keepalive=10)
            res = sub.result
            await sub.delete()
            rpi, rlt, rmk = float(res.RevisedPublishingInterval), int(res.RevisedLifetimeCount), int(res.RevisedMaxKeepAliveCount)
            ok = rlt >= 3 * rmk and rpi >= 10.0
            r.add({
                "subscriptionId": int(res.SubscriptionId),
                "requestedPublishingInterval": 1,
                "requestedLifetimeCount": 5,
                "requestedMaxKeepAliveCount": 10,
                "revisedPublishingInterval": rpi,
                "revisedLifetimeCount": rlt,
                "revisedMaxKeepAliveCount": rmk,
            })
            r.success = ok
            return 0 if ok else 4

        if scenario == "publishing-mode":
            sub = await Sub(conn).create(500.0)
            m = await sub.monitor(nid, sampling=0.0, queue=3, discard=True, ts=ua.TimestampsToReturn.Source)
            if not is_good(m.StatusCode):
                await sub.delete()
                r.set_service(m.StatusCode).fail("service", "CreateMonitoredItem failed")
                return 4
            await _drain(sub, 0.5)  # initial value
            await _set_publishing(conn, sub, False)
            for v in range(1, 6):
                await _write_int32(conn, nid, v)
            await asyncio.sleep(0.2)
            await _set_publishing(conn, sub, True)
            dvs = await _drain(sub, collect)
            await sub.delete()
            values = []
            overflow = False
            for dv in dvs:
                if dv.Value is not None and dv.Value.VariantType == ua.VariantType.Int32:
                    values.append(int(dv.Value.Value))
                if sc_value(dv.StatusCode) & 0x480:
                    overflow = True
            if len(values) < 5:
                overflow = True
            ok = values[-3:] == [3, 4, 5] if len(values) >= 3 else (bool(values) and values[-1] == 5)
            res = sub.result
            r.add({
                "subscriptionId": sub.id,
                "revisedPublishingInterval": float(res.RevisedPublishingInterval),
                "revisedLifetimeCount": int(res.RevisedLifetimeCount),
                "revisedMaxKeepAliveCount": int(res.RevisedMaxKeepAliveCount),
                "overflow": overflow,
                "values": values,
            })
            r.success = ok
            return 0 if ok else 4

        if scenario == "monitoring-mode":
            sub = await Sub(conn).create(100.0)
            m = await sub.monitor(nid, sampling=0.0, queue=5, discard=True, ts=ua.TimestampsToReturn.Source)
            if not is_good(m.StatusCode):
                await sub.delete()
                r.set_service(m.StatusCode).fail("service", "CreateMonitoredItem failed")
                return 4
            mid = int(m.MonitoredItemId)
            await _drain(sub, 0.5)
            await _set_monitoring(conn, sub, mid, ua.MonitoringMode.Disabled)
            await _write_int32(conn, nid, 100)
            disabled = len(await _drain(sub, 0.3))
            await _set_monitoring(conn, sub, mid, ua.MonitoringMode.Sampling)
            await _write_int32(conn, nid, 101)
            await _write_int32(conn, nid, 102)
            sampling = len(await _drain(sub, 0.3))
            await _set_monitoring(conn, sub, mid, ua.MonitoringMode.Reporting)
            await _write_int32(conn, nid, 103)
            reporting = len(await _drain(sub, collect))
            await sub.delete()
            ok = disabled == 0 and reporting >= 1
            r.add({
                "subscriptionId": sub.id,
                "modeSteps": [
                    {"mode": "Disabled", "notificationCount": disabled},
                    {"mode": "Sampling", "notificationCount": sampling},
                    {"mode": "Reporting", "notificationCount": reporting},
                ],
            })
            r.success = ok
            return 0 if ok else 4

        # delete
        sub = await Sub(conn).create(500.0)
        m = await sub.monitor(nid, sampling=100.0, queue=1, ts=ua.TimestampsToReturn.Source)
        if not is_good(m.StatusCode):
            await sub.delete()
            r.set_service(m.StatusCode).fail("service", "CreateMonitoredItem failed")
            return 4
        mid = int(m.MonitoredItemId)

        async def del_mi():
            p = ua.DeleteMonitoredItemsParameters()
            p.SubscriptionId = sub.id
            p.MonitoredItemIds = [mid]
            try:
                res = await conn.session.delete_monitored_items(p)
                return res[0] if res else ua.StatusCode()
            except UaStatusCodeError as e:
                return ua.StatusCode(e.code)

        async def del_sub():
            try:
                res = await conn.session.delete_subscriptions([sub.id])
                return res[0] if res else ua.StatusCode()
            except UaStatusCodeError as e:
                return ua.StatusCode(e.code)

        m1, m2 = await del_mi(), await del_mi()
        s1, s2 = await del_sub(), await del_sub()
        ok = is_bad(m2) and is_bad(s2)
        r.add({
            "subscriptionId": sub.id,
            "deleteMonitoredItem": {"first": status_json(m1), "second": status_json(m2)},
            "deleteSubscription": {"first": status_json(s1), "second": status_json(s2)},
        })
        r.success = ok
        return 0 if ok else 4
    finally:
        await conn.close()


EVENT_FIELDS = ["EventId", "EventType", "SourceName", "Message", "Severity", "Time"]


async def cmd_event_subscribe(args: Args, r: Result) -> int:
    node = args.get("--node")
    if not node:
        raise InputError("missing --endpoint or --node")
    pi = args.float("--publishing-interval-ms", 500.0)
    want = args.int("--events", 1)
    timeout_ms = args.int("--timeout-ms", 10000)
    qs = args.int("--queue-size", 10)
    of_type, min_sev = args.get("--of-type"), args.get("--min-severity")
    parse_nodeid_syntax(node)
    if of_type:
        parse_nodeid_syntax(of_type)
    if min_sev is not None:
        try:
            min_sev_v = int(min_sev)
        except ValueError:
            raise InputError("--min-severity must be an integer")
    conn = Conn(args)
    await conn.connect()
    try:
        nid = await conn.resolve(node)
        ef = ua.EventFilter()
        ef.SelectClauses = [
            ua.SimpleAttributeOperand(
                TypeDefinitionId=ua.NodeId(ua.ObjectIds.BaseEventType),
                BrowsePath=[ua.QualifiedName(f, 0)],
                AttributeId=ua.AttributeIds.Value,
            )
            for f in EVENT_FIELDS
        ]
        elements = []
        if of_type:
            tid = await conn.resolve(of_type)
            elements.append(ua.ContentFilterElement(
                FilterOperator=ua.FilterOperator.OfType,
                FilterOperands=[ua.LiteralOperand(Value=ua.Variant(tid, ua.VariantType.NodeId))],
            ))
        if min_sev is not None:
            elements.append(ua.ContentFilterElement(
                FilterOperator=ua.FilterOperator.GreaterThanOrEqual,
                FilterOperands=[
                    ua.SimpleAttributeOperand(
                        TypeDefinitionId=ua.NodeId(ua.ObjectIds.BaseEventType),
                        BrowsePath=[ua.QualifiedName("Severity", 0)],
                        AttributeId=ua.AttributeIds.Value,
                    ),
                    ua.LiteralOperand(Value=ua.Variant(min_sev_v, ua.VariantType.UInt16)),
                ],
            ))
        if len(elements) == 2:
            elements.append(ua.ContentFilterElement(
                FilterOperator=ua.FilterOperator.And,
                FilterOperands=[ua.ElementOperand(Index=0), ua.ElementOperand(Index=1)],
            ))
        ef.WhereClause = ua.ContentFilter(Elements=elements)
        sub = await Sub(conn).create(pi)
        m = await sub.monitor(nid, sampling=0.0, queue=max(1, qs), discard=True, flt=ef, attr=ua.AttributeIds.EventNotifier)
        events = []
        timed_out = False
        if is_good(m.StatusCode):
            deadline = time.monotonic() + timeout_ms / 1000.0
            while len(events) < want:
                pr = await sub.next(deadline - time.monotonic())
                if pr is None:
                    timed_out = True
                    break
                for fields in _events(pr, 1):
                    if len(events) >= want:
                        break
                    out = []
                    for name, v in zip(EVENT_FIELDS, fields):
                        f = {"name": name}
                        f.update(variant_fields(v))
                        out.append(f)
                    events.append({"sequenceNumber": len(events) + 1, "fields": out})
        await sub.delete()
        r.add({
            "nodeId": nodeid_str(nid),
            "subscriptionId": sub.id,
            "revisedPublishingInterval": float(sub.result.RevisedPublishingInterval),
            "monitoredItemStatusCode": status_json(m.StatusCode),
            "selectClauses": EVENT_FIELDS,
            "events": events,
        })
        r.set_service(m.StatusCode)
        if timed_out:
            r.fail("timeout", "timeout waiting for events")
            return 7
        if not is_good(m.StatusCode):
            r.fail("service", "CreateMonitoredItems rejected the event monitored item")
            return 4
        return 0
    finally:
        await conn.close()


# ── alarms (Part 9: ConditionRefresh, Acknowledge, Confirm, AddComment) ─────────

# (TypeDefinitionId, BrowsePath, AttributeId) in the contract's order (§4 `alarms`).
_BASE_EVENT, _CONDITION, _ACKABLE, _ALARM = 2041, 2782, 2881, 2915
ALARM_SELECT = [
    (_BASE_EVENT, ["EventId"], ua.AttributeIds.Value),
    (_BASE_EVENT, ["EventType"], ua.AttributeIds.Value),
    (_BASE_EVENT, ["SourceNode"], ua.AttributeIds.Value),
    (_BASE_EVENT, ["SourceName"], ua.AttributeIds.Value),
    (_BASE_EVENT, ["Time"], ua.AttributeIds.Value),
    (_BASE_EVENT, ["Message"], ua.AttributeIds.Value),
    (_BASE_EVENT, ["Severity"], ua.AttributeIds.Value),
    (_CONDITION, ["ConditionName"], ua.AttributeIds.Value),
    (_CONDITION, ["BranchId"], ua.AttributeIds.Value),
    (_CONDITION, ["Retain"], ua.AttributeIds.Value),
    (_CONDITION, ["EnabledState", "Id"], ua.AttributeIds.Value),
    (_CONDITION, ["Comment"], ua.AttributeIds.Value),
    (_ACKABLE, ["AckedState", "Id"], ua.AttributeIds.Value),
    (_ACKABLE, ["ConfirmedState", "Id"], ua.AttributeIds.Value),
    (_ALARM, ["ActiveState", "Id"], ua.AttributeIds.Value),
    (_CONDITION, [], ua.AttributeIds.NodeId),  # ConditionId (Part 9 §5.5.2)
]
REFRESH_START, REFRESH_END = 2787, 2788
CONDITION_TYPE, CONDITION_REFRESH = 2782, 3875
METHOD_ACKNOWLEDGE, METHOD_CONFIRM, METHOD_ADD_COMMENT = 9111, 9113, 9029
BAD_NODEID_UNKNOWN = 0x80340000


def _presence_flag(args: Args, flag: str) -> bool:
    """`--acknowledge` alone, or `--acknowledge true|false`."""
    if not args.has(flag):
        return False
    i = args.argv.index(flag)
    nxt = args.argv[i + 1].lower() if i + 1 < len(args.argv) else ""
    if nxt in ("false", "0", "no"):
        return False
    return True


def _field(fields, i):
    if i >= len(fields):
        return None
    v = fields[i]
    if v is None or v.Value is None or v.VariantType in (ua.VariantType.Null, ua.VariantType.StatusCode):
        return None
    if isinstance(v.Value, (list, tuple)):
        return None
    return v


def _f_nodeid(fields, i):
    v = _field(fields, i)
    if v is None or not isinstance(v.Value, ua.NodeId):
        return None
    return nodeid_str(v.Value)


def _f_type(fields, i, vt, conv):
    v = _field(fields, i)
    if v is None or v.VariantType != vt:
        return None
    return conv(v.Value)


def _f_text(fields, i):
    v = _field(fields, i)
    if v is None:
        return None
    if isinstance(v.Value, ua.LocalizedText):
        return v.Value.Text
    if isinstance(v.Value, str):
        return v.Value
    return None


def _b64(b) -> str:
    return base64.b64encode(bytes(b)).decode("ascii")


def _condition_entry(fields) -> dict:
    """ConditionEntry of the contract (§4 `alarms`), from the 16 select clauses."""
    return {
        "conditionId": _f_nodeid(fields, 15),
        "eventId": _f_type(fields, 0, ua.VariantType.ByteString, _b64),
        "eventType": _f_nodeid(fields, 1),
        "sourceNode": _f_nodeid(fields, 2),
        "sourceName": _f_type(fields, 3, ua.VariantType.String, str),
        "conditionName": _f_type(fields, 7, ua.VariantType.String, str),
        # the OPC UA null DateTime (1601-01-01, encoded 0) is null
        "time": _f_type(fields, 4, ua.VariantType.DateTime, lambda d: fmt_datetime(d) if d is not None and d.year > 1601 else None),
        "message": _f_text(fields, 5),
        "severity": _f_type(fields, 6, ua.VariantType.UInt16, int),
        "retain": _f_type(fields, 9, ua.VariantType.Boolean, bool),
        "enabled": _f_type(fields, 10, ua.VariantType.Boolean, bool),
        "acked": _f_type(fields, 12, ua.VariantType.Boolean, bool),
        "confirmed": _f_type(fields, 13, ua.VariantType.Boolean, bool),
        "active": _f_type(fields, 14, ua.VariantType.Boolean, bool),
        "comment": _f_text(fields, 11),
    }


def _event_type_id(fields):
    v = _field(fields, 1)
    if v is None or not isinstance(v.Value, ua.NodeId):
        return None
    nid = v.Value
    if int(nid.NamespaceIndex or 0) != 0 or not isinstance(nid.Identifier, int):
        return None
    return nid.Identifier


async def cmd_alarms(args: Args, r: Result) -> int:
    node = args.get("--node", "i=2253")
    cond_name = args.get("--condition-name")
    do_ack = _presence_flag(args, "--acknowledge")
    do_confirm = _presence_flag(args, "--confirm")
    do_comment = _presence_flag(args, "--add-comment")
    comment = args.get("--comment", "interop-comment")
    timeout_ms = args.int("--timeout-ms", 15000)
    pi = args.float("--publishing-interval-ms", 200.0)
    parse_nodeid_syntax(node)
    conn = Conn(args)
    await conn.connect()
    try:
        nid = await conn.resolve(node)
        deadline = time.monotonic() + timeout_ms / 1000.0
        ef = ua.EventFilter()
        ef.SelectClauses = [
            ua.SimpleAttributeOperand(
                TypeDefinitionId=ua.NodeId(tid),
                BrowsePath=[ua.QualifiedName(p, 0) for p in path],
                AttributeId=attr,
            )
            for tid, path, attr in ALARM_SELECT
        ]
        ef.WhereClause = ua.ContentFilter(Elements=[])
        sub = await Sub(conn).create(pi)
        m = await sub.monitor(nid, sampling=0.0, queue=1000, discard=True, flt=ef, attr=ua.AttributeIds.EventNotifier)
        item = {
            "nodeId": nodeid_str(nid),
            "subscriptionId": sub.id,
            "monitoredItemStatusCode": status_json(m.StatusCode),
            "refresh": {"statusCode": status_json(m.StatusCode), "startSeen": False, "endSeen": False},
            "conditions": [],
            "target": None,
            "acknowledge": None,
            "confirm": None,
            "addComment": None,
        }
        r.add(item)
        if not is_good(m.StatusCode):
            await sub.delete()
            r.set_service(m.StatusCode).fail("service", "CreateMonitoredItems rejected the event monitored item")
            return 4

        # Every received event in arrival order: (fields, ConditionEntry); the
        # latest ConditionEntry per ConditionId (its EventId is used for the methods).
        received: list[tuple[list, dict]] = []
        latest: dict[str, dict] = {}

        async def pump() -> bool:
            pr = await sub.next(deadline - time.monotonic())
            if pr is None:
                return False
            for fields in _events(pr, 1):
                fields = list(fields)
                entry = _condition_entry(fields)
                received.append((fields, entry))
                if entry["conditionId"] is not None:
                    latest[entry["conditionId"]] = entry
            return True

        async def wait_for(idx: int, pred) -> dict | None:
            while True:
                while idx < len(received):
                    e = received[idx][1]
                    idx += 1
                    if pred(e):
                        return e
                if not await pump():
                    return None

        async def call(obj: ua.NodeId, method: int, inputs: list) -> ua.StatusCode:
            req = ua.CallMethodRequest(ObjectId=obj, MethodId=ua.NodeId(method), InputArguments=inputs)
            try:
                return (await conn.session.call([req]))[0].StatusCode
            except UaStatusCodeError as e:
                return ua.StatusCode(e.code)

        # ConditionRefresh (Part 9 §5.5.7) on ConditionType.
        idx = len(received)
        refresh_sc = await call(
            ua.NodeId(CONDITION_TYPE), CONDITION_REFRESH, [ua.Variant(sub.id, ua.VariantType.UInt32)]
        )
        refresh = {"statusCode": status_json(refresh_sc), "startSeen": False, "endSeen": False}
        item["refresh"] = refresh
        if not is_good(refresh_sc):
            await sub.delete()
            r.set_service(refresh_sc).fail("service", "ConditionRefresh failed")
            return 4
        conditions: dict[str, dict] = {}  # first-seen order, last event wins
        while not refresh["endSeen"]:
            while idx < len(received) and not refresh["endSeen"]:
                fields, e = received[idx]
                idx += 1
                et = _event_type_id(fields)
                if et == REFRESH_START:
                    refresh["startSeen"] = True
                elif et == REFRESH_END:
                    refresh["endSeen"] = True
                elif e["conditionId"] is not None:
                    conditions[e["conditionId"]] = e
            if not refresh["endSeen"] and not await pump():
                break
        item["conditions"] = list(conditions.values())
        if not refresh["endSeen"]:
            await sub.delete()
            r.set_service(BAD_TIMEOUT).fail("timeout", "timeout waiting for the RefreshEndEvent")
            return 7

        target = None
        for e in item["conditions"]:
            if (e["conditionName"] == cond_name) if cond_name is not None else (e["retain"] is True):
                target = e
                break
        item["target"] = target
        actions = []
        if do_ack:
            actions.append(("acknowledge", METHOD_ACKNOWLEDGE, lambda e: e["acked"] is True))
        if do_confirm:
            actions.append(("confirm", METHOD_CONFIRM, lambda e: e["confirmed"] is True))
        if do_comment:
            actions.append(("addComment", METHOD_ADD_COMMENT, lambda e: e["comment"] == comment))
        if target is None:
            await sub.delete()
            if actions:
                r.set_service(BAD_NODEID_UNKNOWN).fail("service", "no matching condition in the ConditionRefresh")
                return 4
            return 0

        cid_str = target["conditionId"]
        cid = await conn.resolve(cid_str)
        lt = ua.LocalizedText(Text=comment, Locale="en")
        for key, method, pred in actions:
            e_latest = latest.get(cid_str, target)
            eid = base64.b64decode(e_latest["eventId"]) if e_latest["eventId"] else b""
            mark = len(received)
            inputs = [ua.Variant(eid, ua.VariantType.ByteString), ua.Variant(lt, ua.VariantType.LocalizedText)]
            sc = await call(cid, method, inputs)
            out = {"statusCode": status_json(sc), "event": None}
            if key == "acknowledge":
                out["repeatStatusCode"] = None
            item[key] = out
            if not is_good(sc):
                await sub.delete()
                r.set_service(sc).fail("service", f"{key} failed")
                return 4
            ev = await wait_for(mark, lambda e: e["conditionId"] == cid_str and pred(e))
            out["event"] = ev
            if key == "acknowledge":
                # The same (now stale) EventId again: BadConditionBranchAlreadyAcked / BadEventIdUnknown.
                out["repeatStatusCode"] = status_json(await call(cid, method, inputs))
            if ev is None:
                await sub.delete()
                r.set_service(BAD_TIMEOUT).fail("timeout", f"timeout waiting for the {key} event")
                return 7
        await sub.delete()
        return 0
    finally:
        await conn.close()


async def _history_page(conn: Conn, nid, start, end, num, bounds, ts, cp: bytes | None, release: bool):
    d = ua.ReadRawModifiedDetails()
    d.IsReadModified = False
    d.StartTime = start
    d.EndTime = end
    d.NumValuesPerNode = max(0, num)
    d.ReturnBounds = bounds
    p = ua.HistoryReadParameters()
    p.HistoryReadDetails = d
    p.TimestampsToReturn = ts
    p.ReleaseContinuationPoints = release
    p.NodesToRead = [ua.HistoryReadValueId(NodeId=nid, ContinuationPoint=cp)]
    svc = ua.StatusCode()
    item_sc = ua.StatusCode()
    cp_out = None
    values = []
    try:
        res = await conn.session.history_read(p)
    except UaStatusCodeError as e:
        return ua.StatusCode(e.code), item_sc, None, []
    if res:
        h = res[0]
        item_sc = h.StatusCode or ua.StatusCode()
        if h.ContinuationPoint:
            cp_out = base64.b64encode(h.ContinuationPoint).decode()
        data = h.HistoryData
        for dv in getattr(data, "DataValues", None) or []:
            values.append(_dv_item(dv))
    return svc, item_sc, cp_out, values


async def cmd_history_read(args: Args, r: Result) -> int:
    node, start_s, end_s = args.get("--node"), args.get("--start"), args.get("--end")
    if not node or not start_s or not end_s:
        raise InputError("missing --endpoint, --node, --start, or --end [--scenario continue]")
    try:
        start, end = parse_datetime(start_s), parse_datetime(end_s)
    except ValueError as e:
        raise InputError(f"invalid --start / --end: {e}")
    num = args.int("--num-values", 0)
    cp_s = args.get("--continuation-point")
    release = args.bool("--release-continuation-point", False)
    bounds = args.bool("--return-bounds", False)
    scenario = args.get("--scenario")
    if scenario is not None and scenario != "continue":
        raise InputError(f"unknown --scenario {scenario}")
    ts = _timestamps(args)
    cp = None
    if cp_s:
        try:
            cp = base64.b64decode(cp_s, validate=True)
        except Exception:
            raise InputError("--continuation-point is not Base64")
    parse_nodeid_syntax(node)
    conn = Conn(args)
    await conn.connect()
    try:
        nid = await conn.resolve(node)
        if scenario == "continue":
            if num <= 0:
                num = 2
            pages = []
            last_svc, last_item = ua.StatusCode(), ua.StatusCode()
            cur = None
            for _ in range(8):
                svc, item_sc, cp_out, values = await _history_page(conn, nid, start, end, num, bounds, ts, cur, False)
                last_svc, last_item = svc, item_sc
                pages.append({"values": values, "continuationPoint": cp_out, "statusCode": status_json(item_sc)})
                if not is_good(svc) or not is_good(item_sc) or not cp_out:
                    break
                cur = base64.b64decode(cp_out)
            release_sc, reuse_sc = ua.StatusCode(), ua.StatusCode()
            if cur is not None and pages[-1]["continuationPoint"]:
                cur = base64.b64decode(pages[-1]["continuationPoint"])
            last_cp = next((p["continuationPoint"] for p in reversed(pages) if p["continuationPoint"]), None)
            if last_cp:
                lc = base64.b64decode(last_cp)
                svc, item_sc, _, _ = await _history_page(conn, nid, start, end, num, bounds, ts, lc, True)
                release_sc = item_sc if is_good(svc) else svc
                svc, item_sc, _, _ = await _history_page(conn, nid, start, end, num, bounds, ts, lc, False)
                reuse_sc = item_sc if is_good(svc) else svc
            else:
                svc, item_sc, _, _ = await _history_page(conn, nid, start, end, num, bounds, ts, None, True)
                release_sc = item_sc if is_good(svc) else svc
            ok = is_good(last_svc) and is_good(last_item) and bool(pages)
            r.add({
                "scenario": "continue",
                "nodeId": nodeid_str(nid),
                "pages": pages,
                "releaseStatusCode": status_json(release_sc),
                "reuseAfterReleaseStatusCode": status_json(reuse_sc),
            })
            r.set_service(last_item if is_good(last_svc) else last_svc)
            r.success = ok
            return 0 if ok else 4
        svc, item_sc, cp_out, values = await _history_page(conn, nid, start, end, num, bounds, ts, cp, release)
        r.add({"nodeId": nodeid_str(nid), "statusCode": status_json(item_sc), "continuationPoint": cp_out, "values": values})
        ok = is_good(svc) and is_good(item_sc)
        r.set_service(item_sc if is_good(svc) else svc)
        r.success = ok
        return 0 if ok else 4
    finally:
        await conn.close()


async def cmd_republish(args: Args, r: Result) -> int:
    sid, seq = args.get("--subscription-id"), args.get("--sequence-number")
    if sid is None or seq is None:
        raise InputError("missing --endpoint, --subscription-id, or --sequence-number")
    sid_i, seq_i = args.int("--subscription-id", 0), args.int("--sequence-number", 0)
    conn = Conn(args)
    await conn.connect()
    try:
        item = {"subscriptionId": sid_i, "retransmitSequenceNumber": seq_i}
        try:
            nm = await conn.session.republish(sid_i, seq_i)
        except UaStatusCodeError as e:
            r.add(item)
            r.set_service(e.code)
            r.success = False
            return 4
        item["sequenceNumber"] = int(nm.SequenceNumber or 0)
        if ts_present(nm.PublishTime):
            item["publishTime"] = fmt_datetime(nm.PublishTime)
        item["notificationDataCount"] = len(nm.NotificationData or [])
        r.add(item)
        return 0
    finally:
        await conn.close()


async def cmd_transfer_subscriptions(args: Args, r: Result) -> int:
    ids = args.all("--subscription-id")
    if not ids:
        raise InputError("missing --endpoint or --subscription-id")
    try:
        sids = [int(s) for s in ids]
    except ValueError:
        raise InputError("--subscription-id must be an integer")
    conn = Conn(args)
    await conn.connect()
    try:
        p = ua.TransferSubscriptionsParameters()
        p.SubscriptionIds = sids
        p.SendInitialValues = args.bool("--send-initial-values", False)
        try:
            res = await conn.session.transfer_subscriptions(p)
        except UaStatusCodeError as e:
            r.set_service(e.code)
            r.success = False
            return 4
        ok = True
        for sid, tr in zip(sids, res or []):
            sc = tr.StatusCode or ua.StatusCode()
            if not is_good(sc):
                ok = False
            r.add({"subscriptionId": sid, "statusCode": status_json(sc), "availableSequenceNumbers": [int(x) for x in tr.AvailableSequenceNumbers or []]})
        r.success = ok
        return 0 if ok else 4
    finally:
        await conn.close()


async def cmd_register_nodes(args: Args, r: Result) -> int:
    nodes = args.all("--node")
    if not nodes:
        raise InputError("missing --endpoint or --node")
    for n in nodes:
        parse_nodeid_syntax(n)
    conn = Conn(args)
    await conn.connect()
    try:
        ids = [await conn.resolve(n) for n in nodes]
        reg = await conn.session.register_nodes(ids)
        if len(reg) != len(ids):
            r.set_service(BAD_UNEXPECTED).fail("service", "RegisterNodes returned an unexpected number of ids")
            return 4
        p = ua.ReadParameters()
        p.TimestampsToReturn = ua.TimestampsToReturn.Source
        p.NodesToRead = [ua.ReadValueId(NodeId=x, AttributeId=ua.AttributeIds.Value) for x in reg]
        dvs = await conn.session.read(p)
        try:
            await conn.session.unregister_nodes(reg)
            unreg = ua.StatusCode()
        except UaStatusCodeError as e:
            unreg = ua.StatusCode(e.code)
        first_bad = None if is_good(unreg) else unreg
        for nid, rid, dv in zip(ids, reg, dvs):
            item = {"nodeId": nodeid_str(nid), "registeredNodeId": nodeid_str(rid), "statusCode": status_json(dv.StatusCode)}
            if is_good(dv.StatusCode):
                item.update(variant_fields(dv.Value))
            elif first_bad is None:
                first_bad = dv.StatusCode
            item["unregisterStatusCode"] = status_json(unreg)
            r.add(item)
        if first_bad is not None:
            r.set_service(first_bad)
            r.success = False
            return 4
        return 0
    finally:
        await conn.close()


async def cmd_node_management(args: Args, r: Result) -> int:
    parent, node = args.get("--parent"), args.get("--node")
    if not parent or not node:
        raise InputError("missing --endpoint, --parent or --node")
    bname = args.get("--browse-name", "InteropAdded")
    value = args.int("--value", 42)
    parse_nodeid_syntax(parent)
    parse_nodeid_syntax(node)
    conn = Conn(args)
    await conn.connect()
    try:
        pid, nid = await conn.resolve(parent), await conn.resolve(node)
        attrs = ua.VariableAttributes()
        attrs.DisplayName = ua.LocalizedText(bname, "en")
        attrs.Value = ua.Variant(value, ua.VariantType.Int32)
        attrs.DataType = ua.NodeId(ua.ObjectIds.Int32)
        attrs.ValueRank = -1
        attrs.AccessLevel = 3
        attrs.UserAccessLevel = 3
        item = ua.AddNodesItem()
        item.ParentNodeId = pid
        item.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HasComponent)
        item.RequestedNewNodeId = nid
        item.BrowseName = ua.QualifiedName(bname, nid.NamespaceIndex)
        item.NodeClass = ua.NodeClass.Variable
        item.NodeAttributes = attrs
        item.TypeDefinition = ua.NodeId(ua.ObjectIds.BaseDataVariableType)
        try:
            res = await conn.session.add_nodes([item])
        except UaStatusCodeError as e:
            r.set_service(e.code).fail("service", "AddNodes failed")
            return 4
        add_sc = res[0].StatusCode if res else ua.StatusCode(BAD_UNEXPECTED)
        out = {"parentNodeId": nodeid_str(pid), "requestedNodeId": nodeid_str(nid), "addStatusCode": status_json(add_sc)}
        ok = False
        emit = add_sc
        if is_good(add_sc):
            added = res[0].AddedNodeId
            out["addedNodeId"] = nodeid_str(added)
            rp = ua.ReadParameters()
            rp.TimestampsToReturn = ua.TimestampsToReturn.Source
            rp.NodesToRead = [ua.ReadValueId(NodeId=added, AttributeId=ua.AttributeIds.Value)]
            dv = (await conn.session.read(rp))[0]
            out["readStatusCode"] = status_json(dv.StatusCode)
            matches = False
            if is_good(dv.StatusCode):
                out.update(variant_fields(dv.Value))
                matches = dv.Value is not None and dv.Value.VariantType == ua.VariantType.Int32 and dv.Value.Value == value
            dp = ua.DeleteNodesParameters()
            dp.NodesToDelete = [ua.DeleteNodesItem(NodeId=added, DeleteTargetReferences=True)]
            try:
                dres = await conn.session.delete_nodes(dp)
                del_sc = dres[0] if dres else ua.StatusCode(BAD_UNEXPECTED)
            except UaStatusCodeError as e:
                del_sc = ua.StatusCode(e.code)
            out["deleteStatusCode"] = status_json(del_sc)
            gone = (await conn.session.read(rp))[0]
            out["readAfterDeleteStatusCode"] = status_json(gone.StatusCode)
            ok = is_good(dv.StatusCode) and matches and is_good(del_sc) and is_bad(gone.StatusCode)
            if not is_good(dv.StatusCode):
                emit = dv.StatusCode
            elif not is_good(del_sc):
                emit = del_sc
        r.add(out)
        r.set_service(emit)
        r.success = ok
        return 0 if ok else 4
    finally:
        await conn.close()


async def _sessionless(conn: Conn, op):
    c = conn._new_client()
    try:
        return await asyncio.wait_for(c._with_temp_channel(lambda: op(c)), conn.cto + conn.rto)
    except (OSError, ConnectionError) as e:
        raise TransportError(f"cannot connect to {conn.endpoint}: {e}")
    except asyncio.TimeoutError:
        raise TransportError(f"timeout connecting to {conn.endpoint}", BAD_TIMEOUT)


async def cmd_find_servers_on_network(args: Args, r: Result) -> int:
    conn = Conn(args)
    p = ua.FindServersOnNetworkParameters()
    p.StartingRecordId = args.int("--starting-record-id", 0)
    p.MaxRecordsToReturn = args.int("--max-records", 0)
    p.ServerCapabilityFilter = args.all("--capability")
    try:
        res = await _sessionless(conn, lambda c: c.uaclient.find_servers_on_network(p))
    except UaStatusCodeError as e:
        r.set_service(e.code).fail("service", "FindServersOnNetwork failed")
        return 4
    reset = fmt_datetime(res.LastCounterResetTime) if ts_present(res.LastCounterResetTime) else None
    for s in res.Servers or []:
        item = {
            "recordId": int(s.RecordId),
            "serverName": s.ServerName or "",
            "discoveryUrl": s.DiscoveryUrl or "",
            "serverCapabilities": list(s.ServerCapabilities or []),
        }
        if reset:
            item["lastCounterResetTime"] = reset
        r.add(item)
    return 0


async def cmd_register_server(args: Args, r: Result) -> int:
    uri, urls = args.get("--server-uri"), args.all("--discovery-url")
    if not uri or not urls:
        raise InputError(
            "usage: register-server --endpoint <lds-url> --server-uri <uri> --discovery-url <url> [...]"
        )
    name = args.get("--server-name", uri)
    locale = args.get("--server-name-locale", "en")
    service = args.get("--service", "auto")
    if service not in ("auto", "RegisterServer2", "RegisterServer"):
        raise InputError("invalid --service")
    types = {"Server": 0, "Client": 1, "ClientAndServer": 2, "DiscoveryServer": 3}
    st = args.get("--server-type", "Server")
    if st not in types:
        raise InputError("invalid --server-type")
    online = args.bool("--online", True)
    rs = ua.RegisteredServer()
    rs.ServerUri = uri
    rs.ProductUri = args.get("--product-uri", "")
    rs.ServerNames = [ua.LocalizedText(name, locale)]
    rs.ServerType = ua.ApplicationType(types[st])
    rs.GatewayServerUri = args.get("--gateway-server-uri")
    rs.DiscoveryUrls = urls
    rs.SemaphoreFilePath = args.get("--semaphore-file")
    rs.IsOnline = online
    mdns = ua.MdnsDiscoveryConfiguration()
    mdns.MdnsServerName = args.get("--mdns-name", name)
    mdns.ServerCapabilities = args.all("--capability")
    conn = Conn(args)

    async def op(c):
        out = {"service": None, "status": ua.StatusCode(), "fallback": False, "rs2": None, "cfg": []}
        if service in ("auto", "RegisterServer2"):
            p = ua.RegisterServer2Parameters()
            p.Server = rs
            p.DiscoveryConfiguration = [mdns]
            try:
                out["cfg"] = list(await c.uaclient.register_server2(p) or [])
                out["service"], out["rs2"] = "RegisterServer2", ua.StatusCode()
                return out
            except UaStatusCodeError as e:
                out["rs2"] = ua.StatusCode(e.code)
                if service == "RegisterServer2" or e.code not in UNSUPPORTED_SERVICE:
                    out["service"], out["status"] = "RegisterServer2", ua.StatusCode(e.code)
                    return out
                out["fallback"] = True
        out["service"] = "RegisterServer"
        try:
            await c.uaclient.register_server(rs)
        except UaStatusCodeError as e:
            out["status"] = ua.StatusCode(e.code)
        return out

    res = await _sessionless(conn, op)
    ok = is_good(res["status"]) and all(is_good(x) for x in res["cfg"])
    item = {
        "service": res["service"],
        "serverUri": uri,
        "isOnline": online,
        "statusCode": status_json(res["status"]),
        "fallback": res["fallback"],
    }
    if res["rs2"] is not None:
        item["registerServer2StatusCode"] = status_json(res["rs2"])
    item["configurationResults"] = [status_json(x) for x in res["cfg"]]
    r.add(item)
    r.set_service(res["status"])
    if not ok:
        r.fail("service", f"{res['service']} failed")
        return 4
    return 0


async def cmd_push(args: Args, r: Result) -> int:
    return await push.cmd_push(args, r, Conn)


async def cmd_gds_pull(args: Args, r: Result) -> int:
    return await push.cmd_gds_pull(args, r, Conn)


COMMANDS = {
    "endpoints": cmd_endpoints,
    "find-servers": cmd_find_servers,
    "read": cmd_read,
    "write": cmd_write,
    "browse": cmd_browse,
    "translate": cmd_translate,
    "call": cmd_call,
    "subscribe": cmd_subscribe,
    "subscription-lifecycle": cmd_subscription_lifecycle,
    "event-subscribe": cmd_event_subscribe,
    "alarms": cmd_alarms,
    "history-read": cmd_history_read,
    "republish": cmd_republish,
    "transfer-subscriptions": cmd_transfer_subscriptions,
    "register-nodes": cmd_register_nodes,
    "node-management": cmd_node_management,
    "find-servers-on-network": cmd_find_servers_on_network,
    "register-server": cmd_register_server,
    "push": cmd_push,
    "gds-pull": cmd_gds_pull,
}

UNSUPPORTED_OPS = {
    "codec": "asyncua implements neither the OPC UA JSON nor the XML DataEncoding of built-in values "
    "(only the Binary encoding and NodeSet2 XML import/export)",
}

USAGE_HINT = {
    "history-read": " (usage: history-read --endpoint <url> --node <id> --start <rfc3339> --end <rfc3339>"
    " [--num-values n] [--continuation-point b64] [--release-continuation-point true|false]"
    " [--return-bounds true|false] [--timestamps ...] [--scenario continue])",
}

UNSUPPORTED_FLAGS = {
    "--reverse-listen": "reverse connect (ReverseHello) is not implemented by asyncua",
    "--reverse-server-uri": "reverse connect (ReverseHello) is not implemented by asyncua",
    "--reverse-timeout-ms": "reverse connect (ReverseHello) is not implemented by asyncua",
}


async def run_async(op: str, argv: list[str]) -> int:
    r = Result(op)
    args = Args(argv)
    try:
        if op in UNSUPPORTED_OPS:
            raise InputError(f"client {op} is not supported: {UNSUPPORTED_OPS[op]}")
        for f, why in UNSUPPORTED_FLAGS.items():
            if args.has(f):
                raise InputError(f"{f}: {why}")
        if op not in COMMANDS:
            log(f"unknown client subcommand: {op}")
            return 1
        if not args.get("--endpoint"):
            raise InputError("missing --endpoint" + USAGE_HINT.get(op, ""))
        rc = await COMMANDS[op](args, r)
        r.emit()
        return rc
    except AdapterError as e:
        if e.status is not None:
            r.set_service(e.status)
        elif isinstance(e, InputError):
            r.set_service(0x80AB0000)  # BadInvalidArgument
        r.fail(e.category, str(e))
        r.emit()
        return e.exit_code
    except UaStatusCodeError as e:
        r.set_service(e.code).fail("service", str(e))
        r.emit()
        return 4
    except asyncio.TimeoutError:
        r.set_service(BAD_TIMEOUT).fail("timeout", "request timed out")
        r.emit()
        return 7
    except (OSError, ConnectionError) as e:
        r.fail("transport", str(e) or type(e).__name__)
        r.emit()
        return 3
    except Exception as e:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        r.fail("internal", f"{type(e).__name__}: {e}")
        r.emit()
        return 6


def run(argv: list[str]) -> int:
    if not argv:
        log("usage: client <" + "|".join(OPERATIONS) + "> ...")
        return 1
    return asyncio.run(run_async(argv[0], argv[1:]))
