"""`client push` (docs/CONTAINER_CONTRACT.md §1 "push flags", §4 `push`, §15) and
`client gds-pull` (§16.2) on the asyncua client.

opcua-asyncio 2.1.0 has neither a push certificate management client nor a
GDS pull client, so both commands are built from its generic services: Call
requests on the standard NodeIds of ServerConfiguration (Part 12 §7.10) and
of the GDS Directory (Part 12 §6.6, namespace http://opcfoundation.org/UA/GDS/),
the FileType methods of a TrustList object found by TranslateBrowsePath, the
binary codec for TrustListDataType, and a hand-encoded
ApplicationRecordDataType (the type is not in asyncua's built-in set)."""

from __future__ import annotations

import asyncio
import base64
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from asyncua import ua
from asyncua.common.utils import Buffer
from asyncua.ua import ua_binary
from asyncua.ua.uaerrors import UaStatusCodeError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .common import (
    Args,
    InputError,
    Result,
    ServiceError,
    fmt_datetime,
    is_good,
    nodeid_str,
    parse_nodeid_syntax,
    sc_value,
    status_json,
    ts_present,
)

BAD_NOTHING_TO_DO = 0x800F0000
BAD_NODEID_UNKNOWN = 0x80340000
BAD_UNEXPECTED = 0x80010000
TRUST_LIST_CHUNK = 4096


def _b64(b) -> str:
    return base64.b64encode(bytes(b or b"")).decode("ascii")


def trust_list_json(tl: ua.TrustListDataType) -> dict:
    """The four lists of a TrustListDataType, base64 DER (§4 `push`)."""
    return {
        "specifiedLists": int(tl.SpecifiedLists or 0),
        "trustedCertificates": [_b64(c) for c in tl.TrustedCertificates or []],
        "trustedCrls": [_b64(c) for c in tl.TrustedCrls or []],
        "issuerCertificates": [_b64(c) for c in tl.IssuerCertificates or []],
        "issuerCrls": [_b64(c) for c in tl.IssuerCrls or []],
    }


def decode_trust_list(data: bytes) -> ua.TrustListDataType:
    """The content of a TrustList file: a TrustListDataType in the binary
    encoding (Part 12 §7.8.2.1), not wrapped in an ExtensionObject."""
    return ua_binary.struct_from_binary(ua.TrustListDataType, Buffer(data))


def read_input_file(path: str, flag: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as e:
        raise InputError(f"{flag} {path}: {e}")


def read_certificate_der(path: str, flag: str) -> bytes:
    """A certificate file (PEM or DER) as DER."""
    data = read_input_file(path, flag)
    try:
        if data.lstrip().startswith(b"-----"):
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except ValueError as e:
        raise InputError(f"{flag} {path}: not a PEM or DER certificate: {e}")
    return cert.public_bytes(serialization.Encoding.DER)


def uint16_arg(args: Args, flag: str, default: int) -> int:
    v = args.int(flag, default)
    if not 0 <= v <= 0xFFFF:
        raise InputError(f"{flag} must be an integer 0..65535, got {v}")
    return v


def private_key_format(args: Args, path: str) -> str:
    """`--private-key-format`, else PFX for .pfx / .p12 files, else PEM."""
    f = args.get("--private-key-format")
    if f is not None:
        if f not in ("PEM", "PFX"):
            raise InputError(f"--private-key-format must be PEM or PFX, got {f}")
        return f
    return "PFX" if re.search(r"\.(pfx|p12)$", path, re.IGNORECASE) else "PEM"


def _nodeid_arg(s: str, flag: str) -> str:
    try:
        parse_nodeid_syntax(s)
    except InputError as e:
        raise InputError(f"{flag}: {e}")
    return s


# ── Method calls ──────────────────────────────────────────────────────────────


async def call(conn, object_id: ua.NodeId, method_id: ua.NodeId, *inputs: ua.Variant) -> tuple[int, list]:
    """One Call: the CallMethodResult status (or the Bad service result) and
    the output argument values."""
    req = ua.CallMethodRequest(ObjectId=object_id, MethodId=method_id, InputArguments=list(inputs))
    try:
        res = (await conn.session.call([req]))[0]
    except UaStatusCodeError as e:
        return int(e.code), []
    return sc_value(res.StatusCode), [v.Value for v in res.OutputArguments or []]


def _v(value, vt: ua.VariantType) -> ua.Variant:
    return ua.Variant(value, vt)


async def _child(conn, node_id: ua.NodeId, name: str) -> ua.NodeId:
    """The child of node_id with the BrowseName 0:name (TranslateBrowsePath)."""
    node = conn.client.get_node(node_id)
    return (await node.get_child(ua.QualifiedName(name, 0))).nodeid


class StepFailed(Exception):
    def __init__(self, key: str, code: int):
        super().__init__(f"{key} returned a non-Good status")
        self.key = key
        self.code = code


async def read_trust_list(conn, trust_list: ua.NodeId, masks: int | None) -> ua.TrustListDataType:
    """Read a TrustList object: OpenWithMasks(masks) (or Open(Read) when
    masks is None), Read in TRUST_LIST_CHUNK-byte chunks until an empty one,
    Close. A Bad method status raises StepFailed("readTrustList")."""
    if masks is None:
        sc, out = await call(conn, trust_list, await _child(conn, trust_list, "Open"), _v(1, ua.VariantType.Byte))
    else:
        sc, out = await call(conn, trust_list, await _child(conn, trust_list, "OpenWithMasks"), _v(masks, ua.VariantType.UInt32))
    if not is_good(sc):
        raise StepFailed("readTrustList", sc)
    handle = out[0]
    data = bytearray()
    read_id = await _child(conn, trust_list, "Read")
    try:
        while True:
            sc, out = await call(conn, trust_list, read_id, _v(handle, ua.VariantType.UInt32),
                                 _v(TRUST_LIST_CHUNK, ua.VariantType.Int32))
            if not is_good(sc):
                raise StepFailed("readTrustList", sc)
            chunk = out[0] if out else b""
            if not chunk:
                break
            data += chunk
    finally:
        try:
            await call(conn, trust_list, await _child(conn, trust_list, "Close"), _v(handle, ua.VariantType.UInt32))
        except Exception:  # noqa: BLE001
            pass
    return decode_trust_list(bytes(data))


# ── client push (§1 "push flags", §15) ────────────────────────────────────────

SERVER_CONFIGURATION = ua.NodeId(12637)
SC_UPDATE_CERTIFICATE = ua.NodeId(13737)
SC_CREATE_SIGNING_REQUEST = ua.NodeId(12737)
SC_GET_REJECTED_LIST = ua.NodeId(12777)
SC_APPLY_CHANGES = ua.NodeId(12740)
SC_GET_CERTIFICATES = ua.NodeId(32333)
SC_CREATE_SELF_SIGNED = ua.NodeId(19342)
SC_DELETE_CERTIFICATE = ua.NodeId(19345)
SC_CANCEL_CHANGES = ua.NodeId(25708)
SC_RESET_TO_SERVER_DEFAULTS = ua.NodeId(25709)
# ServerConfiguration.TransactionDiagnostics (TransactionDiagnosticsType, Part 12 §7.10.12)
TRANSACTION_DIAGNOSTICS = [
    ("startTime", 32337),
    ("endTime", 32338),
    ("result", 32339),
    ("affectedTrustLists", 32340),
    ("affectedCertificateGroups", 32341),
    ("errors", 32342),
]
TRUST_LIST_MASKS_ALL = 15

# `--group`: the well-known CertificateGroups (Part 12 §7.8.4) and the
# default CertificateType of each.
PUSH_GROUPS = {
    "Application": ("i=14156", "i=12560"),  # DefaultApplicationGroup, RsaSha256ApplicationCertificateType
    "Https": ("i=14088", "i=12558"),  # DefaultHttpsGroup, HttpsCertificateType
    "UserToken": ("i=14122", "i=15181"),  # DefaultUserTokenGroup, UserCredentialCertificateType
}


@dataclass
class PushOptions:
    group: str
    group_id: str
    certificate_type_id: str
    add: bytes | None = None
    remove: str | None = None
    issuer: bool = False
    get_certificates: bool = False
    self_signed: bool = False
    subject: str = ""
    dns: list[str] = field(default_factory=list)
    ip: list[str] = field(default_factory=list)
    lifetime_days: int = 365
    key_size: int = 0
    delete_type: str | None = None
    update: bytes | None = None
    issuers: list[bytes] = field(default_factory=list)
    key_format: str = ""
    key: bytes | None = None
    csr: bool = False
    reset: bool = False
    apply: bool = False
    cancel: bool = False
    diagnostics: bool = False


def parse_push(args: Args) -> PushOptions:
    """The push flags, validated before connecting (exit 2 on bad input)."""
    group = args.get("--group", "Application")
    if group not in PUSH_GROUPS:
        raise InputError(f"--group must be Application, Https or UserToken, got {group}")
    group_id, default_type = PUSH_GROUPS[group]
    o = PushOptions(group=group, group_id=group_id,
                    certificate_type_id=_nodeid_arg(args.get("--certificate-type-id", default_type), "--certificate-type-id"))
    if args.get("--add-certificate") is not None:
        o.add = read_certificate_der(args.get("--add-certificate"), "--add-certificate")
    o.remove = args.get("--remove-certificate")
    o.issuer = args.has("--issuer")
    o.get_certificates = args.has("--get-certificates")
    o.self_signed = args.has("--create-self-signed")
    o.subject = args.get("--subject", "")
    o.dns = args.all("--dns")
    o.ip = args.all("--ip")
    o.lifetime_days = uint16_arg(args, "--lifetime-days", 365)
    o.key_size = uint16_arg(args, "--key-size", 0)
    if args.get("--delete-certificate") is not None:
        o.delete_type = _nodeid_arg(args.get("--delete-certificate"), "--delete-certificate")
    update_file, key_file = args.get("--update-certificate"), args.get("--update-private-key")
    if key_file is not None and update_file is None:
        raise InputError("--update-private-key needs --update-certificate")
    if update_file is not None:
        o.update = read_certificate_der(update_file, "--update-certificate")
    o.issuers = [read_certificate_der(f, "--issuer-certificate") for f in args.all("--issuer-certificate")]
    if key_file is not None:
        o.key_format = private_key_format(args, key_file)
        o.key = read_input_file(key_file, "--update-private-key")
    o.csr = args.has("--csr")
    o.reset = args.has("--reset-to-defaults")
    o.apply = args.has("--apply")
    o.cancel = not o.apply and (args.has("--cancel") or o.self_signed or o.delete_type is not None)
    o.diagnostics = args.has("--transaction-diagnostics")
    return o


def _nodeid_list(v) -> list[str]:
    return [nodeid_str(n) for n in v or []]


async def read_transaction_diagnostics(conn) -> tuple[int, dict | None]:
    """The six TransactionDiagnostics variables in one Read."""
    p = ua.ReadParameters()
    for _, i in TRANSACTION_DIAGNOSTICS:
        p.NodesToRead.append(ua.ReadValueId(NodeId=ua.NodeId(i), AttributeId=ua.AttributeIds.Value))
    p.TimestampsToReturn = ua.TimestampsToReturn.Neither
    try:
        dvs = await conn.session.read(p)
    except UaStatusCodeError as e:
        return int(e.code), None
    if len(dvs) != len(TRANSACTION_DIAGNOSTICS):
        return BAD_UNEXPECTED, None
    for dv in dvs:
        if not is_good(dv.StatusCode):
            return sc_value(dv.StatusCode), None
    vals = [dv.Value.Value if dv.Value is not None else None for dv in dvs]

    def when(v):
        return fmt_datetime(v) if ts_present(v) else None

    errors = []
    for e in vals[5] or []:
        msg = getattr(e, "Message", None)
        errors.append({
            "targetId": nodeid_str(getattr(e, "TargetId", None)),
            "error": status_json(getattr(e, "Error", None)),
            "message": msg.Text if msg is not None and msg.Text is not None else None,
        })
    return 0, {
        "startTime": when(vals[0]),
        "endTime": when(vals[1]),
        "result": status_json(vals[2]),
        "affectedTrustLists": _nodeid_list(vals[3]),
        "affectedCertificateGroups": _nodeid_list(vals[4]),
        "errors": errors,
    }


async def cmd_push(args: Args, r: Result, conn_factory) -> int:
    """The steps of §1 "push flags" on one session (one transaction, Part 12
    §7.10.2), stopping at the first Bad status."""
    o = parse_push(args)
    conn = conn_factory(args)
    await conn.connect()
    out: dict = {}

    def step(name: str, sc) -> bool:
        out[name + "Status"] = status_json(sc)
        if is_good(sc):
            return True
        r.set_service(sc).fail("service", f"{name} returned a non-Good status")
        return False

    try:
        sc_obj = SERVER_CONFIGURATION
        group_id = await conn.resolve(o.group_id)
        type_id = await conn.resolve(o.certificate_type_id)
        out["certificateGroupId"] = nodeid_str(group_id)
        try:
            trust_list = await _child(conn, group_id, "TrustList")
        except UaStatusCodeError as e:
            raise ServiceError(f"the TrustList of {o.group_id}: {e}", e.code)
        try:
            out["trustList"] = trust_list_json(await read_trust_list(conn, trust_list, TRUST_LIST_MASKS_ALL))
        except StepFailed as e:
            raise ServiceError(f"reading the TrustList of {o.group_id}: {e}", e.code)
        trusted = _v(not o.issuer, ua.VariantType.Boolean)
        ok = True
        if ok and o.add is not None:
            sc, _ = await call(conn, trust_list, await _child(conn, trust_list, "AddCertificate"),
                               _v(o.add, ua.VariantType.ByteString), trusted)
            ok = step("addCertificate", sc)
        if ok and o.remove is not None:
            sc, _ = await call(conn, trust_list, await _child(conn, trust_list, "RemoveCertificate"),
                               _v(o.remove, ua.VariantType.String), trusted)
            ok = step("removeCertificate", sc)
        if ok and o.get_certificates:
            sc, res = await call(conn, sc_obj, SC_GET_CERTIFICATES, _v(group_id, ua.VariantType.NodeId))
            ok = step("getCertificates", sc)
            if ok:
                out["certificateTypeIds"] = _nodeid_list(res[0] if res else None)
                out["certificates"] = [_b64(c) for c in (res[1] if len(res) > 1 else None) or []]
        if ok and o.self_signed:
            sc, res = await call(
                conn, sc_obj, SC_CREATE_SELF_SIGNED,
                _v(group_id, ua.VariantType.NodeId),
                _v(type_id, ua.VariantType.NodeId),
                _v(o.subject, ua.VariantType.String),
                _v(o.dns, ua.VariantType.String),
                _v(o.ip, ua.VariantType.String),
                _v(o.lifetime_days, ua.VariantType.UInt16),
                _v(o.key_size, ua.VariantType.UInt16),
            )
            ok = step("createSelfSignedCertificate", sc)
            if ok:
                out["selfSignedCertificate"] = _b64(res[0] if res else None)
        if ok and o.delete_type is not None:
            sc, _ = await call(conn, sc_obj, SC_DELETE_CERTIFICATE, _v(group_id, ua.VariantType.NodeId),
                               _v(await conn.resolve(o.delete_type), ua.VariantType.NodeId))
            ok = step("deleteCertificate", sc)
        if ok and o.update is not None:
            sc, res = await call(
                conn, sc_obj, SC_UPDATE_CERTIFICATE,
                _v(group_id, ua.VariantType.NodeId),
                _v(type_id, ua.VariantType.NodeId),
                _v(o.update, ua.VariantType.ByteString),
                _v(o.issuers, ua.VariantType.ByteString),
                _v(o.key_format, ua.VariantType.String),
                _v(o.key, ua.VariantType.ByteString),
            )
            ok = step("updateCertificate", sc)
            if ok:
                out["applyChangesRequired"] = bool(res[0]) if res else False
        if ok and o.csr:
            sc, res = await call(
                conn, sc_obj, SC_CREATE_SIGNING_REQUEST,
                _v(group_id, ua.VariantType.NodeId),
                _v(type_id, ua.VariantType.NodeId),
                _v(None, ua.VariantType.String),
                _v(False, ua.VariantType.Boolean),
                _v(None, ua.VariantType.ByteString),
            )
            ok = step("createSigningRequest", sc)
            if ok:
                out["certificateSigningRequest"] = _b64(res[0] if res else None)
        if ok:
            sc, res = await call(conn, sc_obj, SC_GET_REJECTED_LIST)
            ok = step("getRejectedList", sc)
            if ok:
                out["rejectedCertificates"] = [_b64(c) for c in (res[0] if res else None) or []]
        if ok and o.reset:
            ok = step("resetToServerDefaults", (await call(conn, sc_obj, SC_RESET_TO_SERVER_DEFAULTS))[0])
        applied = False
        if ok and o.apply:
            ok = step("applyChanges", (await call(conn, sc_obj, SC_APPLY_CHANGES))[0])
            applied = True
        if ok and o.cancel:
            ok = step("cancelChanges", (await call(conn, sc_obj, SC_CANCEL_CHANGES))[0])
        # The diagnostics explain a failed ApplyChanges too: read them also then.
        if o.diagnostics and (ok or applied):
            sc, diag = await read_transaction_diagnostics(conn)
            out["transactionDiagnosticsStatus"] = status_json(sc)
            if diag is not None:
                out["transactionDiagnostics"] = diag
            if ok and not is_good(sc):
                r.set_service(sc).fail("service", "reading TransactionDiagnostics returned a non-Good status")
                ok = False
        if ok:
            try:
                out["trustListAfter"] = trust_list_json(await read_trust_list(conn, trust_list, TRUST_LIST_MASKS_ALL))
            except StepFailed as e:
                r.set_service(e.code).fail("service", f"reading the TrustList again: {e}")
                ok = False
        r.add(out)
        return 0 if ok else 4
    finally:
        await conn.close()


# ── client gds-pull (§16.2) ───────────────────────────────────────────────────

GDS_NAMESPACE_URI = "http://opcfoundation.org/UA/GDS/"
GDS_DIRECTORY = 141
GDS_DEFAULT_APPLICATION_GROUP = 615
GDS_APPLICATION_RECORD_BINARY = 134
GDS_METHODS = {
    "FindApplications": 143,
    "RegisterApplication": 146,
    "UnregisterApplication": 149,
    "StartNewKeyPairRequest": 154,
    "StartSigningRequest": 157,
    "FinishRequest": 163,
    "CheckRevocationStatus": 177,
    "GetTrustList": 204,
    "GetCertificateStatus": 225,
    "GetCertificateGroups": 508,
    "RevokeCertificate": 15005,
}
APP_TYPES = {"Server": 0, "Client": 1, "ClientAndServer": 2}
CERTIFICATE_TYPES = {"RsaSha256": 12560, "NistP256": 23538}
GDS_PRODUCT_URI = "urn:opcua-interop:asyncua"


@dataclass
class GdsPullOptions:
    app_uri: str
    app_type: str
    discovery_urls: list[str]
    request: str
    certificate_type: str
    revoke: bool
    unregister: bool
    finish_timeout_ms: int

    @property
    def app_name(self) -> str:
        return app_name(self.app_uri)


def app_name(uri: str) -> str:
    """The last `:` / `/` segment of the app uri (§16.2 step 2)."""
    s = uri.rstrip("/:")
    last = re.split(r"[:/]", s)[-1] if s else ""
    return last or "opcua-interop gds-pull app"


def parse_gds_pull(args: Args) -> GdsPullOptions:
    o = GdsPullOptions(
        app_uri=args.get("--app-uri", "urn:opcua-interop:gds-pull:app"),
        app_type=args.get("--app-type", "Server"),
        discovery_urls=args.all("--discovery-url") or ["opc.tcp://localhost:4850"],
        request=args.get("--request", "csr"),
        certificate_type=args.get("--certificate-type", "RsaSha256"),
        revoke=args.has("--revoke"),
        unregister=args.has("--unregister"),
        finish_timeout_ms=args.int("--finish-timeout-ms", 30000),
    )
    if not o.app_uri:
        raise InputError("empty --app-uri")
    if o.app_type not in APP_TYPES:
        raise InputError(f"invalid --app-type {o.app_type} (Server, Client, ClientAndServer)")
    if o.request not in ("csr", "new-key-pair"):
        raise InputError(f"invalid --request {o.request} (csr, new-key-pair)")
    if o.certificate_type not in CERTIFICATE_TYPES:
        raise InputError(f"invalid --certificate-type {o.certificate_type} (RsaSha256, NistP256)")
    if o.finish_timeout_ms < 0:
        raise InputError(f"invalid --finish-timeout-ms {o.finish_timeout_ms}")
    return o


def encode_application_record(ns: int, o: GdsPullOptions) -> ua.ExtensionObject:
    """ApplicationRecordDataType (Part 12 §6.6.4) in the binary encoding,
    with a null ApplicationId (RegisterApplication assigns it)."""
    client = o.app_type == "Client"
    p = ua_binary.Primitives
    body = b"".join([
        ua_binary.nodeid_to_binary(ua.NodeId()),
        p.String.pack(o.app_uri),
        p.Int32.pack(APP_TYPES[o.app_type]),
        ua_binary.list_to_binary(ua.LocalizedText, [ua.LocalizedText(o.app_name, "en-US")]),
        p.String.pack(GDS_PRODUCT_URI),
        ua_binary.pack_uatype_array(ua.VariantType.String, [] if client else o.discovery_urls),
        ua_binary.pack_uatype_array(ua.VariantType.String, [] if client else ["NA"]),
    ])
    return ua.ExtensionObject(TypeId=ua.NodeId(GDS_APPLICATION_RECORD_BINARY, ns), Body=body)


def application_record_id(eo) -> ua.NodeId:
    """The ApplicationId (the first field) of an ApplicationRecordDataType."""
    if isinstance(eo, ua.ExtensionObject):
        return ua_binary.nodeid_from_binary(Buffer(eo.Body or b""))
    return getattr(eo, "ApplicationId")


def make_csr(o: GdsPullOptions) -> bytes:
    """A PKCS #10 request with a fresh RSA 2048 / ECC P-256 key: subject
    CN=<name>, URI SAN = app uri, DNS SAN localhost, SHA-256."""
    if o.certificate_type == "NistP256":
        key = ec.generate_private_key(ec.SECP256R1())
        usage = x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                              data_encipherment=False, key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        usage = x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True,
                              data_encipherment=True, key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, o.app_name)]))
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(o.app_uri), x509.DNSName("localhost")]), critical=False)
        .add_extension(usage, critical=True)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


async def cmd_gds_pull(args: Args, r: Result, conn_factory) -> int:
    """The pull-model steps of §16.2 against the Directory of a GDS."""
    o = parse_gds_pull(args)
    conn = conn_factory(args)
    await conn.connect()
    item: dict = {}
    try:
        ns_array = await conn.client.get_namespace_array()
        if GDS_NAMESPACE_URI not in ns_array:
            raise ServiceError(f"the server has no GDS namespace {GDS_NAMESPACE_URI}", BAD_NODEID_UNKNOWN)
        ns = ns_array.index(GDS_NAMESPACE_URI)
        directory = ua.NodeId(GDS_DIRECTORY, ns)
        group_id = ua.NodeId(GDS_DEFAULT_APPLICATION_GROUP, ns)
        cert_type = ua.NodeId(CERTIFICATE_TYPES[o.certificate_type])

        async def gds(method: str, status_key: str | None, *inputs: ua.Variant) -> list:
            sc, out = await call(conn, directory, ua.NodeId(GDS_METHODS[method], ns), *inputs)
            if status_key is not None:
                item[status_key] = status_json(sc)
            if not is_good(sc):
                raise StepFailed(status_key or method, sc)
            return out

        def nid(n) -> ua.Variant:
            return _v(n, ua.VariantType.NodeId)

        try:
            # 1. FindApplications
            found = (await gds("FindApplications", "findApplicationsStatus", _v(o.app_uri, ua.VariantType.String)))
            del item["findApplicationsStatus"]
            records = (found[0] if found else None) or []
            ids = [application_record_id(e) for e in records]
            item["findApplications"] = [nodeid_str(i) for i in ids]
            # 2. RegisterApplication
            if ids:
                app_id = ids[0]
                item["registered"] = False
            else:
                out = await gds("RegisterApplication", "registerStatus", _v(encode_application_record(ns, o), ua.VariantType.ExtensionObject))
                app_id = out[0]
                item["registered"] = True
            item["applicationId"] = nodeid_str(app_id)
            # 3. StartSigningRequest / StartNewKeyPairRequest
            item["requestKind"] = o.request
            if o.request == "csr":
                out = await gds("StartSigningRequest", "startRequestStatus", nid(app_id), nid(group_id), nid(cert_type),
                                _v(make_csr(o), ua.VariantType.ByteString))
            else:
                out = await gds("StartNewKeyPairRequest", "startRequestStatus", nid(app_id), nid(group_id), nid(cert_type),
                                _v(f"CN={o.app_name}", ua.VariantType.String), _v(["localhost"], ua.VariantType.String),
                                _v("PEM", ua.VariantType.String), _v(None, ua.VariantType.String))
            request_id = out[0]
            item["requestId"] = nodeid_str(request_id)
            # 4. FinishRequest until it issues (Bad_NothingToDo = pending)
            deadline = time.monotonic() + o.finish_timeout_ms / 1000
            while True:
                sc, out = await call(conn, directory, ua.NodeId(GDS_METHODS["FinishRequest"], ns), nid(app_id), nid(request_id))
                if sc_value(sc) & 0xFFFF0000 == BAD_NOTHING_TO_DO and time.monotonic() < deadline:
                    await asyncio.sleep(0.2)
                    continue
                item["finishRequestStatus"] = status_json(sc)
                if not is_good(sc):
                    raise StepFailed("finishRequest", sc)
                break
            certificate = out[0] if out else None
            item["certificate"] = _b64(certificate) if certificate is not None else None
            if o.request == "new-key-pair":
                key = out[1] if len(out) > 1 else None
                item["privateKeyFormat"] = "PEM"
                item["privateKey"] = _b64(key) if key is not None else None
            item["issuerCertificates"] = [_b64(c) for c in (out[2] if len(out) > 2 else None) or []]
            # 5. GetCertificateGroups
            out = await gds("GetCertificateGroups", "getCertificateGroupsStatus", nid(app_id))
            del item["getCertificateGroupsStatus"]
            item["certificateGroups"] = _nodeid_list(out[0] if out else None)
            # 6. GetTrustList + the TrustList (Open Read, Read, Close)
            out = await gds("GetTrustList", "getTrustListStatus", nid(app_id), nid(group_id))
            del item["getTrustListStatus"]
            trust_list_id = out[0]
            item["trustListId"] = nodeid_str(trust_list_id)
            try:
                tl = await read_trust_list(conn, trust_list_id, None)
            except StepFailed as e:
                item["readTrustListStatus"] = status_json(e.code)
                raise
            except UaStatusCodeError as e:
                item["readTrustListStatus"] = status_json(e.code)
                raise StepFailed("readTrustList", int(e.code))
            item["trustList"] = trust_list_json(tl)
            # 7. GetCertificateStatus
            out = await gds("GetCertificateStatus", "getCertificateStatusStatus", nid(app_id), nid(group_id), nid(cert_type))
            item["updateRequired"] = bool(out[0]) if out else False
            # 8. RevokeCertificate, CheckRevocationStatus
            if o.revoke:
                await gds("RevokeCertificate", "revokeStatus", nid(app_id), _v(certificate, ua.VariantType.ByteString))
                out = await gds("CheckRevocationStatus", "checkRevocationStatus", _v(certificate, ua.VariantType.ByteString))
                item["certificateStatus"] = status_json(out[0] if out else None)
            # 9. UnregisterApplication
            if o.unregister:
                await gds("UnregisterApplication", "unregisterStatus", nid(app_id))
        except StepFailed as e:
            r.add(item)
            r.set_service(e.code).fail("service", str(e))
            return 4
        r.add(item)
        return 0
    finally:
        await conn.close()
