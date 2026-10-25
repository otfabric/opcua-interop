"""Shared helpers: result envelope, status codes, canonical NodeId / value encoding
(docs/CLIENT_CONTRACT.md §3, §6, §7), NodeId input parsing (§8) and value
literals (§12)."""

from __future__ import annotations

import base64
import json
import math
import struct
import sys
import uuid
from datetime import datetime, timezone

from asyncua import ua
from asyncua.ua import status_codes

ADAPTER = "asyncua"
ADAPTER_VERSION = "0.16.0"
SCHEMA_VERSION = "1.0"

# OPC UA DateTime "zero" (1601-01-01) as decoded by asyncua.
_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def stack_version() -> str:
    try:
        from importlib.metadata import version

        return version("asyncua")
    except Exception:  # pragma: no cover - metadata always present in the image
        return "unknown"


def file_format(path) -> str:
    """'pem' or 'der' from the file content (asyncua decides by the file suffix,
    and the test PKI stores PEM in *.crt / *.key)."""
    with open(path, "rb") as f:
        head = f.read(64)
    return "pem" if head.lstrip().startswith(b"-----") else "der"


def log(msg: str) -> None:
    print(f"[asyncua] {msg}", file=sys.stderr, flush=True)


# ── Errors mapped to exit codes (§5) ──────────────────────────────────────────


class AdapterError(Exception):
    exit_code = 6
    category = "internal"

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class InputError(AdapterError):
    exit_code = 2
    category = "input"


class TransportError(AdapterError):
    exit_code = 3
    category = "transport"


class ServiceError(AdapterError):
    exit_code = 4
    category = "service"


class TimeoutFailure(AdapterError):
    exit_code = 7
    category = "timeout"


# ── Status codes ──────────────────────────────────────────────────────────────


def sc_value(sc) -> int:
    if sc is None:
        return 0
    if isinstance(sc, ua.StatusCode):
        return int(sc.value)
    return int(sc)


def severity(code: int) -> str:
    top = (code >> 30) & 0x3
    if top == 0:
        return "Good"
    if top == 1:
        return "Uncertain"
    return "Bad"


def status_json(sc) -> dict:
    code = sc_value(sc) & 0xFFFFFFFF
    name, _ = status_codes.get_name_and_doc(code)
    if name in ("Good", "Bad", "Uncertain") and code not in (0,):
        # Unknown value: fall back on the severity name (as the other adapters do).
        name = severity(code)
    # The symbolic table is keyed on the full code; codes with info bits set
    # (e.g. Good|Overflow) are reported under their base name.
    if code not in status_codes.code_to_name_doc and (code & 0xFFFF0000) in status_codes.code_to_name_doc:
        name = status_codes.get_name_and_doc(code & 0xFFFF0000)[0]
    return {"name": name, "code": code, "severity": severity(code)}


GOOD = {"name": "Good", "code": 0, "severity": "Good"}


def is_good(sc) -> bool:
    return (sc_value(sc) >> 30) & 0x3 == 0


def is_bad(sc) -> bool:
    return (sc_value(sc) >> 31) & 0x1 == 1


# ── Envelope (§3) ─────────────────────────────────────────────────────────────


class Result:
    def __init__(self, operation: str):
        self.operation = operation
        self.success = True
        self.service_result = dict(GOOD)
        self.results: list = []
        self.error: dict | None = None

    def set_service(self, sc) -> "Result":
        self.service_result = status_json(sc)
        return self

    def fail(self, category: str, message: str) -> "Result":
        self.success = False
        self.error = {"category": category, "message": message}
        return self

    def add(self, item) -> "Result":
        self.results.append(item)
        return self

    def to_json(self) -> str:
        out = {
            "schemaVersion": SCHEMA_VERSION,
            "adapter": ADAPTER,
            "operation": self.operation,
            "success": bool(self.success and self.error is None),
            "serviceResult": self.service_result,
            "results": self.results,
            "error": self.error,
        }
        return json.dumps(out, ensure_ascii=False, allow_nan=False)

    def emit(self) -> None:
        sys.stdout.write(self.to_json() + "\n")
        sys.stdout.flush()


# ── NodeId canonical form (§6) ────────────────────────────────────────────────


def nodeid_str(nid) -> str:
    if nid is None:
        return "i=0"
    ns = int(nid.NamespaceIndex or 0)
    t = nid.NodeIdType
    ident = nid.Identifier
    if t in (ua.NodeIdType.TwoByte, ua.NodeIdType.FourByte, ua.NodeIdType.Numeric):
        return f"i={ident}" if ns == 0 else f"ns={ns};i={ident}"
    if t == ua.NodeIdType.String:
        return f"ns={ns};s={ident}"
    if t == ua.NodeIdType.Guid:
        g = str(ident).lower()
        return f"ns={ns};g={g}"
    if t == ua.NodeIdType.ByteString:
        b = base64.b64encode(ident or b"").decode()
        return f"ns={ns};b={b}"
    return nid.to_string()


def expanded_str(nid) -> str:
    base = nodeid_str(nid)
    uri = getattr(nid, "NamespaceUri", None)
    srv = getattr(nid, "ServerIndex", 0) or 0
    if uri:
        # replace the ns=<n>; prefix with nsu=<uri>;
        if base.startswith("ns="):
            base = base.split(";", 1)[1]
        base = f"nsu={uri};{base}"
    if srv:
        base = f"svr={srv};{base}"
    return base


def local_nodeid(nid) -> ua.NodeId:
    """ExpandedNodeId -> NodeId (browse / translate results use namespace indices)."""
    if nid is None:
        return ua.NodeId()
    return ua.NodeId(nid.Identifier, nid.NamespaceIndex, nid.NodeIdType)


# ── Values (§7) ───────────────────────────────────────────────────────────────

_VT_NAMES = {vt.value: vt.name for vt in ua.VariantType}


def type_name(vt) -> str:
    if vt is None:
        return "Null"
    try:
        return _VT_NAMES[int(vt.value if hasattr(vt, "value") else vt)]
    except (KeyError, ValueError, TypeError):
        return "Unknown"


def shortest_float32(v: float):
    if not math.isfinite(v):
        return None
    packed = struct.pack("<f", v)
    for p in range(1, 10):
        s = f"{v:.{p}g}"
        try:
            if struct.pack("<f", float(s)) == packed:
                return float(s)
        except OverflowError:
            # A rounding of a value next to FLT_MAX can exceed the float32
            # range (FLT_MAX at 7 digits is 3.402824e38): try more digits.
            continue
    return v


def fmt_datetime(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    if dt.microsecond % 1000 == 0:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ts_present(dt) -> bool:
    return dt is not None and dt > _EPOCH_1601


def _scalar(v, vt: ua.VariantType):
    if v is None:
        return None
    if vt in (ua.VariantType.Int64, ua.VariantType.UInt64):
        return str(int(v))
    if vt == ua.VariantType.Float:
        return shortest_float32(float(v))
    if vt == ua.VariantType.Double:
        f = float(v)
        return f if math.isfinite(f) else None
    if vt == ua.VariantType.Boolean:
        return bool(v)
    if vt in (
        ua.VariantType.SByte,
        ua.VariantType.Byte,
        ua.VariantType.Int16,
        ua.VariantType.UInt16,
        ua.VariantType.Int32,
        ua.VariantType.UInt32,
    ):
        return int(v)
    if vt == ua.VariantType.String:
        return str(v)
    if vt == ua.VariantType.DateTime:
        return fmt_datetime(v)
    if vt == ua.VariantType.Guid:
        return str(v).lower()
    if vt == ua.VariantType.ByteString:
        return base64.b64encode(bytes(v)).decode()
    if vt == ua.VariantType.XmlElement:
        return getattr(v, "Value", v) if not isinstance(v, str) else v
    if vt == ua.VariantType.NodeId:
        return nodeid_str(v)
    if vt == ua.VariantType.ExpandedNodeId:
        return expanded_str(v)
    if vt == ua.VariantType.StatusCode:
        return status_json(v)
    if vt == ua.VariantType.QualifiedName:
        return {"ns": int(v.NamespaceIndex or 0), "name": v.Name or ""}
    if vt == ua.VariantType.LocalizedText:
        return {"locale": v.Locale or "", "text": v.Text or ""}
    if vt == ua.VariantType.ExtensionObject:
        return extension_object_json(v)
    if vt == ua.VariantType.DataValue:
        return datavalue_json(v)
    if vt == ua.VariantType.Variant:
        return {"dataType": type_name(v.VariantType), "builtInType": int(v.VariantType.value), "value": variant_value(v)}
    if vt == ua.VariantType.DiagnosticInfo:
        return diagnostic_json(v)
    return str(v)


def extension_object_json(v):
    if v is None:
        return None
    if isinstance(v, ua.ExtensionObject):
        return {
            "typeId": nodeid_str(v.TypeId),
            "encoding": "binary",
            "body": base64.b64encode(v.Body or b"").decode(),
        }
    # A structure asyncua decoded: re-encode its binary body.
    try:
        from asyncua.ua.ua_binary import struct_to_binary

        type_id = ua.extension_object_typeids.get(type(v).__name__)
        body = struct_to_binary(v)
        out = {"typeId": nodeid_str(type_id) if type_id else "i=0", "encoding": "binary", "body": base64.b64encode(body).decode()}
        out["dataTypeName"] = type(v).__name__
        return out
    except Exception:
        return {"typeId": "i=0", "encoding": "binary", "body": "", "dataTypeName": type(v).__name__}


def datavalue_json(dv) -> dict:
    out: dict = {}
    var = dv.Value
    if var is not None:
        out["dataType"] = type_name(var.VariantType)
        out["builtInType"] = int(var.VariantType.value) if var.VariantType is not None else 0
        if var.Dimensions:
            out["arrayDimensions"] = list(var.Dimensions)
        out["value"] = variant_value(var)
    if dv.StatusCode is not None and sc_value(dv.StatusCode) != 0:
        out["statusCode"] = status_json(dv.StatusCode)
    if ts_present(dv.SourceTimestamp):
        out["sourceTimestamp"] = fmt_datetime(dv.SourceTimestamp)
    if dv.SourcePicoseconds:
        out["sourcePicoseconds"] = int(dv.SourcePicoseconds)
    if ts_present(dv.ServerTimestamp):
        out["serverTimestamp"] = fmt_datetime(dv.ServerTimestamp)
    if dv.ServerPicoseconds:
        out["serverPicoseconds"] = int(dv.ServerPicoseconds)
    return out


def diagnostic_json(d) -> dict:
    out: dict = {}
    for attr, key in (
        ("SymbolicId", "symbolicId"),
        ("NamespaceURI", "namespaceUri"),
        ("LocalizedText", "localizedText"),
        ("Locale", "locale"),
    ):
        val = getattr(d, attr, None)
        if val is not None:
            out[key] = val
    if getattr(d, "AdditionalInfo", None) is not None:
        out["additionalInfo"] = d.AdditionalInfo
    if getattr(d, "InnerStatusCode", None) is not None:
        out["innerStatusCode"] = status_json(d.InnerStatusCode)
    if getattr(d, "InnerDiagnosticInfo", None) is not None:
        out["innerDiagnosticInfo"] = diagnostic_json(d.InnerDiagnosticInfo)
    return out


def _flatten(v):
    if isinstance(v, list):
        out = []
        for x in v:
            out.extend(_flatten(x)) if isinstance(x, list) else out.append(x)
        return out
    return [v]


def variant_value(var):
    """JSON value of a Variant per §7 (arrays as JSON arrays, matrices nested)."""
    if var is None or var.Value is None or var.VariantType == ua.VariantType.Null:
        return None
    vt = var.VariantType
    v = var.Value
    if isinstance(v, (list, tuple)):
        return _nested(v, vt)
    return _scalar(v, vt)


def _nested(v, vt):
    if isinstance(v, (list, tuple)):
        return [_nested(x, vt) for x in v]
    return _scalar(v, vt)


def variant_fields(var) -> dict:
    """dataType / builtInType / value of a Variant (read, notification, history …)."""
    if var is None or var.VariantType is None or var.VariantType == ua.VariantType.Null or var.Value is None:
        return {"dataType": "Null", "builtInType": 0, "value": None}
    return {
        "dataType": type_name(var.VariantType),
        "builtInType": int(var.VariantType.value),
        "value": variant_value(var),
    }


# ── NodeId input (§8) ─────────────────────────────────────────────────────────


def _parse_identifier(rest: str, original: str):
    if rest.startswith("i="):
        try:
            n = int(rest[2:])
        except ValueError:
            raise InputError(f"malformed NodeId: '{original}'")
        if n < 0 or n > 0xFFFFFFFF:
            raise InputError(f"malformed NodeId: '{original}'")
        return n, ua.NodeIdType.Numeric
    if rest.startswith("s="):
        return rest[2:], ua.NodeIdType.String
    if rest.startswith("g="):
        try:
            return uuid.UUID(rest[2:]), ua.NodeIdType.Guid
        except ValueError:
            raise InputError(f"malformed NodeId: '{original}'")
    if rest.startswith("b="):
        try:
            return base64.b64decode(rest[2:], validate=True), ua.NodeIdType.ByteString
        except Exception:
            raise InputError(f"malformed NodeId: '{original}'")
    raise InputError(f"malformed NodeId: '{original}'")


def parse_nodeid_syntax(s: str) -> tuple[str | None, int, object, ua.NodeIdType]:
    """Returns (namespace uri or None, ns index, identifier, type). No network."""
    if s is None or s == "":
        raise InputError("malformed NodeId: ''")
    if s.startswith("nsu="):
        semi = s.find(";")
        if semi < 0:
            raise InputError(f"malformed NodeId: '{s}'")
        uri = s[4:semi]
        if not uri:
            raise InputError(f"malformed NodeId: '{s}'")
        ident, t = _parse_identifier(s[semi + 1 :], s)
        return uri, 0, ident, t
    if s.startswith("ns="):
        semi = s.find(";")
        if semi < 0:
            raise InputError(f"malformed NodeId: '{s}'")
        try:
            ns = int(s[3:semi])
        except ValueError:
            raise InputError(f"malformed NodeId: '{s}'")
        if ns < 0 or ns > 0xFFFF:
            raise InputError(f"malformed NodeId: '{s}'")
        ident, t = _parse_identifier(s[semi + 1 :], s)
        return None, ns, ident, t
    ident, t = _parse_identifier(s, s)
    return None, 0, ident, t


def make_nodeid(ident, ns: int, t: ua.NodeIdType) -> ua.NodeId:
    if t == ua.NodeIdType.Numeric:
        return ua.NodeId(int(ident), ns)
    return ua.NodeId(ident, ns, t)


def parse_nodeid_literal(s: str) -> ua.NodeId:
    """NodeId literal without nsu= (value literals §12, fixture ids are resolved elsewhere)."""
    uri, ns, ident, t = parse_nodeid_syntax(s)
    if uri is not None:
        raise InputError(f"nsu= is not allowed in a NodeId literal: '{s}'")
    return make_nodeid(ident, ns, t)


# ── Value literals (§12) ──────────────────────────────────────────────────────

_SCALAR_TYPES = {
    "Boolean": ua.VariantType.Boolean,
    "SByte": ua.VariantType.SByte,
    "Byte": ua.VariantType.Byte,
    "Int16": ua.VariantType.Int16,
    "UInt16": ua.VariantType.UInt16,
    "Int32": ua.VariantType.Int32,
    "UInt32": ua.VariantType.UInt32,
    "Int64": ua.VariantType.Int64,
    "UInt64": ua.VariantType.UInt64,
    "Float": ua.VariantType.Float,
    "Double": ua.VariantType.Double,
    "String": ua.VariantType.String,
    "DateTime": ua.VariantType.DateTime,
    "Guid": ua.VariantType.Guid,
    "ByteString": ua.VariantType.ByteString,
    "XmlElement": ua.VariantType.XmlElement,
    "NodeId": ua.VariantType.NodeId,
    "ExpandedNodeId": ua.VariantType.ExpandedNodeId,
    "StatusCode": ua.VariantType.StatusCode,
    "QualifiedName": ua.VariantType.QualifiedName,
    "LocalizedText": ua.VariantType.LocalizedText,
    "ExtensionObject": ua.VariantType.ExtensionObject,
    "DataValue": ua.VariantType.DataValue,
    "Variant": ua.VariantType.Variant,
    "DiagnosticInfo": ua.VariantType.DiagnosticInfo,
}

_INT_RANGES = {
    "SByte": (-128, 127),
    "Byte": (0, 255),
    "Int16": (-32768, 32767),
    "UInt16": (0, 65535),
    "Int32": (-(2**31), 2**31 - 1),
    "UInt32": (0, 2**32 - 1),
    "Int64": (-(2**63), 2**63 - 1),
    "UInt64": (0, 2**64 - 1),
}


def parse_datetime(s: str) -> datetime:
    t = s.strip()
    if t.endswith("Z") or t.endswith("z"):
        t = t[:-1] + "+00:00"
    # Python accepts up to 6 fractional digits: trim 7-digit (100 ns) input.
    if "." in t:
        head, frac = t.split(".", 1)
        digits = ""
        i = 0
        while i < len(frac) and frac[i].isdigit():
            digits += frac[i]
            i += 1
        tail = frac[i:]
        digits = (digits + "000000")[:6]
        t = f"{head}.{digits}{tail}"
    dt = datetime.fromisoformat(t)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_expanded(s: str) -> ua.ExpandedNodeId:
    srv = 0
    uri = None
    rest = s
    if rest.startswith("svr="):
        semi = rest.find(";")
        if semi < 0:
            raise InputError(f"malformed ExpandedNodeId: '{s}'")
        srv = int(rest[4:semi])
        rest = rest[semi + 1 :]
    ns = 0
    if rest.startswith("nsu="):
        semi = rest.find(";")
        if semi < 0:
            raise InputError(f"malformed ExpandedNodeId: '{s}'")
        uri = rest[4:semi]
        rest = rest[semi + 1 :]
    elif rest.startswith("ns="):
        semi = rest.find(";")
        ns = int(rest[3:semi])
        rest = rest[semi + 1 :]
    ident, t = _parse_identifier(rest, s)
    if t == ua.NodeIdType.Numeric:
        e = ua.ExpandedNodeId(int(ident), ns)
    else:
        e = ua.ExpandedNodeId(ident, ns, t)
    e.NamespaceUri = uri
    e.ServerIndex = srv
    return e


def parse_scalar(type_name_: str, lit: str):
    t = type_name_
    try:
        if t == "Boolean":
            low = lit.strip().lower()
            if low in ("true", "1"):
                return True
            if low in ("false", "0"):
                return False
            raise ValueError(lit)
        if t in _INT_RANGES:
            n = int(lit.strip(), 10)
            lo, hi = _INT_RANGES[t]
            if n < lo or n > hi:
                raise ValueError(f"{lit} out of range for {t}")
            return n
        if t in ("Float", "Double"):
            low = lit.strip()
            if low in ("NaN", "nan"):
                return float("nan")
            if low in ("Infinity", "+Infinity", "inf"):
                return float("inf")
            if low in ("-Infinity", "-inf"):
                return float("-inf")
            return float(low)
        if t == "String":
            return lit
        if t == "DateTime":
            return parse_datetime(lit)
        if t == "Guid":
            return uuid.UUID(lit.strip())
        if t == "ByteString":
            return base64.b64decode(lit.strip(), validate=True)
        if t == "XmlElement":
            return ua.XmlElement(lit)
        if t == "NodeId":
            return parse_nodeid_literal(lit.strip())
        if t == "ExpandedNodeId":
            return parse_expanded(lit.strip())
        if t == "StatusCode":
            s = lit.strip()
            return ua.StatusCode(int(s, 16) if s.lower().startswith("0x") else int(s))
        if t == "QualifiedName":
            if ":" in lit:
                ns, name = lit.split(":", 1)
                try:
                    return ua.QualifiedName(name, int(ns))
                except ValueError:
                    return ua.QualifiedName(lit, 0)
            return ua.QualifiedName(lit, 0)
        if t == "LocalizedText":
            if ":" in lit:
                loc, text = lit.split(":", 1)
                return ua.LocalizedText(text, loc or None)
            return ua.LocalizedText(lit)
        if t == "ExtensionObject":
            tid, _, body = lit.partition("|")
            eo = ua.ExtensionObject()
            eo.TypeId = parse_nodeid_literal(tid.strip())
            eo.Body = base64.b64decode(body.strip(), validate=True) if body.strip() else None
            return eo
        if t == "Variant":
            inner_t, _, inner = lit.partition(":")
            return build_variant(inner_t, inner)
        if t == "DataValue":
            inner_t, _, inner = lit.partition(":")
            return ua.DataValue(build_variant(inner_t, inner))
        if t == "DiagnosticInfo":
            d = ua.DiagnosticInfo()
            for part in [p for p in lit.split(";") if p]:
                k, _, v = part.partition("=")
                if k == "symbolicId":
                    d.SymbolicId = int(v)
                elif k == "namespaceUri":
                    d.NamespaceURI = int(v)
                elif k == "localizedText":
                    d.LocalizedText = int(v)
                elif k == "locale":
                    d.Locale = int(v)
                elif k == "additionalInfo":
                    d.AdditionalInfo = v
                elif k == "innerStatusCode":
                    d.InnerStatusCode = ua.StatusCode(int(v, 16) if v.lower().startswith("0x") else int(v))
            return d
    except InputError:
        raise
    except Exception as e:
        raise InputError(f"invalid {t} literal '{lit}': {e}")
    raise InputError(f"unknown type: {t}")


def _split_array(lit: str) -> list[str]:
    s = lit.strip()
    if s == "":
        return []
    if s.startswith("["):
        try:
            arr = json.loads(s)
            return [x if isinstance(x, str) else json.dumps(x) for x in arr]
        except ValueError:
            pass
    return lit.split(",")


def build_variant(type_str: str, lit: str) -> ua.Variant:
    """Variant from a §12 literal. Raises InputError on unknown types / bad literals."""
    if type_str.endswith("[]"):
        base = type_str[:-2]
        if base not in _SCALAR_TYPES:
            raise InputError(f"unknown type: {type_str}")
        parts = _split_array(lit)
        if base == "Variant":
            vals = [parse_scalar("Variant", p) for p in parts]
        else:
            vals = [parse_scalar(base, p.strip() if base not in ("String", "XmlElement") else p) for p in parts]
        return ua.Variant(vals, _SCALAR_TYPES[base], is_array=True)
    if type_str not in _SCALAR_TYPES:
        raise InputError(f"unknown type: {type_str}")
    if type_str == "Variant":
        return parse_scalar("Variant", lit)
    return ua.Variant(parse_scalar(type_str, lit), _SCALAR_TYPES[type_str])


def lenient_variant(type_str: str, lit: str) -> ua.Variant:
    """write / call keep the pre-v0.7.0 leniency (§12): an unknown type or a
    malformed literal is sent as a String Variant and the server answers."""
    try:
        return build_variant(type_str, lit)
    except InputError:
        return ua.Variant(lit, ua.VariantType.String)


# ── Argument helpers ──────────────────────────────────────────────────────────


class Args:
    """Flag lookup with the same semantics as the other adapters: --flag value."""

    def __init__(self, argv: list[str]):
        self.argv = argv

    def get(self, flag: str, default=None):
        for i in range(len(self.argv) - 1):
            if self.argv[i] == flag:
                return self.argv[i + 1]
        return default

    def all(self, flag: str) -> list[str]:
        return [self.argv[i + 1] for i in range(len(self.argv) - 1) if self.argv[i] == flag]

    def has(self, flag: str) -> bool:
        return flag in self.argv

    def int(self, flag: str, default: int) -> int:
        v = self.get(flag)
        if v is None:
            return default
        try:
            return int(v)
        except ValueError:
            raise InputError(f"{flag}: not an integer: '{v}'")

    def float(self, flag: str, default: float) -> float:
        v = self.get(flag)
        if v is None:
            return default
        try:
            return float(v)
        except ValueError:
            raise InputError(f"{flag}: not a number: '{v}'")

    def bool(self, flag: str, default: bool) -> bool:
        v = self.get(flag)
        if v is None:
            return default
        low = v.lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "no"):
            return False
        raise InputError(f"{flag}: expected true or false, got '{v}'")
