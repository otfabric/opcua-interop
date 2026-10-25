// SPDX-License-Identifier: MIT
//
// Shared helpers of the node-opcua adapter: command-line parsing, the result
// envelope (docs/CLIENT_CONTRACT.md §3), status codes, the canonical NodeId
// form (§6), the canonical value encoding (§7) and value literals (§12).

import {
    BinaryStream,
    DataType,
    DataValue,
    ExpandedNodeId,
    LocalizedText,
    NodeId,
    NodeIdType,
    QualifiedName,
    StatusCode,
    StatusCodes,
    Variant,
    VariantArrayType,
    ConstantStatusCode,
} from "node-opcua";

export const ADAPTER = "node-opcua";
export const ADAPTER_VERSION = "0.12.0";
export const SCHEMA_VERSION = "1.0";

// ---------------------------------------------------------------------------
// Exit codes (§5)
// ---------------------------------------------------------------------------

export const EXIT_OK = 0;
export const EXIT_INPUT = 2;
export const EXIT_TRANSPORT = 3;
export const EXIT_SERVICE = 4;
export const EXIT_FIXTURE = 5;
export const EXIT_INTERNAL = 6;
export const EXIT_TIMEOUT = 7;

/** Invalid or unsupported command-line input: exit 2, error.category "input". */
export class InputError extends Error {}
/** Connect / transport failure: exit 3, error.category "transport". */
export class TransportError extends Error {
    constructor(message: string, public status?: number) {
        super(message);
    }
}
/** A Bad service result: exit 4, error.category "service". */
export class ServiceError extends Error {
    constructor(message: string, public status: number) {
        super(message);
    }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

export class Args {
    constructor(public readonly argv: string[]) {}

    get(name: string): string | undefined {
        let v: string | undefined;
        for (let i = 0; i < this.argv.length - 1; i++) {
            if (this.argv[i] === name) v = this.argv[i + 1];
        }
        return v;
    }

    all(name: string): string[] {
        const out: string[] = [];
        for (let i = 0; i < this.argv.length - 1; i++) {
            if (this.argv[i] === name) out.push(this.argv[i + 1]);
        }
        return out;
    }

    has(name: string): boolean {
        return this.argv.includes(name);
    }

    num(name: string, def: number): number {
        const v = this.get(name);
        if (v === undefined) return def;
        const n = Number(v);
        if (!Number.isFinite(n)) throw new InputError(`${name}: not a number: ${v}`);
        return n;
    }

    bool(name: string, def: boolean): boolean {
        const v = this.get(name);
        if (v === undefined) return def;
        if (v === "true" || v === "1") return true;
        if (v === "false" || v === "0") return false;
        throw new InputError(`${name}: expected true|false, got ${v}`);
    }
}

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

const statusNames = new Map<number, string>();
for (const [name, sc] of Object.entries(StatusCodes)) {
    if (sc && typeof (sc as StatusCode).value === "number") {
        const v = (sc as StatusCode).value >>> 0;
        if (!statusNames.has(v)) statusNames.set(v, name);
    }
}

export function severityOf(code: number): string {
    const top = (code >>> 30) & 0x3;
    return top === 0 ? "Good" : top === 1 ? "Uncertain" : "Bad";
}

/** The name of the code's upper 16 bits (§4; the info bits do not change it); unknown codes as 0xXXXXXXXX. */
export function statusName(code: number): string {
    code = code >>> 0;
    const base = (code & 0xffff0000) >>> 0;
    if (base === 0) return "Good";
    return statusNames.get(base) ?? `0x${code.toString(16).toUpperCase().padStart(8, "0")}`;
}

export interface StatusJson {
    name: string;
    code: number;
    severity: string;
}

/** A StatusCode object for any 32-bit code (node-opcua only knows the named ones). */
export function makeStatus(code: number): StatusCode {
    code = code >>> 0;
    for (const sc of Object.values(StatusCodes) as StatusCode[]) {
        if (sc && typeof sc.value === "number" && sc.value >>> 0 === code) return sc;
    }
    return new ConstantStatusCode({ value: code, name: statusName(code), description: "" });
}

export function statusJson(sc: StatusCode | number | null | undefined): StatusJson {
    const code = sc === null || sc === undefined ? 0 : typeof sc === "number" ? sc >>> 0 : sc.value >>> 0;
    return { name: statusName(code), code, severity: severityOf(code) };
}

export function codeOf(sc: StatusCode | number | null | undefined): number {
    if (sc === null || sc === undefined) return 0;
    return typeof sc === "number" ? sc >>> 0 : sc.value >>> 0;
}

export function isGood(sc: StatusCode | number | null | undefined): boolean {
    return severityOf(codeOf(sc)) === "Good";
}

export function isBad(sc: StatusCode | number | null | undefined): boolean {
    return severityOf(codeOf(sc)) === "Bad";
}

export function statusByName(name: string): number | undefined {
    const sc = (StatusCodes as unknown as Record<string, StatusCode>)[name];
    return sc ? sc.value >>> 0 : undefined;
}

/**
 * Best-effort extraction of an OPC UA status code from a node-opcua error:
 * the response's serviceResult, a statusCode property, or a Bad... symbol in
 * the message.
 */
export function statusFromError(err: unknown): number | undefined {
    const e = err as { response?: { responseHeader?: { serviceResult?: StatusCode } }; statusCode?: StatusCode | number; message?: string };
    const sr = e?.response?.responseHeader?.serviceResult;
    if (sr && sr.value !== 0) return sr.value >>> 0;
    if (e?.statusCode !== undefined) {
        const c = codeOf(e.statusCode as StatusCode | number);
        if (c !== 0) return c;
    }
    const msg = String(e?.message ?? err ?? "");
    const m = msg.match(/\b(Bad[A-Za-z0-9]+)/g);
    if (m) {
        for (const name of m) {
            const v = statusByName(name);
            if (v !== undefined) return v;
        }
    }
    const hex = msg.match(/0x8[0-9a-fA-F]{7}/);
    if (hex) return parseInt(hex[0], 16) >>> 0;
    return undefined;
}

// ---------------------------------------------------------------------------
// Result envelope (§3)
// ---------------------------------------------------------------------------

export class Result {
    success = true;
    serviceResult: StatusJson = statusJson(0);
    results: unknown[] = [];
    error: { category: string; message: string } | null = null;

    constructor(public operation: string) {}

    setService(sc: StatusCode | number | null | undefined): this {
        this.serviceResult = statusJson(sc);
        return this;
    }

    add(r: unknown): this {
        this.results.push(r);
        return this;
    }

    fail(category: string, message: string): this {
        this.success = false;
        this.error = { category, message };
        return this;
    }

    toJSON(): Record<string, unknown> {
        return {
            schemaVersion: SCHEMA_VERSION,
            adapter: ADAPTER,
            operation: this.operation,
            success: this.success,
            serviceResult: this.serviceResult,
            results: this.results,
            error: this.success ? null : this.error ?? { category: "service", message: "operation failed" },
        };
    }

    emit(): void {
        process.stdout.write(JSON.stringify(this.toJSON()) + "\n");
    }
}

export function log(level: string, msg: string): void {
    process.stderr.write(`[node-opcua] ${level}: ${msg}\n`);
}

// ---------------------------------------------------------------------------
// NodeIds (§6, §8)
// ---------------------------------------------------------------------------

export function nodeIdToString(n: NodeId | ExpandedNodeId | null | undefined): string {
    if (!n) return "i=0";
    const ns = n.namespace;
    const pre = ns === 0 ? "" : `ns=${ns};`;
    switch (n.identifierType) {
        case NodeIdType.NUMERIC:
            return `${pre}i=${n.value}`;
        case NodeIdType.STRING:
            return `ns=${ns};s=${n.value}`;
        case NodeIdType.GUID:
            return `ns=${ns};g=${String(n.value).toLowerCase()}`;
        case NodeIdType.BYTESTRING:
            return `ns=${ns};b=${(n.value as Buffer).toString("base64")}`;
    }
    return n.toString();
}

export function expandedNodeIdToString(e: ExpandedNodeId): string {
    let s = "";
    if (e.serverIndex) s += `svr=${e.serverIndex};`;
    if (e.namespaceUri) s += `nsu=${e.namespaceUri};`;
    else if (e.namespace) s += `ns=${e.namespace};`;
    switch (e.identifierType) {
        case NodeIdType.NUMERIC:
            return `${s}i=${e.value}`;
        case NodeIdType.STRING:
            return `${s}s=${e.value}`;
        case NodeIdType.GUID:
            return `${s}g=${String(e.value).toLowerCase()}`;
        case NodeIdType.BYTESTRING:
            return `${s}b=${(e.value as Buffer).toString("base64")}`;
    }
    return e.toString();
}

const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Parsed `--node` value: either a final NodeId or one that needs a namespace URI resolved. */
export interface ParsedNodeId {
    nsu?: string;
    ns: number;
    type: NodeIdType;
    value: number | string | Buffer;
}

export function parseNodeIdString(s: string): ParsedNodeId {
    const bad = () => new InputError(`malformed NodeId: '${s}'`);
    let rest = s;
    let ns = 0;
    let nsu: string | undefined;
    if (rest.startsWith("nsu=")) {
        const semi = rest.indexOf(";");
        if (semi < 0) throw bad();
        nsu = rest.substring(4, semi);
        if (!nsu) throw bad();
        rest = rest.substring(semi + 1);
    } else if (rest.startsWith("ns=")) {
        const semi = rest.indexOf(";");
        if (semi < 0) throw bad();
        const n = rest.substring(3, semi);
        if (!/^\d+$/.test(n) || Number(n) > 65535) throw bad();
        ns = Number(n);
        rest = rest.substring(semi + 1);
    }
    if (rest.length < 2 || rest[1] !== "=") throw bad();
    const kind = rest[0];
    const id = rest.substring(2);
    switch (kind) {
        case "i":
            if (!/^\d+$/.test(id) || Number(id) > 0xffffffff) throw bad();
            return { nsu, ns, type: NodeIdType.NUMERIC, value: Number(id) };
        case "s":
            if (id.length === 0) throw bad();
            return { nsu, ns, type: NodeIdType.STRING, value: id };
        case "g":
            if (!GUID_RE.test(id)) throw bad();
            return { nsu, ns, type: NodeIdType.GUID, value: id.toUpperCase() };
        case "b":
            if (!/^[A-Za-z0-9+/]*={0,2}$/.test(id)) throw bad();
            return { nsu, ns, type: NodeIdType.BYTESTRING, value: Buffer.from(id, "base64") };
    }
    throw bad();
}

export function makeNodeId(p: ParsedNodeId, ns: number): NodeId {
    return new NodeId(p.type, p.value as never, ns);
}

/** Resolve a parsed NodeId against a NamespaceArray; unknown URI → InputError. */
export function resolveParsed(p: ParsedNodeId, namespaceArray: string[] | undefined): NodeId {
    if (p.nsu === undefined) return makeNodeId(p, p.ns);
    const idx = (namespaceArray ?? []).indexOf(p.nsu);
    if (idx < 0) throw new InputError(`unknown namespace URI: ${p.nsu}`);
    return makeNodeId(p, idx);
}

// ---------------------------------------------------------------------------
// Values (§7)
// ---------------------------------------------------------------------------

export function dataTypeName(dt: DataType): string {
    return DataType[dt] ?? "Null";
}

function int64ToString(v: unknown, signed: boolean): string {
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "number") return String(Math.trunc(v));
    if (Array.isArray(v) && v.length === 2) {
        const hi = BigInt(v[0] >>> 0);
        const lo = BigInt(v[1] >>> 0);
        let x = (hi << 32n) | lo;
        if (signed && x >= 1n << 63n) x -= 1n << 64n;
        return x.toString();
    }
    return String(v);
}

/** Shortest decimal that reads back as the same float32. */
export function float32Number(v: number): number | null {
    if (!Number.isFinite(v)) return null;
    const f = Math.fround(v);
    for (let p = 1; p <= 9; p++) {
        const cand = Number(f.toPrecision(p));
        if (Math.fround(cand) === f) return cand;
    }
    return f;
}

export function dateToString(d: Date | null | undefined): string | null {
    if (!d || !(d instanceof Date) || Number.isNaN(d.getTime())) return null;
    return d.toISOString();
}

export function localizedTextJson(lt: LocalizedText | null | undefined): { locale: string; text: string } {
    return { locale: lt?.locale ?? "", text: lt?.text ?? "" };
}

export function qualifiedNameJson(q: QualifiedName | null | undefined): { ns: number; name: string } {
    return { ns: q?.namespaceIndex ?? 0, name: q?.name ?? "" };
}

function extensionObjectJson(v: unknown): unknown {
    if (v === null || v === undefined) return null;
    const o = v as {
        schema?: { encodingDefaultBinary?: NodeId; name?: string };
        binaryStoreSize?: () => number;
        encode?: (s: BinaryStream) => void;
        constructor?: { encodingDefaultBinary?: NodeId };
    };
    // OpaqueStructure (unknown type) keeps its raw body.
    const opaque = v as { nodeId?: NodeId; buffer?: Buffer };
    if (opaque.buffer && opaque.nodeId && !o.encode) {
        return { typeId: nodeIdToString(opaque.nodeId), encoding: "binary", body: opaque.buffer.toString("base64") };
    }
    try {
        const typeId = o.schema?.encodingDefaultBinary ?? o.constructor?.encodingDefaultBinary;
        const size = o.binaryStoreSize ? o.binaryStoreSize() : 0;
        const stream = new BinaryStream(size);
        o.encode?.(stream);
        const out: Record<string, unknown> = {
            typeId: typeId ? nodeIdToString(typeId) : "i=0",
            encoding: "binary",
            body: stream.buffer.subarray(0, stream.length).toString("base64"),
        };
        if (o.schema?.name) out.dataTypeName = o.schema.name;
        return out;
    } catch {
        return { typeId: "i=0", encoding: "binary", body: "" };
    }
}

export function scalarJson(dt: DataType, v: unknown): unknown {
    if (v === null || v === undefined) return null;
    switch (dt) {
        case DataType.Boolean:
            return !!v;
        case DataType.SByte:
        case DataType.Byte:
        case DataType.Int16:
        case DataType.UInt16:
        case DataType.Int32:
        case DataType.UInt32:
            return Number(v);
        case DataType.Int64:
            return int64ToString(v, true);
        case DataType.UInt64:
            return int64ToString(v, false);
        case DataType.Float:
            return float32Number(Number(v));
        case DataType.Double:
            return Number.isFinite(Number(v)) ? Number(v) : null;
        case DataType.String:
        case DataType.XmlElement:
            return String(v);
        case DataType.DateTime:
            return dateToString(v as Date);
        case DataType.Guid:
            return String(v).toLowerCase();
        case DataType.ByteString:
            return Buffer.isBuffer(v) ? v.toString("base64") : null;
        case DataType.NodeId:
            return nodeIdToString(v as NodeId);
        case DataType.ExpandedNodeId:
            return expandedNodeIdToString(v as ExpandedNodeId);
        case DataType.StatusCode:
            return statusJson(v as StatusCode);
        case DataType.QualifiedName:
            return qualifiedNameJson(v as QualifiedName);
        case DataType.LocalizedText:
            return localizedTextJson(v as LocalizedText);
        case DataType.ExtensionObject:
            return extensionObjectJson(v);
        case DataType.DataValue:
            return dataValueJson(v as DataValue);
        case DataType.Variant: {
            const inner = v as Variant;
            if (!inner || inner.dataType === DataType.Null) return null;
            return { dataType: dataTypeName(inner.dataType), builtInType: inner.dataType, value: variantValueJson(inner) };
        }
        case DataType.DiagnosticInfo:
            return diagnosticInfoJson(v);
    }
    return null;
}

function diagnosticInfoJson(v: unknown): unknown {
    const d = v as {
        symbolicId?: number;
        namespaceURI?: number;
        localizedText?: number;
        locale?: number;
        additionalInfo?: string | null;
        innerStatusCode?: StatusCode;
        innerDiagnosticInfo?: unknown;
    };
    const m: Record<string, unknown> = {};
    if (d.symbolicId !== undefined && d.symbolicId >= 0) m.symbolicId = d.symbolicId;
    if (d.namespaceURI !== undefined && d.namespaceURI >= 0) m.namespaceUri = d.namespaceURI;
    if (d.localizedText !== undefined && d.localizedText >= 0) m.localizedText = d.localizedText;
    if (d.locale !== undefined && d.locale >= 0) m.locale = d.locale;
    if (d.additionalInfo) m.additionalInfo = d.additionalInfo;
    if (d.innerStatusCode && d.innerStatusCode.value !== 0) m.innerStatusCode = statusJson(d.innerStatusCode);
    if (d.innerDiagnosticInfo) m.innerDiagnosticInfo = diagnosticInfoJson(d.innerDiagnosticInfo);
    return m;
}

/** Canonical JSON of a Variant's value: scalar, array or flattened matrix. */
export function variantValueJson(v: Variant | null | undefined): unknown {
    if (!v || v.dataType === DataType.Null) return null;
    if (v.arrayType === VariantArrayType.Scalar) return scalarJson(v.dataType, v.value);
    const arr = v.value as ArrayLike<unknown> | null;
    if (!arr) return [];
    const out: unknown[] = [];
    for (let i = 0; i < arr.length; i++) out.push(scalarJson(v.dataType, arr[i]));
    return out;
}

/** dataType / builtInType of a Variant ("Null"/0 when empty). */
export function variantType(v: Variant | null | undefined): { dataType: string; builtInType: number } {
    if (!v || v.dataType === DataType.Null) return { dataType: "Null", builtInType: 0 };
    return { dataType: dataTypeName(v.dataType), builtInType: v.dataType };
}

export function dataValueJson(dv: DataValue | null | undefined): Record<string, unknown> {
    const m: Record<string, unknown> = {};
    if (!dv) return m;
    if (dv.value && dv.value.dataType !== DataType.Null) {
        m.dataType = dataTypeName(dv.value.dataType);
        m.builtInType = dv.value.dataType;
        if (dv.value.arrayType === VariantArrayType.Matrix && dv.value.dimensions) {
            m.arrayDimensions = dv.value.dimensions;
        }
        m.value = variantValueJson(dv.value);
    }
    if (dv.statusCode && dv.statusCode.value !== 0) m.statusCode = statusJson(dv.statusCode);
    if (dv.sourceTimestamp) m.sourceTimestamp = dateToString(dv.sourceTimestamp);
    if (dv.sourcePicoseconds) m.sourcePicoseconds = dv.sourcePicoseconds;
    if (dv.serverTimestamp) m.serverTimestamp = dateToString(dv.serverTimestamp);
    if (dv.serverPicoseconds) m.serverPicoseconds = dv.serverPicoseconds;
    return m;
}

// ---------------------------------------------------------------------------
// Value literals (§12)
// ---------------------------------------------------------------------------

export function bigToInt64(x: bigint): number[] {
    const u = BigInt.asUintN(64, x);
    return [Number(u >> 32n), Number(u & 0xffffffffn)];
}

function parseNodeIdLiteral(s: string): NodeId {
    const p = parseNodeIdString(s);
    if (p.nsu !== undefined) throw new InputError(`NodeId literal must not use nsu=: ${s}`);
    return makeNodeId(p, p.ns);
}

function parseScalarLiteral(dt: DataType, s: string): unknown {
    const int = (min: bigint, max: bigint): bigint => {
        if (!/^[-+]?\d+$/.test(s.trim())) throw new InputError(`invalid integer literal: ${s}`);
        const v = BigInt(s.trim());
        if (v < min || v > max) throw new InputError(`integer out of range: ${s}`);
        return v;
    };
    switch (dt) {
        case DataType.Boolean:
            if (s === "true" || s === "1") return true;
            if (s === "false" || s === "0") return false;
            throw new InputError(`invalid Boolean literal: ${s}`);
        case DataType.SByte:
            return Number(int(-128n, 127n));
        case DataType.Byte:
            return Number(int(0n, 255n));
        case DataType.Int16:
            return Number(int(-32768n, 32767n));
        case DataType.UInt16:
            return Number(int(0n, 65535n));
        case DataType.Int32:
            return Number(int(-2147483648n, 2147483647n));
        case DataType.UInt32:
            return Number(int(0n, 4294967295n));
        case DataType.Int64:
            return bigToInt64(int(-(1n << 63n), (1n << 63n) - 1n));
        case DataType.UInt64:
            return bigToInt64(int(0n, (1n << 64n) - 1n));
        case DataType.Float:
        case DataType.Double: {
            if (s === "NaN") return NaN;
            if (s === "Infinity" || s === "+Infinity") return Infinity;
            if (s === "-Infinity") return -Infinity;
            const n = Number(s);
            if (s.trim() === "" || Number.isNaN(n)) throw new InputError(`invalid floating-point literal: ${s}`);
            return n;
        }
        case DataType.String:
        case DataType.XmlElement:
            return s;
        case DataType.DateTime: {
            const d = new Date(s);
            if (Number.isNaN(d.getTime())) throw new InputError(`invalid DateTime literal: ${s}`);
            return d;
        }
        case DataType.Guid:
            if (!GUID_RE.test(s)) throw new InputError(`invalid Guid literal: ${s}`);
            return s.toUpperCase();
        case DataType.ByteString:
            return Buffer.from(s, "base64");
        case DataType.NodeId:
            return parseNodeIdLiteral(s);
        case DataType.StatusCode: {
            const n = s.startsWith("0x") || s.startsWith("0X") ? parseInt(s.substring(2), 16) : Number(s);
            if (!Number.isFinite(n)) throw new InputError(`invalid StatusCode literal: ${s}`);
            return makeStatus(n >>> 0);
        }
        case DataType.QualifiedName: {
            const c = s.indexOf(":");
            if (c > 0 && /^\d+$/.test(s.substring(0, c))) {
                return new QualifiedName({ namespaceIndex: Number(s.substring(0, c)), name: s.substring(c + 1) });
            }
            return new QualifiedName({ namespaceIndex: 0, name: s });
        }
        case DataType.LocalizedText: {
            const c = s.indexOf(":");
            if (c >= 0) return new LocalizedText({ locale: s.substring(0, c) || null, text: s.substring(c + 1) });
            return new LocalizedText({ text: s });
        }
    }
    throw new InputError(`unsupported literal type: ${DataType[dt]}`);
}

function splitArrayLiteral(s: string): string[] {
    if (s === "") return [];
    if (s.trim().startsWith("[")) {
        try {
            const arr = JSON.parse(s);
            if (Array.isArray(arr)) return arr.map((x) => String(x));
        } catch {
            /* fall through */
        }
    }
    return s.split(",");
}

export function parseTypeName(t: string): { dt: DataType; array: boolean } {
    const array = t.endsWith("[]");
    const base = array ? t.substring(0, t.length - 2) : t;
    const dt = (DataType as unknown as Record<string, DataType>)[base];
    if (dt === undefined || typeof dt !== "number" || dt === DataType.Null) {
        throw new InputError(`unknown type: ${t}`);
    }
    return { dt, array };
}

/** Builds a Variant from `--type` / `--value` (strict: InputError on a bad literal). */
export function buildVariant(type: string, value: string): Variant {
    const { dt, array } = parseTypeName(type);
    if (array) {
        const parts = splitArrayLiteral(value);
        return new Variant({ dataType: dt, arrayType: VariantArrayType.Array, value: parts.map((p) => parseScalarLiteral(dt, p)) });
    }
    return new Variant({ dataType: dt, arrayType: VariantArrayType.Scalar, value: parseScalarLiteral(dt, value) });
}

/**
 * write / call keep the contract's pre-v0.7.0 leniency (§12): an unknown type
 * or a malformed literal is sent as a String Variant and the server answers.
 */
export function buildVariantLenient(type: string, value: string): Variant {
    try {
        return buildVariant(type, value);
    } catch {
        return new Variant({ dataType: DataType.String, value });
    }
}
