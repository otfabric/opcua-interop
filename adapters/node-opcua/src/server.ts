// SPDX-License-Identifier: MIT
//
// `server` command: an OPCUAServer exposing the fixture address space
// (docs/CONTAINER_CONTRACT.md §10, §11).

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
    DataType,
    DataValue,
    LocalizedText,
    makeRoles,
    MessageSecurityMode,
    NodeId,
    OPCUACertificateManager,
    OPCUAServer,
    QualifiedName,
    RegisterServerMethod,
    SecurityPolicy,
    StatusCode,
    StatusCodes,
    Variant,
    VariantArrayType,
} from "node-opcua";

import { installPushCertificateManagementOnServer } from "node-opcua-server-configuration";
import { ALARM_CLEAR, ALARM_NODE, ALARM_RESET, AlarmFixture, ALARMS_SOURCE, installAlarmFixture } from "./alarms.js";
import { BehaviorDef, Fixture, loadFixture, NodeDef } from "./fixture.js";
import { ADAPTER, ADAPTER_VERSION, bigToInt64, log, makeStatus, parseNodeIdString, parseTypeName } from "./util.js";
import { stackVersion } from "./capabilities.js";

const WELL_KNOWN_ROLES = new Set(["Observer", "Operator", "Engineer", "Supervisor", "ConfigureAdmin", "SecurityAdmin"]);

const EVENTS_SOURCE = "Events.Source";
const HISTORY_NODE = "History.Temperature";

interface ServerOptions {
    fixturePath?: string;
    bindAddress: string;
    bindPort?: number;
    advertisedHost: string;
    advertisedPort?: number;
    endpointPath?: string;
    readyFile: string;
    readyFileExplicit: boolean;
    pkiDir: string;
    certificate?: string;
    privateKey?: string;
    reverseConnect: string[];
    reverseConnectIntervalMs: number;
    registerWith?: string;
    registerIntervalMs: number;
}

const UNSUPPORTED_SERVER_FLAGS: Record<string, string> = {
    "--lds": "node-opcua's OPCUAServer is no Local Discovery Server (node-opcua ships the LDS as a separate OPCUADiscoveryServer without the fixture address space); not run by this adapter",
    "--lds-cleanup-timeout": "--lds is not supported by this adapter",
    "--mdns-name": "mDNS announcement (RegisterServerMethod.MDNS) is not wired into this adapter",
    "--mdns-capability": "mDNS announcement is not wired into this adapter",
    "--pubsub-config": "node-opcua has no open-source PubSub (Part 14) runtime (PubSub is a commercial Sterfive add-on)",
};

function parseServerArgs(argv: string[]): ServerOptions {
    for (const a of argv) {
        const why = UNSUPPORTED_SERVER_FLAGS[a];
        if (why) {
            log("error", `${a} is not supported: ${why}`);
            process.exit(2);
        }
    }
    const o: ServerOptions = {
        fixturePath: process.env.OPCUA_FIXTURE || undefined,
        bindAddress: "0.0.0.0",
        advertisedHost: "localhost",
        readyFile: process.env.OPCUA_READY_FILE || "/run/opcua-interop/ready",
        readyFileExplicit: false,
        pkiDir: "/run/opcua-interop/pki",
        reverseConnect: [],
        reverseConnectIntervalMs: 1000,
        registerIntervalMs: 30000,
    };
    const int = (flag: string, v: string): number => {
        const n = Number(v);
        if (!Number.isInteger(n) || n < 0) {
            log("error", `${flag}: not an integer: ${v}`);
            process.exit(2);
        }
        return n;
    };
    for (let i = 0; i < argv.length - 1; i++) {
        const v = argv[i + 1];
        switch (argv[i]) {
            case "--fixture": o.fixturePath = v; break;
            case "--bind-address": o.bindAddress = v; break;
            case "--bind-port": o.bindPort = int(argv[i], v); break;
            case "--advertised-host": o.advertisedHost = v; break;
            case "--advertised-port": o.advertisedPort = int(argv[i], v); break;
            case "--endpoint-path": o.endpointPath = v; break;
            case "--ready-file": o.readyFile = v; o.readyFileExplicit = true; break;
            case "--pki-dir": o.pkiDir = v; break;
            case "--certificate": o.certificate = v; break;
            case "--private-key": o.privateKey = v; break;
            case "--reverse-connect": o.reverseConnect.push(v); break;
            case "--reverse-connect-interval-ms": o.reverseConnectIntervalMs = Math.max(100, int(argv[i], v)); break;
            case "--register-with": o.registerWith = v; break;
            case "--register-interval-ms": o.registerIntervalMs = Math.max(500, int(argv[i], v)); break;
            case "--ecc-dir": log("warn", "--ecc-dir ignored: node-opcua implements no ECC SecurityPolicy"); break;
        }
    }
    return o;
}

// ---------------------------------------------------------------------------
// PKI
// ---------------------------------------------------------------------------

function isWritableDir(dir: string): boolean {
    try {
        fs.mkdirSync(dir, { recursive: true });
        const probe = path.join(dir, `.probe-${process.pid}`);
        fs.writeFileSync(probe, "");
        fs.unlinkSync(probe);
        return true;
    } catch {
        return false;
    }
}

function copyDir(src: string, dst: string): void {
    fs.mkdirSync(dst, { recursive: true });
    for (const e of fs.readdirSync(src, { withFileTypes: true })) {
        const s = path.join(src, e.name);
        const d = path.join(dst, e.name);
        if (e.isDirectory()) copyDir(s, d);
        else if (e.isFile()) fs.copyFileSync(s, d);
    }
}

/** The PKI directory the certificate manager writes to (a writable copy when the given one is read-only). */
function usablePkiDir(dir: string): string {
    if (isWritableDir(dir)) return dir;
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-pki-"));
    if (fs.existsSync(dir)) copyDir(dir, tmp);
    log("warn", `--pki-dir ${dir} is not writable; using a copy in ${tmp}`);
    return tmp;
}

/** PEM or DER certificate file → DER. */
export function readCertificateDer(file: string): Buffer {
    const raw = fs.readFileSync(file);
    const text = raw.toString("latin1");
    const m = text.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
    if (m) return Buffer.from(m[1].replace(/\s+/g, ""), "base64");
    return raw;
}

export function certificateUri(der: Buffer): string | undefined {
    try {
        const x = new crypto.X509Certificate(der);
        const san = x.subjectAltName ?? "";
        const m = san.match(/URI:([^,\s]+)/);
        return m ? m[1] : undefined;
    } catch {
        return undefined;
    }
}

/** Writes PEM copies node-opcua can read (it wants PEM; the contract allows DER). */
export function toPemFiles(certFile: string, keyFile: string, dir: string): { cert: string; key: string } {
    const der = readCertificateDer(certFile);
    const certPem = `-----BEGIN CERTIFICATE-----\n${der.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "")}\n-----END CERTIFICATE-----\n`;
    const keyRaw = fs.readFileSync(keyFile);
    let keyPem: string;
    if (keyRaw.toString("latin1").includes("-----BEGIN")) {
        keyPem = crypto.createPrivateKey(keyRaw).export({ format: "pem", type: "pkcs8" }).toString();
    } else {
        keyPem = crypto.createPrivateKey({ key: keyRaw, format: "der", type: "pkcs8" }).export({ format: "pem", type: "pkcs8" }).toString();
    }
    fs.mkdirSync(dir, { recursive: true });
    const cert = path.join(dir, "cert.pem");
    const key = path.join(dir, "key.pem");
    fs.writeFileSync(cert, certPem);
    fs.writeFileSync(key, keyPem, { mode: 0o600 });
    return { cert, key };
}

// ---------------------------------------------------------------------------
// Security profiles
// ---------------------------------------------------------------------------

export const POLICIES: Record<string, SecurityPolicy> = {
    None: SecurityPolicy.None,
    Basic128Rsa15: SecurityPolicy.Basic128Rsa15,
    Basic256: SecurityPolicy.Basic256,
    Basic256Sha256: SecurityPolicy.Basic256Sha256,
    Aes128_Sha256_RsaOaep: SecurityPolicy.Aes128_Sha256_RsaOaep,
    Aes256_Sha256_RsaPss: SecurityPolicy.Aes256_Sha256_RsaPss,
};

// ---------------------------------------------------------------------------
// Address space
// ---------------------------------------------------------------------------

const ACCESS_BITS: Record<string, number> = {
    CurrentRead: 0x01,
    CurrentWrite: 0x02,
    HistoryRead: 0x04,
    HistoryWrite: 0x08,
    SemanticChange: 0x10,
    StatusWrite: 0x20,
    TimestampWrite: 0x40,
};

function accessLevel(levels: string[] | undefined): number {
    let v = 0;
    for (const l of levels ?? []) v |= ACCESS_BITS[l] ?? 0;
    return v || ACCESS_BITS.CurrentRead;
}

function fixtureScalar(dt: DataType, v: unknown, resolve: (s: string) => NodeId): unknown {
    switch (dt) {
        case DataType.Boolean: return typeof v === "boolean" ? v : String(v) === "true";
        case DataType.Int64:
        case DataType.UInt64: return bigToInt64(BigInt(String(v)));
        case DataType.DateTime: return new Date(String(v));
        case DataType.Guid: return String(v).toUpperCase();
        case DataType.ByteString: return Buffer.from(String(v ?? ""), "base64");
        case DataType.NodeId: return resolve(String(v));
        case DataType.QualifiedName: {
            const s = String(v);
            const c = s.indexOf(":");
            if (c > 0 && /^\d+$/.test(s.substring(0, c))) return new QualifiedName({ namespaceIndex: Number(s.substring(0, c)), name: s.substring(c + 1) });
            return new QualifiedName({ name: s });
        }
        case DataType.LocalizedText: {
            const s = String(v);
            const c = s.indexOf(":");
            return c >= 0 ? new LocalizedText({ locale: s.substring(0, c), text: s.substring(c + 1) }) : new LocalizedText({ text: s });
        }
        case DataType.StatusCode: return makeStatus(Number(v) >>> 0);
        case DataType.String:
        case DataType.XmlElement: return String(v);
        default: return Number(v);
    }
}

function fixtureVariant(n: NodeDef, resolve: (s: string) => NodeId): Variant {
    const dt = parseTypeName(n.dataType ?? "BaseDataType").dt;
    const rank = n.valueRank ?? -1;
    const v = n.initialValue;
    if (rank >= 1 && Array.isArray(v)) {
        const values = v.map((x) => fixtureScalar(dt, x, resolve));
        if (rank >= 2 && n.arrayDimensions && n.arrayDimensions.length >= 2) {
            return new Variant({ dataType: dt, arrayType: VariantArrayType.Matrix, dimensions: n.arrayDimensions, value: values });
        }
        return new Variant({ dataType: dt, arrayType: VariantArrayType.Array, value: values });
    }
    if (v === undefined || v === null) return new Variant({ dataType: DataType.Null });
    return new Variant({ dataType: dt, arrayType: VariantArrayType.Scalar, value: fixtureScalar(dt, v, resolve) });
}

function localId(fixtureNodeId: string): string {
    const p = parseNodeIdString(fixtureNodeId);
    return String(p.value);
}

export const METHOD_BEHAVIORS = ["Add", "Multiply", "Echo", "NoArguments", "MultipleOutputs", "Fail"];
export const BEHAVIOR_KINDS = ["counter", "toggle", "ramp", "fixed-status"];

export class AddressSpaceBuilder {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    nodes = new Map<string, any>();
    timers: NodeJS.Timeout[] = [];
    /** What the fixture asks for and the address space could not realise (the selftest fails on any). */
    problems: string[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    constructor(private server: OPCUAServer, private fixture: Fixture, private ns: any) {}

    get addressSpace() {
        return this.server.engine.addressSpace!;
    }

    resolve = (s: string): NodeId => {
        const p = parseNodeIdString(s);
        if (p.nsu !== undefined) {
            const idx = this.addressSpace.getNamespaceIndex(p.nsu);
            return new NodeId(p.type, p.value as never, idx < 0 ? this.ns.index : idx);
        }
        return new NodeId(p.type, p.value as never, p.ns);
    };

    browseName(s: string): QualifiedName {
        const c = s.indexOf(":");
        if (c > 0 && /^\d+$/.test(s.substring(0, c))) {
            const idx = Number(s.substring(0, c));
            // The fixture's "1:" is its own namespace, whatever index it got here.
            return new QualifiedName({ namespaceIndex: idx === 0 ? 0 : this.ns.index, name: s.substring(c + 1) });
        }
        return new QualifiedName({ namespaceIndex: this.ns.index, name: s });
    }

    parent(n: NodeDef) {
        const id = this.resolve(n.parentNodeId ?? "i=85");
        return this.nodes.get(id.toString()) ?? this.addressSpace.findNode(id);
    }

    build(): void {
        for (const n of this.fixture.nodes ?? []) {
            try {
                const node = this.addNode(n);
                if (node) this.nodes.set(node.nodeId.toString(), node);
            } catch (e) {
                this.problems.push(`node ${n.nodeId}: ${(e as Error).message}`);
                log("warn", `cannot create node ${n.nodeId}: ${(e as Error).message}`);
            }
        }
        for (const b of this.fixture.behaviors ?? []) {
            if (!BEHAVIOR_KINDS.includes(b.kind)) this.problems.push(`behavior ${b.target}: unknown kind ${b.kind}`);
            if (!this.nodes.has(this.resolve(b.target).toString())) this.problems.push(`behavior ${b.target}: target not in the address space`);
        }
        this.setDiagnostics();
        this.buildAlarms();
    }

    alarms?: AlarmFixture;

    /** The Alarms & Conditions fixture (serverFeatures "alarms"), next to s=Events below s=Compatibility. */
    buildAlarms(): void {
        try {
            const compat = this.nodes.get(new NodeId(2 /* STRING */, "Compatibility" as never, this.ns.index).toString());
            this.alarms = installAlarmFixture(this.addressSpace, this.ns, compat);
        } catch (e) {
            this.problems.push(`alarms fixture: ${(e as Error).message}`);
            log("warn", `cannot create the alarms fixture: ${(e as Error).message}`);
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    addNode(n: NodeDef): any {
        const nodeId = this.resolve(n.nodeId);
        const parent = this.parent(n);
        const ref = n.referenceType === "HasComponent" ? "componentOf" : "organizedBy";
        const common = {
            nodeId,
            browseName: this.browseName(n.browseName),
            displayName: new LocalizedText({ locale: "en", text: n.displayName ?? localId(n.nodeId) }),
            description: n.description ? new LocalizedText({ locale: "en", text: n.description }) : undefined,
        };
        switch (n.nodeClass) {
            case "Object": {
                const isEvents = localId(n.nodeId) === EVENTS_SOURCE;
                return this.ns.addObject({
                    ...common,
                    [ref]: parent,
                    typeDefinition: n.typeDefinition ? this.resolve(n.typeDefinition) : "FolderType",
                    eventNotifier: isEvents ? 1 : 0,
                });
            }
            case "Variable":
                return this.addVariable(n, common, parent, ref);
            case "Method":
                return this.addMethod(n, common, parent);
        }
        this.problems.push(`node ${n.nodeId}: unknown nodeClass ${n.nodeClass}`);
        return undefined;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    addVariable(n: NodeDef, common: any, parent: any, ref: string): any {
        const dt = parseTypeName(n.dataType ?? "BaseDataType").dt;
        const al = accessLevel(n.accessLevel);
        const value = fixtureVariant(n, this.resolve);
        const opts = {
            ...common,
            [ref]: parent,
            dataType: DataType[dt],
            valueRank: n.valueRank ?? -1,
            arrayDimensions: n.arrayDimensions ?? null,
            accessLevel: al,
            userAccessLevel: al,
            minimumSamplingInterval: 0,
        };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let v: any;
        if (n.euRange) {
            v = this.ns.addAnalogDataItem({
                ...opts,
                engineeringUnitsRange: { low: n.euRange.low, high: n.euRange.high },
                acceptValueOutOfRange: true,
            });
        } else {
            v = this.ns.addVariable(opts);
        }
        if (value.dataType !== DataType.Null) v.setValueFromSource(value, StatusCodes.Good);
        if (localId(n.nodeId) === HISTORY_NODE) this.installHistory(v);
        return v;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    installHistory(v: any): void {
        // node-opcua's own in-memory historian serves HistoryRead (raw, with
        // its continuation points); the fixture's samples are pushed into it.
        this.addressSpace.installHistoricalDataNode(v, { maxOnlineValues: 100 });
        v.historizing = true;
        const base = Date.parse("2026-07-24T10:00:00Z");
        const historian = v.varHistorian;
        // Only the fixture's samples: drop what installHistoricalDataNode
        // recorded from the current value.
        while (historian._timeline.length > 0) historian._timeline.shift();
        historian.lastDate = new Date(1600, 0, 1);
        for (let i = 0; i < 5; i++) {
            const ts = new Date(base + i * 5000);
            historian.push(
                new DataValue({
                    value: new Variant({ dataType: DataType.Double, value: 20 + i }),
                    statusCode: StatusCodes.Good,
                    sourceTimestamp: ts,
                    serverTimestamp: ts,
                }),
            );
        }
    }

    args(defs: NodeDef["inputArguments"]) {
        return (defs ?? []).map((a) => ({
            name: a.name,
            dataType: parseTypeName(a.dataType).dt,
            valueRank: a.valueRank ?? -1,
            description: a.description ? new LocalizedText({ locale: "en", text: a.description }) : undefined,
        }));
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    addMethod(n: NodeDef, common: any, parent: any): any {
        if (!METHOD_BEHAVIORS.includes(n.methodBehavior ?? "")) {
            this.problems.push(`method ${n.nodeId}: unknown methodBehavior ${n.methodBehavior}`);
        }
        const m = this.ns.addMethod(parent, {
            ...common,
            inputArguments: this.args(n.inputArguments),
            outputArguments: this.args(n.outputArguments),
        });
        const behavior = n.methodBehavior ?? "";
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        m.bindMethod(async (inputs: Variant[], _context: unknown) => {
            const num = (i: number) => Number(inputs[i]?.value);
            switch (behavior) {
                case "Add":
                    return { statusCode: StatusCodes.Good, outputArguments: [new Variant({ dataType: DataType.Int32, value: (num(0) + num(1)) | 0 })] };
                case "Multiply":
                    return { statusCode: StatusCodes.Good, outputArguments: [new Variant({ dataType: DataType.Double, value: num(0) * num(1) })] };
                case "Echo":
                    return { statusCode: StatusCodes.Good, outputArguments: [new Variant({ dataType: DataType.String, value: inputs[0]?.value })] };
                case "NoArguments":
                    return { statusCode: StatusCodes.Good, outputArguments: [new Variant({ dataType: DataType.Boolean, value: true })] };
                case "MultipleOutputs":
                    return {
                        statusCode: StatusCodes.Good,
                        outputArguments: [
                            new Variant({ dataType: DataType.Int32, value: (num(0) * 2) | 0 }),
                            new Variant({ dataType: DataType.String, value: String(num(0) | 0) }),
                        ],
                    };
                case "Fail":
                    return { statusCode: StatusCodes.BadInternalError };
            }
            return { statusCode: StatusCodes.BadNotImplemented };
        });
        return m;
    }

    setDiagnostics(): void {
        const set = (name: string, text: string) => {
            const v = this.nodes.get(new NodeId(2 /* STRING */, name as never, this.ns.index).toString());
            if (v) v.setValueFromSource(new Variant({ dataType: DataType.String, value: text }), StatusCodes.Good);
        };
        set("Diagnostics.AdapterName", ADAPTER);
        set("Diagnostics.StackVersion", `node-opcua ${stackVersion()}`);
    }

    variable(local: string) {
        return this.nodes.get(new NodeId(2 /* STRING */, local as never, this.ns.index).toString());
    }

    startBehaviors(): void {
        for (const b of this.fixture.behaviors ?? []) {
            const v = this.nodes.get(this.resolve(b.target).toString());
            if (!v) {
                log("warn", `behavior target not found: ${b.target}`);
                continue;
            }
            this.startBehavior(v, b);
        }
        const src = this.variable(EVENTS_SOURCE);
        if (src) {
            const emit = () => {
                try {
                    src.raiseEvent("BaseEventType", {
                        sourceName: { dataType: DataType.String, value: "Events.Source" },
                        sourceNode: { dataType: DataType.NodeId, value: src.nodeId },
                        message: { dataType: DataType.LocalizedText, value: new LocalizedText({ locale: "en", text: "peer-event" }) },
                        severity: { dataType: DataType.UInt16, value: 500 },
                    });
                } catch (e) {
                    log("warn", `BaseEvent emission failed: ${(e as Error).message}`);
                }
            };
            const first = setTimeout(() => {
                emit();
                this.timers.push(setInterval(emit, 2000));
            }, 500);
            this.timers.push(first);
        } else {
            log("warn", "Events.Source not present; BaseEvent emission disabled");
        }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    startBehavior(v: any, b: BehaviorDef): void {
        const every = (ms: number, f: () => void) => {
            f();
            this.timers.push(setInterval(f, ms));
        };
        const ms = b.intervalMs ?? 1000;
        switch (b.kind) {
            case "counter": {
                let c = BigInt(Math.trunc(b.initial ?? 0));
                const inc = BigInt(Math.trunc(b.increment ?? 1));
                every(ms, () => {
                    v.setValueFromSource(new Variant({ dataType: DataType.Int64, arrayType: VariantArrayType.Scalar, value: bigToInt64(c) }), StatusCodes.Good);
                    c += inc;
                });
                break;
            }
            case "toggle": {
                let s = false;
                every(ms, () => {
                    s = !s;
                    v.setValueFromSource(new Variant({ dataType: DataType.Boolean, value: s }), StatusCodes.Good);
                });
                break;
            }
            case "ramp": {
                let r = b.initial ?? 0;
                const inc = b.increment ?? 1, min = b.minimum ?? 0, max = b.maximum ?? 100;
                every(ms, () => {
                    const val = r;
                    r += inc;
                    if (r > max) r = min;
                    v.setValueFromSource(new Variant({ dataType: DataType.Double, value: val }), StatusCodes.Good);
                });
                break;
            }
            case "fixed-status": {
                const cur = v.readValue().value;
                v.setValueFromSource(cur, makeStatus((b.initial ?? 0) >>> 0));
                break;
            }
            default:
                log("warn", `unknown behavior kind: ${b.kind}`);
        }
    }
}

/**
 * What of the fixture this adapter's server cannot realise: the address space
 * is built in a node-opcua server that is initialised but never started
 * (nothing is bound), then the security profiles are checked. Used by `test`.
 */
export async function fixtureProblems(fixture: Fixture): Promise<string[]> {
    const problems: string[] = [];
    if (!fixture.namespaces?.length) return ["fixture declares no namespace"];
    for (const sp of fixture.securityProfiles ?? []) {
        if (!POLICIES[sp.securityPolicy] && !sp.securityPolicy.startsWith("ECC_")) {
            problems.push(`security profile ${sp.securityPolicy}/${sp.securityMode}: not implemented`);
        }
        if (!["None", "Sign", "SignAndEncrypt"].includes(sp.securityMode)) {
            problems.push(`security profile ${sp.securityPolicy}/${sp.securityMode}: unknown mode`);
        }
    }
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-selftest-"));
    const server = new OPCUAServer({
        port: 0,
        serverCertificateManager: new OPCUACertificateManager({ rootFolder: path.join(work, "pki"), disableFileWatchers: true }),
        serverInfo: { applicationUri: fixture.server?.applicationUri },
    });
    try {
        await server.initialize();
        const ns = server.engine.addressSpace!.registerNamespace(fixture.namespaces[0].uri);
        const builder = new AddressSpaceBuilder(server, fixture, ns);
        builder.build();
        problems.push(...builder.problems);
        for (const n of fixture.nodes ?? []) {
            if (!server.engine.addressSpace!.findNode(builder.resolve(n.nodeId))) problems.push(`node ${n.nodeId}: missing from the address space`);
        }
        const history = builder.variable(HISTORY_NODE);
        if (history && !history.historizing) problems.push(`${HISTORY_NODE}: no history installed`);
        for (const local of [ALARMS_SOURCE, ALARM_NODE, ALARM_RESET, ALARM_CLEAR]) {
            if (!server.engine.addressSpace!.findNode(new NodeId(2 /* STRING */, local as never, ns.index))) problems.push(`alarms fixture: ${local} missing`);
        }
        const alarm = builder.alarms?.alarm;
        if (alarm && (!alarm.audibleEnabled || !alarm.audibleSound)) problems.push("alarms fixture: AudibleEnabled / AudibleSound missing");
    } finally {
        await server.shutdown(0).catch(() => undefined);
        fs.rmSync(work, { recursive: true, force: true });
    }
    return problems;
}

// ---------------------------------------------------------------------------
// Ready file (§10)
// ---------------------------------------------------------------------------

function removeReadyFile(file: string): void {
    try {
        fs.unlinkSync(file);
    } catch {
        /* absent */
    }
}

function writeReadyFile(file: string, fixtureId: string, endpoint: string): void {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    removeReadyFile(file);
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ ready: true, adapter: ADAPTER, fixture: fixtureId, endpoint }) + "\n");
    fs.renameSync(tmp, file);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function serverCommand(argv: string[]): Promise<void> {
    const o = parseServerArgs(argv);
    if (!o.fixturePath) {
        log("error", "missing --fixture");
        process.exit(1);
    }
    let fixture: Fixture;
    try {
        fixture = loadFixture(o.fixturePath);
    } catch (e) {
        log("error", `cannot load fixture ${o.fixturePath}: ${(e as Error).message}`);
        process.exit(5);
    }
    log("info", `fixture loaded: id=${fixture.id}`);

    // Stale ready file of a previous run (§10 step 1).
    try {
        removeReadyFile(o.readyFile);
    } catch {
        /* ignore */
    }

    const bindPort = o.bindPort ?? fixture.endpoint?.port ?? 4840;
    const advertisedPort = o.advertisedPort ?? bindPort;
    const endpointPath = o.endpointPath ?? fixture.endpoint?.path ?? "/";
    const resourcePath = endpointPath.replace(/^\/+/, "");
    const advertised = `opc.tcp://${o.advertisedHost}:${advertisedPort}${endpointPath}`;
    log("info", `advertised endpoint: ${advertised}`);

    // Certificate and PKI.
    let applicationUri = fixture.server.applicationUri;
    let certificateFile: string | undefined;
    let privateKeyFile: string | undefined;
    const secure = !!(o.certificate && o.privateKey);
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-server-"));
    if (secure) {
        try {
            const pem = toPemFiles(o.certificate!, o.privateKey!, path.join(work, "own"));
            certificateFile = pem.cert;
            privateKeyFile = pem.key;
            applicationUri = certificateUri(readCertificateDer(o.certificate!)) ?? applicationUri;
            log("info", `server certificate loaded from ${o.certificate}`);
        } catch (e) {
            log("error", `cannot load server certificate or key: ${(e as Error).message}`);
            process.exit(6);
        }
    }
    // Without a certificate only None/None is offered; node-opcua still wants
    // an application certificate, which it creates itself in a scratch PKI.
    const pkiRoot = secure ? usablePkiDir(o.pkiDir) : path.join(work, "pki");
    const serverCertificateManager = new OPCUACertificateManager({
        rootFolder: pkiRoot,
        automaticallyAcceptUnknownCertificate: false,
        disableFileWatchers: true,
    });
    if (secure) {
        // Push certificate management serves the certificate manager's own
        // pair (<pki>/own/certs/certificate.pem and its private key): put the
        // --certificate / --private-key pair there.
        const ownCert = path.join(pkiRoot, "own", "certs", "certificate.pem");
        const ownKey = serverCertificateManager.privateKey;
        fs.mkdirSync(path.dirname(ownCert), { recursive: true });
        fs.mkdirSync(path.dirname(ownKey), { recursive: true });
        fs.copyFileSync(certificateFile!, ownCert);
        fs.copyFileSync(privateKeyFile!, ownKey);
        certificateFile = ownCert;
        privateKeyFile = ownKey;
    }

    const securityPolicies = new Set<SecurityPolicy>([SecurityPolicy.None]);
    const securityModes = new Set<MessageSecurityMode>([MessageSecurityMode.None]);
    if (secure) {
        for (const sp of fixture.securityProfiles ?? []) {
            const p = POLICIES[sp.securityPolicy];
            if (!p) {
                log("info", `skipping security profile ${sp.securityPolicy}/${sp.securityMode}: not implemented by node-opcua`);
                continue;
            }
            if (p === SecurityPolicy.None) continue;
            securityPolicies.add(p);
            if (sp.securityMode === "Sign") securityModes.add(MessageSecurityMode.Sign);
            if (sp.securityMode === "SignAndEncrypt") securityModes.add(MessageSecurityMode.SignAndEncrypt);
        }
    }

    const users = fixture.users ?? [];
    // node-opcua offers UserName on the None endpoint only with an encrypted
    // password: one token policy per securityPolicies entry (password
    // encrypted with the server certificate). Listing the RSA policies with
    // securityModes [None] adds those token policies without adding secure
    // endpoints; node-opcua 2.187 does not pass allowUnsecurePassword through.
    if (users.length) {
        securityPolicies.add(SecurityPolicy.Basic256Sha256);
        securityPolicies.add(SecurityPolicy.Aes128_Sha256_RsaOaep);
    }
    const server = new OPCUAServer({
        port: bindPort,
        host: o.bindAddress === "0.0.0.0" ? undefined : o.bindAddress,
        hostname: o.advertisedHost,
        resourcePath: resourcePath ? `/${resourcePath}` : "",
        advertisedEndpoints: advertisedPort !== bindPort ? [advertised] : undefined,
        securityPolicies: [...securityPolicies],
        securityModes: [...securityModes],
        allowAnonymous: true,
        certificateFile,
        privateKeyFile,
        serverCertificateManager,
        serverInfo: {
            applicationUri,
            productUri: fixture.server.productUri,
            applicationName: new LocalizedText({ locale: "en", text: fixture.server.applicationName }),
        },
        buildInfo: {
            productName: "opcua-interop-node-opcua",
            productUri: fixture.server.productUri,
            manufacturerName: "OTFabric",
            softwareVersion: ADAPTER_VERSION,
            buildNumber: stackVersion(),
            buildDate: new Date(),
        },
        userManager: users.length
            ? {
                  isValidUser: (userName: string, password: string) =>
                      users.some((u) => u.username === userName && (u.password ?? "") === password),
                  // The well-known roles of the fixture user (Part 3 §4.9.2), e.g.
                  // SecurityAdmin for the push certificate management (Part 12 §7.2).
                  getUserRoles: (userName: string) =>
                      makeRoles(
                          ["AuthenticatedUser", ...((users.find((u) => u.username === userName)?.roles ?? []).filter((r) =>
                              WELL_KNOWN_ROLES.has(r),
                          ))].join(";"),
                      ),
              }
            : undefined,
        reverseConnect: o.reverseConnect.length
            ? {
                  connections: o.reverseConnect.map((endpointUrl) => ({ endpointUrl })),
                  reconnectDelay: o.reverseConnectIntervalMs,
                  maxReconnectDelay: o.reverseConnectIntervalMs,
              }
            : undefined,
        registerServerMethod: o.registerWith ? RegisterServerMethod.LDS : RegisterServerMethod.HIDDEN,
        discoveryServerEndpointUrl: o.registerWith,
        serverCapabilities: { maxSessions: 200 },
        maxConnectionsPerEndpoint: 200,
    });
    if (o.registerWith) {
        // node-opcua's RegisterServerManager renews every registrationTimeout.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const rsm = (server as any).registerServerManager;
        if (rsm && "timeout" in rsm) rsm.timeout = o.registerIntervalMs;
    }

    await server.initialize();
    if (secure) {
        // ServerConfiguration push management (Part 12 §7, serverFeatures
        // "push-management"): the trust list is the PKI directory; channels open
        // when ApplyChanges installs a new certificate keep the old one.
        await installPushCertificateManagementOnServer(server, { closeChannelsOnApplyChanges: false });
    }
    const ns = server.engine.addressSpace!.registerNamespace(fixture.namespaces[0].uri);
    const builder = new AddressSpaceBuilder(server, fixture, ns);
    builder.build();

    try {
        await server.start();
    } catch (e) {
        log("error", `server start failed: ${(e as Error).message}`);
        process.exit(1);
    }
    builder.startBehaviors();
    log("info", `server started on port ${bindPort} (${server.endpoints.map((e) => e.endpointDescriptions().length).join(",")} endpoint descriptions)`);

    try {
        writeReadyFile(o.readyFile, fixture.id, advertised);
        log("info", `ready file written: ${o.readyFile}`);
    } catch (e) {
        log("error", `cannot write ready file ${o.readyFile}: ${(e as Error).message}`);
        if (o.readyFileExplicit) process.exit(6);
    }

    let stopping = false;
    const shutdown = async (sig: string) => {
        if (stopping) return;
        stopping = true;
        log("info", `${sig} received, shutting down`);
        for (const t of builder.timers) clearInterval(t);
        const hard = setTimeout(() => process.exit(0), 5000);
        hard.unref();
        try {
            await server.shutdown(0);
        } catch (e) {
            log("warn", `shutdown: ${(e as Error).message}`);
        }
        removeReadyFile(o.readyFile);
        process.exit(0);
    };
    process.on("SIGTERM", () => void shutdown("SIGTERM"));
    process.on("SIGINT", () => void shutdown("SIGINT"));
}
