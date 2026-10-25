// SPDX-License-Identifier: MIT
//
// `client <subcmd>` (docs/CLIENT_CONTRACT.md §1-§9) on node-opcua's OPCUAClient.
// Services are sent as raw requests (performMessageTransaction) so that every
// status code the peer returns reaches the result unchanged.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
    AddNodesRequest,
    ApplicationType,
    AttributeIds,
    BrowseDirection,
    BrowseNextRequest,
    BrowseRequest,
    CallRequest,
    ClientReverseConnect,
    ClientSession,
    ContentFilter,
    ContentFilterElement,
    CreateMonitoredItemsRequest,
    CreateSubscriptionRequest,
    DataChangeFilter,
    DataChangeNotification,
    DataChangeTrigger,
    DataType,
    DataValue,
    DeadbandType,
    DeleteMonitoredItemsRequest,
    DeleteNodesRequest,
    DeleteSubscriptionsRequest,
    ElementOperand,
    EndpointDescription,
    EventFilter,
    EventNotificationList,
    ExpandedNodeId,
    ExtensionObject,
    FilterOperator,
    FindServersOnNetworkRequest,
    HistoryData,
    HistoryReadRequest,
    LiteralOperand,
    LocalizedText,
    makeRelativePath,
    MdnsDiscoveryConfiguration,
    MessageSecurityMode,
    MonitoringMode,
    NodeClass,
    NodeId,
    NumericRange,
    OPCUACertificateManager,
    OPCUAClient,
    PublishRequest,
    PublishResponse,
    QualifiedName,
    QueryDataDescription,
    QueryFirstRequest,
    QueryNextRequest,
    NodeTypeDescription,
    ReadRawModifiedDetails,
    ReadRequest,
    RegisteredServer,
    RegisterServer2Request,
    RegisterServerRequest,
    RelativePath,
    RepublishRequest,
    SecurityPolicy,
    SetMonitoringModeRequest,
    SetPublishingModeRequest,
    SimpleAttributeOperand,
    StatusCode,
    StatusCodes,
    TimestampsToReturn,
    TransferSubscriptionsRequest,
    TranslateBrowsePathsToNodeIdsRequest,
    UserTokenType,
    Variant,
    VariantArrayType,
    ViewDescription,
    WriteRequest,
} from "node-opcua";
import { CertificateGroup, ClientPushCertificateManagement, TrustListMasks } from "node-opcua-server-configuration";
import { TrustListDataType, VariableAttributes } from "node-opcua-types";

import { certificateUri, readCertificateDer, toPemFiles } from "./server.js";
import {
    Args,
    buildVariantLenient,
    codeOf,
    dataTypeName,
    dateToString,
    EXIT_INPUT,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_SERVICE,
    EXIT_TIMEOUT,
    EXIT_TRANSPORT,
    expandedNodeIdToString,
    InputError,
    isBad,
    isGood,
    localizedTextJson,
    log,
    nodeIdToString,
    parseNodeIdString,
    qualifiedNameJson,
    resolveParsed,
    Result,
    ServiceError,
    statusFromError,
    statusJson,
    TransportError,
    variantType,
    variantValueJson,
    dataValueJson,
} from "./util.js";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

class TimeoutError extends Error {}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
    let timer: NodeJS.Timeout;
    const t = new Promise<T>((_, rej) => {
        timer = setTimeout(() => rej(new TimeoutError(`${what}: timeout after ${ms} ms`)), ms);
    });
    return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

const POLICIES: Record<string, SecurityPolicy> = {
    None: SecurityPolicy.None,
    Basic128Rsa15: SecurityPolicy.Basic128Rsa15,
    Basic256: SecurityPolicy.Basic256,
    Basic256Sha256: SecurityPolicy.Basic256Sha256,
    Aes128_Sha256_RsaOaep: SecurityPolicy.Aes128_Sha256_RsaOaep,
    Aes256_Sha256_RsaPss: SecurityPolicy.Aes256_Sha256_RsaPss,
};

const MODES: Record<string, MessageSecurityMode> = {
    None: MessageSecurityMode.None,
    Sign: MessageSecurityMode.Sign,
    SignAndEncrypt: MessageSecurityMode.SignAndEncrypt,
};

const CONTRACT_POLICIES = new Set([
    "None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss",
    "ECC_nistP256", "ECC_nistP384", "ECC_brainpoolP256r1", "ECC_brainpoolP384r1", "ECC_curve25519", "ECC_curve448",
    "ECC_nistP256_AesGcm", "ECC_nistP256_ChaChaPoly",
]);

function securityFromArgs(a: Args): { policy: SecurityPolicy; mode: MessageSecurityMode; policyName: string; modeName: string } {
    const policyName = a.get("--security-policy") ?? "None";
    const modeName = a.get("--security-mode") ?? "None";
    const policy = POLICIES[policyName];
    if (!policy) {
        if (CONTRACT_POLICIES.has(policyName)) {
            throw new InputError(`--security-policy ${policyName} is not supported by node-opcua${policyName.startsWith("ECC_") ? " (no ECC security policies)" : ""}`);
        }
        throw new InputError(`unknown --security-policy ${policyName}`);
    }
    const mode = MODES[modeName];
    if (mode === undefined) throw new InputError(`unknown --security-mode ${modeName}`);
    if ((policy === SecurityPolicy.None) !== (mode === MessageSecurityMode.None)) {
        throw new InputError(`--security-policy ${policyName} cannot be combined with --security-mode ${modeName}`);
    }
    if (policy !== SecurityPolicy.None && (!a.get("--certificate") || !a.get("--private-key"))) {
        throw new InputError(`--security-policy ${policyName} requires --certificate and --private-key`);
    }
    return { policy, mode, policyName, modeName };
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

interface Timeouts {
    connect: number;
    request: number;
    disconnect: number;
}

function timeouts(a: Args): Timeouts {
    return {
        connect: a.num("--connect-timeout", 5) * 1000,
        request: a.num("--request-timeout", 5) * 1000,
        disconnect: a.num("--disconnect-timeout", 2) * 1000,
    };
}

export interface Conn {
    client: OPCUAClient;
    session?: ClientSession;
    nsArray: string[];
    t: Timeouts;
    endpoint?: EndpointDescription;
    reverse?: ClientReverseConnect;
}

let scratch: string | undefined;
function scratchDir(): string {
    if (!scratch) scratch = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-client-"));
    return scratch;
}

/** Client PKI: the --trust-list certificates are the only trust anchors; without one every server certificate is accepted. */
async function clientCertificateManager(a: Args): Promise<OPCUACertificateManager> {
    const trust = a.all("--trust-list");
    const root = path.join(scratchDir(), "pki");
    for (const d of ["trusted/certs", "trusted/crl", "issuers/certs", "issuers/crl", "rejected"]) {
        fs.mkdirSync(path.join(root, d), { recursive: true });
    }
    trust.forEach((f, i) => {
        const der = readCertificateDer(f);
        fs.writeFileSync(path.join(root, "trusted/certs", `trust-${i}.der`), der);
    });
    const cm = new OPCUACertificateManager({
        rootFolder: root,
        automaticallyAcceptUnknownCertificate: trust.length === 0,
        disableFileWatchers: true,
    });
    await cm.initialize();
    return cm;
}

interface ClientParams {
    a: Args;
    t: Timeouts;
    securityMode: MessageSecurityMode;
    securityPolicy: SecurityPolicy;
    serverCertificate?: Buffer;
}

async function makeClient(p: ClientParams): Promise<OPCUAClient> {
    const a = p.a;
    const certFile = a.get("--certificate");
    const keyFile = a.get("--private-key");
    let certificateFile: string | undefined;
    let privateKeyFile: string | undefined;
    let applicationUri = a.get("--application-uri") ?? "urn:otfabric:opcua-interop:client:node-opcua";
    if (certFile && keyFile) {
        try {
            const pem = toPemFiles(certFile, keyFile, path.join(scratchDir(), "own"));
            certificateFile = pem.cert;
            privateKeyFile = pem.key;
            if (!a.get("--application-uri")) applicationUri = certificateUri(readCertificateDer(certFile)) ?? applicationUri;
        } catch (e) {
            throw new InternalError(`cannot load client certificate/key: ${(e as Error).message}`);
        }
    }
    const lifetime = a.num("--channel-lifetime-ms", 0);
    return OPCUAClient.create({
        applicationName: "opcua-interop node-opcua client",
        applicationUri,
        clientName: "opcua-interop",
        endpointMustExist: false,
        securityMode: p.securityMode,
        securityPolicy: p.securityPolicy,
        certificateFile,
        privateKeyFile,
        serverCertificate: p.serverCertificate,
        clientCertificateManager: await clientCertificateManager(a),
        connectionStrategy: { maxRetry: 0, initialDelay: 100, maxDelay: 200 },
        transportTimeout: p.t.connect,
        defaultTransactionTimeout: Math.max(p.t.request, 1000),
        defaultSecureTokenLifetime: lifetime > 0 ? lifetime : undefined,
        requestedSessionTimeout: 60000,
        keepSessionAlive: false,
    });
}

export class InternalError extends Error {}

/** Opens the channel: dials the endpoint, or waits for a ReverseHello with --reverse-listen. */
async function openChannel(client: OPCUAClient, a: Args, url: string, t: Timeouts, rc?: ClientReverseConnect): Promise<void> {
    if (rc) {
        const ms = a.num("--reverse-timeout-ms", 30000);
        await withTimeout(client.connectReverse(rc), ms, "waiting for a reverse connection");
        return;
    }
    try {
        await withTimeout(client.connect(url), t.connect + 1000, `connect ${url}`);
    } catch (e) {
        if (e instanceof TimeoutError) throw new TransportError((e as Error).message, StatusCodes.BadTimeout.value);
        throw new TransportError(`connect ${url}: ${(e as Error).message}`, statusFromError(e));
    }
}

async function startReverse(a: Args): Promise<ClientReverseConnect | undefined> {
    const port = a.get("--reverse-listen");
    if (port === undefined) return undefined;
    if (!/^\d+$/.test(port)) throw new InputError(`--reverse-listen: not a port: ${port}`);
    const rc = new ClientReverseConnect({ connectionUrl: `opc.tcp://0.0.0.0:${port}`, acceptTimeout: a.num("--reverse-timeout-ms", 30000) });
    await rc.start();
    return rc;
}

function policyUri(p: SecurityPolicy): string {
    return p as string;
}

/**
 * GetEndpoints on a None channel, pick the endpoint matching the requested
 * policy and mode (§9), then open the (secured) channel and, unless
 * withSession is false, a session.
 */
export async function connect(a: Args, withSession = true): Promise<Conn> {
    const url = a.get("--endpoint");
    if (!url) throw new InputError("missing --endpoint");
    const sec = securityFromArgs(a);
    const t = timeouts(a);
    const rc = await startReverse(a);

    // 1. Discovery on a None channel.
    const disc = await makeClient({ a, t, securityMode: MessageSecurityMode.None, securityPolicy: SecurityPolicy.None });
    let endpoints: EndpointDescription[];
    try {
        await openChannel(disc, a, url, t, rc);
        endpoints = await withTimeout(disc.getEndpoints(), t.request, "GetEndpoints");
    } catch (e) {
        await disc.disconnect().catch(() => undefined);
        await rc?.stop().catch(() => undefined);
        if (e instanceof TransportError || e instanceof InputError) throw e;
        if (e instanceof TimeoutError && rc) throw new ReverseTimeout((e as Error).message);
        throw new TransportError(`GetEndpoints ${url}: ${(e as Error).message}`, statusFromError(e));
    }
    const ep = endpoints.find((e) => e.securityPolicyUri === policyUri(sec.policy) && e.securityMode === sec.mode);
    if (!ep) {
        await disc.disconnect().catch(() => undefined);
        await rc?.stop().catch(() => undefined);
        throw new TransportError(`no endpoint with SecurityPolicy=${sec.policyName} and MessageSecurityMode=${sec.modeName} at ${url}`);
    }

    // 2. The channel the command runs on (the discovery one when it already fits).
    let client = disc;
    if (sec.policy !== SecurityPolicy.None) {
        await disc.disconnect().catch(() => undefined);
        client = await makeClient({ a, t, securityMode: sec.mode, securityPolicy: sec.policy, serverCertificate: ep.serverCertificate as Buffer });
        try {
            await openChannel(client, a, url, t, rc);
        } catch (e) {
            await client.disconnect().catch(() => undefined);
            await rc?.stop().catch(() => undefined);
            if (e instanceof TimeoutError && rc) throw new ReverseTimeout((e as Error).message);
            throw e;
        }
    }
    const conn: Conn = { client, nsArray: [], t, endpoint: ep, reverse: rc };
    if (!withSession) return conn;

    // 3. Session.
    const username = a.get("--username");
    const identity =
        username !== undefined
            ? { type: UserTokenType.UserName as const, userName: username, password: a.get("--password") ?? "" }
            : { type: UserTokenType.Anonymous as const };
    try {
        conn.session = await withTimeout(client.createSession(identity), t.connect + t.request, "CreateSession/ActivateSession");
    } catch (e) {
        await close(conn);
        const sc = statusFromError(e);
        if (sc !== undefined) throw new ServiceError(`session: ${(e as Error).message}`, sc);
        throw new TransportError(`session: ${(e as Error).message}`);
    }
    try {
        conn.nsArray = await withTimeout(conn.session.readNamespaceArray(), t.request, "read NamespaceArray");
    } catch (e) {
        log("warn", `cannot read the NamespaceArray: ${(e as Error).message}`);
    }
    const wantUri = a.get("--reverse-server-uri");
    if (wantUri !== undefined) {
        const dv = await conn.session.read({ nodeId: "i=2254", attributeId: AttributeIds.Value });
        const arr = (dv.value?.value as string[] | undefined) ?? [];
        if (arr[0] !== wantUri) {
            await close(conn);
            throw new TransportError(`reverse-connected server is ${arr[0]}, want ${wantUri}`, StatusCodes.BadServerUriInvalid.value);
        }
    }
    return conn;
}

class ReverseTimeout extends Error {}

export async function close(c: Conn): Promise<void> {
    try {
        if (c.session) await withTimeout(c.session.close(true), c.t.disconnect, "CloseSession");
    } catch {
        /* best effort */
    }
    try {
        await withTimeout(c.client.disconnect(), c.t.disconnect, "disconnect");
    } catch {
        /* best effort */
    }
    try {
        await c.reverse?.stop();
    } catch {
        /* best effort */
    }
}

function resolve(c: Conn, s: string): NodeId {
    return resolveParsed(parseNodeIdString(s), c.nsArray);
}

/** Raw service call: the response, also when its ServiceResult is Bad. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function tx<T = any>(c: Conn, req: any, timeoutMs?: number): Promise<{ resp?: T; status: number; err?: Error }> {
    const ms = timeoutMs ?? c.t.request;
    if (req.requestHeader) req.requestHeader.timeoutHint = ms;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const target: any = c.session ?? c.client;
    return await new Promise((resolveP) => {
        let done = false;
        const timer = setTimeout(() => {
            if (done) return;
            done = true;
            resolveP({ status: StatusCodes.BadTimeout.value, err: new TimeoutError(`${req.constructor.name}: timeout after ${ms} ms`) });
        }, ms + 2000);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        target.performMessageTransaction(req, (err: Error | null, resp?: any) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            const sr = resp?.responseHeader?.serviceResult;
            if (resp && sr) {
                resolveP({ resp: sr.value === 0 ? resp : resp, status: sr.value >>> 0, err: err ?? undefined });
                return;
            }
            if (err) {
                resolveP({ status: statusFromError(err) ?? StatusCodes.BadCommunicationError.value, err });
                return;
            }
            resolveP({ resp, status: 0 });
        });
    });
}

function timestampsArg(a: Args): TimestampsToReturn {
    const v = a.get("--timestamps") ?? "Both";
    const m: Record<string, TimestampsToReturn> = {
        Source: TimestampsToReturn.Source,
        Server: TimestampsToReturn.Server,
        Both: TimestampsToReturn.Both,
        Neither: TimestampsToReturn.Neither,
    };
    if (m[v] === undefined) throw new InputError(`--timestamps must be Source, Server, Both or Neither`);
    return m[v];
}

function indexRange(s: string | undefined): NumericRange | undefined {
    if (s === undefined) return undefined;
    try {
        return new NumericRange(s);
    } catch {
        throw new InputError(`invalid --index-range ${s}`);
    }
}

/** A Read/notification value: dataType, builtInType, [arrayDimensions], value. */
function valueFields(v: Variant | null | undefined): Record<string, unknown> {
    const m: Record<string, unknown> = { ...variantType(v) };
    if (v && v.dimensions && v.dimensions.length > 1) m.arrayDimensions = v.dimensions;
    m.value = variantValueJson(v);
    return m;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdEndpoints(a: Args, r: Result): Promise<number> {
    const c = await connect(a, false);
    try {
        const eps = await withTimeout(c.client.getEndpoints(), c.t.request, "GetEndpoints");
        for (const ep of eps) {
            r.add({ url: ep.endpointUrl, securityPolicy: ep.securityPolicyUri, securityMode: MessageSecurityMode[ep.securityMode] });
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdFindServers(a: Args, r: Result): Promise<number> {
    const c = await connect(a, false);
    try {
        const apps = await withTimeout(c.client.findServers(), c.t.request, "FindServers");
        for (const app of apps) {
            r.add({
                applicationUri: app.applicationUri ?? "",
                applicationName: localizedTextJson(app.applicationName),
                productUri: app.productUri ?? "",
                discoveryUrls: (app.discoveryUrls ?? []).filter((u) => u),
            });
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdRead(a: Args, r: Result): Promise<number> {
    const nodes = a.all("--node");
    if (!a.get("--endpoint") || nodes.length === 0) throw new InputError("missing --endpoint or --node");
    nodes.forEach((n) => parseNodeIdString(n));
    const range = indexRange(a.get("--index-range"));
    const ts = timestampsArg(a);
    const c = await connect(a);
    try {
        const ids = nodes.map((n) => resolve(c, n));
        const { resp, status } = await tx(c, new ReadRequest({
            maxAge: 0,
            timestampsToReturn: ts,
            nodesToRead: ids.map((nodeId) => ({ nodeId, attributeId: AttributeIds.Value, indexRange: range })),
        }));
        if (!resp || isBad(status)) {
            r.setService(status).fail("service", "Read failed");
            return EXIT_SERVICE;
        }
        let anyBad = false;
        const results: DataValue[] = resp.results ?? [];
        ids.forEach((id, i) => {
            const dv = results[i];
            const item: Record<string, unknown> = { nodeId: nodeIdToString(id), statusCode: statusJson(dv?.statusCode) };
            Object.assign(item, valueFields(dv?.value));
            if (dv?.sourceTimestamp) item.sourceTimestamp = dateToString(dv.sourceTimestamp);
            if (dv?.serverTimestamp) item.serverTimestamp = dateToString(dv.serverTimestamp);
            r.add(item);
            if (!isGood(dv?.statusCode)) anyBad = true;
        });
        if (ids.length === 1) r.setService(results[0]?.statusCode);
        if (anyBad) {
            r.fail("service", "one or more reads returned a non-Good status");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdWrite(a: Args, r: Result): Promise<number> {
    const nodes = a.all("--node"), types = a.all("--type"), values = a.all("--value");
    if (!a.get("--endpoint") || nodes.length === 0 || nodes.length !== types.length || nodes.length !== values.length) {
        throw new InputError("write requires equal counts of --node, --type, and --value");
    }
    nodes.forEach((n) => parseNodeIdString(n));
    const range = indexRange(a.get("--index-range"));
    const c = await connect(a);
    try {
        const ids = nodes.map((n) => resolve(c, n));
        const { resp, status } = await tx(c, new WriteRequest({
            nodesToWrite: ids.map((nodeId, i) => ({
                nodeId,
                attributeId: AttributeIds.Value,
                indexRange: range,
                value: { value: buildVariantLenient(types[i], values[i]) },
            })),
        }));
        if (!resp || isBad(status)) {
            r.setService(status).fail("service", "Write failed");
            return EXIT_SERVICE;
        }
        const results: StatusCode[] = resp.results ?? [];
        let firstBad: StatusCode | undefined;
        ids.forEach((id, i) => {
            r.add({ nodeId: nodeIdToString(id), statusCode: statusJson(results[i]) });
            if (!isGood(results[i]) && !firstBad) firstBad = results[i];
        });
        if (ids.length === 1) r.setService(results[0]);
        else if (firstBad) r.setService(firstBad);
        if (firstBad) {
            r.fail("service", "one or more writes returned a non-Good status");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdBrowse(a: Args, r: Result): Promise<number> {
    if (!a.get("--endpoint")) throw new InputError("missing --endpoint");
    const nodeStr = a.get("--node") ?? "i=85";
    parseNodeIdString(nodeStr);
    const maxRefs = a.num("--max-refs", 0);
    const nodeClassMask = a.num("--node-class-mask", 0);
    const includeSubtypes = a.bool("--include-subtypes", true);
    const resultMask = a.num("--result-mask", 63);
    const c = await connect(a);
    try {
        const nodeId = resolve(c, nodeStr);
        const first = await tx(c, new BrowseRequest({
            requestedMaxReferencesPerNode: maxRefs,
            nodesToBrowse: [{
                nodeId,
                browseDirection: BrowseDirection.Forward,
                referenceTypeId: "i=33",
                includeSubtypes,
                nodeClassMask,
                resultMask,
            }],
        }));
        if (!first.resp || isBad(first.status)) {
            r.setService(first.status).fail("service", "Browse failed");
            return EXIT_SERVICE;
        }
        const br = first.resp.results[0];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const refs: any[] = [...(br.references ?? [])];
        let cp: Buffer | null = br.continuationPoint;
        let guard = 0;
        while (cp && cp.length > 0 && guard++ < 10000) {
            const next = await tx(c, new BrowseNextRequest({ releaseContinuationPoints: false, continuationPoints: [cp] }));
            if (!next.resp || isBad(next.status)) {
                r.setService(next.status).fail("service", "BrowseNext failed");
                return EXIT_SERVICE;
            }
            const nr = next.resp.results[0];
            if (!isGood(nr.statusCode)) {
                r.setService(nr.statusCode).fail("service", "BrowseNext failed");
                return EXIT_SERVICE;
            }
            refs.push(...(nr.references ?? []));
            cp = nr.continuationPoint;
        }
        r.setService(br.statusCode);
        for (const rd of refs) {
            r.add({
                referenceTypeId: nodeIdToString(rd.referenceTypeId),
                isForward: rd.isForward,
                nodeId: nodeIdToString(rd.nodeId),
                browseName: qualifiedNameJson(rd.browseName),
                displayName: localizedTextJson(rd.displayName),
                nodeClass: NodeClass[rd.nodeClass] ?? String(rd.nodeClass),
            });
        }
        if (!isGood(br.statusCode)) {
            r.fail("service", "Browse returned a non-Good status");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdTranslate(a: Args, r: Result): Promise<number> {
    if (!a.get("--endpoint")) throw new InputError("missing --endpoint");
    const pathStr = a.get("--path");
    if (!pathStr) throw new InputError("missing --path");
    const segments = pathStr.split(".").filter((s) => s.length > 0);
    if (segments.length === 0) throw new InputError("empty --path");
    const ns = a.num("--namespace", 0);
    const startStr = a.get("--starting-node") ?? "i=85";
    parseNodeIdString(startStr);
    const c = await connect(a);
    try {
        const startingNode = resolve(c, startStr);
        const { resp, status } = await tx(c, new TranslateBrowsePathsToNodeIdsRequest({
            browsePaths: [{
                startingNode,
                relativePath: {
                    elements: segments.map((name) => ({
                        referenceTypeId: "i=33",
                        isInverse: false,
                        includeSubtypes: true,
                        targetName: new QualifiedName({ namespaceIndex: ns, name }),
                    })),
                },
            }],
        }));
        r.setService(status);
        if (!resp || isBad(status) || !resp.results?.length) {
            r.fail("service", "TranslateBrowsePathsToNodeIds failed");
            return EXIT_SERVICE;
        }
        const bpr = resp.results[0];
        r.add({
            statusCode: statusJson(bpr.statusCode),
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            targets: (bpr.targets ?? []).map((t: any) => nodeIdToString(t.targetId)),
        });
        if (!isGood(bpr.statusCode)) {
            r.fail("service", "browse path did not resolve");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdCall(a: Args, r: Result): Promise<number> {
    const objStr = a.get("--object"), methodStr = a.get("--method");
    if (!a.get("--endpoint") || !objStr || !methodStr) throw new InputError("missing --endpoint, --object, or --method");
    parseNodeIdString(objStr);
    parseNodeIdString(methodStr);
    const inputs = a.all("--input").map((spec) => {
        const colon = spec.indexOf(":");
        if (colon <= 0) throw new InputError(`--input must be Type:value, got ${spec}`);
        return buildVariantLenient(spec.substring(0, colon), spec.substring(colon + 1));
    });
    const c = await connect(a);
    try {
        const objectId = resolve(c, objStr), methodId = resolve(c, methodStr);
        const { resp, status } = await tx(c, new CallRequest({ methodsToCall: [{ objectId, methodId, inputArguments: inputs }] }));
        if (!resp || isBad(status) || !resp.results?.length) {
            r.setService(status).fail("service", "Call failed");
            return EXIT_SERVICE;
        }
        const res = resp.results[0];
        r.setService(res.statusCode);
        r.add({
            objectNodeId: nodeIdToString(objectId),
            methodNodeId: nodeIdToString(methodId),
            statusCode: statusJson(res.statusCode),
            outputArguments: (res.outputArguments ?? []).map((v: Variant) => variantValueJson(v)),
        });
        if (!isGood(res.statusCode)) {
            r.fail("service", "method call returned a non-Good status");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

// ---------------------------------------------------------------------------
// Subscriptions: raw CreateSubscription / CreateMonitoredItems and a Publish pump
// ---------------------------------------------------------------------------

interface SubInfo {
    subscriptionId: number;
    revisedPublishingInterval: number;
    revisedLifetimeCount: number;
    revisedMaxKeepAliveCount: number;
}

async function createSubscription(c: Conn, pi: number, lifetime = 300, keepAlive = 10): Promise<SubInfo> {
    const { resp, status, err } = await tx(c, new CreateSubscriptionRequest({
        requestedPublishingInterval: pi,
        requestedLifetimeCount: lifetime,
        requestedMaxKeepAliveCount: keepAlive,
        maxNotificationsPerPublish: 0,
        publishingEnabled: true,
        priority: 0,
    }));
    if (!resp || isBad(status)) throw new ServiceError(`CreateSubscription failed: ${err?.message ?? statusJson(status).name}`, status);
    return {
        subscriptionId: resp.subscriptionId,
        revisedPublishingInterval: resp.revisedPublishingInterval,
        revisedLifetimeCount: resp.revisedLifetimeCount,
        revisedMaxKeepAliveCount: resp.revisedMaxKeepAliveCount,
    };
}

interface MonResult {
    status: number;
    monitoredItemId: number;
    revisedSamplingInterval: number;
    revisedQueueSize: number;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    filterResult: any;
}

async function createMonitoredItem(
    c: Conn,
    subscriptionId: number,
    nodeId: NodeId,
    opts: { attributeId?: number; samplingInterval: number; queueSize: number; discardOldest: boolean; filter?: unknown; ts: TimestampsToReturn; clientHandle?: number },
): Promise<MonResult> {
    const { resp, status, err } = await tx(c, new CreateMonitoredItemsRequest({
        subscriptionId,
        timestampsToReturn: opts.ts,
        itemsToCreate: [{
            itemToMonitor: { nodeId, attributeId: opts.attributeId ?? AttributeIds.Value },
            monitoringMode: MonitoringMode.Reporting,
            requestedParameters: {
                clientHandle: opts.clientHandle ?? 1,
                samplingInterval: opts.samplingInterval,
                filter: opts.filter as never,
                queueSize: opts.queueSize,
                discardOldest: opts.discardOldest,
            },
        }],
    }));
    if (!resp || isBad(status) || !resp.results?.length) {
        return { status: status || StatusCodes.BadUnexpectedError.value, monitoredItemId: 0, revisedSamplingInterval: 0, revisedQueueSize: 0, filterResult: null };
        void err;
    }
    const m = resp.results[0];
    return {
        status: codeOf(m.statusCode),
        monitoredItemId: m.monitoredItemId,
        revisedSamplingInterval: m.revisedSamplingInterval,
        revisedQueueSize: m.revisedQueueSize,
        filterResult: m.filterResult,
    };
}

interface Notification {
    sequenceNumber: number;
    clientHandle: number;
    value?: DataValue;
    eventFields?: Variant[];
}

/** Keeps Publish requests outstanding and collects data-change / event notifications. */
class PublishPump {
    notifications: Notification[] = [];
    sequenceNumbers: number[] = [];
    private acks: { subscriptionId: number; sequenceNumber: number }[] = [];
    private running = false;
    private loops: Promise<void>[] = [];
    lastError?: Error;
    onNotification?: () => void;

    constructor(private c: Conn, private timeoutMs: number, private outstanding = 2) {}

    start(): void {
        if (this.running) return;
        this.running = true;
        for (let i = 0; i < this.outstanding; i++) this.loops.push(this.loop());
    }

    stop(): void {
        this.running = false;
    }

    private async loop(): Promise<void> {
        while (this.running) {
            const acks = this.acks.splice(0);
            const { resp, status, err } = await tx<PublishResponse>(this.c, new PublishRequest({ subscriptionAcknowledgements: acks }), this.timeoutMs);
            if (!this.running) {
                if (resp?.notificationMessage?.sequenceNumber) this.handle(resp);
                return;
            }
            if (!resp || isBad(status)) {
                this.lastError = err ?? new Error(statusJson(status).name);
                if (status === StatusCodes.BadNoSubscription.value || status === StatusCodes.BadTooManyPublishRequests.value) {
                    await sleep(50);
                    continue;
                }
                if (status === StatusCodes.BadTimeout.value) continue;
                await sleep(100);
                continue;
            }
            this.handle(resp);
        }
    }

    private handle(resp: PublishResponse): void {
        const nm = resp.notificationMessage;
        if (!nm) return;
        if (nm.notificationData && nm.notificationData.length > 0) {
            this.acks.push({ subscriptionId: resp.subscriptionId, sequenceNumber: nm.sequenceNumber });
            this.sequenceNumbers.push(nm.sequenceNumber);
        }
        for (const nd of nm.notificationData ?? []) {
            if (nd instanceof DataChangeNotification) {
                for (const mi of nd.monitoredItems ?? []) {
                    this.notifications.push({ sequenceNumber: nm.sequenceNumber, clientHandle: mi.clientHandle, value: mi.value });
                }
            } else if (nd instanceof EventNotificationList) {
                for (const ev of nd.events ?? []) {
                    this.notifications.push({ sequenceNumber: nm.sequenceNumber, clientHandle: ev.clientHandle, eventFields: ev.eventFields ?? [] });
                }
            }
        }
        this.onNotification?.();
    }

    async waitFor(pred: () => boolean, ms: number): Promise<boolean> {
        const end = Date.now() + ms;
        while (!pred()) {
            if (Date.now() >= end) return false;
            await sleep(20);
        }
        return true;
    }
}

async function deleteSubscription(c: Conn, id: number): Promise<number> {
    const { resp, status } = await tx(c, new DeleteSubscriptionsRequest({ subscriptionIds: [id] }));
    if (resp && !isBad(status) && resp.results?.length) return codeOf(resp.results[0]);
    return status;
}

function notificationJson(n: Notification, seq: number): Record<string, unknown> {
    const dv = n.value;
    const m: Record<string, unknown> = { sequenceNumber: seq };
    const vf = valueFields(dv?.value);
    m.value = vf.value;
    m.dataType = vf.dataType;
    m.builtInType = vf.builtInType;
    if (vf.arrayDimensions) m.arrayDimensions = vf.arrayDimensions;
    m.statusCode = statusJson(dv?.statusCode);
    if (dv?.sourceTimestamp) m.sourceTimestamp = dateToString(dv.sourceTimestamp);
    if (dv?.serverTimestamp) m.serverTimestamp = dateToString(dv.serverTimestamp);
    return m;
}

async function cmdSubscribe(a: Args, r: Result): Promise<number> {
    const nodeStr = a.get("--node");
    if (!a.get("--endpoint") || !nodeStr) throw new InputError("missing --endpoint or --node");
    parseNodeIdString(nodeStr);
    const pi = a.num("--publishing-interval-ms", 500);
    const si = a.num("--sampling-interval-ms", 100);
    const want = a.num("--notifications", 5);
    const toMs = a.num("--timeout-ms", 10000);
    const queueSize = a.num("--queue-size", 1);
    const discardOldest = a.bool("--discard-oldest", true);
    const ts = timestampsArg(a);
    const dbAbs = a.get("--deadband-absolute"), dbPct = a.get("--deadband-percent"), trig = a.get("--trigger");
    const useFilter = dbAbs !== undefined || dbPct !== undefined || trig !== undefined;
    if (dbAbs !== undefined && dbPct !== undefined) throw new InputError("--deadband-absolute and --deadband-percent are mutually exclusive");
    const triggerName = trig ?? "StatusValue";
    const triggers: Record<string, DataChangeTrigger> = {
        Status: DataChangeTrigger.Status,
        StatusValue: DataChangeTrigger.StatusValue,
        StatusValueTimestamp: DataChangeTrigger.StatusValueTimestamp,
    };
    if (useFilter && triggers[triggerName] === undefined) throw new InputError("--trigger must be Status, StatusValue or StatusValueTimestamp");
    const deadbandName = dbAbs !== undefined ? "Absolute" : dbPct !== undefined ? "Percent" : "None";
    const deadbandValue = dbAbs !== undefined ? Number(dbAbs) : dbPct !== undefined ? Number(dbPct) : 0;
    if (!Number.isFinite(deadbandValue)) throw new InputError("invalid deadband value");
    const filter = useFilter
        ? new DataChangeFilter({
              trigger: triggers[triggerName],
              deadbandType: dbAbs !== undefined ? DeadbandType.Absolute : dbPct !== undefined ? DeadbandType.Percent : DeadbandType.None,
              deadbandValue,
          })
        : undefined;

    const deadline = Date.now() + toMs;
    const c = await connect(a);
    try {
        const nodeId = resolve(c, nodeStr);
        const sub = await createSubscription(c, pi);
        const mon = await createMonitoredItem(c, sub.subscriptionId, nodeId, { samplingInterval: si, queueSize: Math.max(1, queueSize), discardOldest, filter, ts });
        const pump = new PublishPump(c, Math.max(sub.revisedPublishingInterval * sub.revisedMaxKeepAliveCount + 5000, c.t.request));
        let timedOut = false;
        if (isGood(mon.status)) {
            pump.start();
            timedOut = !(await pump.waitFor(() => pump.notifications.length >= want, Math.max(0, deadline - Date.now())));
            pump.stop();
        }
        const notes = pump.notifications.slice(0, want).map((n, i) => notificationJson(n, i + 1));
        const item: Record<string, unknown> = {
            nodeId: nodeIdToString(nodeId),
            subscriptionId: sub.subscriptionId,
            revisedPublishingInterval: sub.revisedPublishingInterval,
            revisedLifetimeCount: sub.revisedLifetimeCount,
            revisedMaxKeepAliveCount: sub.revisedMaxKeepAliveCount,
            monitoredItemStatusCode: statusJson(mon.status),
        };
        if (useFilter) {
            item.monitoredItemId = mon.monitoredItemId;
            item.revisedSamplingInterval = mon.revisedSamplingInterval;
            item.revisedQueueSize = mon.revisedQueueSize;
            item.filter = { trigger: triggerName, deadbandType: deadbandName, deadbandValue };
            const fr = mon.filterResult;
            item.filterResult = fr && !(fr instanceof Object && Object.keys(fr).length === 0) && fr.schema ? { typeId: nodeIdToString(fr.schema.encodingDefaultBinary) } : null;
        }
        item.notifications = isGood(mon.status) ? notes : [];
        r.add(item).setService(mon.status);
        await deleteSubscription(c, sub.subscriptionId);
        if (!isGood(mon.status)) {
            r.fail("service", "CreateMonitoredItems rejected the monitored item");
            return EXIT_SERVICE;
        }
        if (timedOut) {
            r.fail("timeout", "timeout waiting for notifications");
            return EXIT_TIMEOUT;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function writeInt32(c: Conn, nodeId: NodeId, v: number): Promise<number> {
    const { resp, status } = await tx(c, new WriteRequest({
        nodesToWrite: [{ nodeId, attributeId: AttributeIds.Value, value: { value: new Variant({ dataType: DataType.Int32, value: v }) } }],
    }));
    if (!resp || isBad(status)) return status;
    return codeOf(resp.results?.[0]);
}

async function cmdSubscriptionLifecycle(a: Args, r: Result): Promise<number> {
    const nodeStr = a.get("--node"), scenario = a.get("--scenario");
    if (!a.get("--endpoint") || !nodeStr || !scenario) throw new InputError("missing --endpoint, --node, or --scenario");
    if (!["revise", "publishing-mode", "monitoring-mode", "delete"].includes(scenario)) throw new InputError(`unknown scenario: ${scenario}`);
    parseNodeIdString(nodeStr);
    const toMs = a.num("--timeout-ms", 15000);
    const collectMs = Math.max(2000, Math.min(toMs - 2000, 5000));
    const c = await connect(a);
    try {
        const nodeId = resolve(c, nodeStr);
        switch (scenario) {
            case "revise": {
                const sub = await createSubscription(c, 1, 5, 10);
                await deleteSubscription(c, sub.subscriptionId);
                const ok = sub.revisedLifetimeCount >= 3 * sub.revisedMaxKeepAliveCount && sub.revisedPublishingInterval >= 10;
                r.add({
                    subscriptionId: sub.subscriptionId,
                    requestedPublishingInterval: 1,
                    requestedLifetimeCount: 5,
                    requestedMaxKeepAliveCount: 10,
                    revisedPublishingInterval: sub.revisedPublishingInterval,
                    revisedLifetimeCount: sub.revisedLifetimeCount,
                    revisedMaxKeepAliveCount: sub.revisedMaxKeepAliveCount,
                });
                if (!ok) {
                    r.fail("service", "revised subscription parameters violate the revision rules");
                    return EXIT_SERVICE;
                }
                return EXIT_OK;
            }
            case "publishing-mode": {
                const sub = await createSubscription(c, 500);
                const mon = await createMonitoredItem(c, sub.subscriptionId, nodeId, { samplingInterval: 0, queueSize: 3, discardOldest: true, ts: TimestampsToReturn.Source });
                if (!isGood(mon.status)) {
                    await deleteSubscription(c, sub.subscriptionId);
                    r.setService(mon.status).fail("service", "CreateMonitoredItem failed");
                    return EXIT_SERVICE;
                }
                const pump = new PublishPump(c, 30000, 1);
                pump.start();
                await pump.waitFor(() => pump.notifications.length >= 1, 1500);
                await tx(c, new SetPublishingModeRequest({ publishingEnabled: false, subscriptionIds: [sub.subscriptionId] }));
                const base = pump.notifications.length;
                for (let v = 1; v <= 5; v++) await writeInt32(c, nodeId, v);
                await sleep(200);
                await tx(c, new SetPublishingModeRequest({ publishingEnabled: true, subscriptionIds: [sub.subscriptionId] }));
                await sleep(collectMs);
                pump.stop();
                await deleteSubscription(c, sub.subscriptionId);
                const after = pump.notifications.slice(base);
                const values: number[] = [];
                let overflow = false;
                for (const n of after) {
                    const v = n.value?.value;
                    if (v && v.dataType === DataType.Int32) values.push(Number(v.value));
                    if ((codeOf(n.value?.statusCode) & 0x480) !== 0) overflow = true;
                }
                if (values.length < 5) overflow = true;
                const nv = values.length;
                const ok = nv >= 3 ? values[nv - 3] === 3 && values[nv - 2] === 4 && values[nv - 1] === 5 : nv >= 1 ? values[nv - 1] === 5 : false;
                r.add({
                    subscriptionId: sub.subscriptionId,
                    revisedPublishingInterval: sub.revisedPublishingInterval,
                    revisedLifetimeCount: sub.revisedLifetimeCount,
                    revisedMaxKeepAliveCount: sub.revisedMaxKeepAliveCount,
                    overflow,
                    values,
                });
                if (!ok) {
                    r.fail("service", "the final queue window is not [3,4,5]");
                    return EXIT_SERVICE;
                }
                return EXIT_OK;
            }
            case "monitoring-mode": {
                const sub = await createSubscription(c, 100);
                const mon = await createMonitoredItem(c, sub.subscriptionId, nodeId, { samplingInterval: 0, queueSize: 5, discardOldest: true, ts: TimestampsToReturn.Source });
                if (!isGood(mon.status)) {
                    await deleteSubscription(c, sub.subscriptionId);
                    r.setService(mon.status).fail("service", "CreateMonitoredItem failed");
                    return EXIT_SERVICE;
                }
                const pump = new PublishPump(c, 30000, 2);
                pump.start();
                await pump.waitFor(() => pump.notifications.length >= 1, 500);
                const setMode = (mode: MonitoringMode) =>
                    tx(c, new SetMonitoringModeRequest({ subscriptionId: sub.subscriptionId, monitoringMode: mode, monitoredItemIds: [mon.monitoredItemId] }));
                const count = () => pump.notifications.length;

                let b = count();
                await setMode(MonitoringMode.Disabled);
                await writeInt32(c, nodeId, 100);
                await sleep(300);
                const disabled = count() - b;

                b = count();
                await setMode(MonitoringMode.Sampling);
                await writeInt32(c, nodeId, 101);
                await writeInt32(c, nodeId, 102);
                await sleep(300);
                const sampling = count() - b;

                b = count();
                await setMode(MonitoringMode.Reporting);
                await writeInt32(c, nodeId, 103);
                await sleep(collectMs);
                const reporting = count() - b;
                pump.stop();
                await deleteSubscription(c, sub.subscriptionId);
                r.add({
                    subscriptionId: sub.subscriptionId,
                    modeSteps: [
                        { mode: "Disabled", notificationCount: disabled },
                        { mode: "Sampling", notificationCount: sampling },
                        { mode: "Reporting", notificationCount: reporting },
                    ],
                });
                if (!(disabled === 0 && reporting >= 1)) {
                    r.fail("service", "monitoring mode transitions not honoured");
                    return EXIT_SERVICE;
                }
                return EXIT_OK;
            }
            case "delete": {
                const sub = await createSubscription(c, 500);
                const mon = await createMonitoredItem(c, sub.subscriptionId, nodeId, { samplingInterval: 100, queueSize: 1, discardOldest: true, ts: TimestampsToReturn.Source });
                if (!isGood(mon.status)) {
                    await deleteSubscription(c, sub.subscriptionId);
                    r.setService(mon.status).fail("service", "CreateMonitoredItem failed");
                    return EXIT_SERVICE;
                }
                const delMon = async () => {
                    const { resp, status } = await tx(c, new DeleteMonitoredItemsRequest({ subscriptionId: sub.subscriptionId, monitoredItemIds: [mon.monitoredItemId] }));
                    return resp && !isBad(status) && resp.results?.length ? codeOf(resp.results[0]) : status;
                };
                const m1 = await delMon(), m2 = await delMon();
                const s1 = await deleteSubscription(c, sub.subscriptionId), s2 = await deleteSubscription(c, sub.subscriptionId);
                r.add({
                    subscriptionId: sub.subscriptionId,
                    deleteMonitoredItem: { first: statusJson(m1), second: statusJson(m2) },
                    deleteSubscription: { first: statusJson(s1), second: statusJson(s2) },
                });
                if (!(isBad(m2) && isBad(s2))) {
                    r.fail("service", "second delete did not fail");
                    return EXIT_SERVICE;
                }
                return EXIT_OK;
            }
        }
        return EXIT_INTERNAL;
    } finally {
        await close(c);
    }
}

const EVENT_FIELDS = ["EventId", "EventType", "SourceName", "Message", "Severity", "Time"];

async function cmdEventSubscribe(a: Args, r: Result): Promise<number> {
    const nodeStr = a.get("--node");
    if (!a.get("--endpoint") || !nodeStr) throw new InputError("missing --endpoint or --node");
    parseNodeIdString(nodeStr);
    const pi = a.num("--publishing-interval-ms", 500);
    const want = a.num("--events", 1);
    const toMs = a.num("--timeout-ms", 10000);
    const queueSize = a.num("--queue-size", 10);
    const ofType = a.get("--of-type");
    const minSev = a.get("--min-severity");
    if (ofType !== undefined) parseNodeIdString(ofType);
    if (minSev !== undefined && !/^\d+$/.test(minSev)) throw new InputError("--min-severity must be an integer");
    const deadline = Date.now() + toMs;
    const c = await connect(a);
    try {
        const nodeId = resolve(c, nodeStr);
        const selectClauses = EVENT_FIELDS.map(
            (name) => new SimpleAttributeOperand({ typeDefinitionId: "i=2041", browsePath: [new QualifiedName({ namespaceIndex: 0, name })], attributeId: AttributeIds.Value }),
        );
        const elements: ContentFilterElement[] = [];
        if (ofType !== undefined) {
            elements.push(new ContentFilterElement({
                filterOperator: FilterOperator.OfType,
                filterOperands: [new LiteralOperand({ value: new Variant({ dataType: DataType.NodeId, value: resolve(c, ofType) }) })],
            }));
        }
        if (minSev !== undefined) {
            elements.push(new ContentFilterElement({
                filterOperator: FilterOperator.GreaterThanOrEqual,
                filterOperands: [
                    new SimpleAttributeOperand({ typeDefinitionId: "i=2041", browsePath: [new QualifiedName({ namespaceIndex: 0, name: "Severity" })], attributeId: AttributeIds.Value }),
                    new LiteralOperand({ value: new Variant({ dataType: DataType.UInt16, value: Number(minSev) }) }),
                ],
            }));
        }
        if (elements.length === 2) {
            elements.push(new ContentFilterElement({
                filterOperator: FilterOperator.And,
                filterOperands: [new ElementOperand({ index: 0 }), new ElementOperand({ index: 1 })],
            }));
        }
        const filter = new EventFilter({ selectClauses, whereClause: new ContentFilter({ elements }) });
        const sub = await createSubscription(c, pi, 10000, 10);
        const mon = await createMonitoredItem(c, sub.subscriptionId, nodeId, {
            attributeId: AttributeIds.EventNotifier,
            samplingInterval: 0,
            queueSize: Math.max(1, queueSize),
            discardOldest: true,
            filter,
            ts: TimestampsToReturn.Both,
        });
        const pump = new PublishPump(c, Math.max(sub.revisedPublishingInterval * sub.revisedMaxKeepAliveCount + 5000, c.t.request));
        let timedOut = false;
        if (isGood(mon.status)) {
            pump.start();
            timedOut = !(await pump.waitFor(() => pump.notifications.filter((n) => n.eventFields).length >= want, Math.max(0, deadline - Date.now())));
            pump.stop();
        }
        await deleteSubscription(c, sub.subscriptionId);
        const events = pump.notifications
            .filter((n) => n.eventFields && n.clientHandle === 1)
            .slice(0, want)
            .map((n, i) => ({
                sequenceNumber: i + 1,
                fields: (n.eventFields ?? []).slice(0, EVENT_FIELDS.length).map((v, j) => ({ name: EVENT_FIELDS[j], ...variantType(v), value: variantValueJson(v) })),
            }));
        r.add({
            nodeId: nodeIdToString(nodeId),
            subscriptionId: sub.subscriptionId,
            revisedPublishingInterval: sub.revisedPublishingInterval,
            monitoredItemStatusCode: statusJson(mon.status),
            selectClauses: EVENT_FIELDS,
            events,
        });
        r.setService(mon.status);
        if (!isGood(mon.status)) {
            r.fail("service", "CreateMonitoredItems rejected the event monitored item");
            return EXIT_SERVICE;
        }
        if (timedOut) {
            r.fail("timeout", "timeout waiting for events");
            return EXIT_TIMEOUT;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

interface HistoryPage {
    svc: number;
    item: number;
    cp: string | null;
    values: Record<string, unknown>[];
}

async function historyReadOnce(
    c: Conn,
    nodeId: NodeId,
    start: Date,
    end: Date,
    numValues: number,
    returnBounds: boolean,
    ts: TimestampsToReturn,
    cp: string | null,
    release: boolean,
): Promise<HistoryPage> {
    const { resp, status } = await tx(c, new HistoryReadRequest({
        historyReadDetails: new ReadRawModifiedDetails({ isReadModified: false, startTime: start, endTime: end, numValuesPerNode: Math.max(0, numValues), returnBounds }),
        timestampsToReturn: ts,
        releaseContinuationPoints: release,
        nodesToRead: [{ nodeId, continuationPoint: cp ? Buffer.from(cp, "base64") : undefined }],
    }));
    const page: HistoryPage = { svc: status, item: 0, cp: null, values: [] };
    if (!resp || isBad(status) || !resp.results?.length) return page;
    const hr = resp.results[0];
    page.item = codeOf(hr.statusCode);
    if (hr.continuationPoint && hr.continuationPoint.length > 0) page.cp = Buffer.from(hr.continuationPoint).toString("base64");
    const hd = hr.historyData;
    if (hd instanceof HistoryData) {
        for (const dv of hd.dataValues ?? []) {
            const v: Record<string, unknown> = {};
            const vf = valueFields(dv.value);
            v.value = vf.value;
            v.dataType = vf.dataType;
            v.builtInType = vf.builtInType;
            v.statusCode = statusJson(dv.statusCode);
            if (dv.sourceTimestamp) v.sourceTimestamp = dateToString(dv.sourceTimestamp);
            if (dv.serverTimestamp) v.serverTimestamp = dateToString(dv.serverTimestamp);
            page.values.push(v);
        }
    }
    return page;
}

async function cmdHistoryRead(a: Args, r: Result): Promise<number> {
    const nodeStr = a.get("--node"), startStr = a.get("--start"), endStr = a.get("--end");
    if (!a.get("--endpoint") || !nodeStr || !startStr || !endStr) {
        throw new InputError("missing --endpoint, --node, --start, or --end [--scenario continue]");
    }
    parseNodeIdString(nodeStr);
    const start = new Date(startStr), end = new Date(endStr);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) throw new InputError("--start / --end must be RFC 3339");
    let numValues = a.num("--num-values", 0);
    const cpIn = a.get("--continuation-point") ?? null;
    const release = a.bool("--release-continuation-point", false);
    const bounds = a.bool("--return-bounds", false);
    const scenario = a.get("--scenario");
    if (scenario !== undefined && scenario !== "continue") throw new InputError(`unknown --scenario ${scenario}`);
    const ts = timestampsArg(a);
    const c = await connect(a);
    try {
        const nodeId = resolve(c, nodeStr);
        if (scenario === "continue") {
            if (numValues <= 0) numValues = 2;
            const pages: Record<string, unknown>[] = [];
            let cp: string | null = null;
            let lastSvc = 0, lastItem = 0;
            for (let i = 0; i < 8; i++) {
                const p = await historyReadOnce(c, nodeId, start, end, numValues, bounds, ts, cp, false);
                lastSvc = p.svc;
                lastItem = p.item;
                pages.push({ values: p.values, continuationPoint: p.cp, statusCode: statusJson(p.item) });
                if (!isGood(p.svc) || !isGood(p.item) || !p.cp) break;
                cp = p.cp;
            }
            // As the Milo adapter: release the last continuation point the
            // session received, then try to reuse it.
            let releaseSc = 0, reuseSc = 0;
            const rel = await historyReadOnce(c, nodeId, start, end, numValues, bounds, ts, cp, true);
            releaseSc = isGood(rel.svc) ? rel.item : rel.svc;
            if (cp) {
                const reuse = await historyReadOnce(c, nodeId, start, end, numValues, bounds, ts, cp, false);
                reuseSc = isGood(reuse.svc) ? reuse.item : reuse.svc;
            }
            r.add({
                scenario: "continue",
                nodeId: nodeIdToString(nodeId),
                pages,
                releaseStatusCode: statusJson(releaseSc),
                reuseAfterReleaseStatusCode: statusJson(reuseSc),
            });
            const ok = isGood(lastSvc) && isGood(lastItem) && pages.length > 0;
            r.setService(isGood(lastSvc) ? lastItem : lastSvc);
            if (!ok) {
                r.fail("service", "HistoryRead failed");
                return EXIT_SERVICE;
            }
            return EXIT_OK;
        }
        const p = await historyReadOnce(c, nodeId, start, end, numValues, bounds, ts, cpIn, release);
        r.add({ nodeId: nodeIdToString(nodeId), statusCode: statusJson(p.item), continuationPoint: p.cp, values: p.values });
        r.setService(isGood(p.svc) ? p.item : p.svc);
        if (!(isGood(p.svc) && isGood(p.item))) {
            r.fail("service", "HistoryRead failed");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

function uintArg(a: Args, name: string): number {
    const v = a.get(name);
    if (v === undefined || !/^\d+$/.test(v) || Number(v) > 0xffffffff) throw new InputError(`${name} must be a uint32`);
    return Number(v);
}

async function cmdRepublish(a: Args, r: Result): Promise<number> {
    if (!a.get("--endpoint")) throw new InputError("missing --endpoint, --subscription-id, or --sequence-number");
    const subId = uintArg(a, "--subscription-id"), seq = uintArg(a, "--sequence-number");
    const c = await connect(a);
    try {
        const { resp, status } = await tx(c, new RepublishRequest({ subscriptionId: subId, retransmitSequenceNumber: seq }));
        const item: Record<string, unknown> = { subscriptionId: subId, retransmitSequenceNumber: seq };
        if (resp && isGood(status) && resp.notificationMessage) {
            const nm = resp.notificationMessage;
            item.sequenceNumber = nm.sequenceNumber;
            if (nm.publishTime) item.publishTime = dateToString(nm.publishTime);
            item.notificationDataCount = (nm.notificationData ?? []).length;
        }
        r.add(item).setService(status);
        if (!isGood(status)) {
            r.fail("service", "Republish failed");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdTransferSubscriptions(a: Args, r: Result): Promise<number> {
    const ids = a.all("--subscription-id");
    if (!a.get("--endpoint") || ids.length === 0) throw new InputError("missing --endpoint or --subscription-id");
    const subIds = ids.map((s) => {
        if (!/^\d+$/.test(s)) throw new InputError(`--subscription-id must be a uint32: ${s}`);
        return Number(s);
    });
    const sendInitial = a.bool("--send-initial-values", false);
    const c = await connect(a);
    try {
        const { resp, status } = await tx(c, new TransferSubscriptionsRequest({ subscriptionIds: subIds, sendInitialValues: sendInitial }));
        r.setService(status);
        let ok = isGood(status);
        if (resp && isGood(status)) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (resp.results ?? []).forEach((tr: any, i: number) => {
                if (!isGood(tr.statusCode)) ok = false;
                r.add({ subscriptionId: subIds[i], statusCode: statusJson(tr.statusCode), availableSequenceNumbers: [...(tr.availableSequenceNumbers ?? [])] });
            });
        }
        if (!ok) {
            r.fail("service", "TransferSubscriptions failed");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdRegisterNodes(a: Args, r: Result): Promise<number> {
    const nodes = a.all("--node");
    if (!a.get("--endpoint") || nodes.length === 0) throw new InputError("missing --endpoint or --node");
    nodes.forEach((n) => parseNodeIdString(n));
    const c = await connect(a);
    try {
        const ids = nodes.map((n) => resolve(c, n));
        const { RegisterNodesRequest, UnregisterNodesRequest } = await import("node-opcua");
        const reg = await tx(c, new RegisterNodesRequest({ nodesToRegister: ids }));
        if (!reg.resp || isBad(reg.status)) {
            r.setService(reg.status).fail("service", "RegisterNodes failed");
            return EXIT_SERVICE;
        }
        const aliases: NodeId[] = reg.resp.registeredNodeIds ?? [];
        const read = await tx(c, new ReadRequest({
            maxAge: 0,
            timestampsToReturn: TimestampsToReturn.Both,
            nodesToRead: aliases.map((nodeId) => ({ nodeId, attributeId: AttributeIds.Value })),
        }));
        const unreg = await tx(c, new UnregisterNodesRequest({ nodesToUnregister: aliases }));
        let ok = isGood(read.status) && isGood(unreg.status);
        ids.forEach((id, i) => {
            const dv: DataValue | undefined = read.resp?.results?.[i];
            const item: Record<string, unknown> = {
                nodeId: nodeIdToString(id),
                registeredNodeId: aliases[i] ? nodeIdToString(aliases[i]) : null,
                statusCode: statusJson(dv ? dv.statusCode : read.status),
            };
            if (dv && isGood(dv.statusCode)) {
                const vf = valueFields(dv.value);
                item.dataType = vf.dataType;
                item.builtInType = vf.builtInType;
                item.value = vf.value;
            } else ok = false;
            item.unregisterStatusCode = statusJson(unreg.status);
            r.add(item);
        });
        if (!ok) {
            r.fail("service", "RegisterNodes / Read / UnregisterNodes did not succeed");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdNodeManagement(a: Args, r: Result): Promise<number> {
    const parentStr = a.get("--parent"), nodeStr = a.get("--node");
    if (!a.get("--endpoint") || !parentStr || !nodeStr) throw new InputError("missing --endpoint, --parent or --node");
    parseNodeIdString(parentStr);
    parseNodeIdString(nodeStr);
    const browseName = a.get("--browse-name") ?? "InteropAdded";
    const valueStr = a.get("--value") ?? "42";
    if (!/^-?\d+$/.test(valueStr) || Number(valueStr) < -2147483648 || Number(valueStr) > 2147483647) throw new InputError("--value must be an Int32");
    const value = Number(valueStr);
    const c = await connect(a);
    try {
        const parent = resolve(c, parentStr), requested = resolve(c, nodeStr);
        const attrs = new VariableAttributes({
            specifiedAttributes: 0x1 | 0x40 | 0x800 | 0x20000 | 0x200000 | 0x80000 | 0x40000,
            displayName: new LocalizedText({ text: browseName }),
            value: new Variant({ dataType: DataType.Int32, value }),
            dataType: new NodeId(1 as never, 6 as never, 0),
            valueRank: -1,
            accessLevel: 3,
            userAccessLevel: 3,
        });
        const add = await tx(c, new AddNodesRequest({
            nodesToAdd: [{
                parentNodeId: parent as never,
                referenceTypeId: "i=47",
                requestedNewNodeId: requested as never,
                browseName: new QualifiedName({ namespaceIndex: requested.namespace, name: browseName }),
                nodeClass: NodeClass.Variable,
                nodeAttributes: attrs as unknown as ExtensionObject,
                typeDefinition: new NodeId(1 as never, 63 as never, 0) as never,
            }],
        }));
        const item: Record<string, unknown> = { parentNodeId: nodeIdToString(parent), requestedNodeId: nodeIdToString(requested) };
        if (!add.resp || isBad(add.status)) {
            item.addStatusCode = statusJson(add.status);
            r.add(item).setService(add.status).fail("service", "AddNodes failed");
            return EXIT_SERVICE;
        }
        const ar = add.resp.results[0];
        item.addStatusCode = statusJson(ar.statusCode);
        if (!isGood(ar.statusCode)) {
            r.add(item).setService(ar.statusCode).fail("service", "AddNodes failed");
            return EXIT_SERVICE;
        }
        const added: NodeId = ar.addedNodeId;
        item.addedNodeId = nodeIdToString(added);
        const read1 = await tx(c, new ReadRequest({ nodesToRead: [{ nodeId: added, attributeId: AttributeIds.Value }] }));
        const dv: DataValue | undefined = read1.resp?.results?.[0];
        item.readStatusCode = statusJson(dv ? dv.statusCode : read1.status);
        if (dv) Object.assign(item, { dataType: variantType(dv.value).dataType, builtInType: variantType(dv.value).builtInType, value: variantValueJson(dv.value) });
        const del = await tx(c, new DeleteNodesRequest({ nodesToDelete: [{ nodeId: added, deleteTargetReferences: true }] }));
        const delSc = del.resp && isGood(del.status) ? codeOf(del.resp.results?.[0]) : del.status;
        item.deleteStatusCode = statusJson(delSc);
        const read2 = await tx(c, new ReadRequest({ nodesToRead: [{ nodeId: added, attributeId: AttributeIds.Value }] }));
        const dv2: DataValue | undefined = read2.resp?.results?.[0];
        const after = dv2 ? codeOf(dv2.statusCode) : read2.status;
        item.readAfterDeleteStatusCode = statusJson(after);
        r.add(item);
        const ok = dv !== undefined && isGood(dv.statusCode) && Number(dv.value?.value) === value && isGood(delSc) && isBad(after);
        r.setService(ok ? 0 : !isGood(delSc) ? delSc : codeOf(dv?.statusCode));
        if (!ok) {
            r.fail("service", "node-management sequence did not succeed");
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdFindServersOnNetwork(a: Args, r: Result): Promise<number> {
    if (!a.get("--endpoint")) throw new InputError("missing --endpoint");
    const c = await connect(a, false);
    try {
        const { resp, status } = await tx(c, new FindServersOnNetworkRequest({
            startingRecordId: a.num("--starting-record-id", 0),
            maxRecordsToReturn: a.num("--max-records", 0),
            serverCapabilityFilter: a.all("--capability"),
        }));
        r.setService(status);
        if (!resp || isBad(status)) {
            r.fail("service", "FindServersOnNetwork failed");
            return EXIT_SERVICE;
        }
        const reset = dateToString(resp.lastCounterResetTime);
        for (const s of resp.servers ?? []) {
            const item: Record<string, unknown> = {
                recordId: s.recordId,
                serverName: s.serverName ?? "",
                discoveryUrl: s.discoveryUrl ?? "",
                serverCapabilities: s.serverCapabilities ?? [],
            };
            if (reset) item.lastCounterResetTime = reset;
            r.add(item);
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

async function cmdRegisterServer(a: Args, r: Result): Promise<number> {
    const serverUri = a.get("--server-uri");
    const urls = a.all("--discovery-url");
    if (!a.get("--endpoint") || !serverUri || urls.length === 0) throw new InputError("missing --endpoint, --server-uri or --discovery-url");
    const service = a.get("--service") ?? "auto";
    if (!["auto", "RegisterServer2", "RegisterServer"].includes(service)) throw new InputError("--service must be auto, RegisterServer2 or RegisterServer");
    const types: Record<string, ApplicationType> = {
        Server: ApplicationType.Server,
        Client: ApplicationType.Client,
        ClientAndServer: ApplicationType.ClientAndServer,
        DiscoveryServer: ApplicationType.DiscoveryServer,
    };
    const serverType = types[a.get("--server-type") ?? "Server"];
    if (serverType === undefined) throw new InputError("--server-type must be Server, Client, ClientAndServer or DiscoveryServer");
    const name = a.get("--server-name") ?? serverUri;
    const online = a.bool("--online", true);
    const server = new RegisteredServer({
        serverUri,
        productUri: a.get("--product-uri") ?? "",
        serverNames: [new LocalizedText({ locale: a.get("--server-name-locale") ?? "en", text: name })],
        serverType,
        gatewayServerUri: a.get("--gateway-server-uri") ?? null,
        discoveryUrls: urls,
        semaphoreFilePath: a.get("--semaphore-file") ?? null,
        isOnline: online,
    });
    const c = await connect(a, false);
    try {
        const item: Record<string, unknown> = { service: "", serverUri, isOnline: online };
        let fallback = false;
        let configResults: number[] = [];
        let status = 0;
        let usedService = service === "RegisterServer" ? "RegisterServer" : "RegisterServer2";
        if (usedService === "RegisterServer2") {
            const cfg = new MdnsDiscoveryConfiguration({ mdnsServerName: a.get("--mdns-name") ?? name, serverCapabilities: a.all("--capability") });
            const r2 = await tx(c, new RegisterServer2Request({ server, discoveryConfiguration: [cfg] }));
            status = r2.status;
            item.registerServer2StatusCode = statusJson(r2.status);
            configResults = (r2.resp?.configurationResults ?? []).map((s: StatusCode) => codeOf(s));
            const unsupported = [StatusCodes.BadServiceUnsupported.value, StatusCodes.BadNotImplemented.value, StatusCodes.BadNotSupported.value];
            if (service === "auto" && unsupported.includes(status)) {
                fallback = true;
                usedService = "RegisterServer";
                configResults = [];
            }
        }
        if (usedService === "RegisterServer") {
            const r1 = await tx(c, new RegisterServerRequest({ server }));
            status = r1.status;
        }
        item.service = usedService;
        item.statusCode = statusJson(status);
        item.fallback = fallback;
        if (item.registerServer2StatusCode === undefined) delete item.registerServer2StatusCode;
        const ordered: Record<string, unknown> = {
            service: item.service,
            serverUri,
            isOnline: online,
            statusCode: item.statusCode,
            fallback,
        };
        if (item.registerServer2StatusCode) ordered.registerServer2StatusCode = item.registerServer2StatusCode;
        ordered.configurationResults = configResults.map((s) => statusJson(s));
        r.add(ordered).setService(status);
        if (!isGood(status) || configResults.some((s) => !isGood(s))) {
            r.fail("service", `${usedService} failed`);
            return EXIT_SERVICE;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

// ---------------------------------------------------------------------------
// alarms: ConditionRefresh + Acknowledge / Confirm / AddComment (Part 9)
// ---------------------------------------------------------------------------

/** The 16 SelectClauses of `alarms`: [TypeDefinitionId, BrowsePath, AttributeId]. */
const ALARM_SELECT: [string, string[], number][] = [
    ["i=2041", ["EventId"], AttributeIds.Value],
    ["i=2041", ["EventType"], AttributeIds.Value],
    ["i=2041", ["SourceNode"], AttributeIds.Value],
    ["i=2041", ["SourceName"], AttributeIds.Value],
    ["i=2041", ["Time"], AttributeIds.Value],
    ["i=2041", ["Message"], AttributeIds.Value],
    ["i=2041", ["Severity"], AttributeIds.Value],
    ["i=2782", ["ConditionName"], AttributeIds.Value],
    ["i=2782", ["BranchId"], AttributeIds.Value],
    ["i=2782", ["Retain"], AttributeIds.Value],
    ["i=2782", ["EnabledState", "Id"], AttributeIds.Value],
    ["i=2782", ["Comment"], AttributeIds.Value],
    ["i=2881", ["AckedState", "Id"], AttributeIds.Value],
    ["i=2881", ["ConfirmedState", "Id"], AttributeIds.Value],
    ["i=2915", ["ActiveState", "Id"], AttributeIds.Value],
    ["i=2782", [], AttributeIds.NodeId], // ConditionId (Part 9 §5.5.2)
];

const REFRESH_START = "i=2787";
const REFRESH_END = "i=2788";

/** A ConditionEntry of the `alarms` result (docs/CLIENT_CONTRACT.md §4 `alarms`). */
export interface ConditionEntry {
    conditionId: string | null;
    eventId: string | null;
    eventType: string | null;
    sourceNode: string | null;
    sourceName: string | null;
    conditionName: string | null;
    time: string | null;
    message: string | null;
    severity: number | null;
    retain: boolean | null;
    enabled: boolean | null;
    acked: boolean | null;
    confirmed: boolean | null;
    active: boolean | null;
    comment: string | null;
}

interface ConditionEvent {
    entry: ConditionEntry;
    eventId: Buffer | null;
}

/** The value of an event field, null for Null / StatusCode (a Bad select result) / absent. */
function eventValue(v: Variant | undefined): unknown {
    if (!v || v.dataType === DataType.Null || v.dataType === DataType.StatusCode) return null;
    return v.value ?? null;
}

/** The ConditionEntry of one event's 16 fields (ALARM_SELECT order). */
export function conditionEntry(fields: Variant[]): ConditionEntry {
    const f = (i: number) => eventValue(fields[i]);
    const nid = (i: number) => (f(i) instanceof NodeId ? nodeIdToString(f(i) as NodeId) : null);
    const str = (i: number) => (typeof f(i) === "string" ? (f(i) as string) : null);
    const bool = (i: number) => (typeof f(i) === "boolean" ? (f(i) as boolean) : null);
    const text = (i: number) => (f(i) instanceof LocalizedText ? ((f(i) as LocalizedText).text ?? "") : null);
    const ev = f(0);
    const t = f(4);
    const sev = f(6);
    return {
        conditionId: nid(15),
        eventId: Buffer.isBuffer(ev) ? ev.toString("base64") : null,
        eventType: nid(1),
        sourceNode: nid(2),
        sourceName: str(3),
        conditionName: str(7),
        // the OPC UA null DateTime (1601-01-01, encoded 0) is null
        time: t instanceof Date && t.getTime() > Date.UTC(1601, 0, 2) ? dateToString(t) : null,
        message: text(5),
        severity: typeof sev === "number" ? sev : null,
        retain: bool(9),
        enabled: bool(10),
        acked: bool(12),
        confirmed: bool(13),
        active: bool(14),
        comment: text(11),
    };
}

/** A presence flag (`--acknowledge`), also `--acknowledge true|false`. */
export function flagArg(a: Args, name: string): boolean {
    const i = a.argv.indexOf(name);
    if (i < 0) return false;
    const next = a.argv[i + 1];
    return !(next === "false" || next === "0");
}

async function callStatus(c: Conn, objectId: NodeId, methodId: NodeId, inputArguments: Variant[]): Promise<number> {
    const { resp, status } = await tx(c, new CallRequest({ methodsToCall: [{ objectId, methodId, inputArguments }] }));
    if (!resp || isBad(status) || !resp.results?.length) return status || StatusCodes.BadUnexpectedError.value;
    return codeOf(resp.results[0].statusCode);
}

async function cmdAlarms(a: Args, r: Result): Promise<number> {
    if (!a.get("--endpoint")) throw new InputError("missing --endpoint");
    const nodeStr = a.get("--node") ?? "i=2253";
    parseNodeIdString(nodeStr);
    const conditionName = a.get("--condition-name");
    const doAck = flagArg(a, "--acknowledge");
    const doConfirm = flagArg(a, "--confirm");
    const doComment = flagArg(a, "--add-comment");
    const commentText = a.get("--comment") ?? "interop-comment";
    const toMs = a.num("--timeout-ms", 15000);
    const pi = a.num("--publishing-interval-ms", 200);
    const c = await connect(a);
    const deadline = Date.now() + toMs;
    const left = () => Math.max(0, deadline - Date.now());
    try {
        const nodeId = resolve(c, nodeStr);
        const selectClauses = ALARM_SELECT.map(([type, browsePath, attributeId]) => new SimpleAttributeOperand({
            typeDefinitionId: type,
            browsePath: browsePath.map((name) => new QualifiedName({ namespaceIndex: 0, name })),
            attributeId,
        }));
        const filter = new EventFilter({ selectClauses, whereClause: new ContentFilter({ elements: [] }) });
        const sub = await createSubscription(c, pi, 10000, 10);
        const pump = new PublishPump(c, Math.max(sub.revisedPublishingInterval * sub.revisedMaxKeepAliveCount + 5000, c.t.request));

        // Event classification, every notification in arrival order.
        let processed = 0;
        let refreshCalled = false;
        let startSeen = false;
        let endSeen = false;
        const refreshed = new Map<string, ConditionEntry>(); // first-seen order, last value
        const latest = new Map<string, ConditionEvent>();
        const condEvents: ConditionEvent[] = [];
        const drain = () => {
            while (processed < pump.notifications.length) {
                const n = pump.notifications[processed++];
                if (!n.eventFields || n.clientHandle !== 1) continue;
                const entry = conditionEntry(n.eventFields);
                if (entry.eventType === REFRESH_START) {
                    if (refreshCalled) startSeen = true;
                    continue;
                }
                if (entry.eventType === REFRESH_END) {
                    if (refreshCalled) endSeen = true;
                    continue;
                }
                if (!entry.conditionId) continue;
                const ev0 = eventValue(n.eventFields[0]);
                const ce: ConditionEvent = { entry, eventId: Buffer.isBuffer(ev0) ? ev0 : null };
                latest.set(entry.conditionId, ce);
                condEvents.push(ce);
                if (refreshCalled && !endSeen) refreshed.set(entry.conditionId, entry);
            }
        };
        pump.onNotification = drain;
        pump.start();

        const mon = await createMonitoredItem(c, sub.subscriptionId, nodeId, {
            attributeId: AttributeIds.EventNotifier,
            samplingInterval: 0,
            queueSize: 1000,
            discardOldest: true,
            filter,
            ts: TimestampsToReturn.Both,
        });

        const item: Record<string, unknown> = {
            nodeId: nodeIdToString(nodeId),
            subscriptionId: sub.subscriptionId,
            monitoredItemStatusCode: statusJson(mon.status),
            refresh: null,
            conditions: [],
            target: null,
            acknowledge: null,
            confirm: null,
            addComment: null,
        };
        let exit = EXIT_OK;
        const finish = async (): Promise<number> => {
            pump.stop();
            await deleteSubscription(c, sub.subscriptionId);
            r.add(item);
            return exit;
        };
        const failWith = (status: number, category: string, msg: string, code: number) => {
            r.setService(status).fail(category, msg);
            exit = code;
        };

        if (!isGood(mon.status)) {
            item.refresh = { statusCode: statusJson(mon.status), startSeen: false, endSeen: false };
            failWith(mon.status, "service", "CreateMonitoredItems rejected the event monitored item", EXIT_SERVICE);
            return await finish();
        }

        // ConditionRefresh(SubscriptionId) on the ConditionType object.
        refreshCalled = true;
        const refreshStatus = await callStatus(c, resolve(c, "i=2782"), resolve(c, "i=3875"),
            [new Variant({ dataType: DataType.UInt32, value: sub.subscriptionId })]);
        const refresh: Record<string, unknown> = { statusCode: statusJson(refreshStatus), startSeen, endSeen };
        item.refresh = refresh;
        if (!isGood(refreshStatus)) {
            failWith(refreshStatus, "service", "ConditionRefresh failed", EXIT_SERVICE);
            return await finish();
        }
        const gotEnd = await pump.waitFor(() => endSeen, left());
        refresh.startSeen = startSeen;
        refresh.endSeen = endSeen;
        const list = [...refreshed.values()];
        item.conditions = list;
        if (!gotEnd) {
            failWith(StatusCodes.BadTimeout.value, "timeout", "timeout waiting for the RefreshEndEvent", EXIT_TIMEOUT);
            return await finish();
        }

        const target = conditionName !== undefined
            ? list.find((e) => e.conditionName === conditionName)
            : list.find((e) => e.retain === true);
        item.target = target ?? null;
        if (!target) {
            if (doAck || doConfirm || doComment) {
                failWith(StatusCodes.BadNodeIdUnknown.value, "service",
                    conditionName !== undefined ? `no condition named ${conditionName} in the refresh` : "no retained condition in the refresh", EXIT_SERVICE);
            }
            return await finish();
        }
        const targetKey = target.conditionId!;
        const conditionId = resolve(c, targetKey);
        const comment = new Variant({ dataType: DataType.LocalizedText, value: new LocalizedText({ locale: "en", text: commentText }) });
        const eventIdArg = (b: Buffer | null) => new Variant({ dataType: DataType.ByteString, value: b });

        /** Calls a condition method, then waits for the target's next event matching `pred`. */
        const action = async (methodId: string, pred: (e: ConditionEntry) => boolean) => {
            const eventId = latest.get(targetKey)?.eventId ?? null;
            const mark = condEvents.length;
            const status = await callStatus(c, conditionId, resolve(c, methodId), [eventIdArg(eventId), comment]);
            let event: ConditionEntry | null = null;
            if (!isGood(status)) return { status, event, eventId, timedOut: false };
            const ok = await pump.waitFor(() => {
                for (let i = mark; i < condEvents.length; i++) {
                    const e = condEvents[i].entry;
                    if (e.conditionId === targetKey && pred(e)) {
                        event = e;
                        return true;
                    }
                }
                return false;
            }, left());
            return { status, event, eventId, timedOut: !ok };
        };

        if (doAck) {
            const res = await action("i=9111", (e) => e.acked === true);
            const ack: Record<string, unknown> = { statusCode: statusJson(res.status), event: res.event, repeatStatusCode: null };
            item.acknowledge = ack;
            if (!isGood(res.status)) {
                failWith(res.status, "service", "Acknowledge failed", EXIT_SERVICE);
                return await finish();
            }
            // The same, now stale, EventId again: Bad_ConditionBranchAlreadyAcked or Bad_EventIdUnknown.
            ack.repeatStatusCode = statusJson(await callStatus(c, conditionId, resolve(c, "i=9111"), [eventIdArg(res.eventId), comment]));
            if (res.timedOut) {
                failWith(StatusCodes.BadTimeout.value, "timeout", "timeout waiting for the acknowledged event", EXIT_TIMEOUT);
                return await finish();
            }
        }
        if (doConfirm) {
            const res = await action("i=9113", (e) => e.confirmed === true);
            item.confirm = { statusCode: statusJson(res.status), event: res.event };
            if (!isGood(res.status)) {
                failWith(res.status, "service", "Confirm failed", EXIT_SERVICE);
                return await finish();
            }
            if (res.timedOut) {
                failWith(StatusCodes.BadTimeout.value, "timeout", "timeout waiting for the confirmed event", EXIT_TIMEOUT);
                return await finish();
            }
        }
        if (doComment) {
            const res = await action("i=9029", (e) => e.comment === commentText);
            item.addComment = { statusCode: statusJson(res.status), event: res.event };
            if (!isGood(res.status)) {
                failWith(res.status, "service", "AddComment failed", EXIT_SERVICE);
                return await finish();
            }
            if (res.timedOut) {
                failWith(StatusCodes.BadTimeout.value, "timeout", "timeout waiting for the comment event", EXIT_TIMEOUT);
                return await finish();
            }
        }
        return await finish();
    } finally {
        await close(c);
    }
}

// ---------------------------------------------------------------------------
// Push certificate management (Part 12 §7) — CLIENT_CONTRACT §15
// ---------------------------------------------------------------------------

function trustListJson(tl: TrustListDataType): Record<string, unknown> {
    const b64 = (l: Buffer[] | null | undefined) => (l ?? []).map((c) => Buffer.from(c).toString("base64"));
    return {
        specifiedLists: tl.specifiedLists,
        trustedCertificates: b64(tl.trustedCertificates as Buffer[]),
        trustedCrls: b64(tl.trustedCrls as Buffer[]),
        issuerCertificates: b64(tl.issuerCertificates as Buffer[]),
        issuerCrls: b64(tl.issuerCrls as Buffer[]),
    };
}

/** ServerConfiguration (i=12637) and the NodeIds of its 1.05 methods and variables (Part 12 §7.10, Annex A). */
export const SERVER_CONFIGURATION = "i=12637";
export const SC_METHODS = {
    getCertificates: "i=32333",
    createSelfSignedCertificate: "i=19342",
    deleteCertificate: "i=19345",
    cancelChanges: "i=25708",
    resetToServerDefaults: "i=25709",
};
/** ServerConfiguration.TransactionDiagnostics children (TransactionDiagnosticsType, Part 12 §7.10.12). */
export const TRANSACTION_DIAGNOSTICS = {
    startTime: "i=32337",
    endTime: "i=32338",
    result: "i=32339",
    affectedTrustLists: "i=32340",
    affectedCertificateGroups: "i=32341",
    errors: "i=32342",
};

/** `--group`: the well-known CertificateGroups (Part 12 §7.8.4) and the default CertificateType of each. */
export const PUSH_GROUPS: Record<string, { groupId: string; certificateTypeId: string }> = {
    // DefaultApplicationGroup, RsaSha256ApplicationCertificateType
    Application: { groupId: "i=14156", certificateTypeId: "i=12560" },
    // DefaultHttpsGroup, HttpsCertificateType
    Https: { groupId: "i=14088", certificateTypeId: "i=12558" },
    // DefaultUserTokenGroup, UserCredentialCertificateType
    UserToken: { groupId: "i=14122", certificateTypeId: "i=15181" },
};

/** The private key format of `--update-private-key`: `--private-key-format`, else PFX for .pfx / .p12, else PEM. */
export function privateKeyFormat(a: Args, file: string): string {
    const f = a.get("--private-key-format");
    if (f !== undefined) {
        if (f !== "PEM" && f !== "PFX") throw new InputError(`--private-key-format must be PEM or PFX, got ${f}`);
        return f;
    }
    return /\.(pfx|p12)$/i.test(file) ? "PFX" : "PEM";
}

function readInputFile(file: string, flag: string): Buffer {
    try {
        return fs.readFileSync(file);
    } catch (e) {
        throw new InputError(`${flag} ${file}: ${(e as Error).message}`);
    }
}

function readInputCertificate(file: string, flag: string): Buffer {
    readInputFile(file, flag);
    return readCertificateDer(file);
}

/** A uint16 flag (LifetimeInDays, KeySizeInBits). */
function uint16Arg(a: Args, name: string, def: number): number {
    const n = a.num(name, def);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new InputError(`${name} must be an integer 0..65535`);
    return n;
}

/** Call one method; the CallMethodResult status (or the service status) and the output arguments. */
async function callMethod(c: Conn, objectId: NodeId, methodId: NodeId, inputArguments: Variant[]): Promise<{ status: number; outputs: Variant[] }> {
    const { resp, status } = await tx(c, new CallRequest({ methodsToCall: [{ objectId, methodId, inputArguments }] }));
    if (!resp || isBad(status) || !resp.results?.length) return { status: status || StatusCodes.BadUnexpectedError.value, outputs: [] };
    return { status: codeOf(resp.results[0].statusCode), outputs: resp.results[0].outputArguments ?? [] };
}

/** TransactionDiagnostics of ServerConfiguration: its six variables read in one Read. */
async function readTransactionDiagnostics(c: Conn): Promise<{ status: number; diagnostics?: Record<string, unknown> }> {
    const keys = Object.keys(TRANSACTION_DIAGNOSTICS) as (keyof typeof TRANSACTION_DIAGNOSTICS)[];
    const { resp, status } = await tx(c, new ReadRequest({
        nodesToRead: keys.map((k) => ({ nodeId: NodeId.resolveNodeId(TRANSACTION_DIAGNOSTICS[k]), attributeId: AttributeIds.Value })),
        timestampsToReturn: TimestampsToReturn.Neither,
    }));
    if (!resp || isBad(status) || (resp.results ?? []).length !== keys.length) return { status: status || StatusCodes.BadUnexpectedError.value };
    const dvs = resp.results as DataValue[];
    const bad = dvs.find((dv) => isBad(dv.statusCode));
    if (bad) return { status: codeOf(bad.statusCode) };
    const v = (i: number) => dvs[i].value?.value;
    const ids = (x: unknown) => ((x as NodeId[] | null) ?? []).map((n) => nodeIdToString(n));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const errors = ((v(5) as any[] | null) ?? []).map((e: any) => ({
        targetId: nodeIdToString(e?.targetId),
        error: statusJson(e?.error),
        message: e?.message?.text ?? null,
    }));
    return {
        status: 0,
        diagnostics: {
            startTime: dateToString(v(0) as Date),
            endTime: dateToString(v(1) as Date),
            result: statusJson(v(2) as StatusCode),
            affectedTrustLists: ids(v(3)),
            affectedCertificateGroups: ids(v(4)),
            errors,
        },
    };
}

/**
 * client push: node-opcua's ClientPushCertificateManagement / TrustListClient
 * (node-opcua-server-configuration) against the ServerConfiguration object of
 * the server, plus the Part 12 1.05 methods that client has no helper for
 * (GetCertificates, CreateSelfSignedCertificate, DeleteCertificate,
 * ResetToServerDefaults, CancelChanges; plain Call requests). The steps run in
 * the order of CLIENT_CONTRACT §1 "push flags" and stop at the first Bad
 * status; everything runs on one session (one transaction, Part 12 §7.10.2).
 */
async function cmdPush(a: Args, r: Result): Promise<number> {
    if (!a.get("--endpoint")) throw new InputError("missing --endpoint");
    const groupName = a.get("--group") ?? "Application";
    const group = PUSH_GROUPS[groupName];
    if (!group) throw new InputError(`--group must be Application, Https or UserToken, got ${groupName}`);
    const certTypeStr = a.get("--certificate-type-id") ?? group.certificateTypeId;
    parseNodeIdString(certTypeStr);
    const addFile = a.get("--add-certificate");
    const removeThumb = a.get("--remove-certificate");
    const issuer = a.has("--issuer");
    const csr = a.has("--csr");
    const apply = a.has("--apply");
    const getCerts = a.has("--get-certificates");
    const selfSigned = a.has("--create-self-signed");
    const deleteType = a.get("--delete-certificate");
    if (deleteType !== undefined) parseNodeIdString(deleteType);
    const updateFile = a.get("--update-certificate");
    const keyFile = a.get("--update-private-key");
    if (keyFile !== undefined && updateFile === undefined) throw new InputError("--update-private-key needs --update-certificate");
    const reset = a.has("--reset-to-defaults");
    const diag = a.has("--transaction-diagnostics");
    const cancel = !apply && (a.has("--cancel") || selfSigned || deleteType !== undefined);
    const lifetime = uint16Arg(a, "--lifetime-days", 365);
    const keySize = uint16Arg(a, "--key-size", 0);
    const add = addFile !== undefined ? readInputCertificate(addFile, "--add-certificate") : undefined;
    const update = updateFile !== undefined ? readInputCertificate(updateFile, "--update-certificate") : undefined;
    const issuers = a.all("--issuer-certificate").map((f) => readInputCertificate(f, "--issuer-certificate"));
    const keyFormat = keyFile !== undefined ? privateKeyFormat(a, keyFile) : "";
    const key = keyFile !== undefined ? readInputFile(keyFile, "--update-private-key") : undefined;

    const c = await connect(a);
    const out: Record<string, unknown> = {};
    const step = (name: string, sc: StatusCode | number): boolean => {
        const v = typeof sc === "number" ? sc : sc.value;
        out[name + "Status"] = statusJson(v);
        if (isGood(v)) return true;
        r.setService(v).fail("service", `${name} returned a non-Good status`);
        return false;
    };
    try {
        const scObj = resolve(c, SERVER_CONFIGURATION);
        const groupId = resolve(c, group.groupId);
        const certTypeId = resolve(c, certTypeStr);
        const method = (m: string) => resolve(c, m);
        out.certificateGroupId = nodeIdToString(groupId);
        const pcm = new ClientPushCertificateManagement(c.session!);
        const tl = await new CertificateGroup(c.session!, groupId).getTrustList();
        out.trustList = trustListJson(await tl.readTrustedCertificateListWithMasks(TrustListMasks.All));
        let ok = true;
        if (ok && add) ok = step("addCertificate", await tl.addCertificate(add, !issuer));
        if (ok && removeThumb !== undefined) ok = step("removeCertificate", await tl.removeCertificate(removeThumb, !issuer));
        if (ok && getCerts) {
            const res = await callMethod(c, scObj, method(SC_METHODS.getCertificates), [new Variant({ dataType: DataType.NodeId, value: groupId })]);
            ok = step("getCertificates", res.status);
            if (ok) {
                out.certificateTypeIds = ((res.outputs[0]?.value as NodeId[] | null) ?? []).map((n) => nodeIdToString(n));
                out.certificates = ((res.outputs[1]?.value as Buffer[] | null) ?? []).map((x) => Buffer.from(x).toString("base64"));
            }
        }
        if (ok && selfSigned) {
            const res = await callMethod(c, scObj, method(SC_METHODS.createSelfSignedCertificate), [
                new Variant({ dataType: DataType.NodeId, value: groupId }),
                new Variant({ dataType: DataType.NodeId, value: certTypeId }),
                new Variant({ dataType: DataType.String, value: a.get("--subject") ?? "" }),
                new Variant({ dataType: DataType.String, arrayType: VariantArrayType.Array, value: a.all("--dns") }),
                new Variant({ dataType: DataType.String, arrayType: VariantArrayType.Array, value: a.all("--ip") }),
                new Variant({ dataType: DataType.UInt16, value: lifetime }),
                new Variant({ dataType: DataType.UInt16, value: keySize }),
            ]);
            ok = step("createSelfSignedCertificate", res.status);
            if (ok) out.selfSignedCertificate = Buffer.from((res.outputs[0]?.value as Buffer | null) ?? []).toString("base64");
        }
        if (ok && deleteType !== undefined) {
            const res = await callMethod(c, scObj, method(SC_METHODS.deleteCertificate), [
                new Variant({ dataType: DataType.NodeId, value: groupId }),
                new Variant({ dataType: DataType.NodeId, value: resolve(c, deleteType) }),
            ]);
            ok = step("deleteCertificate", res.status);
        }
        if (ok && update) {
            const res = key
                ? await pcm.updateCertificate(groupId, certTypeId, update, issuers, keyFormat, key)
                : await pcm.updateCertificate(groupId, certTypeId, update, issuers);
            ok = step("updateCertificate", res.statusCode);
            if (ok) out.applyChangesRequired = res.applyChangesRequired;
        }
        if (ok && csr) {
            const res = await pcm.createSigningRequest(groupId, certTypeId, null, false);
            ok = step("createSigningRequest", res.statusCode);
            if (ok) out.certificateSigningRequest = Buffer.from(res.certificateSigningRequest ?? []).toString("base64");
        }
        if (ok) {
            const rej = await pcm.getRejectedList();
            ok = step("getRejectedList", rej.statusCode);
            if (ok) out.rejectedCertificates = (rej.certificates ?? []).map((x) => Buffer.from(x).toString("base64"));
        }
        if (ok && reset) ok = step("resetToServerDefaults", (await callMethod(c, scObj, method(SC_METHODS.resetToServerDefaults), [])).status);
        let applied = false;
        if (ok && apply) {
            ok = step("applyChanges", await pcm.applyChanges());
            applied = true;
        }
        if (ok && cancel) ok = step("cancelChanges", (await callMethod(c, scObj, method(SC_METHODS.cancelChanges), [])).status);
        // The diagnostics explain a failed ApplyChanges too: read them also then.
        if (diag && (ok || applied)) {
            const d = await readTransactionDiagnostics(c);
            out.transactionDiagnosticsStatus = statusJson(d.status);
            if (d.diagnostics) out.transactionDiagnostics = d.diagnostics;
            if (ok && !isGood(d.status)) {
                r.setService(d.status).fail("service", "reading TransactionDiagnostics returned a non-Good status");
                ok = false;
            }
        }
        if (ok) out.trustListAfter = trustListJson(await tl.readTrustedCertificateListWithMasks(TrustListMasks.All));
        r.add(out);
        return ok ? EXIT_OK : EXIT_SERVICE;
    } catch (e) {
        // The trust list helpers throw on a Bad method result.
        const sc = statusFromError(e);
        if (sc !== undefined) throw new ServiceError(`push: ${(e as Error).message}`, sc);
        throw e;
    } finally {
        await close(c);
    }
}

// ---------------------------------------------------------------------------
// Query (Part 4 §5.9) — CLIENT_CONTRACT §1 "query flags"
// ---------------------------------------------------------------------------

/**
 * `--data-to-return <relativePath>[#<Attribute>]`: a RelativePath in the text
 * form of Part 4 Annex A.2 (`/2:Name`, `.Name`, `<HasProperty>Name`; empty =
 * the node itself) and an AttributeId by name (`Value` default, `BrowseName`,
 * `NodeId`, …) or number. `#` is reserved in the path syntax (escaped `&#`),
 * so the last unescaped `#` separates the attribute.
 */
export function parseDataToReturn(spec: string): QueryDataDescription {
    let cut = -1;
    for (let i = spec.length - 1; i >= 0; i--) {
        if (spec[i] === "#" && (i === 0 || spec[i - 1] !== "&")) {
            cut = i;
            break;
        }
    }
    const pathStr = cut >= 0 ? spec.substring(0, cut) : spec;
    const attrStr = cut >= 0 ? spec.substring(cut + 1) : "Value";
    let attributeId: number;
    if (/^[0-9]+$/.test(attrStr)) attributeId = Number(attrStr);
    else {
        const v = (AttributeIds as unknown as Record<string, number>)[attrStr];
        if (typeof v !== "number") throw new InputError(`--data-to-return ${spec}: unknown attribute ${attrStr}`);
        attributeId = v;
    }
    let relativePath: RelativePath;
    try {
        relativePath = pathStr === "" ? new RelativePath({ elements: [] }) : makeRelativePath(pathStr);
    } catch (e) {
        throw new InputError(`--data-to-return ${spec}: invalid relative path: ${(e as Error).message}`);
    }
    return new QueryDataDescription({ relativePath, attributeId });
}

function expandedJson(e: ExpandedNodeId | null | undefined): string {
    if (!e) return "i=0";
    return e.namespaceUri || e.serverIndex ? expandedNodeIdToString(e) : nodeIdToString(e);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function queryDataSetsJson(sets: any[] | null | undefined): Record<string, unknown>[] {
    return (sets ?? []).map((ds) => ({
        nodeId: expandedJson(ds.nodeId),
        typeDefinitionNode: expandedJson(ds.typeDefinitionNode),
        values: ((ds.values ?? []) as Variant[]).map((v) => valueFields(v)),
    }));
}

const cpJson = (cp: Buffer | null | undefined) => (cp && cp.length > 0 ? Buffer.from(cp).toString("base64") : null);

/**
 * client query: QueryFirst for one NodeTypeDescription (no filter, the whole
 * address space), then QueryNext with the continuation point until the server
 * returns none (or once with ReleaseContinuationPoint).
 */
async function cmdQuery(a: Args, r: Result): Promise<number> {
    const typeStr = a.get("--type-definition");
    if (!a.get("--endpoint") || !typeStr) throw new InputError("missing --endpoint or --type-definition");
    parseNodeIdString(typeStr);
    const dataToReturn = a.all("--data-to-return").map(parseDataToReturn);
    const optUint = (n: string) => (a.get(n) === undefined ? 0 : uintArg(a, n));
    const maxDataSets = optUint("--max-data-sets");
    const maxReferences = optUint("--max-references");
    const release = flagArg(a, "--release-continuation-point");
    const maxNext = a.num("--max-query-next", 100);
    const c = await connect(a);
    try {
        const typeId = resolve(c, typeStr);
        const out: Record<string, unknown> = { typeDefinitionNode: nodeIdToString(typeId) };
        r.add(out);
        const { resp, status } = await tx(c, new QueryFirstRequest({
            view: new ViewDescription({}),
            nodeTypes: [new NodeTypeDescription({
                typeDefinitionNode: new ExpandedNodeId(typeId.identifierType, typeId.value, typeId.namespace),
                includeSubTypes: flagArg(a, "--include-subtypes"),
                dataToReturn,
            })],
            filter: new ContentFilter({ elements: [] }),
            maxDataSetsToReturn: maxDataSets,
            maxReferencesToReturn: maxReferences,
        }));
        const all: Record<string, unknown>[] = [];
        const first = queryDataSetsJson(resp?.queryDataSets);
        all.push(...first);
        out.queryFirst = {
            statusCode: statusJson(status),
            continuationPoint: cpJson(resp?.continuationPoint),
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            parsingResults: ((resp?.parsingResults ?? []) as any[]).map((p) => ({
                statusCode: statusJson(p.statusCode),
                dataStatusCodes: ((p.dataStatusCodes ?? []) as StatusCode[]).map((x) => statusJson(x)),
            })),
            queryDataSets: first,
        };
        const next: Record<string, unknown>[] = [];
        out.queryNext = next;
        out.queryDataSets = all;
        if (!resp || isBad(status)) {
            r.setService(status).fail("service", "QueryFirst failed");
            return EXIT_SERVICE;
        }
        let cp: Buffer | null = resp.continuationPoint && resp.continuationPoint.length > 0 ? resp.continuationPoint : null;
        while (cp && next.length < maxNext) {
            const n = await tx(c, new QueryNextRequest({ releaseContinuationPoint: release, continuationPoint: cp }));
            const sets = queryDataSetsJson(n.resp?.queryDataSets);
            all.push(...sets);
            const revised = n.resp?.revisedContinuationPoint;
            next.push({
                statusCode: statusJson(n.status),
                releaseContinuationPoint: release,
                revisedContinuationPoint: cpJson(revised),
                queryDataSets: sets,
            });
            if (!n.resp || isBad(n.status)) {
                r.setService(n.status).fail("service", "QueryNext failed");
                return EXIT_SERVICE;
            }
            if (release) break;
            cp = revised && revised.length > 0 ? revised : null;
        }
        return EXIT_OK;
    } finally {
        await close(c);
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

type Cmd = (a: Args, r: Result) => Promise<number>;

const COMMANDS: Record<string, Cmd> = {
    endpoints: cmdEndpoints,
    "find-servers": cmdFindServers,
    read: cmdRead,
    write: cmdWrite,
    browse: cmdBrowse,
    translate: cmdTranslate,
    call: cmdCall,
    subscribe: cmdSubscribe,
    "subscription-lifecycle": cmdSubscriptionLifecycle,
    "event-subscribe": cmdEventSubscribe,
    "history-read": cmdHistoryRead,
    republish: cmdRepublish,
    "transfer-subscriptions": cmdTransferSubscriptions,
    "register-nodes": cmdRegisterNodes,
    "node-management": cmdNodeManagement,
    "find-servers-on-network": cmdFindServersOnNetwork,
    "register-server": cmdRegisterServer,
    alarms: cmdAlarms,
    push: cmdPush,
    query: cmdQuery,
};

/** The client operations this adapter dispatches (print-capabilities must declare exactly these). */
export const OPERATIONS = Object.keys(COMMANDS);

const UNSUPPORTED_OPS: Record<string, string> = {
    codec: "the node-opcua adapter has no codec operation: node-opcua has no Part 6 XML encoding of Variants, its 1.05 JSON encoder (node-opcua-json) is not wired into the adapter, and it has no PubSub",
};

export const CLIENT_USAGE =
    "usage: client <endpoints|find-servers|read|write|browse|translate|call|subscribe|subscription-lifecycle|" +
    "event-subscribe|history-read [--scenario continue]|republish|transfer-subscriptions|register-nodes|node-management|" +
    "find-servers-on-network|register-server|alarms|push|query> --endpoint <url> [flags]";

export async function clientCommand(argv: string[]): Promise<number> {
    if (argv.length < 1) {
        process.stderr.write(CLIENT_USAGE + "\n");
        return 1;
    }
    const op = argv[0];
    const a = new Args(argv.slice(1));
    const r = new Result(op);
    if (UNSUPPORTED_OPS[op]) {
        r.setService(StatusCodes.BadNotSupported.value).fail("input", UNSUPPORTED_OPS[op]);
        r.emit();
        return EXIT_INPUT;
    }
    const cmd = COMMANDS[op];
    if (!cmd) {
        process.stderr.write(`unknown client subcommand: ${op}\n${CLIENT_USAGE}\n`);
        return 1;
    }
    let code: number;
    try {
        code = await cmd(a, r);
    } catch (e) {
        if (e instanceof InputError) {
            r.setService(StatusCodes.BadInvalidArgument.value).fail("input", e.message);
            code = EXIT_INPUT;
        } else if (e instanceof TransportError) {
            r.setService(e.status ?? StatusCodes.BadCommunicationError.value).fail("transport", e.message);
            code = EXIT_TRANSPORT;
        } else if (e instanceof ServiceError) {
            r.setService(e.status).fail("service", e.message);
            code = EXIT_SERVICE;
        } else if (e instanceof ReverseTimeout) {
            r.setService(StatusCodes.BadTimeout.value).fail("timeout", e.message);
            code = EXIT_TIMEOUT;
        } else if (e instanceof TimeoutError) {
            r.setService(StatusCodes.BadTimeout.value).fail("timeout", e.message);
            code = EXIT_TIMEOUT;
        } else if (e instanceof InternalError) {
            r.setService(StatusCodes.BadInternalError.value).fail("internal", e.message);
            code = EXIT_INTERNAL;
        } else {
            log("error", `client ${op} failed: ${(e as Error)?.stack ?? e}`);
            const sc = statusFromError(e);
            r.setService(sc ?? StatusCodes.BadInternalError.value).fail("internal", String((e as Error)?.message ?? e));
            code = EXIT_INTERNAL;
        }
    }
    r.emit();
    return code;
}

// Silence "unused" for helpers kept for symmetry with the contract.
void dataTypeName;
void dataValueJson;
