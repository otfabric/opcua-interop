package io.otfabric.opcuainterop;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryDecoder;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryEncoder;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.*;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;

/**
 * {@code client push} (docs/CLIENT_CONTRACT.md §1 "push flags", §4 {@code push}, §15) and
 * {@code client gds-pull} (§16.2).
 *
 * <p>Eclipse Milo 1.1.8 has neither a push certificate management client nor a GDS client, so
 * both commands are plain Call requests: on the standard NodeIds of ServerConfiguration (Part 12
 * §7.10) and of the GDS Directory (Part 12 §6.6, namespace http://opcfoundation.org/UA/GDS/), and
 * on the FileType methods of a TrustList object found with TranslateBrowsePaths. The TrustList
 * file is decoded with Milo's TrustListDataType codec; the GDS ApplicationRecordDataType, which
 * Milo does not define, is encoded by hand.
 *
 * <p>ByteStrings in the results are plain Base64 strings (contract §7).
 */
final class PushCommand {

    private PushCommand() {}

    static final long BAD_NOTHING_TO_DO = 0x800F0000L;
    static final int TRUST_LIST_CHUNK = 4096;
    static final long TRUST_LIST_MASKS_ALL = 15;

    // ServerConfiguration (i=12637) and its methods (Part 12 §7.10).
    static final NodeId SERVER_CONFIGURATION = new NodeId(0, uint(12637));
    static final NodeId SC_UPDATE_CERTIFICATE = new NodeId(0, uint(13737));
    static final NodeId SC_CREATE_SIGNING_REQUEST = new NodeId(0, uint(12737));
    static final NodeId SC_GET_REJECTED_LIST = new NodeId(0, uint(12777));
    static final NodeId SC_APPLY_CHANGES = new NodeId(0, uint(12740));
    static final NodeId SC_GET_CERTIFICATES = new NodeId(0, uint(32333));
    static final NodeId SC_CREATE_SELF_SIGNED = new NodeId(0, uint(19342));
    static final NodeId SC_DELETE_CERTIFICATE = new NodeId(0, uint(19345));
    static final NodeId SC_CANCEL_CHANGES = new NodeId(0, uint(25708));
    static final NodeId SC_RESET_TO_SERVER_DEFAULTS = new NodeId(0, uint(25709));

    /** ServerConfiguration.TransactionDiagnostics (Part 12 §7.10.12): StartTime … Errors. */
    static final int[] TRANSACTION_DIAGNOSTICS = {32337, 32338, 32339, 32340, 32341, 32342};

    /** {@code --group}: the CertificateGroup (Part 12 §7.8.4) and its default CertificateType. */
    static final Map<String, String[]> PUSH_GROUPS = Map.of(
        "Application", new String[]{"i=14156", "i=12560"},
        "Https",       new String[]{"i=14088", "i=12558"},
        "UserToken",   new String[]{"i=14122", "i=15181"});

    // ── helpers ───────────────────────────────────────────────────────────────

    static String b64(ByteString b) {
        return Base64.getEncoder().encodeToString(b == null ? new byte[0] : b.bytesOrEmpty());
    }

    static List<String> b64List(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof ByteString[]) {
            for (ByteString b : (ByteString[]) v) out.add(b64(b));
        }
        return out;
    }

    static List<String> nodeIdList(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof NodeId[]) {
            for (NodeId n : (NodeId[]) v) out.add(ResultBuilder.nodeIdToString(n));
        }
        return out;
    }

    static Object out(Variant[] outs, int i) {
        return outs != null && outs.length > i && outs[i] != null ? outs[i].getValue() : null;
    }

    static byte[] readFile(String path, String flag) throws ClientCommand.InputException {
        try {
            return Files.readAllBytes(Paths.get(path));
        } catch (Exception e) {
            throw new ClientCommand.InputException(flag + " " + path + ": " + e.getMessage());
        }
    }

    /** A certificate file (PEM or DER) as DER. */
    static byte[] readCertificateDer(String path, String flag) throws ClientCommand.InputException {
        byte[] data = readFile(path, flag);
        try {
            X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(data));
            return c.getEncoded();
        } catch (Exception e) {
            throw new ClientCommand.InputException(flag + " " + path + ": not a PEM or DER certificate: " + e.getMessage());
        }
    }

    /** Syntax check of a NodeId flag before connecting; nsu= forms are resolved later. */
    static String nodeIdArg(String s, String flag) throws ClientCommand.InputException {
        try {
            if (s.startsWith("nsu=")) {
                if (s.indexOf(';', 4) < 0) throw new NodeIdParser.InvalidNodeIdException("malformed nsu= NodeId: " + s);
            } else {
                NodeIdParser.parse(s);
            }
        } catch (NodeIdParser.InvalidNodeIdException e) {
            throw new ClientCommand.InputException(flag + ": " + e.getMessage());
        }
        return s;
    }

    static int uint16Arg(String[] args, String flag, int def) throws ClientCommand.InputException {
        String v = ClientCommand.findArg(args, flag);
        if (v == null) return def;
        try {
            int n = Integer.parseInt(v);
            if (n >= 0 && n <= 0xFFFF) return n;
        } catch (NumberFormatException ignored) {
            // fall through
        }
        throw new ClientCommand.InputException(flag + " must be an integer 0..65535, got " + v);
    }

    /** The result of one Call: the CallMethodResult status (or the Bad service result) and outputs. */
    record CallResult(StatusCode status, Variant[] outputs) {}

    static CallResult call(OpcUaClient client, NodeId object, NodeId method, Variant... inputs) {
        try {
            CallResponse resp = client.call(List.of(new CallMethodRequest(object, method, inputs)));
            CallMethodResult r = resp.getResults()[0];
            return new CallResult(r.getStatusCode(), r.getOutputArguments());
        } catch (UaException e) {
            return new CallResult(e.getStatusCode(), null);
        } catch (Exception e) {
            Throwable c = e.getCause();
            if (c instanceof UaException) return new CallResult(((UaException) c).getStatusCode(), null);
            return new CallResult(new StatusCode(StatusCodes.Bad_UnexpectedError), null);
        }
    }

    /** A Bad status of a step: the status key is already in the result. */
    static final class StepFailed extends Exception {
        final StatusCode status;
        StepFailed(String step, StatusCode status) {
            super(step + " returned a non-Good status");
            this.status = status;
        }
    }

    /** The child of {@code node} with BrowseName 0:{@code name} (TranslateBrowsePaths). */
    static NodeId child(OpcUaClient client, NodeId node, String name) throws StepFailed {
        StatusCode sc;
        try {
            BrowsePath bp = new BrowsePath(node, new RelativePath(new RelativePathElement[]{
                new RelativePathElement(Identifiers.HierarchicalReferences, false, true, new QualifiedName(0, name))}));
            TranslateBrowsePathsToNodeIdsResponse resp = client.translateBrowsePaths(List.of(bp));
            BrowsePathResult r = resp.getResults()[0];
            sc = r.getStatusCode();
            if (sc.isGood() && r.getTargets() != null && r.getTargets().length > 0) {
                ExpandedNodeId t = r.getTargets()[0].getTargetId();
                Optional<NodeId> local = t.toNodeId(client.getNamespaceTable());
                if (local.isPresent()) return local.get();
                sc = new StatusCode(StatusCodes.Bad_NodeIdUnknown);
            } else if (sc.isGood()) {
                sc = new StatusCode(StatusCodes.Bad_NoMatch);
            }
        } catch (UaException e) {
            sc = e.getStatusCode();
        }
        throw new StepFailed("TranslateBrowsePaths " + name, sc);
    }

    /** The content of a TrustList file: a TrustListDataType in the binary encoding (Part 12 §7.8.2.1). */
    static TrustListDataType decodeTrustList(EncodingContext ctx, byte[] data) {
        OpcUaBinaryDecoder dec = new OpcUaBinaryDecoder(ctx).setBuffer(Unpooled.wrappedBuffer(data));
        return new TrustListDataType.Codec().decodeType(ctx, dec);
    }

    static Map<String, Object> trustListJson(TrustListDataType tl) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("specifiedLists", tl.getSpecifiedLists() == null ? 0L : tl.getSpecifiedLists().longValue());
        m.put("trustedCertificates", b64List(tl.getTrustedCertificates()));
        m.put("trustedCrls", b64List(tl.getTrustedCrls()));
        m.put("issuerCertificates", b64List(tl.getIssuerCertificates()));
        m.put("issuerCrls", b64List(tl.getIssuerCrls()));
        return m;
    }

    /**
     * Read a TrustList object: OpenWithMasks(masks) (Open(Read) when masks is null), Read in
     * TRUST_LIST_CHUNK-byte chunks until an empty one, Close.
     */
    static TrustListDataType readTrustList(OpcUaClient client, NodeId trustList, Long masks) throws StepFailed {
        CallResult r = masks == null
            ? call(client, trustList, child(client, trustList, "Open"), new Variant(ubyte(1)))
            : call(client, trustList, child(client, trustList, "OpenWithMasks"), new Variant(uint(masks)));
        if (!r.status().isGood()) throw new StepFailed("readTrustList", r.status());
        Object handle = out(r.outputs(), 0);
        if (!(handle instanceof UInteger)) throw new StepFailed("readTrustList", new StatusCode(StatusCodes.Bad_UnexpectedError));
        NodeId readId = child(client, trustList, "Read");
        ByteBuf data = Unpooled.buffer();
        try {
            while (true) {
                r = call(client, trustList, readId, new Variant(handle), new Variant(TRUST_LIST_CHUNK));
                if (!r.status().isGood()) throw new StepFailed("readTrustList", r.status());
                Object chunk = out(r.outputs(), 0);
                byte[] b = chunk instanceof ByteString ? ((ByteString) chunk).bytesOrEmpty() : new byte[0];
                if (b.length == 0) break;
                data.writeBytes(b);
            }
        } finally {
            try {
                call(client, trustList, child(client, trustList, "Close"), new Variant(handle));
            } catch (StepFailed ignored) {
                // best effort
            }
        }
        byte[] bytes = new byte[data.readableBytes()];
        data.readBytes(bytes);
        try {
            return decodeTrustList(client.getStaticEncodingContext(), bytes);
        } catch (RuntimeException e) {
            throw new StepFailed("readTrustList", new StatusCode(StatusCodes.Bad_DecodingError));
        }
    }

    // ── client push ───────────────────────────────────────────────────────────

    static final class PushOptions {
        String groupId;
        String certificateTypeId;
        byte[] add;
        String remove;
        boolean issuer;
        boolean getCertificates;
        boolean selfSigned;
        String subject = "";
        List<String> dns = List.of();
        List<String> ip = List.of();
        int lifetimeDays = 365;
        int keySize = 0;
        String deleteType;
        byte[] update;
        List<byte[]> issuers = new ArrayList<>();
        String keyFormat = "";
        byte[] key;
        boolean csr;
        boolean reset;
        boolean apply;
        boolean cancel;
        boolean diagnostics;
    }

    /** The push flags, validated before connecting (exit 2 on bad input). */
    static PushOptions parsePush(String[] args) throws ClientCommand.InputException {
        PushOptions o = new PushOptions();
        String group = Optional.ofNullable(ClientCommand.findArg(args, "--group")).orElse("Application");
        String[] g = PUSH_GROUPS.get(group);
        if (g == null) throw new ClientCommand.InputException("--group must be Application, Https or UserToken, got " + group);
        o.groupId = g[0];
        o.certificateTypeId = nodeIdArg(
            Optional.ofNullable(ClientCommand.findArg(args, "--certificate-type-id")).orElse(g[1]), "--certificate-type-id");
        String add = ClientCommand.findArg(args, "--add-certificate");
        if (add != null) o.add = readCertificateDer(add, "--add-certificate");
        o.remove = ClientCommand.findArg(args, "--remove-certificate");
        o.issuer = ClientCommand.presenceFlag(args, "--issuer");
        o.getCertificates = ClientCommand.presenceFlag(args, "--get-certificates");
        o.selfSigned = ClientCommand.presenceFlag(args, "--create-self-signed");
        o.subject = Optional.ofNullable(ClientCommand.findArg(args, "--subject")).orElse("");
        o.dns = ClientCommand.findAllArgs(args, "--dns");
        o.ip = ClientCommand.findAllArgs(args, "--ip");
        o.lifetimeDays = uint16Arg(args, "--lifetime-days", 365);
        o.keySize = uint16Arg(args, "--key-size", 0);
        String del = ClientCommand.findArg(args, "--delete-certificate");
        if (del != null) o.deleteType = nodeIdArg(del, "--delete-certificate");
        String updateFile = ClientCommand.findArg(args, "--update-certificate");
        String keyFile = ClientCommand.findArg(args, "--update-private-key");
        if (keyFile != null && updateFile == null) {
            throw new ClientCommand.InputException("--update-private-key needs --update-certificate");
        }
        if (updateFile != null) o.update = readCertificateDer(updateFile, "--update-certificate");
        for (String f : ClientCommand.findAllArgs(args, "--issuer-certificate")) {
            o.issuers.add(readCertificateDer(f, "--issuer-certificate"));
        }
        if (keyFile != null) {
            String fmt = ClientCommand.findArg(args, "--private-key-format");
            if (fmt == null) {
                fmt = keyFile.toLowerCase(Locale.ROOT).matches(".*\\.(pfx|p12)$") ? "PFX" : "PEM";
            } else if (!fmt.equals("PEM") && !fmt.equals("PFX")) {
                throw new ClientCommand.InputException("--private-key-format must be PEM or PFX, got " + fmt);
            }
            o.keyFormat = fmt;
            o.key = readFile(keyFile, "--update-private-key");
        }
        o.csr = ClientCommand.presenceFlag(args, "--csr");
        o.reset = ClientCommand.presenceFlag(args, "--reset-to-defaults");
        o.apply = ClientCommand.presenceFlag(args, "--apply");
        o.cancel = !o.apply && (ClientCommand.presenceFlag(args, "--cancel") || o.selfSigned || o.deleteType != null);
        o.diagnostics = ClientCommand.presenceFlag(args, "--transaction-diagnostics");
        return o;
    }

    static String dateTime(Object v) {
        if (!(v instanceof DateTime)) return null;
        DateTime d = (DateTime) v;
        return d.getUtcTime() <= 0 ? null : d.getJavaInstant().toString();
    }

    /** One TransactionErrorType entry (TargetId, Error, Message). */
    static Map<String, Object> transactionError(OpcUaClient client, Object e) {
        NodeId target = null;
        StatusCode error = null;
        LocalizedText message = null;
        if (e instanceof ExtensionObject) {
            try {
                e = ((ExtensionObject) e).decode(client.getStaticEncodingContext());
            } catch (RuntimeException ignored) {
                // left undecoded
            }
        }
        if (e instanceof TransactionErrorType) {
            TransactionErrorType t = (TransactionErrorType) e;
            target = t.getTargetId();
            error = t.getError();
            message = t.getMessage();
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("targetId", target == null ? null : ResultBuilder.nodeIdToString(target));
        m.put("error", ResultBuilder.statusCodeJson(error == null ? new StatusCode(StatusCodes.Bad_DecodingError) : error));
        m.put("message", message == null ? null : message.getText());
        return m;
    }

    /** The six TransactionDiagnostics variables in one Read: the status and the object (null if a Bad status). */
    static Map.Entry<StatusCode, Map<String, Object>> readTransactionDiagnostics(OpcUaClient client) {
        List<NodeId> ids = new ArrayList<>();
        for (int i : TRANSACTION_DIAGNOSTICS) ids.add(new NodeId(0, uint(i)));
        List<DataValue> dvs;
        try {
            dvs = client.readValues(0, TimestampsToReturn.Neither, ids);
        } catch (UaException e) {
            return new AbstractMap.SimpleEntry<>(e.getStatusCode(), null);
        }
        if (dvs.size() != ids.size()) return new AbstractMap.SimpleEntry<>(new StatusCode(StatusCodes.Bad_UnexpectedError), null);
        Object[] vals = new Object[dvs.size()];
        for (int i = 0; i < dvs.size(); i++) {
            DataValue dv = dvs.get(i);
            if (dv.getStatusCode() != null && !dv.getStatusCode().isGood()) {
                return new AbstractMap.SimpleEntry<>(dv.getStatusCode(), null);
            }
            vals[i] = dv.getValue().getValue();
        }
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("startTime", dateTime(vals[0]));
        d.put("endTime", dateTime(vals[1]));
        d.put("result", ResultBuilder.statusCodeJson(vals[2] instanceof StatusCode ? (StatusCode) vals[2] : StatusCode.GOOD));
        d.put("affectedTrustLists", nodeIdList(vals[3]));
        d.put("affectedCertificateGroups", nodeIdList(vals[4]));
        List<Object> errors = new ArrayList<>();
        if (vals[5] instanceof Object[]) {
            for (Object e : (Object[]) vals[5]) errors.add(transactionError(client, e));
        }
        d.put("errors", errors);
        return new AbstractMap.SimpleEntry<>(StatusCode.GOOD, d);
    }

    static int cmdPush(String[] args) throws Exception {
        String endpointUrl = ClientCommand.findArg(args, "--endpoint");
        if (endpointUrl == null) throw new ClientCommand.InputException("missing --endpoint");
        PushOptions o = parsePush(args);
        long rto = ClientCommand.requestTimeoutMs(args);
        OpcUaClient client = ClientCommand.connectClient(endpointUrl, ClientCommand.connectTimeoutMs(args), rto, args);
        try {
            return runPush(client, o, rto);
        } finally {
            ClientCommand.safeDisconnect(client, ClientCommand.disconnectTimeoutMs(args));
        }
    }

    /** The steps of §1 "push flags" on one session (one transaction, Part 12 §7.10.2). */
    static int runPush(OpcUaClient client, PushOptions o, long rto) throws Exception {
        Map<String, Object> item = new LinkedHashMap<>();
        ResultBuilder rb = new ResultBuilder("push");
        NodeId sc = SERVER_CONFIGURATION;
        NodeId groupId = NodeIdParser.resolveWithClient(o.groupId, client, rto);
        NodeId typeId = NodeIdParser.resolveWithClient(o.certificateTypeId, client, rto);
        NodeId deleteType = o.deleteType == null ? null : NodeIdParser.resolveWithClient(o.deleteType, client, rto);
        item.put("certificateGroupId", ResultBuilder.nodeIdToString(groupId));

        NodeId trustList;
        try {
            trustList = child(client, groupId, "TrustList");
            item.put("trustList", trustListJson(readTrustList(client, trustList, TRUST_LIST_MASKS_ALL)));
        } catch (StepFailed e) {
            rb.addResult(item).serviceResult(e.status).error("service", "reading the TrustList of " + o.groupId + ": " + e.getMessage());
            System.out.println(rb.toJson());
            return 4;
        }

        StatusCode[] failed = {null};
        String[] failedStep = {null};
        java.util.function.BiPredicate<String, StatusCode> step = (name, status) -> {
            item.put(name + "Status", ResultBuilder.statusCodeJson(status));
            if (status.isGood()) return true;
            failed[0] = status;
            failedStep[0] = name;
            return false;
        };

        Variant trusted = new Variant(!o.issuer);
        boolean ok = true;
        try {
            if (o.add != null) {
                ok = step.test("addCertificate", call(client, trustList, child(client, trustList, "AddCertificate"),
                    new Variant(ByteString.of(o.add)), trusted).status());
            }
            if (ok && o.remove != null) {
                ok = step.test("removeCertificate", call(client, trustList, child(client, trustList, "RemoveCertificate"),
                    new Variant(o.remove), trusted).status());
            }
            if (ok && o.getCertificates) {
                CallResult r = call(client, sc, SC_GET_CERTIFICATES, new Variant(groupId));
                ok = step.test("getCertificates", r.status());
                if (ok) {
                    item.put("certificateTypeIds", nodeIdList(out(r.outputs(), 0)));
                    item.put("certificates", b64List(out(r.outputs(), 1)));
                }
            }
            if (ok && o.selfSigned) {
                CallResult r = call(client, sc, SC_CREATE_SELF_SIGNED,
                    new Variant(groupId), new Variant(typeId), new Variant(o.subject),
                    new Variant(o.dns.toArray(new String[0])), new Variant(o.ip.toArray(new String[0])),
                    new Variant(ushort(o.lifetimeDays)), new Variant(ushort(o.keySize)));
                ok = step.test("createSelfSignedCertificate", r.status());
                if (ok) {
                    Object c = out(r.outputs(), 0);
                    item.put("selfSignedCertificate", b64(c instanceof ByteString ? (ByteString) c : null));
                }
            }
            if (ok && deleteType != null) {
                ok = step.test("deleteCertificate",
                    call(client, sc, SC_DELETE_CERTIFICATE, new Variant(groupId), new Variant(deleteType)).status());
            }
            if (ok && o.update != null) {
                ByteString[] issuers = o.issuers.stream().map(ByteString::of).toArray(ByteString[]::new);
                CallResult r = call(client, sc, SC_UPDATE_CERTIFICATE,
                    new Variant(groupId), new Variant(typeId), new Variant(ByteString.of(o.update)),
                    new Variant(issuers), new Variant(o.keyFormat),
                    new Variant(o.key == null ? ByteString.NULL_VALUE : ByteString.of(o.key)));
                ok = step.test("updateCertificate", r.status());
                if (ok) item.put("applyChangesRequired", Boolean.TRUE.equals(out(r.outputs(), 0)));
            }
            if (ok && o.csr) {
                CallResult r = call(client, sc, SC_CREATE_SIGNING_REQUEST,
                    new Variant(groupId), new Variant(typeId), new Variant(""), new Variant(false),
                    new Variant(ByteString.NULL_VALUE));
                ok = step.test("createSigningRequest", r.status());
                if (ok) {
                    Object c = out(r.outputs(), 0);
                    item.put("certificateSigningRequest", b64(c instanceof ByteString ? (ByteString) c : null));
                }
            }
            if (ok) {
                CallResult r = call(client, sc, SC_GET_REJECTED_LIST);
                ok = step.test("getRejectedList", r.status());
                if (ok) item.put("rejectedCertificates", b64List(out(r.outputs(), 0)));
            }
            if (ok && o.reset) {
                ok = step.test("resetToServerDefaults", call(client, sc, SC_RESET_TO_SERVER_DEFAULTS).status());
            }
            boolean applied = false;
            if (ok && o.apply) {
                ok = step.test("applyChanges", call(client, sc, SC_APPLY_CHANGES).status());
                applied = true;
            }
            if (ok && o.cancel) {
                ok = step.test("cancelChanges", call(client, sc, SC_CANCEL_CHANGES).status());
            }
            // The diagnostics explain a failed ApplyChanges too: read them also then.
            if (o.diagnostics && (ok || applied)) {
                Map.Entry<StatusCode, Map<String, Object>> d = readTransactionDiagnostics(client);
                item.put("transactionDiagnosticsStatus", ResultBuilder.statusCodeJson(d.getKey()));
                if (d.getValue() != null) item.put("transactionDiagnostics", d.getValue());
                if (ok && !d.getKey().isGood()) {
                    failed[0] = d.getKey();
                    failedStep[0] = "reading TransactionDiagnostics";
                    ok = false;
                }
            }
            if (ok) {
                item.put("trustListAfter", trustListJson(readTrustList(client, trustList, TRUST_LIST_MASKS_ALL)));
            }
        } catch (StepFailed e) {
            failed[0] = e.status;
            failedStep[0] = e.getMessage();
            ok = false;
        }
        rb.addResult(item);
        if (!ok) {
            rb.serviceResult(failed[0]).error("service", failedStep[0] + " returned a non-Good status");
        }
        System.out.println(rb.toJson());
        return ok ? 0 : 4;
    }

    // ── client gds-pull ───────────────────────────────────────────────────────

    static final String GDS_NAMESPACE_URI = "http://opcfoundation.org/UA/GDS/";
    static final int GDS_DIRECTORY = 141;
    static final int GDS_DEFAULT_APPLICATION_GROUP = 615;
    static final int GDS_APPLICATION_RECORD_BINARY = 134;
    static final Map<String, Integer> GDS_METHODS = Map.ofEntries(
        Map.entry("FindApplications", 143),
        Map.entry("RegisterApplication", 146),
        Map.entry("UnregisterApplication", 149),
        Map.entry("StartNewKeyPairRequest", 154),
        Map.entry("StartSigningRequest", 157),
        Map.entry("FinishRequest", 163),
        Map.entry("CheckRevocationStatus", 177),
        Map.entry("GetTrustList", 204),
        Map.entry("GetCertificateStatus", 225),
        Map.entry("GetCertificateGroups", 508),
        Map.entry("RevokeCertificate", 15005));
    static final Map<String, Integer> APP_TYPES = Map.of("Server", 0, "Client", 1, "ClientAndServer", 2);
    static final Map<String, Integer> CERTIFICATE_TYPES = Map.of("RsaSha256", 12560, "NistP256", 23538);
    static final String GDS_PRODUCT_URI = "urn:opcua-interop:milo";

    static final class GdsPullOptions {
        String appUri;
        String appType;
        List<String> discoveryUrls;
        String request;
        String certificateType;
        boolean revoke;
        boolean unregister;
        long finishTimeoutMs;

        String appName() { return appName(appUri); }

        /** The last {@code :} / {@code /} segment of the app uri (§16.2 step 2). */
        static String appName(String uri) {
            String s = uri.replaceAll("[/:]+$", "");
            String[] parts = s.split("[:/]");
            String last = s.isEmpty() || parts.length == 0 ? "" : parts[parts.length - 1];
            return last.isEmpty() ? "opcua-interop gds-pull app" : last;
        }
    }

    static GdsPullOptions parseGdsPull(String[] args) throws ClientCommand.InputException {
        GdsPullOptions o = new GdsPullOptions();
        o.appUri = Optional.ofNullable(ClientCommand.findArg(args, "--app-uri")).orElse("urn:opcua-interop:gds-pull:app");
        o.appType = Optional.ofNullable(ClientCommand.findArg(args, "--app-type")).orElse("Server");
        o.discoveryUrls = ClientCommand.findAllArgs(args, "--discovery-url");
        if (o.discoveryUrls.isEmpty()) o.discoveryUrls = List.of("opc.tcp://localhost:4850");
        o.request = Optional.ofNullable(ClientCommand.findArg(args, "--request")).orElse("csr");
        o.certificateType = Optional.ofNullable(ClientCommand.findArg(args, "--certificate-type")).orElse("RsaSha256");
        o.revoke = ClientCommand.presenceFlag(args, "--revoke");
        o.unregister = ClientCommand.presenceFlag(args, "--unregister");
        String ft = ClientCommand.findArg(args, "--finish-timeout-ms");
        o.finishTimeoutMs = 30000;
        if (ft != null) {
            try {
                o.finishTimeoutMs = Long.parseLong(ft);
            } catch (NumberFormatException e) {
                o.finishTimeoutMs = -1;
            }
            if (o.finishTimeoutMs < 0) throw new ClientCommand.InputException("invalid --finish-timeout-ms " + ft);
        }
        if (o.appUri.isEmpty()) throw new ClientCommand.InputException("empty --app-uri");
        if (!APP_TYPES.containsKey(o.appType)) {
            throw new ClientCommand.InputException("invalid --app-type " + o.appType + " (Server, Client, ClientAndServer)");
        }
        if (!o.request.equals("csr") && !o.request.equals("new-key-pair")) {
            throw new ClientCommand.InputException("invalid --request " + o.request + " (csr, new-key-pair)");
        }
        if (!CERTIFICATE_TYPES.containsKey(o.certificateType)) {
            throw new ClientCommand.InputException("invalid --certificate-type " + o.certificateType + " (RsaSha256, NistP256)");
        }
        return o;
    }

    /**
     * ApplicationRecordDataType (Part 12 §6.6.4) in the binary encoding, with a null ApplicationId
     * (RegisterApplication assigns it). Milo 1.1.8 does not define the GDS types.
     */
    static ExtensionObject encodeApplicationRecord(EncodingContext ctx, int ns, GdsPullOptions o) {
        boolean client = o.appType.equals("Client");
        ByteBuf buf = Unpooled.buffer();
        OpcUaBinaryEncoder enc = new OpcUaBinaryEncoder(ctx).setBuffer(buf);
        enc.encodeNodeId(NodeId.NULL_VALUE);
        enc.encodeString(o.appUri);
        enc.encodeInt32(APP_TYPES.get(o.appType));
        enc.encodeArray(new LocalizedText[]{new LocalizedText("en-US", o.appName())}, enc::encodeLocalizedText);
        enc.encodeString(GDS_PRODUCT_URI);
        enc.encodeArray(client ? new String[0] : o.discoveryUrls.toArray(new String[0]), enc::encodeString);
        enc.encodeArray(client ? new String[0] : new String[]{"NA"}, enc::encodeString);
        byte[] body = new byte[buf.readableBytes()];
        buf.readBytes(body);
        return ExtensionObject.of(ByteString.of(body), new NodeId(ns, uint(GDS_APPLICATION_RECORD_BINARY)));
    }

    /** The ApplicationId (the first field) of an ApplicationRecordDataType. */
    static NodeId applicationRecordId(EncodingContext ctx, Object eo) {
        if (eo instanceof ExtensionObject && ((ExtensionObject) eo).getBody() instanceof ByteString) {
            byte[] body = ((ByteString) ((ExtensionObject) eo).getBody()).bytesOrEmpty();
            return new OpcUaBinaryDecoder(ctx).setBuffer(Unpooled.wrappedBuffer(body)).decodeNodeId();
        }
        return NodeId.NULL_VALUE;
    }

    /**
     * A PKCS #10 request with a fresh RSA 2048 / ECC P-256 key: subject CN=&lt;name&gt;, URI SAN =
     * app uri, DNS SAN localhost, SHA-256.
     */
    static byte[] makeCsr(GdsPullOptions o) throws Exception {
        boolean ecc = o.certificateType.equals("NistP256");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ecc ? "EC" : "RSA");
        if (ecc) kpg.initialize(new ECGenParameterSpec("secp256r1"));
        else kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        ExtensionsGenerator ext = new ExtensionsGenerator();
        ext.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
            new GeneralName(GeneralName.uniformResourceIdentifier, o.appUri),
            new GeneralName(GeneralName.dNSName, "localhost")}));
        int usage = KeyUsage.digitalSignature | KeyUsage.nonRepudiation;
        if (!ecc) usage |= KeyUsage.keyEncipherment | KeyUsage.dataEncipherment;
        ext.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        // The CN is set as an attribute value, so a name with ',' or '=' stays one RDN.
        X500Name subject = new org.bouncycastle.asn1.x500.X500NameBuilder()
            .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, o.appName()).build();
        return new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic())
            .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate())
            .build(new JcaContentSignerBuilder(ecc ? "SHA256withECDSA" : "SHA256withRSA").build(kp.getPrivate()))
            .getEncoded();
    }

    static int cmdGdsPull(String[] args) throws Exception {
        String endpointUrl = ClientCommand.findArg(args, "--endpoint");
        if (endpointUrl == null) throw new ClientCommand.InputException("missing --endpoint");
        GdsPullOptions o = parseGdsPull(args);
        long rto = ClientCommand.requestTimeoutMs(args);
        OpcUaClient client = ClientCommand.connectClient(endpointUrl, ClientCommand.connectTimeoutMs(args), rto, args);
        try {
            return runGdsPull(client, o);
        } finally {
            ClientCommand.safeDisconnect(client, ClientCommand.disconnectTimeoutMs(args));
        }
    }

    /** The pull-model steps of §16.2 against the Directory of a GDS. */
    static int runGdsPull(OpcUaClient client, GdsPullOptions o) throws Exception {
        ResultBuilder rb = new ResultBuilder("gds-pull");
        UShort nsIdx = client.readNamespaceTable().getIndex(GDS_NAMESPACE_URI);
        if (nsIdx == null) {
            System.out.println(rb.serviceResult(StatusCodes.Bad_NodeIdUnknown)
                .error("service", "the server has no GDS namespace " + GDS_NAMESPACE_URI).toJson());
            return 4;
        }
        int ns = nsIdx.intValue();
        EncodingContext ctx = client.getStaticEncodingContext();
        NodeId directory = new NodeId(ns, uint(GDS_DIRECTORY));
        NodeId groupId = new NodeId(ns, uint(GDS_DEFAULT_APPLICATION_GROUP));
        NodeId certType = new NodeId(0, uint(CERTIFICATE_TYPES.get(o.certificateType)));
        Map<String, Object> item = new LinkedHashMap<>();

        // One GDS method; the status goes to statusKey (removed again on Good when keepGood is false).
        interface Gds { Variant[] call(String method, String statusKey, boolean keepGood, Variant... in) throws StepFailed; }
        Gds gds = (method, statusKey, keepGood, in) -> {
            CallResult r = call(client, directory, new NodeId(ns, uint(GDS_METHODS.get(method))), in);
            if (!r.status().isGood() || keepGood) item.put(statusKey, ResultBuilder.statusCodeJson(r.status()));
            if (!r.status().isGood()) throw new StepFailed(method, r.status());
            return r.outputs();
        };

        try {
            // 1. FindApplications
            Variant[] found = gds.call("FindApplications", "findApplicationsStatus", false, new Variant(o.appUri));
            List<NodeId> ids = new ArrayList<>();
            if (out(found, 0) instanceof Object[]) {
                for (Object e : (Object[]) out(found, 0)) ids.add(applicationRecordId(ctx, e));
            }
            List<String> idStrs = new ArrayList<>();
            for (NodeId n : ids) idStrs.add(ResultBuilder.nodeIdToString(n));
            item.put("findApplications", idStrs);
            // 2. RegisterApplication
            NodeId appId;
            if (!ids.isEmpty()) {
                appId = ids.get(0);
                item.put("registered", false);
            } else {
                Variant[] r = gds.call("RegisterApplication", "registerStatus", true,
                    new Variant(encodeApplicationRecord(ctx, ns, o)));
                appId = (NodeId) out(r, 0);
                item.put("registered", true);
            }
            item.put("applicationId", ResultBuilder.nodeIdToString(appId));
            // 3. StartSigningRequest / StartNewKeyPairRequest
            item.put("requestKind", o.request);
            Variant[] r;
            if (o.request.equals("csr")) {
                r = gds.call("StartSigningRequest", "startRequestStatus", true,
                    new Variant(appId), new Variant(groupId), new Variant(certType), new Variant(ByteString.of(makeCsr(o))));
            } else {
                r = gds.call("StartNewKeyPairRequest", "startRequestStatus", true,
                    new Variant(appId), new Variant(groupId), new Variant(certType),
                    new Variant("CN=" + o.appName()), new Variant(new String[]{"localhost"}),
                    new Variant("PEM"), new Variant(""));
            }
            NodeId requestId = (NodeId) out(r, 0);
            item.put("requestId", ResultBuilder.nodeIdToString(requestId));
            // 4. FinishRequest until it issues (Bad_NothingToDo = pending)
            long deadline = System.nanoTime() + o.finishTimeoutMs * 1_000_000L;
            NodeId finishId = new NodeId(ns, uint(GDS_METHODS.get("FinishRequest")));
            CallResult fr;
            while (true) {
                fr = call(client, directory, finishId, new Variant(appId), new Variant(requestId));
                if ((fr.status().getValue() & 0xFFFF0000L) == BAD_NOTHING_TO_DO && System.nanoTime() < deadline) {
                    Thread.sleep(200);
                    continue;
                }
                break;
            }
            item.put("finishRequestStatus", ResultBuilder.statusCodeJson(fr.status()));
            if (!fr.status().isGood()) throw new StepFailed("FinishRequest", fr.status());
            Object cert = out(fr.outputs(), 0);
            ByteString certificate = cert instanceof ByteString ? (ByteString) cert : null;
            item.put("certificate", certificate == null ? null : b64(certificate));
            if (o.request.equals("new-key-pair")) {
                Object key = out(fr.outputs(), 1);
                item.put("privateKeyFormat", "PEM");
                item.put("privateKey", key instanceof ByteString ? b64((ByteString) key) : null);
            }
            item.put("issuerCertificates", b64List(out(fr.outputs(), 2)));
            // 5. GetCertificateGroups
            r = gds.call("GetCertificateGroups", "getCertificateGroupsStatus", false, new Variant(appId));
            item.put("certificateGroups", nodeIdList(out(r, 0)));
            // 6. GetTrustList + the TrustList (Open Read, Read, Close)
            r = gds.call("GetTrustList", "getTrustListStatus", false, new Variant(appId), new Variant(groupId));
            NodeId trustListId = (NodeId) out(r, 0);
            item.put("trustListId", ResultBuilder.nodeIdToString(trustListId));
            try {
                item.put("trustList", trustListJson(readTrustList(client, trustListId, null)));
            } catch (StepFailed e) {
                item.put("readTrustListStatus", ResultBuilder.statusCodeJson(e.status));
                throw e;
            }
            // 7. GetCertificateStatus
            r = gds.call("GetCertificateStatus", "getCertificateStatusStatus", true,
                new Variant(appId), new Variant(groupId), new Variant(certType));
            item.put("updateRequired", Boolean.TRUE.equals(out(r, 0)));
            // 8. RevokeCertificate, CheckRevocationStatus
            if (o.revoke) {
                ByteString c = certificate == null ? ByteString.NULL_VALUE : certificate;
                gds.call("RevokeCertificate", "revokeStatus", true, new Variant(appId), new Variant(c));
                r = gds.call("CheckRevocationStatus", "checkRevocationStatus", true, new Variant(c));
                Object st = out(r, 0);
                item.put("certificateStatus", ResultBuilder.statusCodeJson(st instanceof StatusCode ? (StatusCode) st : StatusCode.GOOD));
            }
            // 9. UnregisterApplication
            if (o.unregister) {
                gds.call("UnregisterApplication", "unregisterStatus", true, new Variant(appId));
            }
        } catch (StepFailed e) {
            System.out.println(rb.addResult(item).serviceResult(e.status).error("service", e.getMessage()).toJson());
            return 4;
        }
        System.out.println(rb.addResult(item).toJson());
        return 0;
    }
}
