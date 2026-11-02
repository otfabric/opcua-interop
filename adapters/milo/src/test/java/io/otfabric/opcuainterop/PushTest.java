package io.otfabric.opcuainterop;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryDecoder;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryEncoder;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.structured.TrustListDataType;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.junit.jupiter.api.Assertions.*;

/** client push / gds-pull (docs/CONTAINER_CONTRACT.md §1 "push flags", §16.2): flags and encodings. */
public class PushTest {

    private static final EncodingContext CTX = DefaultEncodingContext.INSTANCE;

    @Test
    void pushDefaultsAndImpliedCancel() throws Exception {
        PushCommand.PushOptions o = PushCommand.parsePush(new String[]{"--endpoint", "opc.tcp://x:1"});
        assertEquals("i=14156", o.groupId);
        assertEquals("i=12560", o.certificateTypeId);
        assertFalse(o.cancel);
        assertEquals(365, o.lifetimeDays);

        o = PushCommand.parsePush(new String[]{"--group", "Https", "--create-self-signed", "--dns", "a", "--dns", "b"});
        assertEquals("i=14088", o.groupId);
        assertEquals("i=12558", o.certificateTypeId);
        assertTrue(o.cancel, "--create-self-signed without --apply implies CancelChanges");
        assertEquals(List.of("a", "b"), o.dns);

        o = PushCommand.parsePush(new String[]{"--group", "UserToken", "--delete-certificate", "i=12560", "--apply"});
        assertEquals("i=15181", o.certificateTypeId);
        assertTrue(o.apply);
        assertFalse(o.cancel);
    }

    @Test
    void pushInputErrors() {
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parsePush(new String[]{"--group", "Foo"}));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parsePush(new String[]{"--key-size", "-1"}));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parsePush(new String[]{"--certificate-type-id", "x=1"}));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parsePush(new String[]{"--add-certificate", "/nonexistent"}));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parsePush(new String[]{"--update-private-key", "/k.pem"}));
    }

    @Test
    void pushPrivateKeyFormat(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        Path key = dir.resolve("new.p12");
        Files.write(key, new byte[]{1, 2, 3});
        // Not a certificate: --update-certificate fails first, so check the key format alone.
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parsePush(new String[]{
            "--update-certificate", key.toString(), "--update-private-key", key.toString()}));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parsePush(new String[]{
            "--private-key-format", "DER", "--update-private-key", key.toString()}));
    }

    @Test
    void trustListDecodesWithBase64Lists() {
        TrustListDataType tl = new TrustListDataType(uint(15),
            new ByteString[]{ByteString.of(new byte[]{1, 2})}, new ByteString[0],
            new ByteString[]{ByteString.of(new byte[]{3})}, null);
        ByteBuf buf = Unpooled.buffer();
        new TrustListDataType.Codec().encodeType(CTX, new OpcUaBinaryEncoder(CTX).setBuffer(buf), tl);
        byte[] bytes = new byte[buf.readableBytes()];
        buf.readBytes(bytes);
        Map<String, Object> m = PushCommand.trustListJson(PushCommand.decodeTrustList(CTX, bytes));
        assertEquals(15L, m.get("specifiedLists"));
        assertEquals(List.of("AQI="), m.get("trustedCertificates"));
        assertEquals(List.of(), m.get("trustedCrls"));
        assertEquals(List.of("Aw=="), m.get("issuerCertificates"));
        assertEquals(List.of(), m.get("issuerCrls"));
    }

    @Test
    void gdsPullFlags() throws Exception {
        PushCommand.GdsPullOptions o = PushCommand.parseGdsPull(new String[0]);
        assertEquals("urn:opcua-interop:gds-pull:app", o.appUri);
        assertEquals("app", o.appName());
        assertEquals(List.of("opc.tcp://localhost:4850"), o.discoveryUrls);
        assertEquals(30000, o.finishTimeoutMs);
        assertEquals("opcua-interop gds-pull app", PushCommand.GdsPullOptions.appName("::"));
        assertEquals("x", PushCommand.GdsPullOptions.appName("urn:a/x/"));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parseGdsPull(new String[]{"--app-type", "Device"}));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parseGdsPull(new String[]{"--certificate-type", "Rsa"}));
        assertThrows(ClientCommand.InputException.class, () -> PushCommand.parseGdsPull(new String[]{"--finish-timeout-ms", "-1"}));
    }

    @Test
    void applicationRecordEncoding() throws Exception {
        PushCommand.GdsPullOptions o = PushCommand.parseGdsPull(new String[]{"--app-uri", "urn:x:milo-client"});
        ExtensionObject eo = PushCommand.encodeApplicationRecord(CTX, 3, o);
        assertEquals(new NodeId(3, uint(134)), eo.getEncodingOrTypeId());
        ByteString body = (ByteString) eo.getBody();
        OpcUaBinaryDecoder d = new OpcUaBinaryDecoder(CTX).setBuffer(Unpooled.wrappedBuffer(body.bytesOrEmpty()));
        assertTrue(d.decodeNodeId().isNull());
        assertEquals("urn:x:milo-client", d.decodeString());
        assertEquals(0, d.decodeInt32());
        assertEquals(1, d.decodeInt32());
        assertEquals("milo-client", d.decodeLocalizedText().getText());
        assertEquals(PushCommand.GDS_PRODUCT_URI, d.decodeString());
        assertEquals(1, d.decodeInt32());
        assertEquals("opc.tcp://localhost:4850", d.decodeString());
        assertEquals(1, d.decodeInt32());
        assertEquals("NA", d.decodeString());

        // The ApplicationId of a record is its first field.
        ByteBuf buf = Unpooled.buffer();
        new OpcUaBinaryEncoder(CTX).setBuffer(buf).encodeNodeId(new NodeId(2, java.util.UUID.fromString("7322e67a-0000-0000-0000-000000000001")));
        byte[] b = new byte[buf.readableBytes()];
        buf.readBytes(b);
        assertEquals("ns=2;g=7322e67a-0000-0000-0000-000000000001", ResultBuilder.nodeIdToString(
            PushCommand.applicationRecordId(CTX, ExtensionObject.of(ByteString.of(b), new NodeId(3, uint(134))))));
    }

    @Test
    void csr() throws Exception {
        for (String type : new String[]{"RsaSha256", "NistP256"}) {
            PushCommand.GdsPullOptions o = PushCommand.parseGdsPull(new String[]{
                "--app-uri", "urn:x:milo-client", "--certificate-type", type});
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(PushCommand.makeCsr(o));
            assertEquals("CN=milo-client", csr.getSubject().toString());
            assertTrue(csr.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                .build(csr.getSubjectPublicKeyInfo())));
            GeneralNames sans = GeneralNames.fromExtensions(csr.getRequestedExtensions(), Extension.subjectAlternativeName);
            assertEquals(GeneralName.uniformResourceIdentifier, sans.getNames()[0].getTagNo());
            assertEquals("urn:x:milo-client", sans.getNames()[0].getName().toString());
        }
    }

    @Test
    void b64IsPlainString() {
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{9}), PushCommand.b64(ByteString.of(new byte[]{9})));
        assertEquals("", PushCommand.b64(ByteString.NULL_VALUE));
    }
}
