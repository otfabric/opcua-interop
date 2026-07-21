package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.stack.core.security.DefaultApplicationGroup;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultServerCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.FileBasedCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.FileBasedTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.KeyStoreCertificateStore;
import org.eclipse.milo.opcua.stack.core.security.RsaSha256CertificateFactory;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

public class ServerCommand {

    private static final Logger LOG = LoggerFactory.getLogger(ServerCommand.class);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void run(String[] args) throws Exception {
        String fixturePath    = getenv("OPCUA_FIXTURE", null);
        String bindAddress    = "0.0.0.0";
        int    bindPort       = -1;
        String advertisedHost = "localhost";
        int    advertisedPort = -1;
        String endpointPath   = null;
        String readyFile      = getenv("OPCUA_READY_FILE", "/run/opcua-interop/ready");
        String pkiDir         = "/run/opcua-interop/pki";
        String certFile       = null;
        String keyFile        = null;
        boolean readyFileExplicit = false;

        for (int i = 0; i < args.length - 1; i++) {
            switch (args[i]) {
                case "--fixture":          fixturePath    = args[i + 1]; break;
                case "--bind-address":     bindAddress    = args[i + 1]; break;
                case "--bind-port":        bindPort       = Integer.parseInt(args[i + 1]); break;
                case "--advertised-host":  advertisedHost = args[i + 1]; break;
                case "--advertised-port":  advertisedPort = Integer.parseInt(args[i + 1]); break;
                case "--endpoint-path":    endpointPath   = args[i + 1]; break;
                case "--ready-file":       readyFile = args[i + 1]; readyFileExplicit = true; break;
                case "--pki-dir":          pkiDir = args[i + 1]; break;
                case "--certificate":      certFile = args[i + 1]; break;
                case "--private-key":      keyFile  = args[i + 1]; break;
            }
        }

        if (fixturePath == null) {
            System.err.println("[milo] error: missing --fixture");
            System.exit(1);
        }

        FixtureModel fixture = FixtureLoader.load(fixturePath);
        LOG.info("Fixture loaded: id={}", fixture.id);

        if (bindPort < 0)       bindPort       = fixture.endpoint.port;
        if (advertisedPort < 0) advertisedPort = bindPort;
        if (endpointPath == null) endpointPath = fixture.endpoint.path != null ? fixture.endpoint.path : "/";

        String advertisedEndpoint = "opc.tcp://" + advertisedHost + ":" + advertisedPort + endpointPath;
        LOG.info("Advertised endpoint: {}", advertisedEndpoint);
        LOG.debug("PKI dir: {}", pkiDir);

        /* ── Certificate + key ─────────────────────────────────────────── */
        X509Certificate serverCert = null;
        KeyPair         serverKeyPair = null;
        if (certFile != null && keyFile != null) {
            try {
                serverCert    = loadCertificate(certFile);
                serverKeyPair = new KeyPair(serverCert.getPublicKey(), loadPrivateKey(keyFile));
                LOG.info("Server certificate loaded from {}", certFile);
            } catch (Exception e) {
                LOG.error("FATAL: cannot load server certificate or key: {}", e.getMessage());
                System.exit(6);
            }
        }

        /* ── Certificate manager (new Milo API) ────────────────────────── */
        Path pkiPath = Paths.get(
                (pkiDir != null && !pkiDir.isEmpty()) ? pkiDir : "/run/opcua-interop/pki");

        DefaultCertificateManager certManager;
        String applicationUri = fixture.server.applicationUri;

        if (serverCert != null && serverKeyPair != null) {
            // Build an in-memory PKCS12 keystore from the loaded PEM cert/key
            Path tempSecDir = Files.createTempDirectory("milo-server-security-");
            Path pfxPath = tempSecDir.resolve("server.pfx");
            try (OutputStream os = Files.newOutputStream(pfxPath)) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, "password".toCharArray());
                ks.setKeyEntry("1", serverKeyPair.getPrivate(), "password".toCharArray(),
                        new X509Certificate[]{serverCert});
                ks.store(os, "password".toCharArray());
            }

            Files.createDirectories(pkiPath.resolve("trusted/certs"));
            Files.createDirectories(pkiPath.resolve("trusted/crl"));
            Files.createDirectories(pkiPath.resolve("issuers/certs"));
            Files.createDirectories(pkiPath.resolve("rejected/certs"));

            var certStore = KeyStoreCertificateStore.createAndInitialize(
                    new KeyStoreCertificateStore.Settings(
                            pfxPath,
                            () -> "password".toCharArray(),
                            alias -> "password".toCharArray()));

            var trustListMgr = FileBasedTrustListManager.createAndInitialize(pkiPath);
            var quarantine    = FileBasedCertificateQuarantine.create(pkiPath.resolve("rejected/certs"));

            final X509Certificate fCert     = serverCert;
            final KeyPair         fKeyPair  = serverKeyPair;
            var certFactory = new RsaSha256CertificateFactory() {
                @Override
                protected KeyPair createRsaSha256KeyPair() { return fKeyPair; }
                @Override
                protected X509Certificate[] createRsaSha256CertificateChain(KeyPair kp) {
                    return new X509Certificate[]{fCert};
                }
            };

            var certValidator = new DefaultServerCertificateValidator(trustListMgr, quarantine);
            var appGroup = DefaultApplicationGroup.createAndInitialize(
                    trustListMgr, certStore, certFactory, certValidator);
            certManager = new DefaultCertificateManager(quarantine, appGroup);

            // Application URI must match the cert's SAN URI
            String certUri = CertificateUtil.getSanUri(serverCert).orElse(null);
            if (certUri != null && !certUri.isEmpty()) {
                applicationUri = certUri;
            }
        } else {
            certManager = null;
        }

        /* ── Endpoints ──────────────────────────────────────────────────── */
        Set<EndpointConfig> endpointSet = new LinkedHashSet<>();
        EndpointConfig.Builder baseBuilder = EndpointConfig.newBuilder()
                .setBindAddress(bindAddress)
                .setBindPort(bindPort)
                .setHostname(advertisedHost)
                .setPath(endpointPath)
                .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                .addTokenPolicy(OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS);

        // When users are defined, also offer username auth on the None/None endpoint.
        // Per OPC UA Part 4 §5.6.3.1: empty securityPolicyUri means no password
        // encryption, which is acceptable for non-production test-only endpoints.
        // WARNING: passwords are transmitted in plain text over an unencrypted channel;
        // never enable this pattern in production deployments.
        if (!fixture.users.isEmpty()) {
            UserTokenPolicy usernameNonePolicy = new UserTokenPolicy(
                    "username_none",
                    UserTokenType.UserName,
                    null, null, null);
            baseBuilder.addTokenPolicy(usernameNonePolicy);
        }

        // Always add None/None endpoint
        endpointSet.add(baseBuilder
                .setSecurityPolicy(SecurityPolicy.None)
                .setSecurityMode(MessageSecurityMode.None)
                .build());

        // Add secure endpoints when server has a cert and fixture lists non-None profiles
        if (serverCert != null && !fixture.securityProfiles.isEmpty()) {
            EndpointConfig.Builder secBuilder = EndpointConfig.newBuilder()
                    .setBindAddress(bindAddress)
                    .setBindPort(bindPort)
                    .setHostname(advertisedHost)
                    .setPath(endpointPath)
                    .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                    .setCertificate(serverCert)
                    .addTokenPolicy(OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS);

            // Add Username token policy if fixture has users
            if (!fixture.users.isEmpty()) {
                secBuilder.addTokenPolicy(OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME);
            }

            for (FixtureModel.SecurityProfileDef sp : fixture.securityProfiles) {
                if ("None".equals(sp.securityPolicy) && "None".equals(sp.securityMode)) continue; // already added
                try {
                    SecurityPolicy        policy = toMiloSecurityPolicy(sp.securityPolicy);
                    MessageSecurityMode   mode   = toMiloSecurityMode(sp.securityMode);
                    endpointSet.add(secBuilder
                            .setSecurityPolicy(policy)
                            .setSecurityMode(mode)
                            .build());
                    LOG.info("Registered secure endpoint: policy={} mode={}", sp.securityPolicy, sp.securityMode);
                } catch (IllegalArgumentException e) {
                    LOG.warn("Skipping unknown security profile {}/{}: {}", sp.securityPolicy, sp.securityMode, e.getMessage());
                }
            }
        }

        /* ── Identity validator ─────────────────────────────────────────── */
        List<FixtureModel.UserCredentialDef> users = fixture.users;
        org.eclipse.milo.opcua.sdk.server.identity.IdentityValidator identityValidator;
        if (users.isEmpty()) {
            identityValidator = AnonymousIdentityValidator.INSTANCE;
        } else {
            UsernameIdentityValidator usernameValidator =
                    new UsernameIdentityValidator(authChallenge -> {
                        String user = authChallenge.getUsername();
                        String pass = authChallenge.getPassword();
                        for (FixtureModel.UserCredentialDef u : users) {
                            if (u.username != null && u.username.equals(user) &&
                                    (u.password == null ? "" : u.password).equals(pass)) {
                                return true;
                            }
                        }
                        return false;
                    });
            identityValidator = new CompositeValidator(AnonymousIdentityValidator.INSTANCE,
                                                       usernameValidator);
        }

        BuildInfo buildInfo = new BuildInfo(
                fixture.server.productUri,
                "OTFabric",
                "opcua-interop-milo",
                "0.1.1",
                "1.1.5",
                DateTime.now());

        var serverConfigBuilder = OpcUaServerConfig.builder()
                .setApplicationUri(applicationUri)
                .setApplicationName(LocalizedText.english(fixture.server.applicationName))
                .setProductUri(fixture.server.productUri)
                .setEndpoints(endpointSet)
                .setBuildInfo(buildInfo)
                .setIdentityValidator(identityValidator);

        if (certManager != null) {
            serverConfigBuilder.setCertificateManager(certManager);
        }

        OpcUaServerConfig config = serverConfigBuilder.build();

        OpcUaServer server = new OpcUaServer(config, transportProfile -> {
            OpcTcpServerTransportConfig transportConfig =
                    OpcTcpServerTransportConfig.newBuilder().build();
            return new OpcTcpServerTransport(transportConfig);
        });

        InteropNamespace namespace = new InteropNamespace(server, fixture);
        namespace.startup();

        server.startup().get();
        LOG.info("Server started on port={}", bindPort);

        try {
            writeReadyFile(readyFile, fixture.id, advertisedEndpoint);
        } catch (IOException e) {
            LOG.error("FATAL: cannot write ready file {}: {}", readyFile, e.getMessage());
            System.exit(6);
        }

        final String finalReadyFile = readyFile;
        CountDownLatch latch = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("Shutdown signal received");
            try {
                server.shutdown().get();
            } catch (Exception e) {
                LOG.error("Error during shutdown", e);
            }
            try {
                Files.deleteIfExists(Paths.get(finalReadyFile));
            } catch (Exception ignored) {
                // best-effort cleanup
            }
            latch.countDown();
            // Override the JVM's signal-derived exit code (128+signum = 143 for SIGTERM).
            // Runtime.halt(0) terminates the JVM with code 0 even when the shutdown was
            // initiated by a signal. System.exit() is a no-op here because shutdown is
            // already in progress; halt() is the only way to force a specific exit code.
            Runtime.getRuntime().halt(0);
        }));

        latch.await();
    }

    private static void writeReadyFile(String path, String fixtureId, String endpoint) throws IOException {
        Path p = Paths.get(path);
        Files.createDirectories(p.getParent());
        Files.deleteIfExists(p);

        Map<String, Object> content = new LinkedHashMap<>();
        content.put("ready",    true);
        content.put("adapter",  "milo");
        content.put("fixture",  fixtureId);
        content.put("endpoint", endpoint);
        String json;
        try {
            json = new ObjectMapper().writeValueAsString(content) + "\n";
        } catch (Exception e) {
            throw new IOException("failed to serialize ready file content: " + e.getMessage(), e);
        }

        Path tmp = p.resolveSibling(p.getFileName() + ".tmp");
        Files.writeString(tmp, json);
        Files.move(tmp, p, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        LOG.info("Ready file written: {}", path);
    }

    private static String getenv(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.isEmpty()) ? v : fallback;
    }

    /** Load an X.509 certificate from a PEM or DER file. */
    private static X509Certificate loadCertificate(String path) throws Exception {
        byte[] raw = Files.readAllBytes(Paths.get(path));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        // PEM: strip headers and base64-decode; DER: use as-is
        String pem = new String(raw).trim();
        if (pem.startsWith("-----")) {
            String b64 = pem
                    .replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");
            raw = Base64.getDecoder().decode(b64);
        }
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(raw));
    }

    /**
     * Load a private key from a PEM (PKCS#1 or PKCS#8) or DER PKCS#8 file.
     * OpenSSL's -nodes flag produces PKCS#1 PEM; we convert via BouncyCastle if present,
     * or fall back to PKCS#8 parsing.
     */
    private static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] raw = Files.readAllBytes(Paths.get(path));
        String pem = new String(raw).trim();

        // Try PKCS#8 PEM
        if (pem.contains("BEGIN PRIVATE KEY")) {
            String b64 = pem
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(b64);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        }

        // PKCS#1 RSA PEM — wrap in PKCS#8 envelope
        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            String b64 = pem
                    .replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replaceAll("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] pkcs1 = Base64.getDecoder().decode(b64);
            // Build a PKCS#8 DER wrapper around the PKCS#1 key
            byte[] pkcs8 = pkcs1ToPkcs8(pkcs1);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        }

        // DER PKCS#8 assumed
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw));
    }

    /**
     * Wrap a PKCS#1 RSA key in a minimal PKCS#8 DER AlgorithmIdentifier + BIT STRING.
     * Structure: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING { pkcs1 } }
     */
    private static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        // rsaEncryption OID: 1.2.840.113549.1.1.1
        byte[] oid = new byte[]{ 0x06, 0x09,
            0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00 };  // NULL
        byte[] alg = encodeSequence(oid);
        byte[] octetStr = encodeTag(0x04, pkcs1);
        byte[] inner = concat(new byte[]{0x02, 0x01, 0x00}, alg, octetStr); // INTEGER 0 + alg + key
        return encodeSequence(inner);
    }

    private static byte[] encodeSequence(byte[] content) {
        return encodeTag(0x30, content);
    }

    private static byte[] encodeTag(int tag, byte[] content) {
        int len = content.length;
        byte[] lenBytes;
        if (len < 128) {
            lenBytes = new byte[]{ (byte)len };
        } else if (len < 256) {
            lenBytes = new byte[]{ (byte)0x81, (byte)len };
        } else {
            lenBytes = new byte[]{ (byte)0x82, (byte)(len >> 8), (byte)(len & 0xff) };
        }
        byte[] result = new byte[1 + lenBytes.length + len];
        result[0] = (byte)tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, len);
        return result;
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] r = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) { System.arraycopy(a, 0, r, pos, a.length); pos += a.length; }
        return r;
    }

    private static SecurityPolicy toMiloSecurityPolicy(String name) {
        if (name == null) return SecurityPolicy.None;
        switch (name) {
            case "Basic128Rsa15":      return SecurityPolicy.Basic128Rsa15;
            case "Basic256":           return SecurityPolicy.Basic256;
            case "Basic256Sha256":     return SecurityPolicy.Basic256Sha256;
            case "Aes128_Sha256_RsaOaep": return SecurityPolicy.Aes128_Sha256_RsaOaep;
            case "Aes256_Sha256_RsaPss":  return SecurityPolicy.Aes256_Sha256_RsaPss;
            default:                   return SecurityPolicy.None;
        }
    }

    private static MessageSecurityMode toMiloSecurityMode(String name) {
        if (name == null) return MessageSecurityMode.None;
        switch (name) {
            case "Sign":            return MessageSecurityMode.Sign;
            case "SignAndEncrypt":  return MessageSecurityMode.SignAndEncrypt;
            default:                return MessageSecurityMode.None;
        }
    }
}
