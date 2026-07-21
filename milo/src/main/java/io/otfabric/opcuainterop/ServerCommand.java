package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

public class ServerCommand {

    private static final Logger LOG = LoggerFactory.getLogger(ServerCommand.class);

    public static void run(String[] args) throws Exception {
        String fixturePath    = getenv("OPCUA_FIXTURE", null);
        String bindAddress    = "0.0.0.0";
        int    bindPort       = -1;
        String advertisedHost = "localhost";
        int    advertisedPort = -1;
        String endpointPath   = null;
        String readyFile      = getenv("OPCUA_READY_FILE", "/run/opcua-interop/ready");
        String pkiDir         = "/run/opcua-interop/pki";
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

        Set<EndpointConfig> endpointSet = new LinkedHashSet<>();
        EndpointConfig.Builder builder = EndpointConfig.newBuilder()
                .setBindAddress(bindAddress)
                .setBindPort(bindPort)
                .setHostname(advertisedHost)
                .setPath(endpointPath)
                .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                .addTokenPolicy(OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS);
        endpointSet.add(builder
                .setSecurityPolicy(SecurityPolicy.None)
                .setSecurityMode(MessageSecurityMode.None)
                .build());

        BuildInfo buildInfo = new BuildInfo(
                fixture.server.productUri,
                "OTFabric",
                "opcua-interop-milo",
                "0.1.0",
                "1.1.5",
                DateTime.now());

        OpcUaServerConfig config = OpcUaServerConfig.builder()
                .setApplicationUri(fixture.server.applicationUri)
                .setApplicationName(LocalizedText.english(fixture.server.applicationName))
                .setProductUri(fixture.server.productUri)
                .setEndpoints(endpointSet)
                .setBuildInfo(buildInfo)
                .setIdentityValidator(AnonymousIdentityValidator.INSTANCE)
                .build();

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
}
