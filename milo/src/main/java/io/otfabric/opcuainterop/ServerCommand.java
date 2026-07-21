package io.otfabric.opcuainterop;

import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.server.EndpointConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

public class ServerCommand {

    private static final Logger LOG = LoggerFactory.getLogger(ServerCommand.class);

    public static void run(String[] args) throws Exception {
        String fixturePath = getenv("OPCUA_FIXTURE", null);
        String endpointUrl = null;
        String readyFile   = getenv("OPCUA_READY_FILE", "/run/opcua-interop/ready");

        for (int i = 0; i < args.length - 1; i++) {
            switch (args[i]) {
                case "--fixture":    fixturePath = args[i + 1]; break;
                case "--endpoint":   endpointUrl = args[i + 1]; break;
                case "--ready-file": readyFile   = args[i + 1]; break;
            }
        }

        if (fixturePath == null) {
            System.err.println("[milo] error: missing --fixture");
            System.exit(1);
        }

        FixtureModel fixture = FixtureLoader.load(fixturePath);
        LOG.info("Fixture loaded: id={}", fixture.id);

        int port = fixture.endpoint.port;
        String path = fixture.endpoint.path != null ? fixture.endpoint.path : "/";

        // Override port from endpoint URL if provided
        if (endpointUrl != null) {
            try {
                int lastColon = endpointUrl.lastIndexOf(':');
                if (lastColon >= 0) {
                    String portStr = endpointUrl.substring(lastColon + 1).split("/")[0];
                    int p = Integer.parseInt(portStr);
                    if (p > 0) port = p;
                }
            } catch (NumberFormatException ignored) { }
        }

        String hostname = resolveHostname();

        EndpointConfiguration endpoint = EndpointConfiguration.newBuilder()
                .setBindAddress("0.0.0.0")
                .setBindPort(port)
                .setHostname(hostname)
                .setPath(path)
                .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                .setSecurityPolicy(SecurityPolicy.None)
                .setSecurityMode(MessageSecurityMode.None)
                .addTokenPolicy(OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS)
                .build();

        Set<EndpointConfiguration> endpoints = new LinkedHashSet<>();
        endpoints.add(endpoint);

        BuildInfo buildInfo = new BuildInfo(
                fixture.server.productUri,
                "OTFabric",
                "opcua-interop-milo",
                "0.1.0",
                "0.6.12",
                DateTime.now());

        OpcUaServerConfig config = OpcUaServerConfig.builder()
                .setApplicationUri(fixture.server.applicationUri)
                .setApplicationName(LocalizedText.english(fixture.server.applicationName))
                .setProductUri(fixture.server.productUri)
                .setEndpoints(endpoints)
                .setBuildInfo(buildInfo)
                .setIdentityValidator(AnonymousIdentityValidator.INSTANCE)
                .build();

        OpcUaServer server = new OpcUaServer(config);

        InteropNamespace namespace = new InteropNamespace(server, fixture);
        namespace.startup();

        server.startup().get();
        LOG.info("Server started on port={}", port);

        writeReadyFile(readyFile);

        CountDownLatch latch = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.info("Shutdown signal received");
            try {
                server.shutdown().get();
            } catch (Exception e) {
                LOG.error("Error during shutdown", e);
            } finally {
                latch.countDown();
            }
        }));

        latch.await();
    }

    private static void writeReadyFile(String path) {
        if (path == null || path.isEmpty()) return;
        try {
            Path p = Paths.get(path);
            Files.createDirectories(p.getParent());
            Files.writeString(p, "ready\n");
            LOG.info("Ready file written: {}", path);
        } catch (IOException e) {
            LOG.warn("Cannot write ready file {}: {}", path, e.getMessage());
        }
    }

    private static String resolveHostname() {
        String h = System.getenv("HOSTNAME");
        if (h != null && !h.isEmpty()) return h;
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "localhost";
        }
    }

    private static String getenv(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.isEmpty()) ? v : fallback;
    }
}
