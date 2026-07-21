package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.*;

public class CapabilitiesCommand {

    public static void run() throws Exception {
        Map<String, Object> adapter = new LinkedHashMap<>();
        adapter.put("name",    "milo");
        adapter.put("version", "0.1.0");

        Map<String, Object> stack = new LinkedHashMap<>();
        stack.put("name",    "eclipse-milo");
        stack.put("version", getMiloVersion());

        Map<String, Object> secProfile = new LinkedHashMap<>();
        secProfile.put("policy", "None");
        secProfile.put("mode",   "None");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schemaVersion",         "1.0");
        out.put("adapter",               adapter);
        out.put("stack",                 stack);
        out.put("fixtureSchemaVersions", Collections.singletonList("1.0"));
        out.put("roles",                 Arrays.asList("client", "server"));
        out.put("transports",            Collections.singletonList("opc.tcp"));
        out.put("encodings",             Collections.singletonList("binary"));
        out.put("clientOperations",      Arrays.asList("endpoints", "read", "write", "browse"));
        out.put("serverServices",        Arrays.asList(
                "GetEndpoints", "Browse", "Read", "Write", "Call",
                "CreateSubscription", "CreateMonitoredItems", "Publish"));
        out.put("securityProfiles",      Collections.singletonList(secProfile));
        out.put("userTokenTypes",        Collections.singletonList("Anonymous"));

        System.out.println(new ObjectMapper().writeValueAsString(out));
    }

    private static String getMiloVersion() {
        try {
            InputStream is = CapabilitiesCommand.class.getResourceAsStream(
                    "/META-INF/maven/org.eclipse.milo/sdk-server/pom.properties");
            if (is != null) {
                Properties p = new Properties();
                p.load(is);
                String v = p.getProperty("version");
                if (v != null && !v.isEmpty()) return v;
            }
        } catch (Exception ignored) {
            // fall through to default
        }
        return "0.6.12";
    }
}
