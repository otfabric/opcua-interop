package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.*;

public class CapabilitiesCommand {

    public static void run() throws Exception {
        Map<String, Object> adapter = new LinkedHashMap<>();
        adapter.put("name",    "milo");
        adapter.put("version", "0.5.0-rc.1");

        Map<String, Object> stack = new LinkedHashMap<>();
        stack.put("name",    "eclipse-milo");
        stack.put("version", getMiloVersion());

        List<Map<String, String>> secProfiles = new ArrayList<>();
        for (String[] entry : new String[][]{
                {"None",                  "None"},
                {"Basic256Sha256",        "Sign"},
                {"Basic256Sha256",        "SignAndEncrypt"},
                {"Aes128_Sha256_RsaOaep", "SignAndEncrypt"},
                {"Aes256_Sha256_RsaPss",  "SignAndEncrypt"},
        }) {
            Map<String, String> sp = new LinkedHashMap<>();
            sp.put("policy", entry[0]);
            sp.put("mode",   entry[1]);
            secProfiles.add(sp);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schemaVersion",         "1.0");
        out.put("adapter",               adapter);
        out.put("stack",                 stack);
        out.put("fixtureSchemaVersions", Collections.singletonList("1.0"));
        out.put("roles",                 Arrays.asList("client", "server"));
        out.put("transports",            Collections.singletonList("opc.tcp"));
        out.put("encodings",             Collections.singletonList("binary"));
        out.put("clientOperations",      Arrays.asList("endpoints", "read", "write", "browse", "call", "subscribe", "subscription-lifecycle", "event-subscribe", "history-read", "republish", "transfer-subscriptions"));
        out.put("serverServices",        Arrays.asList(
                "GetEndpoints", "Browse", "Read", "Write", "Call",
                "CreateSubscription", "CreateMonitoredItems", "Publish",
                "SetPublishingMode", "SetMonitoringMode",
                "DeleteMonitoredItems", "DeleteSubscriptions"));
        out.put("securityProfiles",      secProfiles);
        out.put("userTokenTypes",        Arrays.asList("Anonymous", "UserName"));

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
        return "1.1.5";
    }
}
