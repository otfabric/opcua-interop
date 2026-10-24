package io.otfabric.opcuainterop;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.util.*;

public class CapabilitiesCommand {

    public static void run() throws Exception {
        Map<String, Object> adapter = new LinkedHashMap<>();
        adapter.put("name",    "milo");
        adapter.put("version", "0.10.1");

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
        out.put("clientOperations",      Arrays.asList(
                "endpoints", "find-servers", "read", "write", "browse", "translate",
                "call", "subscribe", "subscription-lifecycle", "event-subscribe",
                "history-read", "republish", "transfer-subscriptions",
                "register-nodes", "node-management",
                "find-servers-on-network", "register-server", "codec"));
        // What this adapter can do beyond the plain operations. Eclipse Milo
        // 1.1.8 has no reverse connect (no ReverseHello in its transports), no
        // ECC security policies, and its server answers RegisterServer(2) /
        // FindServersOnNetwork with Bad_ServiceUnsupported: none of those is listed.
        out.put("clientFeatures",        Arrays.asList(
                "channel-lifetime", "deadband", "register-server2",
                "codec-json", "codec-xml", "codec-json-verbose"));
        out.put("serverFeatures",        Arrays.asList(
                "deadband", "percent-deadband", "register-with"));
        Map<String, Object> codec = new LinkedHashMap<>();
        codec.put("formats",     Arrays.asList("json", "xml"));
        codec.put("jsonVersion", "1.05");
        codec.put("jsonModes",   Arrays.asList("compact", "verbose"));
        codec.put("xmlEncodeUnsupported", Collections.emptyList());
        codec.put("xmlDecodeUnsupported", Collections.emptyList());
        out.put("codec", codec);
        // PubSub (OPC UA Part 14): Eclipse Milo 1.1.8 ships only the generated
        // PubSub DataTypes and ObjectType/Method stubs (stack-core
        // types.structured.*, sdk-server model.objects.*); there is no
        // NetworkMessage (UADP / JSON) encoder, no UDP / MQTT transport, no
        // PublishSubscribe runtime and no Security Key Service. Declared
        // explicitly so consumers can record "not implemented by Milo".
        Map<String, Object> pubsub = new LinkedHashMap<>();
        pubsub.put("supported",        false);
        pubsub.put("reason",           "Eclipse Milo 1.1.8 has no PubSub (Part 14) implementation");
        pubsub.put("transports",       Collections.emptyList());
        pubsub.put("encodings",        Collections.emptyList());
        pubsub.put("roles",            Collections.emptyList());
        pubsub.put("securityPolicies", Collections.emptyList());
        Map<String, Object> sks = new LinkedHashMap<>();
        sks.put("server", false);
        sks.put("pull",   false);
        sks.put("push",   false);
        pubsub.put("sks",              sks);
        pubsub.put("informationModel", false);
        pubsub.put("codecOps",         Collections.emptyList());
        out.put("pubsub", pubsub);
        out.put("serverServices",        Arrays.asList(
                "GetEndpoints", "Browse", "Read", "Write", "Call",
                "CreateSubscription", "CreateMonitoredItems", "Publish",
                "SetPublishingMode", "SetMonitoringMode",
                "DeleteMonitoredItems", "DeleteSubscriptions",
                "HistoryRead", "FindServers"));
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
        return "1.1.8";
    }
}
