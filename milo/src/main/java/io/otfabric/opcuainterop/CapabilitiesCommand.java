package io.otfabric.opcuainterop;

public class CapabilitiesCommand {

    public static void run() {
        System.out.println("""
                {
                  "adapter": "milo",
                  "stack": "eclipse-milo",
                  "version": "0.6.12",
                  "fixture": "baseline",
                  "operations": {
                    "server": ["read", "write", "browse", "methods", "behaviors"],
                    "client": ["endpoints", "read", "write", "browse"]
                  }
                }""");
    }
}
