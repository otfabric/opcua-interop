package io.otfabric.opcuacompat;

/**
 * Milo adapter entry point.
 *
 * Phase 3 implementation. Accepts subcommands:
 *   server            -- start OPC UA server from fixture
 *   client <op>       -- run client probe operation
 *   validate-fixture  -- validate fixture against schema
 *   print-capabilities -- emit adapter capability JSON
 *   test              -- run internal unit tests
 *
 * Command-line flags (server):
 *   --fixture <path>
 *   --endpoint <url>
 *   --pki-dir <path>
 *   --ready-file <path>
 */
public class Main {
    public static void main(String[] args) {
        System.err.println("Milo adapter: Phase 3 not yet implemented");
        System.exit(1);
    }
}
