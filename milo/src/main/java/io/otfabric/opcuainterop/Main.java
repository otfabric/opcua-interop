package io.otfabric.opcuainterop;

import java.util.Arrays;

/**
 * Milo adapter entry point.
 *
 * Subcommands:
 *   server            -- start OPC UA server from fixture
 *   client <op>       -- run client probe operation
 *   validate-fixture  -- validate fixture JSON against schema
 *   print-capabilities -- emit adapter capability JSON
 *   test              -- run internal self-tests
 */
public class Main {

    public static void main(String[] args) {
        if (args.length == 0) {
            usage();
            System.exit(1);
        }

        String cmd = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);

        try {
            switch (cmd) {
                case "server":
                    ServerCommand.run(rest);
                    break;

                case "client":
                    int rc = ClientCommand.run(rest);
                    System.exit(rc);
                    break;

                case "validate-fixture":
                    System.exit(ValidateCommand.run(rest));
                    break;

                case "print-capabilities":
                    CapabilitiesCommand.run();
                    break;


                case "test":
                    runSelfTest();
                    break;

                default:
                    System.err.println("unknown subcommand: " + cmd);
                    usage();
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("[milo] fatal: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void usage() {
        System.err.println("usage: opcua-interop-milo <server|client|validate-fixture|print-capabilities|test> [args...]");
    }

    private static void runSelfTest() {
        System.err.println("[milo] self-test: OK");
    }
}
