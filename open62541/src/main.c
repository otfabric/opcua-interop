/*
 * open62541 adapter entry point.
 *
 * Phase 2 implementation. Accepts subcommands:
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
 *
 * Environment equivalents:
 *   OPCUA_FIXTURE, OPCUA_PORT, OPCUA_ENDPOINT_PATH, OPCUA_LOG_LEVEL,
 *   OPCUA_PKI_DIR, OPCUA_TRUST_MODE
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    fprintf(stderr, "open62541 adapter: Phase 2 not yet implemented\n");
    return 1;
}
