/*
 * open62541 adapter entry point.
 *
 * Subcommands:
 *   server              -- start OPC UA server from fixture
 *   client <op>         -- run client probe operation
 *   validate-fixture    -- validate fixture JSON, print OK or error
 *   print-capabilities  -- emit adapter capability JSON
 *   test                -- run internal fixture parser unit tests
 *
 * Server flags:
 *   --fixture <path>
 *   --bind-address <host>        (default: 0.0.0.0)
 *   --bind-port <n>              (default: from fixture)
 *   --advertised-host <host>     (default: localhost)
 *   --advertised-port <n>        (default: bind port)
 *   --endpoint-path <path>       (default: from fixture)
 *   --pki-dir <path>
 *   --ready-file <path>
 *
 * Client exit codes:
 *   0  success
 *   2  invalid argument / malformed NodeId
 *   3  transport / connect failure
 *   4  OPC UA service failure
 *   5  fixture validation failure
 *   6  internal adapter failure
 *   7  timeout
 *
 * Environment equivalents:
 *   OPCUA_FIXTURE, OPCUA_PORT, OPCUA_ENDPOINT_PATH, OPCUA_LOG_LEVEL,
 *   OPCUA_PKI_DIR, OPCUA_TRUST_MODE, OPCUA_READY_FILE,
 *   OPCUA_BIND_ADDRESS, OPCUA_ADVERTISED_HOST
 */

#include "client.h"
#include "fixture.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * print-capabilities
 * ---------------------------------------------------------------------- */

static int cmd_print_capabilities(void) {
    printf("{\n");
    printf("  \"schemaVersion\": \"1.0\",\n");
    printf("  \"adapter\": {\"name\": \"open62541\", \"version\": \"0.4.0\"},\n");
    printf("  \"stack\": {\"name\": \"open62541\", \"version\": \"1.5.5\"},\n");
    printf("  \"fixtureSchemaVersions\": [\"1.0\"],\n");
    printf("  \"roles\": [\"client\", \"server\"],\n");
    printf("  \"transports\": [\"opc.tcp\"],\n");
    printf("  \"encodings\": [\"binary\"],\n");
    printf("  \"clientOperations\": [\n");
    printf("    \"endpoints\",\n");
    printf("    \"read\",\n");
    printf("    \"write\",\n");
    printf("    \"browse\",\n");
    printf("    \"call\",\n");
    printf("    \"subscribe\",\n");
    printf("    \"subscription-lifecycle\"\n");
    printf("  ],\n");
    printf("  \"serverServices\": [\n");
    printf("    \"GetEndpoints\",\n");
    printf("    \"CreateSession\",\n");
    printf("    \"Browse\",\n");
    printf("    \"Read\",\n");
    printf("    \"Write\",\n");
    printf("    \"Call\",\n");
    printf("    \"CreateSubscription\",\n");
    printf("    \"CreateMonitoredItems\",\n");
    printf("    \"Publish\",\n");
    printf("    \"SetPublishingMode\",\n");
    printf("    \"SetMonitoringMode\",\n");
    printf("    \"DeleteMonitoredItems\",\n");
    printf("    \"DeleteSubscriptions\"\n");
    printf("  ],\n");
    printf("  \"securityProfiles\": [\n");
    printf("    {\"policy\": \"None\",                  \"mode\": \"None\"},\n");
    printf("    {\"policy\": \"Basic256Sha256\",        \"mode\": \"Sign\"},\n");
    printf("    {\"policy\": \"Basic256Sha256\",        \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"Aes128_Sha256_RsaOaep\", \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"Aes256_Sha256_RsaPss\",  \"mode\": \"SignAndEncrypt\"}\n");
    printf("  ],\n");
    printf("  \"userTokenTypes\": [\"Anonymous\", \"UserName\"]\n");
    printf("}\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * validate-fixture
 * ---------------------------------------------------------------------- */

static int cmd_validate_fixture(int argc, char **argv) {
    const char *path = NULL;

    /* Accept --fixture <path> or positional */
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], "--fixture") == 0) {
            path = argv[i + 1];
            break;
        }
    }
    if (!path) {
        path = getenv("OPCUA_FIXTURE");
    }
    if (!path || !*path) {
        fprintf(stderr, "validate-fixture: no fixture path given"
                " (use --fixture or OPCUA_FIXTURE)\n");
        return 1;
    }

    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    if (!f) {
        fprintf(stderr, "INVALID: %s\n", errBuf);
        return 1;
    }
    printf("OK id=%s nodes=%zu behaviors=%zu\n",
           f->id ? f->id : "(null)",
           f->nodeCount, f->behaviorCount);
    fixture_free(f);
    return 0;
}

/* -------------------------------------------------------------------------
 * test — internal fixture parser smoke tests
 * ---------------------------------------------------------------------- */

static int cmd_test(int argc, char **argv) {
    /* Forward to the fixture_test main if linked, otherwise print skip. */
    (void)argc; (void)argv;
    fprintf(stderr, "test: use the separate fixture_test binary for unit tests\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: opcua-interop-open62541 <server|client|validate-fixture"
            "|print-capabilities|test> [args...]\n");
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "server") == 0) {
        ServerArgs args;
        char errBuf[512];
        if (server_parse_args(argc - 1, argv + 1, &args, errBuf, sizeof(errBuf)) != 0) {
            fprintf(stderr, "server: %s\n", errBuf);
            return 2;
        }
        return server_run(&args);
    }

    if (strcmp(cmd, "client") == 0) {
        return client_run(argc - 1, argv + 1);
    }

    if (strcmp(cmd, "validate-fixture") == 0) {
        return cmd_validate_fixture(argc - 2, argv + 2);
    }

    if (strcmp(cmd, "print-capabilities") == 0) {
        return cmd_print_capabilities();
    }

    if (strcmp(cmd, "test") == 0) {
        return cmd_test(argc - 2, argv + 2);
    }

    fprintf(stderr, "unknown subcommand: %s\n", cmd);
    return 1;
}
