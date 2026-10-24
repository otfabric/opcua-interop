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
 *   --ecc-dir <path>             ECC certificates (<path>/ecc-<curve>/cert.crt|cert.key)
 *   --reverse-connect <url>      dial a client and send ReverseHello (repeatable)
 *   --lds                        act as Local Discovery Server (with mDNS)
 *   --mdns-name <name>           announce via mDNS under this name
 *   --register-with <lds-url>    register with a Local Discovery Server
 *   --pubsub-config <file>       OPC UA PubSub configuration (JSON, see pubsub_server.c)
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

/* PubSub (Part 14). See docs/CLIENT_CONTRACT.md §14 for what each entry
 * means and the open62541 v1.5.9 limits behind the lists. */
static void print_pubsub_capabilities(void) {
    printf("  \"pubsub\": {\n");
    printf("    \"supported\": true,\n");
    printf("    \"serverFlag\": \"--pubsub-config\",\n");
    printf("    \"roles\": [\"publisher\", \"subscriber\"],\n");
    printf("    \"transports\": [\"udp-uadp\", \"mqtt-uadp\", \"mqtt-json\"],\n");
    printf("    \"transportProfiles\": [\n");
    printf("      \"http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp\",\n");
    printf("      \"http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp\",\n");
    printf("      \"http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json\"\n");
    printf("    ],\n");
    printf("    \"udp\": {\"unicast\": true, \"multicast\": true},\n");
    printf("    \"encodings\": [\"uadp\", \"json\"],\n");
    printf("    \"fieldEncodings\": [\"Variant\", \"DataValue\", \"RawData\"],\n");
    printf("    \"dataSetMessageTypes\": {\"uadp\": [\"KeyFrame\", \"DeltaFrame\", \"KeepAlive\"], \"json\": [\"KeyFrame\"]},\n");
    printf("    \"publishedDataSets\": [\"PublishedDataItems\"],\n");
    printf("    \"subscribedDataSets\": [\"TargetVariables\"],\n");
    printf("    \"securityPolicies\": [\n");
    printf("      \"http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR\",\n");
    printf("      \"http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR\"\n");
    printf("    ],\n");
    printf("    \"securityModes\": [\"None\", \"Sign\", \"SignAndEncrypt\"],\n");
    printf("    \"securityEncodings\": [\"uadp\"],\n");
    printf("    \"keySources\": [\"static\", \"sks-pull\", \"sks-push\", \"sks-server\"],\n");
    printf("    \"sks\": {\"server\": true, \"pull\": true, \"push\": true,\n");
    printf("            \"methods\": [\"GetSecurityKeys\", \"SetSecurityKeys\", \"AddSecurityGroup\", \"RemoveSecurityGroup\"]},\n");
    printf("    \"informationModel\": true,\n");
    printf("    \"informationModelMethods\": [\n");
    printf("      \"AddConnection\", \"RemoveConnection\", \"AddWriterGroup\", \"AddReaderGroup\", \"RemoveGroup\",\n");
    printf("      \"AddDataSetWriter\", \"RemoveDataSetWriter\", \"AddDataSetReader\", \"RemoveDataSetReader\",\n");
    printf("      \"AddPublishedDataItems\", \"RemovePublishedDataSet\", \"AddDataSetFolder\", \"RemoveDataSetFolder\",\n");
    printf("      \"ReserveIds\", \"Enable\", \"Disable\",\n");
    printf("      \"GetSecurityKeys\", \"SetSecurityKeys\", \"AddSecurityGroup\", \"RemoveSecurityGroup\"\n");
    printf("    ],\n");
    printf("    \"codecOps\": [\"pubsub-uadp-encode\", \"pubsub-uadp-decode\", \"pubsub-json-encode\", \"pubsub-json-decode\"],\n");
    printf("    \"codecSecurity\": false\n");
    printf("  },\n");
}

static int cmd_print_capabilities(void) {
    printf("{\n");
    printf("  \"schemaVersion\": \"1.0\",\n");
    printf("  \"adapter\": {\"name\": \"open62541\", \"version\": \"0.9.0\"},\n");
    printf("  \"stack\": {\"name\": \"open62541\", \"version\": \"1.5.9\"},\n");
    printf("  \"fixtureSchemaVersions\": [\"1.0\"],\n");
    printf("  \"roles\": [\"client\", \"server\"],\n");
    printf("  \"transports\": [\"opc.tcp\"],\n");
    printf("  \"encodings\": [\"binary\"],\n");
    printf("  \"clientOperations\": [\n");
    printf("    \"endpoints\",\n");
    printf("    \"find-servers\",\n");
    printf("    \"read\",\n");
    printf("    \"write\",\n");
    printf("    \"browse\",\n");
    printf("    \"translate\",\n");
    printf("    \"call\",\n");
    printf("    \"subscribe\",\n");
    printf("    \"subscription-lifecycle\",\n");
    printf("    \"event-subscribe\",\n");
    printf("    \"history-read\",\n");
    printf("    \"republish\",\n");
    printf("    \"transfer-subscriptions\",\n");
    printf("    \"register-nodes\",\n");
    printf("    \"node-management\",\n");
    printf("    \"find-servers-on-network\",\n");
    printf("    \"register-server\",\n");
    printf("    \"codec\"\n");
    printf("  ],\n");
    printf("  \"clientFeatures\": [\n");
    printf("    \"channel-lifetime\",\n");
    printf("    \"deadband\",\n");
    printf("    \"reverse-listen\",\n");
    printf("    \"ecc-security\",\n");
    printf("    \"ecc-user-token\",\n");
    printf("    \"application-uri\",\n");
    printf("    \"register-server2\",\n");
    printf("    \"codec-json\",\n");
    printf("    \"codec-xml\",\n");
    printf("    \"codec-pubsub\"\n");
    printf("  ],\n");
    printf("  \"serverFeatures\": [\n");
    printf("    \"deadband\",\n");
    printf("    \"percent-deadband\",\n");
    printf("    \"reverse-connect\",\n");
    printf("    \"ecc-security\",\n");
    printf("    \"ecc-user-token\",\n");
    printf("    \"lds\",\n");
    printf("    \"mdns\",\n");
    printf("    \"register-with\",\n");
    printf("    \"node-management\",\n");
    printf("    \"pubsub\"\n");
    printf("  ],\n");
    printf("  \"codec\": {\n");
    printf("    \"formats\": [\"json\", \"xml\"],\n");
    printf("    \"jsonVersion\": \"1.05\",\n");
    printf("    \"jsonModes\": [\"compact\"],\n");
    printf("    \"xmlEncodeUnsupported\": [\"DataValue\", \"DiagnosticInfo\", \"Matrix\"],\n");
    printf("    \"xmlDecodeUnsupported\": [\"DataValue\", \"DiagnosticInfo\", \"XmlElement\"]\n");
    printf("  },\n");
    print_pubsub_capabilities();
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
    printf("    \"DeleteSubscriptions\",\n");
    printf("    \"HistoryRead\",\n");
    printf("    \"Republish\",\n");
    printf("    \"TransferSubscriptions\",\n");
    printf("    \"FindServers\",\n");
    printf("    \"FindServersOnNetwork\",\n");
    printf("    \"RegisterServer\",\n");
    printf("    \"RegisterServer2\"\n");
    printf("  ],\n");
    printf("  \"securityProfiles\": [\n");
    printf("    {\"policy\": \"None\",                  \"mode\": \"None\"},\n");
    printf("    {\"policy\": \"Basic256Sha256\",        \"mode\": \"Sign\"},\n");
    printf("    {\"policy\": \"Basic256Sha256\",        \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"Aes128_Sha256_RsaOaep\", \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"Aes256_Sha256_RsaPss\",  \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_nistP256\",            \"mode\": \"Sign\"},\n");
    printf("    {\"policy\": \"ECC_nistP256\",            \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_nistP384\",            \"mode\": \"Sign\"},\n");
    printf("    {\"policy\": \"ECC_nistP384\",            \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_brainpoolP256r1\",     \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_brainpoolP384r1\",     \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_curve25519\",          \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_curve448\",            \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_nistP256_AesGcm\",     \"mode\": \"SignAndEncrypt\"},\n");
    printf("    {\"policy\": \"ECC_nistP256_ChaChaPoly\", \"mode\": \"SignAndEncrypt\"}\n");
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
