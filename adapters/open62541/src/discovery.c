/*
 * Discovery service set commands that target a Local Discovery Server:
 *
 *   find-servers-on-network  FindServersOnNetwork (mDNS records of an LDS-ME)
 *   register-server          RegisterServer2 / RegisterServer for an arbitrary
 *                            RegisteredServer description (register or
 *                            unregister), so a consumer's LDS can be tested.
 *
 * Both run on a SecureChannel without a Session.
 */

#include "client_internal.h"
#include "output.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void __UA_Client_Service(UA_Client *client, const void *request,
                         const UA_DataType *requestType, void *response,
                         const UA_DataType *responseType);

#define MAX_REPEAT 32

static int collect(int argc, char **argv, const char *flag, const char **out, int max) {
    int n = 0;
    for (int i = 0; i < argc - 1 && n < max; i++)
        if (strcmp(argv[i], flag) == 0) out[n++] = argv[i + 1];
    return n;
}

static int request_ms(int argc, char **argv) {
    const char *v = cli_find_arg(argc, argv, "--request-timeout");
    int s = v ? atoi(v) : 5;
    return (s > 0 ? s : 5) * 1000;
}

static void print_ua_string(const UA_String *s) {
    output_json_string_len(s->data, s->length);
}

/* -------------------------------------------------------------------------
 * find-servers-on-network
 * ---------------------------------------------------------------------- */

int cmd_find_servers_on_network(int argc, char **argv) {
    static const char *op = "find-servers-on-network";
    const char *endpoint = cli_find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input", "missing --endpoint");
        return 2;
    }
    const char *startStr = cli_find_arg(argc, argv, "--starting-record-id");
    const char *maxStr   = cli_find_arg(argc, argv, "--max-records");
    const char *caps[MAX_REPEAT];
    int capCount = collect(argc, argv, "--capability", caps, MAX_REPEAT);

    int exit_code = 3;
    UA_Client *client = cli_make_channel_client(endpoint, request_ms(argc, argv), op, &exit_code);
    if (!client) return exit_code;

    UA_FindServersOnNetworkRequest req;
    UA_FindServersOnNetworkRequest_init(&req);
    req.startingRecordId   = startStr ? (UA_UInt32)strtoul(startStr, NULL, 10) : 0;
    req.maxRecordsToReturn = maxStr ? (UA_UInt32)strtoul(maxStr, NULL, 10) : 0;
    UA_String capStrs[MAX_REPEAT];
    for (int i = 0; i < capCount; i++)
        capStrs[i] = UA_STRING((char *)(uintptr_t)caps[i]);
    req.serverCapabilityFilter     = capCount ? capStrs : NULL;
    req.serverCapabilityFilterSize = (size_t)capCount;

    UA_FindServersOnNetworkResponse resp;
    UA_FindServersOnNetworkResponse_init(&resp);
    __UA_Client_Service(client, &req, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKREQUEST],
                        &resp, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKRESPONSE]);
    UA_StatusCode sc = resp.responseHeader.serviceResult;
    int ok = UA_StatusCode_isGood(sc);

    output_begin("open62541", op);
    output_success(ok);
    output_service_result(sc);
    if (ok) {
        char resetBuf[64];
        output_timestamp(resp.lastCounterResetTime, resetBuf, sizeof(resetBuf));
        output_open_results();
        for (size_t i = 0; i < resp.serversSize; i++) {
            const UA_ServerOnNetwork *s = &resp.servers[i];
            if (i > 0) printf(",");
            printf("{\"recordId\":%" PRIu32 ",\"serverName\":", (uint32_t)s->recordId);
            print_ua_string(&s->serverName);
            printf(",\"discoveryUrl\":");
            print_ua_string(&s->discoveryUrl);
            printf(",\"serverCapabilities\":[");
            for (size_t j = 0; j < s->serverCapabilitiesSize; j++) {
                if (j > 0) printf(",");
                print_ua_string(&s->serverCapabilities[j]);
            }
            printf("]");
            if (resetBuf[0]) printf(",\"lastCounterResetTime\":\"%s\"", resetBuf);
            printf("}");
        }
        output_close_results();
        output_null_error();
    } else {
        output_error("service", "FindServersOnNetwork failed");
    }
    output_end();

    UA_FindServersOnNetworkResponse_clear(&resp);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * register-server
 * ---------------------------------------------------------------------- */

static int parse_app_type(const char *s, UA_ApplicationType *out) {
    if (!s || strcmp(s, "Server") == 0)        { *out = UA_APPLICATIONTYPE_SERVER; return 0; }
    if (strcmp(s, "Client") == 0)              { *out = UA_APPLICATIONTYPE_CLIENT; return 0; }
    if (strcmp(s, "ClientAndServer") == 0)     { *out = UA_APPLICATIONTYPE_CLIENTANDSERVER; return 0; }
    if (strcmp(s, "DiscoveryServer") == 0)     { *out = UA_APPLICATIONTYPE_DISCOVERYSERVER; return 0; }
    return -1;
}

int cmd_register_server(int argc, char **argv) {
    static const char *op = "register-server";
    const char *endpoint  = cli_find_arg(argc, argv, "--endpoint");
    const char *serverUri = cli_find_arg(argc, argv, "--server-uri");
    const char *urls[MAX_REPEAT];
    int urlCount = collect(argc, argv, "--discovery-url", urls, MAX_REPEAT);
    if (!endpoint || !serverUri || urlCount == 0) {
        cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input",
            "usage: register-server --endpoint <lds-url> --server-uri <uri>"
            " --discovery-url <url> [--discovery-url ...] [--server-name <text>]"
            " [--product-uri <uri>] [--server-type Server|Client|ClientAndServer|DiscoveryServer]"
            " [--online true|false] [--service auto|RegisterServer2|RegisterServer]"
            " [--mdns-name <name>] [--capability <cap> ...]");
        return 2;
    }
    const char *productUri = cli_find_arg(argc, argv, "--product-uri");
    const char *name       = cli_find_arg(argc, argv, "--server-name");
    const char *nameLocale = cli_find_arg(argc, argv, "--server-name-locale");
    const char *gateway    = cli_find_arg(argc, argv, "--gateway-server-uri");
    const char *semaphore  = cli_find_arg(argc, argv, "--semaphore-file");
    const char *onlineStr  = cli_find_arg(argc, argv, "--online");
    const char *service    = cli_find_arg(argc, argv, "--service");
    const char *mdnsName   = cli_find_arg(argc, argv, "--mdns-name");
    const char *typeStr    = cli_find_arg(argc, argv, "--server-type");
    const char *caps[MAX_REPEAT];
    int capCount = collect(argc, argv, "--capability", caps, MAX_REPEAT);

    if (!name) name = serverUri;
    if (!nameLocale) nameLocale = "en";
    if (!service) service = "auto";
    int want2 = (strcmp(service, "auto") == 0 || strcmp(service, "RegisterServer2") == 0);
    int want1 = (strcmp(service, "auto") == 0 || strcmp(service, "RegisterServer") == 0);
    UA_ApplicationType appType = UA_APPLICATIONTYPE_SERVER;
    if ((!want1 && !want2) || parse_app_type(typeStr, &appType) != 0) {
        cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input",
                         "invalid --service or --server-type");
        return 2;
    }
    UA_Boolean online = !(onlineStr && strcmp(onlineStr, "false") == 0);

    int exit_code = 3;
    UA_Client *client = cli_make_channel_client(endpoint, request_ms(argc, argv), op, &exit_code);
    if (!client) return exit_code;

    /* RegisteredServer (borrowed strings; nothing here is freed) */
    UA_RegisteredServer rs;
    UA_RegisteredServer_init(&rs);
    rs.serverUri  = UA_STRING((char *)(uintptr_t)serverUri);
    rs.productUri = UA_STRING((char *)(uintptr_t)(productUri ? productUri : ""));
    UA_LocalizedText lt = UA_LOCALIZEDTEXT((char *)(uintptr_t)nameLocale, (char *)(uintptr_t)name);
    rs.serverNames = &lt;
    rs.serverNamesSize = 1;
    rs.serverType = appType;
    if (gateway)   rs.gatewayServerUri  = UA_STRING((char *)(uintptr_t)gateway);
    if (semaphore) rs.semaphoreFilePath = UA_STRING((char *)(uintptr_t)semaphore);
    UA_String urlStrs[MAX_REPEAT];
    for (int i = 0; i < urlCount; i++)
        urlStrs[i] = UA_STRING((char *)(uintptr_t)urls[i]);
    rs.discoveryUrls = urlStrs;
    rs.discoveryUrlsSize = (size_t)urlCount;
    rs.isOnline = online;

    UA_StatusCode sc2 = UA_STATUSCODE_GOOD;   /* RegisterServer2 result, if tried */
    UA_StatusCode sc  = UA_STATUSCODE_GOOD;   /* result of the service that counts */
    const char *used = NULL;
    int fellBack = 0;
    UA_RegisterServer2Response resp2;
    UA_RegisterServer2Response_init(&resp2);

    if (want2) {
        UA_MdnsDiscoveryConfiguration mdns;
        UA_MdnsDiscoveryConfiguration_init(&mdns);
        mdns.mdnsServerName = UA_STRING((char *)(uintptr_t)(mdnsName ? mdnsName : name));
        UA_String capStrs[MAX_REPEAT];
        for (int i = 0; i < capCount; i++)
            capStrs[i] = UA_STRING((char *)(uintptr_t)caps[i]);
        mdns.serverCapabilities = capCount ? capStrs : NULL;
        mdns.serverCapabilitiesSize = (size_t)capCount;

        UA_ExtensionObject cfgObj;
        UA_ExtensionObject_init(&cfgObj);
        cfgObj.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
        cfgObj.content.decoded.type = &UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION];
        cfgObj.content.decoded.data = &mdns;

        UA_RegisterServer2Request req2;
        UA_RegisterServer2Request_init(&req2);
        req2.server = rs;
        req2.discoveryConfiguration = &cfgObj;
        req2.discoveryConfigurationSize = 1;
        __UA_Client_Service(client, &req2, &UA_TYPES[UA_TYPES_REGISTERSERVER2REQUEST],
                            &resp2, &UA_TYPES[UA_TYPES_REGISTERSERVER2RESPONSE]);
        sc2 = resp2.responseHeader.serviceResult;
        sc = sc2;
        used = "RegisterServer2";
    }

    /* Part 4 §5.4.6: fall back to RegisterServer when the LDS does not
     * implement RegisterServer2. */
    if (want1 && (!want2 || sc2 == UA_STATUSCODE_BADSERVICEUNSUPPORTED ||
                  sc2 == UA_STATUSCODE_BADNOTIMPLEMENTED ||
                  sc2 == UA_STATUSCODE_BADNOTSUPPORTED)) {
        UA_RegisterServerRequest req1;
        UA_RegisterServerRequest_init(&req1);
        req1.server = rs;
        UA_RegisterServerResponse resp1;
        UA_RegisterServerResponse_init(&resp1);
        __UA_Client_Service(client, &req1, &UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST],
                            &resp1, &UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE]);
        sc = resp1.responseHeader.serviceResult;
        UA_RegisterServerResponse_clear(&resp1);
        fellBack = want2;
        used = "RegisterServer";
    }

    int ok = UA_StatusCode_isGood(sc);
    int useResp2 = (used && strcmp(used, "RegisterServer2") == 0);
    if (ok && useResp2) {
        for (size_t i = 0; i < resp2.configurationResultsSize; i++)
            if (!UA_StatusCode_isGood(resp2.configurationResults[i])) ok = 0;
    }

    output_begin("open62541", op);
    output_success(ok);
    output_service_result(sc);
    output_open_results();
    printf("{\"service\":\"%s\",\"serverUri\":", used ? used : "");
    output_json_string(serverUri);
    printf(",\"isOnline\":%s,", online ? "true" : "false");
    cli_print_status("statusCode", sc);
    printf(",\"fallback\":%s", fellBack ? "true" : "false");
    if (want2) {
        printf(",");
        cli_print_status("registerServer2StatusCode", sc2);
    }
    printf(",\"configurationResults\":[");
    if (useResp2) {
        for (size_t i = 0; i < resp2.configurationResultsSize; i++) {
            UA_StatusCode c = resp2.configurationResults[i];
            if (i > 0) printf(",");
            printf("{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
                   output_status_code_name(c), (uint32_t)c, output_severity(c));
        }
    }
    printf("]}");
    output_close_results();
    if (ok)
        output_null_error();
    else
        printf(",\"error\":{\"category\":\"service\",\"message\":\"%s failed\"}",
               used ? used : "RegisterServer");
    output_end();

    UA_RegisterServer2Response_clear(&resp2);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}
