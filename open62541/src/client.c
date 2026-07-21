#include "client.h"
#include "output.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <open62541.h>

/* -------------------------------------------------------------------------
 * Shared argument parsing helpers
 * ---------------------------------------------------------------------- */

static const char *find_arg(int argc, char **argv, const char *flag) {
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    }
    return NULL;
}

static int count_flag(int argc, char **argv, const char *flag) {
    int n = 0;
    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], flag) == 0) n++;
    return n;
}

/* -------------------------------------------------------------------------
 * Connect helper — returns a connected client or NULL
 * ---------------------------------------------------------------------- */

static UA_Client *connect_client(const char *endpoint) {
    UA_Client *client = UA_Client_new();
    if (!client) {
        fprintf(stderr, "[open62541] client: out of memory\n");
        return NULL;
    }
    UA_ClientConfig *cfg = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(cfg);

    UA_StatusCode sc = UA_Client_connect(client, endpoint);
    if (sc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[open62541] client: connect to '%s' failed: 0x%08" PRIx32 "\n",
                endpoint, (uint32_t)sc);
        UA_Client_delete(client);
        return NULL;
    }
    return client;
}

/* Parse "nsu=URI;s=name" or "ns=x;s=name" or "i=x" NodeId strings.
 * For nsu= forms the client must already be connected so namespace indices
 * are known; we fall back to ns=1 if we cannot look up. */
static UA_NodeId client_parse_nodeid(UA_Client *client, const char *s) {
    if (!s) return UA_NODEID_NULL;

    if (strncmp(s, "nsu=", 4) == 0) {
        const char *semi = strchr(s + 4, ';');
        if (!semi) return UA_NODEID_NULL;
        size_t uriLen = (size_t)(semi - (s + 4));
        char uri[512];
        if (uriLen >= sizeof(uri)) uriLen = sizeof(uri) - 1;
        memcpy(uri, s + 4, uriLen);
        uri[uriLen] = '\0';
        semi++; /* skip ';' */

        /* Get namespace index from server via NamespaceGetIndex service */
        UA_UInt16 nsIdx = 1;
        {
            UA_String uriStr = UA_STRING(uri);
            UA_UInt32 nsIdx32 = 1;
            UA_StatusCode nsSc = UA_Client_NamespaceGetIndex(
                client, &uriStr, &nsIdx32);
            if (nsSc == UA_STATUSCODE_GOOD) nsIdx = (UA_UInt16)nsIdx32;
        }

        if (strncmp(semi, "s=", 2) == 0)
            return UA_NODEID_STRING(nsIdx, (char*)(semi + 2));
        if (strncmp(semi, "i=", 2) == 0)
            return UA_NODEID_NUMERIC(nsIdx, (UA_UInt32)atoi(semi + 2));
        return UA_NODEID_NULL;
    }

    if (strncmp(s, "ns=", 3) == 0) {
        UA_UInt16 ns = (UA_UInt16)atoi(s + 3);
        const char *semi = strchr(s, ';');
        if (!semi) return UA_NODEID_NULL;
        semi++;
        if (strncmp(semi, "s=", 2) == 0)
            return UA_NODEID_STRING(ns, (char*)(semi + 2));
        if (strncmp(semi, "i=", 2) == 0)
            return UA_NODEID_NUMERIC(ns, (UA_UInt32)atoi(semi + 2));
        return UA_NODEID_NULL;
    }

    if (strncmp(s, "i=", 2) == 0)
        return UA_NODEID_NUMERIC(0, (UA_UInt32)atoi(s + 2));

    return UA_NODEID_NULL;
}

/* Return the dataType name string for a UA_DataType */
static const char *type_name(const UA_DataType *dt) {
    if (!dt) return "Unknown";
    if (dt == &UA_TYPES[UA_TYPES_BOOLEAN])       return "Boolean";
    if (dt == &UA_TYPES[UA_TYPES_SBYTE])         return "SByte";
    if (dt == &UA_TYPES[UA_TYPES_BYTE])          return "Byte";
    if (dt == &UA_TYPES[UA_TYPES_INT16])         return "Int16";
    if (dt == &UA_TYPES[UA_TYPES_UINT16])        return "UInt16";
    if (dt == &UA_TYPES[UA_TYPES_INT32])         return "Int32";
    if (dt == &UA_TYPES[UA_TYPES_UINT32])        return "UInt32";
    if (dt == &UA_TYPES[UA_TYPES_INT64])         return "Int64";
    if (dt == &UA_TYPES[UA_TYPES_UINT64])        return "UInt64";
    if (dt == &UA_TYPES[UA_TYPES_FLOAT])         return "Float";
    if (dt == &UA_TYPES[UA_TYPES_DOUBLE])        return "Double";
    if (dt == &UA_TYPES[UA_TYPES_STRING])        return "String";
    if (dt == &UA_TYPES[UA_TYPES_DATETIME])      return "DateTime";
    if (dt == &UA_TYPES[UA_TYPES_GUID])          return "Guid";
    if (dt == &UA_TYPES[UA_TYPES_BYTESTRING])    return "ByteString";
    if (dt == &UA_TYPES[UA_TYPES_XMLELEMENT])    return "XmlElement";
    if (dt == &UA_TYPES[UA_TYPES_NODEID])        return "NodeId";
    if (dt == &UA_TYPES[UA_TYPES_QUALIFIEDNAME]) return "QualifiedName";
    if (dt == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]) return "LocalizedText";
    if (dt == &UA_TYPES[UA_TYPES_STATUSCODE])    return "StatusCode";
    return dt->typeName ? dt->typeName : "Unknown";
}

/* -------------------------------------------------------------------------
 * endpoints subcommand
 * ---------------------------------------------------------------------- */

static int cmd_endpoints(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        fprintf(stderr, "usage: client endpoints --endpoint <url>\n");
        return 1;
    }

    UA_Client *client = UA_Client_new();
    if (!client) return 2;
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    UA_EndpointDescription *eps = NULL;
    size_t epCount = 0;
    UA_StatusCode sc = UA_Client_getEndpoints(client, endpoint, &epCount, &eps);

    output_begin("endpoints");
    output_success(sc == UA_STATUSCODE_GOOD);
    output_service_result(sc);

    if (sc == UA_STATUSCODE_GOOD) {
        printf(",\"endpoints\":[");
        for (size_t i = 0; i < epCount; i++) {
            if (i > 0) printf(",");
            UA_EndpointDescription *ep = &eps[i];
            char urlBuf[512] = "";
            if (ep->endpointUrl.data && ep->endpointUrl.length < sizeof(urlBuf) - 1) {
                memcpy(urlBuf, ep->endpointUrl.data, ep->endpointUrl.length);
                urlBuf[ep->endpointUrl.length] = '\0';
            }
            printf("{\"endpointUrl\":\"%s\",\"securityMode\":%d",
                   urlBuf, (int)ep->securityMode);
            if (ep->securityPolicyUri.data) {
                printf(",\"securityPolicyUri\":\"%.*s\"",
                       (int)ep->securityPolicyUri.length,
                       ep->securityPolicyUri.data);
            }
            printf("}");
        }
        printf("]");
        UA_Array_delete(eps, epCount, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    }

    output_end();
    UA_Client_delete(client);
    return sc == UA_STATUSCODE_GOOD ? 0 : 3;
}

/* -------------------------------------------------------------------------
 * read subcommand
 * ---------------------------------------------------------------------- */

static int cmd_read(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    if (!endpoint || !nodeStr) {
        fprintf(stderr, "usage: client read --endpoint <url> --node <nodeId>\n");
        return 1;
    }

    UA_Client *client = connect_client(endpoint);
    if (!client) return 2;

    UA_NodeId nodeId = client_parse_nodeid(client, nodeStr);
    UA_DataValue dv  = UA_Client_readValueAttribute(client, nodeId);

    output_begin("read");
    output_success(UA_StatusCode_isGood(dv.status));
    output_service_result(dv.status);

    const char *dtName = (dv.hasValue && dv.value.type)
                         ? type_name(dv.value.type) : "Unknown";
    UA_DateTime srcTs = dv.hasSourceTimestamp ? dv.sourceTimestamp : 0;

    output_read_result(nodeStr, dv.status,
                       dtName,
                       dv.hasValue ? &dv.value : NULL,
                       srcTs);

    output_end();

    int ret = UA_StatusCode_isGood(dv.status) ? 0 : 3;
    UA_DataValue_clear(&dv);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return ret;
}

/* -------------------------------------------------------------------------
 * write subcommand
 * ---------------------------------------------------------------------- */

static UA_Variant build_write_variant(const char *typeStr, const char *valStr) {
    UA_Variant var; UA_Variant_init(&var);
    if (!typeStr || !valStr) return var;

#define SET_SCALAR(UATYPE, CTYPE, PARSE) \
    { CTYPE v = (CTYPE)(PARSE); \
      UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UATYPE]); return var; }

    if (strcmp(typeStr, "Boolean") == 0)
        SET_SCALAR(UA_TYPES_BOOLEAN, UA_Boolean, strcmp(valStr,"true")==0 || strcmp(valStr,"1")==0)
    if (strcmp(typeStr, "SByte")   == 0) SET_SCALAR(UA_TYPES_SBYTE,  UA_SByte,  atoi(valStr))
    if (strcmp(typeStr, "Byte")    == 0) SET_SCALAR(UA_TYPES_BYTE,   UA_Byte,   atoi(valStr))
    if (strcmp(typeStr, "Int16")   == 0) SET_SCALAR(UA_TYPES_INT16,  UA_Int16,  atoi(valStr))
    if (strcmp(typeStr, "UInt16")  == 0) SET_SCALAR(UA_TYPES_UINT16, UA_UInt16, atoi(valStr))
    if (strcmp(typeStr, "Int32")   == 0) SET_SCALAR(UA_TYPES_INT32,  UA_Int32,  atoi(valStr))
    if (strcmp(typeStr, "UInt32")  == 0) SET_SCALAR(UA_TYPES_UINT32, UA_UInt32, (uint32_t)strtoul(valStr,NULL,10))
    if (strcmp(typeStr, "Int64")   == 0) SET_SCALAR(UA_TYPES_INT64,  UA_Int64,  strtoll(valStr,NULL,10))
    if (strcmp(typeStr, "UInt64")  == 0) SET_SCALAR(UA_TYPES_UINT64, UA_UInt64, strtoull(valStr,NULL,10))
    if (strcmp(typeStr, "Float")   == 0) SET_SCALAR(UA_TYPES_FLOAT,  UA_Float,  (float)atof(valStr))
    if (strcmp(typeStr, "Double")  == 0) SET_SCALAR(UA_TYPES_DOUBLE, UA_Double, atof(valStr))
    if (strcmp(typeStr, "String")  == 0) {
        UA_String s = UA_STRING_ALLOC(valStr);
        UA_Variant_setScalarCopy(&var, &s, &UA_TYPES[UA_TYPES_STRING]);
        UA_String_clear(&s);
        return var;
    }
#undef SET_SCALAR
    return var;
}

static int cmd_write(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    const char *typeStr  = find_arg(argc, argv, "--type");
    const char *valStr   = find_arg(argc, argv, "--value");
    if (!endpoint || !nodeStr || !typeStr || !valStr) {
        fprintf(stderr,
            "usage: client write --endpoint <url> --node <nodeId>"
            " --type <type> --value <val>\n");
        return 1;
    }

    UA_Client *client = connect_client(endpoint);
    if (!client) return 2;

    UA_NodeId nodeId = client_parse_nodeid(client, nodeStr);
    UA_Variant var   = build_write_variant(typeStr, valStr);

    UA_StatusCode sc = UA_Client_writeValueAttribute(client, nodeId, &var);

    output_begin("write");
    output_success(sc == UA_STATUSCODE_GOOD);
    output_service_result(sc);
    printf(",\"nodeId\":\"%s\"", nodeStr);
    output_end();

    int ret = (sc == UA_STATUSCODE_GOOD) ? 0 : 3;
    UA_Variant_clear(&var);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return ret;
}

/* -------------------------------------------------------------------------
 * browse subcommand
 * ---------------------------------------------------------------------- */

static int cmd_browse(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    if (!endpoint || !nodeStr) {
        fprintf(stderr, "usage: client browse --endpoint <url> --node <nodeId>\n");
        return 1;
    }

    UA_Client *client = connect_client(endpoint);
    if (!client) return 2;

    UA_NodeId nodeId = client_parse_nodeid(client, nodeStr);

    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.requestedMaxReferencesPerNode = 0;
    req.nodesToBrowse = UA_BrowseDescription_new();
    req.nodesToBrowseSize = 1;
    UA_NodeId_copy(&nodeId, &req.nodesToBrowse[0].nodeId);
    req.nodesToBrowse[0].browseDirection = UA_BROWSEDIRECTION_FORWARD;
    req.nodesToBrowse[0].resultMask = UA_BROWSERESULTMASK_ALL;

    UA_BrowseResponse resp = UA_Client_Service_browse(client, req);
    UA_BrowseRequest_clear(&req);

    UA_StatusCode sc = resp.responseHeader.serviceResult;

    output_begin("browse");
    output_success(sc == UA_STATUSCODE_GOOD);
    output_service_result(sc);
    printf(",\"nodeId\":\"%s\"", nodeStr);
    if (sc == UA_STATUSCODE_GOOD && resp.resultsSize > 0)
        output_browse_results(&resp.results[0]);
    else
        printf(",\"references\":[]");
    output_end();

    int ret = (sc == UA_STATUSCODE_GOOD) ? 0 : 3;
    UA_BrowseResponse_clear(&resp);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return ret;
}

/* -------------------------------------------------------------------------
 * call subcommand
 * ---------------------------------------------------------------------- */

static int cmd_call(int argc, char **argv) {
    const char *endpoint  = find_arg(argc, argv, "--endpoint");
    const char *objStr    = find_arg(argc, argv, "--object");
    const char *methStr   = find_arg(argc, argv, "--method");
    if (!endpoint || !objStr || !methStr) {
        fprintf(stderr,
            "usage: client call --endpoint <url> --object <nodeId>"
            " --method <nodeId> [--input <type:val> ...]\n");
        return 1;
    }

    UA_Client *client = connect_client(endpoint);
    if (!client) return 2;

    UA_NodeId objectId = client_parse_nodeid(client, objStr);
    UA_NodeId methodId = client_parse_nodeid(client, methStr);

    /* Collect --input type:val pairs */
    int inCount = count_flag(argc, argv, "--input");
    UA_Variant *inputs = calloc((size_t)(inCount > 0 ? inCount : 1), sizeof(UA_Variant));
    if (!inputs) { UA_Client_delete(client); return 2; }

    int ni = 0;
    for (int i = 0; i < argc - 1 && ni < inCount; i++) {
        if (strcmp(argv[i], "--input") == 0) {
            const char *spec = argv[i + 1];
            const char *colon = strchr(spec, ':');
            if (colon) {
                char typeStr[64];
                size_t tl = (size_t)(colon - spec);
                if (tl >= sizeof(typeStr)) tl = sizeof(typeStr) - 1;
                memcpy(typeStr, spec, tl);
                typeStr[tl] = '\0';
                inputs[ni] = build_write_variant(typeStr, colon + 1);
            }
            ni++;
        }
    }

    UA_Variant *outputs = NULL;
    size_t      outputsSize = 0;
    UA_StatusCode sc = UA_Client_call(client, objectId, methodId,
                                     (size_t)inCount, inputs,
                                     &outputsSize, &outputs);

    output_begin("call");
    output_success(sc == UA_STATUSCODE_GOOD);
    output_service_result(sc);
    printf(",\"outputs\":[");
    for (size_t i = 0; i < outputsSize; i++) {
        if (i > 0) printf(",");
        output_ua_variant_value(&outputs[i]);
    }
    printf("]");
    output_end();

    int ret = (sc == UA_STATUSCODE_GOOD) ? 0 : 3;

    for (int i = 0; i < inCount; i++) UA_Variant_clear(&inputs[i]);
    free(inputs);
    if (outputs) {
        for (size_t i = 0; i < outputsSize; i++) UA_Variant_clear(&outputs[i]);
        UA_free(outputs);
    }
    UA_NodeId_clear(&objectId);
    UA_NodeId_clear(&methodId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return ret;
}

/* -------------------------------------------------------------------------
 * subscribe subcommand
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_Client    *client;
    const char   *nodeStr;
    int           notificationsWanted;
    int           notificationsReceived;
} SubCtx;

static void sub_data_change_cb(UA_Client *client, UA_UInt32 subId,
    void *subCtx, UA_UInt32 monId, void *monCtx,
    UA_DataValue *val) {
    (void)client; (void)subId; (void)subCtx; (void)monId; (void)monCtx;
    SubCtx *ctx = (SubCtx*)monCtx;
    if (!ctx) return;

    char tsbuf[64] = "";
    if (val->hasSourceTimestamp)
        output_timestamp(val->sourceTimestamp, tsbuf, sizeof(tsbuf));

    const char *dtName = (val->hasValue && val->value.type)
                         ? type_name(val->value.type) : "Unknown";

    printf("{\"notificationIndex\":%d", ctx->notificationsReceived);
    printf(",\"statusCode\":\"%s\"",
           output_status_code_name(val->hasStatus ? val->status : UA_STATUSCODE_GOOD));
    printf(",\"dataType\":\"%s\"", dtName);
    if (val->hasValue) output_ua_variant_field("value", &val->value);
    if (tsbuf[0]) printf(",\"sourceTimestamp\":\"%s\"", tsbuf);
    printf("}");

    ctx->notificationsReceived++;
    if (ctx->notificationsReceived < ctx->notificationsWanted)
        printf(",");
}

static int cmd_subscribe(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    const char *piStr    = find_arg(argc, argv, "--publishing-interval");
    const char *nStr     = find_arg(argc, argv, "--notifications");
    if (!endpoint || !nodeStr) {
        fprintf(stderr,
            "usage: client subscribe --endpoint <url> --node <nodeId>"
            " [--publishing-interval <ms>] [--notifications <n>]\n");
        return 1;
    }

    double piMs = piStr ? atof(piStr) : 500.0;
    int nWanted = nStr  ? atoi(nStr)  : 5;

    UA_Client *client = connect_client(endpoint);
    if (!client) return 2;

    UA_NodeId nodeId = client_parse_nodeid(client, nodeStr);

    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = piMs;
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);

    UA_StatusCode sc = subResp.responseHeader.serviceResult;
    if (sc != UA_STATUSCODE_GOOD) {
        output_begin("subscribe");
        output_success(0);
        output_service_result(sc);
        output_end();
        UA_NodeId_clear(&nodeId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        return 3;
    }

    SubCtx ctx = { client, nodeStr, nWanted, 0 };

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subResp.subscriptionId,
            UA_TIMESTAMPSTORETURN_BOTH,
            monReq, &ctx, sub_data_change_cb, NULL);

    if (monResp.statusCode != UA_STATUSCODE_GOOD) {
        output_begin("subscribe");
        output_success(0);
        output_service_result(monResp.statusCode);
        output_end();
        UA_NodeId_clear(&nodeId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        return 3;
    }

    output_begin("subscribe");
    output_success(1);
    output_service_result(UA_STATUSCODE_GOOD);
    printf(",\"nodeId\":\"%s\",\"notifications\":[", nodeStr);

    while (ctx.notificationsReceived < ctx.notificationsWanted) {
        UA_Client_run_iterate(client, 100);
    }

    printf("]");
    output_end();

    UA_NodeId_clear(&nodeId);
    UA_Client_Subscriptions_deleteSingle(client, subResp.subscriptionId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return 0;
}

/* -------------------------------------------------------------------------
 * Dispatch
 * ---------------------------------------------------------------------- */

int client_run(int argc, char **argv) {
    /* argv[0]="client", argv[1]=subcommand */
    if (argc < 2) {
        fprintf(stderr,
            "usage: client <endpoints|read|write|browse|call|subscribe> ...\n");
        return 1;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "endpoints")  == 0) return cmd_endpoints(argc - 1, argv + 1);
    if (strcmp(sub, "read")       == 0) return cmd_read(argc - 1, argv + 1);
    if (strcmp(sub, "write")      == 0) return cmd_write(argc - 1, argv + 1);
    if (strcmp(sub, "browse")     == 0) return cmd_browse(argc - 1, argv + 1);
    if (strcmp(sub, "call")       == 0) return cmd_call(argc - 1, argv + 1);
    if (strcmp(sub, "subscribe")  == 0) return cmd_subscribe(argc - 1, argv + 1);
    fprintf(stderr, "unknown client subcommand: %s\n", sub);
    return 1;
}
