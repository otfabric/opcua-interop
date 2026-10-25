/*
 * client history-read-events / history-update-events (docs/CLIENT_CONTRACT.md):
 * HistoryRead with ReadEventDetails (Part 11 §6.5.2) and HistoryUpdate with
 * UpdateEventDetails (§6.9.4) / DeleteEventDetails (§6.9.7), sent with the raw
 * UA_Client_Service_historyRead / _historyUpdate. UA_Client_HistoryRead_events
 * of open62541 v1.5.9 follows continuation points itself and stops on any
 * status other than Good (GoodNoData included), so the adapter pages itself.
 */

#include "history_events.h"

#include "client_internal.h"
#include "output.h"
#include "values.h"

#include <cjson/cJSON.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define HEV_DEFAULT_MAX_PAGES 8

/* The contract's default SelectClauses. */
static const char *const kDefaultSelectOrdered[] = {
    "EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"
};

/* -------------------------------------------------------------------------
 * Pure helpers (also exercised by `test`)
 * ---------------------------------------------------------------------- */

int hev_parse_select(const char *path, UA_SimpleAttributeOperand *out) {
    UA_SimpleAttributeOperand_init(out);
    if (!path || !*path) return -1;
    out->typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
    out->attributeId = UA_ATTRIBUTEID_VALUE;
    size_t n = 1;
    for (const char *p = path; *p; p++)
        if (*p == '/') n++;
    out->browsePath = (UA_QualifiedName *)UA_Array_new(n, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
    if (!out->browsePath) return -1;
    out->browsePathSize = n;
    const char *seg = path;
    for (size_t i = 0; i < n; i++) {
        const char *end = strchr(seg, '/');
        size_t len = end ? (size_t)(end - seg) : strlen(seg);
        if (len == 0) { UA_SimpleAttributeOperand_clear(out); return -1; }
        /* "ns:Name" when the part before the first ':' is a decimal index. */
        UA_UInt16 ns = 0;
        const char *name = seg;
        size_t nameLen = len;
        const char *colon = memchr(seg, ':', len);
        if (colon && colon > seg) {
            int digits = 1;
            for (const char *q = seg; q < colon; q++)
                if (!isdigit((unsigned char)*q)) { digits = 0; break; }
            if (digits) {
                unsigned long v = strtoul(seg, NULL, 10);
                if (v > 0xFFFF) { UA_SimpleAttributeOperand_clear(out); return -1; }
                ns = (UA_UInt16)v;
                name = colon + 1;
                nameLen = len - (size_t)(colon + 1 - seg);
                if (nameLen == 0) { UA_SimpleAttributeOperand_clear(out); return -1; }
            }
        }
        out->browsePath[i].namespaceIndex = ns;
        if (UA_String_copy(&(UA_String){nameLen, (UA_Byte *)(uintptr_t)name},
                           &out->browsePath[i].name) != UA_STATUSCODE_GOOD) {
            UA_SimpleAttributeOperand_clear(out);
            return -1;
        }
        seg = end ? end + 1 : seg + len;
    }
    return 0;
}

int hev_parse_timestamps(const char *s, UA_TimestampsToReturn *out) {
    if (!s) { *out = UA_TIMESTAMPSTORETURN_BOTH; return 0; }
    if (strcasecmp(s, "source") == 0)  { *out = UA_TIMESTAMPSTORETURN_SOURCE;  return 0; }
    if (strcasecmp(s, "server") == 0)  { *out = UA_TIMESTAMPSTORETURN_SERVER;  return 0; }
    if (strcasecmp(s, "both") == 0)    { *out = UA_TIMESTAMPSTORETURN_BOTH;    return 0; }
    if (strcasecmp(s, "neither") == 0) { *out = UA_TIMESTAMPSTORETURN_NEITHER; return 0; }
    return -1;
}

int hev_parse_perform(const char *s, UA_PerformUpdateType *out, int *isDelete) {
    *isDelete = 0;
    if (!s) return -1;
    if (strcasecmp(s, "insert") == 0)  { *out = UA_PERFORMUPDATETYPE_INSERT;  return 0; }
    if (strcasecmp(s, "replace") == 0) { *out = UA_PERFORMUPDATETYPE_REPLACE; return 0; }
    if (strcasecmp(s, "update") == 0)  { *out = UA_PERFORMUPDATETYPE_UPDATE;  return 0; }
    if (strcasecmp(s, "delete") == 0)  { *out = UA_PERFORMUPDATETYPE_REMOVE; *isDelete = 1; return 0; }
    return -1;
}

static void set_operand(UA_ExtensionObject *eo, const void *p, const UA_DataType *t) {
    UA_ExtensionObject_setValueCopy(eo, (void *)(uintptr_t)p, t);
}

/* WhereClause: element 0 is the root (Part 4 §7.7.1) — And(1, 2) when both
 * filters are given, else the single element; empty without filters. */
int hev_build_where(const UA_NodeId *ofType, int haveMinSev, UA_UInt16 minSev,
                    UA_ContentFilter *out) {
    UA_ContentFilter_init(out);
    size_t n = (ofType ? 1 : 0) + (haveMinSev ? 1 : 0);
    if (n == 0) return 0;
    if (n == 2) n = 3;
    out->elements = (UA_ContentFilterElement *)
        UA_Array_new(n, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENT]);
    if (!out->elements) return -1;
    out->elementsSize = n;
    size_t i = (n == 3) ? 1 : 0;
    if (n == 3) {
        UA_ContentFilterElement *e = &out->elements[0];
        e->filterOperator = UA_FILTEROPERATOR_AND;
        e->filterOperands = (UA_ExtensionObject *)UA_Array_new(2, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        e->filterOperandsSize = 2;
        UA_ElementOperand a, b;
        UA_ElementOperand_init(&a); a.index = 1;
        UA_ElementOperand_init(&b); b.index = 2;
        set_operand(&e->filterOperands[0], &a, &UA_TYPES[UA_TYPES_ELEMENTOPERAND]);
        set_operand(&e->filterOperands[1], &b, &UA_TYPES[UA_TYPES_ELEMENTOPERAND]);
    }
    if (ofType) {
        UA_ContentFilterElement *e = &out->elements[i++];
        e->filterOperator = UA_FILTEROPERATOR_OFTYPE;
        e->filterOperands = (UA_ExtensionObject *)UA_Array_new(1, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        e->filterOperandsSize = 1;
        UA_LiteralOperand lit;
        UA_LiteralOperand_init(&lit);
        UA_Variant_setScalarCopy(&lit.value, ofType, &UA_TYPES[UA_TYPES_NODEID]);
        set_operand(&e->filterOperands[0], &lit, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
        UA_LiteralOperand_clear(&lit);
    }
    if (haveMinSev) {
        UA_ContentFilterElement *e = &out->elements[i++];
        e->filterOperator = UA_FILTEROPERATOR_GREATERTHANOREQUAL;
        e->filterOperands = (UA_ExtensionObject *)UA_Array_new(2, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        e->filterOperandsSize = 2;
        UA_SimpleAttributeOperand sao;
        hev_parse_select("Severity", &sao);
        UA_LiteralOperand lit;
        UA_LiteralOperand_init(&lit);
        UA_Variant_setScalarCopy(&lit.value, &minSev, &UA_TYPES[UA_TYPES_UINT16]);
        set_operand(&e->filterOperands[0], &sao, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
        set_operand(&e->filterOperands[1], &lit, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
        UA_SimpleAttributeOperand_clear(&sao);
        UA_LiteralOperand_clear(&lit);
    }
    return 0;
}

/* One --event value: {"type":"T","value":v} or a bare JSON value (string →
 * String, bool → Boolean, number → Double, {"text"} → LocalizedText). */
int hev_event_value(const cJSON *j, UA_Variant *out, char *err, size_t errLen) {
    UA_Variant_init(out);
    const cJSON *val = j;
    const char *type = NULL;
    if (cJSON_IsObject(j) && cJSON_GetObjectItemCaseSensitive(j, "type")) {
        const cJSON *t = cJSON_GetObjectItemCaseSensitive(j, "type");
        if (!cJSON_IsString(t)) { snprintf(err, errLen, "\"type\" is not a string"); return -1; }
        type = t->valuestring;
        val = cJSON_GetObjectItemCaseSensitive(j, "value");
        if (!val) { snprintf(err, errLen, "missing \"value\""); return -1; }
    }
    if (cJSON_IsNull(val)) return 0; /* null Variant */
    if (!type) {
        if (cJSON_IsString(val)) type = "String";
        else if (cJSON_IsBool(val)) type = "Boolean";
        else if (cJSON_IsNumber(val)) type = "Double";
        else if (cJSON_IsObject(val) && cJSON_GetObjectItemCaseSensitive(val, "text")) type = "LocalizedText";
        else { snprintf(err, errLen, "a value without \"type\" must be a string, number, boolean or LocalizedText"); return -1; }
    }
    if (strcmp(type, "LocalizedText") == 0 && cJSON_IsObject(val)) {
        const cJSON *loc = cJSON_GetObjectItemCaseSensitive(val, "locale");
        const cJSON *txt = cJSON_GetObjectItemCaseSensitive(val, "text");
        UA_LocalizedText lt;
        UA_LocalizedText_init(&lt);
        lt.locale = UA_STRING_ALLOC(cJSON_IsString(loc) ? loc->valuestring : "");
        lt.text = UA_STRING_ALLOC(cJSON_IsString(txt) ? txt->valuestring : "");
        UA_StatusCode sc = UA_Variant_setScalarCopy(out, &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        UA_LocalizedText_clear(&lt);
        return sc == UA_STATUSCODE_GOOD ? 0 : -1;
    }
    if (strcmp(type, "QualifiedName") == 0 && cJSON_IsObject(val)) {
        const cJSON *ns = cJSON_GetObjectItemCaseSensitive(val, "ns");
        const cJSON *nm = cJSON_GetObjectItemCaseSensitive(val, "name");
        UA_QualifiedName qn = UA_QUALIFIEDNAME_ALLOC(cJSON_IsNumber(ns) ? (UA_UInt16)ns->valueint : 0,
                                                     cJSON_IsString(nm) ? nm->valuestring : "");
        UA_StatusCode sc = UA_Variant_setScalarCopy(out, &qn, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
        UA_QualifiedName_clear(&qn);
        return sc == UA_STATUSCODE_GOOD ? 0 : -1;
    }
    char lit[64];
    const char *literal;
    if (cJSON_IsString(val)) {
        literal = val->valuestring;
    } else if (cJSON_IsBool(val)) {
        literal = cJSON_IsTrue(val) ? "true" : "false";
    } else if (cJSON_IsNumber(val)) {
        double d = val->valuedouble;
        if (d == (double)(long long)d) snprintf(lit, sizeof(lit), "%lld", (long long)d);
        else snprintf(lit, sizeof(lit), "%.17g", d);
        literal = lit;
    } else {
        snprintf(err, errLen, "unsupported value for type %s", type);
        return -1;
    }
    return value_parse(type, literal, NULL, out, err, errLen);
}

/* -------------------------------------------------------------------------
 * Argument helpers
 * ---------------------------------------------------------------------- */

/* All values of a repeatable flag (pointers into argv; caller frees array). */
static const char **collect(int argc, char **argv, const char *flag, size_t *n) {
    *n = 0;
    const char **arr = (const char **)calloc((size_t)argc + 1, sizeof(char *));
    if (!arr) return NULL;
    for (int i = 0; i < argc - 1; i++)
        if (strcmp(argv[i], flag) == 0) arr[(*n)++] = argv[i + 1];
    return arr;
}

/* Presence flag that may carry true|false. */
static int presence_flag(int argc, char **argv, const char *flag) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], flag) != 0) continue;
        if (i + 1 < argc && (strcasecmp(argv[i + 1], "false") == 0 || strcmp(argv[i + 1], "0") == 0))
            return 0;
        return 1;
    }
    return 0;
}

static int input_fail(const char *op, const char *msg) {
    cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input", msg);
    return 2;
}

static int resolve_node(UA_Client *client, const char *s, UA_NodeId *out) {
    if (strncmp(s, "nsu=", 4) == 0) return cli_resolve_nsu_nodeid(client, s, out);
    *out = cli_parse_nodeid_local(s);
    return 0;
}

static void print_status(const char *key, UA_StatusCode sc) {
    printf("\"%s\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           key, output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
}

static void print_select(const char *const *sel, size_t n) {
    printf("\"selectClauses\":[");
    for (size_t i = 0; i < n; i++) {
        if (i) printf(",");
        output_json_string(sel[i]);
    }
    printf("]");
}

static void print_cp(const UA_ByteString *cp) {
    printf("\"continuationPoint\":");
    if (cp && cp->length > 0) {
        char *b = value_b64_encode(cp->data, cp->length);
        if (b) { printf("\"%s\"", b); free(b); return; }
    }
    printf("null");
}

/* The events of a result as JSON objects separated by commas (no brackets);
 * *first tracks the separator across calls. Only the fields the server
 * returned are printed (no padding to the select clauses). */
static void print_event_list(const UA_HistoryReadResult *r, const char *const *sel, size_t nsel,
                             int *first) {
    const UA_HistoryEvent *he = NULL;
    if (r && r->historyData.encoding == UA_EXTENSIONOBJECT_DECODED &&
        r->historyData.content.decoded.type == &UA_TYPES[UA_TYPES_HISTORYEVENT])
        he = (const UA_HistoryEvent *)r->historyData.content.decoded.data;
    for (size_t i = 0; he && i < he->eventsSize; i++) {
        const UA_HistoryEventFieldList *fl = &he->events[i];
        if (!*first) printf(",");
        *first = 0;
        printf("{\"fields\":[");
        for (size_t j = 0; j < fl->eventFieldsSize; j++) {
            const UA_Variant *v = &fl->eventFields[j];
            if (j) printf(",");
            printf("{\"name\":");
            if (j < nsel) output_json_string(sel[j]);
            else printf("\"field%zu\"", j);
            if (UA_Variant_isEmpty(v))
                printf(",\"dataType\":\"Null\",\"builtInType\":0,\"value\":null}");
            else {
                printf(",\"dataType\":\"%s\",\"builtInType\":%d,\"value\":",
                       value_type_name(v->type), ua_type_to_builtin_id(v->type));
                output_ua_variant_value(v);
                printf("}");
            }
        }
        printf("]}");
    }
}

static void print_events(const UA_HistoryReadResult *r, const char *const *sel, size_t nsel) {
    int first = 1;
    printf("\"events\":[");
    print_event_list(r, sel, nsel, &first);
    printf("]");
}

/* Result i of a response, NULL on a service fault or a missing result. */
static const UA_HistoryReadResult *result_of(const UA_HistoryReadResponse *r, size_t i) {
    return (UA_StatusCode_isGood(r->responseHeader.serviceResult) && i < r->resultsSize)
           ? &r->results[i] : NULL;
}

/* -------------------------------------------------------------------------
 * history-read-events
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_DateTime start, end;
    UA_UInt32 numValues;
    UA_TimestampsToReturn ts;
    UA_EventFilter filter;
} HevRead;

/* One HistoryRead of `n` nodes; the same continuation point for each. */
static UA_HistoryReadResponse hev_read(UA_Client *client, const HevRead *rd,
                                       const UA_NodeId *nodes, size_t n,
                                       const UA_ByteString *cp, UA_Boolean release) {
    UA_ReadEventDetails d;
    UA_ReadEventDetails_init(&d);
    d.numValuesPerNode = rd->numValues;
    d.startTime = rd->start;
    d.endTime = rd->end;
    d.filter = rd->filter; /* shallow; copied into the ExtensionObject below */

    UA_HistoryReadRequest req;
    UA_HistoryReadRequest_init(&req);
    UA_ExtensionObject_setValueCopy(&req.historyReadDetails, &d, &UA_TYPES[UA_TYPES_READEVENTDETAILS]);
    req.timestampsToReturn = rd->ts;
    req.releaseContinuationPoints = release;
    req.nodesToRead = (UA_HistoryReadValueId *)UA_Array_new(n, &UA_TYPES[UA_TYPES_HISTORYREADVALUEID]);
    req.nodesToReadSize = req.nodesToRead ? n : 0;
    for (size_t i = 0; i < req.nodesToReadSize; i++) {
        UA_NodeId_copy(&nodes[i], &req.nodesToRead[i].nodeId);
        if (cp && cp->length > 0) UA_ByteString_copy(cp, &req.nodesToRead[i].continuationPoint);
    }
    UA_HistoryReadResponse resp = UA_Client_Service_historyRead(client, req);
    UA_HistoryReadRequest_clear(&req);
    return resp;
}

/* Status of item i of a response (the service result when it is Bad or the
 * item is missing). */
static UA_StatusCode item_status(const UA_HistoryReadResponse *r, size_t i) {
    UA_StatusCode svc = r->responseHeader.serviceResult;
    if (!UA_StatusCode_isGood(svc)) return svc;
    if (i >= r->resultsSize) return UA_STATUSCODE_BADUNEXPECTEDERROR;
    return r->results[i].statusCode;
}

int cmd_history_read_events(int argc, char **argv) {
    static const char *op = "history-read-events";
    const char *endpoint = cli_find_arg(argc, argv, "--endpoint");
    size_t nNodes = 0, nSel = 0;
    const char **nodeStrs = collect(argc, argv, "--node", &nNodes);
    const char **selStrs = collect(argc, argv, "--select", &nSel);
    int rc = 2;
    if (!nodeStrs || !selStrs) { free(nodeStrs); free(selStrs); return input_fail(op, "out of memory"); }
    if (!endpoint || nNodes == 0) {
        rc = input_fail(op, "usage: history-read-events --endpoint <url> --node <nodeId> [--node ...]"
                            " [--start <rfc3339>] [--end <rfc3339>] [--num-values <n>] [--select <path>]..."
                            " [--of-type <nodeId>] [--min-severity <n>] [--continuation-point <b64>]"
                            " [--release-continuation-point] [--timestamps source|server|both|neither]"
                            " [--scenario continue [--max-pages <n>]]");
        goto out_args;
    }
    for (size_t i = 0; i < nNodes; i++) {
        if (cli_validate_nodeid(nodeStrs[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStrs[i]);
            rc = input_fail(op, msg);
            goto out_args;
        }
    }
    const char *const *sel = nSel ? (const char *const *)selStrs : kDefaultSelectOrdered;
    size_t selN = nSel ? nSel : sizeof(kDefaultSelectOrdered) / sizeof(kDefaultSelectOrdered[0]);

    HevRead rd;
    memset(&rd, 0, sizeof(rd));
    UA_EventFilter_init(&rd.filter);
    const char *s;
    if ((s = cli_find_arg(argc, argv, "--start")) && value_parse_datetime(s, &rd.start) != 0) {
        rc = input_fail(op, "invalid --start (expect UTC RFC 3339)");
        goto out_args;
    }
    if ((s = cli_find_arg(argc, argv, "--end")) && value_parse_datetime(s, &rd.end) != 0) {
        rc = input_fail(op, "invalid --end (expect UTC RFC 3339)");
        goto out_args;
    }
    if ((s = cli_find_arg(argc, argv, "--num-values"))) {
        char *e;
        long v = strtol(s, &e, 10);
        if (*e || v < 0 || v > 0xFFFFFFFFL) { rc = input_fail(op, "--num-values must be a non-negative integer"); goto out_args; }
        rd.numValues = (UA_UInt32)v;
    }
    if (hev_parse_timestamps(cli_find_arg(argc, argv, "--timestamps"), &rd.ts) != 0) {
        rc = input_fail(op, "--timestamps must be source, server, both or neither");
        goto out_args;
    }
    const char *ofTypeStr = cli_find_arg(argc, argv, "--of-type");
    const char *minSevStr = cli_find_arg(argc, argv, "--min-severity");
    UA_UInt16 minSev = 0;
    if (ofTypeStr && cli_validate_nodeid(ofTypeStr) != 0) { rc = input_fail(op, "malformed --of-type NodeId"); goto out_args; }
    if (minSevStr) {
        char *e;
        long v = strtol(minSevStr, &e, 10);
        if (*e || v < 0 || v > 0xFFFF) { rc = input_fail(op, "--min-severity must be 0..65535"); goto out_args; }
        minSev = (UA_UInt16)v;
    }
    const char *scenario = cli_find_arg(argc, argv, "--scenario");
    if (scenario && strcmp(scenario, "continue") != 0) { rc = input_fail(op, "unknown --scenario (only continue)"); goto out_args; }
    int maxPages = HEV_DEFAULT_MAX_PAGES;
    if ((s = cli_find_arg(argc, argv, "--max-pages"))) {
        maxPages = atoi(s);
        if (maxPages <= 0) { rc = input_fail(op, "--max-pages must be positive"); goto out_args; }
    }
    UA_Boolean release = presence_flag(argc, argv, "--release-continuation-point") ? UA_TRUE : UA_FALSE;
    UA_ByteString cpIn;
    UA_ByteString_init(&cpIn);
    if ((s = cli_find_arg(argc, argv, "--continuation-point"))) {
        size_t len = 0;
        unsigned char *b = value_b64_decode(s, &len);
        if (!b && *s) { rc = input_fail(op, "--continuation-point is not Base64"); goto out_args; }
        cpIn.data = b;
        cpIn.length = b ? len : 0;
    }
    if (release && !s) {
        rc = input_fail(op, "--release-continuation-point needs --continuation-point");
        goto out_args;
    }
    if (s && nNodes > 1) {
        rc = input_fail(op, "--continuation-point takes a single --node");
        goto out_filter;
    }

    /* SelectClauses */
    rd.filter.selectClauses = (UA_SimpleAttributeOperand *)
        UA_Array_new(selN, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
    rd.filter.selectClausesSize = selN;
    for (size_t i = 0; i < selN; i++) {
        if (hev_parse_select(sel[i], &rd.filter.selectClauses[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "invalid --select path: '%s'", sel[i]);
            rc = input_fail(op, msg);
            goto out_filter;
        }
    }

    int exit_code = 3;
    int req_ms = 5000;
    UA_Client *client = cli_make_client(endpoint, req_ms, op, &exit_code);
    if (!client) { rc = exit_code; goto out_filter; }

    UA_NodeId *nodes = (UA_NodeId *)UA_Array_new(nNodes, &UA_TYPES[UA_TYPES_NODEID]);
    for (size_t i = 0; i < nNodes; i++) {
        if (resolve_node(client, nodeStrs[i], &nodes[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStrs[i]);
            cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input", msg);
            rc = 2;
            goto out_client;
        }
    }
    UA_NodeId ofType;
    UA_NodeId_init(&ofType);
    if (ofTypeStr && resolve_node(client, ofTypeStr, &ofType) != 0) {
        cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input", "unknown namespace URI in --of-type");
        rc = 2;
        goto out_client;
    }
    hev_build_where(ofTypeStr ? &ofType : NULL, minSevStr != NULL, minSev, &rd.filter.whereClause);
    UA_NodeId_clear(&ofType);

    if (scenario) {
        /* Per node: follow CPs up to --max-pages, then release the last CP
         * seen and try to reuse it (as history-read --scenario continue);
         * without any CP no release is sent and both statuses are null. */
        if (rd.numValues == 0) rd.numValues = 2;
        UA_StatusCode *releaseSc = (UA_StatusCode *)calloc(nNodes, sizeof(UA_StatusCode));
        UA_StatusCode *reuseSc = (UA_StatusCode *)calloc(nNodes, sizeof(UA_StatusCode));
        int *pageCount = (int *)calloc(nNodes, sizeof(int));
        int *hadCp = (int *)calloc(nNodes, sizeof(int)); /* a CP was returned: release + reuse ran */
        UA_HistoryReadResponse **all = (UA_HistoryReadResponse **)calloc(nNodes, sizeof(*all));
        int ok = 1, timeout = 0;
        UA_StatusCode emit = UA_STATUSCODE_GOOD;
        for (size_t ni = 0; ni < nNodes; ni++) {
            all[ni] = (UA_HistoryReadResponse *)calloc((size_t)maxPages, sizeof(UA_HistoryReadResponse));
            UA_ByteString lastCp;
            UA_ByteString_init(&lastCp);
            UA_ByteString cur;
            UA_ByteString_init(&cur);
            UA_StatusCode last = UA_STATUSCODE_GOOD;
            for (int p = 0; p < maxPages; p++) {
                all[ni][p] = hev_read(client, &rd, &nodes[ni], 1, cur.length ? &cur : NULL, UA_FALSE);
                pageCount[ni]++;
                last = item_status(&all[ni][p], 0);
                UA_ByteString_clear(&cur);
                if (!UA_StatusCode_isGood(last)) break;
                const UA_ByteString *cp = &all[ni][p].results[0].continuationPoint;
                if (cp->length == 0) break;
                UA_ByteString_clear(&lastCp);
                UA_ByteString_copy(cp, &lastCp);
                UA_ByteString_copy(cp, &cur);
            }
            UA_ByteString_clear(&cur);
            releaseSc[ni] = reuseSc[ni] = UA_STATUSCODE_GOOD;
            if (lastCp.length > 0) {
                hadCp[ni] = 1;
                UA_HistoryReadResponse r = hev_read(client, &rd, &nodes[ni], 1, &lastCp, UA_TRUE);
                releaseSc[ni] = item_status(&r, 0);
                UA_HistoryReadResponse_clear(&r);
                r = hev_read(client, &rd, &nodes[ni], 1, &lastCp, UA_FALSE);
                reuseSc[ni] = item_status(&r, 0);
                UA_HistoryReadResponse_clear(&r);
            }
            UA_ByteString_clear(&lastCp);
            if (!UA_StatusCode_isGood(last)) {
                if (ok) emit = last;
                ok = 0;
                if (last == UA_STATUSCODE_BADTIMEOUT) timeout = 1;
            } else if (ok && emit == UA_STATUSCODE_GOOD && last != UA_STATUSCODE_GOOD) {
                emit = last;
            }
        }
        output_begin("open62541", op);
        output_success(ok);
        output_service_result(emit);
        output_open_results();
        for (size_t ni = 0; ni < nNodes; ni++) {
            if (ni) printf(",");
            printf("{\"scenario\":\"continue\",\"nodeId\":");
            output_nodeid(&nodes[ni]);
            printf(",");
            print_select(sel, selN);
            /* The last page's status and CP, all pages' events in order. */
            const UA_HistoryReadResponse *lastPage = &all[ni][pageCount[ni] - 1];
            printf(",");
            print_status("statusCode", item_status(lastPage, 0));
            printf(",");
            print_cp(result_of(lastPage, 0) ? &result_of(lastPage, 0)->continuationPoint : NULL);
            printf(",\"events\":[");
            int first = 1;
            for (int p = 0; p < pageCount[ni]; p++)
                print_event_list(result_of(&all[ni][p], 0), sel, selN, &first);
            printf("]");
            printf(",\"pages\":[");
            for (int p = 0; p < pageCount[ni]; p++) {
                const UA_HistoryReadResponse *r = &all[ni][p];
                const UA_HistoryReadResult *res = result_of(r, 0);
                if (p) printf(",");
                printf("{");
                print_status("statusCode", item_status(r, 0));
                printf(",");
                print_cp(res ? &res->continuationPoint : NULL);
                printf(",");
                print_events(res, sel, selN);
                printf("}");
            }
            printf("],");
            if (hadCp[ni]) {
                print_status("releaseStatusCode", releaseSc[ni]);
                printf(",");
                print_status("reuseAfterReleaseStatusCode", reuseSc[ni]);
            } else {
                printf("\"releaseStatusCode\":null,\"reuseAfterReleaseStatusCode\":null");
            }
            printf("}");
        }
        output_close_results();
        output_null_error();
        output_end();
        for (size_t ni = 0; ni < nNodes; ni++) {
            for (int p = 0; p < pageCount[ni]; p++) UA_HistoryReadResponse_clear(&all[ni][p]);
            free(all[ni]);
        }
        free(all); free(pageCount); free(hadCp); free(releaseSc); free(reuseSc);
        rc = timeout ? 7 : (ok ? 0 : 4);
        goto out_client;
    }

    {
        UA_HistoryReadResponse resp = hev_read(client, &rd, nodes, nNodes, cpIn.length ? &cpIn : NULL, release);
        UA_StatusCode svc = resp.responseHeader.serviceResult;
        int ok = UA_StatusCode_isGood(svc);
        UA_StatusCode emit = svc;
        if (ok) {
            for (size_t i = 0; i < nNodes; i++) {
                UA_StatusCode isc = item_status(&resp, i);
                if (!UA_StatusCode_isGood(isc)) { if (ok) emit = isc; ok = 0; }
                else if (ok && emit == UA_STATUSCODE_GOOD) emit = isc;
            }
        }
        output_begin("open62541", op);
        output_success(ok);
        output_service_result(emit);
        if (!UA_StatusCode_isGood(svc)) {
            printf(",\"results\":[],\"error\":{\"category\":\"%s\",\"message\":\"HistoryRead failed: %s\"}",
                   svc == UA_STATUSCODE_BADTIMEOUT ? "timeout" : "service", output_status_code_name(svc));
        } else {
            output_open_results();
            for (size_t i = 0; i < nNodes; i++) {
                const UA_HistoryReadResult *res = i < resp.resultsSize ? &resp.results[i] : NULL;
                if (i) printf(",");
                printf("{\"nodeId\":");
                output_nodeid(&nodes[i]);
                printf(",");
                print_status("statusCode", item_status(&resp, i));
                printf(",");
                print_cp(res ? &res->continuationPoint : NULL);
                printf(",");
                print_select(sel, selN);
                printf(",");
                print_events(res, sel, selN);
                printf("}");
            }
            output_close_results();
            output_null_error();
        }
        output_end();
        UA_HistoryReadResponse_clear(&resp);
        rc = (svc == UA_STATUSCODE_BADTIMEOUT) ? 7 : (ok ? 0 : 4);
    }

out_client:
    UA_Array_delete(nodes, nNodes, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
out_filter:
    UA_EventFilter_clear(&rd.filter);
    UA_ByteString_clear(&cpIn);
out_args:
    free(nodeStrs);
    free(selStrs);
    return rc;
}

/* -------------------------------------------------------------------------
 * history-update-events
 * ---------------------------------------------------------------------- */

static const char *perform_name(UA_PerformUpdateType t) {
    switch (t) {
    case UA_PERFORMUPDATETYPE_INSERT:  return "Insert";
    case UA_PERFORMUPDATETYPE_REPLACE: return "Replace";
    case UA_PERFORMUPDATETYPE_UPDATE:  return "Update";
    default:                           return "Delete";
    }
}

int cmd_history_update_events(int argc, char **argv) {
    static const char *op = "history-update-events";
    const char *endpoint = cli_find_arg(argc, argv, "--endpoint");
    const char *nodeStr = cli_find_arg(argc, argv, "--node");
    const char *performStr = cli_find_arg(argc, argv, "--perform");
    size_t nSel = 0, nEv = 0, nIds = 0;
    const char **selStrs = collect(argc, argv, "--select", &nSel);
    const char **evStrs = collect(argc, argv, "--event", &nEv);
    const char **idStrs = collect(argc, argv, "--event-id", &nIds);
    cJSON **evs = NULL;
    const char **sel = NULL;
    size_t selN = 0;
    UA_HistoryUpdateRequest req;
    UA_HistoryUpdateRequest_init(&req);
    int rc = 2;
    char err[512];

    if (!selStrs || !evStrs || !idStrs) { rc = input_fail(op, "out of memory"); goto out; }
    if (!endpoint || !nodeStr || !performStr) {
        rc = input_fail(op, "usage: history-update-events --endpoint <url> --node <nodeId>"
                            " --perform insert|replace|update|delete [--select <path>]..."
                            " [--event <json>]... [--event-id <b64>]...");
        goto out;
    }
    if (cli_validate_nodeid(nodeStr) != 0) {
        snprintf(err, sizeof(err), "malformed NodeId: '%s'", nodeStr);
        rc = input_fail(op, err);
        goto out;
    }
    UA_PerformUpdateType perform;
    int isDelete = 0;
    if (hev_parse_perform(performStr, &perform, &isDelete) != 0) {
        rc = input_fail(op, "--perform must be insert, replace, update or delete");
        goto out;
    }
    if (isDelete && nIds == 0) { rc = input_fail(op, "--perform delete needs --event-id"); goto out; }
    if (!isDelete && nEv == 0) { rc = input_fail(op, "--perform insert|replace|update needs --event"); goto out; }

    /* Parse --event objects; without --select the keys in first-seen order. */
    evs = (cJSON **)calloc(nEv ? nEv : 1, sizeof(cJSON *));
    sel = (const char **)calloc(nSel + 64 * (nEv ? nEv : 1) + 1, sizeof(char *));
    if (!evs || !sel) { rc = input_fail(op, "out of memory"); goto out; }
    for (size_t i = 0; i < nSel; i++) sel[selN++] = selStrs[i];
    for (size_t i = 0; i < nEv; i++) {
        evs[i] = cJSON_Parse(evStrs[i]);
        if (!evs[i] || !cJSON_IsObject(evs[i])) {
            snprintf(err, sizeof(err), "--event %zu is not a JSON object", i + 1);
            rc = input_fail(op, err);
            goto out;
        }
        if (nSel == 0) {
            const cJSON *it;
            cJSON_ArrayForEach(it, evs[i]) {
                size_t k;
                for (k = 0; k < selN; k++)
                    if (strcmp(sel[k], it->string) == 0) break;
                if (k == selN && selN < nSel + 64 * nEv) sel[selN++] = it->string;
            }
        }
    }

    if (isDelete) {
        UA_DeleteEventDetails d;
        UA_DeleteEventDetails_init(&d);
        d.eventIds = (UA_ByteString *)UA_Array_new(nIds, &UA_TYPES[UA_TYPES_BYTESTRING]);
        d.eventIdsSize = nIds;
        for (size_t i = 0; i < nIds; i++) {
            size_t len = 0;
            unsigned char *b = value_b64_decode(idStrs[i], &len);
            if (!b && *idStrs[i]) {
                UA_DeleteEventDetails_clear(&d);
                snprintf(err, sizeof(err), "--event-id is not Base64: '%s'", idStrs[i]);
                rc = input_fail(op, err);
                goto out;
            }
            d.eventIds[i].data = b;
            d.eventIds[i].length = b ? len : 0;
        }
        req.historyUpdateDetails = (UA_ExtensionObject *)UA_Array_new(1, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        req.historyUpdateDetailsSize = 1;
        UA_ExtensionObject_setValueCopy(&req.historyUpdateDetails[0], &d, &UA_TYPES[UA_TYPES_DELETEEVENTDETAILS]);
        UA_DeleteEventDetails_clear(&d);
    } else {
        UA_UpdateEventDetails d;
        UA_UpdateEventDetails_init(&d);
        d.performInsertReplace = perform;
        d.filter.selectClauses = (UA_SimpleAttributeOperand *)
            UA_Array_new(selN, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
        d.filter.selectClausesSize = selN;
        for (size_t i = 0; i < selN; i++) {
            if (hev_parse_select(sel[i], &d.filter.selectClauses[i]) != 0) {
                UA_UpdateEventDetails_clear(&d);
                snprintf(err, sizeof(err), "invalid --select path: '%s'", sel[i]);
                rc = input_fail(op, err);
                goto out;
            }
        }
        d.eventData = (UA_HistoryEventFieldList *)UA_Array_new(nEv, &UA_TYPES[UA_TYPES_HISTORYEVENTFIELDLIST]);
        d.eventDataSize = nEv;
        for (size_t i = 0; i < nEv; i++) {
            UA_HistoryEventFieldList *fl = &d.eventData[i];
            fl->eventFields = (UA_Variant *)UA_Array_new(selN, &UA_TYPES[UA_TYPES_VARIANT]);
            fl->eventFieldsSize = selN;
            for (size_t k = 0; k < selN; k++) {
                const cJSON *v = cJSON_GetObjectItemCaseSensitive(evs[i], sel[k]);
                if (!v) continue; /* null Variant */
                char verr[256];
                if (hev_event_value(v, &fl->eventFields[k], verr, sizeof(verr)) != 0) {
                    UA_UpdateEventDetails_clear(&d);
                    snprintf(err, sizeof(err), "--event %zu field %s: %s", i + 1, sel[k], verr);
                    rc = input_fail(op, err);
                    goto out;
                }
            }
        }
        req.historyUpdateDetails = (UA_ExtensionObject *)UA_Array_new(1, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        req.historyUpdateDetailsSize = 1;
        /* The NodeId is set after connecting (nsu= resolution). */
        UA_ExtensionObject_setValueCopy(&req.historyUpdateDetails[0], &d, &UA_TYPES[UA_TYPES_UPDATEEVENTDETAILS]);
        UA_UpdateEventDetails_clear(&d);
    }

    int exit_code = 3;
    UA_Client *client = cli_make_client(endpoint, 5000, op, &exit_code);
    if (!client) { rc = exit_code; goto out; }
    UA_NodeId nodeId;
    UA_NodeId_init(&nodeId);
    if (resolve_node(client, nodeStr, &nodeId) != 0) {
        snprintf(err, sizeof(err), "unknown namespace URI in '%s'", nodeStr);
        cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input", err);
        rc = 2;
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        goto out;
    }
    {
        void *det = req.historyUpdateDetails[0].content.decoded.data;
        UA_NodeId *target = isDelete ? &((UA_DeleteEventDetails *)det)->nodeId
                                     : &((UA_UpdateEventDetails *)det)->nodeId;
        UA_NodeId_copy(&nodeId, target);
    }
    UA_HistoryUpdateResponse resp = UA_Client_Service_historyUpdate(client, req);
    UA_StatusCode svc = resp.responseHeader.serviceResult;
    UA_StatusCode item = UA_STATUSCODE_GOOD;
    if (UA_StatusCode_isGood(svc))
        item = resp.resultsSize > 0 ? resp.results[0].statusCode : UA_STATUSCODE_BADUNEXPECTEDERROR;
    int ok = UA_StatusCode_isGood(svc) && UA_StatusCode_isGood(item);

    output_begin("open62541", op);
    output_success(ok);
    output_service_result(UA_StatusCode_isGood(svc) ? item : svc);
    if (!UA_StatusCode_isGood(svc)) {
        printf(",\"results\":[],\"error\":{\"category\":\"%s\",\"message\":\"HistoryUpdate failed: %s\"}",
               svc == UA_STATUSCODE_BADTIMEOUT ? "timeout" : "service", output_status_code_name(svc));
    } else {
        output_open_results();
        printf("{\"nodeId\":");
        output_nodeid(&nodeId);
        printf(",\"performUpdateType\":\"%s\",", perform_name(perform));
        print_status("statusCode", item);
        printf(",\"operationResults\":[");
        if (resp.resultsSize > 0) {
            const UA_HistoryUpdateResult *r = &resp.results[0];
            for (size_t i = 0; i < r->operationResultsSize; i++) {
                UA_StatusCode sc = r->operationResults[i];
                if (i) printf(",");
                printf("{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
                       output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
            }
        }
        printf("]}");
        output_close_results();
        output_null_error();
    }
    output_end();
    rc = (svc == UA_STATUSCODE_BADTIMEOUT) ? 7 : (ok ? 0 : 4);
    UA_HistoryUpdateResponse_clear(&resp);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

out:
    UA_HistoryUpdateRequest_clear(&req);
    if (evs) for (size_t i = 0; i < nEv; i++) cJSON_Delete(evs[i]);
    free(evs);
    free(sel);
    free(selStrs);
    free(evStrs);
    free(idStrs);
    return rc;
}

/* -------------------------------------------------------------------------
 * Self-test (`opcua-interop-open62541 test`)
 * ---------------------------------------------------------------------- */

static int str_eq(const UA_String *a, const char *b) {
    return a->length == strlen(b) && (a->length == 0 || memcmp(a->data, b, a->length) == 0);
}

#define T(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int hev_selftest(void) {
    int fails = 0;
    UA_SimpleAttributeOperand op;
    T(hev_parse_select("EventId", &op) == 0);
    T(op.browsePathSize == 1 && op.browsePath[0].namespaceIndex == 0 &&
      str_eq(&op.browsePath[0].name, "EventId"));
    T(op.typeDefinitionId.identifier.numeric == UA_NS0ID_BASEEVENTTYPE && op.attributeId == UA_ATTRIBUTEID_VALUE);
    UA_SimpleAttributeOperand_clear(&op);
    T(hev_parse_select("AckedState/2:Id", &op) == 0);
    T(op.browsePathSize == 2 && op.browsePath[1].namespaceIndex == 2 &&
      str_eq(&op.browsePath[1].name, "Id") &&
      str_eq(&op.browsePath[0].name, "AckedState"));
    UA_SimpleAttributeOperand_clear(&op);
    T(hev_parse_select("a:b", &op) == 0); /* non-numeric prefix: ns 0, name "a:b" */
    T(op.browsePath[0].namespaceIndex == 0 && op.browsePath[0].name.length == 3);
    UA_SimpleAttributeOperand_clear(&op);
    T(hev_parse_select("A//B", &op) != 0);
    T(hev_parse_select("", &op) != 0);

    UA_TimestampsToReturn ts;
    T(hev_parse_timestamps("Neither", &ts) == 0 && ts == UA_TIMESTAMPSTORETURN_NEITHER);
    T(hev_parse_timestamps("source", &ts) == 0 && ts == UA_TIMESTAMPSTORETURN_SOURCE);
    T(hev_parse_timestamps(NULL, &ts) == 0 && ts == UA_TIMESTAMPSTORETURN_BOTH);
    T(hev_parse_timestamps("x", &ts) != 0);

    UA_PerformUpdateType p;
    int del;
    T(hev_parse_perform("Insert", &p, &del) == 0 && p == UA_PERFORMUPDATETYPE_INSERT && !del);
    T(hev_parse_perform("update", &p, &del) == 0 && p == UA_PERFORMUPDATETYPE_UPDATE);
    T(hev_parse_perform("delete", &p, &del) == 0 && del);
    T(hev_parse_perform("upsert", &p, &del) != 0);

    UA_ContentFilter cf;
    UA_NodeId t2130 = UA_NODEID_NUMERIC(0, 2130);
    T(hev_build_where(NULL, 0, 0, &cf) == 0 && cf.elementsSize == 0);
    UA_ContentFilter_clear(&cf);
    T(hev_build_where(&t2130, 0, 0, &cf) == 0 && cf.elementsSize == 1 &&
      cf.elements[0].filterOperator == UA_FILTEROPERATOR_OFTYPE);
    UA_ContentFilter_clear(&cf);
    T(hev_build_where(&t2130, 1, 300, &cf) == 0 && cf.elementsSize == 3 &&
      cf.elements[0].filterOperator == UA_FILTEROPERATOR_AND &&
      cf.elements[1].filterOperator == UA_FILTEROPERATOR_OFTYPE &&
      cf.elements[2].filterOperator == UA_FILTEROPERATOR_GREATERTHANOREQUAL);
    if (cf.elementsSize == 3) {
        const UA_ElementOperand *a = (const UA_ElementOperand *)cf.elements[0].filterOperands[0].content.decoded.data;
        const UA_ElementOperand *b = (const UA_ElementOperand *)cf.elements[0].filterOperands[1].content.decoded.data;
        T(a->index == 1 && b->index == 2);
        const UA_LiteralOperand *l = (const UA_LiteralOperand *)cf.elements[2].filterOperands[1].content.decoded.data;
        T(l->value.type == &UA_TYPES[UA_TYPES_UINT16] && *(UA_UInt16 *)l->value.data == 300);
    }
    UA_ContentFilter_clear(&cf);

    char err[256];
    UA_Variant v;
    cJSON *j = cJSON_Parse("{\"EventId\":{\"type\":\"ByteString\",\"value\":\"aGlzdC1ldnQtMA==\"},"
                           "\"Time\":{\"type\":\"DateTime\",\"value\":\"2026-07-24T10:00:00Z\"},"
                           "\"Severity\":{\"type\":\"UInt16\",\"value\":700},"
                           "\"Message\":{\"type\":\"LocalizedText\",\"value\":{\"text\":\"x\"}},"
                           "\"EventType\":{\"type\":\"NodeId\",\"value\":\"i=2041\"},"
                           "\"SourceName\":\"src\",\"Nothing\":null}");
    T(j != NULL);
    T(hev_event_value(cJSON_GetObjectItem(j, "EventId"), &v, err, sizeof(err)) == 0 &&
      v.type == &UA_TYPES[UA_TYPES_BYTESTRING] && ((UA_ByteString *)v.data)->length == 10);
    UA_Variant_clear(&v);
    T(hev_event_value(cJSON_GetObjectItem(j, "Time"), &v, err, sizeof(err)) == 0 && v.type == &UA_TYPES[UA_TYPES_DATETIME]);
    UA_Variant_clear(&v);
    T(hev_event_value(cJSON_GetObjectItem(j, "Severity"), &v, err, sizeof(err)) == 0 &&
      v.type == &UA_TYPES[UA_TYPES_UINT16] && *(UA_UInt16 *)v.data == 700);
    UA_Variant_clear(&v);
    T(hev_event_value(cJSON_GetObjectItem(j, "Message"), &v, err, sizeof(err)) == 0 &&
      v.type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT] &&
      str_eq(&((UA_LocalizedText *)v.data)->text, "x"));
    UA_Variant_clear(&v);
    T(hev_event_value(cJSON_GetObjectItem(j, "EventType"), &v, err, sizeof(err)) == 0 &&
      v.type == &UA_TYPES[UA_TYPES_NODEID] && ((UA_NodeId *)v.data)->identifier.numeric == 2041);
    UA_Variant_clear(&v);
    T(hev_event_value(cJSON_GetObjectItem(j, "SourceName"), &v, err, sizeof(err)) == 0 && v.type == &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_clear(&v);
    T(hev_event_value(cJSON_GetObjectItem(j, "Nothing"), &v, err, sizeof(err)) == 0 && UA_Variant_isEmpty(&v));
    cJSON_Delete(j);
    j = cJSON_Parse("{\"type\":\"Bogus\",\"value\":1}");
    T(hev_event_value(j, &v, err, sizeof(err)) != 0);
    UA_Variant_clear(&v);
    cJSON_Delete(j);

    fprintf(stderr, "history-events self-test: %s (%d failure%s)\n",
            fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
