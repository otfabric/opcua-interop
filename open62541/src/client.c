#include "client.h"
#include "output.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <open62541.h>

/* BadNamespaceUriInvalid (0x80530000) is defined in the OPC UA spec Part 4
 * but not exposed by every open62541 version. Define it locally if absent. */
#ifndef UA_STATUSCODE_BADNAMESPACEURIINVALID
#define UA_STATUSCODE_BADNAMESPACEURIINVALID ((UA_StatusCode)0x80530000U)
#endif

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

static int parse_int_flag(int argc, char **argv, const char *flag, int def) {
    const char *v = find_arg(argc, argv, flag);
    if (!v) return def;
    int r = atoi(v);
    return (r > 0) ? r : def;
}

/* -------------------------------------------------------------------------
 * Base64 decode (for ByteString NodeIds)
 * ---------------------------------------------------------------------- */

static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Returns malloc'd buffer; sets *outLen. Returns NULL on error. */
static unsigned char *b64_decode(const char *in, size_t *outLen) {
    if (!in) { *outLen = 0; return NULL; }
    size_t inLen = strlen(in);
    if (inLen == 0) { *outLen = 0; return (unsigned char *)calloc(1, 1); }
    if (inLen % 4 != 0) { *outLen = 0; return NULL; }

    *outLen = inLen / 4 * 3;
    if (in[inLen-1] == '=') (*outLen)--;
    if (inLen >= 2 && in[inLen-2] == '=') (*outLen)--;

    unsigned char *out = (unsigned char *)malloc(*outLen + 1);
    if (!out) { *outLen = 0; return NULL; }

    size_t j = 0;
    for (size_t i = 0; i < inLen; i += 4) {
        int a = b64_char_val(in[i]);
        int b = b64_char_val(in[i+1]);
        int c = (in[i+2] == '=') ? 0 : b64_char_val(in[i+2]);
        int d = (in[i+3] == '=') ? 0 : b64_char_val(in[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(out); *outLen = 0; return NULL; }
        if (j < *outLen) out[j++] = (unsigned char)((a << 2) | (b >> 4));
        if (j < *outLen) out[j++] = (unsigned char)(((b & 0xf) << 4) | (c >> 2));
        if (j < *outLen) out[j++] = (unsigned char)(((c & 3) << 6) | d);
    }
    return out;
}

/* -------------------------------------------------------------------------
 * GUID parsing: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 * ---------------------------------------------------------------------- */

static int parse_guid_string(const char *s, UA_Guid *out) {
    if (!s) return 0;
    unsigned d1, d2, d3;
    unsigned b[8];
    if (sscanf(s, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               &d1, &d2, &d3,
               &b[0], &b[1], &b[2], &b[3],
               &b[4], &b[5], &b[6], &b[7]) != 11) return 0;
    out->data1 = (UA_UInt32)d1;
    out->data2 = (UA_UInt16)d2;
    out->data3 = (UA_UInt16)d3;
    for (int i = 0; i < 8; i++) out->data4[i] = (UA_Byte)b[i];
    return 1;
}

/* -------------------------------------------------------------------------
 * NodeId parsing
 * ---------------------------------------------------------------------- */

/*
 * Validate structural form of a NodeId string without resolving namespaces.
 * Returns 0 if structurally valid, -1 if malformed.
 */
static int validate_nodeid_structure(const char *s) {
    if (!s || !*s) return -1;
    /* i=N */
    if (strncmp(s, "i=", 2) == 0) {
        const char *rest = s + 2;
        if (!*rest) return -1;
        while (*rest) { if (*rest < '0' || *rest > '9') return -1; rest++; }
        return 0;
    }
    /* ns=N;<type>= */
    if (strncmp(s, "ns=", 3) == 0) {
        const char *semi = strchr(s + 3, ';');
        if (!semi) return -1;
        semi++;
        if (strncmp(semi, "s=", 2) == 0 ||
            strncmp(semi, "i=", 2) == 0 ||
            strncmp(semi, "g=", 2) == 0 ||
            strncmp(semi, "b=", 2) == 0)
            return 0;
        return -1;
    }
    /* nsu=URI;<type>= */
    if (strncmp(s, "nsu=", 4) == 0) {
        const char *semi = strchr(s + 4, ';');
        if (!semi) return -1;
        semi++;
        if (strncmp(semi, "s=", 2) == 0 ||
            strncmp(semi, "i=", 2) == 0 ||
            strncmp(semi, "g=", 2) == 0 ||
            strncmp(semi, "b=", 2) == 0)
            return 0;
        return -1;
    }
    return -1;
}

/*
 * Parse a NodeId string that uses ns= or i= prefixes (not nsu=).
 * The client may be NULL for these forms.
 * Returns a UA_NodeId — caller must UA_NodeId_clear() when done.
 * Returns UA_NODEID_NULL on error.
 */
static UA_NodeId parse_nodeid_local(const char *s) {
    if (!s) return UA_NODEID_NULL;

    if (strncmp(s, "i=", 2) == 0)
        return UA_NODEID_NUMERIC(0, (UA_UInt32)atoi(s + 2));

    if (strncmp(s, "ns=", 3) == 0) {
        UA_UInt16 ns = (UA_UInt16)atoi(s + 3);
        const char *semi = strchr(s + 3, ';');
        if (!semi) return UA_NODEID_NULL;
        semi++;
        if (strncmp(semi, "s=", 2) == 0)
            return UA_NODEID_STRING_ALLOC(ns, semi + 2);
        if (strncmp(semi, "i=", 2) == 0)
            return UA_NODEID_NUMERIC(ns, (UA_UInt32)atoi(semi + 2));
        if (strncmp(semi, "g=", 2) == 0) {
            UA_Guid guid;
            memset(&guid, 0, sizeof(guid));
            if (!parse_guid_string(semi + 2, &guid)) return UA_NODEID_NULL;
            return UA_NODEID_GUID(ns, guid);
        }
        if (strncmp(semi, "b=", 2) == 0) {
            size_t decoded_len;
            unsigned char *decoded = b64_decode(semi + 2, &decoded_len);
            if (!decoded) return UA_NODEID_NULL;
            UA_NodeId nid;
            UA_NodeId_init(&nid);
            nid.namespaceIndex = ns;
            nid.identifierType = UA_NODEIDTYPE_BYTESTRING;
            nid.identifier.byteString.data   = decoded;
            nid.identifier.byteString.length = decoded_len;
            return nid;
        }
        return UA_NODEID_NULL;
    }

    return UA_NODEID_NULL;
}

/*
 * Resolve a nsu= NodeId after connecting.
 * Returns 0 on success (out is populated, caller must UA_NodeId_clear()),
 * -1 on namespace-not-found (unknown URI), -2 on other error.
 */
static int resolve_nsu_nodeid(UA_Client *client, const char *s, UA_NodeId *out) {
    if (!s || strncmp(s, "nsu=", 4) != 0) return -2;

    const char *uri_start = s + 4;
    const char *semi = strchr(uri_start, ';');
    if (!semi) return -2;

    size_t uri_len = (size_t)(semi - uri_start);
    char *uri = (char *)malloc(uri_len + 1);
    if (!uri) return -2;
    memcpy(uri, uri_start, uri_len);
    uri[uri_len] = '\0';

    UA_String uri_str;
    uri_str.data   = (UA_Byte *)uri;
    uri_str.length = uri_len;

    UA_UInt32 nsIdx32 = 0;
    UA_StatusCode sc = UA_Client_NamespaceGetIndex(client, &uri_str, &nsIdx32);
    free(uri);

    if (sc != UA_STATUSCODE_GOOD) return -1;

    UA_UInt16 nsIdx = (UA_UInt16)nsIdx32;
    const char *id = semi + 1;

    if (strncmp(id, "s=", 2) == 0) {
        *out = UA_NODEID_STRING_ALLOC(nsIdx, id + 2);
        return 0;
    }
    if (strncmp(id, "i=", 2) == 0) {
        *out = UA_NODEID_NUMERIC(nsIdx, (UA_UInt32)atoi(id + 2));
        return 0;
    }
    if (strncmp(id, "g=", 2) == 0) {
        UA_Guid guid;
        memset(&guid, 0, sizeof(guid));
        if (!parse_guid_string(id + 2, &guid)) return -2;
        *out = UA_NODEID_GUID(nsIdx, guid);
        return 0;
    }
    if (strncmp(id, "b=", 2) == 0) {
        size_t decoded_len;
        unsigned char *decoded = b64_decode(id + 2, &decoded_len);
        if (!decoded) return -2;
        UA_NodeId_init(out);
        out->namespaceIndex = nsIdx;
        out->identifierType = UA_NODEIDTYPE_BYTESTRING;
        out->identifier.byteString.data   = decoded;
        out->identifier.byteString.length = decoded_len;
        return 0;
    }
    return -2;
}

/* -------------------------------------------------------------------------
 * DataType name for a UA_DataType pointer
 * ---------------------------------------------------------------------- */

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
 * Endpoint security check
 * ---------------------------------------------------------------------- */

static const char k_none_policy[] =
    "http://opcfoundation.org/UA/SecurityPolicy#None";

/*
 * Returns 1 if the server at url has a SecurityPolicy#None / None endpoint.
 * Returns 0 on error or not found; fills *out_sc with the GetEndpoints result.
 */
static int endpoint_has_none_security(const char *url, UA_StatusCode *out_sc) {
    UA_Client *c = UA_Client_new();
    if (!c) { *out_sc = UA_STATUSCODE_BADOUTOFMEMORY; return 0; }
    UA_ClientConfig_setDefault(UA_Client_getConfig(c));

    UA_EndpointDescription *eps = NULL;
    size_t epCount = 0;
    UA_StatusCode sc = UA_Client_getEndpoints(c, url, &epCount, &eps);
    UA_Client_delete(c);
    *out_sc = sc;

    if (sc != UA_STATUSCODE_GOOD) return 0;

    int found = 0;
    for (size_t i = 0; i < epCount && !found; i++) {
        if (eps[i].securityMode != UA_MESSAGESECURITYMODE_NONE) continue;
        const UA_String *uri = &eps[i].securityPolicyUri;
        size_t pol_len = sizeof(k_none_policy) - 1;
        if (uri->length == pol_len &&
            memcmp(uri->data, k_none_policy, pol_len) == 0)
            found = 1;
    }
    if (eps) UA_Array_delete(eps, epCount, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    return found;
}

/* -------------------------------------------------------------------------
 * Client connect helper
 * ---------------------------------------------------------------------- */

/*
 * Checks endpoint security then creates and connects a client.
 * On failure: emits the complete error envelope for operation op, sets
 * *exit_code to 3, and returns NULL.
 * On success: returns a connected UA_Client* (caller must disconnect+delete).
 */
static UA_Client *make_client(const char *url,
                               int request_ms,
                               const char *op,
                               int *exit_code) {
    /* Verify a None/None endpoint exists */
    UA_StatusCode ep_sc = UA_STATUSCODE_GOOD;
    if (!endpoint_has_none_security(url, &ep_sc)) {
        UA_StatusCode err_sc = (ep_sc != UA_STATUSCODE_GOOD)
                               ? ep_sc
                               : UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
        const char *msg = (ep_sc != UA_STATUSCODE_GOOD)
                          ? "GetEndpoints request failed"
                          : "no SecurityPolicy#None/None endpoint available";
        output_begin("open62541", op);
        output_success(0);
        output_service_result(err_sc);
        output_error("transport", msg);
        output_end();
        *exit_code = 3;
        return NULL;
    }

    UA_Client *client = UA_Client_new();
    if (!client) {
        output_begin("open62541", op);
        output_success(0);
        output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
        output_error("internal", "UA_Client_new failed");
        output_end();
        *exit_code = 6;
        return NULL;
    }

    UA_ClientConfig *cfg = UA_Client_getConfig(client);
    UA_ClientConfig_setDefault(cfg);
    if (request_ms > 0)
        cfg->timeout = (UA_UInt32)request_ms;
    cfg->connectivityCheckInterval = 0;

    UA_StatusCode sc = UA_Client_connect(client, url);
    if (sc != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        const char *msg;
        int ec;
        if (sc == UA_STATUSCODE_BADTIMEOUT) {
            msg = "connection timed out";
            ec  = 7;
        } else {
            msg = "failed to connect";
            ec  = 3;
        }
        output_begin("open62541", op);
        output_success(0);
        output_service_result(sc);
        output_error((ec == 7) ? "timeout" : "transport", msg);
        output_end();
        *exit_code = ec;
        return NULL;
    }

    return client;
}

/* -------------------------------------------------------------------------
 * NodeId resolution helper — validate + parse all --node args
 * ---------------------------------------------------------------------- */

#define MAX_NODES 128

/*
 * Validate node strings, parse non-nsu forms, connect client (via make_client),
 * then resolve nsu= forms.
 *
 * nodes[]  - raw --node arg strings
 * n        - count
 * ids[]    - output UA_NodeId array (caller must UA_NodeId_clear each)
 * op       - operation name for error envelopes
 * url      - endpoint URL
 * req_ms   - request timeout in ms
 * exit_code - set on failure
 *
 * Returns connected client on success, NULL on failure (envelope already emitted).
 */
static UA_Client *resolve_node_ids(const char **nodes, int n,
                                    UA_NodeId *ids,
                                    const char *op,
                                    const char *url,
                                    int req_ms,
                                    int *exit_code) {
    /* Phase 1: structural validation (before any network I/O) */
    for (int i = 0; i < n; i++) {
        if (validate_nodeid_structure(nodes[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodes[i]);
            output_begin("open62541", op);
            output_success(0);
            output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
            output_error("input", msg);
            output_end();
            *exit_code = 2;
            return NULL;
        }
    }

    /* Phase 2: parse non-nsu forms */
    int has_nsu = 0;
    for (int i = 0; i < n; i++) {
        UA_NodeId_init(&ids[i]);
        if (strncmp(nodes[i], "nsu=", 4) == 0) {
            has_nsu = 1;
        } else {
            ids[i] = parse_nodeid_local(nodes[i]);
        }
    }

    /* Phase 3: connect */
    UA_Client *client = make_client(url, req_ms, op, exit_code);
    if (!client) {
        for (int i = 0; i < n; i++) UA_NodeId_clear(&ids[i]);
        return NULL;
    }

    /* Phase 4: resolve nsu= forms */
    if (has_nsu) {
        for (int i = 0; i < n; i++) {
            if (strncmp(nodes[i], "nsu=", 4) != 0) continue;

            int r = resolve_nsu_nodeid(client, nodes[i], &ids[i]);
            if (r != 0) {
                /* Clean up already-resolved ids */
                for (int j = 0; j < n; j++) UA_NodeId_clear(&ids[j]);
                UA_Client_disconnect(client);
                UA_Client_delete(client);

                char msg[512];
                if (r == -1) {
                    /* Extract URI for message */
                    const char *uri_end = strchr(nodes[i] + 4, ';');
                    if (uri_end) {
                        int uri_len = (int)(uri_end - (nodes[i] + 4));
                        snprintf(msg, sizeof(msg), "unknown namespace URI: '%.*s'",
                                 uri_len, nodes[i] + 4);
                    } else {
                        snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodes[i]);
                    }
                    output_begin("open62541", op);
                    output_success(0);
                    output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
                    output_error("input", msg);
                    output_end();
                } else {
                    snprintf(msg, sizeof(msg), "failed to resolve NodeId: '%s'", nodes[i]);
                    output_begin("open62541", op);
                    output_success(0);
                    output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
                    output_error("input", msg);
                    output_end();
                }
                *exit_code = 2;
                return NULL;
            }
        }
    }

    return client;
}

/* -------------------------------------------------------------------------
 * Security mode name
 * ---------------------------------------------------------------------- */

static const char *security_mode_name(UA_MessageSecurityMode mode) {
    switch (mode) {
        case UA_MESSAGESECURITYMODE_NONE:           return "None";
        case UA_MESSAGESECURITYMODE_SIGN:           return "Sign";
        case UA_MESSAGESECURITYMODE_SIGNANDENCRYPT: return "SignAndEncrypt";
        default:                                    return "Invalid";
    }
}

/* -------------------------------------------------------------------------
 * endpoints subcommand
 * ---------------------------------------------------------------------- */

static int cmd_endpoints(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        output_begin("open62541", "endpoints");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    UA_Client *client = UA_Client_new();
    if (!client) {
        output_begin("open62541", "endpoints");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
        output_error("internal", "UA_Client_new failed");
        output_end();
        return 6;
    }
    UA_ClientConfig_setDefault(UA_Client_getConfig(client));

    UA_EndpointDescription *eps = NULL;
    size_t epCount = 0;
    UA_StatusCode sc = UA_Client_getEndpoints(client, endpoint, &epCount, &eps);
    UA_Client_delete(client);

    int ok = (sc == UA_STATUSCODE_GOOD);
    output_begin("open62541", "endpoints");
    output_success(ok);
    output_service_result(sc);

    if (ok) {
        output_open_results();
        for (size_t i = 0; i < epCount; i++) {
            UA_EndpointDescription *ep = &eps[i];
            if (i > 0) printf(",");

            char url_buf[512] = "";
            if (ep->endpointUrl.data && ep->endpointUrl.length < sizeof(url_buf) - 1) {
                memcpy(url_buf, ep->endpointUrl.data, ep->endpointUrl.length);
                url_buf[ep->endpointUrl.length] = '\0';
            }

            char pol_buf[512] = "";
            if (ep->securityPolicyUri.data &&
                ep->securityPolicyUri.length < sizeof(pol_buf) - 1) {
                memcpy(pol_buf, ep->securityPolicyUri.data, ep->securityPolicyUri.length);
                pol_buf[ep->securityPolicyUri.length] = '\0';
            }

            printf("{\"url\":\"%s\",\"securityPolicy\":\"%s\",\"securityMode\":\"%s\"}",
                   url_buf, pol_buf, security_mode_name(ep->securityMode));
        }
        output_close_results();
        output_null_error();
    } else {
        output_error("transport", "GetEndpoints failed");
    }

    output_end();
    if (eps) UA_Array_delete(eps, epCount, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    return ok ? 0 : 3;
}

/* -------------------------------------------------------------------------
 * read subcommand
 * ---------------------------------------------------------------------- */

static int cmd_read(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        output_begin("open62541", "read");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;

    /* Collect all --node arguments */
    int node_count = count_flag(argc, argv, "--node");
    if (node_count == 0) {
        output_begin("open62541", "read");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --node");
        output_end();
        return 2;
    }
    if (node_count > MAX_NODES) node_count = MAX_NODES;

    const char *nodes[MAX_NODES];
    int n = 0;
    for (int i = 0; i < argc - 1 && n < MAX_NODES; i++) {
        if (strcmp(argv[i], "--node") == 0)
            nodes[n++] = argv[i + 1];
    }

    UA_NodeId ids[MAX_NODES];
    int exit_code = 3;
    UA_Client *client = resolve_node_ids(nodes, n, ids, "read", endpoint, req_ms, &exit_code);
    if (!client) return exit_code;

    /* Batch read via ReadService */
    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.timestampsToReturn = UA_TIMESTAMPSTORETURN_SOURCE;
    req.nodesToRead = (UA_ReadValueId *)UA_Array_new((size_t)n,
                          &UA_TYPES[UA_TYPES_READVALUEID]);
    req.nodesToReadSize = (size_t)n;

    for (int i = 0; i < n; i++) {
        UA_ReadValueId_init(&req.nodesToRead[i]);
        UA_NodeId_copy(&ids[i], &req.nodesToRead[i].nodeId);
        req.nodesToRead[i].attributeId = UA_ATTRIBUTEID_VALUE;
    }

    UA_ReadResponse resp = UA_Client_Service_read(client, req);
    UA_ReadRequest_clear(&req);

    UA_StatusCode svc_sc = resp.responseHeader.serviceResult;

    /* Determine overall success: service must be Good, and all per-item Good */
    int all_good = UA_StatusCode_isGood(svc_sc);
    if (all_good) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i].status)) {
                all_good = 0;
                break;
            }
        }
    }

    /* Promote worst per-item status to serviceResult when service itself is Good */
    UA_StatusCode emit_sc = svc_sc;
    if (UA_StatusCode_isGood(svc_sc) && !all_good) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i].status)) {
                emit_sc = resp.results[i].status;
                break;
            }
        }
    }

    output_begin("open62541", "read");
    output_success(all_good);
    output_service_result(emit_sc);
    output_open_results();

    if (UA_StatusCode_isGood(svc_sc)) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            UA_DataValue *dv = &resp.results[i];
            const char *dt_name = (dv->hasValue && dv->value.type)
                                   ? type_name(dv->value.type) : "Unknown";
            int bi = (dv->hasValue && dv->value.type)
                      ? ua_type_to_builtin_id(dv->value.type) : 0;
            UA_DateTime src_ts = dv->hasSourceTimestamp ? dv->sourceTimestamp : 0;
            if (i > 0) printf(",");
            output_read_result_item(nodes[i], dv->status, dt_name, bi,
                                    dv->hasValue ? &dv->value : NULL, src_ts);
        }
    }

    output_close_results();
    output_null_error();
    output_end();

    UA_ReadResponse_clear(&resp);
    for (int i = 0; i < n; i++) UA_NodeId_clear(&ids[i]);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (svc_sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    if (!UA_StatusCode_isGood(svc_sc))      return 4;
    if (!all_good)                           return 4;
    return 0;
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
        SET_SCALAR(UA_TYPES_BOOLEAN, UA_Boolean,
                   strcmp(valStr,"true")==0 || strcmp(valStr,"1")==0)
    if (strcmp(typeStr, "SByte")   == 0) SET_SCALAR(UA_TYPES_SBYTE,  UA_SByte,  atoi(valStr))
    if (strcmp(typeStr, "Byte")    == 0) SET_SCALAR(UA_TYPES_BYTE,   UA_Byte,   atoi(valStr))
    if (strcmp(typeStr, "Int16")   == 0) SET_SCALAR(UA_TYPES_INT16,  UA_Int16,  atoi(valStr))
    if (strcmp(typeStr, "UInt16")  == 0) SET_SCALAR(UA_TYPES_UINT16, UA_UInt16, atoi(valStr))
    if (strcmp(typeStr, "Int32")   == 0) SET_SCALAR(UA_TYPES_INT32,  UA_Int32,  atoi(valStr))
    if (strcmp(typeStr, "UInt32")  == 0)
        SET_SCALAR(UA_TYPES_UINT32, UA_UInt32, (uint32_t)strtoul(valStr,NULL,10))
    if (strcmp(typeStr, "Int64")   == 0)
        SET_SCALAR(UA_TYPES_INT64,  UA_Int64,  strtoll(valStr,NULL,10))
    if (strcmp(typeStr, "UInt64")  == 0)
        SET_SCALAR(UA_TYPES_UINT64, UA_UInt64, strtoull(valStr,NULL,10))
    if (strcmp(typeStr, "Float")   == 0)
        SET_SCALAR(UA_TYPES_FLOAT,  UA_Float,  (float)atof(valStr))
    if (strcmp(typeStr, "Double")  == 0)
        SET_SCALAR(UA_TYPES_DOUBLE, UA_Double, atof(valStr))
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
        output_begin("open62541", "write");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
                     "usage: write --endpoint <url> --node <id> --type <t> --value <v>");
        output_end();
        return 2;
    }

    /* Validate NodeId structure before connecting */
    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "write");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "write", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId;
    UA_NodeId_init(&nodeId);

    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        int r = resolve_nsu_nodeid(client, nodeStr, &nodeId);
        if (r != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            if (r == -1) {
                const char *uri_end = strchr(nodeStr + 4, ';');
                if (uri_end) {
                    snprintf(msg, sizeof(msg), "unknown namespace URI: '%.*s'",
                             (int)(uri_end - (nodeStr + 4)), nodeStr + 4);
                } else {
                    snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
                }
            } else {
                snprintf(msg, sizeof(msg), "failed to resolve NodeId: '%s'", nodeStr);
            }
            output_begin("open62541", "write");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    UA_Variant var = build_write_variant(typeStr, valStr);
    UA_StatusCode sc = UA_Client_writeValueAttribute(client, nodeId, &var);

    int ok = UA_StatusCode_isGood(sc);
    output_begin("open62541", "write");
    output_success(ok);
    output_service_result(sc);
    output_write_result(nodeStr, sc);
    output_end();

    int ret;
    if (sc == UA_STATUSCODE_BADTIMEOUT)     ret = 7;
    else if (!ok)                            ret = 4;
    else                                     ret = 0;

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
    if (!endpoint) {
        output_begin("open62541", "browse");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    /* Default starting node: i=85 (Objects folder) */
    const char *nodeStr = find_arg(argc, argv, "--node");
    if (!nodeStr) nodeStr = "i=85";

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "browse");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int max_refs = parse_int_flag(argc, argv, "--max-refs", 0);
    int req_ms   = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;

    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "browse", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId;
    UA_NodeId_init(&nodeId);

    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        int r = resolve_nsu_nodeid(client, nodeStr, &nodeId);
        if (r != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            if (r == -1) {
                const char *uri_end = strchr(nodeStr + 4, ';');
                if (uri_end)
                    snprintf(msg, sizeof(msg), "unknown namespace URI: '%.*s'",
                             (int)(uri_end - (nodeStr + 4)), nodeStr + 4);
                else
                    snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            } else {
                snprintf(msg, sizeof(msg), "failed to resolve NodeId: '%s'", nodeStr);
            }
            output_begin("open62541", "browse");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    /* Initial browse request */
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.requestedMaxReferencesPerNode = (UA_UInt32)max_refs;
    req.nodesToBrowse = UA_BrowseDescription_new();
    req.nodesToBrowseSize = 1;
    UA_NodeId_copy(&nodeId, &req.nodesToBrowse[0].nodeId);
    req.nodesToBrowse[0].browseDirection = UA_BROWSEDIRECTION_FORWARD;
    req.nodesToBrowse[0].resultMask      = UA_BROWSERESULTMASK_ALL;

    UA_BrowseResponse resp = UA_Client_Service_browse(client, req);
    UA_BrowseRequest_clear(&req);

    UA_StatusCode sc = resp.responseHeader.serviceResult;

    /* Accumulate all references, following continuation points */
    UA_ReferenceDescription *allRefs  = NULL;
    size_t                   allCount = 0;

    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0) {
        size_t initial = resp.results[0].referencesSize;
        if (initial > 0) {
            allRefs = (UA_ReferenceDescription *)UA_Array_new(
                initial, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
            if (allRefs) {
                for (size_t i = 0; i < initial; i++)
                    UA_ReferenceDescription_copy(&resp.results[0].references[i],
                                                 &allRefs[i]);
                allCount = initial;
            }
        }

        /* Follow continuation points */
        UA_ByteString cp = UA_BYTESTRING_NULL;
        UA_ByteString_copy(&resp.results[0].continuationPoint, &cp);

        while (cp.length > 0) {
            UA_BrowseNextRequest nreq;
            UA_BrowseNextRequest_init(&nreq);
            nreq.releaseContinuationPoints     = UA_FALSE;
            nreq.continuationPoints            = &cp;
            nreq.continuationPointsSize        = 1;

            UA_BrowseNextResponse nresp = UA_Client_Service_browseNext(client, nreq);

            if (nresp.responseHeader.serviceResult != UA_STATUSCODE_GOOD ||
                nresp.resultsSize == 0) {
                UA_BrowseNextResponse_clear(&nresp);
                break;
            }

            size_t extra = nresp.results[0].referencesSize;
            if (extra > 0) {
                size_t newCount = allCount + extra;
                UA_ReferenceDescription *newRefs = (UA_ReferenceDescription *)
                    UA_Array_new(newCount, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
                if (newRefs) {
                    for (size_t i = 0; i < allCount; i++)
                        UA_ReferenceDescription_copy(&allRefs[i], &newRefs[i]);
                    for (size_t i = 0; i < extra; i++)
                        UA_ReferenceDescription_copy(&nresp.results[0].references[i],
                                                     &newRefs[allCount + i]);
                    if (allRefs)
                        UA_Array_delete(allRefs, allCount,
                                        &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
                    allRefs  = newRefs;
                    allCount = newCount;
                }
            }

            UA_ByteString_clear(&cp);
            UA_ByteString_copy(&nresp.results[0].continuationPoint, &cp);
            UA_BrowseNextResponse_clear(&nresp);
        }
        UA_ByteString_clear(&cp);
    }

    UA_BrowseResponse_clear(&resp);

    int ok = UA_StatusCode_isGood(sc);
    output_begin("open62541", "browse");
    output_success(ok);
    output_service_result(sc);

    if (ok) {
        output_browse_results(allRefs, allCount);
    } else {
        output_error("service", "Browse service failed");
    }

    output_end();

    if (allRefs)
        UA_Array_delete(allRefs, allCount, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * call subcommand
 * ---------------------------------------------------------------------- */

static int cmd_call(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *objStr   = find_arg(argc, argv, "--object");
    const char *methStr  = find_arg(argc, argv, "--method");
    if (!endpoint || !objStr || !methStr) {
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: call --endpoint <url> --object <nodeId> --method <nodeId>"
            " [--input <type:val> ...]");
        output_end();
        return 2;
    }

    if (validate_nodeid_structure(objStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", objStr);
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }
    if (validate_nodeid_structure(methStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", methStr);
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int req_ms   = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "call", &exit_code);
    if (!client) return exit_code;

    UA_NodeId objectId; UA_NodeId_init(&objectId);
    UA_NodeId methodId; UA_NodeId_init(&methodId);

    int   resolve_rc = 0;
    char  resolve_msg[512] = "";

    if (strncmp(objStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, objStr, &objectId) != 0) {
            snprintf(resolve_msg, sizeof(resolve_msg),
                     "unknown namespace URI in object NodeId: '%s'", objStr);
            resolve_rc = 1;
        }
    } else {
        objectId = parse_nodeid_local(objStr);
    }

    if (resolve_rc == 0 && strncmp(methStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, methStr, &methodId) != 0) {
            snprintf(resolve_msg, sizeof(resolve_msg),
                     "unknown namespace URI in method NodeId: '%s'", methStr);
            resolve_rc = 1;
        }
    } else if (resolve_rc == 0) {
        methodId = parse_nodeid_local(methStr);
    }

    if (resolve_rc != 0) {
        UA_NodeId_clear(&objectId);
        UA_NodeId_clear(&methodId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
        output_error("input", resolve_msg);
        output_end();
        return 2;
    }

    int inCount = count_flag(argc, argv, "--input");
    UA_Variant *inputs = (UA_Variant *)calloc(
        (size_t)(inCount > 0 ? inCount : 1), sizeof(UA_Variant));
    if (!inputs) {
        UA_NodeId_clear(&objectId);
        UA_NodeId_clear(&methodId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        return 6;
    }

    int ni = 0;
    for (int i = 0; i < argc - 1 && ni < inCount; i++) {
        if (strcmp(argv[i], "--input") == 0) {
            const char *spec  = argv[i + 1];
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

    UA_Variant *outputs     = NULL;
    size_t      outputsSize = 0;
    UA_StatusCode sc = UA_Client_call(client, objectId, methodId,
                                      (size_t)inCount, inputs,
                                      &outputsSize, &outputs);

    int ok = UA_StatusCode_isGood(sc);
    output_begin("open62541", "call");
    output_success(ok);
    output_service_result(sc);
    output_open_results();
    output_call_result(objStr, methStr, sc, outputs, outputsSize);
    output_close_results();
    output_null_error();
    output_end();

    int ret;
    if      (sc == UA_STATUSCODE_BADTIMEOUT) ret = 7;
    else if (!ok)                             ret = 4;
    else                                      ret = 0;

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

#define MAX_NOTIFICATIONS 256

typedef struct {
    int      index;
    uint32_t statusCode;
    char     dataType[64];
    int      builtInType;
    char     valueJson[512];
    char     sourceTimestamp[64];
} NotifEntry;

typedef struct {
    int        wanted;
    int        count;
    NotifEntry entries[MAX_NOTIFICATIONS];
} NotifStore;

static void sub_data_change_cb(UA_Client *client, UA_UInt32 subId,
    void *subCtx, UA_UInt32 monId, void *monCtx, UA_DataValue *val) {
    (void)client; (void)subId; (void)subCtx; (void)monId;
    NotifStore *store = (NotifStore *)monCtx;
    if (!store || store->count >= MAX_NOTIFICATIONS) return;

    NotifEntry *e = &store->entries[store->count];
    e->index      = store->count;
    e->statusCode = (uint32_t)(val->hasStatus ? val->status : UA_STATUSCODE_GOOD);
    e->sourceTimestamp[0] = '\0';
    if (val->hasSourceTimestamp)
        output_timestamp(val->sourceTimestamp, e->sourceTimestamp,
                         sizeof(e->sourceTimestamp));

    if (val->hasValue && val->value.type) {
        strncpy(e->dataType, type_name(val->value.type), sizeof(e->dataType) - 1);
        e->dataType[sizeof(e->dataType) - 1] = '\0';
        e->builtInType = ua_type_to_builtin_id(val->value.type);
        output_variant_to_buf(&val->value, e->valueJson, sizeof(e->valueJson));
    } else {
        strcpy(e->dataType,  "Unknown");
        e->builtInType = 0;
        strcpy(e->valueJson, "null");
    }
    store->count++;
}

static int cmd_subscribe(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    const char *piStr    = find_arg(argc, argv, "--publishing-interval-ms");
    const char *siStr    = find_arg(argc, argv, "--sampling-interval-ms");
    const char *nStr     = find_arg(argc, argv, "--notifications");
    const char *toStr    = find_arg(argc, argv, "--timeout-ms");

    if (!endpoint || !nodeStr) {
        output_begin("open62541", "subscribe");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: subscribe --endpoint <url> --node <nodeId>"
            " [--notifications <n>] [--timeout-ms <ms>]");
        output_end();
        return 2;
    }

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "subscribe");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    double piMs    = piStr ? atof(piStr) : 500.0;
    double siMs    = siStr ? atof(siStr) : 100.0;
    int    nWanted = nStr  ? atoi(nStr)  : 5;
    int    toMs    = toStr ? atoi(toStr) : 10000;
    if (nWanted <= 0) nWanted = 5;
    if (nWanted > MAX_NOTIFICATIONS) nWanted = MAX_NOTIFICATIONS;

    int exit_code = 3;
    UA_Client *client = make_client(endpoint, 5000, "subscribe", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId; UA_NodeId_init(&nodeId);
    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            output_begin("open62541", "subscribe");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval  = piMs;
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode svc_sc = subResp.responseHeader.serviceResult;
    if (!UA_StatusCode_isGood(svc_sc)) {
        UA_NodeId_clear(&nodeId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        output_begin("open62541", "subscribe");
        output_success(0);
        output_service_result(svc_sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = nWanted;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    monReq.requestedParameters.samplingInterval = siMs;
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subResp.subscriptionId, UA_TIMESTAMPSTORETURN_BOTH,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode mon_sc = monResp.statusCode;

    int timedOut = 0;
    if (UA_StatusCode_isGood(mon_sc)) {
        time_t start = time(NULL);
        while (store.count < nWanted) {
            if ((int)(difftime(time(NULL), start) * 1000.0) >= toMs) {
                timedOut = 1;
                break;
            }
            UA_Client_run_iterate(client, 100);
        }
    }

    int all_ok   = UA_StatusCode_isGood(mon_sc) && !timedOut;
    UA_StatusCode emit_sc = UA_StatusCode_isGood(mon_sc) ? svc_sc : mon_sc;

    output_begin("open62541", "subscribe");
    output_success(all_ok);
    output_service_result(emit_sc);

    printf(",\"results\":[{\"nodeId\":");
    output_nodeid(&nodeId);
    printf(",\"monitoredItemStatusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
           ",\"severity\":\"%s\"}",
           output_status_code_name(mon_sc), (uint32_t)mon_sc,
           output_severity(mon_sc));
    printf(",\"notifications\":[");
    for (int i = 0; i < store.count; i++) {
        NotifEntry *e = &store.entries[i];
        if (i > 0) printf(",");
        printf("{\"sequenceNumber\":%d", e->index + 1);
        printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
               ",\"severity\":\"%s\"}",
               output_status_code_name((UA_StatusCode)e->statusCode),
               e->statusCode,
               output_severity((UA_StatusCode)e->statusCode));
        printf(",\"dataType\":\"%s\"", e->dataType);
        printf(",\"builtInType\":%d", e->builtInType);
        printf(",\"value\":%s", e->valueJson);
        if (e->sourceTimestamp[0])
            printf(",\"sourceTimestamp\":\"%s\"", e->sourceTimestamp);
        printf("}");
    }
    printf("]}]");

    if (timedOut)
        printf(",\"error\":{\"category\":\"timeout\","
               "\"message\":\"timeout waiting for notifications\"}");
    else
        printf(",\"error\":null");
    output_end();

    UA_Client_Subscriptions_deleteSingle(client, subResp.subscriptionId);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return timedOut ? 7 : 0;
}

/* -------------------------------------------------------------------------
 * Dispatch
 * ---------------------------------------------------------------------- */

int client_run(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: client <endpoints|read|write|browse|call|subscribe> ...\n");
        return 2;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "endpoints")  == 0) return cmd_endpoints(argc - 1, argv + 1);
    if (strcmp(sub, "read")       == 0) return cmd_read(argc - 1, argv + 1);
    if (strcmp(sub, "write")      == 0) return cmd_write(argc - 1, argv + 1);
    if (strcmp(sub, "browse")     == 0) return cmd_browse(argc - 1, argv + 1);
    if (strcmp(sub, "call")       == 0) return cmd_call(argc - 1, argv + 1);
    if (strcmp(sub, "subscribe")  == 0) return cmd_subscribe(argc - 1, argv + 1);
    fprintf(stderr, "unknown client subcommand: %s\n", sub);
    return 2;
}
