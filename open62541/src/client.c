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

/* Silent logger: discard all open62541 log output so that only JSON goes to
 * stdout.  The adapter's client operations are designed to emit exactly one
 * JSON line on stdout; mixing in open62541's colourised info/warn messages
 * would break envelope validation in the smoke harness. */
static void silent_log(void *ctx, UA_LogLevel level, UA_LogCategory cat,
                       const char *msg, va_list args) {
    (void)ctx; (void)level; (void)cat; (void)msg; (void)args;
}
static UA_Logger g_silent_logger = { silent_log, NULL, NULL };

/* Apply the silent logger to a freshly-initialised client config, including
 * the event loop that is created by UA_ClientConfig_setDefault. */
static void client_silence_logger(UA_ClientConfig *cfg) {
    cfg->logging = &g_silent_logger;
    if (cfg->eventLoop)
        cfg->eventLoop->logger = &g_silent_logger;
}

/* Load a binary (DER) file into a UA_ByteString.  Returns UA_BYTESTRING_NULL
 * on any error. */
static UA_ByteString load_cert_file(const char *path) {
    UA_ByteString bs = UA_BYTESTRING_NULL;
    if (!path || !*path) return bs;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[open62541] warn: cannot open %s: %s\n", path, strerror(errno));
        return bs;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return bs; }
    bs.data = (UA_Byte *)UA_malloc((size_t)sz);
    if (!bs.data) { fclose(f); return bs; }
    bs.length = (size_t)fread(bs.data, 1, (size_t)sz, f);
    fclose(f);
    if (bs.length != (size_t)sz) {
        UA_ByteString_clear(&bs);
        return UA_BYTESTRING_NULL;
    }
    return bs;
}

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
 * Global security configuration (parsed once in client_run before dispatch)
 * ---------------------------------------------------------------------- */

typedef struct {
    const char  *policyName;    /* "None", "Basic256Sha256", etc. */
    const char  *modeName;      /* "None", "Sign", "SignAndEncrypt" */
    const char  *certFile;      /* DER client application cert */
    const char  *keyFile;       /* DER private key */
    const char **trustFiles;    /* array of --trust-list values */
    int          trustCount;
    const char  *username;      /* NULL = anonymous */
    const char  *password;      /* NULL = treat as empty string */
} ClientSecurity;

static ClientSecurity g_sec = { "None", "None", NULL, NULL, NULL, 0, NULL, NULL };

static UA_MessageSecurityMode security_mode_enum(const char *s) {
    if (!s || strcmp(s, "None") == 0)        return UA_MESSAGESECURITYMODE_NONE;
    if (strcmp(s, "Sign") == 0)              return UA_MESSAGESECURITYMODE_SIGN;
    if (strcmp(s, "SignAndEncrypt") == 0)    return UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    return UA_MESSAGESECURITYMODE_NONE;
}

static const char *security_policy_uri(const char *name) {
    static const struct { const char *n; const char *uri; } tbl[] = {
        { "None",               "http://opcfoundation.org/UA/SecurityPolicy#None"               },
        { "Basic128Rsa15",      "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"      },
        { "Basic256",           "http://opcfoundation.org/UA/SecurityPolicy#Basic256"           },
        { "Basic256Sha256",     "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"     },
        { "Aes128_Sha256_RsaOaep","http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"},
        { "Aes256_Sha256_RsaPss","http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss" },
    };
    for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++) {
        if (name && strcmp(name, tbl[i].n) == 0) return tbl[i].uri;
    }
    return tbl[0].uri; /* fallback: None */
}

static UA_Boolean security_is_none(void) {
    return security_mode_enum(g_sec.modeName) == UA_MESSAGESECURITYMODE_NONE;
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

    UA_UInt16 nsIdx = 0;
    UA_StatusCode sc = UA_Client_NamespaceGetIndex(client, &uri_str, &nsIdx);
    free(uri);

    if (sc != UA_STATUSCODE_GOOD) return -1;
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

/*
 * Returns 1 if the server at url has an endpoint matching the globally
 * configured security policy and mode.
 * Returns 0 on error or not found; fills *out_sc with the GetEndpoints result.
 */
static int endpoint_check_security(const char *url, UA_StatusCode *out_sc) {
    UA_Client *c = UA_Client_new();
    if (!c) { *out_sc = UA_STATUSCODE_BADOUTOFMEMORY; return 0; }
    UA_ClientConfig_setDefault(UA_Client_getConfig(c));
    client_silence_logger(UA_Client_getConfig(c));

    UA_EndpointDescription *eps = NULL;
    size_t epCount = 0;
    UA_StatusCode sc = UA_Client_getEndpoints(c, url, &epCount, &eps);
    UA_Client_delete(c);
    *out_sc = sc;

    if (sc != UA_STATUSCODE_GOOD) return 0;

    const char *want_uri = security_policy_uri(g_sec.policyName);
    UA_MessageSecurityMode want_mode = security_mode_enum(g_sec.modeName);
    size_t want_uri_len = strlen(want_uri);

    int found = 0;
    for (size_t i = 0; i < epCount && !found; i++) {
        if (eps[i].securityMode != want_mode) continue;
        const UA_String *uri = &eps[i].securityPolicyUri;
        if (uri->length == want_uri_len &&
            memcmp(uri->data, want_uri, want_uri_len) == 0)
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
    /* Verify a matching endpoint exists */
    UA_StatusCode ep_sc = UA_STATUSCODE_GOOD;
    if (!endpoint_check_security(url, &ep_sc)) {
        UA_StatusCode err_sc = (ep_sc != UA_STATUSCODE_GOOD)
                               ? ep_sc
                               : UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
        char msg_buf[256];
        if (ep_sc != UA_STATUSCODE_GOOD) {
            snprintf(msg_buf, sizeof(msg_buf), "GetEndpoints request failed");
        } else {
            snprintf(msg_buf, sizeof(msg_buf),
                     "no %s/%s endpoint available",
                     g_sec.policyName ? g_sec.policyName : "None",
                     g_sec.modeName   ? g_sec.modeName   : "None");
        }
        output_begin("open62541", op);
        output_success(0);
        output_service_result(err_sc);
        output_error("transport", msg_buf);
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

#ifdef UA_ENABLE_ENCRYPTION
    if (!security_is_none()) {
        UA_ByteString cert = load_cert_file(g_sec.certFile);
        UA_ByteString key  = load_cert_file(g_sec.keyFile);

        size_t trust_count = (size_t)g_sec.trustCount;
        UA_ByteString *trust_list = NULL;
        if (trust_count > 0) {
            trust_list = (UA_ByteString *)calloc(trust_count, sizeof(UA_ByteString));
            if (trust_list) {
                for (size_t i = 0; i < trust_count; i++)
                    trust_list[i] = load_cert_file(g_sec.trustFiles[i]);
            }
        }

        UA_StatusCode sc = UA_ClientConfig_setDefaultEncryption(
            cfg,
            cert, key,
            trust_list, trust_count,
            NULL, 0);

        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        for (size_t i = 0; i < trust_count; i++)
            UA_ByteString_clear(&trust_list[i]);
        free(trust_list);

        if (sc != UA_STATUSCODE_GOOD) {
            UA_Client_delete(client);
            output_begin("open62541", op);
            output_success(0);
            output_service_result(sc);
            output_error("internal", "UA_ClientConfig_setDefaultEncryption failed");
            output_end();
            *exit_code = 6;
            return NULL;
        }

        /* Select the requested security policy and mode */
        cfg->securityPolicyUri =
            UA_STRING_ALLOC(security_policy_uri(g_sec.policyName));
        cfg->securityMode = security_mode_enum(g_sec.modeName);
    } else {
        UA_ClientConfig_setDefault(cfg);
        /* open62541 v1.5.x endpoint selection: when a server advertises multiple
         * security endpoints, the client picks the highest-security endpoint that
         * has a matching user token policy, regardless of the client's configured
         * security mode.  Explicitly pinning None here forces the client to
         * select the None/None endpoint even when secure endpoints are available. */
        cfg->securityPolicyUri = UA_STRING_ALLOC(security_policy_uri("None"));
        cfg->securityMode = UA_MESSAGESECURITYMODE_NONE;
        /* open62541 v1.5.x rejects UserName token policies on None/None endpoints
         * by default to prevent cleartext password transmission.  For test
         * deployments where None/None username auth is deliberately used,
         * set allowNonePolicyPassword = UA_TRUE (same flag as on the server). */
        if (g_sec.username)
            cfg->allowNonePolicyPassword = UA_TRUE;
    }
#else
    UA_ClientConfig_setDefault(cfg);
    if (!security_is_none()) {
        fprintf(stderr, "[open62541] warn: non-None security requested but binary built "
                        "without UA_ENABLE_ENCRYPTION\n");
    }
#endif /* UA_ENABLE_ENCRYPTION */

    client_silence_logger(cfg);
    if (request_ms > 0)
        cfg->timeout = (UA_UInt32)request_ms;
    cfg->connectivityCheckInterval = 0;

    /* Set user identity token */
    if (g_sec.username) {
        UA_UserNameIdentityToken token;
        UA_UserNameIdentityToken_init(&token);
        token.userName = UA_STRING_ALLOC(g_sec.username);
        const char *pw = g_sec.password ? g_sec.password : "";
        token.password = UA_BYTESTRING_ALLOC(pw);
        UA_ExtensionObject_clear(&cfg->userIdentityToken);
        /* UA_ExtensionObject_setValueCopy(eo, p, type): data first, type second. */
        UA_ExtensionObject_setValueCopy(&cfg->userIdentityToken,
            &token, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
        UA_UserNameIdentityToken_clear(&token);
    }

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
    client_silence_logger(UA_Client_getConfig(client));

    UA_EndpointDescription *eps = NULL;
    size_t epCount = 0;
    UA_StatusCode sc = UA_Client_getEndpoints(client, endpoint, &epCount, &eps);

    /* Milo/Netty warm-up: the very first GetEndpoints call occasionally fails with
     * BadSecureChannelClosed before Netty's thread pool is fully ready.  Retry once. */
    if (sc == UA_STATUSCODE_BADSECURECHANNELCLOSED ||
        sc == UA_STATUSCODE_BADSECURECHANNELIDINVALID) {
        UA_Client_delete(client);
        client = UA_Client_new();
        if (!client) {
            output_begin("open62541", "endpoints");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
            output_error("internal", "UA_Client_new failed on retry");
            output_end();
            return 6;
        }
        UA_ClientConfig_setDefault(UA_Client_getConfig(client));
        client_silence_logger(UA_Client_getConfig(client));
        sc = UA_Client_getEndpoints(client, endpoint, &epCount, &eps);
    }

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

    /* Optional IndexRange applied to every ReadValueId. */
    const char *indexRange = find_arg(argc, argv, "--index-range");
    /* TimestampsToReturn: Source|Server|Both|Neither (default Source). */
    const char *tsStr = find_arg(argc, argv, "--timestamps");
    UA_TimestampsToReturn ts = UA_TIMESTAMPSTORETURN_SOURCE;
    if (tsStr) {
        if (strcmp(tsStr, "Source") == 0)       ts = UA_TIMESTAMPSTORETURN_SOURCE;
        else if (strcmp(tsStr, "Server") == 0)  ts = UA_TIMESTAMPSTORETURN_SERVER;
        else if (strcmp(tsStr, "Both") == 0)    ts = UA_TIMESTAMPSTORETURN_BOTH;
        else if (strcmp(tsStr, "Neither") == 0) ts = UA_TIMESTAMPSTORETURN_NEITHER;
    }

    /* Batch read via ReadService */
    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.timestampsToReturn = ts;
    req.nodesToRead = (UA_ReadValueId *)UA_Array_new((size_t)n,
                          &UA_TYPES[UA_TYPES_READVALUEID]);
    req.nodesToReadSize = (size_t)n;

    for (int i = 0; i < n; i++) {
        UA_ReadValueId_init(&req.nodesToRead[i]);
        UA_NodeId_copy(&ids[i], &req.nodesToRead[i].nodeId);
        req.nodesToRead[i].attributeId = UA_ATTRIBUTEID_VALUE;
        if (indexRange && indexRange[0])
            req.nodesToRead[i].indexRange = UA_STRING_ALLOC(indexRange);
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
    /* Comma-separated Int32 array, e.g. --type Int32[] --value 1,2,3 */
    if (strcmp(typeStr, "Int32[]") == 0) {
        size_t count = 1;
        for (const char *p = valStr; *p; p++)
            if (*p == ',') count++;
        UA_Int32 *arr = (UA_Int32 *)UA_Array_new(count, &UA_TYPES[UA_TYPES_INT32]);
        if (!arr) return var;
        size_t idx = 0;
        char *dup = strdup(valStr);
        char *tok = strtok(dup, ",");
        while (tok && idx < count) {
            arr[idx++] = (UA_Int32)atoi(tok);
            tok = strtok(NULL, ",");
        }
        free(dup);
        UA_Variant_setArray(&var, arr, idx, &UA_TYPES[UA_TYPES_INT32]);
        return var;
    }
#undef SET_SCALAR
    return var;
}

static int cmd_write(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    int node_count = count_flag(argc, argv, "--node");
    int type_count = count_flag(argc, argv, "--type");
    int val_count  = count_flag(argc, argv, "--value");

    if (!endpoint || node_count == 0 || type_count == 0 || val_count == 0 ||
        node_count != type_count || node_count != val_count) {
        output_begin("open62541", "write");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
                     "usage: write --endpoint <url> --node <id> --type <t> --value <v> "
                     "[--node ... --type ... --value ...] (equal counts required)");
        output_end();
        return 2;
    }
    if (node_count > MAX_NODES) node_count = MAX_NODES;

    const char *nodes[MAX_NODES];
    const char *types[MAX_NODES];
    const char *vals[MAX_NODES];
    int nn = 0, nt = 0, nv = 0;
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], "--node") == 0 && nn < MAX_NODES)
            nodes[nn++] = argv[i + 1];
        else if (strcmp(argv[i], "--type") == 0 && nt < MAX_NODES)
            types[nt++] = argv[i + 1];
        else if (strcmp(argv[i], "--value") == 0 && nv < MAX_NODES)
            vals[nv++] = argv[i + 1];
    }

    for (int i = 0; i < node_count; i++) {
        if (validate_nodeid_structure(nodes[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodes[i]);
            output_begin("open62541", "write");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
            output_error("input", msg);
            output_end();
            return 2;
        }
    }

    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_NodeId ids[MAX_NODES];
    UA_Client *client = resolve_node_ids(nodes, node_count, ids, "write",
                                         endpoint, req_ms, &exit_code);
    if (!client) return exit_code;

    /* Optional IndexRange applied to every WriteValue. */
    const char *indexRange = find_arg(argc, argv, "--index-range");

    UA_WriteRequest req;
    UA_WriteRequest_init(&req);
    req.nodesToWrite = (UA_WriteValue *)UA_Array_new((size_t)node_count,
                            &UA_TYPES[UA_TYPES_WRITEVALUE]);
    req.nodesToWriteSize = (size_t)node_count;

    UA_Variant vars[MAX_NODES];
    for (int i = 0; i < node_count; i++) {
        UA_WriteValue_init(&req.nodesToWrite[i]);
        UA_NodeId_copy(&ids[i], &req.nodesToWrite[i].nodeId);
        req.nodesToWrite[i].attributeId = UA_ATTRIBUTEID_VALUE;
        if (indexRange && indexRange[0])
            req.nodesToWrite[i].indexRange = UA_STRING_ALLOC(indexRange);
        vars[i] = build_write_variant(types[i], vals[i]);
        UA_Variant_copy(&vars[i], &req.nodesToWrite[i].value.value);
        req.nodesToWrite[i].value.hasValue = true;
    }

    UA_WriteResponse resp = UA_Client_Service_write(client, req);
    UA_WriteRequest_clear(&req);

    UA_StatusCode svc_sc = resp.responseHeader.serviceResult;
    int all_good = UA_StatusCode_isGood(svc_sc);
    if (all_good) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i])) {
                all_good = 0;
                break;
            }
        }
    }

    UA_StatusCode emit_sc = svc_sc;
    if (UA_StatusCode_isGood(svc_sc) && !all_good && resp.resultsSize > 0) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i])) {
                emit_sc = resp.results[i];
                break;
            }
        }
    }

    output_begin("open62541", "write");
    output_success(all_good);
    output_service_result(emit_sc);
    output_open_results();
    if (UA_StatusCode_isGood(svc_sc)) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (i > 0) printf(",");
            output_write_result_item(nodes[i], resp.results[i]);
        }
    }
    output_close_results();
    output_null_error();
    output_end();

    int ret;
    if (svc_sc == UA_STATUSCODE_BADTIMEOUT) ret = 7;
    else if (!UA_StatusCode_isGood(svc_sc) || !all_good) ret = 4;
    else ret = 0;

    for (int i = 0; i < node_count; i++) {
        UA_Variant_clear(&vars[i]);
        UA_NodeId_clear(&ids[i]);
    }
    UA_WriteResponse_clear(&resp);
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
    /* NodeClassMask: 0 = all classes. Variable = 2. */
    const char *ncmStr = find_arg(argc, argv, "--node-class-mask");
    UA_UInt32 nodeClassMask = ncmStr ? (UA_UInt32)strtoul(ncmStr, NULL, 0) : 0;
    /* IncludeSubtypes: default true; --include-subtypes false for exact RefType match. */
    const char *incStr = find_arg(argc, argv, "--include-subtypes");
    UA_Boolean includeSubtypes = UA_TRUE;
    if (incStr && (strcmp(incStr, "false") == 0 || strcmp(incStr, "0") == 0))
        includeSubtypes = UA_FALSE;
    /* ResultMask: default ALL; e.g. --result-mask 8 for BrowseName only. */
    const char *rmStr = find_arg(argc, argv, "--result-mask");
    UA_UInt32 resultMask = rmStr ? (UA_UInt32)strtoul(rmStr, NULL, 0)
                                 : UA_BROWSERESULTMASK_ALL;

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
    req.nodesToBrowse[0].referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    req.nodesToBrowse[0].includeSubtypes  = includeSubtypes;
    req.nodesToBrowse[0].nodeClassMask    = nodeClassMask;
    req.nodesToBrowse[0].resultMask       = resultMask;

    UA_BrowseResponse resp = UA_Client_Service_browse(client, req);
    UA_BrowseRequest_clear(&req);

    UA_StatusCode sc = resp.responseHeader.serviceResult;
    /* Promote per-item BrowseResult status when the service header is Good. */
    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0 &&
        !UA_StatusCode_isGood(resp.results[0].statusCode)) {
        sc = resp.results[0].statusCode;
    }

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
    char     serverTimestamp[64];
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
    e->serverTimestamp[0] = '\0';
    if (val->hasSourceTimestamp)
        output_timestamp(val->sourceTimestamp, e->sourceTimestamp,
                         sizeof(e->sourceTimestamp));
    if (val->hasServerTimestamp)
        output_timestamp(val->serverTimestamp, e->serverTimestamp,
                         sizeof(e->serverTimestamp));

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

    /* Queue-size and discard-oldest options. */
    const char *qsStr     = find_arg(argc, argv, "--queue-size");
    const char *doStr     = find_arg(argc, argv, "--discard-oldest");
    UA_UInt32   queueSize = qsStr ? (UA_UInt32)atoi(qsStr) : 1;
    UA_Boolean  discardOldest = UA_TRUE; /* default: keep newest */
    if (doStr) {
        discardOldest = (strcmp(doStr, "false") == 0) ? UA_FALSE : UA_TRUE;
    }
    if (queueSize < 1) queueSize = 1;

    /* TimestampsToReturn: Source|Server|Both|Neither (default Both). */
    const char *tsStr = find_arg(argc, argv, "--timestamps");
    UA_TimestampsToReturn ts = UA_TIMESTAMPSTORETURN_BOTH;
    if (tsStr) {
        if (strcmp(tsStr, "Source") == 0)       ts = UA_TIMESTAMPSTORETURN_SOURCE;
        else if (strcmp(tsStr, "Server") == 0)  ts = UA_TIMESTAMPSTORETURN_SERVER;
        else if (strcmp(tsStr, "Neither") == 0) ts = UA_TIMESTAMPSTORETURN_NEITHER;
        else if (strcmp(tsStr, "Both") == 0)    ts = UA_TIMESTAMPSTORETURN_BOTH;
    }

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
    monReq.requestedParameters.queueSize        = queueSize;
    monReq.requestedParameters.discardOldest    = discardOldest;
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subResp.subscriptionId, ts,
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
    printf(",\"subscriptionId\":%" PRIu32, (uint32_t)subResp.subscriptionId);
    printf(",\"revisedPublishingInterval\":%.17g", subResp.revisedPublishingInterval);
    printf(",\"revisedLifetimeCount\":%" PRIu32, (uint32_t)subResp.revisedLifetimeCount);
    printf(",\"revisedMaxKeepAliveCount\":%" PRIu32, (uint32_t)subResp.revisedMaxKeepAliveCount);
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
        if (e->serverTimestamp[0])
            printf(",\"serverTimestamp\":\"%s\"", e->serverTimestamp);
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
 * subscription-lifecycle subcommand helpers
 * ---------------------------------------------------------------------- */

static UA_StatusCode slc_set_publishing_mode(UA_Client *client, UA_UInt32 subId,
                                              UA_Boolean enabled) {
    UA_SetPublishingModeRequest req;
    UA_SetPublishingModeRequest_init(&req);
    req.publishingEnabled = enabled;
    req.subscriptionIdsSize = 1;
    req.subscriptionIds = &subId;
    UA_SetPublishingModeResponse resp;
    UA_SetPublishingModeResponse_init(&resp);
    __UA_Client_Service(client, &req,
        &UA_TYPES[UA_TYPES_SETPUBLISHINGMODEREQUEST],
        &resp,
        &UA_TYPES[UA_TYPES_SETPUBLISHINGMODERESPONSE]);
    UA_StatusCode sc = resp.responseHeader.serviceResult;
    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0)
        sc = resp.results[0];
    UA_SetPublishingModeResponse_clear(&resp);
    return sc;
}

static UA_StatusCode slc_set_monitoring_mode(UA_Client *client, UA_UInt32 subId,
                                              UA_UInt32 monId, UA_MonitoringMode mode) {
    UA_SetMonitoringModeRequest req;
    UA_SetMonitoringModeRequest_init(&req);
    req.subscriptionId = subId;
    req.monitoringMode = mode;
    req.monitoredItemIdsSize = 1;
    req.monitoredItemIds = &monId;
    UA_SetMonitoringModeResponse resp;
    UA_SetMonitoringModeResponse_init(&resp);
    __UA_Client_Service(client, &req,
        &UA_TYPES[UA_TYPES_SETMONITORINGMODEREQUEST],
        &resp,
        &UA_TYPES[UA_TYPES_SETMONITORINGMODERESPONSE]);
    UA_StatusCode sc = resp.responseHeader.serviceResult;
    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0)
        sc = resp.results[0];
    UA_SetMonitoringModeResponse_clear(&resp);
    return sc;
}

static UA_StatusCode slc_write_int32(UA_Client *client, UA_NodeId nodeId, UA_Int32 val) {
    UA_Variant var;
    UA_Variant_init(&var);
    UA_Variant_setScalar(&var, &val, &UA_TYPES[UA_TYPES_INT32]);
    return UA_Client_writeValueAttribute(client, nodeId, &var);
}

/* -------------------------------------------------------------------------
 * subscription-lifecycle scenarios
 * ---------------------------------------------------------------------- */

static int slc_revise(UA_Client *client, UA_NodeId nodeId, int toMs) {
    (void)nodeId; (void)toMs;
    UA_CreateSubscriptionRequest req;
    UA_CreateSubscriptionRequest_init(&req);
    req.requestedPublishingInterval = 1.0;
    req.requestedLifetimeCount      = 5;
    req.requestedMaxKeepAliveCount  = 10;
    req.publishingEnabled           = UA_TRUE;

    UA_CreateSubscriptionResponse resp =
        UA_Client_Subscriptions_create(client, req, NULL, NULL, NULL);
    UA_StatusCode sc  = resp.responseHeader.serviceResult;
    UA_UInt32     sid = resp.subscriptionId;
    double        rpi = resp.revisedPublishingInterval;
    UA_UInt32     rlt = resp.revisedLifetimeCount;
    UA_UInt32     rmk = resp.revisedMaxKeepAliveCount;
    UA_CreateSubscriptionResponse_clear(&resp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    UA_Client_Subscriptions_deleteSingle(client, sid);

    int ok = (rlt >= 3u * rmk) && (rpi >= 10.0);
    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, sid);
    printf(",\"requestedPublishingInterval\":1");
    printf(",\"requestedLifetimeCount\":5");
    printf(",\"requestedMaxKeepAliveCount\":10");
    printf(",\"revisedPublishingInterval\":%.17g", rpi);
    printf(",\"revisedLifetimeCount\":%" PRIu32, rlt);
    printf(",\"revisedMaxKeepAliveCount\":%" PRIu32, rmk);
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

static int slc_publishing_mode(UA_Client *client, UA_NodeId nodeId, int toMs) {
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = 500.0;
    subReq.publishingEnabled = UA_TRUE;

    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode sc  = subResp.responseHeader.serviceResult;
    UA_UInt32 subId   = subResp.subscriptionId;
    double    rpi     = subResp.revisedPublishingInterval;
    UA_UInt32 rlt     = subResp.revisedLifetimeCount;
    UA_UInt32 rmk     = subResp.revisedMaxKeepAliveCount;
    UA_CreateSubscriptionResponse_clear(&subResp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = MAX_NOTIFICATIONS;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    monReq.requestedParameters.samplingInterval = 100.0;
    monReq.requestedParameters.queueSize        = 3;
    monReq.requestedParameters.discardOldest    = UA_TRUE;
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subId, UA_TIMESTAMPSTORETURN_SOURCE,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode monSc = monResp.statusCode;

    if (!UA_StatusCode_isGood(monSc)) {
        UA_Client_Subscriptions_deleteSingle(client, subId);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(monSc);
        output_error("service", "CreateMonitoredItem failed");
        output_end();
        return 4;
    }

    /* Drain initial notification (up to 500ms) */
    time_t t0 = time(NULL);
    while (store.count < 1) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= 500) break;
        UA_Client_run_iterate(client, 50);
    }

    /* SetPublishingMode false then reset counter */
    slc_set_publishing_mode(client, subId, UA_FALSE);
    store.count = 0;

    /* Write 1,2,3,4,5 */
    for (int v = 1; v <= 5; v++) {
        slc_write_int32(client, nodeId, (UA_Int32)v);
        UA_Client_run_iterate(client, 20);
    }

    /* Wait 200ms with publishing off */
    t0 = time(NULL);
    while ((int)(difftime(time(NULL), t0) * 1000.0) < 200)
        UA_Client_run_iterate(client, 50);

    /* SetPublishingMode true */
    slc_set_publishing_mode(client, subId, UA_TRUE);

    /* Collect queued notifications (expect up to queueSize=3) */
    int collectMs = toMs - 2000;
    if (collectMs < 2000) collectMs = 2000;
    if (collectMs > 5000) collectMs = 5000;
    t0 = time(NULL);
    while (store.count < 3) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= collectMs) break;
        UA_Client_run_iterate(client, 50);
    }

    UA_Client_Subscriptions_deleteSingle(client, subId);

    int nv = store.count;
    /* Overflow: wrote 5 values, queueSize=3 means 2 were discarded */
    int overflow = (nv < 5);
    for (int i = 0; i < nv; i++) {
        /* Overflow info bit: bit 10 in status code SubCode */
        if (store.entries[i].statusCode & 0x04800000u)
            overflow = 1;
    }

    /* success: last values should be [3,4,5] */
    int ok = 0;
    if (nv >= 3) {
        int a = atoi(store.entries[nv-3].valueJson);
        int b = atoi(store.entries[nv-2].valueJson);
        int c = atoi(store.entries[nv-1].valueJson);
        ok = (a == 3 && b == 4 && c == 5);
    } else if (nv >= 1) {
        ok = (atoi(store.entries[nv-1].valueJson) == 5);
    }

    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, subId);
    printf(",\"revisedPublishingInterval\":%.17g", rpi);
    printf(",\"revisedLifetimeCount\":%" PRIu32, rlt);
    printf(",\"revisedMaxKeepAliveCount\":%" PRIu32, rmk);
    printf(",\"overflow\":%s", overflow ? "true" : "false");
    printf(",\"values\":[");
    for (int i = 0; i < nv; i++) {
        if (i > 0) printf(",");
        printf("%s", store.entries[i].valueJson);
    }
    printf("]");
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

static int slc_monitoring_mode(UA_Client *client, UA_NodeId nodeId, int toMs) {
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = 100.0;
    subReq.publishingEnabled = UA_TRUE;

    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode sc  = subResp.responseHeader.serviceResult;
    UA_UInt32 subId   = subResp.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&subResp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = MAX_NOTIFICATIONS;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    monReq.requestedParameters.samplingInterval = 100.0;
    monReq.requestedParameters.queueSize        = 5;
    monReq.requestedParameters.discardOldest    = UA_TRUE;
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subId, UA_TIMESTAMPSTORETURN_SOURCE,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode monSc = monResp.statusCode;
    UA_UInt32 monId     = monResp.monitoredItemId;

    if (!UA_StatusCode_isGood(monSc)) {
        UA_Client_Subscriptions_deleteSingle(client, subId);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(monSc);
        output_error("service", "CreateMonitoredItem failed");
        output_end();
        return 4;
    }

    /* Drain initial notification */
    time_t t0 = time(NULL);
    while (store.count < 1) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= 500) break;
        UA_Client_run_iterate(client, 50);
    }
    store.count = 0;

    /* SetMonitoringMode DISABLED; write 100; wait 300ms; expect 0 notifications */
    slc_set_monitoring_mode(client, subId, monId, UA_MONITORINGMODE_DISABLED);
    slc_write_int32(client, nodeId, 100);
    t0 = time(NULL);
    while ((int)(difftime(time(NULL), t0) * 1000.0) < 300)
        UA_Client_run_iterate(client, 50);
    int disabledCount = store.count;

    /* SetMonitoringMode SAMPLING; write 101,102; wait 300ms */
    slc_set_monitoring_mode(client, subId, monId, UA_MONITORINGMODE_SAMPLING);
    slc_write_int32(client, nodeId, 101);
    UA_Client_run_iterate(client, 20);
    slc_write_int32(client, nodeId, 102);
    t0 = time(NULL);
    while ((int)(difftime(time(NULL), t0) * 1000.0) < 300)
        UA_Client_run_iterate(client, 50);
    int samplingCount = store.count - disabledCount;

    /* SetMonitoringMode REPORTING; write 103; collect >= 1 notification */
    slc_set_monitoring_mode(client, subId, monId, UA_MONITORINGMODE_REPORTING);
    slc_write_int32(client, nodeId, 103);
    int beforeReporting = store.count;
    int collectMs = toMs - 2000;
    if (collectMs < 2000) collectMs = 2000;
    if (collectMs > 5000) collectMs = 5000;
    t0 = time(NULL);
    while (store.count <= beforeReporting) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= collectMs) break;
        UA_Client_run_iterate(client, 50);
    }
    int reportingCount = store.count - beforeReporting;

    UA_Client_Subscriptions_deleteSingle(client, subId);

    int ok = (disabledCount == 0) && (reportingCount >= 1);
    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, subId);
    printf(",\"modeSteps\":[");
    printf("{\"mode\":\"Disabled\",\"notificationCount\":%d}", disabledCount);
    printf(",{\"mode\":\"Sampling\",\"notificationCount\":%d}", samplingCount);
    printf(",{\"mode\":\"Reporting\",\"notificationCount\":%d}", reportingCount);
    printf("]");
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

static int slc_delete(UA_Client *client, UA_NodeId nodeId, int toMs) {
    (void)toMs;
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = 500.0;
    subReq.publishingEnabled = UA_TRUE;

    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode sc  = subResp.responseHeader.serviceResult;
    UA_UInt32 subId   = subResp.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&subResp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = 0;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subId, UA_TIMESTAMPSTORETURN_SOURCE,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode monSc = monResp.statusCode;
    UA_UInt32 monId     = monResp.monitoredItemId;

    if (!UA_StatusCode_isGood(monSc)) {
        UA_Client_Subscriptions_deleteSingle(client, subId);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(monSc);
        output_error("service", "CreateMonitoredItem failed");
        output_end();
        return 4;
    }

    /* DeleteMonitoredItems: first (expect Good), second (expect Bad) */
    UA_DeleteMonitoredItemsRequest dmReq;
    UA_DeleteMonitoredItemsRequest_init(&dmReq);
    dmReq.subscriptionId       = subId;
    dmReq.monitoredItemIds     = &monId;
    dmReq.monitoredItemIdsSize = 1;

    UA_DeleteMonitoredItemsResponse dmResp1;
    UA_DeleteMonitoredItemsResponse_init(&dmResp1);
    __UA_Client_Service(client, &dmReq,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST],
        &dmResp1,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
    UA_StatusCode delMon1 = (dmResp1.resultsSize > 0)
        ? dmResp1.results[0] : dmResp1.responseHeader.serviceResult;
    UA_DeleteMonitoredItemsResponse_clear(&dmResp1);

    UA_DeleteMonitoredItemsResponse dmResp2;
    UA_DeleteMonitoredItemsResponse_init(&dmResp2);
    __UA_Client_Service(client, &dmReq,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST],
        &dmResp2,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
    UA_StatusCode delMon2 = (dmResp2.resultsSize > 0)
        ? dmResp2.results[0] : dmResp2.responseHeader.serviceResult;
    UA_DeleteMonitoredItemsResponse_clear(&dmResp2);

    /* DeleteSubscriptions: first (expect Good), second (expect Bad) */
    UA_DeleteSubscriptionsRequest dsReq;
    UA_DeleteSubscriptionsRequest_init(&dsReq);
    dsReq.subscriptionIds     = &subId;
    dsReq.subscriptionIdsSize = 1;

    UA_DeleteSubscriptionsResponse dsResp1;
    UA_DeleteSubscriptionsResponse_init(&dsResp1);
    __UA_Client_Service(client, &dsReq,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST],
        &dsResp1,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
    UA_StatusCode delSub1 = (dsResp1.resultsSize > 0)
        ? dsResp1.results[0] : dsResp1.responseHeader.serviceResult;
    UA_DeleteSubscriptionsResponse_clear(&dsResp1);

    UA_DeleteSubscriptionsResponse dsResp2;
    UA_DeleteSubscriptionsResponse_init(&dsResp2);
    __UA_Client_Service(client, &dsReq,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST],
        &dsResp2,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
    UA_StatusCode delSub2 = (dsResp2.resultsSize > 0)
        ? dsResp2.results[0] : dsResp2.responseHeader.serviceResult;
    UA_DeleteSubscriptionsResponse_clear(&dsResp2);

    int ok = UA_StatusCode_isBad(delMon2) && UA_StatusCode_isBad(delSub2);
    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, subId);
    printf(",\"deleteMonitoredItem\":{");
    printf("\"first\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delMon1), (uint32_t)delMon1,
           output_severity(delMon1));
    printf(",\"second\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delMon2), (uint32_t)delMon2,
           output_severity(delMon2));
    printf("}");
    printf(",\"deleteSubscription\":{");
    printf("\"first\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delSub1), (uint32_t)delSub1,
           output_severity(delSub1));
    printf(",\"second\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delSub2), (uint32_t)delSub2,
           output_severity(delSub2));
    printf("}");
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * subscription-lifecycle subcommand
 * ---------------------------------------------------------------------- */

static int cmd_subscription_lifecycle(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    const char *scenario = find_arg(argc, argv, "--scenario");
    const char *toStr    = find_arg(argc, argv, "--timeout-ms");

    if (!endpoint || !nodeStr || !scenario) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: subscription-lifecycle --endpoint <url> --node <nodeId>"
            " --scenario <revise|publishing-mode|monitoring-mode|delete>");
        output_end();
        return 2;
    }

    int toMs = toStr ? atoi(toStr) : 15000;

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int exit_code = 3;
    UA_Client *client =
        make_client(endpoint, 5000, "subscription-lifecycle", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId; UA_NodeId_init(&nodeId);
    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            output_begin("open62541", "subscription-lifecycle");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    int result;
    if      (strcmp(scenario, "revise")           == 0)
        result = slc_revise(client, nodeId, toMs);
    else if (strcmp(scenario, "publishing-mode")  == 0)
        result = slc_publishing_mode(client, nodeId, toMs);
    else if (strcmp(scenario, "monitoring-mode")  == 0)
        result = slc_monitoring_mode(client, nodeId, toMs);
    else if (strcmp(scenario, "delete")           == 0)
        result = slc_delete(client, nodeId, toMs);
    else {
        char msg[256];
        snprintf(msg, sizeof(msg), "unknown scenario: '%s'", scenario);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        result = 2;
    }

    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return result;
}

/* -------------------------------------------------------------------------
 * Dispatch
 * ---------------------------------------------------------------------- */

int client_run(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: client <endpoints|read|write|browse|call|subscribe|subscription-lifecycle> ...\n");
        return 2;
    }

    /* Parse global security flags from the full argv array.
     * Each subcommand receives the full argv so these flags are visible. */
    {
        const char *v;
        if ((v = find_arg(argc, argv, "--security-policy")) != NULL)
            g_sec.policyName = v;
        if ((v = find_arg(argc, argv, "--security-mode")) != NULL)
            g_sec.modeName = v;
        if ((v = find_arg(argc, argv, "--certificate")) != NULL)
            g_sec.certFile = v;
        if ((v = find_arg(argc, argv, "--private-key")) != NULL)
            g_sec.keyFile = v;
        if ((v = find_arg(argc, argv, "--username")) != NULL)
            g_sec.username = v;
        if ((v = find_arg(argc, argv, "--password")) != NULL)
            g_sec.password = v;

        /* Collect all --trust-list values */
        int tc = count_flag(argc, argv, "--trust-list");
        if (tc > 0) {
            static const char **trust_arr = NULL;
            static int trust_cap = 0;
            if (tc > trust_cap) {
                free((void *)trust_arr);
                trust_arr = (const char **)malloc((size_t)tc * sizeof(const char *));
                trust_cap = tc;
            }
            int ti = 0;
            for (int i = 0; i < argc - 1 && ti < tc; i++) {
                if (strcmp(argv[i], "--trust-list") == 0)
                    trust_arr[ti++] = argv[i + 1];
            }
            g_sec.trustFiles = trust_arr;
            g_sec.trustCount = tc;
        }
    }

    const char *sub = argv[1];
    if (strcmp(sub, "endpoints")             == 0) return cmd_endpoints(argc - 1, argv + 1);
    if (strcmp(sub, "read")                  == 0) return cmd_read(argc - 1, argv + 1);
    if (strcmp(sub, "write")                 == 0) return cmd_write(argc - 1, argv + 1);
    if (strcmp(sub, "browse")                == 0) return cmd_browse(argc - 1, argv + 1);
    if (strcmp(sub, "call")                  == 0) return cmd_call(argc - 1, argv + 1);
    if (strcmp(sub, "subscribe")             == 0) return cmd_subscribe(argc - 1, argv + 1);
    if (strcmp(sub, "subscription-lifecycle") == 0) return cmd_subscription_lifecycle(argc - 1, argv + 1);
    fprintf(stderr, "unknown client subcommand: %s\n", sub);
    return 2;
}
