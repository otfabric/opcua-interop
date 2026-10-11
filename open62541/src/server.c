#define _POSIX_C_SOURCE 200809L

#include "server.h"
#include "fixture.h"

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <open62541.h>

/* -------------------------------------------------------------------------
 * Signal handling
 * ---------------------------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/* -------------------------------------------------------------------------
 * Argument parsing
 * ---------------------------------------------------------------------- */

int server_parse_args(int argc, char **argv, ServerArgs *out,
                      char *errBuf, size_t errLen) {
    memset(out, 0, sizeof(*out));

    /* Defaults from environment */
    const char *env;
    if ((env = getenv("OPCUA_FIXTURE"))       && *env) out->fixturePath    = strdup(env);
    if ((env = getenv("OPCUA_READY_FILE"))    && *env) out->readyFile       = strdup(env);
    if ((env = getenv("OPCUA_PKI_DIR"))       && *env) out->pkiDir          = strdup(env);
    if ((env = getenv("OPCUA_BIND_ADDRESS"))  && *env) out->bindAddress     = strdup(env);
    if ((env = getenv("OPCUA_ADVERTISED_HOST")) && *env) out->advertisedHost = strdup(env);
    if ((env = getenv("OPCUA_ENDPOINT_PATH")) && *env) out->endpointPath    = strdup(env);
    if ((env = getenv("OPCUA_PORT"))          && *env) out->bindPort        = atoi(env);

    /* CLI overrides */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fixture") == 0 && i+1 < argc) {
            free(out->fixturePath);    out->fixturePath    = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--bind-address") == 0 && i+1 < argc) {
            free(out->bindAddress);    out->bindAddress    = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--bind-port") == 0 && i+1 < argc) {
            out->bindPort = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--advertised-host") == 0 && i+1 < argc) {
            free(out->advertisedHost); out->advertisedHost = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--advertised-port") == 0 && i+1 < argc) {
            out->advertisedPort = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--endpoint-path") == 0 && i+1 < argc) {
            free(out->endpointPath);   out->endpointPath   = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--pki-dir") == 0 && i+1 < argc) {
            free(out->pkiDir);         out->pkiDir         = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--certificate") == 0 && i+1 < argc) {
            free(out->certFile);       out->certFile       = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--private-key") == 0 && i+1 < argc) {
            free(out->keyFile);        out->keyFile        = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--ready-file") == 0 && i+1 < argc) {
            free(out->readyFile);      out->readyFile      = strdup(argv[++i]);
            out->readyFileExplicit = 1;
        } else if (strcmp(argv[i], "--ecc-dir") == 0 && i+1 < argc) {
            free(out->eccDir);         out->eccDir         = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--reverse-connect") == 0 && i+1 < argc) {
            if (out->reverseConnectCount < SERVER_MAX_REVERSE)
                out->reverseConnect[out->reverseConnectCount++] = strdup(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "--reverse-connect-interval-ms") == 0 && i+1 < argc) {
            out->reverseIntervalMs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--lds") == 0) {
            out->lds = 1;
        } else if (strcmp(argv[i], "--lds-cleanup-timeout") == 0 && i+1 < argc) {
            out->ldsCleanupTimeoutS = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--mdns-name") == 0 && i+1 < argc) {
            free(out->mdnsName);       out->mdnsName       = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--mdns-capability") == 0 && i+1 < argc) {
            if (out->mdnsCapCount < SERVER_MAX_CAPS)
                out->mdnsCaps[out->mdnsCapCount++] = strdup(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "--register-with") == 0 && i+1 < argc) {
            free(out->registerWith);   out->registerWith   = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--register-interval-ms") == 0 && i+1 < argc) {
            out->registerIntervalMs = atoi(argv[++i]);
        }
    }
    if (out->reverseIntervalMs <= 0)  out->reverseIntervalMs  = 1000;
    if (out->registerIntervalMs <= 0) out->registerIntervalMs = 30000;

    if (!out->fixturePath || !*out->fixturePath) {
        snprintf(errBuf, errLen, "missing --fixture (or OPCUA_FIXTURE)");
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * NodeId parsing helpers
 * ---------------------------------------------------------------------- */

/*
 * Parse a NodeId string of the forms:
 *   i=85
 *   ns=<idx>;i=<num>
 *   ns=<idx>;s=<str>
 *   nsu=<uri>;s=<str>
 *   nsu=<uri>;i=<num>
 *
 * For nsu= forms, nsIndex is the runtime namespace index for that URI,
 * which the caller must look up first.
 */
static UA_NodeId parse_nodeid(const char *s, UA_UInt16 nsuIndex) {
    if (!s) return UA_NODEID_NULL;

    /* nsu=<uri>;s=<name> or nsu=<uri>;i=<num> */
    if (strncmp(s, "nsu=", 4) == 0) {
        const char *semi = strchr(s, ';');
        if (!semi) return UA_NODEID_NULL;
        semi++; /* skip ';' */
        if (strncmp(semi, "s=", 2) == 0) {
            return UA_NODEID_STRING_ALLOC(nsuIndex, semi + 2);
        }
        if (strncmp(semi, "i=", 2) == 0) {
            return UA_NODEID_NUMERIC(nsuIndex, (UA_UInt32)atoi(semi + 2));
        }
        return UA_NODEID_NULL;
    }

    /* ns=<idx>;... */
    if (strncmp(s, "ns=", 3) == 0) {
        UA_UInt16 ns = (UA_UInt16)atoi(s + 3);
        const char *semi = strchr(s, ';');
        if (!semi) return UA_NODEID_NULL;
        semi++;
        if (strncmp(semi, "s=", 2) == 0) {
            return UA_NODEID_STRING_ALLOC(ns, semi + 2);
        }
        if (strncmp(semi, "i=", 2) == 0) {
            return UA_NODEID_NUMERIC(ns, (UA_UInt32)atoi(semi + 2));
        }
        return UA_NODEID_NULL;
    }

    /* i=<num> — numeric in namespace 0 */
    if (strncmp(s, "i=", 2) == 0) {
        return UA_NODEID_NUMERIC(0, (UA_UInt32)atoi(s + 2));
    }

    return UA_NODEID_NULL;
}

/* Look up (or register) the runtime namespace index for a URI in the server.
 * UA_Server_addNamespace is idempotent: returns the existing index if already
 * registered. */
static UA_UInt16 ns_index_for_uri(UA_Server *srv, const char *uri) {
    return (UA_UInt16)UA_Server_addNamespace(srv, uri);
}

/*
 * Given a nodeId string in the fixture format, look up the appropriate
 * namespace index and return a UA_NodeId.
 */
static UA_NodeId resolve_nodeid(UA_Server *srv, const char *s) {
    if (!s) return UA_NODEID_NULL;
    if (strncmp(s, "nsu=", 4) == 0) {
        const char *semi = strchr(s + 4, ';');
        if (!semi) return UA_NODEID_NULL;
        size_t uriLen = (size_t)(semi - (s + 4));
        char *uri = malloc(uriLen + 1);
        if (!uri) return UA_NODEID_NULL;
        memcpy(uri, s + 4, uriLen);
        uri[uriLen] = '\0';
        UA_UInt16 idx = ns_index_for_uri(srv, uri);
        free(uri);
        return parse_nodeid(s, idx);
    }
    return parse_nodeid(s, 0);
}

/* -------------------------------------------------------------------------
 * Reference type mapping
 * ---------------------------------------------------------------------- */

static UA_NodeId ref_type_id(const char *name) {
    if (!name) return UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    if (strcmp(name, "Organizes")       == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    if (strcmp(name, "HasComponent")    == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    if (strcmp(name, "HasProperty")     == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    if (strcmp(name, "HasSubtype")      == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE);
    if (strcmp(name, "HasTypeDefinition") == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_HASTYPEDEFINITION);
    if (strcmp(name, "HasModellingRule") == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_HASMODELLINGRULE);
    if (strcmp(name, "HasEncoding")     == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_HASENCODING);
    if (strcmp(name, "Aggregates")      == 0)
        return UA_NODEID_NUMERIC(0, UA_NS0ID_AGGREGATES);
    return UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
}

/* -------------------------------------------------------------------------
 * DataType mapping
 * ---------------------------------------------------------------------- */

static const UA_DataType *data_type_for_name(const char *name) {
    if (!name) return &UA_TYPES[UA_TYPES_VARIANT];
    if (strcmp(name, "Boolean")       == 0) return &UA_TYPES[UA_TYPES_BOOLEAN];
    if (strcmp(name, "SByte")         == 0) return &UA_TYPES[UA_TYPES_SBYTE];
    if (strcmp(name, "Byte")          == 0) return &UA_TYPES[UA_TYPES_BYTE];
    if (strcmp(name, "Int16")         == 0) return &UA_TYPES[UA_TYPES_INT16];
    if (strcmp(name, "UInt16")        == 0) return &UA_TYPES[UA_TYPES_UINT16];
    if (strcmp(name, "Int32")         == 0) return &UA_TYPES[UA_TYPES_INT32];
    if (strcmp(name, "UInt32")        == 0) return &UA_TYPES[UA_TYPES_UINT32];
    if (strcmp(name, "Int64")         == 0) return &UA_TYPES[UA_TYPES_INT64];
    if (strcmp(name, "UInt64")        == 0) return &UA_TYPES[UA_TYPES_UINT64];
    if (strcmp(name, "Float")         == 0) return &UA_TYPES[UA_TYPES_FLOAT];
    if (strcmp(name, "Double")        == 0) return &UA_TYPES[UA_TYPES_DOUBLE];
    if (strcmp(name, "String")        == 0) return &UA_TYPES[UA_TYPES_STRING];
    if (strcmp(name, "DateTime")      == 0) return &UA_TYPES[UA_TYPES_DATETIME];
    if (strcmp(name, "Guid")          == 0) return &UA_TYPES[UA_TYPES_GUID];
    if (strcmp(name, "ByteString")    == 0) return &UA_TYPES[UA_TYPES_BYTESTRING];
    if (strcmp(name, "XmlElement")    == 0) return &UA_TYPES[UA_TYPES_XMLELEMENT];
    if (strcmp(name, "NodeId")        == 0) return &UA_TYPES[UA_TYPES_NODEID];
    if (strcmp(name, "ExpandedNodeId")== 0) return &UA_TYPES[UA_TYPES_EXPANDEDNODEID];
    if (strcmp(name, "QualifiedName") == 0) return &UA_TYPES[UA_TYPES_QUALIFIEDNAME];
    if (strcmp(name, "LocalizedText") == 0) return &UA_TYPES[UA_TYPES_LOCALIZEDTEXT];
    if (strcmp(name, "StatusCode")    == 0) return &UA_TYPES[UA_TYPES_STATUSCODE];
    return &UA_TYPES[UA_TYPES_VARIANT];
}

static UA_NodeId data_type_nodeid(const char *name) {
    const UA_DataType *dt = data_type_for_name(name);
    return UA_NODEID_NUMERIC(0, dt->typeId.identifier.numeric);
}

/* -------------------------------------------------------------------------
 * initialValue → UA_Variant
 * ---------------------------------------------------------------------- */

#include <cjson/cJSON.h>

/* Simple base64 decode. Returns malloc'd buffer and sets *outLen.
 * Supports standard base64 (RFC 4648). */
static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static uint8_t *b64_decode(const char *in, size_t *outLen) {
    if (!in) { *outLen = 0; return NULL; }
    size_t inLen = strlen(in);
    if (inLen == 0) { *outLen = 0; return calloc(1, 1); }
    if (inLen % 4 != 0) { *outLen = 0; return NULL; }

    *outLen = inLen / 4 * 3;
    if (in[inLen-1] == '=') (*outLen)--;
    if (in[inLen-2] == '=') (*outLen)--;

    uint8_t *out = malloc(*outLen + 1);
    if (!out) { *outLen = 0; return NULL; }

    size_t j = 0;
    for (size_t i = 0; i < inLen; i += 4) {
        int a = b64_char_val(in[i]);
        int b = b64_char_val(in[i+1]);
        int c = (in[i+2] == '=') ? 0 : b64_char_val(in[i+2]);
        int d = (in[i+3] == '=') ? 0 : b64_char_val(in[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(out); *outLen = 0; return NULL; }
        if (j < *outLen) out[j++] = (uint8_t)((a << 2) | (b >> 4));
        if (j < *outLen) out[j++] = (uint8_t)(((b & 0xf) << 4) | (c >> 2));
        if (j < *outLen) out[j++] = (uint8_t)(((c & 3) << 6) | d);
    }
    return out;
}

/* Parse an ISO 8601 date string "YYYY-MM-DDTHH:MM:SSZ" into UA_DateTime. */
static UA_DateTime parse_datetime(const char *s) {
    if (!s) return 0;
    struct tm t;
    memset(&t, 0, sizeof(t));
    /* Accept formats: YYYY-MM-DDTHH:MM:SSZ */
    if (sscanf(s, "%d-%d-%dT%d:%d:%d",
               &t.tm_year, &t.tm_mon, &t.tm_mday,
               &t.tm_hour, &t.tm_min, &t.tm_sec) < 3) {
        return 0;
    }
    t.tm_year -= 1900;
    t.tm_mon  -= 1;
    time_t epoch = mktime(&t);
    /* UA_DateTime: 100ns intervals since 1601-01-01 */
    return (UA_DateTime)((int64_t)epoch * UA_DATETIME_SEC + UA_DATETIME_UNIX_EPOCH);
}

/* Parse a GUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" */
static UA_Guid parse_guid(const char *s) {
    UA_Guid g; memset(&g, 0, sizeof(g));
    if (!s) return g;
    unsigned d1, d2, d3;
    unsigned b[8];
    if (sscanf(s, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               &d1, &d2, &d3,
               &b[0], &b[1], &b[2], &b[3],
               &b[4], &b[5], &b[6], &b[7]) == 11) {
        g.data1 = (UA_UInt32)d1;
        g.data2 = (UA_UInt16)d2;
        g.data3 = (UA_UInt16)d3;
        for (int i = 0; i < 8; i++) g.data4[i] = (UA_Byte)b[i];
    }
    return g;
}

/* Parse a QualifiedName "nsIdx:name" */
static UA_QualifiedName parse_qualified_name(const char *s) {
    UA_QualifiedName qn; UA_QualifiedName_init(&qn);
    if (!s) return qn;
    const char *colon = strchr(s, ':');
    if (colon) {
        qn.namespaceIndex = (UA_UInt16)atoi(s);
        qn.name = UA_STRING_ALLOC(colon + 1);
    } else {
        qn.name = UA_STRING_ALLOC(s);
    }
    return qn;
}

/* Parse a LocalizedText "locale:text" */
static UA_LocalizedText parse_localized_text(const char *s) {
    if (!s) return UA_LOCALIZEDTEXT("", "");
    const char *colon = strchr(s, ':');
    if (!colon) return UA_LOCALIZEDTEXT_ALLOC("", s);
    size_t locLen = (size_t)(colon - s);
    char *loc = malloc(locLen + 1);
    if (!loc) return UA_LOCALIZEDTEXT("", "");
    memcpy(loc, s, locLen);
    loc[locLen] = '\0';
    UA_LocalizedText lt = UA_LOCALIZEDTEXT_ALLOC(loc, colon + 1);
    free(loc);
    return lt;
}

static UA_Variant build_variant_scalar(const cJSON *jv, const char *dataType) {
    UA_Variant var; UA_Variant_init(&var);
    if (!jv || !dataType) return var;

    if (strcmp(dataType, "Boolean") == 0) {
        UA_Boolean v = cJSON_IsTrue(jv) ? UA_TRUE : UA_FALSE;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_BOOLEAN]);
    } else if (strcmp(dataType, "SByte") == 0) {
        UA_SByte v = (UA_SByte)jv->valueint;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_SBYTE]);
    } else if (strcmp(dataType, "Byte") == 0) {
        UA_Byte v = (UA_Byte)jv->valueint;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_BYTE]);
    } else if (strcmp(dataType, "Int16") == 0) {
        UA_Int16 v = (UA_Int16)jv->valueint;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_INT16]);
    } else if (strcmp(dataType, "UInt16") == 0) {
        UA_UInt16 v = (UA_UInt16)jv->valueint;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_UINT16]);
    } else if (strcmp(dataType, "Int32") == 0) {
        UA_Int32 v = (UA_Int32)jv->valueint;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_INT32]);
    } else if (strcmp(dataType, "UInt32") == 0) {
        UA_UInt32 v = (UA_UInt32)(uint32_t)jv->valuedouble;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_UINT32]);
    } else if (strcmp(dataType, "Int64") == 0) {
        UA_Int64 v;
        if (cJSON_IsString(jv)) v = (UA_Int64)strtoll(jv->valuestring, NULL, 10);
        else                    v = (UA_Int64)(int64_t)jv->valuedouble;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_INT64]);
    } else if (strcmp(dataType, "UInt64") == 0) {
        UA_UInt64 v;
        if (cJSON_IsString(jv)) v = (UA_UInt64)strtoull(jv->valuestring, NULL, 10);
        else                    v = (UA_UInt64)(uint64_t)jv->valuedouble;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_UINT64]);
    } else if (strcmp(dataType, "Float") == 0) {
        UA_Float v = (UA_Float)jv->valuedouble;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_FLOAT]);
    } else if (strcmp(dataType, "Double") == 0) {
        UA_Double v = jv->valuedouble;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_DOUBLE]);
    } else if (strcmp(dataType, "String") == 0) {
        const char *s = cJSON_IsString(jv) ? jv->valuestring : "";
        UA_String v   = UA_STRING_ALLOC(s);
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_STRING]);
        UA_String_clear(&v);
    } else if (strcmp(dataType, "XmlElement") == 0) {
        const char *s = cJSON_IsString(jv) ? jv->valuestring : "";
        UA_XmlElement v = UA_STRING_ALLOC(s);
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_XMLELEMENT]);
        UA_String_clear(&v);
    } else if (strcmp(dataType, "DateTime") == 0) {
        UA_DateTime v = parse_datetime(cJSON_IsString(jv) ? jv->valuestring : "");
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_DATETIME]);
    } else if (strcmp(dataType, "Guid") == 0) {
        UA_Guid v = parse_guid(cJSON_IsString(jv) ? jv->valuestring : "");
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_GUID]);
    } else if (strcmp(dataType, "ByteString") == 0) {
        UA_ByteString v = UA_BYTESTRING_NULL;
        if (cJSON_IsString(jv) && jv->valuestring && *jv->valuestring) {
            size_t outLen;
            uint8_t *decoded = b64_decode(jv->valuestring, &outLen);
            if (decoded) {
                v.data   = decoded;
                v.length = outLen;
            }
        }
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_ByteString_clear(&v);
    } else if (strcmp(dataType, "NodeId") == 0) {
        UA_NodeId v = UA_NODEID_NULL;
        if (cJSON_IsString(jv)) v = parse_nodeid(jv->valuestring, 0);
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_NODEID]);
        UA_NodeId_clear(&v);
    } else if (strcmp(dataType, "QualifiedName") == 0) {
        UA_QualifiedName v = parse_qualified_name(
            cJSON_IsString(jv) ? jv->valuestring : "");
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
        UA_QualifiedName_clear(&v);
    } else if (strcmp(dataType, "LocalizedText") == 0) {
        UA_LocalizedText v = parse_localized_text(
            cJSON_IsString(jv) ? jv->valuestring : "");
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        UA_LocalizedText_clear(&v);
    } else if (strcmp(dataType, "StatusCode") == 0) {
        UA_StatusCode v = (UA_StatusCode)(uint32_t)jv->valuedouble;
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_STATUSCODE]);
    }

    return var;
}

static UA_Variant build_variant(const cJSON *jv, const char *dataType, int valueRank) {
    UA_Variant var; UA_Variant_init(&var);
    if (!jv) return var;

    if (valueRank == -1 || !cJSON_IsArray(jv)) {
        return build_variant_scalar(jv, dataType);
    }

    /* Array — build an array of UA values via scalar variant allocation,
     * then collect into a single array variant. */
    int n = cJSON_GetArraySize(jv);
    const UA_DataType *dt = data_type_for_name(dataType);

    if (n == 0) {
        /* Empty array: UA_Array_new(0,…) returns UA_EMPTY_ARRAY_SENTINEL so
         * open62541 encodes arrayLength=0 (empty), not the null variant that
         * results from passing NULL directly to UA_Variant_setArray. */
        void *empty = UA_Array_new(0, dt);
        UA_Variant_setArray(&var, empty, 0, dt);
        return var;
    }

    /* Build intermediate array using UA_Array_new so memory is properly
     * managed by open62541. Each element is initialised with UA_copy from
     * the scalar variant. */
    void *arr = UA_Array_new((size_t)n, dt);
    if (!arr) return var;

    cJSON *el;
    int i = 0;
    cJSON_ArrayForEach(el, jv) {
        UA_Variant elem = build_variant_scalar(el, dataType);
        void *dst = (char*)arr + (size_t)i * dt->memSize;
        if (!UA_Variant_isEmpty(&elem) && elem.data) {
            /* Deep-copy the scalar value into the array slot. The slot was
             * zero-initialised by UA_Array_new, so UA_copy is safe. */
            UA_copy(elem.data, dst, dt);
        } else {
            UA_init(dst, dt);
        }
        UA_Variant_clear(&elem);
        i++;
    }

    /* UA_Variant_setArray takes ownership of arr; use setArrayCopy then
     * delete our copy so the variant is self-contained. */
    UA_Variant_setArrayCopy(&var, arr, (size_t)n, dt);
    UA_Array_delete(arr, (size_t)n, dt);
    return var;
}

/* -------------------------------------------------------------------------
 * BrowseName parsing (e.g. "1:Scalar.Int32")
 * ---------------------------------------------------------------------- */

static UA_QualifiedName parse_browse_name(const char *s) {
    if (!s) return UA_QUALIFIEDNAME(0, "");
    const char *colon = strchr(s, ':');
    if (colon) {
        UA_UInt16 nsIdx = (UA_UInt16)atoi(s);
        return UA_QUALIFIEDNAME_ALLOC(nsIdx, colon + 1);
    }
    return UA_QUALIFIEDNAME_ALLOC(0, s);
}

/* -------------------------------------------------------------------------
 * Method callbacks
 * ---------------------------------------------------------------------- */

static UA_StatusCode method_add_cb(UA_Server *srv, const UA_NodeId *sessionId,
    void *sessionCtx, const UA_NodeId *methodId, void *methodCtx,
    const UA_NodeId *objectId, void *objectCtx,
    size_t inputSize, const UA_Variant *input,
    size_t outputSize, UA_Variant *output) {
    (void)srv; (void)sessionId; (void)sessionCtx; (void)methodId;
    (void)methodCtx; (void)objectId; (void)objectCtx;
    if (inputSize < 2 || outputSize < 1) return UA_STATUSCODE_BADINVALIDARGUMENT;
    if (!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_INT32])) return UA_STATUSCODE_BADINVALIDARGUMENT;
    if (!UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_INT32])) return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Int32 a = *(UA_Int32*)input[0].data;
    UA_Int32 b = *(UA_Int32*)input[1].data;
    UA_Int32 r = a + b;
    UA_Variant_setScalarCopy(&output[0], &r, &UA_TYPES[UA_TYPES_INT32]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode method_multiply_cb(UA_Server *srv, const UA_NodeId *sessionId,
    void *sessionCtx, const UA_NodeId *methodId, void *methodCtx,
    const UA_NodeId *objectId, void *objectCtx,
    size_t inputSize, const UA_Variant *input,
    size_t outputSize, UA_Variant *output) {
    (void)srv; (void)sessionId; (void)sessionCtx; (void)methodId;
    (void)methodCtx; (void)objectId; (void)objectCtx;
    if (inputSize < 2 || outputSize < 1) return UA_STATUSCODE_BADINVALIDARGUMENT;
    if (!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_DOUBLE])) return UA_STATUSCODE_BADINVALIDARGUMENT;
    if (!UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_DOUBLE])) return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Double a = *(UA_Double*)input[0].data;
    UA_Double b = *(UA_Double*)input[1].data;
    UA_Double r = a * b;
    UA_Variant_setScalarCopy(&output[0], &r, &UA_TYPES[UA_TYPES_DOUBLE]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode method_echo_cb(UA_Server *srv, const UA_NodeId *sessionId,
    void *sessionCtx, const UA_NodeId *methodId, void *methodCtx,
    const UA_NodeId *objectId, void *objectCtx,
    size_t inputSize, const UA_Variant *input,
    size_t outputSize, UA_Variant *output) {
    (void)srv; (void)sessionId; (void)sessionCtx; (void)methodId;
    (void)methodCtx; (void)objectId; (void)objectCtx;
    if (inputSize < 1 || outputSize < 1) return UA_STATUSCODE_BADINVALIDARGUMENT;
    if (!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_STRING])) return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_String s;
    UA_String_copy((UA_String*)input[0].data, &s);
    UA_Variant_setScalarCopy(&output[0], &s, &UA_TYPES[UA_TYPES_STRING]);
    UA_String_clear(&s);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode method_noargs_cb(UA_Server *srv, const UA_NodeId *sessionId,
    void *sessionCtx, const UA_NodeId *methodId, void *methodCtx,
    const UA_NodeId *objectId, void *objectCtx,
    size_t inputSize, const UA_Variant *input,
    size_t outputSize, UA_Variant *output) {
    (void)srv; (void)sessionId; (void)sessionCtx; (void)methodId;
    (void)methodCtx; (void)objectId; (void)objectCtx;
    (void)inputSize; (void)input;
    if (outputSize < 1) return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Boolean v = UA_TRUE;
    UA_Variant_setScalarCopy(&output[0], &v, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode method_multipleoutputs_cb(UA_Server *srv, const UA_NodeId *sessionId,
    void *sessionCtx, const UA_NodeId *methodId, void *methodCtx,
    const UA_NodeId *objectId, void *objectCtx,
    size_t inputSize, const UA_Variant *input,
    size_t outputSize, UA_Variant *output) {
    (void)srv; (void)sessionId; (void)sessionCtx; (void)methodId;
    (void)methodCtx; (void)objectId; (void)objectCtx;
    if (inputSize < 1 || outputSize < 2) return UA_STATUSCODE_BADINVALIDARGUMENT;
    if (!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_INT32])) return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Int32 inp = *(UA_Int32*)input[0].data;
    UA_Int32 doubled = inp * 2;
    char label[32]; snprintf(label, sizeof(label), "%d", inp);
    UA_String labelStr = UA_STRING(label);
    UA_Variant_setScalarCopy(&output[0], &doubled, &UA_TYPES[UA_TYPES_INT32]);
    UA_Variant_setScalarCopy(&output[1], &labelStr, &UA_TYPES[UA_TYPES_STRING]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode method_fail_cb(UA_Server *srv, const UA_NodeId *sessionId,
    void *sessionCtx, const UA_NodeId *methodId, void *methodCtx,
    const UA_NodeId *objectId, void *objectCtx,
    size_t inputSize, const UA_Variant *input,
    size_t outputSize, UA_Variant *output) {
    (void)srv; (void)sessionId; (void)sessionCtx; (void)methodId;
    (void)methodCtx; (void)objectId; (void)objectCtx;
    (void)inputSize; (void)input; (void)outputSize; (void)output;
    return UA_STATUSCODE_BADINTERNALERROR;
}

static UA_MethodCallback method_callback_for(const char *behavior) {
    if (!behavior) return NULL;
    if (strcmp(behavior, "Add")             == 0) return method_add_cb;
    if (strcmp(behavior, "Multiply")        == 0) return method_multiply_cb;
    if (strcmp(behavior, "Echo")            == 0) return method_echo_cb;
    if (strcmp(behavior, "NoArguments")     == 0) return method_noargs_cb;
    if (strcmp(behavior, "MultipleOutputs") == 0) return method_multipleoutputs_cb;
    if (strcmp(behavior, "Fail")            == 0) return method_fail_cb;
    return NULL;
}

/* -------------------------------------------------------------------------
 * Build UA_Argument array from fixture Argument array
 * ---------------------------------------------------------------------- */

static UA_Argument *build_ua_arguments(const Argument *args, size_t count) {
    if (count == 0) return NULL;
    UA_Argument *out = calloc(count, sizeof(UA_Argument));
    if (!out) return NULL;
    for (size_t i = 0; i < count; i++) {
        UA_Argument_init(&out[i]);
        out[i].name        = UA_STRING_ALLOC(args[i].name ? args[i].name : "");
        out[i].dataType    = data_type_nodeid(args[i].dataType);
        out[i].valueRank   = args[i].valueRank;
        out[i].description = UA_LOCALIZEDTEXT_ALLOC("en",
            args[i].description ? args[i].description : "");
    }
    return out;
}

/* -------------------------------------------------------------------------
 * Behavior callbacks
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_Server   *server;
    UA_NodeId    nodeId;
    BehaviorKind kind;
    int64_t      counter;     /* for counter */
    UA_Boolean   toggle;      /* for toggle */
    double       rampVal;     /* for ramp */
    double       rampInc;
    double       rampMin;
    double       rampMax;
} BehaviorCtx;

static void behavior_callback(UA_Server *server, void *data) {
    BehaviorCtx *ctx = (BehaviorCtx*)data;
    UA_Variant var; UA_Variant_init(&var);

    switch (ctx->kind) {
        case BEH_COUNTER: {
            UA_Int64 v = (UA_Int64)ctx->counter++;
            UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_INT64]);
            break;
        }
        case BEH_TOGGLE: {
            ctx->toggle = !ctx->toggle;
            UA_Boolean v = ctx->toggle;
            UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_BOOLEAN]);
            break;
        }
        case BEH_RAMP: {
            UA_Double v = ctx->rampVal;
            ctx->rampVal += ctx->rampInc;
            if (ctx->rampVal > ctx->rampMax) ctx->rampVal = ctx->rampMin;
            UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_DOUBLE]);
            break;
        }
        default:
            return;
    }

    UA_Server_writeValue(server, ctx->nodeId, var);
    UA_Variant_clear(&var);
}

/* -------------------------------------------------------------------------
 * Ready file helpers
 * ---------------------------------------------------------------------- */

static void unlink_ready_file(const char *path) {
    if (!path || !*path) return;
    if (unlink(path) != 0 && errno != ENOENT) {
        fprintf(stderr, "[open62541] warn: unlink ready file '%s': %s\n",
                path, strerror(errno));
    }
}

/*
 * Write the readiness file atomically:
 *   1. Remove any stale file from a prior run (called on startup).
 *   2. Write JSON to <path>.tmp
 *   3. Rename <path>.tmp -> <path>
 * If explicit == 1 and the write/rename fails, print FATAL and return -1.
 * If explicit == 0, failures are warnings only and return 0.
 */
static int write_ready_file_atomic(const char *path, int explicit,
                                    const char *adapter,
                                    const char *fixture_id,
                                    const char *adv_url) {
    if (!path || !*path) return 0;

    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        if (explicit) {
            fprintf(stderr, "FATAL: cannot write ready file '%s': %s\n",
                    tmp_path, strerror(errno));
            return -1;
        }
        fprintf(stderr, "[open62541] warn: cannot write ready file '%s': %s\n",
                tmp_path, strerror(errno));
        return 0;
    }

    fprintf(fp, "{\"ready\":true,\"adapter\":\"%s\",\"fixture\":\"%s\",\"endpoint\":\"%s\"}\n",
            adapter ? adapter : "open62541",
            fixture_id ? fixture_id : "",
            adv_url ? adv_url : "");
    fclose(fp);

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        if (explicit) {
            fprintf(stderr, "FATAL: cannot rename ready file '%s' -> '%s': %s\n",
                    tmp_path, path, strerror(errno));
            return -1;
        }
        fprintf(stderr, "[open62541] warn: cannot rename ready file: %s\n",
                strerror(errno));
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Security helpers
 * ---------------------------------------------------------------------- */

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

#ifdef UA_ENABLE_ENCRYPTION

#include <dirent.h>

/* Load all *.crt / *.der files from a directory as DER byte-strings.
 * Returns a heap-allocated array via *out; caller must UA_ByteString_clear
 * each element and then free the array.  *count is set on success. */
static UA_ByteString *load_trust_dir(const char *dir_path, size_t *count) {
    *count = 0;
    if (!dir_path || !*dir_path) return NULL;

    DIR *d = opendir(dir_path);
    if (!d) return NULL;

    /* Two-pass: count then fill */
    size_t cap = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *n = ent->d_name;
        size_t l = strlen(n);
        if (l > 4 && (strcmp(n + l - 4, ".crt") == 0 ||
                       strcmp(n + l - 4, ".der") == 0))
            cap++;
    }

    if (cap == 0) { closedir(d); return NULL; }

    UA_ByteString *arr = (UA_ByteString *)calloc(cap, sizeof(UA_ByteString));
    if (!arr) { closedir(d); return NULL; }

    rewinddir(d);
    size_t n_filled = 0;
    char path_buf[1024];
    while ((ent = readdir(d)) != NULL && n_filled < cap) {
        const char *nm = ent->d_name;
        size_t l = strlen(nm);
        if (l > 4 && (strcmp(nm + l - 4, ".crt") == 0 ||
                       strcmp(nm + l - 4, ".der") == 0)) {
            snprintf(path_buf, sizeof(path_buf), "%s/%s", dir_path, nm);
            arr[n_filled] = load_cert_file(path_buf);
            if (arr[n_filled].length > 0) {
                fprintf(stderr, "[open62541] info: trust: loaded %s\n", path_buf);
                n_filled++;
            }
        }
    }
    closedir(d);
    *count = n_filled;
    return arr;
}

#endif /* UA_ENABLE_ENCRYPTION */

/* -------------------------------------------------------------------------
 * Gate-compliant raw historian (fixed samples) + BaseEvent emission
 * ---------------------------------------------------------------------- */

#ifdef UA_ENABLE_HISTORIZING

typedef struct {
    UA_NodeId histNodeId;
    UA_DataValue samples[5];
    size_t sampleCount;
    /* Simple session-local CP table: token -> next offset. */
    struct {
        UA_Byte token[8];
        size_t offset;
        UA_Boolean inUse;
        UA_Boolean released;
    } cps[16];
} InteropHistCtx;

static void interop_hist_clear(UA_HistoryDatabase *hdb) {
    InteropHistCtx *ctx = (InteropHistCtx *)hdb->context;
    if (!ctx) return;
    UA_NodeId_clear(&ctx->histNodeId);
    for (size_t i = 0; i < ctx->sampleCount; i++)
        UA_DataValue_clear(&ctx->samples[i]);
    free(ctx);
    hdb->context = NULL;
}

static void interop_hist_read_raw(
    UA_Server *server, void *hdbContext,
    const UA_NodeId *sessionId, void *sessionContext,
    const UA_RequestHeader *requestHeader,
    const UA_ReadRawModifiedDetails *details,
    UA_TimestampsToReturn timestampsToReturn,
    UA_Boolean releaseContinuationPoints,
    size_t nodesToReadSize,
    const UA_HistoryReadValueId *nodesToRead,
    UA_HistoryReadResponse *response,
    UA_HistoryData * const * const historyData)
{
    (void)server; (void)sessionId; (void)sessionContext;
    (void)requestHeader; (void)timestampsToReturn;
    InteropHistCtx *ctx = (InteropHistCtx *)hdbContext;
    if (!ctx || !details || !nodesToRead || !response || !historyData) return;

    for (size_t i = 0; i < nodesToReadSize; i++) {
        UA_HistoryReadResult *res = &response->results[i];
        if (!UA_NodeId_equal(&nodesToRead[i].nodeId, &ctx->histNodeId)) {
            res->statusCode = UA_STATUSCODE_BADHISTORYOPERATIONUNSUPPORTED;
            continue;
        }

        size_t offset = 0;
        const UA_ByteString *cpIn = &nodesToRead[i].continuationPoint;
        if (cpIn->length > 0 && cpIn->data) {
            int found = -1;
            for (size_t c = 0; c < 16; c++) {
                if (ctx->cps[c].inUse &&
                    ctx->cps[c].token[0] == cpIn->data[0] &&
                    (cpIn->length < 2 || ctx->cps[c].token[1] == cpIn->data[1])) {
                    found = (int)c;
                    break;
                }
            }
            if (found < 0 || ctx->cps[found].released) {
                res->statusCode = UA_STATUSCODE_BADCONTINUATIONPOINTINVALID;
                continue;
            }
            if (releaseContinuationPoints) {
                ctx->cps[found].released = UA_TRUE;
                res->statusCode = UA_STATUSCODE_GOOD;
                continue;
            }
            offset = ctx->cps[found].offset;
        } else if (releaseContinuationPoints) {
            res->statusCode = UA_STATUSCODE_GOOD;
            continue;
        }

        /* Filter by start/end (inclusive). */
        UA_DataValue matched[5];
        size_t matchedCount = 0;
        for (size_t s = 0; s < ctx->sampleCount && matchedCount < 5; s++) {
            UA_DateTime t = ctx->samples[s].sourceTimestamp;
            if (details->startTime && t < details->startTime) continue;
            if (details->endTime && t > details->endTime) continue;
            matched[matchedCount++] = ctx->samples[s]; /* shallow; copied below */
        }

        UA_UInt32 num = details->numValuesPerNode;
        if (num == 0 || num > matchedCount) num = (UA_UInt32)matchedCount;
        if (offset > matchedCount) {
            res->statusCode = UA_STATUSCODE_BADCONTINUATIONPOINTINVALID;
            continue;
        }
        size_t end = offset + (size_t)num;
        if (end > matchedCount) end = matchedCount;

        UA_HistoryData *hd = historyData[i];
        if (!hd) {
            res->statusCode = UA_STATUSCODE_BADINTERNALERROR;
            continue;
        }
        size_t n = end - offset;
        hd->dataValues = (UA_DataValue *)UA_Array_new(n, &UA_TYPES[UA_TYPES_DATAVALUE]);
        hd->dataValuesSize = n;
        for (size_t k = 0; k < n; k++)
            UA_DataValue_copy(&matched[offset + k], &hd->dataValues[k]);

        if (end < matchedCount) {
            /* Issue / refresh a CP token. */
            int slot = -1;
            for (size_t c = 0; c < 16; c++) {
                if (!ctx->cps[c].inUse ||
                    (cpIn->length > 0 && ctx->cps[c].token[0] == cpIn->data[0])) {
                    slot = (int)c; break;
                }
            }
            if (slot < 0) slot = 0;
            ctx->cps[slot].inUse = UA_TRUE;
            ctx->cps[slot].released = UA_FALSE;
            ctx->cps[slot].offset = end;
            ctx->cps[slot].token[0] = (UA_Byte)(1 + slot);
            ctx->cps[slot].token[1] = 0xA5;
            UA_ByteString_clear(&res->continuationPoint);
            UA_ByteString_allocBuffer(&res->continuationPoint, 2);
            res->continuationPoint.data[0] = ctx->cps[slot].token[0];
            res->continuationPoint.data[1] = ctx->cps[slot].token[1];
        }
        res->statusCode = UA_STATUSCODE_GOOD;
    }
}

static UA_HistoryDatabase interop_make_history_database(const UA_NodeId *histNodeId) {
    InteropHistCtx *ctx = calloc(1, sizeof(InteropHistCtx));
    UA_HistoryDatabase hdb;
    memset(&hdb, 0, sizeof(hdb));
    if (!ctx) return hdb;
    UA_NodeId_copy(histNodeId, &ctx->histNodeId);
    ctx->sampleCount = 5;
    /* 2026-07-24T10:00:00Z .. +20s step 5s, values 20..24 */
    /* 2026-07-24T10:00:00Z */
    UA_DateTime base = UA_DateTime_fromUnixTime(1784887200);
    for (size_t i = 0; i < 5; i++) {
        UA_Double val = 20.0 + (double)i;
        UA_DataValue_init(&ctx->samples[i]);
        UA_Variant_setScalarCopy(&ctx->samples[i].value, &val, &UA_TYPES[UA_TYPES_DOUBLE]);
        ctx->samples[i].hasValue = UA_TRUE;
        ctx->samples[i].hasSourceTimestamp = UA_TRUE;
        ctx->samples[i].hasServerTimestamp = UA_TRUE;
        ctx->samples[i].sourceTimestamp = base + (UA_DateTime)(i * 5) * UA_DATETIME_SEC;
        ctx->samples[i].serverTimestamp = ctx->samples[i].sourceTimestamp;
        ctx->samples[i].hasStatus = UA_TRUE;
        ctx->samples[i].status = UA_STATUSCODE_GOOD;
    }
    hdb.context = ctx;
    hdb.clear = interop_hist_clear;
    hdb.readRaw = interop_hist_read_raw;
    return hdb;
}

#endif /* UA_ENABLE_HISTORIZING */

typedef struct {
    UA_Server *server;
    UA_NodeId sourceId;
    UA_NodeId eventTypeId;
} InteropEventCtx;

static void interop_emit_base_event(UA_Server *server, void *data) {
    InteropEventCtx *ctx = (InteropEventCtx *)data;
    if (!ctx || !server) return;

    /* open62541 1.5 createEvent emits in one call (no separate triggerEvent). */
    UA_LocalizedText msg = UA_LOCALIZEDTEXT("en", "peer-event");
    UA_StatusCode sc = UA_Server_createEvent(
        server, ctx->sourceId, ctx->eventTypeId, 500, msg, NULL, NULL, NULL);
    if (sc != UA_STATUSCODE_GOOD)
        fprintf(stderr, "[open62541] warn: createEvent: 0x%08" PRIx32 "\n", (uint32_t)sc);
}

static UA_StatusCode interop_add_event_type(UA_Server *server, UA_NodeId *outType) {
    UA_ObjectTypeAttributes attr = UA_ObjectTypeAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT("en", "InteropBaseEventType");
    attr.description = UA_LOCALIZEDTEXT("en", "Concrete BaseEvent subtype for interop emission");
    return UA_Server_addObjectTypeNode(
        server, UA_NODEID_NULL,
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE),
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE),
        UA_QUALIFIEDNAME(1, "InteropBaseEventType"),
        attr, NULL, outType);
}

/* -------------------------------------------------------------------------
 * ECC SecurityPolicies
 *
 * Each ECC policy needs an application certificate of its own curve. They are
 * looked up as <ecc-dir>/ecc-<curve>/cert.crt and cert.key. Only policies that
 * are listed in the fixture's securityProfiles and whose certificate exists
 * get an endpoint.
 * ---------------------------------------------------------------------- */

#ifdef UA_ENABLE_ENCRYPTION

typedef UA_StatusCode (*EccAddPolicy)(UA_ServerConfig *config,
                                      const UA_ByteString *certificate,
                                      const UA_ByteString *privateKey);

static const struct {
    const char  *name;      /* fixture securityPolicy name */
    const char  *curveDir;  /* sub-directory of --ecc-dir */
    EccAddPolicy add;
} g_eccPolicies[] = {
    { "ECC_nistP256",            "ecc-nistp256",        UA_ServerConfig_addSecurityPolicyEccNistP256 },
    { "ECC_nistP384",            "ecc-nistp384",        UA_ServerConfig_addSecurityPolicyEccNistP384 },
    { "ECC_brainpoolP256r1",     "ecc-brainpoolp256r1", UA_ServerConfig_addSecurityPolicyEccBrainpoolP256r1 },
    { "ECC_brainpoolP384r1",     "ecc-brainpoolp384r1", UA_ServerConfig_addSecurityPolicyEccBrainpoolP384r1 },
    { "ECC_curve25519",          "ecc-curve25519",      UA_ServerConfig_addSecurityPolicyEccCurve25519 },
    { "ECC_curve448",            "ecc-curve448",        UA_ServerConfig_addSecurityPolicyEccCurve448 },
    { "ECC_nistP256_AesGcm",     "ecc-nistp256",        UA_ServerConfig_addSecurityPolicyEccNistP256AesGcm },
    { "ECC_nistP256_ChaChaPoly", "ecc-nistp256",        UA_ServerConfig_addSecurityPolicyEccNistP256ChaChaPoly },
};

static UA_MessageSecurityMode security_mode_from_name(const char *s) {
    if (s && strcmp(s, "Sign") == 0)           return UA_MESSAGESECURITYMODE_SIGN;
    if (s && strcmp(s, "SignAndEncrypt") == 0) return UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    return UA_MESSAGESECURITYMODE_NONE;
}

/* Adds the ECC policies + endpoints named in the fixture. Returns the number
 * of endpoints added. */
static size_t add_ecc_endpoints(UA_ServerConfig *cfg, const Fixture *fixture,
                                const char *eccDir) {
    size_t added = 0;
    for (size_t pi = 0; pi < sizeof(g_eccPolicies) / sizeof(g_eccPolicies[0]); pi++) {
        const char *name = g_eccPolicies[pi].name;

        /* Is this policy requested by the fixture at all? */
        int wanted = 0;
        for (size_t i = 0; i < fixture->securityProfileCount; i++)
            if (fixture->securityProfiles[i].policy &&
                strcmp(fixture->securityProfiles[i].policy, name) == 0)
                wanted = 1;
        if (!wanted) continue;

        char certPath[1100], keyPath[1100], uri[128];
        snprintf(certPath, sizeof(certPath), "%s/%s/cert.crt", eccDir, g_eccPolicies[pi].curveDir);
        snprintf(keyPath,  sizeof(keyPath),  "%s/%s/cert.key", eccDir, g_eccPolicies[pi].curveDir);
        if (access(certPath, R_OK) != 0 || access(keyPath, R_OK) != 0) {
            fprintf(stderr, "[open62541] info: ECC policy %s skipped (no %s)\n", name, certPath);
            continue;
        }
        UA_ByteString cert = load_cert_file(certPath);
        UA_ByteString key  = load_cert_file(keyPath);
        UA_StatusCode sc = g_eccPolicies[pi].add(cfg, &cert, &key);
        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        if (sc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "[open62541] warn: ECC policy %s not available: %s\n",
                    name, UA_StatusCode_name(sc));
            continue;
        }

        snprintf(uri, sizeof(uri), "http://opcfoundation.org/UA/SecurityPolicy#%s", name);
        for (size_t i = 0; i < fixture->securityProfileCount; i++) {
            const SecurityProfile *sp = &fixture->securityProfiles[i];
            if (!sp->policy || strcmp(sp->policy, name) != 0) continue;
            UA_MessageSecurityMode mode = security_mode_from_name(sp->mode);
            if (mode == UA_MESSAGESECURITYMODE_NONE) continue;
            sc = UA_ServerConfig_addEndpoint(cfg, UA_STRING(uri), mode);
            if (sc == UA_STATUSCODE_GOOD) {
                added++;
                fprintf(stderr, "[open62541] info: ECC endpoint %s/%s\n", name, sp->mode);
            } else {
                fprintf(stderr, "[open62541] warn: ECC endpoint %s/%s: %s\n",
                        name, sp->mode, UA_StatusCode_name(sc));
            }
        }
    }
    return added;
}

#endif /* UA_ENABLE_ENCRYPTION */

/* -------------------------------------------------------------------------
 * Reverse connect / discovery registration
 * ---------------------------------------------------------------------- */

static void reverse_state_cb(UA_Server *server, UA_UInt64 handle,
                             UA_SecureChannelState state, void *context) {
    (void)server;
    fprintf(stderr, "[open62541] info: reverse connect #%" PRIu64 " to %s: channel state %d\n",
            (uint64_t)handle, context ? (const char *)context : "?", (int)state);
}

#ifdef UA_ENABLE_DISCOVERY

static void register_with_lds(UA_Server *server, void *data) {
    const char *url = (const char *)data;
    UA_ClientConfig cc;
    memset(&cc, 0, sizeof(cc));
    UA_ClientConfig_setDefault(&cc);
    cc.securityMode = UA_MESSAGESECURITYMODE_NONE;
    UA_StatusCode sc = UA_Server_registerDiscovery(
        server, &cc, UA_STRING((char *)(uintptr_t)url), UA_STRING_NULL);
    if (sc != UA_STATUSCODE_GOOD)
        fprintf(stderr, "[open62541] warn: register with %s: %s\n", url, UA_StatusCode_name(sc));
}

#endif /* UA_ENABLE_DISCOVERY */

/* -------------------------------------------------------------------------
 * EURange property (AnalogItemType)
 * ---------------------------------------------------------------------- */

static void set_eu_range(UA_Server *server, const UA_NodeId *varId,
                         const char *fixtureId, double low, double high) {
    UA_Range range;
    range.low  = low;
    range.high = high;
    UA_Variant val;
    UA_Variant_init(&val);
    UA_Variant_setScalar(&val, &range, &UA_TYPES[UA_TYPES_RANGE]);

    /* AnalogItemType instances get their mandatory EURange child from the
     * type; write it if it is there, otherwise add the property. */
    UA_QualifiedName qn = UA_QUALIFIEDNAME(0, "EURange");
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, *varId, 1, &qn);
    UA_StatusCode sc;
    if (bpr.statusCode == UA_STATUSCODE_GOOD && bpr.targetsSize > 0) {
        sc = UA_Server_writeValue(server, bpr.targets[0].targetId.nodeId, val);
    } else {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        attr.displayName = UA_LOCALIZEDTEXT("en", "EURange");
        attr.dataType    = UA_TYPES[UA_TYPES_RANGE].typeId;
        attr.valueRank   = UA_VALUERANK_SCALAR;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        attr.value       = val;
        sc = UA_Server_addVariableNode(server, UA_NODEID_NULL, *varId,
                                       UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY), qn,
                                       UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
                                       attr, NULL, NULL);
    }
    UA_BrowsePathResult_clear(&bpr);
    if (sc != UA_STATUSCODE_GOOD)
        fprintf(stderr, "[open62541] warn: EURange of '%s': %s\n",
                fixtureId, UA_StatusCode_name(sc));
}

/* -------------------------------------------------------------------------
 * server_run
 * ---------------------------------------------------------------------- */

int server_run(const ServerArgs *args) {
    char errBuf[512];

    Fixture *fixture = fixture_load(args->fixturePath, errBuf, sizeof(errBuf));
    if (!fixture) {
        fprintf(stderr, "[open62541] error: fixture_load failed: %s\n", errBuf);
        return 1;
    }
    fprintf(stderr, "[open62541] info: fixture loaded id=%s\n", fixture->id);

    /* Resolve bind / advertised parameters */
    const char *bind_addr   = (args->bindAddress && *args->bindAddress)
                               ? args->bindAddress : "0.0.0.0";
    int         bind_port   = (args->bindPort > 0) ? args->bindPort : fixture->port;
    const char *adv_host    = (args->advertisedHost && *args->advertisedHost)
                               ? args->advertisedHost : "localhost";
    int         adv_port    = (args->advertisedPort > 0) ? args->advertisedPort : bind_port;
    const char *ep_path     = (args->endpointPath && *args->endpointPath)
                               ? args->endpointPath
                               : (fixture->endpointPath ? fixture->endpointPath : "");

    char bind_url[512];
    char adv_url[512];
    snprintf(bind_url, sizeof(bind_url), "opc.tcp://%s:%d%s", bind_addr, bind_port, ep_path);
    snprintf(adv_url,  sizeof(adv_url),  "opc.tcp://%s:%d%s", adv_host,  adv_port,  ep_path);

    fprintf(stderr, "[open62541] info: bind=%s advertised=%s\n", bind_url, adv_url);

    /* Remove any stale ready file from a prior run */
    if (args->readyFile && *args->readyFile)
        unlink_ready_file(args->readyFile);

    /* Create server using a pre-configured UA_ServerConfig so we control the
     * bind URL before any internal EventLoop state is attached.
     * UA_Server_new() would call UA_ServerConfig_setDefault(port=4840) internally,
     * which makes it unsafe to later replace serverUrls via UA_Array_delete.
     * By configuring serverUrls before passing to UA_Server_newWithConfig we own
     * the entire lifecycle of the config. */
    UA_ServerConfig cfg_val;
    memset(&cfg_val, 0, sizeof(UA_ServerConfig));

    /* Determine whether to enable security: an RSA application certificate
     * (cert + key) and / or a directory with ECC application certificates. */
    UA_Boolean have_rsa = (args->certFile && *args->certFile &&
                           args->keyFile  && *args->keyFile);
    UA_Boolean have_ecc = (args->eccDir && *args->eccDir);
    UA_Boolean use_security = have_rsa || have_ecc;

#ifdef UA_ENABLE_ENCRYPTION
    if (use_security) {
        UA_ByteString cert = have_rsa ? load_cert_file(args->certFile) : UA_BYTESTRING_NULL;
        UA_ByteString key  = have_rsa ? load_cert_file(args->keyFile)  : UA_BYTESTRING_NULL;
        if (have_rsa && (cert.length == 0 || key.length == 0)) {
            fprintf(stderr, "[open62541] error: failed to load certificate or private key\n");
            UA_ByteString_clear(&cert);
            UA_ByteString_clear(&key);
            fixture_free(fixture);
            return 1;
        }

        /* Load trust list from pki_dir/trusted/certs/ */
        char trust_dir[1024];
        const char *pki_dir = (args->pkiDir && *args->pkiDir)
                               ? args->pkiDir : "/run/opcua-interop/pki";
        snprintf(trust_dir, sizeof(trust_dir), "%s/trusted/certs", pki_dir);
        size_t trust_count = 0;
        UA_ByteString *trust_list = load_trust_dir(trust_dir, &trust_count);

        UA_StatusCode cfgSc = UA_ServerConfig_setDefaultWithSecurityPolicies(
            &cfg_val, (UA_UInt16)bind_port,
            &cert, &key,
            trust_list, trust_count,
            NULL, 0,
            NULL, 0);

        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        for (size_t i = 0; i < trust_count; i++)
            UA_ByteString_clear(&trust_list[i]);
        free(trust_list);

        if (cfgSc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "[open62541] error: UA_ServerConfig_setDefaultWithSecurityPolicies: 0x%08" PRIx32 "\n",
                    (uint32_t)cfgSc);
            fixture_free(fixture);
            return 1;
        }
        if (have_rsa)
            fprintf(stderr, "[open62541] info: security enabled from %s\n", args->certFile);

        if (have_ecc) {
            size_t n = add_ecc_endpoints(&cfg_val, fixture, args->eccDir);
            fprintf(stderr, "[open62541] info: %zu ECC endpoint(s) from %s\n", n, args->eccDir);
            /* The user token policies are derived from the SecurityPolicy
             * list; rebuild them now that it has grown. (Repeated below with
             * the fixture users, if any.) */
            UA_AccessControl_default(&cfg_val, UA_TRUE, NULL, 0, NULL);
        }
    } else {
        UA_StatusCode cfgSc = UA_ServerConfig_setDefault(&cfg_val);
        if (cfgSc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "[open62541] error: UA_ServerConfig_setDefault: 0x%08" PRIx32 "\n",
                    (uint32_t)cfgSc);
            fixture_free(fixture);
            return 1;
        }
    }
#else
    if (use_security) {
        fprintf(stderr, "[open62541] warn: --certificate/--private-key supplied but binary was "
                        "built without UA_ENABLE_ENCRYPTION; ignoring security config\n");
    }
    /* UA_ServerConfig_setDefault sets up the EventLoop, security policies, etc. */
    UA_StatusCode cfgSc = UA_ServerConfig_setDefault(&cfg_val);
    if (cfgSc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[open62541] error: UA_ServerConfig_setDefault: 0x%08" PRIx32 "\n",
                (uint32_t)cfgSc);
        fixture_free(fixture);
        return 1;
    }
#endif /* UA_ENABLE_ENCRYPTION */

    /* Replace serverUrls now — before the server is created and the EventLoop
     * registers anything.  setDefault leaves a "opc.tcp://:4840" entry; we
     * replace it with the desired bind URL. */
    {
        char bind_srv_url[256];
        /* Empty hostname = all interfaces in open62541 v1.5+ */
        if (strcmp(bind_addr, "0.0.0.0") == 0)
            snprintf(bind_srv_url, sizeof(bind_srv_url), "opc.tcp://:%d", bind_port);
        else
            snprintf(bind_srv_url, sizeof(bind_srv_url), "opc.tcp://%s:%d", bind_addr, bind_port);

        /* Safe to free here: setDefault populated this via UA_Array_copy which
         * produces normal heap allocations, and the EventLoop hasn't started. */
        UA_Array_delete(cfg_val.serverUrls, cfg_val.serverUrlsSize,
                        &UA_TYPES[UA_TYPES_STRING]);
        cfg_val.serverUrls     = NULL;
        cfg_val.serverUrlsSize = 0;

        UA_String bind_str = UA_STRING_ALLOC(bind_srv_url);
        UA_StatusCode scUrl =
            UA_Array_copy(&bind_str, 1, (void **)&cfg_val.serverUrls,
                          &UA_TYPES[UA_TYPES_STRING]);
        if (scUrl == UA_STATUSCODE_GOOD)
            cfg_val.serverUrlsSize = 1;
        UA_String_clear(&bind_str);
    }

    /* Allow username/password authentication over a None/None (unencrypted)
     * channel. OPC UA Part 4 §5.6.3.1 permits this for test deployments.
     * Without this flag open62541 silently drops every UserName token that
     * arrives on a None/None SecureChannel. */
    if (fixture->userCount > 0)
        cfg_val.allowNonePolicyPassword = UA_TRUE;

    /* Configure username/password access control BEFORE creating the server.
     * UA_AccessControl_default propagates the UserName token policy into the
     * endpoint descriptions during UA_Server_newWithConfig; calling it after
     * server creation updates the callbacks but not the endpoint token arrays,
     * causing clients to see no UserName policy in GetEndpoints. */
    if (fixture->userCount > 0) {
        UA_UsernamePasswordLogin *logins =
            (UA_UsernamePasswordLogin *)calloc(fixture->userCount,
                                               sizeof(UA_UsernamePasswordLogin));
        if (!logins) {
            fprintf(stderr, "[open62541] error: out of memory for user logins\n");
            fixture_free(fixture);
            return 1;
        }
        for (size_t i = 0; i < fixture->userCount; i++) {
            logins[i].username = UA_STRING_ALLOC(fixture->users[i].username
                                                  ? fixture->users[i].username : "");
            logins[i].password = UA_STRING_ALLOC(fixture->users[i].password
                                                  ? fixture->users[i].password : "");
        }
        UA_StatusCode acSc = UA_AccessControl_default(
            &cfg_val, UA_TRUE /* allowAnonymous */, NULL,
            fixture->userCount, logins);
        for (size_t i = 0; i < fixture->userCount; i++) {
            UA_String_clear(&logins[i].username);
            UA_String_clear(&logins[i].password);
        }
        free(logins);
        if (acSc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "[open62541] warn: UA_AccessControl_default: 0x%08" PRIx32 "\n",
                    (uint32_t)acSc);
        } else {
            fprintf(stderr, "[open62541] info: username/password auth enabled (%zu user(s))\n",
                    fixture->userCount);
        }
    }

    /* Reverse connect retry interval (the stack default is 15 s). */
    cfg_val.reverseReconnectInterval = (UA_UInt32)args->reverseIntervalMs;

#ifdef UA_ENABLE_DISCOVERY
    if (args->lds) {
        /* RegisterServer / RegisterServer2 are only served by a
         * DiscoveryServer application. */
        cfg_val.applicationDescription.applicationType = UA_APPLICATIONTYPE_DISCOVERYSERVER;
        if (args->ldsCleanupTimeoutS > 0)
            cfg_val.discoveryCleanupTimeout = (UA_UInt32)args->ldsCleanupTimeoutS;
    }
# ifdef UA_ENABLE_DISCOVERY_MULTICAST
    {
        /* The mDNS record (also sent in RegisterServer2). mDNS itself is on
         * for an LDS (FindServersOnNetwork) and with --mdns-name. */
        const char *mdns_name = (args->mdnsName && *args->mdnsName)
            ? args->mdnsName
            : (args->lds ? "opcua-interop-lds"
                         : (fixture->applicationName ? fixture->applicationName
                                                     : "opcua-interop"));
        UA_String_clear(&cfg_val.mdnsConfig.mdnsServerName);
        cfg_val.mdnsConfig.mdnsServerName = UA_STRING_ALLOC(mdns_name);

        size_t capCount = args->mdnsCapCount > 0 ? (size_t)args->mdnsCapCount : 1;
        UA_String *caps = (UA_String *)UA_Array_new(capCount, &UA_TYPES[UA_TYPES_STRING]);
        if (caps) {
            if (args->mdnsCapCount > 0) {
                for (size_t i = 0; i < capCount; i++)
                    caps[i] = UA_STRING_ALLOC(args->mdnsCaps[i]);
            } else {
                caps[0] = UA_STRING_ALLOC(args->lds ? "LDS" : "NA");
            }
            UA_Array_delete(cfg_val.mdnsConfig.serverCapabilities,
                            cfg_val.mdnsConfig.serverCapabilitiesSize,
                            &UA_TYPES[UA_TYPES_STRING]);
            cfg_val.mdnsConfig.serverCapabilities = caps;
            cfg_val.mdnsConfig.serverCapabilitiesSize = capCount;
        }
        cfg_val.mdnsEnabled = (args->lds || (args->mdnsName && *args->mdnsName));
        if (cfg_val.mdnsEnabled)
            fprintf(stderr, "[open62541] info: mDNS enabled name=%s\n", mdns_name);
    }
# endif
#endif

    UA_Server *server = UA_Server_newWithConfig(&cfg_val);
    if (!server) {
        fprintf(stderr, "[open62541] error: UA_Server_newWithConfig failed\n");
        /* cfg_val ownership was consumed by UA_Server_newWithConfig even on
         * failure; do not call UA_ServerConfig_clean here (deprecated, and the
         * memory is no longer ours to free). */
        fixture_free(fixture);
        return 1;
    }
    UA_ServerConfig *cfg = UA_Server_getConfig(server);

    /* In open62541 v1.5.x endpoints are populated after startup from serverUrls.
     * Override endpoint/discovery URLs now for any that are already set,
     * and record adv_url so the startup hooks can apply it too.
     * (Pre-startup arrays may be empty — the loops are no-ops in that case.) */
    for (size_t i = 0; i < cfg->endpointsSize; i++) {
        UA_String_clear(&cfg->endpoints[i].endpointUrl);
        cfg->endpoints[i].endpointUrl = UA_STRING_ALLOC(adv_url);
    }
    for (size_t i = 0; i < cfg->applicationDescription.discoveryUrlsSize; i++) {
        UA_String_clear(&cfg->applicationDescription.discoveryUrls[i]);
        cfg->applicationDescription.discoveryUrls[i] = UA_STRING_ALLOC(adv_url);
    }
    if (fixture->applicationUri) {
        UA_String_clear(&cfg->applicationDescription.applicationUri);
        cfg->applicationDescription.applicationUri =
            UA_STRING_ALLOC(fixture->applicationUri);
    }
    if (fixture->productUri) {
        UA_String_clear(&cfg->applicationDescription.productUri);
        cfg->applicationDescription.productUri =
            UA_STRING_ALLOC(fixture->productUri);
    }
    if (fixture->applicationName) {
        UA_LocalizedText_clear(&cfg->applicationDescription.applicationName);
        cfg->applicationDescription.applicationName =
            UA_LOCALIZEDTEXT_ALLOC("en", fixture->applicationName);
    }

    /* Register namespaces */
    UA_UInt16 *nsMap = calloc(fixture->namespaceCount + 1, sizeof(UA_UInt16));
    if (!nsMap) {
        fprintf(stderr, "[open62541] error: out of memory\n");
        UA_Server_delete(server);
        fixture_free(fixture);
        return 1;
    }
    for (size_t i = 0; i < fixture->namespaceCount; i++) {
        nsMap[i] = UA_Server_addNamespace(server, fixture->namespaces[i].uri);
    }

    /* Helper: resolve a fixture NodeId string to a UA_NodeId */
#define RESOLVE(s) resolve_nodeid(server, (s))

    /* Add nodes */
    for (size_t ni = 0; ni < fixture->nodeCount; ni++) {
        FixtureNode *nd = &fixture->nodes[ni];
        UA_NodeId nodeId     = RESOLVE(nd->nodeId);
        UA_NodeId parentId   = RESOLVE(nd->parentNodeId);
        UA_NodeId refTypeId  = ref_type_id(nd->referenceType);
        UA_QualifiedName bn  = parse_browse_name(nd->browseName);
        UA_LocalizedText dn  = UA_LOCALIZEDTEXT_ALLOC("en",
            nd->displayName ? nd->displayName : "");
        UA_LocalizedText desc = UA_LOCALIZEDTEXT_ALLOC("en",
            nd->description ? nd->description : "");

        UA_StatusCode sc = UA_STATUSCODE_GOOD;

        switch (nd->nodeClass) {
            case NODE_OBJECT: {
                UA_ObjectAttributes attr = UA_ObjectAttributes_default;
                attr.displayName = dn;
                attr.description = desc;
                if (nd->nodeId && strstr(nd->nodeId, "s=Events.Source"))
                    attr.eventNotifier = (UA_Byte)1; /* SubscribeToEvents */
                UA_NodeId typeDefId = nd->typeDefinition
                    ? RESOLVE(nd->typeDefinition)
                    : UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE);
                sc = UA_Server_addObjectNode(server, nodeId, parentId,
                    refTypeId, bn, typeDefId, attr, NULL, NULL);
                break;
            }
            case NODE_VARIABLE: {
                UA_VariableAttributes attr = UA_VariableAttributes_default;
                attr.displayName  = dn;
                attr.description  = desc;
                attr.dataType     = data_type_nodeid(nd->dataType);
                attr.valueRank    = nd->valueRank;
                attr.accessLevel  = nd->accessLevel;
                attr.userAccessLevel = nd->accessLevel;
                if (nd->nodeId && strstr(nd->nodeId, "s=History.Temperature"))
                    attr.historizing = UA_TRUE;

                if (nd->arrayDimensions && nd->arrayDimensionsSize > 0) {
                    attr.arrayDimensions     = nd->arrayDimensions;
                    attr.arrayDimensionsSize = nd->arrayDimensionsSize;
                }

                if (nd->initialValue) {
                    attr.value = build_variant(nd->initialValue, nd->dataType,
                                               nd->valueRank);
                    /* Per OPC UA Part 6 §5.1.4, the Variant's ArrayDimensions
                     * field is only encoded for multi-dimensional arrays
                     * (ValueRank >= 2). Setting it for 1D arrays causes
                     * open62541 to reject the encoding when the declared
                     * dimension size (0 = variable) does not match the actual
                     * element count. */
                    if (nd->arrayDimensions && nd->arrayDimensionsSize > 1
                            && !UA_Variant_isEmpty(&attr.value)) {
                        attr.value.arrayDimensions =
                            (UA_UInt32 *)UA_Array_new(nd->arrayDimensionsSize,
                                                      &UA_TYPES[UA_TYPES_UINT32]);
                        if (attr.value.arrayDimensions) {
                            memcpy(attr.value.arrayDimensions, nd->arrayDimensions,
                                   nd->arrayDimensionsSize * sizeof(UA_UInt32));
                            attr.value.arrayDimensionsSize = nd->arrayDimensionsSize;
                        }
                    }
                }

                UA_NodeId typeDefId = nd->typeDefinition
                    ? RESOLVE(nd->typeDefinition)
                    : UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE);
                sc = UA_Server_addVariableNode(server, nodeId, parentId,
                    refTypeId, bn, typeDefId, attr, NULL, NULL);
                UA_Variant_clear(&attr.value);
                if (sc == UA_STATUSCODE_GOOD && nd->hasEuRange)
                    set_eu_range(server, &nodeId, nd->nodeId,
                                 nd->euRangeLow, nd->euRangeHigh);
                break;
            }
            case NODE_METHOD: {
                UA_MethodAttributes attr = UA_MethodAttributes_default;
                attr.displayName  = dn;
                attr.description  = desc;
                attr.executable      = UA_TRUE;
                attr.userExecutable  = UA_TRUE;

                UA_Argument *inArgs  = build_ua_arguments(nd->inputArgs,  nd->inputArgCount);
                UA_Argument *outArgs = build_ua_arguments(nd->outputArgs, nd->outputArgCount);
                UA_MethodCallback cb = method_callback_for(nd->methodBehavior);

                sc = UA_Server_addMethodNode(server, nodeId, parentId,
                    refTypeId, bn, attr, cb,
                    nd->inputArgCount,  inArgs,
                    nd->outputArgCount, outArgs,
                    NULL, NULL);

                for (size_t j = 0; j < nd->inputArgCount; j++)
                    UA_Argument_clear(&inArgs[j]);
                for (size_t j = 0; j < nd->outputArgCount; j++)
                    UA_Argument_clear(&outArgs[j]);
                free(inArgs); free(outArgs);
                break;
            }
        }

        UA_QualifiedName_clear(&bn);
        UA_LocalizedText_clear(&dn);
        UA_LocalizedText_clear(&desc);
        UA_NodeId_clear(&nodeId);
        UA_NodeId_clear(&parentId);
        UA_NodeId_clear(&refTypeId);

        if (sc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "[open62541] warn: addNode '%s' failed: 0x%08" PRIx32 "\n",
                    nd->nodeId, (uint32_t)sc);
        }
    }
#undef RESOLVE

    /* Install gate-compliant raw historian for History.Temperature */
#ifdef UA_ENABLE_HISTORIZING
    {
        UA_NodeId histId = resolve_nodeid(server,
            "nsu=urn:otfabric:opcua-interop:model;s=History.Temperature");
        UA_ServerConfig *scfg = UA_Server_getConfig(server);
        scfg->historyDatabase = interop_make_history_database(&histId);
        UA_NodeId_clear(&histId);
        fprintf(stderr, "[open62541] info: History.Temperature raw historian enabled\n");
    }
#endif

    /* Concrete BaseEvent subtype + periodic emission from Events.Source */
    InteropEventCtx *evtCtx = calloc(1, sizeof(InteropEventCtx));
    if (evtCtx) {
        evtCtx->server = server;
        evtCtx->sourceId = resolve_nodeid(server,
            "nsu=urn:otfabric:opcua-interop:model;s=Events.Source");
        UA_StatusCode esc = interop_add_event_type(server, &evtCtx->eventTypeId);
        if (esc == UA_STATUSCODE_GOOD &&
            !UA_NodeId_isNull(&evtCtx->sourceId)) {
            UA_UInt64 evtCbId = 0;
            UA_Server_addRepeatedCallback(server, interop_emit_base_event, evtCtx,
                                          2000, &evtCbId);
            fprintf(stderr, "[open62541] info: BaseEvent emission scheduled on Events.Source\n");
        } else {
            fprintf(stderr, "[open62541] warn: event setup failed: 0x%08" PRIx32 "\n",
                    (uint32_t)esc);
            UA_NodeId_clear(&evtCtx->sourceId);
            UA_NodeId_clear(&evtCtx->eventTypeId);
            free(evtCtx);
            evtCtx = NULL;
        }
    }

    /* Register behavior repeated callbacks */
    BehaviorCtx *behCtxs = calloc(fixture->behaviorCount, sizeof(BehaviorCtx));
    if (behCtxs) {
        for (size_t bi = 0; bi < fixture->behaviorCount; bi++) {
            Behavior   *beh = &fixture->behaviors[bi];
            BehaviorCtx *ctx = &behCtxs[bi];

            /* fixed-status is applied once after startup; skip the scheduler. */
            if (beh->kind == BEH_FIXED_STATUS) continue;

            ctx->server  = server;
            ctx->nodeId  = resolve_nodeid(server, beh->target);
            ctx->kind    = beh->kind;
            ctx->counter = (int64_t)beh->initial;
            ctx->toggle  = UA_FALSE;
            ctx->rampVal = beh->initial;
            ctx->rampInc = beh->increment;
            ctx->rampMin = beh->minimum;
            ctx->rampMax = beh->maximum;

            UA_UInt64 cbId;
            UA_Server_addRepeatedCallback(server, behavior_callback, ctx,
                                          (UA_UInt32)beh->intervalMs, &cbId);
        }
    }

    /* Apply fixed-status behaviors: write a DataValue with the given status
     * code to each target node.  Done before startup so the status is visible
     * from the first read after the server becomes ready. */
    for (size_t bi = 0; bi < fixture->behaviorCount; bi++) {
        Behavior *beh = &fixture->behaviors[bi];
        if (beh->kind != BEH_FIXED_STATUS) continue;
        UA_NodeId nid = resolve_nodeid(server, beh->target);
        /* Read the existing value to preserve it. */
        UA_Variant existing; UA_Variant_init(&existing);
        UA_Server_readValue(server, nid, &existing);
        UA_DataValue dv;
        UA_DataValue_init(&dv);
        UA_Variant_copy(&existing, &dv.value);
        dv.hasValue  = UA_TRUE;
        dv.hasStatus = UA_TRUE;
        dv.status    = (UA_StatusCode)(uint32_t)beh->initial;
        UA_Server_writeDataValue(server, nid, dv);
        UA_Variant_clear(&existing);
        UA_DataValue_clear(&dv);
        UA_NodeId_clear(&nid);
    }

    /* Signal handling */
    signal(SIGTERM, on_signal);
    signal(SIGINT,  on_signal);

    /* Start server */
    UA_StatusCode sc = UA_Server_run_startup(server);
    if (sc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[open62541] error: UA_Server_run_startup: 0x%08" PRIx32 "\n",
                (uint32_t)sc);
        UA_Server_delete(server);
        free(behCtxs); free(nsMap);
        fixture_free(fixture);
        return 1;
    }

    fprintf(stderr, "[open62541] info: server started bind_port=%d adv=%s\n",
            bind_port, adv_url);

    /* The stack fills applicationDescription.discoveryUrls from the listen
     * sockets (opc.tcp://<hostname>:<port>). Publish the advertised endpoint
     * URL instead: it is what FindServers returns, what is registered with an
     * LDS, and the EndpointUrl of the ReverseHello. */
    {
        UA_Array_delete(cfg->applicationDescription.discoveryUrls,
                        cfg->applicationDescription.discoveryUrlsSize,
                        &UA_TYPES[UA_TYPES_STRING]);
        cfg->applicationDescription.discoveryUrls = NULL;
        cfg->applicationDescription.discoveryUrlsSize = 0;
        UA_String adv = UA_STRING(adv_url);
        if (UA_Array_copy(&adv, 1, (void **)&cfg->applicationDescription.discoveryUrls,
                          &UA_TYPES[UA_TYPES_STRING]) == UA_STATUSCODE_GOOD)
            cfg->applicationDescription.discoveryUrlsSize = 1;
    }

    for (int ri = 0; ri < args->reverseConnectCount; ri++) {
        UA_UInt64 handle = 0;
        UA_StatusCode rsc = UA_Server_addReverseConnect(
            server, UA_STRING(args->reverseConnect[ri]),
            reverse_state_cb, args->reverseConnect[ri], &handle);
        fprintf(stderr, "[open62541] info: reverse connect to %s every %d ms: %s\n",
                args->reverseConnect[ri], args->reverseIntervalMs,
                UA_StatusCode_name(rsc));
    }

#ifdef UA_ENABLE_DISCOVERY
    /* (UA_Server_setRegisterServerCallback is declared by v1.5.9 but not
     * implemented, so registrations are not logged here.) */
    if (args->registerWith && *args->registerWith) {
        UA_UInt64 regCbId = 0;
        register_with_lds(server, args->registerWith);
        UA_Server_addRepeatedCallback(server, register_with_lds, args->registerWith,
                                      (UA_Double)args->registerIntervalMs, &regCbId);
        fprintf(stderr, "[open62541] info: registering with %s every %d ms\n",
                args->registerWith, args->registerIntervalMs);
    }
#endif

    /* Write readiness file atomically */
    if (args->readyFile && *args->readyFile) {
        int r = write_ready_file_atomic(args->readyFile, args->readyFileExplicit,
                                         "open62541", fixture->id, adv_url);
        if (r != 0) {
            UA_Server_run_shutdown(server);
            UA_Server_delete(server);
            free(behCtxs); free(nsMap);
            fixture_free(fixture);
            return 6;
        }
    }

    /* Main loop */
    while (g_running) {
        UA_Server_run_iterate(server, UA_TRUE);
    }

    fprintf(stderr, "[open62541] info: shutting down\n");
#ifdef UA_ENABLE_DISCOVERY
    if (args->registerWith && *args->registerWith) {
        /* Unregister (isOnline=false) and give the async exchange a moment. */
        UA_ClientConfig cc;
        memset(&cc, 0, sizeof(cc));
        UA_ClientConfig_setDefault(&cc);
        cc.securityMode = UA_MESSAGESECURITYMODE_NONE;
        UA_StatusCode dsc = UA_Server_deregisterDiscovery(
            server, &cc, UA_STRING(args->registerWith));
        fprintf(stderr, "[open62541] info: unregister from %s: %s\n",
                args->registerWith, UA_StatusCode_name(dsc));
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            UA_Server_run_iterate(server, UA_FALSE);
            struct timespec nap = { 0, 10 * 1000 * 1000 };
            nanosleep(&nap, NULL);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if ((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 >= 1500)
                break;
        }
    }
#endif
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);

    /* Remove ready file on clean shutdown */
    if (args->readyFile && *args->readyFile)
        unlink_ready_file(args->readyFile);

    /* Clean up behavior contexts */
    if (behCtxs) {
        for (size_t bi = 0; bi < fixture->behaviorCount; bi++)
            UA_NodeId_clear(&behCtxs[bi].nodeId);
        free(behCtxs);
    }
    if (evtCtx) {
        UA_NodeId_clear(&evtCtx->sourceId);
        UA_NodeId_clear(&evtCtx->eventTypeId);
        free(evtCtx);
    }

    free(nsMap);
    fixture_free(fixture);
    return 0;
}
