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
        } else if (strcmp(argv[i], "--ready-file") == 0 && i+1 < argc) {
            free(out->readyFile);      out->readyFile      = strdup(argv[++i]);
            out->readyFileExplicit = 1;
        }
    }

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
            return UA_NODEID_STRING(nsuIndex, (char*)(semi + 2));
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
            return UA_NODEID_STRING(ns, (char*)(semi + 2));
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
        UA_UInt32 v = (UA_UInt32)(uint32_t)jv->valueint;
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
    } else if (strcmp(dataType, "String") == 0 ||
               strcmp(dataType, "XmlElement") == 0) {
        const char *s = cJSON_IsString(jv) ? jv->valuestring : "";
        UA_String v   = UA_STRING_ALLOC(s);
        UA_Variant_setScalarCopy(&var, &v, &UA_TYPES[UA_TYPES_STRING]);
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
        UA_StatusCode v = (UA_StatusCode)(uint32_t)jv->valueint;
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
        UA_Variant_setArray(&var, NULL, 0, dt);
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

    /* Create server */
    UA_Server *server = UA_Server_new();
    if (!server) {
        fprintf(stderr, "[open62541] error: UA_Server_new failed\n");
        fixture_free(fixture);
        return 1;
    }
    UA_ServerConfig *cfg = UA_Server_getConfig(server);
    UA_StatusCode cfgSc = UA_ServerConfig_setMinimal(cfg, (UA_UInt16)bind_port, NULL);
    if (cfgSc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "[open62541] error: UA_ServerConfig_setMinimal: 0x%08" PRIx32 "\n",
                (uint32_t)cfgSc);
        UA_Server_delete(server);
        fixture_free(fixture);
        return 1;
    }

    /* Override advertised endpoint URL */
    for (size_t i = 0; i < cfg->endpointsSize; i++) {
        UA_String_clear(&cfg->endpoints[i].endpointUrl);
        cfg->endpoints[i].endpointUrl = UA_STRING_ALLOC(adv_url);
    }
    for (size_t i = 0; i < cfg->applicationDescription.discoveryUrlsSize; i++) {
        UA_String_clear(&cfg->applicationDescription.discoveryUrls[i]);
        cfg->applicationDescription.discoveryUrls[i] = UA_STRING_ALLOC(adv_url);
    }
    /* serverUrls (v1.3.x uses endpointUrl / discoveryUrls only) */

    /* Application description */
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

                if (nd->initialValue) {
                    attr.value = build_variant(nd->initialValue, nd->dataType,
                                               nd->valueRank);
                }

                UA_NodeId typeDefId = nd->typeDefinition
                    ? RESOLVE(nd->typeDefinition)
                    : UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE);
                sc = UA_Server_addVariableNode(server, nodeId, parentId,
                    refTypeId, bn, typeDefId, attr, NULL, NULL);
                UA_Variant_clear(&attr.value);
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

    /* Register behavior repeated callbacks */
    BehaviorCtx *behCtxs = calloc(fixture->behaviorCount, sizeof(BehaviorCtx));
    if (behCtxs) {
        for (size_t bi = 0; bi < fixture->behaviorCount; bi++) {
            Behavior   *beh = &fixture->behaviors[bi];
            BehaviorCtx *ctx = &behCtxs[bi];
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

    free(nsMap);
    fixture_free(fixture);
    return 0;
}
