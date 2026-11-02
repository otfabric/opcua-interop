#define _GNU_SOURCE

#include "values.h"

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cjson/cJSON.h>

/* -------------------------------------------------------------------------
 * Built-in type table
 * ---------------------------------------------------------------------- */

static const struct { const char *name; int idx; } g_builtin[] = {
    { "Boolean",         UA_TYPES_BOOLEAN },
    { "SByte",           UA_TYPES_SBYTE },
    { "Byte",            UA_TYPES_BYTE },
    { "Int16",           UA_TYPES_INT16 },
    { "UInt16",          UA_TYPES_UINT16 },
    { "Int32",           UA_TYPES_INT32 },
    { "UInt32",          UA_TYPES_UINT32 },
    { "Int64",           UA_TYPES_INT64 },
    { "UInt64",          UA_TYPES_UINT64 },
    { "Float",           UA_TYPES_FLOAT },
    { "Double",          UA_TYPES_DOUBLE },
    { "String",          UA_TYPES_STRING },
    { "DateTime",        UA_TYPES_DATETIME },
    { "Guid",            UA_TYPES_GUID },
    { "ByteString",      UA_TYPES_BYTESTRING },
    { "XmlElement",      UA_TYPES_XMLELEMENT },
    { "NodeId",          UA_TYPES_NODEID },
    { "ExpandedNodeId",  UA_TYPES_EXPANDEDNODEID },
    { "StatusCode",      UA_TYPES_STATUSCODE },
    { "QualifiedName",   UA_TYPES_QUALIFIEDNAME },
    { "LocalizedText",   UA_TYPES_LOCALIZEDTEXT },
    { "ExtensionObject", UA_TYPES_EXTENSIONOBJECT },
    { "DataValue",       UA_TYPES_DATAVALUE },
    { "Variant",         UA_TYPES_VARIANT },
    { "DiagnosticInfo",  UA_TYPES_DIAGNOSTICINFO },
};

const UA_DataType *value_builtin_type(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < sizeof(g_builtin) / sizeof(g_builtin[0]); i++)
        if (strcmp(name, g_builtin[i].name) == 0)
            return &UA_TYPES[g_builtin[i].idx];
    return NULL;
}

const char *value_type_name(const UA_DataType *type) {
    if (!type) return "Unknown";
    for (size_t i = 0; i < sizeof(g_builtin) / sizeof(g_builtin[0]); i++)
        if (type == &UA_TYPES[g_builtin[i].idx])
            return g_builtin[i].name;
    return type->typeName ? type->typeName : "Unknown";
}

/* -------------------------------------------------------------------------
 * Base64
 * ---------------------------------------------------------------------- */

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

unsigned char *value_b64_decode(const char *in, size_t *outLen) {
    *outLen = 0;
    if (!in) return NULL;
    size_t inLen = strlen(in);
    if (inLen == 0) return (unsigned char *)calloc(1, 1);
    if (inLen % 4 != 0) return NULL;

    size_t n = inLen / 4 * 3;
    if (in[inLen - 1] == '=') n--;
    if (in[inLen - 2] == '=') n--;

    unsigned char *out = (unsigned char *)malloc(n + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < inLen; i += 4) {
        int a = b64_val(in[i]);
        int b = b64_val(in[i + 1]);
        int c = (in[i + 2] == '=') ? 0 : b64_val(in[i + 2]);
        int d = (in[i + 3] == '=') ? 0 : b64_val(in[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(out); return NULL; }
        if (j < n) out[j++] = (unsigned char)((a << 2) | (b >> 4));
        if (j < n) out[j++] = (unsigned char)(((b & 0xf) << 4) | (c >> 2));
        if (j < n) out[j++] = (unsigned char)(((c & 3) << 6) | d);
    }
    *outLen = n;
    return out;
}

char *value_b64_encode(const unsigned char *data, size_t len) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t outLen = ((len + 2) / 3) * 4;
    char *out = (char *)malloc(outLen + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned char a = data[i];
        unsigned char b = (i + 1 < len) ? data[i + 1] : 0;
        unsigned char c = (i + 2 < len) ? data[i + 2] : 0;
        out[j++] = b64[a >> 2];
        out[j++] = b64[((a & 3) << 4) | (b >> 4)];
        out[j++] = (i + 1 < len) ? b64[((b & 0xf) << 2) | (c >> 6)] : '=';
        out[j++] = (i + 2 < len) ? b64[c & 0x3f] : '=';
    }
    out[j] = '\0';
    return out;
}

/* -------------------------------------------------------------------------
 * Scalar literal parsers
 * ---------------------------------------------------------------------- */

int value_parse_datetime(const char *s, UA_DateTime *out) {
    if (!s || !*s) return -1;
    int Y, M, D, h, m, sec, consumed = 0;
    if (sscanf(s, "%d-%d-%dT%d:%d:%d%n", &Y, &M, &D, &h, &m, &sec, &consumed) < 6)
        return -1;
    const char *p = s + consumed;
    int64_t ticks = 0; /* 100 ns units */
    if (*p == '.') {
        p++;
        int digits = 0;
        while (isdigit((unsigned char)*p)) {
            if (digits < 7) { ticks = ticks * 10 + (*p - '0'); digits++; }
            p++;
        }
        while (digits < 7) { ticks *= 10; digits++; }
    }
    if (*p != 'Z' && *p != 'z' && *p != '\0') return -1;

    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = Y - 1900;
    tm.tm_mon  = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min  = m;
    tm.tm_sec  = sec;
    time_t t = timegm(&tm);
    *out = (UA_DateTime)(((int64_t)t + 11644473600LL) * UA_DATETIME_SEC + ticks);
    return 0;
}

static int parse_guid(const char *s, UA_Guid *out) {
    unsigned d1, d2, d3, b[8];
    if (!s || strlen(s) != 36) return -1;
    if (sscanf(s, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               &d1, &d2, &d3, &b[0], &b[1], &b[2], &b[3],
               &b[4], &b[5], &b[6], &b[7]) != 11)
        return -1;
    out->data1 = (UA_UInt32)d1;
    out->data2 = (UA_UInt16)d2;
    out->data3 = (UA_UInt16)d3;
    for (int i = 0; i < 8; i++) out->data4[i] = (UA_Byte)b[i];
    return 0;
}

/* `<i|s|g|b>=<id>` with an explicit namespace index. */
static int parse_nodeid_ident(const char *s, UA_UInt16 ns, UA_NodeId *out) {
    UA_NodeId_init(out);
    out->namespaceIndex = ns;
    if (strncmp(s, "i=", 2) == 0) {
        char *end = NULL;
        unsigned long v = strtoul(s + 2, &end, 10);
        if (end == s + 2 || *end) return -1;
        out->identifierType = UA_NODEIDTYPE_NUMERIC;
        out->identifier.numeric = (UA_UInt32)v;
        return 0;
    }
    if (strncmp(s, "s=", 2) == 0) {
        out->identifierType = UA_NODEIDTYPE_STRING;
        out->identifier.string = UA_STRING_ALLOC(s + 2);
        return 0;
    }
    if (strncmp(s, "g=", 2) == 0) {
        out->identifierType = UA_NODEIDTYPE_GUID;
        return parse_guid(s + 2, &out->identifier.guid);
    }
    if (strncmp(s, "b=", 2) == 0) {
        size_t n = 0;
        unsigned char *raw = value_b64_decode(s + 2, &n);
        if (!raw) return -1;
        out->identifierType = UA_NODEIDTYPE_BYTESTRING;
        UA_ByteString tmp = { n, raw };
        UA_ByteString_copy(&tmp, &out->identifier.byteString);
        free(raw);
        return 0;
    }
    return -1;
}

static int parse_nodeid(const char *s, UA_NodeId *out) {
    UA_UInt16 ns = 0;
    if (strncmp(s, "ns=", 3) == 0) {
        char *end = NULL;
        ns = (UA_UInt16)strtoul(s + 3, &end, 10);
        if (!end || *end != ';') return -1;
        s = end + 1;
    }
    return parse_nodeid_ident(s, ns, out);
}

static int parse_expanded_nodeid(const char *s, UA_ExpandedNodeId *out) {
    UA_ExpandedNodeId_init(out);
    if (strncmp(s, "svr=", 4) == 0) {
        char *end = NULL;
        out->serverIndex = (UA_UInt32)strtoul(s + 4, &end, 10);
        if (!end || *end != ';') return -1;
        s = end + 1;
    }
    if (strncmp(s, "nsu=", 4) == 0) {
        const char *semi = strchr(s + 4, ';');
        if (!semi) return -1;
        size_t n = (size_t)(semi - (s + 4));
        out->namespaceUri.data = (UA_Byte *)UA_malloc(n ? n : 1);
        if (!out->namespaceUri.data) return -1;
        memcpy(out->namespaceUri.data, s + 4, n);
        out->namespaceUri.length = n;
        return parse_nodeid_ident(semi + 1, 0, &out->nodeId);
    }
    return parse_nodeid(s, &out->nodeId);
}

static int parse_u32(const char *s, UA_UInt32 *out) {
    if (!s || !*s) return -1;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0); /* decimal or 0x-prefixed */
    if (end == s || *end) return -1;
    *out = (UA_UInt32)v;
    return 0;
}

static int parse_double_lit(const char *s, double *out) {
    if (!s || !*s) return -1;
    if (strcmp(s, "NaN") == 0)       { *out = NAN; return 0; }
    if (strcmp(s, "Infinity") == 0)  { *out = INFINITY; return 0; }
    if (strcmp(s, "-Infinity") == 0) { *out = -INFINITY; return 0; }
    char *end = NULL;
    *out = strtod(s, &end);
    return (end == s) ? -1 : 0;
}

/* Split "<Type>:<literal>" used by Variant / DataValue literals. */
static int split_typed(const char *s, char *typeBuf, size_t typeLen, const char **rest) {
    const char *colon = strchr(s, ':');
    if (!colon) return -1;
    size_t n = (size_t)(colon - s);
    if (n == 0 || n >= typeLen) return -1;
    memcpy(typeBuf, s, n);
    typeBuf[n] = '\0';
    *rest = colon + 1;
    return 0;
}

static int parse_extension_object(const char *s, UA_ExtensionObject *out) {
    const char *bar = strchr(s, '|');
    if (!bar) return -1;
    char idBuf[512];
    size_t n = (size_t)(bar - s);
    if (n == 0 || n >= sizeof(idBuf)) return -1;
    memcpy(idBuf, s, n);
    idBuf[n] = '\0';

    UA_ExtensionObject raw;
    UA_ExtensionObject_init(&raw);
    if (parse_nodeid(idBuf, &raw.content.encoded.typeId) != 0) return -1;
    size_t bodyLen = 0;
    unsigned char *body = value_b64_decode(bar + 1, &bodyLen);
    if (!body) { UA_NodeId_clear(&raw.content.encoded.typeId); return -1; }
    raw.encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
    UA_ByteString tmp = { bodyLen, body };
    UA_ByteString_copy(&tmp, &raw.content.encoded.body);
    free(body);

    /* Round-trip through the binary codec so bodies of known DataTypes are
     * held decoded (and are then encoded structurally in JSON / XML). */
    UA_ByteString bin = UA_BYTESTRING_NULL;
    UA_StatusCode sc = UA_encodeBinary(&raw, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], &bin, NULL);
    if (sc == UA_STATUSCODE_GOOD)
        sc = UA_decodeBinary(&bin, out, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT], NULL);
    UA_ByteString_clear(&bin);
    if (sc != UA_STATUSCODE_GOOD) {
        *out = raw; /* keep the opaque form */
        return 0;
    }
    UA_ExtensionObject_clear(&raw);
    return 0;
}

static int parse_diagnostic_info(const char *s, UA_DiagnosticInfo *out) {
    UA_DiagnosticInfo_init(out);
    char *dup = strdup(s);
    if (!dup) return -1;
    int rc = 0;
    char *save = NULL;
    for (char *tok = strtok_r(dup, ";", &save); tok; tok = strtok_r(NULL, ";", &save)) {
        char *eq = strchr(tok, '=');
        if (!eq) { rc = -1; break; }
        *eq = '\0';
        const char *val = eq + 1;
        if (strcmp(tok, "symbolicId") == 0) {
            out->hasSymbolicId = true; out->symbolicId = (UA_Int32)atoi(val);
        } else if (strcmp(tok, "namespaceUri") == 0) {
            out->hasNamespaceUri = true; out->namespaceUri = (UA_Int32)atoi(val);
        } else if (strcmp(tok, "localizedText") == 0) {
            out->hasLocalizedText = true; out->localizedText = (UA_Int32)atoi(val);
        } else if (strcmp(tok, "locale") == 0) {
            out->hasLocale = true; out->locale = (UA_Int32)atoi(val);
        } else if (strcmp(tok, "additionalInfo") == 0) {
            out->hasAdditionalInfo = true; out->additionalInfo = UA_STRING_ALLOC(val);
        } else if (strcmp(tok, "innerStatusCode") == 0) {
            UA_UInt32 code = 0;
            if (parse_u32(val, &code) != 0) { rc = -1; break; }
            out->hasInnerStatusCode = true; out->innerStatusCode = code;
        } else {
            rc = -1;
            break;
        }
    }
    free(dup);
    return rc;
}

/* Parse one literal into dst, which must be zero-initialised memory of
 * `type`. Returns 0 on success. */
static int parse_scalar(const UA_DataType *type, const char *lit, void *dst,
                        char *errBuf, size_t errLen) {
#define FAIL(...) do { snprintf(errBuf, errLen, __VA_ARGS__); return -1; } while (0)
    if (!lit) lit = "";
    int idx = (int)(type - UA_TYPES);

    switch (idx) {
    case UA_TYPES_BOOLEAN:
        *(UA_Boolean *)dst = (strcmp(lit, "true") == 0 || strcmp(lit, "1") == 0);
        return 0;
    case UA_TYPES_SBYTE:  *(UA_SByte *)dst  = (UA_SByte)atoi(lit);  return 0;
    case UA_TYPES_BYTE:   *(UA_Byte *)dst   = (UA_Byte)atoi(lit);   return 0;
    case UA_TYPES_INT16:  *(UA_Int16 *)dst  = (UA_Int16)atoi(lit);  return 0;
    case UA_TYPES_UINT16: *(UA_UInt16 *)dst = (UA_UInt16)atoi(lit); return 0;
    case UA_TYPES_INT32:  *(UA_Int32 *)dst  = (UA_Int32)atoi(lit);  return 0;
    case UA_TYPES_UINT32: *(UA_UInt32 *)dst = (UA_UInt32)strtoul(lit, NULL, 10); return 0;
    case UA_TYPES_INT64:  *(UA_Int64 *)dst  = (UA_Int64)strtoll(lit, NULL, 10);  return 0;
    case UA_TYPES_UINT64: *(UA_UInt64 *)dst = (UA_UInt64)strtoull(lit, NULL, 10); return 0;
    case UA_TYPES_FLOAT: {
        double d = 0;
        if (parse_double_lit(lit, &d) != 0) FAIL("invalid Float literal '%s'", lit);
        *(UA_Float *)dst = (UA_Float)d;
        return 0;
    }
    case UA_TYPES_DOUBLE: {
        double d = 0;
        if (parse_double_lit(lit, &d) != 0) FAIL("invalid Double literal '%s'", lit);
        *(UA_Double *)dst = d;
        return 0;
    }
    case UA_TYPES_STRING:
    case UA_TYPES_XMLELEMENT:
        *(UA_String *)dst = UA_STRING_ALLOC(lit);
        return 0;
    case UA_TYPES_DATETIME:
        if (value_parse_datetime(lit, (UA_DateTime *)dst) != 0)
            FAIL("invalid DateTime literal '%s' (want RFC 3339 UTC)", lit);
        return 0;
    case UA_TYPES_GUID:
        if (parse_guid(lit, (UA_Guid *)dst) != 0) FAIL("invalid Guid literal '%s'", lit);
        return 0;
    case UA_TYPES_BYTESTRING: {
        size_t n = 0;
        unsigned char *raw = value_b64_decode(lit, &n);
        if (!raw) FAIL("invalid Base64 ByteString literal");
        UA_ByteString tmp = { n, raw };
        if (n == 0) {
            ((UA_ByteString *)dst)->data = (UA_Byte *)UA_EMPTY_ARRAY_SENTINEL;
            ((UA_ByteString *)dst)->length = 0;
        } else {
            UA_ByteString_copy(&tmp, (UA_ByteString *)dst);
        }
        free(raw);
        return 0;
    }
    case UA_TYPES_NODEID:
        if (parse_nodeid(lit, (UA_NodeId *)dst) != 0) FAIL("invalid NodeId literal '%s'", lit);
        return 0;
    case UA_TYPES_EXPANDEDNODEID:
        if (parse_expanded_nodeid(lit, (UA_ExpandedNodeId *)dst) != 0)
            FAIL("invalid ExpandedNodeId literal '%s'", lit);
        return 0;
    case UA_TYPES_STATUSCODE:
        if (parse_u32(lit, (UA_UInt32 *)dst) != 0) FAIL("invalid StatusCode literal '%s'", lit);
        return 0;
    case UA_TYPES_QUALIFIEDNAME: {
        UA_QualifiedName *qn = (UA_QualifiedName *)dst;
        const char *colon = strchr(lit, ':');
        if (colon) {
            qn->namespaceIndex = (UA_UInt16)atoi(lit);
            qn->name = UA_STRING_ALLOC(colon + 1);
        } else {
            qn->name = UA_STRING_ALLOC(lit);
        }
        return 0;
    }
    case UA_TYPES_LOCALIZEDTEXT: {
        UA_LocalizedText *lt = (UA_LocalizedText *)dst;
        const char *colon = strchr(lit, ':');
        if (colon) {
            size_t n = (size_t)(colon - lit);
            if (n > 0) {
                lt->locale.data = (UA_Byte *)UA_malloc(n);
                if (!lt->locale.data) FAIL("out of memory");
                memcpy(lt->locale.data, lit, n);
                lt->locale.length = n;
            }
            lt->text = UA_STRING_ALLOC(colon + 1);
        } else {
            lt->text = UA_STRING_ALLOC(lit);
        }
        return 0;
    }
    case UA_TYPES_EXTENSIONOBJECT:
        if (parse_extension_object(lit, (UA_ExtensionObject *)dst) != 0)
            FAIL("invalid ExtensionObject literal (want <typeId>|<base64 body>)");
        return 0;
    case UA_TYPES_DATAVALUE: {
        char t[64]; const char *rest = NULL;
        if (split_typed(lit, t, sizeof(t), &rest) != 0)
            FAIL("invalid DataValue literal (want <Type>:<value>)");
        UA_DataValue *dv = (UA_DataValue *)dst;
        if (value_parse(t, rest, NULL, &dv->value, errBuf, errLen) != 0) return -1;
        dv->hasValue = true;
        return 0;
    }
    case UA_TYPES_VARIANT: {
        char t[64]; const char *rest = NULL;
        if (split_typed(lit, t, sizeof(t), &rest) != 0)
            FAIL("invalid Variant literal (want <Type>:<value>)");
        return value_parse(t, rest, NULL, (UA_Variant *)dst, errBuf, errLen);
    }
    case UA_TYPES_DIAGNOSTICINFO:
        if (parse_diagnostic_info(lit, (UA_DiagnosticInfo *)dst) != 0)
            FAIL("invalid DiagnosticInfo literal (want key=value;...)");
        return 0;
    default:
        FAIL("unsupported type '%s'", type->typeName ? type->typeName : "?");
    }
#undef FAIL
}

/* -------------------------------------------------------------------------
 * Array literal splitting
 * ---------------------------------------------------------------------- */

typedef struct { char **items; size_t count; } StrList;

static void strlist_free(StrList *l) {
    for (size_t i = 0; i < l->count; i++) free(l->items[i]);
    free(l->items);
    l->items = NULL;
    l->count = 0;
}

static int strlist_push(StrList *l, const char *s, size_t n) {
    char **tmp = (char **)realloc(l->items, (l->count + 1) * sizeof(char *));
    if (!tmp) return -1;
    l->items = tmp;
    char *dup = (char *)malloc(n + 1);
    if (!dup) return -1;
    memcpy(dup, s, n);
    dup[n] = '\0';
    l->items[l->count++] = dup;
    return 0;
}

static int split_array_literal(const char *val, StrList *out) {
    out->items = NULL;
    out->count = 0;
    if (!val || !*val) return 0; /* empty array */

    const char *p = val;
    while (*p == ' ') p++;
    if (*p == '[') {
        cJSON *arr = cJSON_Parse(p);
        if (!arr || !cJSON_IsArray(arr)) { cJSON_Delete(arr); return -1; }
        cJSON *el;
        cJSON_ArrayForEach(el, arr) {
            int rc;
            if (cJSON_IsString(el)) {
                rc = strlist_push(out, el->valuestring, strlen(el->valuestring));
            } else {
                char *txt = cJSON_PrintUnformatted(el);
                rc = txt ? strlist_push(out, txt, strlen(txt)) : -1;
                free(txt);
            }
            if (rc != 0) { cJSON_Delete(arr); strlist_free(out); return -1; }
        }
        cJSON_Delete(arr);
        return 0;
    }

    const char *start = val;
    for (p = val; ; p++) {
        if (*p == ',' || *p == '\0') {
            if (strlist_push(out, start, (size_t)(p - start)) != 0) {
                strlist_free(out);
                return -1;
            }
            if (*p == '\0') break;
            start = p + 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * value_parse
 * ---------------------------------------------------------------------- */

int value_parse(const char *typeStr, const char *valStr, const char *dims,
                UA_Variant *out, char *errBuf, size_t errLen) {
    UA_Variant_init(out);
    if (!typeStr || !*typeStr) {
        snprintf(errBuf, errLen, "missing type");
        return -1;
    }

    char name[64];
    size_t tl = strlen(typeStr);
    int isArray = (tl > 2 && strcmp(typeStr + tl - 2, "[]") == 0);
    if (isArray) tl -= 2;
    if (tl >= sizeof(name)) {
        snprintf(errBuf, errLen, "unknown type '%s'", typeStr);
        return -1;
    }
    memcpy(name, typeStr, tl);
    name[tl] = '\0';

    const UA_DataType *type = value_builtin_type(name);
    if (!type) {
        snprintf(errBuf, errLen, "unknown type '%s'", typeStr);
        return -1;
    }

    if (!isArray) {
        if (dims && *dims) {
            snprintf(errBuf, errLen, "--dimensions requires an array type (%s[])", name);
            return -1;
        }
        /* A scalar Variant literal is the inner value itself: a Variant
         * cannot hold a scalar Variant (Part 6 §5.1.2). */
        if (type == &UA_TYPES[UA_TYPES_VARIANT])
            return parse_scalar(type, valStr, out, errBuf, errLen);

        void *v = UA_new(type);
        if (!v) { snprintf(errBuf, errLen, "out of memory"); return -1; }
        if (parse_scalar(type, valStr, v, errBuf, errLen) != 0) {
            UA_delete(v, type);
            return -1;
        }
        UA_Variant_setScalar(out, v, type);
        return 0;
    }

    StrList items;
    if (split_array_literal(valStr, &items) != 0) {
        snprintf(errBuf, errLen, "invalid array literal");
        return -1;
    }

    void *arr = UA_Array_new(items.count, type);
    if (!arr && items.count > 0) {
        strlist_free(&items);
        snprintf(errBuf, errLen, "out of memory");
        return -1;
    }
    for (size_t i = 0; i < items.count; i++) {
        void *slot = (char *)arr + i * type->memSize;
        if (parse_scalar(type, items.items[i], slot, errBuf, errLen) != 0) {
            UA_Array_delete(arr, items.count, type);
            strlist_free(&items);
            return -1;
        }
    }
    UA_Variant_setArray(out, arr, items.count, type);
    size_t total = items.count;
    strlist_free(&items);

    if (dims && *dims) {
        StrList dl;
        if (split_array_literal(dims, &dl) != 0 || dl.count == 0) {
            UA_Variant_clear(out);
            snprintf(errBuf, errLen, "invalid --dimensions");
            return -1;
        }
        UA_UInt32 *d = (UA_UInt32 *)UA_Array_new(dl.count, &UA_TYPES[UA_TYPES_UINT32]);
        size_t product = 1;
        for (size_t i = 0; d && i < dl.count; i++) {
            d[i] = (UA_UInt32)strtoul(dl.items[i], NULL, 10);
            product *= d[i];
        }
        size_t dimCount = dl.count;
        strlist_free(&dl);
        if (!d || product != total) {
            if (d) UA_Array_delete(d, dimCount, &UA_TYPES[UA_TYPES_UINT32]);
            UA_Variant_clear(out);
            snprintf(errBuf, errLen,
                     "--dimensions product does not match the %zu array elements", total);
            return -1;
        }
        out->arrayDimensions = d;
        out->arrayDimensionsSize = dimCount;
    }
    return 0;
}
