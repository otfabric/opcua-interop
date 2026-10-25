/*
 * Part 12 client helpers shared by `client push` and `client gds-pull`
 * (see part12.h).
 */
#define _GNU_SOURCE

#include "part12.h"

#include "client_internal.h"
#include "output.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* -------------------------------------------------------------------------
 * JSON builder
 * ---------------------------------------------------------------------- */

void p12j_init(P12Json *j) {
    memset(j, 0, sizeof(*j));
    j->first = 1;
}

void p12j_free(P12Json *j) {
    free(j->buf);
    memset(j, 0, sizeof(*j));
}

static void p12j_append(P12Json *j, const char *s, size_t n) {
    if (j->oom) return;
    if (j->len + n + 1 > j->cap) {
        size_t cap = j->cap ? j->cap : 1024;
        while (cap < j->len + n + 1) cap *= 2;
        char *nb = (char *)realloc(j->buf, cap);
        if (!nb) { j->oom = 1; return; }
        j->buf = nb;
        j->cap = cap;
    }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

void p12j_raw(P12Json *j, const char *s) {
    p12j_append(j, s, strlen(s));
}

void p12j_printf(P12Json *j, const char *fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) { j->oom = 1; return; }
    if ((size_t)n < sizeof(tmp)) { p12j_append(j, tmp, (size_t)n); return; }
    char *big = (char *)malloc((size_t)n + 1);
    if (!big) { j->oom = 1; return; }
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    p12j_append(j, big, (size_t)n);
    free(big);
}

void p12j_sep(P12Json *j) {
    if (!j->first) p12j_raw(j, ",");
    j->first = 0;
}

void p12j_key(P12Json *j, const char *key) {
    p12j_sep(j);
    p12j_cstr(j, key);
    p12j_raw(j, ":");
}

void p12j_open(P12Json *j, char c) {
    char s[2] = { c, 0 };
    p12j_raw(j, s);
    j->first = 1;
}

void p12j_close(P12Json *j, char c) {
    char s[2] = { c, 0 };
    p12j_raw(j, s);
    j->first = 0;
}

void p12j_str(P12Json *j, const char *data, size_t len) {
    p12j_raw(j, "\"");
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        char esc[8];
        if (c == '"')       p12j_raw(j, "\\\"");
        else if (c == '\\') p12j_raw(j, "\\\\");
        else if (c == '\n') p12j_raw(j, "\\n");
        else if (c == '\r') p12j_raw(j, "\\r");
        else if (c == '\t') p12j_raw(j, "\\t");
        else if (c < 0x20) {
            snprintf(esc, sizeof(esc), "\\u%04x", c);
            p12j_raw(j, esc);
        } else {
            p12j_append(j, (const char *)&data[i], 1);
        }
    }
    p12j_raw(j, "\"");
}

void p12j_cstr(P12Json *j, const char *s) {
    if (!s) { p12j_raw(j, "null"); return; }
    p12j_str(j, s, strlen(s));
}

void p12j_uastr(P12Json *j, const UA_String *s) {
    if (!s || !s->data) { p12j_raw(j, "null"); return; }
    p12j_str(j, (const char *)s->data, s->length);
}

void p12j_b64(P12Json *j, const UA_Byte *data, size_t len) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    p12j_raw(j, "\"");
    for (size_t i = 0; data && i < len; i += 3) {
        unsigned char a = data[i];
        unsigned char b = (i + 1 < len) ? data[i + 1] : 0;
        unsigned char c = (i + 2 < len) ? data[i + 2] : 0;
        char q[4];
        q[0] = b64[a >> 2];
        q[1] = b64[((a & 3) << 4) | (b >> 4)];
        q[2] = (i + 1 < len) ? b64[((b & 0xf) << 2) | (c >> 6)] : '=';
        q[3] = (i + 2 < len) ? b64[c & 0x3f] : '=';
        p12j_append(j, q, 4);
    }
    p12j_raw(j, "\"");
}

/* The canonical NodeId string of §6, as output.c prints it. */
void p12j_nodeid(P12Json *j, const UA_NodeId *id) {
    char tmp[128];
    switch (id->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
        if (id->namespaceIndex == 0)
            snprintf(tmp, sizeof(tmp), "i=%" PRIu32, id->identifier.numeric);
        else
            snprintf(tmp, sizeof(tmp), "ns=%" PRIu16 ";i=%" PRIu32,
                     id->namespaceIndex, id->identifier.numeric);
        p12j_cstr(j, tmp);
        return;
    case UA_NODEIDTYPE_STRING: {
        const UA_String *s = &id->identifier.string;
        int n = snprintf(tmp, sizeof(tmp), "ns=%" PRIu16 ";s=", id->namespaceIndex);
        size_t total = (size_t)n + s->length;
        char *full = (char *)malloc(total + 1);
        if (!full) { j->oom = 1; return; }
        memcpy(full, tmp, (size_t)n);
        if (s->length) memcpy(full + n, s->data, s->length);
        p12j_str(j, full, total);
        free(full);
        return;
    }
    case UA_NODEIDTYPE_GUID: {
        const UA_Guid *g = &id->identifier.guid;
        snprintf(tmp, sizeof(tmp),
                 "ns=%" PRIu16 ";g=%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16
                 "-%02" PRIx8 "%02" PRIx8 "-%02" PRIx8 "%02" PRIx8 "%02" PRIx8
                 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8,
                 id->namespaceIndex, g->data1, g->data2, g->data3,
                 g->data4[0], g->data4[1], g->data4[2], g->data4[3],
                 g->data4[4], g->data4[5], g->data4[6], g->data4[7]);
        p12j_cstr(j, tmp);
        return;
    }
    case UA_NODEIDTYPE_BYTESTRING: {
        /* "ns=<n>;b=<base64>": the base64 alphabet needs no escaping. */
        P12Json b;
        p12j_init(&b);
        p12j_b64(&b, id->identifier.byteString.data, id->identifier.byteString.length);
        snprintf(tmp, sizeof(tmp), "\"ns=%" PRIu16 ";b=", id->namespaceIndex);
        p12j_raw(j, tmp);
        if (b.buf && b.len >= 2) p12j_append(j, b.buf + 1, b.len - 1); /* skip the opening quote */
        else p12j_raw(j, "\"");
        if (b.oom) j->oom = 1;
        p12j_free(&b);
        return;
    }
    default:
        p12j_cstr(j, "i=0");
        return;
    }
}

void p12j_status(P12Json *j, UA_StatusCode sc) {
    p12j_printf(j, "{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
                output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
    j->first = 0;
}

void p12j_datetime(P12Json *j, UA_DateTime dt) {
    if (dt == 0) { p12j_raw(j, "null"); return; }
    char buf[64];
    output_timestamp(dt, buf, sizeof(buf));
    p12j_cstr(j, buf);
}

void p12j_status_field(P12Json *j, const char *key, UA_StatusCode sc) {
    p12j_key(j, key);
    p12j_status(j, sc);
}

void p12j_b64_field(P12Json *j, const char *key, const UA_ByteString *bs) {
    p12j_key(j, key);
    if (bs) p12j_b64(j, bs->data, bs->length);
    else p12j_raw(j, "\"\"");
}

static void p12j_b64_list(P12Json *j, const UA_ByteString *list, size_t n) {
    p12j_open(j, '[');
    for (size_t i = 0; list && i < n; i++) {
        p12j_sep(j);
        p12j_b64(j, list[i].data, list[i].length);
    }
    p12j_close(j, ']');
}

void p12j_b64_array_field(P12Json *j, const char *key, const UA_Variant *v) {
    p12j_key(j, key);
    if (v && v->type == &UA_TYPES[UA_TYPES_BYTESTRING] && !UA_Variant_isScalar(v))
        p12j_b64_list(j, (const UA_ByteString *)v->data, v->arrayLength);
    else if (v && UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_BYTESTRING]))
        p12j_b64_list(j, (const UA_ByteString *)v->data, 1);
    else
        p12j_raw(j, "[]");
    j->first = 0;
}

void p12j_nodeid_array_field(P12Json *j, const char *key, const UA_Variant *v) {
    p12j_key(j, key);
    p12j_open(j, '[');
    if (v && v->type == &UA_TYPES[UA_TYPES_NODEID] && v->data) {
        size_t n = UA_Variant_isScalar(v) ? 1 : v->arrayLength;
        const UA_NodeId *ids = (const UA_NodeId *)v->data;
        for (size_t i = 0; i < n; i++) {
            p12j_sep(j);
            p12j_nodeid(j, &ids[i]);
        }
    }
    p12j_close(j, ']');
}

void p12j_trust_list(P12Json *j, const UA_TrustListDataType *tl) {
    p12j_open(j, '{');
    p12j_key(j, "specifiedLists");
    p12j_printf(j, "%" PRIu32, tl->specifiedLists);
    p12j_key(j, "trustedCertificates");
    p12j_b64_list(j, tl->trustedCertificates, tl->trustedCertificatesSize);
    p12j_key(j, "trustedCrls");
    p12j_b64_list(j, tl->trustedCrls, tl->trustedCrlsSize);
    p12j_key(j, "issuerCertificates");
    p12j_b64_list(j, tl->issuerCertificates, tl->issuerCertificatesSize);
    p12j_key(j, "issuerCrls");
    p12j_b64_list(j, tl->issuerCrls, tl->issuerCrlsSize);
    p12j_close(j, '}');
}

/* -------------------------------------------------------------------------
 * Arguments
 * ---------------------------------------------------------------------- */

int p12_has_flag(int argc, char **argv, const char *flag) {
    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], flag) == 0) return 1;
    return 0;
}

const char **p12_all_values(int argc, char **argv, const char *flag, size_t *n) {
    *n = 0;
    const char **out = (const char **)calloc((size_t)(argc > 0 ? argc : 1), sizeof(char *));
    if (!out) return NULL;
    for (int i = 0; i < argc - 1; i++)
        if (strcmp(argv[i], flag) == 0) out[(*n)++] = argv[++i];
    return out;
}

int p12_parse_uint(const char *s, unsigned long max, unsigned long *out) {
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v > max) return -1;
    *out = v;
    return 0;
}

int p12_read_file(const char *path, UA_ByteString *out) {
    UA_ByteString_init(out);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    if (UA_ByteString_allocBuffer(out, (size_t)sz) != UA_STATUSCODE_GOOD) {
        fclose(f);
        return -1;
    }
    size_t got = fread(out->data, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        UA_ByteString_clear(out);
        return -1;
    }
    return 0;
}

int p12_read_certificate(const char *path, UA_ByteString *out) {
    UA_ByteString raw;
    if (p12_read_file(path, &raw) != 0) return -1;
    UA_ByteString_init(out);
    int rc = -1;
    X509 *x = NULL;
    if (raw.length >= 10 && memmem(raw.data, raw.length, "-----BEGIN", 10)) {
        BIO *bio = BIO_new_mem_buf(raw.data, (int)raw.length);
        if (bio) {
            x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
    } else {
        const unsigned char *p = raw.data;
        x = d2i_X509(NULL, &p, (long)raw.length);
    }
    if (x) {
        int n = i2d_X509(x, NULL);
        if (n > 0 && UA_ByteString_allocBuffer(out, (size_t)n) == UA_STATUSCODE_GOOD) {
            unsigned char *p = out->data;
            if (i2d_X509(x, &p) == n) rc = 0;
            else UA_ByteString_clear(out);
        }
        X509_free(x);
    }
    UA_ByteString_clear(&raw);
    return rc;
}

int p12_resolve_nodeid(UA_Client *client, const char *s, UA_NodeId *out) {
    UA_NodeId_init(out);
    if (strncmp(s, "nsu=", 4) == 0) return cli_resolve_nsu_nodeid(client, s, out);
    *out = cli_parse_nodeid_local(s);
    return UA_NodeId_isNull(out) && strcmp(s, "i=0") != 0 ? -1 : 0;
}

/* -------------------------------------------------------------------------
 * Variants
 * ---------------------------------------------------------------------- */

void p12v_nodeid(UA_Variant *v, const UA_NodeId *id) {
    UA_Variant_setScalarCopy(v, id, &UA_TYPES[UA_TYPES_NODEID]);
}

void p12v_string(UA_Variant *v, const char *s) {
    UA_String str = UA_STRING_NULL;
    if (s) str = UA_STRING((char *)(uintptr_t)s);
    UA_Variant_setScalarCopy(v, &str, &UA_TYPES[UA_TYPES_STRING]);
}

void p12v_bool(UA_Variant *v, UA_Boolean b) {
    UA_Variant_setScalarCopy(v, &b, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

void p12v_byte(UA_Variant *v, UA_Byte b) {
    UA_Variant_setScalarCopy(v, &b, &UA_TYPES[UA_TYPES_BYTE]);
}

void p12v_uint16(UA_Variant *v, UA_UInt16 x) {
    UA_Variant_setScalarCopy(v, &x, &UA_TYPES[UA_TYPES_UINT16]);
}

void p12v_uint32(UA_Variant *v, UA_UInt32 x) {
    UA_Variant_setScalarCopy(v, &x, &UA_TYPES[UA_TYPES_UINT32]);
}

void p12v_int32(UA_Variant *v, UA_Int32 x) {
    UA_Variant_setScalarCopy(v, &x, &UA_TYPES[UA_TYPES_INT32]);
}

void p12v_bytestring(UA_Variant *v, const UA_ByteString *bs) {
    UA_ByteString empty = UA_BYTESTRING_NULL;
    UA_Variant_setScalarCopy(v, bs ? bs : &empty, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

void p12v_string_array(UA_Variant *v, const char **s, size_t n) {
    UA_String *arr = n ? (UA_String *)calloc(n, sizeof(UA_String)) : NULL;
    for (size_t i = 0; arr && i < n; i++) arr[i] = UA_STRING((char *)(uintptr_t)s[i]);
    UA_Variant_setArrayCopy(v, arr, arr ? n : 0, &UA_TYPES[UA_TYPES_STRING]);
    free(arr);
}

void p12v_bytestring_array(UA_Variant *v, const UA_ByteString *bs, size_t n) {
    UA_Variant_setArrayCopy(v, bs, bs ? n : 0, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

void p12v_clear_all(UA_Variant *v, size_t n) {
    for (size_t i = 0; i < n; i++) UA_Variant_clear(&v[i]);
}

const UA_NodeId *p12_out_nodeid(const UA_Variant *out, size_t n, size_t i) {
    if (!out || i >= n || !UA_Variant_hasScalarType(&out[i], &UA_TYPES[UA_TYPES_NODEID]))
        return NULL;
    return (const UA_NodeId *)out[i].data;
}

const UA_ByteString *p12_out_bytestring(const UA_Variant *out, size_t n, size_t i) {
    if (!out || i >= n || !UA_Variant_hasScalarType(&out[i], &UA_TYPES[UA_TYPES_BYTESTRING]))
        return NULL;
    return (const UA_ByteString *)out[i].data;
}

int p12_out_bool(const UA_Variant *out, size_t n, size_t i) {
    if (!out || i >= n || !UA_Variant_hasScalarType(&out[i], &UA_TYPES[UA_TYPES_BOOLEAN]))
        return 0;
    return *(const UA_Boolean *)out[i].data ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Services
 * ---------------------------------------------------------------------- */

int p12_is_transport(UA_StatusCode sc) {
    switch (sc) {
    case UA_STATUSCODE_BADTIMEOUT:
    case UA_STATUSCODE_BADCONNECTIONCLOSED:
    case UA_STATUSCODE_BADSECURECHANNELCLOSED:
    case UA_STATUSCODE_BADSECURECHANNELIDINVALID:
    case UA_STATUSCODE_BADCOMMUNICATIONERROR:
    case UA_STATUSCODE_BADCONNECTIONREJECTED:
    case UA_STATUSCODE_BADDISCONNECT:
    case UA_STATUSCODE_BADNOTCONNECTED:
    case UA_STATUSCODE_BADSERVERNOTCONNECTED:
    case UA_STATUSCODE_BADSESSIONCLOSED:
    case UA_STATUSCODE_BADSESSIONIDINVALID:
        return 1;
    default:
        return 0;
    }
}

UA_StatusCode p12_call(UA_Client *client, const UA_NodeId *object,
                       const UA_NodeId *method, UA_Variant *inputs, size_t nIn,
                       UA_Variant **outputs, size_t *nOut) {
    *outputs = NULL;
    *nOut = 0;
    return UA_Client_call(client, *object, *method, nIn, inputs, nOut, outputs);
}

void p12_free_outputs(UA_Variant *outputs, size_t n) {
    /* UA_Array_delete: a method without outputs returns the empty-array
     * sentinel, which UA_free must not see. */
    if (outputs) UA_Array_delete(outputs, n, &UA_TYPES[UA_TYPES_VARIANT]);
}

UA_StatusCode p12_translate(UA_Client *client, const UA_NodeId *start,
                            const char *const *const *paths, size_t n,
                            UA_NodeId *out) {
    for (size_t i = 0; i < n; i++) UA_NodeId_init(&out[i]);
    UA_BrowsePath *bps = (UA_BrowsePath *)UA_Array_new(n, &UA_TYPES[UA_TYPES_BROWSEPATH]);
    if (!bps) return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode sc = UA_STATUSCODE_GOOD;
    for (size_t i = 0; i < n && sc == UA_STATUSCODE_GOOD; i++) {
        size_t depth = 0;
        while (paths[i][depth]) depth++;
        sc |= UA_NodeId_copy(start, &bps[i].startingNode);
        bps[i].relativePath.elements = (UA_RelativePathElement *)
            UA_Array_new(depth, &UA_TYPES[UA_TYPES_RELATIVEPATHELEMENT]);
        if (!bps[i].relativePath.elements) { sc = UA_STATUSCODE_BADOUTOFMEMORY; break; }
        bps[i].relativePath.elementsSize = depth;
        for (size_t k = 0; k < depth; k++) {
            UA_RelativePathElement *e = &bps[i].relativePath.elements[k];
            e->referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
            e->isInverse = false;
            e->includeSubtypes = true;
            e->targetName = UA_QUALIFIEDNAME_ALLOC(0, paths[i][k]);
        }
    }
    if (sc != UA_STATUSCODE_GOOD) {
        UA_Array_delete(bps, n, &UA_TYPES[UA_TYPES_BROWSEPATH]);
        return sc;
    }
    UA_TranslateBrowsePathsToNodeIdsRequest req;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&req);
    req.browsePaths = bps;
    req.browsePathsSize = n;
    UA_TranslateBrowsePathsToNodeIdsResponse resp =
        UA_Client_Service_translateBrowsePathsToNodeIds(client, req);
    UA_TranslateBrowsePathsToNodeIdsRequest_clear(&req);

    sc = resp.responseHeader.serviceResult;
    if (sc == UA_STATUSCODE_GOOD && resp.resultsSize != n) sc = UA_STATUSCODE_BADUNEXPECTEDERROR;
    for (size_t i = 0; i < n && sc == UA_STATUSCODE_GOOD; i++) {
        const UA_BrowsePathResult *r = &resp.results[i];
        if (r->statusCode != UA_STATUSCODE_GOOD) { sc = r->statusCode; break; }
        if (r->targetsSize == 0) { sc = UA_STATUSCODE_BADNOMATCH; break; }
        sc = UA_NodeId_copy(&r->targets[0].targetId.nodeId, &out[i]);
    }
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&resp);
    if (sc != UA_STATUSCODE_GOOD)
        for (size_t i = 0; i < n; i++) UA_NodeId_clear(&out[i]);
    return sc;
}

#define P12_READ_CHUNK 4096

UA_StatusCode p12_read_trust_list(UA_Client *client, const UA_NodeId *trustList,
                                  int withMasks, UA_UInt32 masks,
                                  UA_TrustListDataType *tl) {
    UA_TrustListDataType_init(tl);
    static const char *const pOpen[] = { "Open", NULL };
    static const char *const pOpenMasks[] = { "OpenWithMasks", NULL };
    static const char *const pRead[] = { "Read", NULL };
    static const char *const pClose[] = { "Close", NULL };
    const char *const *paths[3] = { withMasks ? pOpenMasks : pOpen, pRead, pClose };
    UA_NodeId ids[3];
    UA_StatusCode sc = p12_translate(client, trustList, paths, 3, ids);
    if (sc != UA_STATUSCODE_GOOD) return sc;

    UA_Variant in[2];
    UA_Variant *out = NULL;
    size_t nOut = 0;
    if (withMasks) p12v_uint32(&in[0], masks);
    else p12v_byte(&in[0], 1); /* FileType Open mode Read (Part 5 §C.2.1) */
    sc = p12_call(client, trustList, &ids[0], in, 1, &out, &nOut);
    UA_Variant_clear(&in[0]);
    UA_UInt32 handle = 0;
    if (sc == UA_STATUSCODE_GOOD) {
        if (nOut >= 1 && UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_UINT32]))
            handle = *(UA_UInt32 *)out[0].data;
        else
            sc = UA_STATUSCODE_BADUNEXPECTEDERROR;
    }
    p12_free_outputs(out, nOut);
    if (sc != UA_STATUSCODE_GOOD) goto done;

    UA_ByteString data = UA_BYTESTRING_NULL;
    UA_StatusCode readSc = UA_STATUSCODE_GOOD;
    for (;;) {
        p12v_uint32(&in[0], handle);
        p12v_int32(&in[1], P12_READ_CHUNK);
        readSc = p12_call(client, trustList, &ids[1], in, 2, &out, &nOut);
        p12v_clear_all(in, 2);
        if (readSc != UA_STATUSCODE_GOOD) { p12_free_outputs(out, nOut); break; }
        const UA_ByteString *chunk = p12_out_bytestring(out, nOut, 0);
        size_t clen = chunk ? chunk->length : 0;
        if (clen > 0) {
            UA_Byte *nd = (UA_Byte *)UA_realloc(data.data, data.length + clen);
            if (!nd) { readSc = UA_STATUSCODE_BADOUTOFMEMORY; p12_free_outputs(out, nOut); break; }
            memcpy(nd + data.length, chunk->data, clen);
            data.data = nd;
            data.length += clen;
        }
        p12_free_outputs(out, nOut);
        if (clen < P12_READ_CHUNK) break;
    }
    /* Close also after a failed Read; a transport failure wins. */
    p12v_uint32(&in[0], handle);
    UA_StatusCode closeSc = p12_call(client, trustList, &ids[2], in, 1, &out, &nOut);
    UA_Variant_clear(&in[0]);
    p12_free_outputs(out, nOut);
    if (readSc != UA_STATUSCODE_GOOD) sc = readSc;
    else if (closeSc != UA_STATUSCODE_GOOD) sc = closeSc;
    else if (UA_decodeBinary(&data, tl, &UA_TYPES[UA_TYPES_TRUSTLISTDATATYPE], NULL)
             != UA_STATUSCODE_GOOD) {
        UA_TrustListDataType_clear(tl);
        sc = UA_STATUSCODE_BADDECODINGERROR;
    }
    UA_ByteString_clear(&data);

done:
    for (int i = 0; i < 3; i++) UA_NodeId_clear(&ids[i]);
    return sc;
}

int p12_extension_body(const UA_ExtensionObject *eo, UA_ByteString *out) {
    UA_ByteString_init(out);
    if (eo->encoding == UA_EXTENSIONOBJECT_ENCODED_BYTESTRING)
        return UA_ByteString_copy(&eo->content.encoded.body, out) == UA_STATUSCODE_GOOD ? 0 : -1;
    if ((eo->encoding == UA_EXTENSIONOBJECT_DECODED ||
         eo->encoding == UA_EXTENSIONOBJECT_DECODED_NODELETE) &&
        eo->content.decoded.type && eo->content.decoded.data)
        return UA_encodeBinary(eo->content.decoded.data, eo->content.decoded.type, out, NULL)
               == UA_STATUSCODE_GOOD ? 0 : -1;
    return -1;
}

static int p12_le_i32(const UA_Byte *p, size_t len, size_t off, int32_t *v) {
    if (off + 4 > len) return -1;
    *v = (int32_t)((uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
                   ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24));
    return 0;
}

size_t p12_nodeid_encoded_length(const UA_Byte *buf, size_t len) {
    if (len < 1) return 0;
    size_t n;
    int32_t slen = 0;
    switch (buf[0] & 0x3f) {
    case 0: n = 2; break;                         /* TwoByte */
    case 1: n = 4; break;                         /* FourByte */
    case 2: n = 7; break;                         /* Numeric */
    case 3:                                       /* String */
    case 5:                                       /* ByteString */
        if (p12_le_i32(buf, len, 3, &slen) != 0) return 0;
        n = 7 + (slen > 0 ? (size_t)slen : 0);
        break;
    case 4: n = 19; break;                        /* Guid */
    default: return 0;
    }
    return n <= len ? n : 0;
}

/* -------------------------------------------------------------------------
 * Envelope
 * ---------------------------------------------------------------------- */

void p12_emit(const char *op, int ok, UA_StatusCode sc, const char *category,
              const char *message, const P12Json *item) {
    output_begin("open62541", op);
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[");
    if (item && item->buf && !item->oom) fputs(item->buf, stdout);
    printf("]");
    if (category) {
        P12Json e;
        p12j_init(&e);
        p12j_raw(&e, ",\"error\":{\"category\":");
        p12j_cstr(&e, category);
        p12j_raw(&e, ",\"message\":");
        p12j_cstr(&e, message ? message : "");
        p12j_raw(&e, "}");
        if (e.buf) fputs(e.buf, stdout);
        p12j_free(&e);
    } else {
        output_null_error();
    }
    output_end();
}

int p12_exit_code(UA_StatusCode sc) {
    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    if (p12_is_transport(sc)) return 3;
    return 4;
}
