/*
 * `client codec pubsub-*` — byte-level interop of the PubSub message mappings
 * (OPC UA Part 14 §7.2.4 UADP, §7.2.5 JSON) without a transport.
 *
 *   codec pubsub-uadp-encode  description (JSON) -> UADP NetworkMessage (Base64)
 *   codec pubsub-uadp-decode  UADP NetworkMessage (Base64) -> description
 *   codec pubsub-json-encode  description (JSON) -> JSON NetworkMessage
 *   codec pubsub-json-decode  JSON NetworkMessage -> description
 *
 * Input:  --document <text> | --input <file> | stdin
 * Options: --metadata <json> | --metadata-file <file>  (DataSetMetaDataType, or
 *          [{"dataSetWriterId":n,"metaData":<DataSetMetaDataType>}, ...])
 *
 * The en-/decoding is open62541's own (UA_NetworkMessage_encodeBinary /
 * _decodeBinary / _encodeJson / _decodeJson from <open62541/pubsub.h>). That
 * standalone API has no message security: a SecurityHeader is encoded and
 * decoded as plain header fields, but nothing is signed, encrypted, verified
 * or decrypted (signed/encrypted traffic is covered by the live
 * publish/subscribe path only). The description format is defined in
 * docs/CONTAINER_CONTRACT.md §14.
 */

#define _GNU_SOURCE

#include "client_internal.h"
#include "output.h"
#include "pubsub_server.h"
#include "values.h"

#include <cjson/cJSON.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define OP "codec"

typedef enum { MAP_UADP, MAP_JSON } Mapping;

static int usage_error(const char *msg) {
    cli_emit_failure(OP, UA_STATUSCODE_BADINVALIDARGUMENT, "input", msg);
    return 2;
}

/* -------------------------------------------------------------------------
 * Input helpers
 * ---------------------------------------------------------------------- */

static char *read_stream(FILE *f, size_t *lenOut) {
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap + 1);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) {
            cap *= 2;
            char *t = (char *)realloc(buf, cap + 1);
            if (!t) { free(buf); return NULL; }
            buf = t;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' ' || buf[len - 1] == '\t'))
        len--;
    buf[len] = '\0';
    *lenOut = len;
    return buf;
}

static char *read_input(int argc, char **argv, size_t *len) {
    const char *doc = cli_find_arg(argc, argv, "--document");
    const char *path = cli_find_arg(argc, argv, "--input");
    if (doc) {
        *len = strlen(doc);
        return strdup(doc);
    }
    FILE *f = path ? fopen(path, "rb") : stdin;
    if (!f) return NULL;
    char *r = read_stream(f, len);
    if (path) fclose(f);
    return r;
}

/* -------------------------------------------------------------------------
 * Metadata (--metadata / --metadata-file)
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_UInt16 writerId;
    int hasWriterId;
    UA_DataSetMetaDataType md;
} MetaEntry;

typedef struct {
    MetaEntry *items;
    size_t count;
} MetaList;

static void meta_clear(MetaList *m) {
    for (size_t i = 0; i < m->count; i++)
        UA_DataSetMetaDataType_clear(&m->items[i].md);
    free(m->items);
    m->items = NULL;
    m->count = 0;
}

static int meta_parse(int argc, char **argv, MetaList *out, char *err, size_t errLen) {
    memset(out, 0, sizeof(*out));
    const char *txt = cli_find_arg(argc, argv, "--metadata");
    const char *path = cli_find_arg(argc, argv, "--metadata-file");
    char *owned = NULL;
    if (!txt && path) {
        FILE *f = fopen(path, "rb");
        if (!f) { snprintf(err, errLen, "cannot open --metadata-file"); return -1; }
        size_t l = 0;
        owned = read_stream(f, &l);
        fclose(f);
        txt = owned;
    }
    if (!txt) return 0;
    cJSON *root = cJSON_Parse(txt);
    if (!root) {
        free(owned);
        snprintf(err, errLen, "--metadata is not JSON");
        return -1;
    }
    int rc = 0;
    if (cJSON_IsArray(root)) {
        size_t n = (size_t)cJSON_GetArraySize(root);
        out->items = (MetaEntry *)calloc(n ? n : 1, sizeof(MetaEntry));
        const cJSON *e;
        cJSON_ArrayForEach(e, root) {
            MetaEntry *me = &out->items[out->count];
            const cJSON *wid = cJSON_GetObjectItemCaseSensitive(e, "dataSetWriterId");
            const cJSON *md = cJSON_GetObjectItemCaseSensitive(e, "metaData");
            if (!cJSON_IsNumber(wid) || !cJSON_IsObject(md)) {
                snprintf(err, errLen, "--metadata array entries are "
                         "{\"dataSetWriterId\":n,\"metaData\":{...}}");
                rc = -1;
                break;
            }
            me->writerId = (UA_UInt16)wid->valuedouble;
            me->hasWriterId = 1;
            char *mt = cJSON_PrintUnformatted(md);
            UA_StatusCode sc = pubsub_decode_json(mt, strlen(mt), &me->md,
                                                  &UA_TYPES[UA_TYPES_DATASETMETADATATYPE], NULL, 0);
            free(mt);
            if (sc != UA_STATUSCODE_GOOD) {
                snprintf(err, errLen, "--metadata: not a DataSetMetaDataType (%s)",
                         UA_StatusCode_name(sc));
                rc = -1;
                break;
            }
            out->count++;
        }
    } else {
        out->items = (MetaEntry *)calloc(1, sizeof(MetaEntry));
        UA_StatusCode sc = pubsub_decode_json(txt, strlen(txt), &out->items[0].md,
                                              &UA_TYPES[UA_TYPES_DATASETMETADATATYPE], NULL, 0);
        if (sc != UA_STATUSCODE_GOOD) {
            snprintf(err, errLen, "--metadata: not a DataSetMetaDataType (%s)",
                     UA_StatusCode_name(sc));
            rc = -1;
        } else {
            out->count = 1;
        }
    }
    cJSON_Delete(root);
    free(owned);
    if (rc != 0) meta_clear(out);
    return rc;
}

static const UA_DataSetMetaDataType *meta_for(const MetaList *m, UA_UInt16 writerId) {
    for (size_t i = 0; i < m->count; i++)
        if (m->items[i].hasWriterId && m->items[i].writerId == writerId)
            return &m->items[i].md;
    for (size_t i = 0; i < m->count; i++)
        if (!m->items[i].hasWriterId)
            return &m->items[i].md;
    return NULL;
}

/* -------------------------------------------------------------------------
 * Description printing (decode)
 * ---------------------------------------------------------------------- */

/* RFC 3339 UTC with the full 100 ns resolution of a DateTime */
static void print_datetime_full(UA_DateTime dt) {
    UA_DateTimeStruct t = UA_DateTime_toStruct(dt);
    long frac = (long)(((dt % UA_DATETIME_SEC) + UA_DATETIME_SEC) % UA_DATETIME_SEC);
    printf("\"%04u-%02u-%02uT%02u:%02u:%02u.%07ldZ\"", t.year, t.month, t.day,
           t.hour, t.min, t.sec, frac);
}

static const char *publisher_id_type(UA_PublisherIdType t) {
    switch (t) {
    case UA_PUBLISHERIDTYPE_BYTE:   return "Byte";
    case UA_PUBLISHERIDTYPE_UINT16: return "UInt16";
    case UA_PUBLISHERIDTYPE_UINT32: return "UInt32";
    case UA_PUBLISHERIDTYPE_UINT64: return "UInt64";
    case UA_PUBLISHERIDTYPE_STRING: return "String";
    }
    return "Unknown";
}

static void print_publisher_id(const UA_PublisherId *p) {
    printf("{\"type\":\"%s\",\"value\":", publisher_id_type(p->idType));
    switch (p->idType) {
    case UA_PUBLISHERIDTYPE_BYTE:   printf("%u", (unsigned)p->id.byte); break;
    case UA_PUBLISHERIDTYPE_UINT16: printf("%u", (unsigned)p->id.uint16); break;
    case UA_PUBLISHERIDTYPE_UINT32: printf("%" PRIu32, p->id.uint32); break;
    case UA_PUBLISHERIDTYPE_UINT64: printf("\"%" PRIu64 "\"", p->id.uint64); break;
    case UA_PUBLISHERIDTYPE_STRING:
        output_json_string_len(p->id.string.data, p->id.string.length); break;
    default: printf("null");
    }
    printf("}");
}

static void print_b64(const UA_Byte *data, size_t len) {
    char *b = value_b64_encode(data ? data : (const UA_Byte *)"", len);
    printf("\"%s\"", b ? b : "");
    free(b);
}

static void print_variant_members(const UA_Variant *v) {
    if (UA_Variant_isEmpty(v)) {
        printf("\"dataType\":\"Null\",\"builtInType\":0,\"value\":null");
        return;
    }
    printf("\"dataType\":");
    output_json_string(value_type_name(v->type));
    printf(",\"builtInType\":%d", ua_type_to_builtin_id(v->type));
    if (!UA_Variant_isScalar(v) && v->arrayDimensionsSize > 1) {
        printf(",\"arrayDimensions\":[");
        for (size_t i = 0; i < v->arrayDimensionsSize; i++)
            printf("%s%" PRIu32, i ? "," : "", v->arrayDimensions[i]);
        printf("]");
    }
    output_ua_variant_field("value", v);
}

static void print_field(const UA_DataValue *dv, UA_FieldEncoding enc, const UA_String *name,
                        int index) {
    printf("{");
    int first = 1;
    if (name && name->length > 0) {
        printf("\"name\":");
        output_json_string_len(name->data, name->length);
        first = 0;
    }
    if (index >= 0) {
        printf("%s\"index\":%d", first ? "" : ",", index);
        first = 0;
    }
    if (!first) printf(",");
    print_variant_members(&dv->value);
    if (enc == UA_FIELDENCODING_DATAVALUE) {
        if (dv->hasStatus) {
            printf(",");
            cli_print_status("statusCode", dv->status);
        }
        if (dv->hasSourceTimestamp) {
            printf(",\"sourceTimestamp\":");
            print_datetime_full(dv->sourceTimestamp);
        }
        if (dv->hasSourcePicoseconds)
            printf(",\"sourcePicoseconds\":%u", (unsigned)dv->sourcePicoseconds);
        if (dv->hasServerTimestamp) {
            printf(",\"serverTimestamp\":");
            print_datetime_full(dv->serverTimestamp);
        }
        if (dv->hasServerPicoseconds)
            printf(",\"serverPicoseconds\":%u", (unsigned)dv->serverPicoseconds);
    }
    printf("}");
}

static const char *message_type_name(UA_DataSetMessageType t) {
    switch (t) {
    case UA_DATASETMESSAGE_DATAKEYFRAME:   return "KeyFrame";
    case UA_DATASETMESSAGE_DATADELTAFRAME: return "DeltaFrame";
    case UA_DATASETMESSAGE_EVENT:          return "Event";
    case UA_DATASETMESSAGE_KEEPALIVE:      return "KeepAlive";
    }
    return "Unknown";
}

static const char *field_encoding_name(UA_FieldEncoding e) {
    switch (e) {
    case UA_FIELDENCODING_VARIANT:   return "Variant";
    case UA_FIELDENCODING_RAWDATA:   return "RawData";
    case UA_FIELDENCODING_DATAVALUE: return "DataValue";
    default:                         return "Unknown";
    }
}

/* names: optional per-field names (JSON keys) when no metadata is known */
static void print_dsm(const UA_DataSetMessage *dsm, int hasWriterId, UA_UInt16 writerId,
                      const UA_DataSetMetaDataType *md, const UA_String *names,
                      size_t namesCount) {
    const UA_DataSetMessageHeader *h = &dsm->header;
    printf("{");
    if (hasWriterId) printf("\"dataSetWriterId\":%u,", (unsigned)writerId);
    printf("\"messageType\":\"%s\",\"fieldEncoding\":\"%s\",\"valid\":%s",
           message_type_name(h->dataSetMessageType), field_encoding_name(h->fieldEncoding),
           h->dataSetMessageValid ? "true" : "false");
    if (h->dataSetMessageSequenceNrEnabled)
        printf(",\"sequenceNumber\":%u", (unsigned)h->dataSetMessageSequenceNr);
    if (h->timestampEnabled) {
        printf(",\"timestamp\":");
        print_datetime_full(h->timestamp);
    }
    if (h->picoSecondsIncluded)
        printf(",\"picoseconds\":%u", (unsigned)h->picoSeconds);
    if (h->statusEnabled)
        printf(",\"status\":%u", (unsigned)h->status);
    if (h->configVersionMajorVersionEnabled || h->configVersionMinorVersionEnabled) {
        printf(",\"configVersion\":{");
        int f = 1;
        if (h->configVersionMajorVersionEnabled) {
            printf("\"majorVersion\":%" PRIu32, h->configVersionMajorVersion);
            f = 0;
        }
        if (h->configVersionMinorVersionEnabled)
            printf("%s\"minorVersion\":%" PRIu32, f ? "" : ",", h->configVersionMinorVersion);
        printf("}");
    }
    if (h->dataSetMessageType == UA_DATASETMESSAGE_DATAKEYFRAME) {
        printf(",\"fields\":[");
        for (size_t i = 0; i < dsm->fieldCount; i++) {
            if (i) printf(",");
            const UA_String *name = NULL;
            if (md && i < md->fieldsSize) name = &md->fields[i].name;
            else if (names && i < namesCount) name = &names[i];
            print_field(&dsm->data.keyFrameFields[i], h->fieldEncoding, name, -1);
        }
        printf("]");
    } else if (h->dataSetMessageType == UA_DATASETMESSAGE_DATADELTAFRAME) {
        printf(",\"fields\":[");
        for (size_t i = 0; i < dsm->fieldCount; i++) {
            if (i) printf(",");
            const UA_DataSetMessage_DeltaFrameField *df = &dsm->data.deltaFrameFields[i];
            const UA_String *name = (md && df->index < md->fieldsSize)
                ? &md->fields[df->index].name : NULL;
            print_field(&df->value, h->fieldEncoding, name, (int)df->index);
        }
        printf("]");
    }
    printf("}");
}

static void print_description(const UA_NetworkMessage *nm, Mapping map, const MetaList *meta,
                              const UA_String *const *jsonNames, const size_t *jsonNameCounts) {
    printf("{\"mapping\":\"%s\"", map == MAP_UADP ? "uadp" : "json");
    if (map == MAP_UADP) printf(",\"version\":%u", (unsigned)nm->version);
    if (nm->messageIdEnabled) {
        printf(",\"messageId\":");
        output_json_string_len(nm->messageId.data, nm->messageId.length);
    }
    if (nm->publisherIdEnabled) {
        printf(",\"publisherId\":");
        print_publisher_id(&nm->publisherId);
    }
    if (nm->dataSetClassIdEnabled) {
        printf(",\"dataSetClassId\":");
        output_ua_scalar(&nm->dataSetClassId, &UA_TYPES[UA_TYPES_GUID]);
    }
    if (nm->groupHeaderEnabled) {
        const UA_NetworkMessageGroupHeader *g = &nm->groupHeader;
        printf(",\"groupHeader\":{");
        int f = 1;
        if (g->writerGroupIdEnabled) { printf("\"writerGroupId\":%u", (unsigned)g->writerGroupId); f = 0; }
        if (g->groupVersionEnabled) { printf("%s\"groupVersion\":%" PRIu32, f ? "" : ",", g->groupVersion); f = 0; }
        if (g->networkMessageNumberEnabled) { printf("%s\"networkMessageNumber\":%u", f ? "" : ",", (unsigned)g->networkMessageNumber); f = 0; }
        if (g->sequenceNumberEnabled) printf("%s\"sequenceNumber\":%u", f ? "" : ",", (unsigned)g->sequenceNumber);
        printf("}");
    }
    if (map == MAP_UADP)
        printf(",\"payloadHeader\":%s", nm->payloadHeaderEnabled ? "true" : "false");
    if (nm->timestampEnabled) {
        printf(",\"timestamp\":");
        print_datetime_full(nm->timestamp);
    }
    if (nm->picosecondsEnabled)
        printf(",\"picoseconds\":%u", (unsigned)nm->picoseconds);
    if (nm->promotedFieldsEnabled) {
        printf(",\"promotedFields\":[");
        for (size_t i = 0; i < nm->promotedFieldsSize; i++) {
            if (i) printf(",");
            printf("{");
            print_variant_members(&nm->promotedFields[i]);
            printf("}");
        }
        printf("]");
    }
    if (nm->securityEnabled) {
        const UA_NetworkMessageSecurityHeader *s = &nm->securityHeader;
        printf(",\"security\":{\"signed\":%s,\"encrypted\":%s,\"forceKeyReset\":%s,"
               "\"securityTokenId\":%" PRIu32 ",\"nonce\":",
               s->networkMessageSigned ? "true" : "false",
               s->networkMessageEncrypted ? "true" : "false",
               s->forceKeyReset ? "true" : "false", s->securityTokenId);
        print_b64(s->messageNonce, s->messageNonceSize);
        if (s->securityFooterEnabled)
            printf(",\"securityFooterSize\":%u", (unsigned)s->securityFooterSize);
        printf("}");
        if (s->securityFooterEnabled && nm->securityFooter.length > 0) {
            printf(",\"securityFooter\":");
            print_b64(nm->securityFooter.data, nm->securityFooter.length);
        }
    }
    if (map == MAP_UADP)
        printf(",\"chunk\":%s", nm->chunkMessage ? "true" : "false");
    printf(",\"messages\":[");
    int writerIdsKnown = (map == MAP_JSON) || nm->payloadHeaderEnabled;
    for (size_t i = 0; nm->payload.dataSetMessages && i < nm->messageCount; i++) {
        if (i) printf(",");
        UA_UInt16 wid = nm->dataSetWriterIds[i];
        const UA_DataSetMetaDataType *md = meta_for(meta, wid);
        print_dsm(&nm->payload.dataSetMessages[i], writerIdsKnown, wid, md,
                  jsonNames ? jsonNames[i] : NULL, jsonNameCounts ? jsonNameCounts[i] : 0);
    }
    printf("]}");
}

/* -------------------------------------------------------------------------
 * Description parsing (encode)
 * ---------------------------------------------------------------------- */

/* Canonical value encoding (contract §7) -> value literal (contract §12) */
static char *canon_to_literal(const cJSON *v, const char *typeName) {
    if (cJSON_IsString(v)) return strdup(v->valuestring);
    if (cJSON_IsBool(v)) return strdup(cJSON_IsTrue(v) ? "true" : "false");
    if (cJSON_IsNull(v)) {
        if (strcmp(typeName, "Float") == 0 || strcmp(typeName, "Double") == 0)
            return strdup("NaN");
        return strdup("");
    }
    if (cJSON_IsNumber(v)) return cJSON_PrintUnformatted(v);
    if (cJSON_IsObject(v)) {
        char buf[1024];
        const cJSON *a, *b;
        if (strcmp(typeName, "QualifiedName") == 0) {
            a = cJSON_GetObjectItemCaseSensitive(v, "ns");
            b = cJSON_GetObjectItemCaseSensitive(v, "name");
            snprintf(buf, sizeof(buf), "%d:%s", cJSON_IsNumber(a) ? a->valueint : 0,
                     cJSON_IsString(b) ? b->valuestring : "");
            return strdup(buf);
        }
        if (strcmp(typeName, "LocalizedText") == 0) {
            a = cJSON_GetObjectItemCaseSensitive(v, "locale");
            b = cJSON_GetObjectItemCaseSensitive(v, "text");
            snprintf(buf, sizeof(buf), "%s:%s", cJSON_IsString(a) ? a->valuestring : "",
                     cJSON_IsString(b) ? b->valuestring : "");
            return strdup(buf);
        }
        if (strcmp(typeName, "StatusCode") == 0) {
            a = cJSON_GetObjectItemCaseSensitive(v, "code");
            snprintf(buf, sizeof(buf), "%.0f", cJSON_IsNumber(a) ? a->valuedouble : 0.0);
            return strdup(buf);
        }
        if (strcmp(typeName, "ExtensionObject") == 0) {
            a = cJSON_GetObjectItemCaseSensitive(v, "typeId");
            b = cJSON_GetObjectItemCaseSensitive(v, "body");
            snprintf(buf, sizeof(buf), "%s|%s", cJSON_IsString(a) ? a->valuestring : "",
                     cJSON_IsString(b) ? b->valuestring : "");
            return strdup(buf);
        }
        if (strcmp(typeName, "Variant") == 0) {
            a = cJSON_GetObjectItemCaseSensitive(v, "dataType");
            b = cJSON_GetObjectItemCaseSensitive(v, "value");
            if (!cJSON_IsString(a)) return NULL;
            char *inner = canon_to_literal(b, a->valuestring);
            if (!inner) return NULL;
            snprintf(buf, sizeof(buf), "%s:%s", a->valuestring, inner);
            free(inner);
            return strdup(buf);
        }
    }
    return NULL;
}

/* Build a Variant from {"dataType","value"[,"arrayDimensions"]} */
static int parse_typed_value(const cJSON *obj, UA_Variant *out, char *err, size_t errLen) {
    UA_Variant_init(out);
    const cJSON *dt = cJSON_GetObjectItemCaseSensitive(obj, "dataType");
    const cJSON *val = cJSON_GetObjectItemCaseSensitive(obj, "value");
    if (!cJSON_IsString(dt)) {
        snprintf(err, errLen, "field without \"dataType\"");
        return -1;
    }
    if (strcmp(dt->valuestring, "Null") == 0)
        return 0; /* empty Variant */
    char *literal = NULL;
    char typeStr[80];
    char dims[256] = "";
    if (cJSON_IsArray(val)) {
        snprintf(typeStr, sizeof(typeStr), "%s[]", dt->valuestring);
        cJSON *lits = cJSON_CreateArray();
        const cJSON *e;
        cJSON_ArrayForEach(e, val) {
            char *l = canon_to_literal(e, dt->valuestring);
            if (!l) {
                cJSON_Delete(lits);
                snprintf(err, errLen, "cannot convert a %s array element", dt->valuestring);
                return -1;
            }
            cJSON_AddItemToArray(lits, cJSON_CreateString(l));
            free(l);
        }
        literal = cJSON_PrintUnformatted(lits);
        cJSON_Delete(lits);
        const cJSON *ad = cJSON_GetObjectItemCaseSensitive(obj, "arrayDimensions");
        if (cJSON_IsArray(ad)) {
            size_t off = 0;
            cJSON_ArrayForEach(e, ad)
                off += (size_t)snprintf(dims + off, sizeof(dims) - off, "%s%d",
                                        off ? "," : "", e->valueint);
        }
    } else {
        snprintf(typeStr, sizeof(typeStr), "%s", dt->valuestring);
        literal = canon_to_literal(val, dt->valuestring);
        if (!literal) {
            snprintf(err, errLen, "cannot convert the %s value", dt->valuestring);
            return -1;
        }
    }
    int rc = value_parse(typeStr, literal, dims[0] ? dims : NULL, out, err, errLen);
    free(literal);
    return rc;
}

static int parse_datetime_member(const cJSON *obj, const char *key, UA_DateTime *dt,
                                 UA_Boolean *enabled) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!v) return 0;
    if (!cJSON_IsString(v) || value_parse_datetime(v->valuestring, dt) != 0) return -1;
    if (enabled) *enabled = true;
    return 0;
}

static int get_u32(const cJSON *obj, const char *key, UA_UInt32 *out, UA_Boolean *enabled) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!v) return 0;
    if (!cJSON_IsNumber(v)) return -1;
    *out = (UA_UInt32)v->valuedouble;
    if (enabled) *enabled = true;
    return 1;
}

static int parse_field(const cJSON *fo, UA_FieldEncoding enc, UA_DataValue *dv,
                       char *err, size_t errLen) {
    UA_DataValue_init(dv);
    if (parse_typed_value(fo, &dv->value, err, errLen) != 0) return -1;
    dv->hasValue = !UA_Variant_isEmpty(&dv->value);
    if (enc != UA_FIELDENCODING_DATAVALUE) return 0;
    const cJSON *sc = cJSON_GetObjectItemCaseSensitive(fo, "statusCode");
    if (sc) {
        const cJSON *code = cJSON_IsObject(sc) ? cJSON_GetObjectItemCaseSensitive(sc, "code") : sc;
        if (!cJSON_IsNumber(code)) { snprintf(err, errLen, "invalid statusCode"); return -1; }
        dv->status = (UA_StatusCode)code->valuedouble;
        dv->hasStatus = true;
    }
    UA_Boolean b = false;
    if (parse_datetime_member(fo, "sourceTimestamp", &dv->sourceTimestamp, &b) != 0 ||
        (dv->hasSourceTimestamp = b, b = false,
         parse_datetime_member(fo, "serverTimestamp", &dv->serverTimestamp, &b) != 0)) {
        snprintf(err, errLen, "invalid field timestamp (RFC 3339 UTC)");
        return -1;
    }
    dv->hasServerTimestamp = b;
    UA_UInt32 u = 0;
    UA_Boolean e = false;
    if (get_u32(fo, "sourcePicoseconds", &u, &e) > 0) { dv->sourcePicoseconds = (UA_UInt16)u; dv->hasSourcePicoseconds = true; }
    e = false;
    if (get_u32(fo, "serverPicoseconds", &u, &e) > 0) { dv->serverPicoseconds = (UA_UInt16)u; dv->hasServerPicoseconds = true; }
    return 0;
}

static int parse_publisher_id(const cJSON *p, UA_PublisherId *out, char *err, size_t errLen) {
    const cJSON *t = cJSON_GetObjectItemCaseSensitive(p, "type");
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(p, "value");
    if (!cJSON_IsString(t) || !v) {
        snprintf(err, errLen, "publisherId is {\"type\":\"Byte|UInt16|UInt32|UInt64|String\",\"value\":...}");
        return -1;
    }
    const char *ty = t->valuestring;
    double num = cJSON_IsNumber(v) ? v->valuedouble
               : (cJSON_IsString(v) ? strtod(v->valuestring, NULL) : 0);
    if (strcmp(ty, "Byte") == 0) { out->idType = UA_PUBLISHERIDTYPE_BYTE; out->id.byte = (UA_Byte)num; }
    else if (strcmp(ty, "UInt16") == 0) { out->idType = UA_PUBLISHERIDTYPE_UINT16; out->id.uint16 = (UA_UInt16)num; }
    else if (strcmp(ty, "UInt32") == 0) { out->idType = UA_PUBLISHERIDTYPE_UINT32; out->id.uint32 = (UA_UInt32)num; }
    else if (strcmp(ty, "UInt64") == 0) {
        out->idType = UA_PUBLISHERIDTYPE_UINT64;
        out->id.uint64 = cJSON_IsString(v) ? strtoull(v->valuestring, NULL, 10) : (UA_UInt64)num;
    } else if (strcmp(ty, "String") == 0) {
        if (!cJSON_IsString(v)) { snprintf(err, errLen, "String publisherId needs a string value"); return -1; }
        out->idType = UA_PUBLISHERIDTYPE_STRING;
        out->id.string = UA_STRING_ALLOC(v->valuestring);
    } else {
        snprintf(err, errLen, "unknown publisherId type '%s'", ty);
        return -1;
    }
    return 0;
}

static int parse_enum(const cJSON *v, const char *const *names, int count, int *out) {
    if (!v) return 0;
    if (!cJSON_IsString(v)) return -1;
    for (int i = 0; i < count; i++)
        if (strcmp(v->valuestring, names[i]) == 0) { *out = i; return 0; }
    return -1;
}

/* Encoding metadata built from the description (names, types) */
typedef struct {
    UA_DataSetMessage_EncodingMetaData emd[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
    UA_FieldMetaData *fields[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
    size_t count;
} BuiltMeta;

static void built_meta_clear(BuiltMeta *bm) {
    for (size_t i = 0; i < bm->count; i++)
        UA_Array_delete(bm->fields[i], bm->emd[i].fieldsSize, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
    bm->count = 0;
}

static int parse_description(const cJSON *d, Mapping map, UA_NetworkMessage *nm,
                             const MetaList *meta, BuiltMeta *bm, char *err, size_t errLen) {
    memset(nm, 0, sizeof(*nm));
    memset(bm, 0, sizeof(*bm));
    nm->networkMessageType = UA_NETWORKMESSAGE_DATASET;
    const cJSON *v;
    UA_UInt32 u = 0;

    v = cJSON_GetObjectItemCaseSensitive(d, "version");
    nm->version = cJSON_IsNumber(v) ? (UA_Byte)v->valueint : 1;
    v = cJSON_GetObjectItemCaseSensitive(d, "messageId");
    if (cJSON_IsString(v)) { nm->messageIdEnabled = true; nm->messageId = UA_STRING_ALLOC(v->valuestring); }
    v = cJSON_GetObjectItemCaseSensitive(d, "publisherId");
    if (v) {
        if (parse_publisher_id(v, &nm->publisherId, err, errLen) != 0) return -1;
        nm->publisherIdEnabled = true;
    }
    v = cJSON_GetObjectItemCaseSensitive(d, "dataSetClassId");
    if (cJSON_IsString(v)) {
        UA_Variant g;
        if (value_parse("Guid", v->valuestring, NULL, &g, err, errLen) != 0) return -1;
        nm->dataSetClassId = *(UA_Guid *)g.data;
        nm->dataSetClassIdEnabled = true;
        UA_Variant_clear(&g);
    }
    v = cJSON_GetObjectItemCaseSensitive(d, "groupHeader");
    if (cJSON_IsObject(v)) {
        UA_NetworkMessageGroupHeader *g = &nm->groupHeader;
        nm->groupHeaderEnabled = true;
        if (get_u32(v, "writerGroupId", &u, &g->writerGroupIdEnabled) > 0) g->writerGroupId = (UA_UInt16)u;
        if (get_u32(v, "groupVersion", &u, &g->groupVersionEnabled) > 0) g->groupVersion = u;
        if (get_u32(v, "networkMessageNumber", &u, &g->networkMessageNumberEnabled) > 0) g->networkMessageNumber = (UA_UInt16)u;
        if (get_u32(v, "sequenceNumber", &u, &g->sequenceNumberEnabled) > 0) g->sequenceNumber = (UA_UInt16)u;
    }
    v = cJSON_GetObjectItemCaseSensitive(d, "payloadHeader");
    nm->payloadHeaderEnabled = (map == MAP_JSON) ? true : (v ? cJSON_IsTrue(v) : true);
    if (parse_datetime_member(d, "timestamp", &nm->timestamp, &nm->timestampEnabled) != 0) {
        snprintf(err, errLen, "invalid timestamp (RFC 3339 UTC)");
        return -1;
    }
    if (get_u32(d, "picoseconds", &u, &nm->picosecondsEnabled) > 0) nm->picoseconds = (UA_UInt16)u;
    v = cJSON_GetObjectItemCaseSensitive(d, "chunk");
    nm->chunkMessage = cJSON_IsTrue(v);

    v = cJSON_GetObjectItemCaseSensitive(d, "promotedFields");
    if (cJSON_IsArray(v) && cJSON_GetArraySize(v) > 0) {
        size_t n = (size_t)cJSON_GetArraySize(v);
        nm->promotedFields = (UA_Variant *)UA_Array_new(n, &UA_TYPES[UA_TYPES_VARIANT]);
        nm->promotedFieldsSize = (UA_UInt16)n;
        nm->promotedFieldsEnabled = true;
        size_t i = 0;
        const cJSON *pf;
        cJSON_ArrayForEach(pf, v) {
            if (parse_typed_value(pf, &nm->promotedFields[i++], err, errLen) != 0) return -1;
        }
    }

    v = cJSON_GetObjectItemCaseSensitive(d, "security");
    if (cJSON_IsObject(v)) {
        UA_NetworkMessageSecurityHeader *s = &nm->securityHeader;
        nm->securityEnabled = true;
        s->networkMessageSigned = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "signed"));
        s->networkMessageEncrypted = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "encrypted"));
        s->forceKeyReset = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(v, "forceKeyReset"));
        get_u32(v, "securityTokenId", &s->securityTokenId, NULL);
        const cJSON *nonce = cJSON_GetObjectItemCaseSensitive(v, "nonce");
        if (cJSON_IsString(nonce)) {
            size_t l = 0;
            unsigned char *b = value_b64_decode(nonce->valuestring, &l);
            if (!b || l > UA_NETWORKMESSAGE_MAX_NONCE_LENGTH) {
                free(b);
                snprintf(err, errLen, "security.nonce: Base64, at most %d bytes",
                         UA_NETWORKMESSAGE_MAX_NONCE_LENGTH);
                return -1;
            }
            memcpy(s->messageNonce, b, l);
            s->messageNonceSize = (UA_UInt16)l;
            free(b);
        }
        if (get_u32(v, "securityFooterSize", &u, &s->securityFooterEnabled) > 0)
            s->securityFooterSize = (UA_UInt16)u;
        const cJSON *foot = cJSON_GetObjectItemCaseSensitive(d, "securityFooter");
        if (cJSON_IsString(foot)) {
            size_t l = 0;
            unsigned char *b = value_b64_decode(foot->valuestring, &l);
            if (b) {
                UA_ByteString_allocBuffer(&nm->securityFooter, l);
                memcpy(nm->securityFooter.data, b, l);
                free(b);
                if (!s->securityFooterEnabled) {
                    s->securityFooterEnabled = true;
                    s->securityFooterSize = (UA_UInt16)l;
                }
            }
        }
    }

    const cJSON *msgs = cJSON_GetObjectItemCaseSensitive(d, "messages");
    if (!cJSON_IsArray(msgs)) {
        snprintf(err, errLen, "\"messages\" (array of DataSetMessages) is required");
        return -1;
    }
    size_t count = (size_t)cJSON_GetArraySize(msgs);
    if (count > UA_NETWORKMESSAGE_MAXMESSAGECOUNT) {
        snprintf(err, errLen, "at most %d DataSetMessages", UA_NETWORKMESSAGE_MAXMESSAGECOUNT);
        return -1;
    }
    nm->messageCount = (UA_Byte)count;
    nm->payload.dataSetMessages = (UA_DataSetMessage *)calloc(count ? count : 1,
                                                              sizeof(UA_DataSetMessage));
    static const char *const mtNames[] = { "KeyFrame", "DeltaFrame", "Event", "KeepAlive" };
    static const char *const feNames[] = { "Variant", "RawData", "DataValue" };
    size_t mi = 0;
    const cJSON *m;
    cJSON_ArrayForEach(m, msgs) {
        UA_DataSetMessage *dsm = &nm->payload.dataSetMessages[mi];
        UA_DataSetMessageHeader *h = &dsm->header;
        if (get_u32(m, "dataSetWriterId", &u, NULL) > 0) nm->dataSetWriterIds[mi] = (UA_UInt16)u;
        int mt = 0, fe = 0;
        if (parse_enum(cJSON_GetObjectItemCaseSensitive(m, "messageType"), mtNames, 4, &mt) != 0 ||
            parse_enum(cJSON_GetObjectItemCaseSensitive(m, "fieldEncoding"), feNames, 3, &fe) != 0) {
            snprintf(err, errLen, "messages[%zu]: messageType KeyFrame|DeltaFrame|Event|KeepAlive, "
                     "fieldEncoding Variant|RawData|DataValue", mi);
            return -1;
        }
        h->dataSetMessageType = (UA_DataSetMessageType)mt;
        h->fieldEncoding = (UA_FieldEncoding)fe;
        const cJSON *valid = cJSON_GetObjectItemCaseSensitive(m, "valid");
        h->dataSetMessageValid = valid ? cJSON_IsTrue(valid) : true;
        if (get_u32(m, "sequenceNumber", &u, &h->dataSetMessageSequenceNrEnabled) > 0)
            h->dataSetMessageSequenceNr = (UA_UInt16)u;
        if (parse_datetime_member(m, "timestamp", &h->timestamp, &h->timestampEnabled) != 0) {
            snprintf(err, errLen, "messages[%zu].timestamp: RFC 3339 UTC", mi);
            return -1;
        }
        if (get_u32(m, "picoseconds", &u, &h->picoSecondsIncluded) > 0) h->picoSeconds = (UA_UInt16)u;
        if (get_u32(m, "status", &u, &h->statusEnabled) > 0) h->status = (UA_UInt16)u;
        const cJSON *cv = cJSON_GetObjectItemCaseSensitive(m, "configVersion");
        if (cJSON_IsObject(cv)) {
            get_u32(cv, "majorVersion", &h->configVersionMajorVersion, &h->configVersionMajorVersionEnabled);
            get_u32(cv, "minorVersion", &h->configVersionMinorVersion, &h->configVersionMinorVersionEnabled);
        }

        const cJSON *fields = cJSON_GetObjectItemCaseSensitive(m, "fields");
        size_t fc = cJSON_IsArray(fields) ? (size_t)cJSON_GetArraySize(fields) : 0;
        dsm->fieldCount = (UA_UInt16)fc;

        /* Encoding metadata: --metadata for this writer, else built from the
         * field names / types of the description */
        UA_DataSetMessage_EncodingMetaData *emd = &bm->emd[bm->count];
        emd->dataSetWriterId = nm->dataSetWriterIds[mi];
        const UA_DataSetMetaDataType *md = meta_for(meta, nm->dataSetWriterIds[mi]);
        UA_FieldMetaData *fmd = (UA_FieldMetaData *)UA_Array_new(fc, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
        if (md) {
            UA_Array_delete(fmd, fc, &UA_TYPES[UA_TYPES_FIELDMETADATA]);
            UA_Array_copy(md->fields, md->fieldsSize, (void **)&fmd,
                          &UA_TYPES[UA_TYPES_FIELDMETADATA]);
            emd->fieldsSize = md->fieldsSize;
        } else {
            emd->fieldsSize = fc;
        }
        emd->fields = fmd;
        bm->fields[bm->count] = fmd;
        bm->count++;

        if (h->dataSetMessageType == UA_DATASETMESSAGE_DATAKEYFRAME && fc > 0) {
            dsm->data.keyFrameFields = (UA_DataValue *)UA_Array_new(fc, &UA_TYPES[UA_TYPES_DATAVALUE]);
            size_t fi = 0;
            const cJSON *fo;
            cJSON_ArrayForEach(fo, fields) {
                char ferr[200];
                if (parse_field(fo, h->fieldEncoding, &dsm->data.keyFrameFields[fi], ferr, sizeof(ferr)) != 0) {
                    snprintf(err, errLen, "messages[%zu].fields[%zu]: %s", mi, fi, ferr);
                    return -1;
                }
                if (!md) {
                    const cJSON *nmv = cJSON_GetObjectItemCaseSensitive(fo, "name");
                    if (cJSON_IsString(nmv)) fmd[fi].name = UA_STRING_ALLOC(nmv->valuestring);
                    const UA_Variant *fv = &dsm->data.keyFrameFields[fi].value;
                    if (fv->type) {
                        fmd[fi].builtInType = (UA_Byte)ua_type_to_builtin_id(fv->type);
                        UA_NodeId_copy(&fv->type->typeId, &fmd[fi].dataType);
                        fmd[fi].valueRank = UA_Variant_isScalar(fv) ? -1 :
                            (fv->arrayDimensionsSize > 1 ? (UA_Int32)fv->arrayDimensionsSize : 1);
                    } else {
                        fmd[fi].valueRank = -1;
                    }
                }
                fi++;
            }
        } else if (h->dataSetMessageType == UA_DATASETMESSAGE_DATADELTAFRAME && fc > 0) {
            dsm->data.deltaFrameFields = (UA_DataSetMessage_DeltaFrameField *)
                calloc(fc, sizeof(UA_DataSetMessage_DeltaFrameField));
            size_t fi = 0;
            const cJSON *fo;
            cJSON_ArrayForEach(fo, fields) {
                char ferr[200];
                if (get_u32(fo, "index", &u, NULL) <= 0) {
                    snprintf(err, errLen, "messages[%zu].fields[%zu]: DeltaFrame fields need \"index\"", mi, fi);
                    return -1;
                }
                dsm->data.deltaFrameFields[fi].index = (UA_UInt16)u;
                if (parse_field(fo, h->fieldEncoding, &dsm->data.deltaFrameFields[fi].value,
                                ferr, sizeof(ferr)) != 0) {
                    snprintf(err, errLen, "messages[%zu].fields[%zu]: %s", mi, fi, ferr);
                    return -1;
                }
                fi++;
            }
        }
        mi++;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * JSON payload key names (decode without metadata)
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_String *names[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
    size_t counts[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
} JsonNames;

static void json_names_collect(const char *doc, size_t len, JsonNames *jn) {
    memset(jn, 0, sizeof(*jn));
    cJSON *root = cJSON_ParseWithLength(doc, len);
    if (!root) return;
    cJSON *msgs = cJSON_GetObjectItemCaseSensitive(root, "Messages");
    cJSON *single = NULL;
    if (cJSON_IsObject(msgs)) { single = msgs; }
    size_t i = 0;
    cJSON *m = single ? single : (cJSON_IsArray(msgs) ? msgs->child : NULL);
    for (; m && i < UA_NETWORKMESSAGE_MAXMESSAGECOUNT; m = single ? NULL : m->next, i++) {
        cJSON *p = cJSON_GetObjectItemCaseSensitive(m, "Payload");
        if (!cJSON_IsObject(p)) continue;
        size_t n = (size_t)cJSON_GetArraySize(p);
        jn->names[i] = (UA_String *)UA_Array_new(n, &UA_TYPES[UA_TYPES_STRING]);
        jn->counts[i] = n;
        size_t k = 0;
        for (cJSON *f = p->child; f && k < n; f = f->next, k++)
            jn->names[i][k] = UA_STRING_ALLOC(f->string);
    }
    cJSON_Delete(root);
}

static void json_names_clear(JsonNames *jn) {
    for (size_t i = 0; i < UA_NETWORKMESSAGE_MAXMESSAGECOUNT; i++)
        UA_Array_delete(jn->names[i], jn->counts[i], &UA_TYPES[UA_TYPES_STRING]);
}

/* -------------------------------------------------------------------------
 * Commands
 * ---------------------------------------------------------------------- */

static void emit_head(const char *action, Mapping map, UA_StatusCode sc) {
    output_begin("open62541", OP);
    output_success(sc == UA_STATUSCODE_GOOD);
    output_service_result(sc);
    output_open_results();
    printf("{\"action\":\"%s\",\"mapping\":\"%s\",", action, map == MAP_UADP ? "uadp" : "json");
    cli_print_status("statusCode", sc);
}

static void emit_tail(UA_StatusCode sc, const char *what) {
    printf("}");
    output_close_results();
    if (sc == UA_STATUSCODE_GOOD) {
        output_null_error();
    } else {
        printf(",\"error\":{\"category\":\"service\",\"message\":");
        output_json_string(what);
        printf("}");
    }
    output_end();
}

static void clear_built_nm(UA_NetworkMessage *nm) {
    /* parse_description allocated the DSM array with calloc and the delta
     * frame arrays with calloc; UA_NetworkMessage_clear frees with UA_free,
     * which is free() in the default allocator. */
    UA_NetworkMessage_clear(nm);
}

static int pubsub_encode(int argc, char **argv, Mapping map, const char *action) {
    char err[512];
    size_t len = 0;
    char *doc = read_input(argc, argv, &len);
    if (!doc || len == 0) { free(doc); return usage_error("empty description (--document, --input or stdin)"); }
    MetaList meta;
    if (meta_parse(argc, argv, &meta, err, sizeof(err)) != 0) { free(doc); return usage_error(err); }
    cJSON *d = cJSON_Parse(doc);
    free(doc);
    if (!cJSON_IsObject(d)) { cJSON_Delete(d); meta_clear(&meta); return usage_error("the description is not a JSON object"); }

    UA_NetworkMessage nm;
    BuiltMeta bm;
    if (parse_description(d, map, &nm, &meta, &bm, err, sizeof(err)) != 0) {
        cJSON_Delete(d);
        clear_built_nm(&nm);
        built_meta_clear(&bm);
        meta_clear(&meta);
        return usage_error(err);
    }
    cJSON_Delete(d);

    UA_NetworkMessage_EncodingOptions eo;
    eo.metaData = bm.emd;
    eo.metaDataSize = bm.count;
    UA_ByteString out = UA_BYTESTRING_NULL;
    UA_StatusCode sc;
    if (map == MAP_UADP)
        sc = UA_NetworkMessage_encodeBinary(&nm, &out, &eo);
    else
        sc = UA_NetworkMessage_encodeJson(&nm, &out, &eo, NULL);

    emit_head(action, map, sc);
    if (sc == UA_STATUSCODE_GOOD) {
        if (map == MAP_UADP) {
            printf(",\"encoded\":");
            print_b64(out.data, out.length);
        } else {
            printf(",\"encoded\":");
            output_json_string_len(out.data, out.length);
        }
        printf(",\"length\":%zu", out.length);
    }
    emit_tail(sc, "encoding failed");

    UA_ByteString_clear(&out);
    clear_built_nm(&nm);
    built_meta_clear(&bm);
    meta_clear(&meta);
    return sc == UA_STATUSCODE_GOOD ? 0 : 4;
}

/* EncodingMetaData from --metadata for the given writer ids */
static size_t meta_to_emd(const MetaList *meta, const UA_UInt16 *writerIds, size_t n,
                          UA_DataSetMessage_EncodingMetaData *emd) {
    size_t k = 0;
    for (size_t i = 0; i < n && k < UA_NETWORKMESSAGE_MAXMESSAGECOUNT; i++) {
        const UA_DataSetMetaDataType *md = meta_for(meta, writerIds[i]);
        if (!md) continue;
        emd[k].dataSetWriterId = writerIds[i];
        emd[k].fields = md->fields;
        emd[k].fieldsSize = md->fieldsSize;
        emd[k].configuredSize = 0;
        k++;
    }
    return k;
}

static int pubsub_decode(int argc, char **argv, Mapping map, const char *action) {
    char err[512];
    size_t len = 0;
    char *doc = read_input(argc, argv, &len);
    if (!doc || len == 0) { free(doc); return usage_error("empty input (--document, --input or stdin)"); }
    MetaList meta;
    if (meta_parse(argc, argv, &meta, err, sizeof(err)) != 0) { free(doc); return usage_error(err); }

    UA_ByteString wire = UA_BYTESTRING_NULL;
    if (map == MAP_UADP) {
        size_t bl = 0;
        unsigned char *b = value_b64_decode(doc, &bl);
        if (!b) { free(doc); meta_clear(&meta); return usage_error("the UADP input is not Base64"); }
        wire.data = b;
        wire.length = bl;
    } else {
        wire.data = (UA_Byte *)doc;
        wire.length = len;
    }

    UA_DataSetMessage_EncodingMetaData emd[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
    memset(emd, 0, sizeof(emd));
    UA_NetworkMessage_EncodingOptions eo;
    eo.metaData = emd;
    eo.metaDataSize = 0;

    UA_NetworkMessage nm;
    memset(&nm, 0, sizeof(nm));
    UA_StatusCode sc;
    JsonNames jn;
    memset(&jn, 0, sizeof(jn));
    if (map == MAP_UADP) {
        if (meta.count > 0) {
            /* Learn the writer ids from the headers, then attach the metadata */
            UA_NetworkMessage hdr;
            memset(&hdr, 0, sizeof(hdr));
            size_t off = 0;
            UA_UInt16 ids[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
            size_t nIds = 1;
            ids[0] = 0;
            if (UA_NetworkMessage_decodeBinaryHeaders(&wire, &hdr, NULL, NULL, &off) ==
                    UA_STATUSCODE_GOOD && hdr.payloadHeaderEnabled) {
                nIds = hdr.messageCount;
                memcpy(ids, hdr.dataSetWriterIds, nIds * sizeof(UA_UInt16));
            } else if (meta.count > 0 && meta.items[0].hasWriterId) {
                nIds = 0;
                for (size_t i = 0; i < meta.count && i < UA_NETWORKMESSAGE_MAXMESSAGECOUNT; i++)
                    ids[nIds++] = meta.items[i].writerId;
            }
            UA_NetworkMessage_clear(&hdr);
            eo.metaDataSize = meta_to_emd(&meta, ids, nIds, emd);
        }
        sc = UA_NetworkMessage_decodeBinary(&wire, &nm, eo.metaDataSize ? &eo : NULL, NULL);
    } else {
        if (meta.count > 0) {
            /* JSON writer ids are in the DataSetMessages: decode once to learn them */
            UA_NetworkMessage first;
            memset(&first, 0, sizeof(first));
            if (UA_NetworkMessage_decodeJson(&wire, &first, NULL, NULL) == UA_STATUSCODE_GOOD)
                eo.metaDataSize = meta_to_emd(&meta, first.dataSetWriterIds, first.messageCount, emd);
            UA_NetworkMessage_clear(&first);
        }
        json_names_collect((const char *)wire.data, wire.length, &jn);
        sc = UA_NetworkMessage_decodeJson(&wire, &nm, eo.metaDataSize ? &eo : NULL, NULL);
    }

    emit_head(action, map, sc);
    if (sc == UA_STATUSCODE_GOOD) {
        printf(",\"networkMessage\":");
        print_description(&nm, map, &meta, map == MAP_JSON ? (const UA_String *const *)jn.names : NULL,
                          map == MAP_JSON ? jn.counts : NULL);
        /* The stack's own re-encoding of what it decoded. The v1.5.9 JSON
         * encoder dereferences the EncodingMetaData of every DataSetWriterId
         * (NULL -> crash), so JSON always gets one entry per message, with
         * the field names from --metadata or from the decoded Payload keys. */
        UA_DataSetMessage_EncodingMetaData remd[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
        UA_FieldMetaData *rfields[UA_NETWORKMESSAGE_MAXMESSAGECOUNT];
        memset(remd, 0, sizeof(remd));
        memset(rfields, 0, sizeof(rfields));
        UA_NetworkMessage_EncodingOptions reo = eo;
        if (map == MAP_JSON) {
            for (size_t i = 0; i < nm.messageCount; i++) {
                remd[i].dataSetWriterId = nm.dataSetWriterIds[i];
                const UA_DataSetMetaDataType *md = meta_for(&meta, nm.dataSetWriterIds[i]);
                if (md) {
                    remd[i].fields = md->fields;
                    remd[i].fieldsSize = md->fieldsSize;
                } else if (jn.counts[i] > 0) {
                    rfields[i] = (UA_FieldMetaData *)UA_Array_new(jn.counts[i],
                                                                  &UA_TYPES[UA_TYPES_FIELDMETADATA]);
                    for (size_t k = 0; rfields[i] && k < jn.counts[i]; k++)
                        UA_String_copy(&jn.names[i][k], &rfields[i][k].name);
                    remd[i].fields = rfields[i];
                    remd[i].fieldsSize = rfields[i] ? jn.counts[i] : 0;
                }
            }
            reo.metaData = remd;
            reo.metaDataSize = nm.messageCount;
        }
        UA_ByteString re = UA_BYTESTRING_NULL;
        UA_StatusCode rsc = (map == MAP_UADP)
            ? UA_NetworkMessage_encodeBinary(&nm, &re, eo.metaDataSize ? &eo : NULL)
            : UA_NetworkMessage_encodeJson(&nm, &re, &reo, NULL);
        for (size_t i = 0; i < UA_NETWORKMESSAGE_MAXMESSAGECOUNT; i++)
            if (rfields[i])
                UA_Array_delete(rfields[i], jn.counts[i], &UA_TYPES[UA_TYPES_FIELDMETADATA]);
        printf(",\"reencoded\":");
        if (rsc != UA_STATUSCODE_GOOD) printf("null");
        else if (map == MAP_UADP) print_b64(re.data, re.length);
        else output_json_string_len(re.data, re.length);
        printf(",");
        cli_print_status("reencodeStatusCode", rsc);
        UA_ByteString_clear(&re);
    }
    emit_tail(sc, "decoding failed");

    UA_NetworkMessage_clear(&nm);
    json_names_clear(&jn);
    if (map == MAP_UADP) free(wire.data);
    free(doc);
    meta_clear(&meta);
    return sc == UA_STATUSCODE_GOOD ? 0 : 4;
}

int cmd_codec_pubsub(int argc, char **argv) {
    /* argv[0] = pubsub-<mapping>-<action> */
    const char *op = argv[0];
    if (strcmp(op, "pubsub-uadp-encode") == 0) return pubsub_encode(argc, argv, MAP_UADP, op);
    if (strcmp(op, "pubsub-uadp-decode") == 0) return pubsub_decode(argc, argv, MAP_UADP, op);
    if (strcmp(op, "pubsub-json-encode") == 0) return pubsub_encode(argc, argv, MAP_JSON, op);
    if (strcmp(op, "pubsub-json-decode") == 0) return pubsub_decode(argc, argv, MAP_JSON, op);
    return usage_error("codec pubsub-uadp-encode|pubsub-uadp-decode|pubsub-json-encode|"
                       "pubsub-json-decode [--document <text>|--input <file>] "
                       "[--metadata <json>|--metadata-file <file>]");
}
