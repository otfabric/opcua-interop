#include "output.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

static void print_json_string(const char *s) {
    if (!s) { printf("null"); return; }
    putchar('"');
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if      (c == '"')  printf("\\\"");
        else if (c == '\\') printf("\\\\");
        else if (c == '\n') printf("\\n");
        else if (c == '\r') printf("\\r");
        else if (c == '\t') printf("\\t");
        else if (c < 0x20)  printf("\\u%04x", c);
        else                putchar(c);
    }
    putchar('"');
}

static void print_json_string_len(const unsigned char *data, size_t len) {
    if (!data) { printf("null"); return; }
    /* Copy to NUL-terminated buffer */
    char *tmp = malloc(len + 1);
    if (!tmp) { printf("null"); return; }
    memcpy(tmp, data, len);
    tmp[len] = '\0';
    print_json_string(tmp);
    free(tmp);
}

/* -------------------------------------------------------------------------
 * Status codes
 * ---------------------------------------------------------------------- */

const char *output_severity(UA_StatusCode code) {
    if (UA_StatusCode_isGood(code))      return "Good";
    if (UA_StatusCode_isUncertain(code)) return "Uncertain";
    return "Bad";
}

const char *output_status_code_name(UA_StatusCode code) {
    const char *name = UA_StatusCode_name(code);
    return (name && name[0]) ? name : "Unknown";
}

/* -------------------------------------------------------------------------
 * Built-in type id
 * ---------------------------------------------------------------------- */

int ua_type_to_builtin_id(const UA_DataType *type) {
    if (!type) return 0;
    if (type == &UA_TYPES[UA_TYPES_BOOLEAN])       return 1;
    if (type == &UA_TYPES[UA_TYPES_SBYTE])         return 2;
    if (type == &UA_TYPES[UA_TYPES_BYTE])          return 3;
    if (type == &UA_TYPES[UA_TYPES_INT16])         return 4;
    if (type == &UA_TYPES[UA_TYPES_UINT16])        return 5;
    if (type == &UA_TYPES[UA_TYPES_INT32])         return 6;
    if (type == &UA_TYPES[UA_TYPES_UINT32])        return 7;
    if (type == &UA_TYPES[UA_TYPES_INT64])         return 8;
    if (type == &UA_TYPES[UA_TYPES_UINT64])        return 9;
    if (type == &UA_TYPES[UA_TYPES_FLOAT])         return 10;
    if (type == &UA_TYPES[UA_TYPES_DOUBLE])        return 11;
    if (type == &UA_TYPES[UA_TYPES_STRING])        return 12;
    if (type == &UA_TYPES[UA_TYPES_DATETIME])      return 13;
    if (type == &UA_TYPES[UA_TYPES_GUID])          return 14;
    if (type == &UA_TYPES[UA_TYPES_BYTESTRING])    return 15;
    if (type == &UA_TYPES[UA_TYPES_XMLELEMENT])    return 16;
    if (type == &UA_TYPES[UA_TYPES_NODEID])        return 17;
    if (type == &UA_TYPES[UA_TYPES_STATUSCODE])    return 19;
    if (type == &UA_TYPES[UA_TYPES_QUALIFIEDNAME]) return 20;
    if (type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]) return 21;
    return 0;
}

/* -------------------------------------------------------------------------
 * Timestamp
 * ---------------------------------------------------------------------- */

void output_timestamp(UA_DateTime dt, char *buf, size_t bufLen) {
    if (dt == 0) { if (bufLen > 0) buf[0] = '\0'; return; }
    UA_DateTimeStruct dts = UA_DateTime_toStruct(dt);
    snprintf(buf, bufLen,
             "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             dts.year, dts.month, dts.day,
             dts.hour, dts.min,   dts.sec,
             dts.milliSec);
}

/* -------------------------------------------------------------------------
 * NodeId printing
 * ---------------------------------------------------------------------- */

static void print_base64(const unsigned char *data, size_t len) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < len; i += 3) {
        unsigned char a = data[i];
        unsigned char b = (i+1 < len) ? data[i+1] : 0;
        unsigned char c = (i+2 < len) ? data[i+2] : 0;
        putchar(b64[a >> 2]);
        putchar(b64[((a & 3) << 4) | (b >> 4)]);
        putchar((i+1 < len) ? b64[((b & 0xf) << 2) | (c >> 6)] : '=');
        putchar((i+2 < len) ? b64[c & 0x3f] : '=');
    }
}

static void print_ua_nodeid(const UA_NodeId *nid) {
    switch (nid->identifierType) {
        case UA_NODEIDTYPE_NUMERIC:
            if (nid->namespaceIndex == 0)
                printf("\"i=%" PRIu32 "\"", nid->identifier.numeric);
            else
                printf("\"ns=%" PRIu16 ";i=%" PRIu32 "\"",
                       nid->namespaceIndex, nid->identifier.numeric);
            break;
        case UA_NODEIDTYPE_STRING: {
            const UA_String *s = &nid->identifier.string;
            printf("\"ns=%" PRIu16 ";s=", nid->namespaceIndex);
            for (size_t i = 0; i < s->length; i++) {
                unsigned char c = s->data[i];
                if (c == '"' || c == '\\') putchar('\\');
                putchar((char)c);
            }
            printf("\"");
            break;
        }
        case UA_NODEIDTYPE_GUID: {
            const UA_Guid *g = &nid->identifier.guid;
            printf("\"ns=%" PRIu16 ";g=%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16
                   "-%02" PRIx8 "%02" PRIx8
                   "-%02" PRIx8 "%02" PRIx8 "%02" PRIx8
                   "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "\"",
                   nid->namespaceIndex,
                   g->data1, g->data2, g->data3,
                   g->data4[0], g->data4[1],
                   g->data4[2], g->data4[3], g->data4[4],
                   g->data4[5], g->data4[6], g->data4[7]);
            break;
        }
        case UA_NODEIDTYPE_BYTESTRING: {
            const UA_ByteString *bs = &nid->identifier.byteString;
            printf("\"ns=%" PRIu16 ";b=", nid->namespaceIndex);
            if (bs->data && bs->length > 0)
                print_base64(bs->data, bs->length);
            printf("\"");
            break;
        }
        default:
            printf("\"ns=%" PRIu16 ";...\"", nid->namespaceIndex);
            break;
    }
}

/* -------------------------------------------------------------------------
 * NodeClass name
 * ---------------------------------------------------------------------- */

static const char *node_class_name(UA_NodeClass nc) {
    switch (nc) {
        case UA_NODECLASS_OBJECT:        return "Object";
        case UA_NODECLASS_VARIABLE:      return "Variable";
        case UA_NODECLASS_METHOD:        return "Method";
        case UA_NODECLASS_OBJECTTYPE:    return "ObjectType";
        case UA_NODECLASS_VARIABLETYPE:  return "VariableType";
        case UA_NODECLASS_REFERENCETYPE: return "ReferenceType";
        case UA_NODECLASS_DATATYPE:      return "DataType";
        case UA_NODECLASS_VIEW:          return "View";
        default:                         return "Unknown";
    }
}

/* -------------------------------------------------------------------------
 * UA_Variant printing
 * ---------------------------------------------------------------------- */

static void print_ua_string(const UA_String *s) {
    if (!s || !s->data) { printf("null"); return; }
    if (s->length == 0) { printf("\"\""); return; }
    print_json_string_len(s->data, s->length);
}

/* Like print_ua_string but always emits a JSON string (never null). */
static void print_ua_string_nn(const UA_String *s) {
    if (!s || !s->data || s->length == 0) { printf("\"\""); return; }
    print_json_string_len(s->data, s->length);
}

static void print_ua_guid(const UA_Guid *g) {
    printf("\"%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16
           "-%02" PRIx8 "%02" PRIx8
           "-%02" PRIx8 "%02" PRIx8 "%02" PRIx8
           "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "\"",
           g->data1, g->data2, g->data3,
           g->data4[0], g->data4[1],
           g->data4[2], g->data4[3], g->data4[4],
           g->data4[5], g->data4[6], g->data4[7]);
}

static void print_scalar(const void *data, const UA_DataType *type) {
    if (!data || !type) { printf("null"); return; }

    if (type == &UA_TYPES[UA_TYPES_BOOLEAN]) {
        printf("%s", *(UA_Boolean*)data ? "true" : "false");
    } else if (type == &UA_TYPES[UA_TYPES_SBYTE]) {
        printf("%" PRId8, *(UA_SByte*)data);
    } else if (type == &UA_TYPES[UA_TYPES_BYTE]) {
        printf("%" PRIu8, *(UA_Byte*)data);
    } else if (type == &UA_TYPES[UA_TYPES_INT16]) {
        printf("%" PRId16, *(UA_Int16*)data);
    } else if (type == &UA_TYPES[UA_TYPES_UINT16]) {
        printf("%" PRIu16, *(UA_UInt16*)data);
    } else if (type == &UA_TYPES[UA_TYPES_INT32]) {
        printf("%" PRId32, *(UA_Int32*)data);
    } else if (type == &UA_TYPES[UA_TYPES_UINT32]) {
        printf("%" PRIu32, *(UA_UInt32*)data);
    } else if (type == &UA_TYPES[UA_TYPES_INT64]) {
        printf("\"%" PRId64 "\"", *(UA_Int64*)data);
    } else if (type == &UA_TYPES[UA_TYPES_UINT64]) {
        printf("\"%" PRIu64 "\"", *(UA_UInt64*)data);
    } else if (type == &UA_TYPES[UA_TYPES_FLOAT]) {
        float v = *(UA_Float*)data;
        if (isfinite(v)) printf("%g", (double)v); else printf("null");
    } else if (type == &UA_TYPES[UA_TYPES_DOUBLE]) {
        double v = *(UA_Double*)data;
        if (isfinite(v)) printf("%.17g", v); else printf("null");
    } else if (type == &UA_TYPES[UA_TYPES_STRING]) {
        print_ua_string((UA_String*)data);
    } else if (type == &UA_TYPES[UA_TYPES_DATETIME]) {
        char buf[64];
        output_timestamp(*(UA_DateTime*)data, buf, sizeof(buf));
        if (buf[0]) printf("\"%s\"", buf); else printf("null");
    } else if (type == &UA_TYPES[UA_TYPES_GUID]) {
        print_ua_guid((UA_Guid*)data);
    } else if (type == &UA_TYPES[UA_TYPES_BYTESTRING]) {
        UA_ByteString *bs = (UA_ByteString*)data;
        if (!bs->data) { printf("null"); return; }
        putchar('"');
        print_base64(bs->data, bs->length);
        putchar('"');
    } else if (type == &UA_TYPES[UA_TYPES_XMLELEMENT]) {
        UA_XmlElement *xe = (UA_XmlElement*)data;
        if (!xe->data) { printf("null"); return; }
        print_json_string_len(xe->data, xe->length);
    } else if (type == &UA_TYPES[UA_TYPES_NODEID]) {
        print_ua_nodeid((UA_NodeId*)data);
    } else if (type == &UA_TYPES[UA_TYPES_QUALIFIEDNAME]) {
        UA_QualifiedName *qn = (UA_QualifiedName*)data;
        printf("{\"ns\":%" PRIu16 ",\"name\":", qn->namespaceIndex);
        print_ua_string_nn(&qn->name);
        printf("}");
    } else if (type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]) {
        UA_LocalizedText *lt = (UA_LocalizedText*)data;
        printf("{\"locale\":");
        print_ua_string_nn(&lt->locale);
        printf(",\"text\":");
        print_ua_string_nn(&lt->text);
        printf("}");
    } else if (type == &UA_TYPES[UA_TYPES_STATUSCODE]) {
        UA_StatusCode sc = *(UA_StatusCode*)data;
        printf("{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
               output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
    } else {
        printf("null");
    }
}

void output_ua_variant_value(const UA_Variant *var) {
    if (!var || UA_Variant_isEmpty(var)) { printf("null"); return; }

    if (UA_Variant_isScalar(var)) {
        print_scalar(var->data, var->type);
    } else {
        size_t n    = var->arrayLength;
        char  *base = (char*)var->data;
        size_t sz   = var->type->memSize;
        printf("[");
        for (size_t i = 0; i < n; i++) {
            if (i > 0) printf(",");
            print_scalar(base + i * sz, var->type);
        }
        printf("]");
    }
}

void output_ua_variant_field(const char *key, const UA_Variant *var) {
    printf(",\"%s\":", key);
    output_ua_variant_value(var);
}

/* -------------------------------------------------------------------------
 * Top-level envelope
 * ---------------------------------------------------------------------- */

void output_begin(const char *adapter, const char *op) {
    printf("{\"schemaVersion\":\"1.0\",\"adapter\":");
    print_json_string(adapter);
    printf(",\"operation\":");
    print_json_string(op);
}

void output_success(int ok) {
    printf(",\"success\":%s", ok ? "true" : "false");
}

void output_service_result(UA_StatusCode code) {
    printf(",\"serviceResult\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(code), (uint32_t)code, output_severity(code));
}

void output_end(void) {
    printf("}\n");
    fflush(stdout);
}

/* -------------------------------------------------------------------------
 * Results / error block
 * ---------------------------------------------------------------------- */

void output_open_results(void) {
    printf(",\"results\":[");
}

void output_close_results(void) {
    printf("]");
}

void output_null_error(void) {
    printf(",\"error\":null");
}

void output_no_results(void) {
    printf(",\"results\":[]");
    printf(",\"error\":null");
}

void output_error(const char *category, const char *message) {
    printf(",\"results\":[]");
    printf(",\"error\":{\"category\":");
    print_json_string(category);
    printf(",\"message\":");
    print_json_string(message);
    printf("}");
}

/* -------------------------------------------------------------------------
 * Read result items
 * ---------------------------------------------------------------------- */

void output_read_result_item(const char *nodeId, UA_StatusCode sc,
                              const char *dataType, int builtInType,
                              const UA_Variant *val, UA_DateTime sourceTs) {
    printf("{\"nodeId\":");
    print_json_string(nodeId);
    printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
    printf(",\"dataType\":");
    print_json_string(dataType);
    printf(",\"builtInType\":%d", builtInType);
    if (val) output_ua_variant_field("value", val);
    else     printf(",\"value\":null");
    if (sourceTs != 0) {
        char tsbuf[64];
        output_timestamp(sourceTs, tsbuf, sizeof(tsbuf));
        if (tsbuf[0]) printf(",\"sourceTimestamp\":\"%s\"", tsbuf);
    }
    printf("}");
}

void output_read_result(const char *nodeId, UA_StatusCode sc,
                        const char *dataType, int builtInType,
                        const UA_Variant *val, UA_DateTime sourceTs) {
    output_open_results();
    output_read_result_item(nodeId, sc, dataType, builtInType, val, sourceTs);
    output_close_results();
    output_null_error();
}

/* -------------------------------------------------------------------------
 * Write result
 * ---------------------------------------------------------------------- */

void output_write_result_item(const char *nodeId, UA_StatusCode sc) {
    printf("{\"nodeId\":");
    print_json_string(nodeId);
    printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}}",
           output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
}

void output_write_result(const char *nodeId, UA_StatusCode sc) {
    printf(",\"results\":[");
    output_write_result_item(nodeId, sc);
    printf("],\"error\":null");
}

/* -------------------------------------------------------------------------
 * Browse results
 * ---------------------------------------------------------------------- */

void output_browse_results(const UA_ReferenceDescription *refs, size_t count) {
    printf(",\"results\":[");
    for (size_t i = 0; i < count; i++) {
        const UA_ReferenceDescription *ref = &refs[i];
        if (i > 0) printf(",");
        printf("{\"referenceTypeId\":");
        print_ua_nodeid(&ref->referenceTypeId);
        printf(",\"isForward\":%s", ref->isForward ? "true" : "false");
        printf(",\"nodeId\":");
        print_ua_nodeid(&ref->nodeId.nodeId);
        printf(",\"browseName\":{\"ns\":%" PRIu16 ",\"name\":",
               ref->browseName.namespaceIndex);
        print_ua_string_nn(&ref->browseName.name);
        printf("},\"displayName\":{\"locale\":");
        print_ua_string_nn(&ref->displayName.locale);
        printf(",\"text\":");
        print_ua_string_nn(&ref->displayName.text);
        printf("},\"nodeClass\":\"%s\"}", node_class_name(ref->nodeClass));
    }
    printf("],\"error\":null");
}

/* -------------------------------------------------------------------------
 * NodeId public wrapper
 * ---------------------------------------------------------------------- */

void output_nodeid(const UA_NodeId *nid) {
    print_ua_nodeid(nid);
}

/* -------------------------------------------------------------------------
 * output_variant_to_buf — serialize a UA_Variant to a char buffer
 * ---------------------------------------------------------------------- */

static int format_scalar_to_buf(const void *data, const UA_DataType *type,
                                 char *buf, size_t bufLen) {
    if (!data || !type || bufLen == 0) { if (bufLen > 0) buf[0] = '\0'; return 0; }
    if (type == &UA_TYPES[UA_TYPES_BOOLEAN])
        return snprintf(buf, bufLen, "%s", *(UA_Boolean*)data ? "true" : "false");
    if (type == &UA_TYPES[UA_TYPES_SBYTE])
        return snprintf(buf, bufLen, "%" PRId8,  *(UA_SByte*)data);
    if (type == &UA_TYPES[UA_TYPES_BYTE])
        return snprintf(buf, bufLen, "%" PRIu8,  *(UA_Byte*)data);
    if (type == &UA_TYPES[UA_TYPES_INT16])
        return snprintf(buf, bufLen, "%" PRId16, *(UA_Int16*)data);
    if (type == &UA_TYPES[UA_TYPES_UINT16])
        return snprintf(buf, bufLen, "%" PRIu16, *(UA_UInt16*)data);
    if (type == &UA_TYPES[UA_TYPES_INT32])
        return snprintf(buf, bufLen, "%" PRId32, *(UA_Int32*)data);
    if (type == &UA_TYPES[UA_TYPES_UINT32])
        return snprintf(buf, bufLen, "%" PRIu32, *(UA_UInt32*)data);
    if (type == &UA_TYPES[UA_TYPES_INT64])
        return snprintf(buf, bufLen, "\"%" PRId64 "\"", *(UA_Int64*)data);
    if (type == &UA_TYPES[UA_TYPES_UINT64])
        return snprintf(buf, bufLen, "\"%" PRIu64 "\"", *(UA_UInt64*)data);
    if (type == &UA_TYPES[UA_TYPES_FLOAT]) {
        float v = *(UA_Float*)data;
        return isfinite(v) ? snprintf(buf, bufLen, "%g", (double)v)
                           : snprintf(buf, bufLen, "null");
    }
    if (type == &UA_TYPES[UA_TYPES_DOUBLE]) {
        double v = *(UA_Double*)data;
        return isfinite(v) ? snprintf(buf, bufLen, "%.17g", v)
                           : snprintf(buf, bufLen, "null");
    }
    if (type == &UA_TYPES[UA_TYPES_STRING]) {
        UA_String *s = (UA_String*)data;
        if (!s->data) return snprintf(buf, bufLen, "null");
        size_t out = 0;
        if (out < bufLen) buf[out++] = '"';
        for (size_t i = 0; i < s->length && out + 8 < bufLen; i++) {
            unsigned char c = s->data[i];
            if      (c == '"')  { buf[out++] = '\\'; buf[out++] = '"';  }
            else if (c == '\\') { buf[out++] = '\\'; buf[out++] = '\\'; }
            else if (c == '\n') { buf[out++] = '\\'; buf[out++] = 'n';  }
            else if (c == '\r') { buf[out++] = '\\'; buf[out++] = 'r';  }
            else if (c == '\t') { buf[out++] = '\\'; buf[out++] = 't';  }
            else if (c < 0x20)  { out += (size_t)snprintf(buf + out, bufLen - out,
                                                           "\\u%04x", c); }
            else                  buf[out++] = (char)c;
        }
        if (out < bufLen) buf[out++] = '"';
        if (out < bufLen) buf[out]   = '\0';
        return (int)out;
    }
    return snprintf(buf, bufLen, "null");
}

int output_variant_to_buf(const UA_Variant *var, char *buf, size_t bufLen) {
    if (!var || UA_Variant_isEmpty(var))
        return snprintf(buf, bufLen, "null");
    if (UA_Variant_isScalar(var))
        return format_scalar_to_buf(var->data, var->type, buf, bufLen);

    /* Array */
    size_t out = 0;
    if (out < bufLen) buf[out++] = '[';
    size_t n    = var->arrayLength;
    char  *base = (char*)var->data;
    size_t sz   = var->type->memSize;
    for (size_t i = 0; i < n && out + 32 < bufLen; i++) {
        if (i > 0 && out + 1 < bufLen) buf[out++] = ',';
        char tmp[256];
        int r = format_scalar_to_buf(base + i * sz, var->type, tmp, sizeof(tmp));
        if (r > 0 && out + (size_t)r < bufLen) {
            memcpy(buf + out, tmp, (size_t)r);
            out += (size_t)r;
        }
    }
    if (out < bufLen) buf[out++] = ']';
    if (out < bufLen) buf[out]   = '\0';
    return (int)out;
}

/* -------------------------------------------------------------------------
 * Call result item
 * ---------------------------------------------------------------------- */

void output_call_result(const char *objectNodeId, const char *methodNodeId,
                        UA_StatusCode sc,
                        const UA_Variant *outputs, size_t outputsSize) {
    printf("{\"objectNodeId\":");
    print_json_string(objectNodeId);
    printf(",\"methodNodeId\":");
    print_json_string(methodNodeId);
    printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
    printf(",\"outputArguments\":[");
    for (size_t i = 0; i < outputsSize; i++) {
        if (i > 0) printf(",");
        output_ua_variant_value(&outputs[i]);
    }
    printf("]}");
}
