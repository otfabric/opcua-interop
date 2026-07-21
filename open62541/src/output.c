#include "output.h"

#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Print a JSON-escaped string to stdout. */
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

/* -------------------------------------------------------------------------
 * Status codes
 * ---------------------------------------------------------------------- */

const char *output_status_code_name(UA_StatusCode code) {
    /* Fast-path common codes */
    switch (code) {
        case UA_STATUSCODE_GOOD:                  return "Good";
        case UA_STATUSCODE_BADNOTREADABLE:         return "BadNotReadable";
        case UA_STATUSCODE_BADNOTWRITABLE:         return "BadNotWritable";
        case UA_STATUSCODE_BADNODEIDUNKNOWN:       return "BadNodeIdUnknown";
        case UA_STATUSCODE_BADCONNECTIONREJECTED:  return "BadConnectionRejected";
        case UA_STATUSCODE_BADSESSIONIDINVALID:    return "BadSessionIdInvalid";
        case UA_STATUSCODE_BADTIMEOUT:             return "BadTimeout";
        case UA_STATUSCODE_BADSERVICEUNSUPPORTED:  return "BadServiceUnsupported";
        case UA_STATUSCODE_BADINTERNALERROR:       return "BadInternalError";
        case UA_STATUSCODE_BADOUTOFMEMORY:         return "BadOutOfMemory";
        case UA_STATUSCODE_BADNODECLASSINVALID:    return "BadNodeClassInvalid";
        case UA_STATUSCODE_BADINVALIDARGUMENT:     return "BadInvalidArgument";
        default: break;
    }
    if (UA_StatusCode_isGood(code))        return "Good";
    if (UA_StatusCode_isUncertain(code))   return "Uncertain";
    return "Bad";
}

/* -------------------------------------------------------------------------
 * Timestamp
 * ---------------------------------------------------------------------- */

void output_timestamp(UA_DateTime dt, char *buf, size_t bufLen) {
    if (dt == 0) { snprintf(buf, bufLen, ""); return; }
    UA_DateTimeStruct dts = UA_DateTime_toStruct(dt);
    snprintf(buf, bufLen,
             "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
             dts.year, dts.month, dts.day,
             dts.hour, dts.min,   dts.sec,
             dts.milliSec);
}

/* -------------------------------------------------------------------------
 * Variant printing
 * ---------------------------------------------------------------------- */

static void print_ua_string(const UA_String *s) {
    if (!s || !s->data) { printf("null"); return; }
    /* Treat as UTF-8 */
    char *tmp = malloc(s->length + 1);
    if (!tmp) { printf("null"); return; }
    memcpy(tmp, s->data, s->length);
    tmp[s->length] = '\0';
    print_json_string(tmp);
    free(tmp);
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

static void print_ua_nodeid(const UA_NodeId *nid) {
    switch (nid->identifierType) {
        case UA_NODEIDTYPE_NUMERIC:
            printf("\"ns=%" PRIu16 ";i=%" PRIu32 "\"",
                   nid->namespaceIndex, nid->identifier.numeric);
            break;
        case UA_NODEIDTYPE_STRING: {
            char *tmp = malloc(nid->identifier.string.length + 1);
            if (tmp) {
                memcpy(tmp, nid->identifier.string.data,
                       nid->identifier.string.length);
                tmp[nid->identifier.string.length] = '\0';
                printf("\"ns=%" PRIu16 ";s=", nid->namespaceIndex);
                for (char *p = tmp; *p; p++) {
                    if (*p == '"' || *p == '\\') putchar('\\');
                    putchar(*p);
                }
                printf("\"");
                free(tmp);
            } else {
                printf("null");
            }
            break;
        }
        default:
            printf("\"ns=%" PRIu16 ";...\"", nid->namespaceIndex);
            break;
    }
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
        /* Emit as string to preserve precision in JSON parsers */
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
        printf("\"%s\"", buf);
    } else if (type == &UA_TYPES[UA_TYPES_GUID]) {
        print_ua_guid((UA_Guid*)data);
    } else if (type == &UA_TYPES[UA_TYPES_BYTESTRING]) {
        /* Base64-encode */
        UA_ByteString *bs = (UA_ByteString*)data;
        if (!bs->data) { printf("null"); return; }
        static const char b64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        putchar('"');
        for (size_t i = 0; i < bs->length; i += 3) {
            unsigned char a = bs->data[i];
            unsigned char b = (i+1 < bs->length) ? bs->data[i+1] : 0;
            unsigned char c = (i+2 < bs->length) ? bs->data[i+2] : 0;
            putchar(b64[a >> 2]);
            putchar(b64[((a & 3) << 4) | (b >> 4)]);
            putchar((i+1 < bs->length) ? b64[((b & 0xf) << 2) | (c >> 6)] : '=');
            putchar((i+2 < bs->length) ? b64[c & 0x3f] : '=');
        }
        putchar('"');
    } else if (type == &UA_TYPES[UA_TYPES_XMLELEMENT]) {
        /* XmlElement is a ByteString containing UTF-8 XML */
        UA_XmlElement *xe = (UA_XmlElement*)data;
        if (!xe->data) { printf("null"); return; }
        char *tmp = malloc(xe->length + 1);
        if (tmp) {
            memcpy(tmp, xe->data, xe->length);
            tmp[xe->length] = '\0';
            print_json_string(tmp);
            free(tmp);
        } else { printf("null"); }
    } else if (type == &UA_TYPES[UA_TYPES_NODEID]) {
        print_ua_nodeid((UA_NodeId*)data);
    } else if (type == &UA_TYPES[UA_TYPES_QUALIFIEDNAME]) {
        UA_QualifiedName *qn = (UA_QualifiedName*)data;
        char *tmp = malloc(qn->name.length + 1);
        if (tmp) {
            memcpy(tmp, qn->name.data, qn->name.length);
            tmp[qn->name.length] = '\0';
            printf("\"%" PRIu16 ":", qn->namespaceIndex);
            for (char *p = tmp; *p; p++) {
                if (*p == '"' || *p == '\\') putchar('\\');
                putchar(*p);
            }
            printf("\"");
            free(tmp);
        } else { printf("null"); }
    } else if (type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]) {
        UA_LocalizedText *lt = (UA_LocalizedText*)data;
        char *txt = malloc(lt->text.length + 1);
        char *loc = malloc(lt->locale.length + 1);
        if (txt && loc) {
            memcpy(txt, lt->text.data,   lt->text.length);
            memcpy(loc, lt->locale.data, lt->locale.length);
            txt[lt->text.length]   = '\0';
            loc[lt->locale.length] = '\0';
            printf("{\"locale\":");
            print_json_string(loc);
            printf(",\"text\":");
            print_json_string(txt);
            printf("}");
        } else { printf("null"); }
        free(txt); free(loc);
    } else if (type == &UA_TYPES[UA_TYPES_STATUSCODE]) {
        UA_StatusCode sc = *(UA_StatusCode*)data;
        printf("{\"code\":%" PRIu32 ",\"name\":\"%s\"}",
               (uint32_t)sc, output_status_code_name(sc));
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
 * Top-level output primitives
 * ---------------------------------------------------------------------- */

void output_begin(const char *op) {
    printf("{\"operation\":");
    print_json_string(op);
}

void output_success(int ok) {
    printf(",\"success\":%s", ok ? "true" : "false");
}

void output_service_result(UA_StatusCode code) {
    printf(",\"serviceResult\":\"%s\"", output_status_code_name(code));
}

void output_end(void) {
    printf("}\n");
    fflush(stdout);
}

/* -------------------------------------------------------------------------
 * Compound helpers
 * ---------------------------------------------------------------------- */

void output_read_result(const char *nodeId, UA_StatusCode sc,
                        const char *dataType, const UA_Variant *val,
                        UA_DateTime sourceTs) {
    char tsbuf[64];
    output_timestamp(sourceTs, tsbuf, sizeof(tsbuf));
    printf(",\"results\":[{\"nodeId\":");
    print_json_string(nodeId);
    printf(",\"statusCode\":\"%s\"", output_status_code_name(sc));
    printf(",\"dataType\":");
    print_json_string(dataType);
    if (val) output_ua_variant_field("value", val);
    else     printf(",\"value\":null");
    if (tsbuf[0]) {
        printf(",\"sourceTimestamp\":\"%s\"", tsbuf);
    }
    printf("}]");
}

void output_browse_results(UA_BrowseResult *result) {
    printf(",\"references\":[");
    if (result) {
        for (size_t i = 0; i < result->referencesSize; i++) {
            UA_ReferenceDescription *ref = &result->references[i];
            if (i > 0) printf(",");
            printf("{");
            printf("\"referenceTypeId\":");
            print_ua_nodeid(&ref->referenceTypeId);
            printf(",\"isForward\":%s", ref->isForward ? "true" : "false");
            printf(",\"nodeId\":");
            print_ua_nodeid(&ref->nodeId.nodeId);
            printf(",\"browseName\":\"%.*s\"",
                   (int)ref->browseName.name.length,
                   ref->browseName.name.data);
            printf(",\"displayName\":\"%.*s\"",
                   (int)ref->displayName.text.length,
                   ref->displayName.text.data);
            printf(",\"nodeClass\":%d", (int)ref->nodeClass);
            printf("}");
        }
    }
    printf("]");
}
