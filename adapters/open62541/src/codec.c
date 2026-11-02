/*
 * `client codec` — OPC UA JSON / XML DataEncoding of built-in values.
 *
 *   codec encode --format json|xml --type <Type[[]]> --value <literal>
 *                [--dimensions d1,d2,...]
 *   codec encode --format json|xml --endpoint <url> --node <nodeId>
 *   codec decode --format json|xml --type <BuiltInType|Variant|DataValue>
 *                [--input <file> | --document <text>]      (default: stdin)
 *
 * Encoding is done by open62541's UA_encodeJson / UA_encodeXml, decoding by
 * UA_decodeJson / UA_decodeXml. Documents are embedded in the result as JSON
 * strings (byte-exact); the OPC UA Binary encoding of the same value is added
 * as Base64 so a consumer can compare bit-exactly.
 *
 * open62541 v1.5.9 implements the OPC UA 1.05 JSON encoding ("UaType" /
 * "Value" / "Dimensions"); its `useReversible` option has no effect in that
 * encoder, so there is a single JSON mode ("compact").
 */

#define _GNU_SOURCE

#include "client_internal.h"
#include "output.h"
#include "values.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OP "codec"

typedef enum { FMT_JSON, FMT_XML } Format;

static int usage_error(const char *msg) {
    cli_emit_failure(OP, UA_STATUSCODE_BADINVALIDARGUMENT, "input", msg);
    return 2;
}

/*
 * What open62541 v1.5.9's XML codec does not implement. The library reports
 * these by OR-ing status codes together (yielding unrelated names such as
 * BadContentFilterInvalid), so the known gaps are answered here with a clean
 * BadNotImplemented.
 *   encode: DataValue, DiagnosticInfo, matrices (ArrayDimensions)
 *   decode: DataValue, DiagnosticInfo, XmlElement
 */
static int xml_unsupported_type(const UA_DataType *type, int decoding) {
    if (type == &UA_TYPES[UA_TYPES_DATAVALUE] ||
        type == &UA_TYPES[UA_TYPES_DIAGNOSTICINFO])
        return 1;
    return decoding && type == &UA_TYPES[UA_TYPES_XMLELEMENT];
}

static int xml_encode_unsupported(const void *src, const UA_DataType *type) {
    if (xml_unsupported_type(type, 0)) return 1;
    if (type == &UA_TYPES[UA_TYPES_VARIANT]) {
        const UA_Variant *v = (const UA_Variant *)src;
        if (v->arrayDimensionsSize > 1) return 1;
        if (v->type && xml_unsupported_type(v->type, 0)) return 1;
    }
    return 0;
}

static UA_StatusCode encode_doc(Format fmt, const void *src, const UA_DataType *type,
                                UA_ByteString *out) {
    UA_ByteString_init(out);
    if (fmt == FMT_XML && xml_encode_unsupported(src, type))
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
#ifdef UA_ENABLE_JSON_ENCODING
    if (fmt == FMT_JSON) return UA_encodeJson(src, type, out, NULL);
#endif
#ifdef UA_ENABLE_XML_ENCODING
    if (fmt == FMT_XML) return UA_encodeXml(src, type, out, NULL);
#endif
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

static UA_StatusCode decode_doc(Format fmt, const UA_ByteString *doc, void *dst,
                                const UA_DataType *type) {
    if (fmt == FMT_XML && xml_unsupported_type(type, 1))
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
#ifdef UA_ENABLE_JSON_ENCODING
    if (fmt == FMT_JSON) return UA_decodeJson(doc, dst, type, NULL);
#endif
#ifdef UA_ENABLE_XML_ENCODING
    if (fmt == FMT_XML) return UA_decodeXml(doc, dst, type, NULL);
#endif
    return UA_STATUSCODE_BADNOTSUPPORTED;
}

/* Print ,"key":"<document>" or ,"key":null on encode failure. Returns the
 * encode status. */
static UA_StatusCode print_doc_field(const char *key, int *first, Format fmt,
                                     const void *src, const UA_DataType *type) {
    UA_ByteString doc;
    UA_StatusCode sc = encode_doc(fmt, src, type, &doc);
    printf("%s\"%s\":", *first ? "" : ",", key);
    *first = 0;
    if (sc == UA_STATUSCODE_GOOD)
        output_json_string_len(doc.data, doc.length);
    else
        printf("null");
    UA_ByteString_clear(&doc);
    return sc;
}

static UA_StatusCode print_binary_field(const char *key, int *first,
                                        const void *src, const UA_DataType *type) {
    UA_ByteString bin = UA_BYTESTRING_NULL;
    UA_StatusCode sc = UA_encodeBinary(src, type, &bin, NULL);
    printf("%s\"%s\":", *first ? "" : ",", key);
    *first = 0;
    if (sc == UA_STATUSCODE_GOOD) {
        char *b64 = value_b64_encode(bin.data ? bin.data : (const unsigned char *)"", bin.length);
        printf("\"%s\"", b64 ? b64 : "");
        free(b64);
    } else {
        printf("null");
    }
    UA_ByteString_clear(&bin);
    return sc;
}

/* ,"dataType":..,"builtInType":..,"valueRank":..[,"arrayDimensions":[..]],"value":.. */
static void print_variant_fields(const UA_Variant *v) {
    if (UA_Variant_isEmpty(v)) {
        printf(",\"dataType\":\"Null\",\"builtInType\":0,\"valueRank\":-1,\"value\":null");
        return;
    }
    printf(",\"dataType\":");
    output_json_string(value_type_name(v->type));
    printf(",\"builtInType\":%d", ua_type_to_builtin_id(v->type));
    if (UA_Variant_isScalar(v)) {
        printf(",\"valueRank\":-1");
    } else if (v->arrayDimensionsSize > 1) {
        printf(",\"valueRank\":%zu,\"arrayDimensions\":[", v->arrayDimensionsSize);
        for (size_t i = 0; i < v->arrayDimensionsSize; i++)
            printf("%s%" PRIu32, i ? "," : "", v->arrayDimensions[i]);
        printf("]");
    } else {
        printf(",\"valueRank\":1");
    }
    output_ua_variant_field("value", v);
}

static int parse_format(int argc, char **argv, Format *fmt, const char **name) {
    const char *f = cli_find_arg(argc, argv, "--format");
    if (!f) f = cli_find_arg(argc, argv, "--decode"); /* short form: --decode json|xml */
    if (!f) return -1;
    if (strcmp(f, "json") == 0) { *fmt = FMT_JSON; *name = "json"; return 0; }
    if (strcmp(f, "xml") == 0)  { *fmt = FMT_XML;  *name = "xml";  return 0; }
    return -1;
}

/* open62541 has one JSON flavour. Returns 0 when the requested mode is it. */
static int check_json_mode(int argc, char **argv) {
    const char *m = cli_find_arg(argc, argv, "--json-mode");
    return (!m || strcmp(m, "compact") == 0) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * encode
 * ---------------------------------------------------------------------- */

static int codec_encode(int argc, char **argv) {
    Format fmt; const char *fmtName = "";
    if (parse_format(argc, argv, &fmt, &fmtName) != 0)
        return usage_error("codec encode: --format json|xml is required");
    if (check_json_mode(argc, argv) != 0)
        return usage_error("--json-mode: open62541 only implements the OPC UA 1.05 "
                           "\"compact\" JSON encoding");

    const char *nodeStr  = cli_find_arg(argc, argv, "--node");
    const char *typeStr  = cli_find_arg(argc, argv, "--type");
    const char *valStr   = cli_find_arg(argc, argv, "--value");
    const char *dims     = cli_find_arg(argc, argv, "--dimensions");
    const char *endpoint = cli_find_arg(argc, argv, "--endpoint");

    UA_DataValue dv;
    UA_DataValue_init(&dv);
    UA_NodeId nodeId = UA_NODEID_NULL;
    int fromNode = 0;

    if (nodeStr) {
        if (typeStr || valStr)
            return usage_error("codec encode: use either --node or --type/--value");
        if (!endpoint)
            return usage_error("codec encode --node requires --endpoint");
        if (cli_validate_nodeid(nodeStr) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
            return usage_error(msg);
        }
        int exit_code = 3;
        UA_Client *client = cli_make_client(endpoint, 5000, OP, &exit_code);
        if (!client) return exit_code;
        if (strncmp(nodeStr, "nsu=", 4) == 0) {
            if (cli_resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
                UA_Client_disconnect(client);
                UA_Client_delete(client);
                cli_emit_failure(OP, (UA_StatusCode)0x80530000U, "input",
                                 "unknown namespace URI in --node");
                return 2;
            }
        } else {
            nodeId = cli_parse_nodeid_local(nodeStr);
        }

        UA_ReadValueId rvi;
        UA_ReadValueId_init(&rvi);
        rvi.nodeId = nodeId;
        rvi.attributeId = UA_ATTRIBUTEID_VALUE;
        UA_ReadRequest req;
        UA_ReadRequest_init(&req);
        req.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
        req.nodesToRead = &rvi;
        req.nodesToReadSize = 1;
        UA_ReadResponse resp = UA_Client_Service_read(client, req);
        UA_StatusCode sc = resp.responseHeader.serviceResult;
        if (sc == UA_STATUSCODE_GOOD && resp.resultsSize != 1)
            sc = UA_STATUSCODE_BADUNEXPECTEDERROR;
        if (sc == UA_STATUSCODE_GOOD) {
            dv = resp.results[0];
            UA_DataValue_init(&resp.results[0]);
            if (dv.hasStatus && UA_StatusCode_isBad(dv.status)) sc = dv.status;
        }
        UA_ReadResponse_clear(&resp);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        if (sc != UA_STATUSCODE_GOOD) {
            UA_DataValue_clear(&dv);
            UA_NodeId_clear(&nodeId);
            cli_emit_failure(OP, sc, "service", "Read of --node failed");
            return sc == UA_STATUSCODE_BADTIMEOUT ? 7 : 4;
        }
        fromNode = 1;
    } else {
        if (!typeStr || !valStr)
            return usage_error("codec encode: --type and --value (or --node) are required");
        char errBuf[256];
        if (value_parse(typeStr, valStr, dims, &dv.value, errBuf, sizeof(errBuf)) != 0)
            return usage_error(errBuf);
        dv.hasValue = true;

        /* Optional DataValue members for locally constructed values. */
        const char *v;
        if ((v = cli_find_arg(argc, argv, "--status")) != NULL) {
            dv.status = (UA_StatusCode)strtoul(v, NULL, 0);
            dv.hasStatus = true;
        }
        if ((v = cli_find_arg(argc, argv, "--source-timestamp")) != NULL) {
            if (value_parse_datetime(v, &dv.sourceTimestamp) != 0) {
                UA_DataValue_clear(&dv);
                return usage_error("invalid --source-timestamp (want RFC 3339 UTC)");
            }
            dv.hasSourceTimestamp = true;
        }
        if ((v = cli_find_arg(argc, argv, "--server-timestamp")) != NULL) {
            if (value_parse_datetime(v, &dv.serverTimestamp) != 0) {
                UA_DataValue_clear(&dv);
                return usage_error("invalid --server-timestamp (want RFC 3339 UTC)");
            }
            dv.hasServerTimestamp = true;
        }
        if ((v = cli_find_arg(argc, argv, "--source-picoseconds")) != NULL) {
            dv.sourcePicoseconds = (UA_UInt16)atoi(v);
            dv.hasSourcePicoseconds = true;
        }
        if ((v = cli_find_arg(argc, argv, "--server-picoseconds")) != NULL) {
            dv.serverPicoseconds = (UA_UInt16)atoi(v);
            dv.hasServerPicoseconds = true;
        }
    }

    /* The bare built-in encoding only exists for scalars. */
    int scalar = !UA_Variant_isEmpty(&dv.value) && UA_Variant_isScalar(&dv.value);

    /* Encode first so the envelope can carry the status. The Variant
     * document is the primary result; the bare value and the DataValue are
     * reported individually (open62541's XML encoder, for one, implements
     * neither DataValue nor matrices). */
    UA_ByteString probe;
    UA_StatusCode scVariant = encode_doc(fmt, &dv.value, &UA_TYPES[UA_TYPES_VARIANT], &probe);
    UA_ByteString_clear(&probe);
    UA_StatusCode scDataValue = encode_doc(fmt, &dv, &UA_TYPES[UA_TYPES_DATAVALUE], &probe);
    UA_ByteString_clear(&probe);
    UA_StatusCode scValue = UA_STATUSCODE_GOOD;
    if (scalar) {
        scValue = encode_doc(fmt, dv.value.data, dv.value.type, &probe);
        UA_ByteString_clear(&probe);
    }
    UA_StatusCode sc = scVariant;
    int ok = (sc == UA_STATUSCODE_GOOD);

    output_begin("open62541", OP);
    output_success(ok);
    output_service_result(sc);
    output_open_results();
    printf("{\"action\":\"encode\",\"format\":\"%s\"", fmtName);
    if (fmt == FMT_JSON) printf(",\"jsonMode\":\"compact\"");
    printf(",\"source\":\"%s\"", fromNode ? "node" : "literal");
    if (fromNode) {
        printf(",\"nodeId\":");
        output_nodeid(&nodeId);
    }
    print_variant_fields(&dv.value);
    printf(",\"dataValue\":");
    output_ua_datavalue(&dv);

    int first = 1;
    printf(",\"encoded\":{");
    if (scalar) print_doc_field("value", &first, fmt, dv.value.data, dv.value.type);
    print_doc_field("variant", &first, fmt, &dv.value, &UA_TYPES[UA_TYPES_VARIANT]);
    print_doc_field("dataValue", &first, fmt, &dv, &UA_TYPES[UA_TYPES_DATAVALUE]);
    printf("}");

    printf(",\"statusCodes\":{");
    if (scalar) { cli_print_status("value", scValue); printf(","); }
    cli_print_status("variant", scVariant);
    printf(",");
    cli_print_status("dataValue", scDataValue);
    printf("}");

    first = 1;
    printf(",\"binary\":{");
    if (scalar) print_binary_field("value", &first, dv.value.data, dv.value.type);
    print_binary_field("variant", &first, &dv.value, &UA_TYPES[UA_TYPES_VARIANT]);
    print_binary_field("dataValue", &first, &dv, &UA_TYPES[UA_TYPES_DATAVALUE]);
    printf("}}");
    output_close_results();
    if (ok)
        output_null_error();
    else
        printf(",\"error\":{\"category\":\"service\",\"message\":\"encoding failed\"}");
    output_end();

    UA_DataValue_clear(&dv);
    if (fromNode) UA_NodeId_clear(&nodeId);
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * decode
 * ---------------------------------------------------------------------- */

static int read_all(FILE *f, UA_ByteString *out) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return -1;
    for (;;) {
        if (len == cap) {
            cap *= 2;
            unsigned char *tmp = (unsigned char *)realloc(buf, cap);
            if (!tmp) { free(buf); return -1; }
            buf = tmp;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    /* Trailing whitespace (the newline of a shell pipe) is not part of the
     * document. */
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' '  || buf[len - 1] == '\t'))
        len--;
    out->data = buf;
    out->length = len;
    return 0;
}

static int codec_decode(int argc, char **argv) {
    Format fmt; const char *fmtName = "";
    if (parse_format(argc, argv, &fmt, &fmtName) != 0)
        return usage_error("codec decode: --format json|xml is required");
    if (check_json_mode(argc, argv) != 0)
        return usage_error("--json-mode: open62541 only implements the OPC UA 1.05 "
                           "\"compact\" JSON encoding");

    const char *typeStr = cli_find_arg(argc, argv, "--type");
    if (!typeStr)
        return usage_error("codec decode: --type <BuiltInType|Variant|DataValue> is required");
    const UA_DataType *type = value_builtin_type(typeStr);
    if (!type) {
        char msg[256];
        snprintf(msg, sizeof(msg), "unknown --type '%s' (arrays are decoded as Variant)", typeStr);
        return usage_error(msg);
    }

    UA_ByteString doc = UA_BYTESTRING_NULL;
    const char *inlineDoc = cli_find_arg(argc, argv, "--document");
    const char *inputPath = cli_find_arg(argc, argv, "--input");
    if (inlineDoc) {
        doc.length = strlen(inlineDoc);
        doc.data = (UA_Byte *)malloc(doc.length ? doc.length : 1);
        if (!doc.data) return usage_error("out of memory");
        memcpy(doc.data, inlineDoc, doc.length);
    } else {
        FILE *f = inputPath ? fopen(inputPath, "rb") : stdin;
        if (!f) return usage_error("cannot open --input file");
        int rc = read_all(f, &doc);
        if (inputPath) fclose(f);
        if (rc != 0) return usage_error("cannot read the input document");
    }
    if (doc.length == 0) {
        free(doc.data);
        return usage_error("empty input document (stdin, --input or --document)");
    }

    void *val = UA_new(type);
    if (!val) { free(doc.data); return usage_error("out of memory"); }
    UA_StatusCode sc = decode_doc(fmt, &doc, val, type);
    free(doc.data);
    int ok = (sc == UA_STATUSCODE_GOOD);

    output_begin("open62541", OP);
    output_success(ok);
    output_service_result(sc);
    output_open_results();
    printf("{\"action\":\"decode\",\"format\":\"%s\"", fmtName);
    if (fmt == FMT_JSON) printf(",\"jsonMode\":\"compact\"");
    printf(",\"type\":");
    output_json_string(typeStr);
    printf(",");
    cli_print_status("statusCode", sc);
    if (ok) {
        if (type == &UA_TYPES[UA_TYPES_VARIANT]) {
            print_variant_fields((const UA_Variant *)val);
        } else if (type == &UA_TYPES[UA_TYPES_DATAVALUE]) {
            const UA_DataValue *dv = (const UA_DataValue *)val;
            print_variant_fields(&dv->value);
            printf(",\"dataValue\":");
            output_ua_datavalue(dv);
        } else {
            printf(",\"dataType\":");
            output_json_string(value_type_name(type));
            printf(",\"builtInType\":%d,\"valueRank\":-1,\"value\":",
                   ua_type_to_builtin_id(type));
            output_ua_scalar(val, type);
        }
        int first = 0;
        print_binary_field("binary", &first, val, type);
        print_doc_field("reencoded", &first, fmt, val, type);
    }
    printf("}");
    output_close_results();
    if (ok)
        output_null_error();
    else
        printf(",\"error\":{\"category\":\"service\",\"message\":\"decoding failed\"}");
    output_end();

    if (ok) UA_delete(val, type); else UA_free(val);
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * short form: codec --endpoint <url> --node <id> [--node ...]
 *
 * Reads every node and reports the Variant in both encodings side by side
 * ("json" / "xml"), plus the DataValue ("dataValueJson" / "dataValueXml").
 * A document the stack cannot produce is null.
 * ---------------------------------------------------------------------- */

#define CODEC_MAX_NODES 64

static void print_doc_or_null(const char *key, Format fmt, const void *src,
                              const UA_DataType *type) {
    int first = 0;
    print_doc_field(key, &first, fmt, src, type);
}

static int codec_nodes(int argc, char **argv) {
    const char *endpoint = cli_find_arg(argc, argv, "--endpoint");
    const char *nodes[CODEC_MAX_NODES];
    int n = 0;
    for (int i = 0; i < argc - 1 && n < CODEC_MAX_NODES; i++)
        if (strcmp(argv[i], "--node") == 0) nodes[n++] = argv[i + 1];
    if (!endpoint || n == 0)
        return usage_error("usage: codec --endpoint <url> --node <nodeId> [--node ...]");
    for (int i = 0; i < n; i++) {
        if (cli_validate_nodeid(nodes[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodes[i]);
            return usage_error(msg);
        }
    }

    int exit_code = 3;
    UA_Client *client = cli_make_client(endpoint, 5000, OP, &exit_code);
    if (!client) return exit_code;

    UA_ReadValueId rvis[CODEC_MAX_NODES];
    for (int i = 0; i < n; i++) {
        UA_ReadValueId_init(&rvis[i]);
        rvis[i].attributeId = UA_ATTRIBUTEID_VALUE;
        int bad = 0;
        if (strncmp(nodes[i], "nsu=", 4) == 0)
            bad = cli_resolve_nsu_nodeid(client, nodes[i], &rvis[i].nodeId) != 0;
        else
            rvis[i].nodeId = cli_parse_nodeid_local(nodes[i]);
        if (bad) {
            for (int j = 0; j < i; j++) UA_NodeId_clear(&rvis[j].nodeId);
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            cli_emit_failure(OP, (UA_StatusCode)0x80530000U, "input",
                             "unknown namespace URI in --node");
            return 2;
        }
    }

    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;
    req.nodesToRead = rvis;
    req.nodesToReadSize = (size_t)n;
    UA_ReadResponse resp = UA_Client_Service_read(client, req);
    UA_StatusCode sc = resp.responseHeader.serviceResult;
    if (sc == UA_STATUSCODE_GOOD && resp.resultsSize != (size_t)n)
        sc = UA_STATUSCODE_BADUNEXPECTEDERROR;
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (sc != UA_STATUSCODE_GOOD) {
        for (int i = 0; i < n; i++) UA_NodeId_clear(&rvis[i].nodeId);
        UA_ReadResponse_clear(&resp);
        cli_emit_failure(OP, sc, "service", "Read failed");
        return sc == UA_STATUSCODE_BADTIMEOUT ? 7 : 4;
    }

    int ok = 1;
    UA_StatusCode emit = UA_STATUSCODE_GOOD;
    for (int i = 0; i < n; i++) {
        UA_DataValue *dv = &resp.results[i];
        UA_StatusCode item = dv->hasStatus ? dv->status : UA_STATUSCODE_GOOD;
        UA_ByteString probe;
        UA_StatusCode enc = UA_StatusCode_isBad(item)
            ? item : encode_doc(FMT_JSON, &dv->value, &UA_TYPES[UA_TYPES_VARIANT], &probe);
        if (!UA_StatusCode_isBad(item)) UA_ByteString_clear(&probe);
        if (enc != UA_STATUSCODE_GOOD) {
            ok = 0;
            if (emit == UA_STATUSCODE_GOOD) emit = enc;
        }
    }

    output_begin("open62541", OP);
    output_success(ok);
    output_service_result(emit);
    output_open_results();
    for (int i = 0; i < n; i++) {
        UA_DataValue *dv = &resp.results[i];
        UA_StatusCode item = dv->hasStatus ? dv->status : UA_STATUSCODE_GOOD;
        if (i > 0) printf(",");
        printf("{\"nodeId\":");
        output_nodeid(&rvis[i].nodeId);
        printf(",");
        cli_print_status("statusCode", item);
        if (!UA_StatusCode_isBad(item)) {
            print_variant_fields(&dv->value);
            print_doc_or_null("json", FMT_JSON, &dv->value, &UA_TYPES[UA_TYPES_VARIANT]);
            print_doc_or_null("xml", FMT_XML, &dv->value, &UA_TYPES[UA_TYPES_VARIANT]);
            print_doc_or_null("dataValueJson", FMT_JSON, dv, &UA_TYPES[UA_TYPES_DATAVALUE]);
            print_doc_or_null("dataValueXml", FMT_XML, dv, &UA_TYPES[UA_TYPES_DATAVALUE]);
            int first = 0;
            print_binary_field("binary", &first, &dv->value, &UA_TYPES[UA_TYPES_VARIANT]);
            print_binary_field("dataValueBinary", &first, dv, &UA_TYPES[UA_TYPES_DATAVALUE]);
        } else {
            printf(",\"json\":null,\"xml\":null");
        }
        printf("}");
    }
    output_close_results();
    if (ok)
        output_null_error();
    else
        printf(",\"error\":{\"category\":\"service\",\"message\":\"read or encoding failed\"}");
    output_end();

    for (int i = 0; i < n; i++) UA_NodeId_clear(&rvis[i].nodeId);
    UA_ReadResponse_clear(&resp);
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * dispatch
 * ---------------------------------------------------------------------- */

int cmd_codec(int argc, char **argv) {
    /* argv[0] = "codec", argv[1] = encode | decode | first flag (short form) */
    static const char *usage =
        "usage: codec encode --format json|xml (--type <T> --value <v> | --endpoint <url> --node <id>)"
        " | codec decode --format json|xml --type <T>"
        " | codec --endpoint <url> --node <id> [--node ...]"
        " | codec --decode json|xml --type <T>"
        " | codec pubsub-uadp-encode|pubsub-uadp-decode|pubsub-json-encode|pubsub-json-decode"
        " [--document <text>|--input <file>] [--metadata <json>|--metadata-file <file>]";
    if (argc < 2) return usage_error(usage);
#ifdef UA_ENABLE_PUBSUB
    /* PubSub NetworkMessage mappings (pubsub_codec.c) */
    if (strncmp(argv[1], "pubsub-", 7) == 0) return cmd_codec_pubsub(argc - 1, argv + 1);
#endif
    if (strcmp(argv[1], "encode") == 0) return codec_encode(argc - 1, argv + 1);
    if (strcmp(argv[1], "decode") == 0) return codec_decode(argc - 1, argv + 1);
    if (cli_find_arg(argc, argv, "--decode")) return codec_decode(argc, argv);
    if (cli_find_arg(argc, argv, "--node"))   return codec_nodes(argc, argv);
    return usage_error(usage);
}
