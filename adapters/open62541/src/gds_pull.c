/*
 * `client gds-pull` (CLIENT_CONTRACT §16.2): the GDS pull model of Part 12
 * §6.6 / §7.9 against the Directory object of a Global Discovery Server.
 * open62541 v1.5.9 has no GDS client: the Directory methods are plain
 * UA_Client_call requests on the standard NodeIds of the GDS namespace (its
 * index from the server's NamespaceArray), ApplicationRecordDataType (a
 * GDS-namespace structure the stack does not know) is encoded and decoded
 * here, and the PKCS #10 request is made with OpenSSL.
 */
#define _GNU_SOURCE

#include "client_internal.h"
#include "part12.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* The GDS namespace (Part 12 Annex A). */
#define GDS_NAMESPACE "http://opcfoundation.org/UA/GDS/"
/* Directory (ns=GDS) and its methods. */
#define GDS_DIRECTORY                  141
#define GDS_FIND_APPLICATIONS          143
#define GDS_REGISTER_APPLICATION       146
#define GDS_UNREGISTER_APPLICATION     149
#define GDS_START_NEW_KEY_PAIR_REQUEST 154
#define GDS_START_SIGNING_REQUEST      157
#define GDS_FINISH_REQUEST             163
#define GDS_CHECK_REVOCATION_STATUS    177
#define GDS_GET_TRUST_LIST             204
#define GDS_GET_CERTIFICATE_STATUS     225
#define GDS_GET_CERTIFICATE_GROUPS     508
#define GDS_REVOKE_CERTIFICATE         15005
/* Directory.CertificateGroups.DefaultApplicationGroup (ns=GDS). */
#define GDS_DEFAULT_APPLICATION_GROUP  615
/* ApplicationRecordDataType_Encoding_DefaultBinary (ns=GDS). */
#define GDS_APPLICATION_RECORD_BINARY  134
/* RsaSha256ApplicationCertificateType, EccNistP256ApplicationCertificateType (ns=0). */
#define GDS_RSA_SHA256_TYPE            12560
#define GDS_NIST_P256_TYPE             23538
#define GDS_FINISH_POLL_MS             200

#define GDS_PRODUCT_URI "urn:opcua-interop:open62541"

typedef struct {
    const char *appUri;
    char *appName;
    UA_Int32 appType;      /* Server 0, Client 1, ClientAndServer 2 */
    const char **urls;
    size_t nUrls;
    int csr;               /* StartSigningRequest, else StartNewKeyPairRequest */
    int nistP256;
    int revoke, unregister;
    unsigned long finishTimeoutMs;
} GdsArgs;

static void gds_args_clear(GdsArgs *a) {
    free(a->appName);
    free((void *)a->urls);
    memset(a, 0, sizeof(*a));
}

/* The record name: the last ':' / '/' segment of the app uri. */
static char *gds_app_name(const char *uri) {
    const char *last = uri;
    for (const char *p = uri; *p; p++)
        if (*p == ':' || *p == '/') last = p + 1;
    return strdup(*last ? last : "opcua-interop gds-pull app");
}

static int gds_parse(int argc, char **argv, GdsArgs *a, char *msg, size_t msgLen) {
    memset(a, 0, sizeof(*a));
    if (!cli_find_arg(argc, argv, "--endpoint")) {
        snprintf(msg, msgLen, "--endpoint is required");
        return -1;
    }
    a->appUri = cli_find_arg(argc, argv, "--app-uri");
    if (!a->appUri) a->appUri = "urn:opcua-interop:gds-pull:app";
    const char *t = cli_find_arg(argc, argv, "--app-type");
    if (!t || strcmp(t, "Server") == 0) a->appType = 0;
    else if (strcmp(t, "Client") == 0) a->appType = 1;
    else if (strcmp(t, "ClientAndServer") == 0) a->appType = 2;
    else {
        snprintf(msg, msgLen, "invalid --app-type %s (Server|Client|ClientAndServer)", t);
        return -1;
    }
    const char *r = cli_find_arg(argc, argv, "--request");
    if (!r || strcmp(r, "csr") == 0) a->csr = 1;
    else if (strcmp(r, "new-key-pair") == 0) a->csr = 0;
    else {
        snprintf(msg, msgLen, "invalid --request %s (csr|new-key-pair)", r);
        return -1;
    }
    const char *c = cli_find_arg(argc, argv, "--certificate-type");
    if (!c || strcmp(c, "RsaSha256") == 0) a->nistP256 = 0;
    else if (strcmp(c, "NistP256") == 0) a->nistP256 = 1;
    else {
        snprintf(msg, msgLen, "invalid --certificate-type %s (RsaSha256|NistP256)", c);
        return -1;
    }
    a->finishTimeoutMs = 30000;
    const char *ft = cli_find_arg(argc, argv, "--finish-timeout-ms");
    if (ft && p12_parse_uint(ft, 0xffffffffUL, &a->finishTimeoutMs) != 0) {
        snprintf(msg, msgLen, "invalid --finish-timeout-ms %s", ft);
        return -1;
    }
    a->urls = p12_all_values(argc, argv, "--discovery-url", &a->nUrls);
    a->appName = gds_app_name(a->appUri);
    if (!a->urls || !a->appName) {
        snprintf(msg, msgLen, "out of memory");
        return -1;
    }
    a->revoke = p12_has_flag(argc, argv, "--revoke");
    a->unregister = p12_has_flag(argc, argv, "--unregister");
    return 0;
}

/* -------------------------------------------------------------------------
 * ApplicationRecordDataType (Part 12 §6.6.2)
 * ---------------------------------------------------------------------- */

static int gds_append(UA_ByteString *buf, const void *p, const UA_DataType *type) {
    UA_ByteString enc = UA_BYTESTRING_NULL;
    if (UA_encodeBinary(p, type, &enc, NULL) != UA_STATUSCODE_GOOD) return -1;
    UA_Byte *nd = (UA_Byte *)UA_realloc(buf->data, buf->length + enc.length);
    if (!nd) { UA_ByteString_clear(&enc); return -1; }
    memcpy(nd + buf->length, enc.data, enc.length);
    buf->data = nd;
    buf->length += enc.length;
    UA_ByteString_clear(&enc);
    return 0;
}

static int gds_append_string(UA_ByteString *buf, const char *s) {
    UA_String str = UA_STRING((char *)(uintptr_t)s);
    return gds_append(buf, &str, &UA_TYPES[UA_TYPES_STRING]);
}

/* The binary body of an ApplicationRecordDataType with a null ApplicationId:
 * ApplicationId, ApplicationUri, ApplicationType, ApplicationNames,
 * ProductUri, DiscoveryUrls, ServerCapabilities. */
static int gds_encode_record(const GdsArgs *a, UA_ByteString *out) {
    UA_ByteString_init(out);
    int client = a->appType == 1;
    UA_NodeId nullId = UA_NODEID_NULL;
    UA_Int32 one = 1;
    UA_LocalizedText name = UA_LOCALIZEDTEXT("en-US", a->appName);
    static const char *defaultUrl = "opc.tcp://localhost:4850";
    const char *const *urls = a->nUrls ? a->urls : &defaultUrl;
    UA_Int32 nUrls = client ? 0 : (UA_Int32)(a->nUrls ? a->nUrls : 1);
    UA_Int32 nCaps = client ? 0 : 1;
    int rc = 0;
    rc |= gds_append(out, &nullId, &UA_TYPES[UA_TYPES_NODEID]);
    rc |= gds_append_string(out, a->appUri);
    rc |= gds_append(out, &a->appType, &UA_TYPES[UA_TYPES_INT32]);
    rc |= gds_append(out, &one, &UA_TYPES[UA_TYPES_INT32]);
    rc |= gds_append(out, &name, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    rc |= gds_append_string(out, GDS_PRODUCT_URI);
    rc |= gds_append(out, &nUrls, &UA_TYPES[UA_TYPES_INT32]);
    for (UA_Int32 i = 0; i < nUrls; i++) rc |= gds_append_string(out, urls[i]);
    rc |= gds_append(out, &nCaps, &UA_TYPES[UA_TYPES_INT32]);
    if (nCaps) rc |= gds_append_string(out, "NA");
    if (rc) UA_ByteString_clear(out);
    return rc ? -1 : 0;
}

/* The ApplicationId (first field) of an ApplicationRecordDataType element of
 * a FindApplications output (an ExtensionObject the stack cannot decode, or
 * a value it decoded). 0 on success. */
static int gds_record_id(const UA_Variant *v, size_t i, UA_NodeId *out) {
    UA_NodeId_init(out);
    const void *elem = (const UA_Byte *)v->data + i * v->type->memSize;
    UA_ByteString body = UA_BYTESTRING_NULL;
    int rc;
    if (v->type == &UA_TYPES[UA_TYPES_EXTENSIONOBJECT])
        rc = p12_extension_body((const UA_ExtensionObject *)elem, &body);
    else
        rc = UA_encodeBinary(elem, v->type, &body, NULL) == UA_STATUSCODE_GOOD ? 0 : -1;
    if (rc == 0 && UA_decodeBinary(&body, out, &UA_TYPES[UA_TYPES_NODEID], NULL) != UA_STATUSCODE_GOOD) {
        UA_NodeId_init(out);
        rc = -1;
    }
    UA_ByteString_clear(&body);
    return rc;
}

/* -------------------------------------------------------------------------
 * PKCS #10 request: subject CN=<name>, URI SAN = app uri, DNS SAN localhost,
 * SHA-256, a fresh RSA 2048 or ECC P-256 key.
 * ---------------------------------------------------------------------- */

static int gds_add_san(STACK_OF(GENERAL_NAME) *gens, int type, const char *value) {
    GENERAL_NAME *g = GENERAL_NAME_new();
    ASN1_IA5STRING *s = ASN1_IA5STRING_new();
    if (!g || !s || !ASN1_STRING_set(s, value, -1)) {
        GENERAL_NAME_free(g);
        ASN1_IA5STRING_free(s);
        return -1;
    }
    GENERAL_NAME_set0_value(g, type, s);
    if (!sk_GENERAL_NAME_push(gens, g)) {
        GENERAL_NAME_free(g);
        return -1;
    }
    return 0;
}

static int gds_make_csr(const GdsArgs *a, UA_ByteString *out) {
    UA_ByteString_init(out);
    int rc = -1;
    EVP_PKEY *key = a->nistP256 ? EVP_EC_gen("P-256") : EVP_RSA_gen(2048);
    X509_REQ *req = X509_REQ_new();
    X509_NAME *name = X509_NAME_new();
    STACK_OF(GENERAL_NAME) *gens = sk_GENERAL_NAME_new_null();
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION *san = NULL;
    if (!key || !req || !name || !gens || !exts) goto out;
    if (!X509_REQ_set_version(req, 0)) goto out;
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                    (const unsigned char *)a->appName, -1, -1, 0)) goto out;
    if (!X509_REQ_set_subject_name(req, name)) goto out;
    if (gds_add_san(gens, GEN_URI, a->appUri) != 0) goto out;
    if (gds_add_san(gens, GEN_DNS, "localhost") != 0) goto out;
    san = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
    if (!san || !sk_X509_EXTENSION_push(exts, san)) goto out;
    san = NULL; /* owned by exts */
    if (!X509_REQ_add_extensions(req, exts)) goto out;
    if (!X509_REQ_set_pubkey(req, key)) goto out;
    if (X509_REQ_sign(req, key, EVP_sha256()) <= 0) goto out;
    int n = i2d_X509_REQ(req, NULL);
    if (n <= 0 || UA_ByteString_allocBuffer(out, (size_t)n) != UA_STATUSCODE_GOOD) goto out;
    unsigned char *p = out->data;
    if (i2d_X509_REQ(req, &p) != n) { UA_ByteString_clear(out); goto out; }
    rc = 0;
out:
    X509_EXTENSION_free(san);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return rc;
}

/* -------------------------------------------------------------------------
 * Steps
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_Client *client;
    P12Json j;
    int failed;
    UA_StatusCode failSc;
    char failMsg[256];
    UA_NodeId directory;
    UA_UInt16 ns;
    int internal;       /* the adapter could not build a request (exit 6) */
    int transport;      /* the connection failed: the command stops */
    UA_StatusCode transportSc;
} GdsRun;

/* Call a Directory method. statusKey gets the status when it is Bad, or
 * also when Good with keepGood. 1 when Good (outputs set), else 0. */
static int gds_call(GdsRun *s, const char *statusKey, int keepGood, UA_UInt32 method,
                    UA_Variant *in, size_t nIn, UA_Variant **out, size_t *nOut) {
    UA_NodeId m = UA_NODEID_NUMERIC(s->ns, method);
    UA_StatusCode sc = p12_call(s->client, &s->directory, &m, in, nIn, out, nOut);
    p12v_clear_all(in, nIn);
    if (p12_is_transport(sc)) {
        p12_free_outputs(*out, *nOut);
        *out = NULL;
        *nOut = 0;
        s->transport = 1;
        s->transportSc = sc;
        snprintf(s->failMsg, sizeof(s->failMsg), "%s: the connection failed", statusKey);
        return 0;
    }
    if (sc == UA_STATUSCODE_GOOD) {
        if (keepGood) p12j_status_field(&s->j, statusKey, sc);
        return 1;
    }
    p12j_status_field(&s->j, statusKey, sc);
    s->failed = 1;
    s->failSc = sc;
    snprintf(s->failMsg, sizeof(s->failMsg), "%s: %s", statusKey, UA_StatusCode_name(sc));
    p12_free_outputs(*out, *nOut);
    *out = NULL;
    *nOut = 0;
    return 0;
}

static void gds_sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0) {}
}

static long long gds_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* The GDS namespace index from the NamespaceArray; 0 if absent. */
static UA_StatusCode gds_namespace(UA_Client *client, UA_UInt16 *ns) {
    *ns = 0;
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode sc = UA_Client_readValueAttribute(
        client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_NAMESPACEARRAY), &v);
    if (sc != UA_STATUSCODE_GOOD) return sc;
    if (v.type == &UA_TYPES[UA_TYPES_STRING]) {
        const UA_String *uris = (const UA_String *)v.data;
        UA_String want = UA_STRING(GDS_NAMESPACE);
        for (size_t i = 0; i < v.arrayLength && i <= 0xffff; i++)
            if (UA_String_equal(&uris[i], &want)) { *ns = (UA_UInt16)i; break; }
    }
    UA_Variant_clear(&v);
    return *ns ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADNODEIDUNKNOWN;
}

static void gds_steps(GdsRun *s, const GdsArgs *a) {
    P12Json *j = &s->j;
    UA_NodeId group = UA_NODEID_NUMERIC(s->ns, GDS_DEFAULT_APPLICATION_GROUP);
    UA_NodeId certType = UA_NODEID_NUMERIC(0, a->nistP256 ? GDS_NIST_P256_TYPE : GDS_RSA_SHA256_TYPE);
    UA_NodeId appId, requestId, trustList;
    UA_NodeId_init(&appId);
    UA_NodeId_init(&requestId);
    UA_NodeId_init(&trustList);
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_Variant in[7];
    UA_Variant *out = NULL;
    size_t nOut = 0;

    /* 1. FindApplications */
    p12v_string(&in[0], a->appUri);
    if (!gds_call(s, "findApplicationsStatus", 0, GDS_FIND_APPLICATIONS, in, 1, &out, &nOut)) goto done;
    int found = 0;
    p12j_key(j, "findApplications");
    p12j_open(j, '[');
    if (nOut > 0 && out[0].type && out[0].data && !UA_Variant_isScalar(&out[0])) {
        for (size_t i = 0; i < out[0].arrayLength; i++) {
            UA_NodeId id;
            if (gds_record_id(&out[0], i, &id) != 0) continue;
            p12j_sep(j);
            p12j_nodeid(j, &id);
            if (!found) { UA_NodeId_copy(&id, &appId); found = 1; }
            UA_NodeId_clear(&id);
        }
    }
    p12j_close(j, ']');
    p12_free_outputs(out, nOut);

    /* 2. RegisterApplication if nothing was found */
    if (found) {
        p12j_key(j, "registered");
        p12j_raw(j, "false");
    } else {
        UA_ExtensionObject eo;
        UA_ExtensionObject_init(&eo);
        if (gds_encode_record(a, &eo.content.encoded.body) != 0) {
            s->internal = 1;
            snprintf(s->failMsg, sizeof(s->failMsg), "cannot encode ApplicationRecordDataType");
            goto done;
        }
        eo.encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
        eo.content.encoded.typeId = UA_NODEID_NUMERIC(s->ns, GDS_APPLICATION_RECORD_BINARY);
        UA_Variant_setScalarCopy(&in[0], &eo, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
        UA_ExtensionObject_clear(&eo);
        if (!gds_call(s, "registerStatus", 1, GDS_REGISTER_APPLICATION, in, 1, &out, &nOut)) goto done;
        p12j_key(j, "registered");
        p12j_raw(j, "true");
        const UA_NodeId *id = p12_out_nodeid(out, nOut, 0);
        if (id) UA_NodeId_copy(id, &appId);
        p12_free_outputs(out, nOut);
    }
    p12j_key(j, "applicationId");
    p12j_nodeid(j, &appId);

    /* 3. StartSigningRequest / StartNewKeyPairRequest */
    p12j_key(j, "requestKind");
    p12j_cstr(j, a->csr ? "csr" : "new-key-pair");
    int ok;
    if (a->csr) {
        UA_ByteString csr;
        if (gds_make_csr(a, &csr) != 0) {
            s->internal = 1;
            snprintf(s->failMsg, sizeof(s->failMsg), "cannot create the certificate request");
            goto done;
        }
        p12v_nodeid(&in[0], &appId);
        p12v_nodeid(&in[1], &group);
        p12v_nodeid(&in[2], &certType);
        p12v_bytestring(&in[3], &csr);
        UA_ByteString_clear(&csr);
        ok = gds_call(s, "startRequestStatus", 1, GDS_START_SIGNING_REQUEST, in, 4, &out, &nOut);
    } else {
        char subject[512];
        snprintf(subject, sizeof(subject), "CN=%s", a->appName);
        const char *domains[1] = { "localhost" };
        p12v_nodeid(&in[0], &appId);
        p12v_nodeid(&in[1], &group);
        p12v_nodeid(&in[2], &certType);
        p12v_string(&in[3], subject);
        p12v_string_array(&in[4], domains, 1);
        p12v_string(&in[5], "PEM");
        p12v_string(&in[6], NULL);
        ok = gds_call(s, "startRequestStatus", 1, GDS_START_NEW_KEY_PAIR_REQUEST, in, 7, &out, &nOut);
    }
    if (!ok) goto done;
    {
        const UA_NodeId *id = p12_out_nodeid(out, nOut, 0);
        if (id) UA_NodeId_copy(id, &requestId);
    }
    p12_free_outputs(out, nOut);
    p12j_key(j, "requestId");
    p12j_nodeid(j, &requestId);

    /* 4. FinishRequest while it answers BadNothingToDo (pending) */
    long long deadline = gds_now_ms() + (long long)a->finishTimeoutMs;
    UA_NodeId finish = UA_NODEID_NUMERIC(s->ns, GDS_FINISH_REQUEST);
    UA_StatusCode sc;
    for (;;) {
        p12v_nodeid(&in[0], &appId);
        p12v_nodeid(&in[1], &requestId);
        sc = p12_call(s->client, &s->directory, &finish, in, 2, &out, &nOut);
        p12v_clear_all(in, 2);
        if (sc == UA_STATUSCODE_BADNOTHINGTODO && gds_now_ms() < deadline) {
            p12_free_outputs(out, nOut);
            gds_sleep_ms(GDS_FINISH_POLL_MS);
            continue;
        }
        break;
    }
    if (p12_is_transport(sc)) {
        p12_free_outputs(out, nOut);
        s->transport = 1;
        s->transportSc = sc;
        snprintf(s->failMsg, sizeof(s->failMsg), "finishRequest: the connection failed");
        goto done;
    }
    p12j_status_field(j, "finishRequestStatus", sc);
    if (sc != UA_STATUSCODE_GOOD) {
        p12_free_outputs(out, nOut);
        s->failed = 1;
        s->failSc = sc;
        snprintf(s->failMsg, sizeof(s->failMsg), "finishRequest: %s", UA_StatusCode_name(sc));
        goto done;
    }
    {
        const UA_ByteString *c = p12_out_bytestring(out, nOut, 0);
        if (c) UA_ByteString_copy(c, &certificate);
        p12j_b64_field(j, "certificate", &certificate);
        if (!a->csr) {
            p12j_key(j, "privateKeyFormat");
            p12j_cstr(j, "PEM");
            p12j_b64_field(j, "privateKey", p12_out_bytestring(out, nOut, 1));
        }
        p12j_b64_array_field(j, "issuerCertificates", nOut > 2 ? &out[2] : NULL);
    }
    p12_free_outputs(out, nOut);

    /* 5. GetCertificateGroups */
    p12v_nodeid(&in[0], &appId);
    if (!gds_call(s, "getCertificateGroupsStatus", 0, GDS_GET_CERTIFICATE_GROUPS, in, 1, &out, &nOut)) goto done;
    p12j_nodeid_array_field(j, "certificateGroups", nOut > 0 ? &out[0] : NULL);
    p12_free_outputs(out, nOut);

    /* 6. GetTrustList, then read the TrustList (Open, Read, Close) */
    p12v_nodeid(&in[0], &appId);
    p12v_nodeid(&in[1], &group);
    if (!gds_call(s, "getTrustListStatus", 0, GDS_GET_TRUST_LIST, in, 2, &out, &nOut)) goto done;
    {
        const UA_NodeId *id = p12_out_nodeid(out, nOut, 0);
        if (id) UA_NodeId_copy(id, &trustList);
    }
    p12_free_outputs(out, nOut);
    p12j_key(j, "trustListId");
    p12j_nodeid(j, &trustList);
    {
        UA_TrustListDataType tl;
        sc = p12_read_trust_list(s->client, &trustList, 0, 0, &tl);
        if (p12_is_transport(sc)) {
            s->transport = 1;
            s->transportSc = sc;
            snprintf(s->failMsg, sizeof(s->failMsg), "readTrustList: the connection failed");
            goto done;
        }
        if (sc != UA_STATUSCODE_GOOD) {
            p12j_status_field(j, "readTrustListStatus", sc);
            s->failed = 1;
            s->failSc = sc;
            snprintf(s->failMsg, sizeof(s->failMsg), "readTrustList: %s", UA_StatusCode_name(sc));
            goto done;
        }
        p12j_key(j, "trustList");
        p12j_trust_list(j, &tl);
        UA_TrustListDataType_clear(&tl);
    }

    /* 7. GetCertificateStatus */
    p12v_nodeid(&in[0], &appId);
    p12v_nodeid(&in[1], &group);
    p12v_nodeid(&in[2], &certType);
    if (!gds_call(s, "getCertificateStatusStatus", 1, GDS_GET_CERTIFICATE_STATUS, in, 3, &out, &nOut)) goto done;
    p12j_key(j, "updateRequired");
    p12j_raw(j, p12_out_bool(out, nOut, 0) ? "true" : "false");
    p12_free_outputs(out, nOut);

    /* 8. RevokeCertificate, CheckRevocationStatus */
    if (a->revoke) {
        p12v_nodeid(&in[0], &appId);
        p12v_bytestring(&in[1], &certificate);
        if (!gds_call(s, "revokeStatus", 1, GDS_REVOKE_CERTIFICATE, in, 2, &out, &nOut)) goto done;
        p12_free_outputs(out, nOut);
        p12v_bytestring(&in[0], &certificate);
        if (!gds_call(s, "checkRevocationStatus", 1, GDS_CHECK_REVOCATION_STATUS, in, 1, &out, &nOut)) goto done;
        UA_StatusCode status = UA_STATUSCODE_BADUNEXPECTEDERROR;
        if (nOut > 0 && UA_Variant_hasScalarType(&out[0], &UA_TYPES[UA_TYPES_STATUSCODE]))
            status = *(UA_StatusCode *)out[0].data;
        p12j_status_field(j, "certificateStatus", status);
        p12_free_outputs(out, nOut);
    }

    /* 9. UnregisterApplication */
    if (a->unregister) {
        p12v_nodeid(&in[0], &appId);
        if (gds_call(s, "unregisterStatus", 1, GDS_UNREGISTER_APPLICATION, in, 1, &out, &nOut))
            p12_free_outputs(out, nOut);
    }

done:
    UA_NodeId_clear(&appId);
    UA_NodeId_clear(&requestId);
    UA_NodeId_clear(&trustList);
    UA_ByteString_clear(&certificate);
}

int cmd_gds_pull(int argc, char **argv) {
    const char *op = "gds-pull";
    GdsArgs a;
    char msg[512];
    if (gds_parse(argc, argv, &a, msg, sizeof(msg)) != 0) {
        gds_args_clear(&a);
        cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input", msg);
        return 2;
    }
    const char *endpoint = cli_find_arg(argc, argv, "--endpoint");
    const char *rt = cli_find_arg(argc, argv, "--request-timeout");
    int reqMs = (rt && atoi(rt) > 0 ? atoi(rt) : 5) * 1000;
    int exitCode = 3;
    UA_Client *client = cli_make_client(endpoint, reqMs, op, &exitCode);
    if (!client) {
        gds_args_clear(&a);
        return exitCode;
    }

    int code;
    UA_UInt16 ns = 0;
    UA_StatusCode nsSc = gds_namespace(client, &ns);
    if (nsSc != UA_STATUSCODE_GOOD) {
        int ec = p12_is_transport(nsSc) ? p12_exit_code(nsSc) : 4;
        snprintf(msg, sizeof(msg), "the server has no namespace %s (%s)", GDS_NAMESPACE,
                 UA_StatusCode_name(nsSc));
        cli_emit_failure(op, nsSc, ec == 7 ? "timeout" : ec == 3 ? "transport" : "service", msg);
        code = ec;
    } else {
        GdsRun s;
        memset(&s, 0, sizeof(s));
        s.client = client;
        s.ns = ns;
        s.directory = UA_NODEID_NUMERIC(ns, GDS_DIRECTORY);
        p12j_init(&s.j);
        p12j_open(&s.j, '{');
        gds_steps(&s, &a);
        p12j_close(&s.j, '}');
        if (s.j.oom) {
            p12_emit(op, 0, UA_STATUSCODE_BADOUTOFMEMORY, "internal", "out of memory", NULL);
            code = 6;
        } else if (s.transport) {
            code = p12_exit_code(s.transportSc);
            p12_emit(op, 0, s.transportSc, code == 7 ? "timeout" : "transport", s.failMsg, NULL);
        } else if (s.internal) {
            p12_emit(op, 0, UA_STATUSCODE_BADINTERNALERROR, "internal", s.failMsg, NULL);
            code = 6;
        } else if (s.failed) {
            p12_emit(op, 0, s.failSc, "service", s.failMsg, &s.j);
            code = 4;
        } else {
            p12_emit(op, 1, UA_STATUSCODE_GOOD, NULL, NULL, &s.j);
            code = 0;
        }
        p12j_free(&s.j);
    }
    gds_args_clear(&a);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return code;
}
