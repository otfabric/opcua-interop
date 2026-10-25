/*
 * `client push` (CLIENT_CONTRACT §1 "push flags", §4 `push`, §15): push
 * certificate management (Part 12 §7) against the ServerConfiguration object
 * of the server. open62541 v1.5.9 has no push client API, so every step is a
 * plain UA_Client_call on the standard NodeIds of ServerConfiguration and of
 * the TrustList of the selected CertificateGroup, on one session (the
 * transaction of Part 12 §7.10.2 is the session's).
 */
#define _GNU_SOURCE

#include "client_internal.h"
#include "part12.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ServerConfiguration (Part 12 §7.10) and its methods. */
#define PUSH_SERVER_CONFIGURATION      12637
#define PUSH_UPDATE_CERTIFICATE        13737
#define PUSH_CREATE_SIGNING_REQUEST    12737
#define PUSH_GET_REJECTED_LIST         12777
#define PUSH_APPLY_CHANGES             12740
#define PUSH_GET_CERTIFICATES          32333
#define PUSH_CREATE_SELF_SIGNED        19342
#define PUSH_DELETE_CERTIFICATE        19345
#define PUSH_CANCEL_CHANGES            25708
#define PUSH_RESET_TO_SERVER_DEFAULTS  25709
/* TrustListMasks All (Part 12 §7.8.2.7). */
#define PUSH_TRUST_LIST_MASKS_ALL      15

/* ServerConfiguration.TransactionDiagnostics: StartTime, EndTime, Result,
 * AffectedTrustLists, AffectedCertificateGroups, Errors (Part 12 §7.10.12). */
static const UA_UInt32 kTxDiagnostics[6] = { 32337, 32338, 32339, 32340, 32341, 32342 };

typedef struct {
    UA_UInt32 group;
    UA_UInt32 defaultType;
    const char *certTypeStr;  /* --certificate-type-id, or NULL */
    UA_ByteString add;        /* --add-certificate (DER) */
    const char *remove;       /* --remove-certificate thumbprint */
    int issuer, csr, apply, cancel, getCerts, selfSigned, reset, diagnostics;
    const char *subject;
    const char **dns; size_t nDns;
    const char **ip;  size_t nIp;
    UA_UInt16 lifetimeDays, keySize;
    const char *deleteType;   /* --delete-certificate */
    int update;
    UA_ByteString updateCert;
    int haveKey;
    const char *keyFormat;
    UA_ByteString key;
    UA_ByteString *issuers; size_t nIssuers;
} PushArgs;

static void push_args_clear(PushArgs *a) {
    UA_ByteString_clear(&a->add);
    UA_ByteString_clear(&a->updateCert);
    UA_ByteString_clear(&a->key);
    for (size_t i = 0; a->issuers && i < a->nIssuers; i++) UA_ByteString_clear(&a->issuers[i]);
    free(a->issuers);
    free((void *)a->dns);
    free((void *)a->ip);
    memset(a, 0, sizeof(*a));
}

static int ends_with_ci(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcasecmp(s + n - m, suffix) == 0;
}

/* Parse and check the flags; a bad flag or an unreadable file is an input
 * error before connecting. 0 on success, else msg is set. */
static int push_parse(int argc, char **argv, PushArgs *a, char *msg, size_t msgLen) {
    memset(a, 0, sizeof(*a));
    if (!cli_find_arg(argc, argv, "--endpoint")) {
        snprintf(msg, msgLen, "--endpoint is required");
        return -1;
    }
    const char *group = cli_find_arg(argc, argv, "--group");
    if (!group || strcmp(group, "Application") == 0) {
        a->group = 14156; a->defaultType = 12560; /* DefaultApplicationGroup, RsaSha256ApplicationCertificateType */
    } else if (strcmp(group, "Https") == 0) {
        a->group = 14088; a->defaultType = 12558; /* DefaultHttpsGroup, HttpsCertificateType */
    } else if (strcmp(group, "UserToken") == 0) {
        a->group = 14122; a->defaultType = 15181; /* DefaultUserTokenGroup, UserCredentialCertificateType */
    } else {
        snprintf(msg, msgLen, "--group must be Application, Https or UserToken, got %s", group);
        return -1;
    }
    a->certTypeStr = cli_find_arg(argc, argv, "--certificate-type-id");
    if (a->certTypeStr && cli_validate_nodeid(a->certTypeStr) != 0) {
        snprintf(msg, msgLen, "malformed NodeId: '%s'", a->certTypeStr);
        return -1;
    }
    a->deleteType = cli_find_arg(argc, argv, "--delete-certificate");
    if (a->deleteType && cli_validate_nodeid(a->deleteType) != 0) {
        snprintf(msg, msgLen, "malformed NodeId: '%s'", a->deleteType);
        return -1;
    }
    const char *f;
    if ((f = cli_find_arg(argc, argv, "--add-certificate")) &&
        p12_read_certificate(f, &a->add) != 0) {
        snprintf(msg, msgLen, "--add-certificate %s: cannot read a PEM or DER certificate", f);
        return -1;
    }
    a->remove = cli_find_arg(argc, argv, "--remove-certificate");
    a->issuer = p12_has_flag(argc, argv, "--issuer");
    a->csr = p12_has_flag(argc, argv, "--csr");
    a->apply = p12_has_flag(argc, argv, "--apply");
    a->getCerts = p12_has_flag(argc, argv, "--get-certificates");
    a->selfSigned = p12_has_flag(argc, argv, "--create-self-signed");
    a->reset = p12_has_flag(argc, argv, "--reset-to-defaults");
    a->diagnostics = p12_has_flag(argc, argv, "--transaction-diagnostics");
    /* --cancel is implied by --create-self-signed / --delete-certificate
     * without --apply: the created / deleted certificate is not installed. */
    a->cancel = !a->apply &&
        (p12_has_flag(argc, argv, "--cancel") || a->selfSigned || a->deleteType);
    a->subject = cli_find_arg(argc, argv, "--subject");
    a->dns = p12_all_values(argc, argv, "--dns", &a->nDns);
    a->ip = p12_all_values(argc, argv, "--ip", &a->nIp);
    if (!a->dns || !a->ip) {
        snprintf(msg, msgLen, "out of memory");
        return -1;
    }
    unsigned long v = 365;
    const char *s = cli_find_arg(argc, argv, "--lifetime-days");
    if (s && p12_parse_uint(s, 65535, &v) != 0) {
        snprintf(msg, msgLen, "--lifetime-days must be a UInt16, got %s", s);
        return -1;
    }
    a->lifetimeDays = (UA_UInt16)v;
    v = 0;
    s = cli_find_arg(argc, argv, "--key-size");
    if (s && p12_parse_uint(s, 65535, &v) != 0) {
        snprintf(msg, msgLen, "--key-size must be a UInt16, got %s", s);
        return -1;
    }
    a->keySize = (UA_UInt16)v;

    const char *upd = cli_find_arg(argc, argv, "--update-certificate");
    const char *keyFile = cli_find_arg(argc, argv, "--update-private-key");
    if (keyFile && !upd) {
        snprintf(msg, msgLen, "--update-private-key needs --update-certificate");
        return -1;
    }
    if (upd) {
        a->update = 1;
        if (p12_read_certificate(upd, &a->updateCert) != 0) {
            snprintf(msg, msgLen, "--update-certificate %s: cannot read a PEM or DER certificate", upd);
            return -1;
        }
    }
    if (keyFile) {
        const char *fmt = cli_find_arg(argc, argv, "--private-key-format");
        if (fmt && strcmp(fmt, "PEM") != 0 && strcmp(fmt, "PFX") != 0) {
            snprintf(msg, msgLen, "--private-key-format must be PEM or PFX, got %s", fmt);
            return -1;
        }
        if (!fmt) fmt = (ends_with_ci(keyFile, ".pfx") || ends_with_ci(keyFile, ".p12")) ? "PFX" : "PEM";
        a->keyFormat = fmt;
        a->haveKey = 1;
        if (p12_read_file(keyFile, &a->key) != 0) {
            snprintf(msg, msgLen, "--update-private-key %s: cannot read the file", keyFile);
            return -1;
        }
    }
    size_t nIss = 0;
    const char **iss = p12_all_values(argc, argv, "--issuer-certificate", &nIss);
    if (!iss) {
        snprintf(msg, msgLen, "out of memory");
        return -1;
    }
    if (nIss) {
        a->issuers = (UA_ByteString *)calloc(nIss, sizeof(UA_ByteString));
        if (!a->issuers) { free((void *)iss); snprintf(msg, msgLen, "out of memory"); return -1; }
    }
    for (size_t i = 0; i < nIss; i++) {
        if (p12_read_certificate(iss[i], &a->issuers[i]) != 0) {
            a->nIssuers = i;
            snprintf(msg, msgLen, "--issuer-certificate %s: cannot read a PEM or DER certificate", iss[i]);
            free((void *)iss);
            return -1;
        }
    }
    a->nIssuers = nIss;
    free((void *)iss);
    return 0;
}

/* The result item and the first failing status. */
typedef struct {
    P12Json j;
    int failed;
    int inputErr; /* a NodeId flag that does not resolve (exit 2) */
    UA_StatusCode failSc;
    char failMsg[256];
} PushOut;

static void push_fail(PushOut *o, UA_StatusCode sc, const char *what) {
    if (o->failed) return;
    o->failed = 1;
    o->failSc = sc;
    snprintf(o->failMsg, sizeof(o->failMsg), "%s returned a non-Good status", what);
}

/* Record the status of a step; 1 when it is Good. */
static int push_step(PushOut *o, const char *name, UA_StatusCode sc) {
    char key[64];
    snprintf(key, sizeof(key), "%sStatus", name);
    p12j_status_field(&o->j, key, sc);
    if (sc == UA_STATUSCODE_GOOD) return 1;
    push_fail(o, sc, name);
    return 0;
}

/* The JSON of one TransactionErrorType (TargetId NodeId, Error StatusCode,
 * Message LocalizedText) from its binary body; the stack may not know the
 * 1.05 type, so it is decoded here. */
static void push_tx_error(P12Json *j, const UA_ByteString *body) {
    UA_NodeId target;
    UA_NodeId_init(&target);
    size_t off = body ? p12_nodeid_encoded_length(body->data, body->length) : 0;
    UA_StatusCode err = UA_STATUSCODE_BADDECODINGERROR;
    UA_LocalizedText text;
    UA_LocalizedText_init(&text);
    int ok = off > 0 && off + 4 <= body->length &&
             UA_decodeBinary(body, &target, &UA_TYPES[UA_TYPES_NODEID], NULL) == UA_STATUSCODE_GOOD;
    if (ok) {
        const UA_Byte *p = body->data + off;
        err = (UA_StatusCode)p[0] | ((UA_StatusCode)p[1] << 8) |
              ((UA_StatusCode)p[2] << 16) | ((UA_StatusCode)p[3] << 24);
        UA_ByteString rest = { body->length - off - 4, body->data + off + 4 };
        if (UA_decodeBinary(&rest, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT], NULL) != UA_STATUSCODE_GOOD)
            UA_LocalizedText_init(&text);
    } else {
        UA_NodeId_clear(&target);
        err = UA_STATUSCODE_BADDECODINGERROR;
    }
    p12j_open(j, '{');
    p12j_key(j, "targetId");
    p12j_nodeid(j, &target);
    p12j_key(j, "error");
    p12j_status(j, err);
    p12j_key(j, "message");
    p12j_uastr(j, &text.text);
    p12j_close(j, '}');
    UA_NodeId_clear(&target);
    UA_LocalizedText_clear(&text);
}

static void push_tx_errors(P12Json *j, const UA_Variant *v) {
    p12j_key(j, "errors");
    p12j_open(j, '[');
    if (v && v->type && v->data && v->arrayLength > 0) {
        for (size_t i = 0; i < v->arrayLength; i++) {
            const void *elem = (const UA_Byte *)v->data + i * v->type->memSize;
            UA_ByteString body = UA_BYTESTRING_NULL;
            int rc;
            if (v->type == &UA_TYPES[UA_TYPES_EXTENSIONOBJECT])
                rc = p12_extension_body((const UA_ExtensionObject *)elem, &body);
            else /* unwrapped into a type the stack knows: encode it again */
                rc = UA_encodeBinary(elem, v->type, &body, NULL) == UA_STATUSCODE_GOOD ? 0 : -1;
            p12j_sep(j);
            push_tx_error(j, rc == 0 ? &body : NULL);
            UA_ByteString_clear(&body);
        }
    }
    p12j_close(j, ']');
}

/* Read the TransactionDiagnostics variables in one Read: their status and,
 * when Good, the "transactionDiagnostics" JSON. A transport failure is
 * returned as the result (the caller stops). */
static UA_StatusCode push_tx_diagnostics(UA_Client *client, PushOut *o, int *transport) {
    *transport = 0;
    UA_ReadValueId ids[6];
    for (int i = 0; i < 6; i++) {
        UA_ReadValueId_init(&ids[i]);
        ids[i].nodeId = UA_NODEID_NUMERIC(0, kTxDiagnostics[i]);
        ids[i].attributeId = UA_ATTRIBUTEID_VALUE;
    }
    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.nodesToRead = ids;
    req.nodesToReadSize = 6;
    req.timestampsToReturn = UA_TIMESTAMPSTORETURN_NEITHER;
    UA_ReadResponse resp = UA_Client_Service_read(client, req);
    UA_StatusCode sc = resp.responseHeader.serviceResult;
    if (p12_is_transport(sc)) {
        *transport = 1;
        UA_ReadResponse_clear(&resp);
        return sc;
    }
    if (sc == UA_STATUSCODE_GOOD && resp.resultsSize != 6) sc = UA_STATUSCODE_BADUNEXPECTEDERROR;
    for (size_t i = 0; sc == UA_STATUSCODE_GOOD && i < 6; i++)
        if (resp.results[i].hasStatus && resp.results[i].status != UA_STATUSCODE_GOOD)
            sc = resp.results[i].status;
    p12j_status_field(&o->j, "transactionDiagnosticsStatus", sc);
    if (sc == UA_STATUSCODE_GOOD) {
        const UA_Variant *v[6];
        for (int i = 0; i < 6; i++) v[i] = resp.results[i].hasValue ? &resp.results[i].value : NULL;
        P12Json *j = &o->j;
        p12j_key(j, "transactionDiagnostics");
        p12j_open(j, '{');
        for (int i = 0; i < 2; i++) {
            p12j_key(j, i == 0 ? "startTime" : "endTime");
            UA_DateTime dt = 0;
            if (v[i] && UA_Variant_hasScalarType(v[i], &UA_TYPES[UA_TYPES_DATETIME]))
                dt = *(UA_DateTime *)v[i]->data;
            p12j_datetime(j, dt);
        }
        UA_StatusCode result = UA_STATUSCODE_GOOD;
        if (v[2] && UA_Variant_hasScalarType(v[2], &UA_TYPES[UA_TYPES_STATUSCODE]))
            result = *(UA_StatusCode *)v[2]->data;
        p12j_status_field(j, "result", result);
        p12j_nodeid_array_field(j, "affectedTrustLists", v[3]);
        p12j_nodeid_array_field(j, "affectedCertificateGroups", v[4]);
        push_tx_errors(j, v[5]);
        p12j_close(j, '}');
    }
    UA_ReadResponse_clear(&resp);
    return sc;
}

/* Run a method of ServerConfiguration; returns its status, *transport when
 * the connection failed (the command stops). */
static UA_StatusCode push_call(UA_Client *client, const UA_NodeId *object, UA_UInt32 method,
                               const UA_NodeId *methodId, UA_Variant *in, size_t nIn,
                               UA_Variant **out, size_t *nOut, int *transport) {
    UA_NodeId m = methodId ? *methodId : UA_NODEID_NUMERIC(0, method);
    UA_StatusCode sc = p12_call(client, object, &m, in, nIn, out, nOut);
    p12v_clear_all(in, nIn);
    *transport = p12_is_transport(sc);
    return sc;
}

/* The steps, stopping at the first Bad status. Returns Good, or the status
 * that ends the command as a whole (transport, timeout, a TrustList read). */
static UA_StatusCode push_steps(UA_Client *client, const PushArgs *a, PushOut *o) {
    const UA_NodeId sc_obj = UA_NODEID_NUMERIC(0, PUSH_SERVER_CONFIGURATION);
    const UA_NodeId group = UA_NODEID_NUMERIC(0, a->group);
    UA_NodeId certType = UA_NODEID_NUMERIC(0, a->defaultType);
    UA_NodeId tl[3];
    for (int i = 0; i < 3; i++) UA_NodeId_init(&tl[i]);
    UA_TrustListDataType list;
    UA_Variant in[7];
    UA_Variant *out = NULL;
    size_t nOut = 0;
    int transport = 0;
    UA_StatusCode sc;
    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    p12j_key(&o->j, "certificateGroupId");
    p12j_nodeid(&o->j, &group);

    if (a->certTypeStr && p12_resolve_nodeid(client, a->certTypeStr, &certType) != 0) {
        snprintf(o->failMsg, sizeof(o->failMsg), "unknown namespace URI in --certificate-type-id '%s'", a->certTypeStr);
        o->inputErr = 1;
        return UA_STATUSCODE_BADNAMESPACEURIINVALID;
    }

    /* The TrustList of the group and its TrustListType methods. */
    static const char *const pTl[] = { "TrustList", NULL };
    static const char *const pAdd[] = { "TrustList", "AddCertificate", NULL };
    static const char *const pRemove[] = { "TrustList", "RemoveCertificate", NULL };
    const char *const *paths[3] = { pTl, pAdd, pRemove };
    sc = p12_translate(client, &group, paths, 3, tl);
    if (sc != UA_STATUSCODE_GOOD) {
        snprintf(o->failMsg, sizeof(o->failMsg), "the TrustList of the certificate group not found");
        ret = sc;
        goto done;
    }
    sc = p12_read_trust_list(client, &tl[0], 1, PUSH_TRUST_LIST_MASKS_ALL, &list);
    if (sc != UA_STATUSCODE_GOOD) {
        snprintf(o->failMsg, sizeof(o->failMsg), "reading the TrustList returned a non-Good status");
        ret = sc;
        goto done;
    }
    p12j_key(&o->j, "trustList");
    p12j_trust_list(&o->j, &list);
    UA_TrustListDataType_clear(&list);

#define PUSH_TRANSPORT_CHECK() do { if (transport) { p12_free_outputs(out, nOut); ret = sc; goto done; } } while (0)

    if (a->add.length) {
        p12v_bytestring(&in[0], &a->add);
        p12v_bool(&in[1], !a->issuer);
        sc = push_call(client, &tl[0], 0, &tl[1], in, 2, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        push_step(o, "addCertificate", sc);
        p12_free_outputs(out, nOut);
    }
    if (!o->failed && a->remove) {
        p12v_string(&in[0], a->remove);
        p12v_bool(&in[1], !a->issuer);
        sc = push_call(client, &tl[0], 0, &tl[2], in, 2, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        push_step(o, "removeCertificate", sc);
        p12_free_outputs(out, nOut);
    }
    if (!o->failed && a->getCerts) {
        p12v_nodeid(&in[0], &group);
        sc = push_call(client, &sc_obj, PUSH_GET_CERTIFICATES, NULL, in, 1, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        if (push_step(o, "getCertificates", sc)) {
            p12j_nodeid_array_field(&o->j, "certificateTypeIds", nOut > 0 ? &out[0] : NULL);
            p12j_b64_array_field(&o->j, "certificates", nOut > 1 ? &out[1] : NULL);
        }
        p12_free_outputs(out, nOut);
    }
    if (!o->failed && a->selfSigned) {
        p12v_nodeid(&in[0], &group);
        p12v_nodeid(&in[1], &certType);
        p12v_string(&in[2], a->subject ? a->subject : "");
        p12v_string_array(&in[3], a->dns, a->nDns);
        p12v_string_array(&in[4], a->ip, a->nIp);
        p12v_uint16(&in[5], a->lifetimeDays);
        p12v_uint16(&in[6], a->keySize);
        sc = push_call(client, &sc_obj, PUSH_CREATE_SELF_SIGNED, NULL, in, 7, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        if (push_step(o, "createSelfSignedCertificate", sc))
            p12j_b64_field(&o->j, "selfSignedCertificate", p12_out_bytestring(out, nOut, 0));
        p12_free_outputs(out, nOut);
    }
    if (!o->failed && a->deleteType) {
        UA_NodeId typeId;
        if (p12_resolve_nodeid(client, a->deleteType, &typeId) != 0) {
            snprintf(o->failMsg, sizeof(o->failMsg), "unknown namespace URI in --delete-certificate '%s'", a->deleteType);
            o->inputErr = 1;
            ret = UA_STATUSCODE_BADNAMESPACEURIINVALID;
            goto done;
        }
        p12v_nodeid(&in[0], &group);
        p12v_nodeid(&in[1], &typeId);
        UA_NodeId_clear(&typeId);
        sc = push_call(client, &sc_obj, PUSH_DELETE_CERTIFICATE, NULL, in, 2, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        push_step(o, "deleteCertificate", sc);
        p12_free_outputs(out, nOut);
    }
    if (!o->failed && a->update) {
        p12v_nodeid(&in[0], &group);
        p12v_nodeid(&in[1], &certType);
        p12v_bytestring(&in[2], &a->updateCert);
        p12v_bytestring_array(&in[3], a->issuers, a->nIssuers);
        p12v_string(&in[4], a->haveKey ? a->keyFormat : "");
        p12v_bytestring(&in[5], a->haveKey ? &a->key : NULL);
        sc = push_call(client, &sc_obj, PUSH_UPDATE_CERTIFICATE, NULL, in, 6, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        if (push_step(o, "updateCertificate", sc)) {
            p12j_key(&o->j, "applyChangesRequired");
            p12j_raw(&o->j, p12_out_bool(out, nOut, 0) ? "true" : "false");
        }
        p12_free_outputs(out, nOut);
    }
    if (!o->failed && a->csr) {
        p12v_nodeid(&in[0], &group);
        p12v_nodeid(&in[1], &certType);
        p12v_string(&in[2], NULL);
        p12v_bool(&in[3], false);
        p12v_bytestring(&in[4], NULL);
        sc = push_call(client, &sc_obj, PUSH_CREATE_SIGNING_REQUEST, NULL, in, 5, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        if (push_step(o, "createSigningRequest", sc))
            p12j_b64_field(&o->j, "certificateSigningRequest", p12_out_bytestring(out, nOut, 0));
        p12_free_outputs(out, nOut);
    }
    if (!o->failed) {
        sc = push_call(client, &sc_obj, PUSH_GET_REJECTED_LIST, NULL, in, 0, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        if (push_step(o, "getRejectedList", sc))
            p12j_b64_array_field(&o->j, "rejectedCertificates", nOut > 0 ? &out[0] : NULL);
        p12_free_outputs(out, nOut);
    }
    if (!o->failed && a->reset) {
        sc = push_call(client, &sc_obj, PUSH_RESET_TO_SERVER_DEFAULTS, NULL, in, 0, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        push_step(o, "resetToServerDefaults", sc);
        p12_free_outputs(out, nOut);
    }
    int applied = 0;
    if (!o->failed && a->apply) {
        sc = push_call(client, &sc_obj, PUSH_APPLY_CHANGES, NULL, in, 0, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        push_step(o, "applyChanges", sc);
        p12_free_outputs(out, nOut);
        applied = 1;
    }
    if (!o->failed && a->cancel) {
        sc = push_call(client, &sc_obj, PUSH_CANCEL_CHANGES, NULL, in, 0, &out, &nOut, &transport);
        PUSH_TRANSPORT_CHECK();
        push_step(o, "cancelChanges", sc);
        p12_free_outputs(out, nOut);
    }
    /* The diagnostics explain a failed ApplyChanges too: read them also then. */
    if (a->diagnostics && (!o->failed || applied)) {
        sc = push_tx_diagnostics(client, o, &transport);
        if (transport) { ret = sc; goto done; }
        if (!o->failed && sc != UA_STATUSCODE_GOOD) {
            o->failed = 1;
            o->failSc = sc;
            snprintf(o->failMsg, sizeof(o->failMsg), "reading TransactionDiagnostics returned a non-Good status");
        }
    }
    if (!o->failed) {
        sc = p12_read_trust_list(client, &tl[0], 1, PUSH_TRUST_LIST_MASKS_ALL, &list);
        if (sc != UA_STATUSCODE_GOOD) {
            snprintf(o->failMsg, sizeof(o->failMsg), "reading the TrustList again returned a non-Good status");
            ret = sc;
            goto done;
        }
        p12j_key(&o->j, "trustListAfter");
        p12j_trust_list(&o->j, &list);
        UA_TrustListDataType_clear(&list);
    }
#undef PUSH_TRANSPORT_CHECK

done:
    for (int i = 0; i < 3; i++) UA_NodeId_clear(&tl[i]);
    UA_NodeId_clear(&certType);
    return ret;
}

int cmd_push(int argc, char **argv) {
    const char *op = "push";
    PushArgs a;
    char msg[512];
    if (push_parse(argc, argv, &a, msg, sizeof(msg)) != 0) {
        push_args_clear(&a);
        cli_emit_failure(op, UA_STATUSCODE_BADINVALIDARGUMENT, "input", msg);
        return 2;
    }
    const char *endpoint = cli_find_arg(argc, argv, "--endpoint");
    const char *rt = cli_find_arg(argc, argv, "--request-timeout");
    int reqMs = (rt && atoi(rt) > 0 ? atoi(rt) : 5) * 1000;
    int exitCode = 3;
    UA_Client *client = cli_make_client(endpoint, reqMs, op, &exitCode);
    if (!client) {
        push_args_clear(&a);
        return exitCode;
    }

    PushOut o;
    memset(&o, 0, sizeof(o));
    p12j_init(&o.j);
    p12j_open(&o.j, '{');
    UA_StatusCode ret = push_steps(client, &a, &o);
    p12j_close(&o.j, '}');

    int code;
    if (o.j.oom) {
        p12_emit(op, 0, UA_STATUSCODE_BADOUTOFMEMORY, "internal", "out of memory", NULL);
        code = 6;
    } else if (o.inputErr) {
        p12_emit(op, 0, ret, "input", o.failMsg, NULL);
        code = 2;
    } else if (ret != UA_STATUSCODE_GOOD) {
        /* A transport failure, or a step without a status key of its own
         * (the TrustList read): the result so far, failed. */
        int ec = p12_exit_code(ret);
        const char *cat = ec == 7 ? "timeout" : ec == 3 ? "transport" : "service";
        p12_emit(op, 0, ret, cat, o.failMsg[0] ? o.failMsg : "the connection failed", &o.j);
        code = ec;
    } else if (o.failed) {
        p12_emit(op, 0, o.failSc, "service", o.failMsg, &o.j);
        code = 4;
    } else {
        p12_emit(op, 1, UA_STATUSCODE_GOOD, NULL, NULL, &o.j);
        code = 0;
    }
    p12j_free(&o.j);
    push_args_clear(&a);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return code;
}
