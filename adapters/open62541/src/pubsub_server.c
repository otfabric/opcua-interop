/*
 * OPC UA PubSub (Part 14) for `server --pubsub-config <file>`.
 *
 * The file is a JSON document:
 *
 *   {
 *     "configuration":  <PubSubConfigurationDataType, OPC UA 1.05 JSON>,
 *     "securityGroups": [ { "securityGroupId": "...", "securityPolicyUri": "...",
 *                           "keyLifetimeMs": 60000, "maxFutureKeyCount": 2,
 *                           "maxPastKeyCount": 1,
 *                           "keys": [ { "tokenId": 1, "key": "<base64>" } ] } ],
 *     "serveSks":  false,
 *     "deltaFrames": false,
 *     "sksClient": { "endpointUrl": "opc.tcp://...", "securityPolicyUri": "...",
 *                    "securityMode": "SignAndEncrypt", "username": "...",
 *                    "password": "..." }
 *   }
 *
 * The configuration is decoded with UA_decodeJson into a
 * UA_PubSubConfigurationDataType and then built component by component with
 * the open62541 server API (UA_Server_addPubSubConnection, ...). That is used
 * instead of UA_Server_loadPubSubConfigFromByteString because the v1.5.9
 * loader drops fields the interop tests need (WriterGroup/ReaderGroup
 * SecurityGroupId, ReaderGroup and DataSetReader TransportSettings — i.e. the
 * MQTT QueueName of a subscriber —, the DataSetWriter TransportSettings) and
 * ignores errors of nested components. Which fields are honoured is
 * documented in docs/CLIENT_CONTRACT.md §14.
 */

#define _GNU_SOURCE

#include "pubsub_server.h"
#include "pubsub_security.h"
#include "client_internal.h"
#include "values.h"

#include <cjson/cJSON.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_PREFIX "[open62541] "

#define PROFILE_UDP_UADP  "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"
#define PROFILE_MQTT_UADP "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp"
#define PROFILE_MQTT_JSON "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json"

/* -------------------------------------------------------------------------
 * Runtime state kept for the lifetime of the server
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_UInt32  tokenId;
    UA_ByteString key;
} StaticKey;

typedef enum {
    KEYSRC_NONE = 0,   /* no keys yet: SetSecurityKeys (push) can provide them */
    KEYSRC_STATIC,     /* "keys" in the config file */
    KEYSRC_SKS_SERVER, /* this server is the SKS ("serveSks") */
    KEYSRC_SKS_CLIENT  /* pulled from "sksClient" */
} KeySource;

typedef struct {
    char      *id;
    char      *policyUri;
    double     keyLifetimeMs;
    UA_UInt32  maxFutureKeyCount;
    UA_UInt32  maxPastKeyCount;
    StaticKey *keys;
    size_t     keyCount;
    KeySource  source;
    UA_NodeId  nodeId;  /* SKS SecurityGroup node */
    int        sksKeysReceived;
    int        sksInFlight;
} SecGroup;

typedef struct {
    char *endpointUrl; /* referenced by the open62541 keystorage: never freed */
    char *policy;
    char *mode;
    char *username;
    char *password;
    char *certFile;
    char *keyFile;
    char *pkiDir;
} SksSettings;

struct Built;

typedef struct {
    SecGroup *groups;
    size_t    groupCount;
    SksSettings sks;
    UA_UInt64 sksRetryCallbackId;
    UA_Server *server;
    /* Error recovery: the components the configuration enabled, and the
     * pending one-shot re-enable (see on_state_change). */
    struct Built *built;
    UA_Boolean recoveryPending;
    UA_UInt32  recoveryDelayMs;
    UA_DateTime lastErrorAt;
} PubSubRuntime;

static PubSubRuntime g_rt;

/* -------------------------------------------------------------------------
 * Small helpers
 * ---------------------------------------------------------------------- */

static void set_err(char *errBuf, size_t errLen, const char *fmt, const char *a,
                    UA_StatusCode sc) {
    char msg[384];
    snprintf(msg, sizeof(msg), fmt, a ? a : "");
    if (sc != UA_STATUSCODE_GOOD)
        snprintf(errBuf, errLen, "%s: %s", msg, UA_StatusCode_name(sc));
    else
        snprintf(errBuf, errLen, "%s", msg);
}

static char *ua_to_cstr(const UA_String *s) {
    char *r = (char *)malloc(s->length + 1);
    if (!r) return NULL;
    if (s->length) memcpy(r, s->data, s->length);
    r[s->length] = '\0';
    return r;
}

static UA_ByteString load_file(const char *path) {
    UA_ByteString bs = UA_BYTESTRING_NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return bs;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz > 0 && UA_ByteString_allocBuffer(&bs, (size_t)sz) == UA_STATUSCODE_GOOD) {
        if (fread(bs.data, 1, (size_t)sz, f) != (size_t)sz)
            UA_ByteString_clear(&bs);
    }
    fclose(f);
    return bs;
}

static const UA_DataType *eo_type(const UA_ExtensionObject *eo) {
    if (eo->encoding == UA_EXTENSIONOBJECT_DECODED ||
        eo->encoding == UA_EXTENSIONOBJECT_DECODED_NODELETE)
        return eo->content.decoded.type;
    return NULL;
}

static int eo_is(const UA_ExtensionObject *eo, int typeIndex) {
    return eo_type(eo) == &UA_TYPES[typeIndex];
}

static int eo_empty(const UA_ExtensionObject *eo) {
    return eo->encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY;
}

static int ua_streq(const UA_String *s, const char *c) {
    UA_String cs = UA_STRING((char *)(uintptr_t)c);
    return UA_String_equal(s, &cs);
}

/* -------------------------------------------------------------------------
 * JSON normalisation (1.05 in-situ ExtensionObjects -> UaBody form)
 * ---------------------------------------------------------------------- */

static void normalize_node(cJSON *node);

static void normalize_typeid(cJSON *typeIdItem) {
    if (!cJSON_IsString(typeIdItem)) return;
    UA_NodeId id;
    if (UA_NodeId_parse(&id, UA_STRING(typeIdItem->valuestring)) != UA_STATUSCODE_GOOD)
        return;
    for (size_t i = 0; i < UA_TYPES_COUNT; i++) {
        if (UA_NodeId_equal(&UA_TYPES[i].binaryEncodingId, &id) ||
            UA_NodeId_equal(&UA_TYPES[i].xmlEncodingId, &id)) {
            UA_String s = UA_STRING_NULL;
            if (UA_NodeId_print(&UA_TYPES[i].typeId, &s) == UA_STATUSCODE_GOOD) {
                char *c = ua_to_cstr(&s);
                if (c) cJSON_SetValuestring(typeIdItem, c);
                free(c);
            }
            UA_String_clear(&s);
            break;
        }
    }
    UA_NodeId_clear(&id);
}

static void normalize_object(cJSON *obj) {
    cJSON *typeId = cJSON_GetObjectItemCaseSensitive(obj, "UaTypeId");
    if (typeId) {
        normalize_typeid(typeId);
        if (!cJSON_GetObjectItemCaseSensitive(obj, "UaBody") &&
            !cJSON_GetObjectItemCaseSensitive(obj, "UaEncoding")) {
            /* Move every other member into a UaBody object */
            cJSON *body = cJSON_CreateObject();
            cJSON *child = obj->child;
            while (child) {
                cJSON *next = child->next;
                if (strcmp(child->string, "UaTypeId") != 0) {
                    cJSON_DetachItemViaPointer(obj, child);
                    cJSON_AddItemToObject(body, child->string, child);
                }
                child = next;
            }
            cJSON_AddItemToObject(obj, "UaBody", body);
        }
    }
    for (cJSON *c = obj->child; c; c = c->next)
        normalize_node(c);
}

static void normalize_node(cJSON *node) {
    if (cJSON_IsObject(node))
        normalize_object(node);
    else if (cJSON_IsArray(node))
        for (cJSON *c = node->child; c; c = c->next)
            normalize_node(c);
}

char *pubsub_normalize_json(const char *json, size_t len) {
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root) return NULL;
    normalize_node(root);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

UA_StatusCode pubsub_decode_json(const char *json, size_t len, void *dst,
                                 const UA_DataType *type,
                                 const UA_String *namespaceUris, size_t nsCount) {
    char *norm = pubsub_normalize_json(json, len);
    if (!norm) return UA_STATUSCODE_BADDECODINGERROR;

    UA_DecodeJsonOptions opts;
    memset(&opts, 0, sizeof(opts));
    UA_NamespaceMapping nsm;
    memset(&nsm, 0, sizeof(nsm));
    UA_UInt16 ident[256];
    for (size_t i = 0; i < 256; i++) ident[i] = (UA_UInt16)i;
    if (namespaceUris && nsCount > 0) {
        /* Indices are the server's own (identity); nsu= is resolved by URI */
        nsm.namespaceUris = (UA_String *)(uintptr_t)namespaceUris;
        nsm.namespaceUrisSize = nsCount;
        nsm.local2remote = ident;
        nsm.local2remoteSize = 256;
        nsm.remote2local = ident;
        nsm.remote2localSize = 256;
        opts.namespaceMapping = &nsm;
    }
    UA_ByteString doc = { strlen(norm), (UA_Byte *)norm };
    UA_StatusCode sc = UA_decodeJson(&doc, dst, type, &opts);
    free(norm);
    return sc;
}

/* -------------------------------------------------------------------------
 * Security groups
 * ---------------------------------------------------------------------- */

static SecGroup *find_group(const UA_String *id) {
    if (!id || id->length == 0) return NULL;
    for (size_t i = 0; i < g_rt.groupCount; i++)
        if (ua_streq(id, g_rt.groups[i].id))
            return &g_rt.groups[i];
    return NULL;
}

static int parse_security_groups(const cJSON *arr, char *errBuf, size_t errLen) {
    if (!arr) return 0;
    if (!cJSON_IsArray(arr)) {
        snprintf(errBuf, errLen, "securityGroups must be an array");
        return -1;
    }
    size_t n = (size_t)cJSON_GetArraySize(arr);
    g_rt.groups = (SecGroup *)calloc(n ? n : 1, sizeof(SecGroup));
    if (!g_rt.groups) { snprintf(errBuf, errLen, "out of memory"); return -1; }
    g_rt.groupCount = n;
    size_t gi = 0;
    const cJSON *g;
    cJSON_ArrayForEach(g, arr) {
        SecGroup *sg = &g_rt.groups[gi++];
        const cJSON *id  = cJSON_GetObjectItemCaseSensitive(g, "securityGroupId");
        const cJSON *pol = cJSON_GetObjectItemCaseSensitive(g, "securityPolicyUri");
        if (!cJSON_IsString(id) || !*id->valuestring) {
            snprintf(errBuf, errLen, "securityGroups[%zu].securityGroupId is required", gi - 1);
            return -1;
        }
        sg->id = strdup(id->valuestring);
        sg->policyUri = strdup(cJSON_IsString(pol) ? pol->valuestring : PUBSUB_POLICY_AES256CTR);
        const cJSON *v;
        v = cJSON_GetObjectItemCaseSensitive(g, "keyLifetimeMs");
        sg->keyLifetimeMs = cJSON_IsNumber(v) ? v->valuedouble : 60000.0;
        v = cJSON_GetObjectItemCaseSensitive(g, "maxFutureKeyCount");
        sg->maxFutureKeyCount = cJSON_IsNumber(v) ? (UA_UInt32)v->valuedouble : 2;
        v = cJSON_GetObjectItemCaseSensitive(g, "maxPastKeyCount");
        sg->maxPastKeyCount = cJSON_IsNumber(v) ? (UA_UInt32)v->valuedouble : 1;
        const cJSON *keys = cJSON_GetObjectItemCaseSensitive(g, "keys");
        if (keys && !cJSON_IsArray(keys)) {
            snprintf(errBuf, errLen, "securityGroups[%zu].keys must be an array", gi - 1);
            return -1;
        }
        size_t kn = keys ? (size_t)cJSON_GetArraySize(keys) : 0;
        if (kn > 0) {
            sg->keys = (StaticKey *)calloc(kn, sizeof(StaticKey));
            sg->keyCount = kn;
            size_t ki = 0;
            const cJSON *k;
            cJSON_ArrayForEach(k, keys) {
                const cJSON *tok = cJSON_GetObjectItemCaseSensitive(k, "tokenId");
                const cJSON *key = cJSON_GetObjectItemCaseSensitive(k, "key");
                if (!cJSON_IsNumber(tok) || !cJSON_IsString(key)) {
                    snprintf(errBuf, errLen, "securityGroups[%zu].keys[%zu] needs tokenId and key",
                             gi - 1, ki);
                    return -1;
                }
                size_t blen = 0;
                unsigned char *b = value_b64_decode(key->valuestring, &blen);
                if (!b) {
                    snprintf(errBuf, errLen, "securityGroups[%zu].keys[%zu].key is not Base64",
                             gi - 1, ki);
                    return -1;
                }
                sg->keys[ki].tokenId = (UA_UInt32)tok->valuedouble;
                UA_ByteString_allocBuffer(&sg->keys[ki].key, blen);
                memcpy(sg->keys[ki].key.data, b, blen);
                free(b);
                ki++;
            }
        }
    }
    return 0;
}

/* Split signingKey | encryptingKey | keyNonce by the policy's key lengths */
static UA_StatusCode split_key(UA_PubSubSecurityPolicy *sp, const UA_ByteString *key,
                               UA_ByteString *sig, UA_ByteString *enc, UA_ByteString *nonce) {
    size_t sl = sp->getSignatureKeyLength(sp, NULL);
    size_t el = sp->getEncryptionKeyLength(sp, NULL);
    if (key->length != sp->nonceLength || key->length < sl + el)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    sig->data = key->data;              sig->length = sl;
    enc->data = key->data + sl;         enc->length = el;
    nonce->data = key->data + sl + el;  nonce->length = key->length - sl - el;
    return UA_STATUSCODE_GOOD;
}

/* -------------------------------------------------------------------------
 * AddSecurityGroup / RemoveSecurityGroup (not bound to a callback by
 * open62541 v1.5.9 — the adapter binds them to UA_Server_addSecurityGroup /
 * UA_Server_removeSecurityGroup)
 * ---------------------------------------------------------------------- */

static UA_StatusCode
add_security_group_cb(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext,
                      const UA_NodeId *methodId, void *methodContext,
                      const UA_NodeId *objectId, void *objectContext,
                      size_t inputSize, const UA_Variant *input,
                      size_t outputSize, UA_Variant *output) {
    (void)sessionId; (void)sessionContext; (void)methodId; (void)methodContext;
    (void)objectContext;
    if (inputSize < 5 || outputSize < 2)
        return UA_STATUSCODE_BADARGUMENTSMISSING;
    if (inputSize > 5)
        return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    if (!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_STRING]) ||
        !(UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_DURATION]) ||
          UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_DOUBLE])) ||
        !UA_Variant_hasScalarType(&input[2], &UA_TYPES[UA_TYPES_STRING]) ||
        !UA_Variant_hasScalarType(&input[3], &UA_TYPES[UA_TYPES_UINT32]) ||
        !UA_Variant_hasScalarType(&input[4], &UA_TYPES[UA_TYPES_UINT32]))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    UA_SecurityGroupConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.securityGroupName = *(UA_String *)input[0].data;
    cfg.keyLifeTime       = *(UA_Double *)input[1].data;
    cfg.securityPolicyUri = *(UA_String *)input[2].data;
    cfg.maxFutureKeyCount = *(UA_UInt32 *)input[3].data;
    cfg.maxPastKeyCount   = *(UA_UInt32 *)input[4].data;
    if (cfg.securityGroupName.length == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_NodeId nodeId = UA_NODEID_NULL;
    UA_StatusCode sc = UA_Server_addSecurityGroup(server, *objectId, &cfg, &nodeId);
    if (sc != UA_STATUSCODE_GOOD)
        return sc;
    /* SecurityGroupId = the name (open62541 uses the name as the id) */
    UA_Variant_setScalarCopy(&output[0], &cfg.securityGroupName, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalarCopy(&output[1], &nodeId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_NodeId_clear(&nodeId);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
remove_security_group_cb(UA_Server *server, const UA_NodeId *sessionId, void *sessionContext,
                         const UA_NodeId *methodId, void *methodContext,
                         const UA_NodeId *objectId, void *objectContext,
                         size_t inputSize, const UA_Variant *input,
                         size_t outputSize, UA_Variant *output) {
    (void)sessionId; (void)sessionContext; (void)methodId; (void)methodContext;
    (void)objectId; (void)objectContext; (void)outputSize; (void)output;
    if (inputSize < 1) return UA_STATUSCODE_BADARGUMENTSMISSING;
    if (inputSize > 1) return UA_STATUSCODE_BADTOOMANYARGUMENTS;
    if (!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_NODEID]))
        return UA_STATUSCODE_BADTYPEMISMATCH;
    UA_StatusCode sc = UA_Server_removeSecurityGroup(server, *(UA_NodeId *)input[0].data);
    return sc == UA_STATUSCODE_BADNOTFOUND ? UA_STATUSCODE_BADNODEIDUNKNOWN : sc;
}

UA_StatusCode pubsub_server_prepare_config(UA_ServerConfig *cfg) {
    return adapter_pubsub_install_security_policies(cfg);
}

UA_StatusCode pubsub_server_init(UA_Server *server) {
    g_rt.server = server;
    UA_StatusCode sc = UA_STATUSCODE_GOOD;

    /* AddSecurityGroup / RemoveSecurityGroup on PublishSubscribe.SecurityGroups
     * and on the SecurityGroupFolderType declaration (sub-folders). */
    static const UA_UInt32 addIds[] = {
        UA_NS0ID_PUBLISHSUBSCRIBE_SECURITYGROUPS_ADDSECURITYGROUP,
        UA_NS0ID_SECURITYGROUPFOLDERTYPE_ADDSECURITYGROUP };
    static const UA_UInt32 rmIds[] = {
        UA_NS0ID_PUBLISHSUBSCRIBE_SECURITYGROUPS_REMOVESECURITYGROUP,
        UA_NS0ID_SECURITYGROUPFOLDERTYPE_REMOVESECURITYGROUP };
    for (size_t i = 0; i < 2; i++) {
        UA_StatusCode a = UA_Server_setMethodNodeCallback(
            server, UA_NODEID_NUMERIC(0, addIds[i]), add_security_group_cb);
        UA_StatusCode r = UA_Server_setMethodNodeCallback(
            server, UA_NODEID_NUMERIC(0, rmIds[i]), remove_security_group_cb);
        if (a != UA_STATUSCODE_GOOD || r != UA_STATUSCODE_GOOD) {
            fprintf(stderr, LOG_PREFIX "warn: binding AddSecurityGroup/RemoveSecurityGroup "
                    "(i=%" PRIu32 "): %s / %s\n", addIds[i],
                    UA_StatusCode_name(a), UA_StatusCode_name(r));
            sc = a != UA_STATUSCODE_GOOD ? a : r;
        }
    }

    /* PublishSubscribe.SupportedTransportProfiles: open62541 only lists
     * pubsub-udp-uadp although it is built with MQTT. */
    UA_String profiles[3] = { UA_STRING(PROFILE_UDP_UADP), UA_STRING(PROFILE_MQTT_UADP),
                              UA_STRING(PROFILE_MQTT_JSON) };
    UA_Variant v;
    UA_Variant_setArray(&v, profiles, 3, &UA_TYPES[UA_TYPES_STRING]);
    UA_StatusCode wsc = UA_Server_writeValue(
        server, UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_SUPPORTEDTRANSPORTPROFILES), v);
    if (wsc != UA_STATUSCODE_GOOD)
        fprintf(stderr, LOG_PREFIX "warn: SupportedTransportProfiles: %s\n",
                UA_StatusCode_name(wsc));
    return sc;
}

/* -------------------------------------------------------------------------
 * SKS client (pull)
 * ---------------------------------------------------------------------- */

static void activate_keys_for_group(UA_Server *server, const UA_String *groupId);

static void sks_pull_cb(UA_Server *server, UA_StatusCode status, void *context) {
    SecGroup *sg = (SecGroup *)context;
    sg->sksInFlight = 0;
    fprintf(stderr, LOG_PREFIX "info: pubsub: SKS pull for SecurityGroup '%s': %s\n",
            sg->id, UA_StatusCode_name(status));
    if (status != UA_STATUSCODE_GOOD) return;
    sg->sksKeysReceived = 1;
    UA_String gid = UA_STRING(sg->id);
    activate_keys_for_group(server, &gid);
}

static UA_ByteString *load_trust_list(const char *pkiDir, size_t *count) {
    *count = 0;
    if (!pkiDir || !*pkiDir) return NULL;
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/trusted/certs", pkiDir);
    DIR *d = opendir(dir);
    if (!d) return NULL;
    UA_ByteString *list = NULL;
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[1400];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        UA_ByteString bs = load_file(path);
        if (bs.length == 0) continue;
        UA_ByteString *tmp = (UA_ByteString *)realloc(list, (n + 1) * sizeof(UA_ByteString));
        if (!tmp) { UA_ByteString_clear(&bs); break; }
        list = tmp;
        list[n++] = bs;
    }
    closedir(d);
    *count = n;
    return list;
}

static const char *policy_uri_from_name(const char *name) {
    if (!name || !*name) return "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
    if (strncmp(name, "http://", 7) == 0) return name;
    static char buf[256];
    snprintf(buf, sizeof(buf), "http://opcfoundation.org/UA/SecurityPolicy#%s", name);
    return buf;
}

static char *json_strdup(const cJSON *o, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return cJSON_IsString(v) ? strdup(v->valuestring) : NULL;
}

/* Validate and keep the "sksClient" settings (fatal errors only here) */
static int parse_sks_client(const cJSON *sks, const PubSubOptions *opt,
                            char *errBuf, size_t errLen) {
    SksSettings *k = &g_rt.sks;
    if (!cJSON_IsObject(sks)) {
        snprintf(errBuf, errLen, "sksClient must be an object");
        return -1;
    }
    k->endpointUrl = json_strdup(sks, "endpointUrl");
    k->policy      = json_strdup(sks, "securityPolicyUri");
    k->mode        = json_strdup(sks, "securityMode");
    k->username    = json_strdup(sks, "username");
    k->password    = json_strdup(sks, "password");
    if (!k->endpointUrl) {
        snprintf(errBuf, errLen, "sksClient.endpointUrl is required");
        return -1;
    }
    if (!opt->certFile || !opt->keyFile) {
        snprintf(errBuf, errLen, "sksClient needs the server's --certificate and --private-key "
                 "(GetSecurityKeys requires a SignAndEncrypt channel)");
        return -1;
    }
    k->certFile = strdup(opt->certFile);
    k->keyFile  = strdup(opt->keyFile);
    k->pkiDir   = opt->pkiDir ? strdup(opt->pkiDir) : NULL;
    return 0;
}

/* One GetSecurityKeys attempt for a group (asynchronous; the result arrives
 * in sks_pull_cb). Failures are logged and retried by sks_retry_cb. */
static void sks_attempt(UA_Server *server, SecGroup *sg) {
    SksSettings *k = &g_rt.sks;
    UA_ByteString cert = load_file(k->certFile);
    UA_ByteString key  = load_file(k->keyFile);
    if (cert.length == 0 || key.length == 0) {
        UA_ByteString_clear(&cert); UA_ByteString_clear(&key);
        fprintf(stderr, LOG_PREFIX "warn: pubsub: SKS client: cannot read the certificate / key\n");
        return;
    }
    size_t trustCount = 0;
    UA_ByteString *trust = load_trust_list(k->pkiDir, &trustCount);

    UA_ClientConfig cc;
    memset(&cc, 0, sizeof(cc));
    UA_StatusCode sc = UA_ClientConfig_setDefaultEncryption(&cc, cert, key, trust,
                                                            trustCount, NULL, 0);
    for (size_t i = 0; i < trustCount; i++) UA_ByteString_clear(&trust[i]);
    free(trust);
    UA_ByteString_clear(&cert);
    UA_ByteString_clear(&key);
    if (sc != UA_STATUSCODE_GOOD) {
        UA_ClientConfig_clear(&cc);
        fprintf(stderr, LOG_PREFIX "warn: pubsub: SKS client encryption setup: %s\n",
                UA_StatusCode_name(sc));
        return;
    }
    UA_String_clear(&cc.securityPolicyUri);
    cc.securityPolicyUri = UA_STRING_ALLOC(policy_uri_from_name(k->policy));
    cc.securityMode = (k->mode && strcmp(k->mode, "Sign") == 0)
        ? UA_MESSAGESECURITYMODE_SIGN : UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    char *san = cli_certificate_san_uri(k->certFile);
    if (san) {
        UA_String_clear(&cc.clientDescription.applicationUri);
        cc.clientDescription.applicationUri = UA_STRING_ALLOC(san);
        free(san);
    }
    if (k->username) {
        UA_UserNameIdentityToken tok;
        UA_UserNameIdentityToken_init(&tok);
        tok.userName = UA_STRING_ALLOC(k->username);
        tok.password = UA_BYTESTRING_ALLOC(k->password ? k->password : "");
        UA_ExtensionObject_clear(&cc.userIdentityToken);
        UA_ExtensionObject_setValueCopy(&cc.userIdentityToken, &tok,
                                        &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
        UA_UserNameIdentityToken_clear(&tok);
    }

    sg->sksInFlight = 1;
    UA_String gid = UA_STRING(sg->id);
    /* The endpoint URL is referenced (not copied) by the keystorage */
    sc = UA_Server_setSksClient(server, gid, &cc, k->endpointUrl, sks_pull_cb, sg);
    if (sc != UA_STATUSCODE_GOOD) {
        sg->sksInFlight = 0;
        fprintf(stderr, LOG_PREFIX "warn: pubsub: SKS pull for SecurityGroup '%s' from %s: %s "
                "(retrying)\n", sg->id, k->endpointUrl, UA_StatusCode_name(sc));
    }
}

/* Until the first keys arrived: retry GetSecurityKeys every 2 s (the SKS may
 * start after this server). Later refreshes are done by open62541 itself
 * (GetSecurityKeys at half the KeyLifetime). */
static void sks_retry_cb(UA_Server *server, void *data) {
    (void)data;
    for (size_t i = 0; i < g_rt.groupCount; i++) {
        SecGroup *sg = &g_rt.groups[i];
        if (sg->source != KEYSRC_SKS_CLIENT || sg->sksKeysReceived || sg->sksInFlight)
            continue;
        sks_attempt(server, sg);
    }
}

/* -------------------------------------------------------------------------
 * Key activation
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_NodeId id;
    int       isWriter;
    UA_String groupId;   /* borrowed from the decoded configuration */
} SecuredGroup;

#define MAX_SECURED 64
static SecuredGroup g_secured[MAX_SECURED];
static size_t g_securedCount;

static void activate_keys_for_group(UA_Server *server, const UA_String *groupId) {
    for (size_t i = 0; i < g_securedCount; i++) {
        SecuredGroup *s = &g_secured[i];
        if (!UA_String_equal(&s->groupId, groupId)) continue;
        UA_StatusCode sc = s->isWriter
            ? UA_Server_setWriterGroupActivateKey(server, s->id)
            : UA_Server_setReaderGroupActivateKey(server, s->id);
        if (sc != UA_STATUSCODE_GOOD)
            fprintf(stderr, LOG_PREFIX "warn: pubsub: activating keys: %s\n",
                    UA_StatusCode_name(sc));
    }
}

static int apply_group_keys(UA_Server *server, const UA_NodeId *id, int isWriter,
                            SecGroup *sg, UA_PubSubSecurityPolicy *sp,
                            char *errBuf, size_t errLen) {
    if (g_securedCount < MAX_SECURED) {
        g_secured[g_securedCount].id = *id;
        g_secured[g_securedCount].isWriter = isWriter;
        g_secured[g_securedCount].groupId = UA_STRING(sg->id);
        g_securedCount++;
    }
    if (sg->source == KEYSRC_STATIC) {
        /* The first key is the current one (static keys do not roll over) */
        UA_ByteString sig, enc, nonce;
        UA_StatusCode sc = split_key(sp, &sg->keys[0].key, &sig, &enc, &nonce);
        if (sc != UA_STATUSCODE_GOOD) {
            char msg[256];
            snprintf(msg, sizeof(msg), "SecurityGroup '%s': key length %zu does not match "
                     "%s (%zu bytes: signingKey|encryptingKey|keyNonce)", sg->id,
                     sg->keys[0].key.length, sg->policyUri, sp->nonceLength);
            snprintf(errBuf, errLen, "%s", msg);
            return -1;
        }
        sc = isWriter
            ? UA_Server_setWriterGroupEncryptionKeys(server, *id, sg->keys[0].tokenId, sig, enc, nonce)
            : UA_Server_setReaderGroupEncryptionKeys(server, *id, sg->keys[0].tokenId, sig, enc, nonce);
        if (sc != UA_STATUSCODE_GOOD) {
            set_err(errBuf, errLen, "setting the static keys of SecurityGroup '%s'", sg->id, sc);
            return -1;
        }
    } else if (sg->source == KEYSRC_SKS_SERVER) {
        UA_StatusCode sc = isWriter ? UA_Server_setWriterGroupActivateKey(server, *id)
                                    : UA_Server_setReaderGroupActivateKey(server, *id);
        if (sc != UA_STATUSCODE_GOOD) {
            set_err(errBuf, errLen, "activating the SKS keys of SecurityGroup '%s'", sg->id, sc);
            return -1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Configuration -> open62541 API
 * ---------------------------------------------------------------------- */

typedef struct {
    UA_NodeId      id;
    int            enabled;
    UA_PubSubState state; /* last state reported by stateChangeCallback */
} Created;

#define MAX_COMPONENTS 256
typedef struct Built {
    Created connections[MAX_COMPONENTS]; size_t nConn;
    Created writerGroups[MAX_COMPONENTS]; size_t nWg;
    Created writers[MAX_COMPONENTS];      size_t nDsw;
    Created readerGroups[MAX_COMPONENTS]; size_t nRg;
    Created readers[MAX_COMPONENTS];      size_t nDsr;
    UA_NodeId pds[MAX_COMPONENTS];        UA_String pdsName[MAX_COMPONENTS]; size_t nPds;
} Built;

static int add_published_datasets(UA_Server *server, const UA_PubSubConfigurationDataType *c,
                                  Built *b, char *errBuf, size_t errLen) {
    for (size_t i = 0; i < c->publishedDataSetsSize && b->nPds < MAX_COMPONENTS; i++) {
        const UA_PublishedDataSetDataType *p = &c->publishedDataSets[i];
        char *name = ua_to_cstr(&p->name);
        if (!eo_is(&p->dataSetSource, UA_TYPES_PUBLISHEDDATAITEMSDATATYPE)) {
            set_err(errBuf, errLen, "PublishedDataSet '%s': only PublishedDataItemsDataType "
                    "sources are supported (PublishedEvents is not implemented by open62541 1.5.9)",
                    name, UA_STATUSCODE_BADNOTIMPLEMENTED);
            free(name);
            return -1;
        }
        const UA_PublishedDataItemsDataType *items =
            (const UA_PublishedDataItemsDataType *)p->dataSetSource.content.decoded.data;

        UA_PublishedDataSetConfig pc;
        memset(&pc, 0, sizeof(pc));
        pc.name = p->name;
        pc.publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS;
        UA_NodeId pdsId;
        UA_AddPublishedDataSetResult r = UA_Server_addPublishedDataSet(server, &pc, &pdsId);
        if (r.addResult != UA_STATUSCODE_GOOD) {
            set_err(errBuf, errLen, "UA_Server_addPublishedDataSet('%s')", name, r.addResult);
            free(name);
            return -1;
        }
        b->pds[b->nPds] = pdsId;
        b->pdsName[b->nPds] = p->name;
        b->nPds++;

        for (size_t f = 0; f < items->publishedDataSize; f++) {
            UA_DataSetFieldConfig fc;
            memset(&fc, 0, sizeof(fc));
            fc.dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
            char alias[32];
            snprintf(alias, sizeof(alias), "Field%zu", f);
            if (f < p->dataSetMetaData.fieldsSize) {
                const UA_FieldMetaData *fm = &p->dataSetMetaData.fields[f];
                fc.field.variable.fieldNameAlias = fm->name;
                fc.field.variable.promotedField = (fm->fieldFlags & 0x0001) != 0;
                fc.field.variable.maxStringLength = fm->maxStringLength;
                fc.field.variable.description = fm->description;
                fc.field.variable.dataSetFieldId = fm->dataSetFieldId;
            } else {
                fc.field.variable.fieldNameAlias = UA_STRING(alias);
            }
            fc.field.variable.configurationVersion = p->dataSetMetaData.configurationVersion;
            fc.field.variable.publishParameters = items->publishedData[f];
            if (fc.field.variable.publishParameters.attributeId == 0)
                fc.field.variable.publishParameters.attributeId = UA_ATTRIBUTEID_VALUE;
            UA_DataSetFieldResult fr = UA_Server_addDataSetField(server, pdsId, &fc, NULL);
            if (fr.result != UA_STATUSCODE_GOOD) {
                char what[256];
                snprintf(what, sizeof(what), "%s field %zu", name, f);
                set_err(errBuf, errLen, "UA_Server_addDataSetField(%s)", what, fr.result);
                free(name);
                return -1;
            }
        }
        fprintf(stderr, LOG_PREFIX "info: pubsub: PublishedDataSet '%s' (%zu fields)\n",
                name, items->publishedDataSize);
        free(name);
    }
    return 0;
}

static const UA_NodeId *find_pds(const Built *b, const UA_String *name) {
    for (size_t i = 0; i < b->nPds; i++)
        if (UA_String_equal(&b->pdsName[i], name))
            return &b->pds[i];
    return NULL;
}

static int resolve_security(UA_Server *server, const char *what, UA_MessageSecurityMode mode,
                            const UA_String *groupId, SecGroup **sgOut,
                            UA_PubSubSecurityPolicy **spOut, char *errBuf, size_t errLen) {
    *sgOut = NULL;
    *spOut = NULL;
    if (mode != UA_MESSAGESECURITYMODE_SIGN && mode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return 0;
    SecGroup *sg = find_group(groupId);
    if (!sg) {
        char *g = ua_to_cstr(groupId);
        char msg[300];
        snprintf(msg, sizeof(msg), "%s: SecurityMode needs a SecurityGroupId listed in "
                 "\"securityGroups\" (got '%s')", what, g ? g : "");
        free(g);
        snprintf(errBuf, errLen, "%s", msg);
        return -1;
    }
    UA_PubSubSecurityPolicy *sp =
        adapter_pubsub_find_policy(UA_Server_getConfig(server), sg->policyUri);
    if (!sp) {
        set_err(errBuf, errLen, "unsupported PubSub securityPolicyUri '%s'", sg->policyUri,
                UA_STATUSCODE_BADSECURITYPOLICYREJECTED);
        return -1;
    }
    *sgOut = sg;
    *spOut = sp;
    return 0;
}

static int is_json_profile(const UA_String *profile) {
    return ua_streq(profile, PROFILE_MQTT_JSON);
}

static int add_writer_group(UA_Server *server, const UA_NodeId connId,
                            const UA_PubSubConnectionDataType *conn,
                            const UA_WriterGroupDataType *w, Built *b,
                            char *errBuf, size_t errLen) {
    char *name = ua_to_cstr(&w->name);
    UA_WriterGroupConfig wc;
    memset(&wc, 0, sizeof(wc));
    wc.name = w->name;
    wc.writerGroupId = w->writerGroupId;
    wc.publishingInterval = w->publishingInterval;
    wc.keepAliveTime = w->keepAliveTime;
    wc.priority = w->priority;
    wc.transportSettings = w->transportSettings;
    wc.messageSettings = w->messageSettings;
    wc.groupProperties.map = w->groupProperties;
    wc.groupProperties.mapSize = w->groupPropertiesSize;
    wc.maxEncapsulatedDataSetMessageCount = 255;
    wc.securityMode = w->securityMode;
    wc.securityGroupId = w->securityGroupId;
    if (eo_is(&w->messageSettings, UA_TYPES_JSONWRITERGROUPMESSAGEDATATYPE) ||
        (eo_empty(&w->messageSettings) && is_json_profile(&conn->transportProfileUri)))
        wc.encodingMimeType = UA_PUBSUB_ENCODING_JSON;
    else
        wc.encodingMimeType = UA_PUBSUB_ENCODING_UADP;
    if (wc.securityMode == UA_MESSAGESECURITYMODE_INVALID)
        wc.securityMode = UA_MESSAGESECURITYMODE_NONE;

    SecGroup *sg; UA_PubSubSecurityPolicy *sp;
    char what[300];
    snprintf(what, sizeof(what), "WriterGroup '%s'", name);
    if (resolve_security(server, what, wc.securityMode, &w->securityGroupId, &sg, &sp,
                         errBuf, errLen) != 0) {
        free(name);
        return -1;
    }
    wc.securityPolicy = sp;

    UA_NodeId wgId;
    UA_StatusCode sc = UA_Server_addWriterGroup(server, connId, &wc, &wgId);
    if (sc != UA_STATUSCODE_GOOD) {
        set_err(errBuf, errLen, "UA_Server_addWriterGroup('%s')", name, sc);
        free(name);
        return -1;
    }
    if (b->nWg < MAX_COMPONENTS) {
        b->writerGroups[b->nWg].id = wgId;
        b->writerGroups[b->nWg].enabled = w->enabled;
        b->nWg++;
    }
    if (sg && apply_group_keys(server, &wgId, 1, sg, sp, errBuf, errLen) != 0) {
        free(name);
        return -1;
    }

    for (size_t i = 0; i < w->dataSetWritersSize; i++) {
        const UA_DataSetWriterDataType *d = &w->dataSetWriters[i];
        char *dname = ua_to_cstr(&d->name);
        UA_NodeId pdsId = UA_NODEID_NULL;
        if (d->dataSetName.length > 0) {
            const UA_NodeId *p = find_pds(b, &d->dataSetName);
            if (!p) {
                char *ds = ua_to_cstr(&d->dataSetName);
                char msg[300];
                snprintf(msg, sizeof(msg), "DataSetWriter '%s': no PublishedDataSet named '%s'",
                         dname, ds ? ds : "");
                free(ds);
                snprintf(errBuf, errLen, "%s", msg);
                free(dname); free(name);
                return -1;
            }
            pdsId = *p;
        }
        UA_DataSetWriterConfig dc;
        memset(&dc, 0, sizeof(dc));
        dc.name = d->name;
        dc.dataSetWriterId = d->dataSetWriterId;
        dc.dataSetFieldContentMask = d->dataSetFieldContentMask;
        dc.keyFrameCount = d->keyFrameCount;
        dc.messageSettings = d->messageSettings;
        dc.transportSettings = d->transportSettings;
        dc.dataSetName = d->dataSetName;
        dc.dataSetWriterProperties.map = d->dataSetWriterProperties;
        dc.dataSetWriterProperties.mapSize = d->dataSetWriterPropertiesSize;
        UA_NodeId dswId;
        sc = UA_Server_addDataSetWriter(server, wgId, pdsId, &dc, &dswId);
        if (sc != UA_STATUSCODE_GOOD) {
            set_err(errBuf, errLen, "UA_Server_addDataSetWriter('%s')", dname, sc);
            free(dname); free(name);
            return -1;
        }
        if (b->nDsw < MAX_COMPONENTS) {
            b->writers[b->nDsw].id = dswId;
            b->writers[b->nDsw].enabled = d->enabled;
            b->nDsw++;
        }
        fprintf(stderr, LOG_PREFIX "info: pubsub:   DataSetWriter '%s' id=%u\n",
                dname, (unsigned)d->dataSetWriterId);
        free(dname);
    }
    fprintf(stderr, LOG_PREFIX "info: pubsub:  WriterGroup '%s' id=%u %s interval=%.0fms "
            "security=%d%s%s\n", name, (unsigned)w->writerGroupId,
            wc.encodingMimeType == UA_PUBSUB_ENCODING_JSON ? "JSON" : "UADP",
            w->publishingInterval, (int)wc.securityMode,
            sg ? " group=" : "", sg ? sg->id : "");
    free(name);
    return 0;
}

static int add_reader_group(UA_Server *server, const UA_NodeId connId,
                            const UA_PubSubConnectionDataType *conn,
                            const UA_ReaderGroupDataType *r, Built *b,
                            char *errBuf, size_t errLen) {
    char *name = ua_to_cstr(&r->name);
    UA_ReaderGroupConfig rc;
    memset(&rc, 0, sizeof(rc));
    rc.name = r->name;
    rc.securityMode = r->securityMode;
    if (rc.securityMode == UA_MESSAGESECURITYMODE_INVALID)
        rc.securityMode = UA_MESSAGESECURITYMODE_NONE;
    rc.securityGroupId = r->securityGroupId;
    rc.groupProperties.map = r->groupProperties;
    rc.groupProperties.mapSize = r->groupPropertiesSize;

    /* Encoding: the transport profile, or the readers' message settings */
    rc.encodingMimeType = is_json_profile(&conn->transportProfileUri)
        ? UA_PUBSUB_ENCODING_JSON : UA_PUBSUB_ENCODING_UADP;
    if (r->dataSetReadersSize > 0 &&
        eo_is(&r->dataSetReaders[0].messageSettings, UA_TYPES_JSONDATASETREADERMESSAGEDATATYPE))
        rc.encodingMimeType = UA_PUBSUB_ENCODING_JSON;

    /* Broker transport: open62541 subscribes one topic per ReaderGroup. Take
     * the ReaderGroup's own TransportSettings if they are broker settings,
     * otherwise the BrokerDataSetReaderTransportDataType of the readers (all
     * readers of the group must name the same QueueName). */
    if (eo_is(&r->transportSettings, UA_TYPES_BROKERDATASETREADERTRANSPORTDATATYPE)) {
        rc.transportSettings = r->transportSettings;
    } else {
        const UA_BrokerDataSetReaderTransportDataType *first = NULL;
        for (size_t i = 0; i < r->dataSetReadersSize; i++) {
            const UA_ExtensionObject *ts = &r->dataSetReaders[i].transportSettings;
            if (!eo_is(ts, UA_TYPES_BROKERDATASETREADERTRANSPORTDATATYPE)) continue;
            const UA_BrokerDataSetReaderTransportDataType *bt =
                (const UA_BrokerDataSetReaderTransportDataType *)ts->content.decoded.data;
            if (!first) {
                first = bt;
                rc.transportSettings = *ts;
            } else if (!UA_String_equal(&first->queueName, &bt->queueName)) {
                set_err(errBuf, errLen, "ReaderGroup '%s': open62541 subscribes one QueueName per "
                        "ReaderGroup; put DataSetReaders with different QueueNames into separate "
                        "ReaderGroups", name, UA_STATUSCODE_BADCONFIGURATIONERROR);
                free(name);
                return -1;
            }
        }
    }

    SecGroup *sg; UA_PubSubSecurityPolicy *sp;
    char what[300];
    snprintf(what, sizeof(what), "ReaderGroup '%s'", name);
    if (resolve_security(server, what, rc.securityMode, &r->securityGroupId, &sg, &sp,
                         errBuf, errLen) != 0) {
        free(name);
        return -1;
    }
    rc.securityPolicy = sp;

    UA_NodeId rgId;
    UA_StatusCode sc = UA_Server_addReaderGroup(server, connId, &rc, &rgId);
    if (sc != UA_STATUSCODE_GOOD) {
        set_err(errBuf, errLen, "UA_Server_addReaderGroup('%s')", name, sc);
        free(name);
        return -1;
    }
    if (b->nRg < MAX_COMPONENTS) {
        b->readerGroups[b->nRg].id = rgId;
        b->readerGroups[b->nRg].enabled = r->enabled;
        b->nRg++;
    }
    if (sg && apply_group_keys(server, &rgId, 0, sg, sp, errBuf, errLen) != 0) {
        free(name);
        return -1;
    }

    for (size_t i = 0; i < r->dataSetReadersSize; i++) {
        const UA_DataSetReaderDataType *d = &r->dataSetReaders[i];
        char *dname = ua_to_cstr(&d->name);
        UA_DataSetReaderConfig dc;
        memset(&dc, 0, sizeof(dc));
        dc.name = d->name;
        if (!UA_Variant_isEmpty(&d->publisherId)) {
            sc = UA_PublisherId_fromVariant(&dc.publisherId, &d->publisherId);
            if (sc != UA_STATUSCODE_GOOD) {
                set_err(errBuf, errLen, "DataSetReader '%s': PublisherId must be a Byte, UInt16, "
                        "UInt32, UInt64 or String scalar", dname, sc);
                free(dname); free(name);
                return -1;
            }
        }
        dc.writerGroupId = d->writerGroupId;
        dc.dataSetWriterId = d->dataSetWriterId;
        dc.dataSetMetaData = d->dataSetMetaData;
        dc.dataSetFieldContentMask = d->dataSetFieldContentMask;
        dc.messageReceiveTimeout = d->messageReceiveTimeout;
        dc.messageSettings = d->messageSettings;
        dc.transportSettings = d->transportSettings;
        dc.subscribedDataSetType = UA_PUBSUB_SDS_TARGET;

        const UA_TargetVariablesDataType *tv = NULL;
        if (eo_is(&d->subscribedDataSet, UA_TYPES_TARGETVARIABLESDATATYPE)) {
            tv = (const UA_TargetVariablesDataType *)d->subscribedDataSet.content.decoded.data;
        } else if (eo_is(&d->subscribedDataSet, UA_TYPES_SUBSCRIBEDDATASETMIRRORDATATYPE)) {
            set_err(errBuf, errLen, "DataSetReader '%s': SubscribedDataSetMirror is not implemented "
                    "by open62541 1.5.9; use TargetVariables", dname,
                    UA_STATUSCODE_BADNOTIMPLEMENTED);
            UA_PublisherId_clear(&dc.publisherId);
            free(dname); free(name);
            return -1;
        } else if (!eo_empty(&d->subscribedDataSet)) {
            set_err(errBuf, errLen, "DataSetReader '%s': SubscribedDataSet must be a "
                    "TargetVariablesDataType", dname, UA_STATUSCODE_BADTYPEMISMATCH);
            UA_PublisherId_clear(&dc.publisherId);
            free(dname); free(name);
            return -1;
        }

        UA_NodeId dsrId;
        sc = UA_Server_addDataSetReader(server, rgId, &dc, &dsrId);
        UA_PublisherId_clear(&dc.publisherId);
        if (sc != UA_STATUSCODE_GOOD) {
            set_err(errBuf, errLen, "UA_Server_addDataSetReader('%s')", dname, sc);
            free(dname); free(name);
            return -1;
        }
        if (tv && tv->targetVariablesSize > 0) {
            /* open62541 maps TargetVariables[i] to DataSetMetaData.Fields[i]
             * (the DataSetFieldId of the FieldTargetDataType is not used). */
            sc = UA_Server_setDataSetReaderTargetVariables(server, dsrId,
                                                           tv->targetVariablesSize,
                                                           tv->targetVariables);
            if (sc != UA_STATUSCODE_GOOD) {
                set_err(errBuf, errLen, "DataSetReader '%s': TargetVariables", dname, sc);
                free(dname); free(name);
                return -1;
            }
        }
        if (b->nDsr < MAX_COMPONENTS) {
            b->readers[b->nDsr].id = dsrId;
            b->readers[b->nDsr].enabled = d->enabled;
            b->nDsr++;
        }
        fprintf(stderr, LOG_PREFIX "info: pubsub:   DataSetReader '%s' writerGroupId=%u "
                "dataSetWriterId=%u targets=%zu timeout=%.0fms\n", dname,
                (unsigned)d->writerGroupId, (unsigned)d->dataSetWriterId,
                tv ? tv->targetVariablesSize : 0, d->messageReceiveTimeout);
        free(dname);
    }
    fprintf(stderr, LOG_PREFIX "info: pubsub:  ReaderGroup '%s' %s security=%d%s%s\n", name,
            rc.encodingMimeType == UA_PUBSUB_ENCODING_JSON ? "JSON" : "UADP",
            (int)rc.securityMode, sg ? " group=" : "", sg ? sg->id : "");
    free(name);
    return 0;
}

static int add_connections(UA_Server *server, const UA_PubSubConfigurationDataType *c,
                           Built *b, char *errBuf, size_t errLen) {
    for (size_t i = 0; i < c->connectionsSize; i++) {
        const UA_PubSubConnectionDataType *conn = &c->connections[i];
        char *name = ua_to_cstr(&conn->name);
        if (!eo_is(&conn->address, UA_TYPES_NETWORKADDRESSURLDATATYPE)) {
            set_err(errBuf, errLen, "PubSubConnection '%s': Address must be a "
                    "NetworkAddressUrlDataType", name, UA_STATUSCODE_BADTYPEMISMATCH);
            free(name);
            return -1;
        }
        /* Part 14 names the MQTT scheme mqtt:// (mqtts:// with TLS);
         * open62541 v1.5.9 only parses opc.mqtt://. Translate. */
        UA_NetworkAddressUrlDataType addrCopy;
        UA_NetworkAddressUrlDataType_copy(
            (const UA_NetworkAddressUrlDataType *)conn->address.content.decoded.data, &addrCopy);
        if (addrCopy.url.length > 7 && strncmp((const char *)addrCopy.url.data, "mqtt://", 7) == 0) {
            char *rest = ua_to_cstr(&addrCopy.url);
            char buf[512];
            snprintf(buf, sizeof(buf), "opc.mqtt://%s", rest + 7);
            free(rest);
            UA_String_clear(&addrCopy.url);
            addrCopy.url = UA_STRING_ALLOC(buf);
        } else if (addrCopy.url.length > 8 &&
                   strncmp((const char *)addrCopy.url.data, "mqtts://", 8) == 0) {
            UA_NetworkAddressUrlDataType_clear(&addrCopy);
            set_err(errBuf, errLen, "PubSubConnection '%s': mqtts:// (MQTT over TLS) is not "
                    "supported by open62541 1.5.9", name, UA_STATUSCODE_BADNOTSUPPORTED);
            free(name);
            return -1;
        }
        UA_PubSubConnectionConfig cc;
        memset(&cc, 0, sizeof(cc));
        cc.name = conn->name;
        cc.transportProfileUri = conn->transportProfileUri;
        UA_Variant_setScalar(&cc.address, &addrCopy,
                             &UA_TYPES[UA_TYPES_NETWORKADDRESSURLDATATYPE]);
        cc.connectionProperties.map = conn->connectionProperties;
        cc.connectionProperties.mapSize = conn->connectionPropertiesSize;
        if (eo_type(&conn->transportSettings))
            UA_Variant_setScalar(&cc.connectionTransportSettings,
                                 conn->transportSettings.content.decoded.data,
                                 conn->transportSettings.content.decoded.type);
        if (!UA_Variant_isEmpty(&conn->publisherId)) {
            UA_StatusCode psc = UA_PublisherId_fromVariant(&cc.publisherId, &conn->publisherId);
            if (psc != UA_STATUSCODE_GOOD) {
                set_err(errBuf, errLen, "PubSubConnection '%s': PublisherId must be a Byte, "
                        "UInt16, UInt32, UInt64 or String scalar", name, psc);
                UA_NetworkAddressUrlDataType_clear(&addrCopy);
                free(name);
                return -1;
            }
        }
        UA_NodeId connId;
        UA_StatusCode sc = UA_Server_addPubSubConnection(server, &cc, &connId);
        UA_PublisherId_clear(&cc.publisherId);
        UA_NetworkAddressUrlDataType_clear(&addrCopy);
        if (sc != UA_STATUSCODE_GOOD) {
            set_err(errBuf, errLen, "UA_Server_addPubSubConnection('%s')", name, sc);
            free(name);
            return -1;
        }
        if (b->nConn < MAX_COMPONENTS) {
            b->connections[b->nConn].id = connId;
            b->connections[b->nConn].enabled = conn->enabled;
            b->nConn++;
        }
        const UA_NetworkAddressUrlDataType *addr =
            (const UA_NetworkAddressUrlDataType *)conn->address.content.decoded.data;
        char *url = ua_to_cstr(&addr->url);
        char *prof = ua_to_cstr(&conn->transportProfileUri);
        fprintf(stderr, LOG_PREFIX "info: pubsub: PubSubConnection '%s' %s %s\n",
                name, url ? url : "", prof ? prof : "");
        free(url); free(prof);

        for (size_t w = 0; w < conn->writerGroupsSize; w++)
            if (add_writer_group(server, connId, conn, &conn->writerGroups[w], b,
                                 errBuf, errLen) != 0) { free(name); return -1; }
        for (size_t r = 0; r < conn->readerGroupsSize; r++)
            if (add_reader_group(server, connId, conn, &conn->readerGroups[r], b,
                                 errBuf, errLen) != 0) { free(name); return -1; }
        free(name);
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * Error recovery
 *
 * open62541 puts a WriterGroup and its PubSubConnection into Error when a
 * send fails, for example an MQTT publish before the broker has accepted
 * the connection, and leaves them there. A deployment re-enables them; so
 * does the adapter: a component the configuration enabled that enters
 * Error is re-enabled after a delay that doubles up to 5 s while the
 * recovery keeps failing (a re-enable can reach Operational and fail
 * again on the first send: only 10 s without an error starts over). Components disabled on purpose (through the
 * information model) are left alone: only Error is recovered from.
 * ---------------------------------------------------------------------- */

#define RECOVERY_MIN_MS 200
#define RECOVERY_MAX_MS 5000

/* find_created returns the entry of a component the configuration
 * enabled, or NULL. */
static Created *find_created(Created *list, size_t n, const UA_NodeId id) {
    for (size_t i = 0; i < n; i++)
        if (list[i].enabled && UA_NodeId_equal(&list[i].id, &id)) return &list[i];
    return NULL;
}

/* recover re-enables the components of list last seen in Error; *failed
 * counts the re-enables that failed. */
static size_t recover(UA_Server *server, Created *list, size_t n,
                      UA_StatusCode (*enable)(UA_Server *, const UA_NodeId),
                      size_t *failed) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (!list[i].enabled || list[i].state != UA_PUBSUBSTATE_ERROR) continue;
        if (enable(server, list[i].id) != UA_STATUSCODE_GOOD) (*failed)++;
        k++;
    }
    return k;
}

static void schedule_recovery(UA_Server *server);

static void recover_cb(UA_Server *server, void *data) {
    (void)data;
    g_rt.recoveryPending = false;
    struct Built *b = g_rt.built;
    if (!b) return;
    /* Connections first: a group cannot be operational on a broken one. */
    size_t failed = 0;
    size_t n = recover(server, b->connections, b->nConn, UA_Server_enablePubSubConnection, &failed);
    n += recover(server, b->writerGroups, b->nWg, UA_Server_enableWriterGroup, &failed);
    n += recover(server, b->readerGroups, b->nRg, UA_Server_enableReaderGroup, &failed);
    if (n)
        fprintf(stderr, LOG_PREFIX "info: pubsub: re-enabled %zu component(s) after an error"
                " (%zu failed)\n", n, failed);
    /* A re-enable that fails (for example a broker name that does not
     * resolve yet) goes from Error to Error: no state change reports it. */
    if (failed) schedule_recovery(server);
}

static void on_state_change(UA_Server *server, const UA_NodeId id,
                            UA_PubSubState state, UA_StatusCode status) {
    (void)status;
    struct Built *b = g_rt.built;
    if (!b) return;
    Created *c = find_created(b->connections, b->nConn, id);
    if (!c) c = find_created(b->writerGroups, b->nWg, id);
    if (!c) c = find_created(b->readerGroups, b->nRg, id);
    if (!c) return;
    c->state = state;
    if (state == UA_PUBSUBSTATE_ERROR) schedule_recovery(server);
}

/* schedule_recovery re-enables the components in Error after the current
 * backoff delay, unless a re-enable is already pending. */
static void schedule_recovery(UA_Server *server) {
    if (g_rt.recoveryPending) return;
    UA_EventLoop *el = UA_Server_getConfig(server)->eventLoop;
    UA_DateTime now = el->dateTime_nowMonotonic(el);
    if (now - g_rt.lastErrorAt > 2 * RECOVERY_MAX_MS * (UA_DateTime)UA_DATETIME_MSEC)
        g_rt.recoveryDelayMs = RECOVERY_MIN_MS; /* stable since the last error: start over */
    g_rt.lastErrorAt = now;
    UA_UInt32 delay = g_rt.recoveryDelayMs ? g_rt.recoveryDelayMs : RECOVERY_MIN_MS;
    g_rt.recoveryDelayMs = delay * 2 > RECOVERY_MAX_MS ? RECOVERY_MAX_MS : delay * 2;
    UA_UInt64 cbId;
    /* Not from inside the state machine: re-enable from a timed callback. */
    UA_DateTime at = now + (UA_DateTime)delay * UA_DATETIME_MSEC;
    if (UA_Server_addTimedCallback(server, recover_cb, NULL, at, &cbId) == UA_STATUSCODE_GOOD) {
        g_rt.recoveryPending = true;
        fprintf(stderr, LOG_PREFIX "info: pubsub: a component is in Error, re-enabling in %u ms\n", delay);
    }
}

static int enable_all(UA_Server *server, const Built *b, char *errBuf, size_t errLen) {
    /* Children first, connections last (as UA_Server_enableAllPubSubComponents) */
    struct { const Created *list; size_t n; const char *kind;
             UA_StatusCode (*fn)(UA_Server *, const UA_NodeId); } steps[] = {
        { b->writers,      b->nDsw,  "DataSetWriter",    UA_Server_enableDataSetWriter },
        { b->writerGroups, b->nWg,   "WriterGroup",      UA_Server_enableWriterGroup },
        { b->readers,      b->nDsr,  "DataSetReader",    UA_Server_enableDataSetReader },
        { b->readerGroups, b->nRg,   "ReaderGroup",      UA_Server_enableReaderGroup },
        { b->connections,  b->nConn, "PubSubConnection", UA_Server_enablePubSubConnection },
    };
    for (size_t s = 0; s < sizeof(steps) / sizeof(steps[0]); s++) {
        for (size_t i = 0; i < steps[s].n; i++) {
            if (!steps[s].list[i].enabled) continue;
            UA_StatusCode sc = steps[s].fn(server, steps[s].list[i].id);
            if (sc != UA_STATUSCODE_GOOD) {
                set_err(errBuf, errLen, "enabling a %s", steps[s].kind, sc);
                return -1;
            }
        }
    }
    return 0;
}

static UA_String *read_namespaces(UA_Server *server, size_t *count) {
    *count = 0;
    UA_Variant v;
    UA_Variant_init(&v);
    if (UA_Server_readValue(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_NAMESPACEARRAY), &v)
            != UA_STATUSCODE_GOOD || !UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING])) {
        UA_Variant_clear(&v);
        return NULL;
    }
    UA_String *ns = (UA_String *)v.data;
    *count = v.arrayLength;
    v.data = NULL;
    v.arrayLength = 0;
    UA_Variant_clear(&v);
    return ns;
}

int pubsub_server_apply(UA_Server *server, const PubSubOptions *opt,
                        char *errBuf, size_t errLen) {
    g_rt.server = server;
    UA_ByteString file = load_file(opt->configPath);
    if (file.length == 0) {
        snprintf(errBuf, errLen, "cannot read --pubsub-config %s", opt->configPath);
        return -1;
    }
    cJSON *root = cJSON_ParseWithLength((const char *)file.data, file.length);
    UA_ByteString_clear(&file);
    if (!root || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        snprintf(errBuf, errLen, "--pubsub-config: not a JSON object");
        return -1;
    }
    for (cJSON *c = root->child; c; c = c->next) {
        if (strcmp(c->string, "configuration") && strcmp(c->string, "securityGroups") &&
            strcmp(c->string, "serveSks") && strcmp(c->string, "sksClient") &&
            strcmp(c->string, "deltaFrames")) {
            snprintf(errBuf, errLen, "--pubsub-config: unknown member \"%s\"", c->string);
            cJSON_Delete(root);
            return -1;
        }
    }
    const cJSON *jcfg = cJSON_GetObjectItemCaseSensitive(root, "configuration");
    const cJSON *jsks = cJSON_GetObjectItemCaseSensitive(root, "sksClient");
    int serveSks = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "serveSks"));

    /* Delta frames (server-wide in open62541). Off by default: v1.5.9 sends a
     * DeltaFrame after every KeyFrame even with KeyFrameCount = 1, and its own
     * DataSetReader discards DeltaFrames ("Only keyframes are supported"). */
    UA_Server_getConfig(server)->pubSubConfig.enableDeltaFrames =
        cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "deltaFrames"));
    if (!jcfg || !cJSON_IsObject(jcfg)) {
        snprintf(errBuf, errLen, "--pubsub-config: \"configuration\" "
                 "(PubSubConfigurationDataType) is required");
        cJSON_Delete(root);
        return -1;
    }
    if (parse_security_groups(cJSON_GetObjectItemCaseSensitive(root, "securityGroups"),
                              errBuf, errLen) != 0) {
        cJSON_Delete(root);
        return -1;
    }

    /* Key source per group */
    for (size_t i = 0; i < g_rt.groupCount; i++) {
        SecGroup *sg = &g_rt.groups[i];
        if (!adapter_pubsub_find_policy(UA_Server_getConfig(server), sg->policyUri)) {
            set_err(errBuf, errLen, "securityGroups: unsupported securityPolicyUri '%s' "
                    "(PubSub-Aes128-CTR, PubSub-Aes256-CTR)", sg->policyUri,
                    UA_STATUSCODE_BADSECURITYPOLICYREJECTED);
            cJSON_Delete(root);
            return -1;
        }
        if (serveSks) {
            if (sg->keyCount > 0) {
                set_err(errBuf, errLen, "SecurityGroup '%s': \"keys\" cannot be combined with "
                        "\"serveSks\" (the SKS generates the keys; read them with "
                        "GetSecurityKeys)", sg->id, UA_STATUSCODE_GOOD);
                cJSON_Delete(root);
                return -1;
            }
            sg->source = KEYSRC_SKS_SERVER;
        } else if (sg->keyCount > 0) {
            sg->source = KEYSRC_STATIC;
        } else if (jsks) {
            sg->source = KEYSRC_SKS_CLIENT;
        } else {
            sg->source = KEYSRC_NONE;
        }
    }

    /* SKS role: SecurityGroups under PublishSubscribe.SecurityGroups. Created
     * before the groups that use them, so they attach to the same keys. */
    if (serveSks) {
        for (size_t i = 0; i < g_rt.groupCount; i++) {
            SecGroup *sg = &g_rt.groups[i];
            UA_SecurityGroupConfig sgc;
            memset(&sgc, 0, sizeof(sgc));
            sgc.securityGroupName = UA_STRING(sg->id);
            sgc.securityPolicyUri = UA_STRING(sg->policyUri);
            sgc.keyLifeTime = sg->keyLifetimeMs;
            sgc.maxFutureKeyCount = sg->maxFutureKeyCount;
            sgc.maxPastKeyCount = sg->maxPastKeyCount;
            UA_StatusCode sc = UA_Server_addSecurityGroup(
                server, UA_NODEID_NUMERIC(0, UA_NS0ID_PUBLISHSUBSCRIBE_SECURITYGROUPS),
                &sgc, &sg->nodeId);
            if (sc != UA_STATUSCODE_GOOD) {
                set_err(errBuf, errLen, "UA_Server_addSecurityGroup('%s')", sg->id, sc);
                cJSON_Delete(root);
                return -1;
            }
            UA_String s = UA_STRING_NULL;
            UA_NodeId_print(&sg->nodeId, &s);
            fprintf(stderr, LOG_PREFIX "info: pubsub: SKS SecurityGroup '%s' %s policy=%s "
                    "keyLifetime=%.0fms node=%.*s\n", sg->id, "served", sg->policyUri,
                    sg->keyLifetimeMs, (int)s.length, (const char *)s.data);
            UA_String_clear(&s);
        }
    }

    /* Decode the PubSubConfigurationDataType */
    char *cfgText = cJSON_PrintUnformatted(jcfg);
    size_t nsCount = 0;
    UA_String *ns = read_namespaces(server, &nsCount);
    UA_PubSubConfigurationDataType cfg;
    UA_PubSubConfigurationDataType_init(&cfg);
    UA_StatusCode sc = pubsub_decode_json(cfgText, strlen(cfgText), &cfg,
                                          &UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONDATATYPE],
                                          ns, nsCount);
    free(cfgText);
    UA_Array_delete(ns, nsCount, &UA_TYPES[UA_TYPES_STRING]);
    if (sc != UA_STATUSCODE_GOOD) {
        set_err(errBuf, errLen, "\"configuration\" is not a PubSubConfigurationDataType in the "
                "OPC UA JSON encoding%s", "", sc);
        cJSON_Delete(root);
        return -1;
    }

    Built *b = (Built *)calloc(1, sizeof(Built));
    int rc = b ? 0 : -1;
    if (!b) snprintf(errBuf, errLen, "out of memory");
    if (rc == 0) rc = add_published_datasets(server, &cfg, b, errBuf, errLen);
    if (rc == 0) rc = add_connections(server, &cfg, b, errBuf, errLen);

    /* SKS pull for the groups without static keys */
    if (rc == 0 && jsks) {
        int any = 0;
        for (size_t i = 0; i < g_rt.groupCount; i++)
            any |= (g_rt.groups[i].source == KEYSRC_SKS_CLIENT);
        if (any) {
            rc = parse_sks_client(jsks, opt, errBuf, errLen);
            if (rc == 0) {
                for (size_t i = 0; i < g_rt.groupCount; i++) {
                    if (g_rt.groups[i].source != KEYSRC_SKS_CLIENT) continue;
                    fprintf(stderr, LOG_PREFIX "info: pubsub: SecurityGroup '%s' pulls keys from "
                            "SKS %s\n", g_rt.groups[i].id, g_rt.sks.endpointUrl);
                    sks_attempt(server, &g_rt.groups[i]);
                }
                UA_Server_addRepeatedCallback(server, sks_retry_cb, NULL, 2000.0,
                                              &g_rt.sksRetryCallbackId);
            }
        }
    }
    if (rc == 0) {
        /* Before enabling: the first send may already fail. */
        g_rt.built = b;
        UA_Server_getConfig(server)->pubSubConfig.stateChangeCallback = on_state_change;
    }
    if (rc == 0 && cfg.enabled)
        rc = enable_all(server, b, errBuf, errLen);
    if (rc == 0)
        fprintf(stderr, LOG_PREFIX "info: pubsub: configuration applied (%zu connection(s), "
                "%zu writer group(s), %zu reader group(s)%s)\n", b->nConn, b->nWg, b->nRg,
                cfg.enabled ? "" : ", not enabled");

    /* The configuration is copied by the API; the secured-group list keeps
     * borrowed group ids from g_rt (not from cfg). b stays for the error
     * recovery (freed in pubsub_server_cleanup) unless applying failed. */
    if (rc != 0) {
        if (g_rt.built == b) g_rt.built = NULL;
        free(b);
    }
    UA_PubSubConfigurationDataType_clear(&cfg);
    cJSON_Delete(root);
    return rc;
}

void pubsub_server_cleanup(void) {
    free(g_rt.built);
    g_rt.built = NULL;
    for (size_t i = 0; i < g_rt.groupCount; i++) {
        SecGroup *sg = &g_rt.groups[i];
        free(sg->id);
        free(sg->policyUri);
        for (size_t k = 0; k < sg->keyCount; k++)
            UA_ByteString_clear(&sg->keys[k].key);
        free(sg->keys);
        UA_NodeId_clear(&sg->nodeId);
    }
    free(g_rt.groups);
    /* Called after UA_Server_delete: nothing references the SKS settings */
    SksSettings *k = &g_rt.sks;
    free(k->endpointUrl); free(k->policy); free(k->mode); free(k->username);
    free(k->password); free(k->certFile); free(k->keyFile); free(k->pkiDir);
    memset(&g_rt, 0, sizeof(g_rt));
    g_securedCount = 0;
}
