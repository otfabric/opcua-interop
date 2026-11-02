#define _GNU_SOURCE

#include "client.h"
#include "client_internal.h"
#include "history_events.h"
#include "output.h"
#include "values.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <open62541.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Synchronous generic service call. Defined (non-static) in the amalgamation
 * but not declared in open62541.h for the 1.5 series; declare it here so the
 * call sites are not implicit declarations. */
void __UA_Client_Service(UA_Client *client, const void *request,
                         const UA_DataType *requestType, void *response,
                         const UA_DataType *responseType);

/* BadNamespaceUriInvalid (0x80530000) is defined in the OPC UA spec Part 4
 * but not exposed by every open62541 version. Define it locally if absent. */
#ifndef UA_STATUSCODE_BADNAMESPACEURIINVALID
#define UA_STATUSCODE_BADNAMESPACEURIINVALID ((UA_StatusCode)0x80530000U)
#endif

/* Silent logger: discard all open62541 log output so that only JSON goes to
 * stdout.  The adapter's client operations are designed to emit exactly one
 * JSON line on stdout; mixing in open62541's colourised info/warn messages
 * would break envelope validation in the smoke harness. */
static void silent_log(void *ctx, UA_LogLevel level, UA_LogCategory cat,
                       const char *msg, va_list args) {
    (void)ctx; (void)cat;
    /* OPCUA_CLIENT_LOG=1 sends the stack's log to stderr (never stdout). */
    static int enabled = -1;
    if (enabled < 0) {
        const char *e = getenv("OPCUA_CLIENT_LOG");
        enabled = (e && *e && strcmp(e, "0") != 0) ? 1 : 0;
    }
    if (!enabled) return;
    /* The stack uses its own format extensions (%S for UA_String). */
    char text[1024];
    UA_String out = { sizeof(text) - 1, (UA_Byte *)text };
    if (UA_String_vformat(&out, msg, args) != UA_STATUSCODE_GOOD) return;
    fprintf(stderr, "[open62541] client log(%d): %.*s\n", (int)level,
            (int)out.length, text);
}
static UA_Logger g_silent_logger = { silent_log, NULL, NULL };

/* Apply the silent logger to a client config, including the event loop that
 * is created by UA_ClientConfig_setDefault. UA_Client_new installs a malloc'd
 * stdout logger (UA_Log_Stdout_new, freed by its `clear`) and hands that
 * pointer to the event loop, the certificate verification and the None
 * security policies; every copy is pointed at the silent logger before the
 * old one is cleared, so nothing keeps a dangling pointer and it is not
 * leaked. Idempotent: a config that already has the silent logger only gets
 * its copies re-pointed. */
static void client_silence_logger(UA_ClientConfig *cfg) {
    UA_Logger *old = cfg->logging;
    cfg->logging = &g_silent_logger;
    if (cfg->eventLoop)
        cfg->eventLoop->logger = &g_silent_logger;
    if (!old || old == &g_silent_logger)
        return;
    if (cfg->certificateVerification.logging == old)
        cfg->certificateVerification.logging = &g_silent_logger;
    for (size_t i = 0; i < cfg->securityPoliciesSize; i++)
        if (cfg->securityPolicies[i].logger == old)
            cfg->securityPolicies[i].logger = &g_silent_logger;
    for (size_t i = 0; i < cfg->authSecurityPoliciesSize; i++)
        if (cfg->authSecurityPolicies[i].logger == old)
            cfg->authSecurityPolicies[i].logger = &g_silent_logger;
    if (old->clear)
        old->clear(old);
}

/* Load a binary (DER) file into a UA_ByteString.  Returns UA_BYTESTRING_NULL
 * on any error. */
static UA_ByteString load_cert_file(const char *path) {
    UA_ByteString bs = UA_BYTESTRING_NULL;
    if (!path || !*path) return bs;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[open62541] warn: cannot open %s: %s\n", path, strerror(errno));
        return bs;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return bs; }
    bs.data = (UA_Byte *)UA_malloc((size_t)sz);
    if (!bs.data) { fclose(f); return bs; }
    bs.length = (size_t)fread(bs.data, 1, (size_t)sz, f);
    fclose(f);
    if (bs.length != (size_t)sz) {
        UA_ByteString_clear(&bs);
        return UA_BYTESTRING_NULL;
    }
    return bs;
}

/* -------------------------------------------------------------------------
 * Shared argument parsing helpers
 * ---------------------------------------------------------------------- */

static const char *find_arg(int argc, char **argv, const char *flag) {
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    }
    return NULL;
}

static int count_flag(int argc, char **argv, const char *flag) {
    int n = 0;
    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], flag) == 0) n++;
    return n;
}

static int parse_int_flag(int argc, char **argv, const char *flag, int def) {
    const char *v = find_arg(argc, argv, flag);
    if (!v) return def;
    int r = atoi(v);
    return (r > 0) ? r : def;
}

/* -------------------------------------------------------------------------
 * Global security configuration (parsed once in client_run before dispatch)
 * ---------------------------------------------------------------------- */

typedef struct {
    const char  *policyName;    /* "None", "Basic256Sha256", etc. */
    const char  *modeName;      /* "None", "Sign", "SignAndEncrypt" */
    const char  *certFile;      /* DER client application cert */
    const char  *keyFile;       /* DER private key */
    const char **trustFiles;    /* array of --trust-list values */
    int          trustCount;
    const char  *username;      /* NULL = anonymous */
    const char  *password;      /* NULL = treat as empty string */
    int          channelLifetimeMs; /* 0 = stack default; >0 requested SecureChannel lifetime */
    const char  *applicationUri;    /* NULL = SAN URI of --certificate, else stack default */
    int          reverseListenPort; /* 0 = dial; >0 wait for a ReverseHello on this port */
    int          reverseTimeoutMs;  /* how long to wait for the reverse connection */
    const char  *reverseServerUri;  /* optional expected server ApplicationUri */
} ClientSecurity;

static ClientSecurity g_sec = { "None", "None", NULL, NULL, NULL, 0, NULL, NULL, 0,
                                NULL, 0, 30000, NULL };

static UA_MessageSecurityMode security_mode_enum(const char *s) {
    if (!s || strcmp(s, "None") == 0)        return UA_MESSAGESECURITYMODE_NONE;
    if (strcmp(s, "Sign") == 0)              return UA_MESSAGESECURITYMODE_SIGN;
    if (strcmp(s, "SignAndEncrypt") == 0)    return UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    return UA_MESSAGESECURITYMODE_NONE;
}

static const char *security_policy_uri(const char *name) {
    static const struct { const char *n; const char *uri; } tbl[] = {
        { "None",               "http://opcfoundation.org/UA/SecurityPolicy#None"               },
        { "Basic128Rsa15",      "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"      },
        { "Basic256",           "http://opcfoundation.org/UA/SecurityPolicy#Basic256"           },
        { "Basic256Sha256",     "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"     },
        { "Aes128_Sha256_RsaOaep","http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"},
        { "Aes256_Sha256_RsaPss","http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss" },
        { "ECC_nistP256",       "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256"       },
        { "ECC_nistP384",       "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384"       },
        { "ECC_brainpoolP256r1","http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1"},
        { "ECC_brainpoolP384r1","http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1"},
        { "ECC_curve25519",     "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519"     },
        { "ECC_curve448",       "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448"       },
        { "ECC_nistP256_AesGcm","http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm"},
        { "ECC_nistP256_ChaChaPoly","http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_ChaChaPoly"},
    };
    for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++) {
        if (name && strcmp(name, tbl[i].n) == 0) return tbl[i].uri;
    }
    return tbl[0].uri; /* fallback: None */
}

static UA_Boolean security_is_none(void) {
    return security_mode_enum(g_sec.modeName) == UA_MESSAGESECURITYMODE_NONE;
}

/* 1 when `name` is one of the policy names this adapter accepts. */
static int security_policy_known(const char *name) {
    if (!name) return 1;
    const char *uri = security_policy_uri(name);
    const char *hash = strrchr(uri, '#');
    return hash && strcmp(hash + 1, name) == 0;
}

/* -------------------------------------------------------------------------
 * ECC SecurityPolicies
 *
 * open62541 v1.5.9 (OpenSSL backend) only puts the AEAD ECC policies and the
 * Curve25519/448 policies into its default set; ECC_nistP256 / ECC_nistP384 /
 * ECC_brainpoolP256r1 / ECC_brainpoolP384r1 have to be added explicitly. A
 * policy can only be instantiated with a certificate of its own curve.
 * ---------------------------------------------------------------------- */

typedef UA_StatusCode (*EccPolicyCtor)(UA_SecurityPolicy *policy,
                                       const UA_ApplicationType applicationType,
                                       const UA_ByteString localCertificate,
                                       const UA_ByteString localPrivateKey,
                                       const UA_Logger *logger);

static EccPolicyCtor ecc_policy_ctor(const char *name) {
    if (!name) return NULL;
    if (strcmp(name, "ECC_nistP256") == 0)            return UA_SecurityPolicy_EccNistP256;
    if (strcmp(name, "ECC_nistP384") == 0)            return UA_SecurityPolicy_EccNistP384;
    if (strcmp(name, "ECC_brainpoolP256r1") == 0)     return UA_SecurityPolicy_EccBrainpoolP256r1;
    if (strcmp(name, "ECC_brainpoolP384r1") == 0)     return UA_SecurityPolicy_EccBrainpoolP384r1;
    if (strcmp(name, "ECC_curve25519") == 0)          return UA_SecurityPolicy_EccCurve25519;
    if (strcmp(name, "ECC_curve448") == 0)            return UA_SecurityPolicy_EccCurve448;
    if (strcmp(name, "ECC_nistP256_AesGcm") == 0)     return UA_SecurityPolicy_EccNistP256AesGcm;
    if (strcmp(name, "ECC_nistP256_ChaChaPoly") == 0) return UA_SecurityPolicy_EccNistP256ChaChaPoly;
    return NULL;
}

static int policy_array_has(const UA_SecurityPolicy *arr, size_t n, const char *uri) {
    UA_String want = UA_STRING((char *)(uintptr_t)uri);
    for (size_t i = 0; i < n; i++)
        if (UA_String_equal(&arr[i].policyUri, &want)) return 1;
    return 0;
}

/* Append the ECC policy `name` to a client policy array unless present. */
static UA_StatusCode policy_array_add_ecc(UA_SecurityPolicy **arr, size_t *n,
                                          const char *name,
                                          const UA_ByteString cert,
                                          const UA_ByteString key,
                                          const UA_Logger *logger) {
    EccPolicyCtor ctor = ecc_policy_ctor(name);
    if (!ctor) return UA_STATUSCODE_GOOD; /* not an ECC policy */
    if (policy_array_has(*arr, *n, security_policy_uri(name)))
        return UA_STATUSCODE_GOOD;

    UA_SecurityPolicy *grown = (UA_SecurityPolicy *)
        UA_realloc(*arr, sizeof(UA_SecurityPolicy) * (*n + 1));
    if (!grown) return UA_STATUSCODE_BADOUTOFMEMORY;
    *arr = grown;
    memset(&grown[*n], 0, sizeof(UA_SecurityPolicy));
    UA_StatusCode sc = ctor(&grown[*n], UA_APPLICATIONTYPE_CLIENT, cert, key, logger);
    if (sc == UA_STATUSCODE_GOOD) (*n)++;
    return sc;
}

/* -------------------------------------------------------------------------
 * ApplicationUri from the certificate's subjectAltName
 * ---------------------------------------------------------------------- */

/* Returns a malloc'd copy of the first URI SAN of a PEM or DER certificate
 * file, or NULL. */
static char *certificate_san_uri(const char *path) {
    if (!path || !*path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    if (!x) {
        rewind(f);
        x = d2i_X509_fp(f, NULL);
    }
    fclose(f);
    if (!x) return NULL;

    char *result = NULL;
    GENERAL_NAMES *names = (GENERAL_NAMES *)
        X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    if (names) {
        int count = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < count && !result; i++) {
            const GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);
            if (gn->type != GEN_URI) continue;
            const unsigned char *data = ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier);
            int len = ASN1_STRING_length(gn->d.uniformResourceIdentifier);
            if (data && len > 0) result = strndup((const char *)data, (size_t)len);
        }
        GENERAL_NAMES_free(names);
    }
    X509_free(x);
    return result;
}

char *cli_certificate_san_uri(const char *path) {
    return certificate_san_uri(path);
}

/* -------------------------------------------------------------------------
 * Base64 decode (for ByteString NodeIds)
 * ---------------------------------------------------------------------- */

static int b64_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Returns malloc'd buffer; sets *outLen. Returns NULL on error. */
static unsigned char *b64_decode(const char *in, size_t *outLen) {
    if (!in) { *outLen = 0; return NULL; }
    size_t inLen = strlen(in);
    if (inLen == 0) { *outLen = 0; return (unsigned char *)calloc(1, 1); }
    if (inLen % 4 != 0) { *outLen = 0; return NULL; }

    *outLen = inLen / 4 * 3;
    if (in[inLen-1] == '=') (*outLen)--;
    if (inLen >= 2 && in[inLen-2] == '=') (*outLen)--;

    unsigned char *out = (unsigned char *)malloc(*outLen + 1);
    if (!out) { *outLen = 0; return NULL; }

    size_t j = 0;
    for (size_t i = 0; i < inLen; i += 4) {
        int a = b64_char_val(in[i]);
        int b = b64_char_val(in[i+1]);
        int c = (in[i+2] == '=') ? 0 : b64_char_val(in[i+2]);
        int d = (in[i+3] == '=') ? 0 : b64_char_val(in[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(out); *outLen = 0; return NULL; }
        if (j < *outLen) out[j++] = (unsigned char)((a << 2) | (b >> 4));
        if (j < *outLen) out[j++] = (unsigned char)(((b & 0xf) << 4) | (c >> 2));
        if (j < *outLen) out[j++] = (unsigned char)(((c & 3) << 6) | d);
    }
    return out;
}

/* -------------------------------------------------------------------------
 * GUID parsing: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 * ---------------------------------------------------------------------- */

static int parse_guid_string(const char *s, UA_Guid *out) {
    if (!s) return 0;
    unsigned d1, d2, d3;
    unsigned b[8];
    if (sscanf(s, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               &d1, &d2, &d3,
               &b[0], &b[1], &b[2], &b[3],
               &b[4], &b[5], &b[6], &b[7]) != 11) return 0;
    out->data1 = (UA_UInt32)d1;
    out->data2 = (UA_UInt16)d2;
    out->data3 = (UA_UInt16)d3;
    for (int i = 0; i < 8; i++) out->data4[i] = (UA_Byte)b[i];
    return 1;
}

/* -------------------------------------------------------------------------
 * NodeId parsing
 * ---------------------------------------------------------------------- */

/*
 * Validate structural form of a NodeId string without resolving namespaces.
 * Returns 0 if structurally valid, -1 if malformed.
 */
static int validate_nodeid_structure(const char *s) {
    if (!s || !*s) return -1;
    /* i=N */
    if (strncmp(s, "i=", 2) == 0) {
        const char *rest = s + 2;
        if (!*rest) return -1;
        while (*rest) { if (*rest < '0' || *rest > '9') return -1; rest++; }
        return 0;
    }
    /* ns=N;<type>= */
    if (strncmp(s, "ns=", 3) == 0) {
        const char *semi = strchr(s + 3, ';');
        if (!semi) return -1;
        semi++;
        if (strncmp(semi, "s=", 2) == 0 ||
            strncmp(semi, "i=", 2) == 0 ||
            strncmp(semi, "g=", 2) == 0 ||
            strncmp(semi, "b=", 2) == 0)
            return 0;
        return -1;
    }
    /* nsu=URI;<type>= */
    if (strncmp(s, "nsu=", 4) == 0) {
        const char *semi = strchr(s + 4, ';');
        if (!semi) return -1;
        semi++;
        if (strncmp(semi, "s=", 2) == 0 ||
            strncmp(semi, "i=", 2) == 0 ||
            strncmp(semi, "g=", 2) == 0 ||
            strncmp(semi, "b=", 2) == 0)
            return 0;
        return -1;
    }
    return -1;
}

/*
 * Parse a NodeId string that uses ns= or i= prefixes (not nsu=).
 * The client may be NULL for these forms.
 * Returns a UA_NodeId — caller must UA_NodeId_clear() when done.
 * Returns UA_NODEID_NULL on error.
 */
static UA_NodeId parse_nodeid_local(const char *s) {
    if (!s) return UA_NODEID_NULL;

    if (strncmp(s, "i=", 2) == 0)
        return UA_NODEID_NUMERIC(0, (UA_UInt32)atoi(s + 2));

    if (strncmp(s, "ns=", 3) == 0) {
        UA_UInt16 ns = (UA_UInt16)atoi(s + 3);
        const char *semi = strchr(s + 3, ';');
        if (!semi) return UA_NODEID_NULL;
        semi++;
        if (strncmp(semi, "s=", 2) == 0)
            return UA_NODEID_STRING_ALLOC(ns, semi + 2);
        if (strncmp(semi, "i=", 2) == 0)
            return UA_NODEID_NUMERIC(ns, (UA_UInt32)atoi(semi + 2));
        if (strncmp(semi, "g=", 2) == 0) {
            UA_Guid guid;
            memset(&guid, 0, sizeof(guid));
            if (!parse_guid_string(semi + 2, &guid)) return UA_NODEID_NULL;
            return UA_NODEID_GUID(ns, guid);
        }
        if (strncmp(semi, "b=", 2) == 0) {
            size_t decoded_len;
            unsigned char *decoded = b64_decode(semi + 2, &decoded_len);
            if (!decoded) return UA_NODEID_NULL;
            UA_NodeId nid;
            UA_NodeId_init(&nid);
            nid.namespaceIndex = ns;
            nid.identifierType = UA_NODEIDTYPE_BYTESTRING;
            nid.identifier.byteString.data   = decoded;
            nid.identifier.byteString.length = decoded_len;
            return nid;
        }
        return UA_NODEID_NULL;
    }

    return UA_NODEID_NULL;
}

/*
 * Resolve a nsu= NodeId after connecting.
 * Returns 0 on success (out is populated, caller must UA_NodeId_clear()),
 * -1 on namespace-not-found (unknown URI), -2 on other error.
 */
static int resolve_nsu_nodeid(UA_Client *client, const char *s, UA_NodeId *out) {
    if (!s || strncmp(s, "nsu=", 4) != 0) return -2;

    const char *uri_start = s + 4;
    const char *semi = strchr(uri_start, ';');
    if (!semi) return -2;

    size_t uri_len = (size_t)(semi - uri_start);
    char *uri = (char *)malloc(uri_len + 1);
    if (!uri) return -2;
    memcpy(uri, uri_start, uri_len);
    uri[uri_len] = '\0';

    UA_String uri_str;
    uri_str.data   = (UA_Byte *)uri;
    uri_str.length = uri_len;

    UA_UInt16 nsIdx = 0;
    UA_StatusCode sc = UA_Client_NamespaceGetIndex(client, &uri_str, &nsIdx);
    free(uri);

    if (sc != UA_STATUSCODE_GOOD) return -1;
    const char *id = semi + 1;

    if (strncmp(id, "s=", 2) == 0) {
        *out = UA_NODEID_STRING_ALLOC(nsIdx, id + 2);
        return 0;
    }
    if (strncmp(id, "i=", 2) == 0) {
        *out = UA_NODEID_NUMERIC(nsIdx, (UA_UInt32)atoi(id + 2));
        return 0;
    }
    if (strncmp(id, "g=", 2) == 0) {
        UA_Guid guid;
        memset(&guid, 0, sizeof(guid));
        if (!parse_guid_string(id + 2, &guid)) return -2;
        *out = UA_NODEID_GUID(nsIdx, guid);
        return 0;
    }
    if (strncmp(id, "b=", 2) == 0) {
        size_t decoded_len;
        unsigned char *decoded = b64_decode(id + 2, &decoded_len);
        if (!decoded) return -2;
        UA_NodeId_init(out);
        out->namespaceIndex = nsIdx;
        out->identifierType = UA_NODEIDTYPE_BYTESTRING;
        out->identifier.byteString.data   = decoded;
        out->identifier.byteString.length = decoded_len;
        return 0;
    }
    return -2;
}

/* -------------------------------------------------------------------------
 * DataType name for a UA_DataType pointer
 * ---------------------------------------------------------------------- */

static const char *type_name(const UA_DataType *dt) {
    if (!dt) return "Unknown";
    if (dt == &UA_TYPES[UA_TYPES_BOOLEAN])       return "Boolean";
    if (dt == &UA_TYPES[UA_TYPES_SBYTE])         return "SByte";
    if (dt == &UA_TYPES[UA_TYPES_BYTE])          return "Byte";
    if (dt == &UA_TYPES[UA_TYPES_INT16])         return "Int16";
    if (dt == &UA_TYPES[UA_TYPES_UINT16])        return "UInt16";
    if (dt == &UA_TYPES[UA_TYPES_INT32])         return "Int32";
    if (dt == &UA_TYPES[UA_TYPES_UINT32])        return "UInt32";
    if (dt == &UA_TYPES[UA_TYPES_INT64])         return "Int64";
    if (dt == &UA_TYPES[UA_TYPES_UINT64])        return "UInt64";
    if (dt == &UA_TYPES[UA_TYPES_FLOAT])         return "Float";
    if (dt == &UA_TYPES[UA_TYPES_DOUBLE])        return "Double";
    if (dt == &UA_TYPES[UA_TYPES_STRING])        return "String";
    if (dt == &UA_TYPES[UA_TYPES_DATETIME])      return "DateTime";
    if (dt == &UA_TYPES[UA_TYPES_GUID])          return "Guid";
    if (dt == &UA_TYPES[UA_TYPES_BYTESTRING])    return "ByteString";
    if (dt == &UA_TYPES[UA_TYPES_XMLELEMENT])    return "XmlElement";
    if (dt == &UA_TYPES[UA_TYPES_NODEID])        return "NodeId";
    if (dt == &UA_TYPES[UA_TYPES_QUALIFIEDNAME]) return "QualifiedName";
    if (dt == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]) return "LocalizedText";
    if (dt == &UA_TYPES[UA_TYPES_STATUSCODE])    return "StatusCode";
    return dt->typeName ? dt->typeName : "Unknown";
}

/* -------------------------------------------------------------------------
 * Endpoint security check
 * ---------------------------------------------------------------------- */

/*
 * Returns 1 if the server at url has an endpoint matching the globally
 * configured security policy and mode.
 * Returns 0 on error or not found; fills *out_sc with the GetEndpoints result.
 */
static int endpoint_check_security(const char *url, UA_StatusCode *out_sc) {
    UA_Client *c = UA_Client_new();
    if (!c) { *out_sc = UA_STATUSCODE_BADOUTOFMEMORY; return 0; }
    UA_ClientConfig_setDefault(UA_Client_getConfig(c));
    client_silence_logger(UA_Client_getConfig(c));

    UA_EndpointDescription *eps = NULL;
    size_t epCount = 0;
    UA_StatusCode sc = UA_Client_getEndpoints(c, url, &epCount, &eps);
    UA_Client_delete(c);

    /* Milo/Netty warm-up: the very first GetEndpoints occasionally fails with
     * BadSecureChannelClosed. Retry once (as the endpoints command does). */
    if (sc == UA_STATUSCODE_BADSECURECHANNELCLOSED ||
        sc == UA_STATUSCODE_BADSECURECHANNELIDINVALID) {
        c = UA_Client_new();
        if (!c) { *out_sc = UA_STATUSCODE_BADOUTOFMEMORY; return 0; }
        client_silence_logger(UA_Client_getConfig(c));
        UA_ClientConfig_setDefault(UA_Client_getConfig(c));
        client_silence_logger(UA_Client_getConfig(c));
        sc = UA_Client_getEndpoints(c, url, &epCount, &eps);
        UA_Client_delete(c);
    }
    *out_sc = sc;

    if (sc != UA_STATUSCODE_GOOD) return 0;

    const char *want_uri = security_policy_uri(g_sec.policyName);
    UA_MessageSecurityMode want_mode = security_mode_enum(g_sec.modeName);
    size_t want_uri_len = strlen(want_uri);

    int found = 0;
    for (size_t i = 0; i < epCount && !found; i++) {
        if (eps[i].securityMode != want_mode) continue;
        const UA_String *uri = &eps[i].securityPolicyUri;
        if (uri->length == want_uri_len &&
            memcmp(uri->data, want_uri, want_uri_len) == 0)
            found = 1;
    }
    if (eps) UA_Array_delete(eps, epCount, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    return found;
}

/* -------------------------------------------------------------------------
 * Reverse connect (Part 6 7.1.3)
 *
 * The client opens a listen socket and the server dials in with a
 * ReverseHello. open62541 opens that first channel with SecurityPolicy None,
 * calls GetEndpoints on it and, when the selected endpoint needs another
 * policy / mode (or advertises another EndpointUrl than the ReverseHello),
 * closes the channel so it can be reopened. On a reverse connection only the
 * server can reopen, so we listen again and wait for the server's next
 * attempt; the endpoint selected in the first round is then used directly.
 * ---------------------------------------------------------------------- */

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/*
 * Wait for a reverse connection. With want_session the call returns once the
 * session is activated; otherwise once the SecureChannel is open.
 */
static UA_StatusCode reverse_connect(UA_Client *client, int want_session) {
    UA_ClientConfig *cfg = UA_Client_getConfig(client);
    cfg->noSession   = want_session ? UA_FALSE : UA_TRUE;
    cfg->noReconnect = UA_TRUE; /* never fall back to dialling */
    cfg->tcpReuseAddr = UA_TRUE; /* the port is listened on again after a close */

    int timeout_ms = g_sec.reverseTimeoutMs > 0 ? g_sec.reverseTimeoutMs : 30000;
    long long deadline = mono_ms() + timeout_ms;
    UA_StatusCode last = UA_STATUSCODE_BADTIMEOUT;

    while (mono_ms() < deadline) {
        UA_SecureChannelState ch;
        UA_SessionState ss;
        UA_StatusCode cs;

        /* Let a previous channel finish closing before listening again. */
        UA_Client_getState(client, &ch, &ss, &cs);
        while (ch != UA_SECURECHANNELSTATE_CLOSED && mono_ms() < deadline) {
            UA_Client_run_iterate(client, 20);
            UA_Client_getState(client, &ch, &ss, &cs);
        }
        if (ch != UA_SECURECHANNELSTATE_CLOSED) break;

        UA_StatusCode sc = UA_Client_startListeningForReverseConnect(
            client, NULL, 0, (UA_UInt16)g_sec.reverseListenPort);
        if (sc != UA_STATUSCODE_GOOD) {
            /* A bad endpoint certificate / unavailable policy is final. */
            if (sc != UA_STATUSCODE_BADCONNECTIONCLOSED) return sc;
            last = sc;
            UA_Client_run_iterate(client, 100);
            continue;
        }

        int listening = 0;
        while (mono_ms() < deadline) {
            UA_Client_run_iterate(client, 20);
            UA_Client_getState(client, &ch, &ss, &cs);
            if (ch == UA_SECURECHANNELSTATE_REVERSE_LISTENING) listening = 1;
            if (want_session && ss == UA_SESSIONSTATE_ACTIVATED)
                return UA_STATUSCODE_GOOD;
            if (!want_session && ch == UA_SECURECHANNELSTATE_OPEN)
                return UA_STATUSCODE_GOOD;
            if (cs != UA_STATUSCODE_GOOD) {
                /* BadNotConnected is the "would reconnect" marker set because
                 * of noReconnect; everything else is a real failure. */
                if (cs != UA_STATUSCODE_BADNOTCONNECTED &&
                    cs != UA_STATUSCODE_BADCONNECTIONCLOSED)
                    return cs;
                last = cs;
                break;
            }
            if (ch == UA_SECURECHANNELSTATE_CLOSED && listening) break;
        }
    }
    return UA_STATUSCODE_BADTIMEOUT;
}

/* Compare ServerArray[0] of the connected server with --reverse-server-uri. */
static UA_StatusCode reverse_check_server_uri(UA_Client *client) {
    UA_Variant v;
    UA_Variant_init(&v);
    UA_StatusCode sc = UA_Client_readValueAttribute(
        client, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERARRAY), &v);
    if (sc != UA_STATUSCODE_GOOD) return sc;
    sc = UA_STATUSCODE_BADSERVERURIINVALID;
    if (v.type == &UA_TYPES[UA_TYPES_STRING] && v.arrayLength > 0) {
        UA_String want = UA_STRING((char *)(uintptr_t)g_sec.reverseServerUri);
        if (UA_String_equal(&((UA_String *)v.data)[0], &want))
            sc = UA_STATUSCODE_GOOD;
    }
    UA_Variant_clear(&v);
    return sc;
}

/* -------------------------------------------------------------------------
 * Client connect helper
 * ---------------------------------------------------------------------- */

/*
 * Checks endpoint security and creates a client configured from the global
 * flags (security, identity, lifetimes) without connecting it.
 * On failure: emits the complete error envelope for operation op, sets
 * *exit_code, and returns NULL.
 */
static UA_Client *make_client_unconnected(const char *url,
                                          int request_ms,
                                          const char *op,
                                          int *exit_code) {
    /* A security policy this build does not know must not silently fall back
     * to None. */
    if (!security_policy_known(g_sec.policyName)) {
        char msg_buf[256];
        snprintf(msg_buf, sizeof(msg_buf), "unknown --security-policy '%s'",
                 g_sec.policyName ? g_sec.policyName : "");
        output_begin("open62541", op);
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg_buf);
        output_end();
        *exit_code = 2;
        return NULL;
    }

    /* Verify a matching endpoint exists. Not possible when waiting for a
     * reverse connection: the server is the one that dials. */
    UA_StatusCode ep_sc = UA_STATUSCODE_GOOD;
    if (g_sec.reverseListenPort <= 0 && !endpoint_check_security(url, &ep_sc)) {
        UA_StatusCode err_sc = (ep_sc != UA_STATUSCODE_GOOD)
                               ? ep_sc
                               : UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
        char msg_buf[256];
        if (ep_sc != UA_STATUSCODE_GOOD) {
            snprintf(msg_buf, sizeof(msg_buf), "GetEndpoints request failed");
        } else {
            snprintf(msg_buf, sizeof(msg_buf),
                     "no %s/%s endpoint available",
                     g_sec.policyName ? g_sec.policyName : "None",
                     g_sec.modeName   ? g_sec.modeName   : "None");
        }
        output_begin("open62541", op);
        output_success(0);
        output_service_result(err_sc);
        output_error("transport", msg_buf);
        output_end();
        *exit_code = 3;
        return NULL;
    }

    UA_Client *client = UA_Client_new();
    if (!client) {
        output_begin("open62541", op);
        output_success(0);
        output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
        output_error("internal", "UA_Client_new failed");
        output_end();
        *exit_code = 6;
        return NULL;
    }

    UA_ClientConfig *cfg = UA_Client_getConfig(client);

    /* Install the silent logger before the config helpers run: they log
     * (to stdout) while loading policies, and stdout is reserved for the
     * result envelope. */
    client_silence_logger(cfg);

#ifdef UA_ENABLE_ENCRYPTION
    if (!security_is_none()) {
        UA_ByteString cert = load_cert_file(g_sec.certFile);
        UA_ByteString key  = load_cert_file(g_sec.keyFile);

        size_t trust_count = (size_t)g_sec.trustCount;
        UA_ByteString *trust_list = NULL;
        if (trust_count > 0) {
            trust_list = (UA_ByteString *)calloc(trust_count, sizeof(UA_ByteString));
            if (trust_list) {
                for (size_t i = 0; i < trust_count; i++)
                    trust_list[i] = load_cert_file(g_sec.trustFiles[i]);
            }
        }

        UA_StatusCode sc = UA_ClientConfig_setDefaultEncryption(
            cfg,
            cert, key,
            trust_list, trust_count,
            NULL, 0);

        /* The ECC policies that are not part of the stack's default set are
         * added here, for the SecureChannel and for user-token encryption
         * (EccEncryptedSecret). */
        const char *policy_err = "UA_ClientConfig_setDefaultEncryption failed";
        if (sc == UA_STATUSCODE_GOOD && ecc_policy_ctor(g_sec.policyName)) {
            UA_ByteString der = UA_BYTESTRING_NULL;
            sc = UA_CertificateUtils_decryptPrivateKey(key, UA_BYTESTRING_NULL, &der);
            if (sc == UA_STATUSCODE_GOOD)
                sc = policy_array_add_ecc(&cfg->securityPolicies,
                                          &cfg->securityPoliciesSize,
                                          g_sec.policyName, cert, der, cfg->logging);
            if (sc == UA_STATUSCODE_GOOD)
                sc = policy_array_add_ecc(&cfg->authSecurityPolicies,
                                          &cfg->authSecurityPoliciesSize,
                                          g_sec.policyName, cert, der, cfg->logging);
            UA_ByteString_clear(&der);
            policy_err = "the certificate / private key cannot be used with the "
                         "requested ECC security policy (curve mismatch?)";
        }

        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        for (size_t i = 0; i < trust_count; i++)
            UA_ByteString_clear(&trust_list[i]);
        free(trust_list);

        if (sc != UA_STATUSCODE_GOOD) {
            UA_Client_delete(client);
            output_begin("open62541", op);
            output_success(0);
            output_service_result(sc);
            output_error("internal", policy_err);
            output_end();
            *exit_code = 6;
            return NULL;
        }

        /* Select the requested security policy and mode */
        cfg->securityPolicyUri =
            UA_STRING_ALLOC(security_policy_uri(g_sec.policyName));
        cfg->securityMode = security_mode_enum(g_sec.modeName);
    } else {
        UA_ClientConfig_setDefault(cfg);
        /* open62541 v1.5.x endpoint selection: when a server advertises multiple
         * security endpoints, the client picks the highest-security endpoint that
         * has a matching user token policy, regardless of the client's configured
         * security mode.  Explicitly pinning None here forces the client to
         * select the None/None endpoint even when secure endpoints are available. */
        cfg->securityPolicyUri = UA_STRING_ALLOC(security_policy_uri("None"));
        cfg->securityMode = UA_MESSAGESECURITYMODE_NONE;
        /* open62541 v1.5.x rejects UserName token policies on None/None endpoints
         * by default to prevent cleartext password transmission.  For test
         * deployments where None/None username auth is deliberately used,
         * set allowNonePolicyPassword = UA_TRUE (same flag as on the server). */
        if (g_sec.username)
            cfg->allowNonePolicyPassword = UA_TRUE;
    }
#else
    UA_ClientConfig_setDefault(cfg);
    if (!security_is_none()) {
        fprintf(stderr, "[open62541] warn: non-None security requested but binary built "
                        "without UA_ENABLE_ENCRYPTION\n");
    }
#endif /* UA_ENABLE_ENCRYPTION */

    client_silence_logger(cfg);
    if (request_ms > 0)
        cfg->timeout = (UA_UInt32)request_ms;
    cfg->connectivityCheckInterval = 0;
    /* Short requested lifetimes force SecurityToken renewals during the
     * command (the client renews at 75% of the revised lifetime). */
    if (g_sec.channelLifetimeMs > 0)
        cfg->secureChannelLifeTime = (UA_UInt32)g_sec.channelLifetimeMs;

    /* ApplicationUri: explicit flag, else the URI in the certificate's
     * subjectAltName (servers compare the two in CreateSession). */
    {
        char *san = NULL;
        const char *uri = g_sec.applicationUri;
        if (!uri && !security_is_none())
            uri = san = certificate_san_uri(g_sec.certFile);
        if (uri && *uri) {
            UA_String_clear(&cfg->clientDescription.applicationUri);
            cfg->clientDescription.applicationUri = UA_STRING_ALLOC(uri);
        }
        free(san);
    }

    /* Set user identity token */
    if (g_sec.username) {
        UA_UserNameIdentityToken token;
        UA_UserNameIdentityToken_init(&token);
        token.userName = UA_STRING_ALLOC(g_sec.username);
        const char *pw = g_sec.password ? g_sec.password : "";
        token.password = UA_BYTESTRING_ALLOC(pw);
        UA_ExtensionObject_clear(&cfg->userIdentityToken);
        /* UA_ExtensionObject_setValueCopy(eo, p, type): data first, type second. */
        UA_ExtensionObject_setValueCopy(&cfg->userIdentityToken,
            &token, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
        UA_UserNameIdentityToken_clear(&token);
    }

    return client;
}

/*
 * Checks endpoint security then creates and connects a client.
 * On failure: emits the complete error envelope for operation op, sets
 * *exit_code to 3, and returns NULL.
 * On success: returns a connected UA_Client* (caller must disconnect+delete).
 */
static UA_Client *make_client(const char *url,
                               int request_ms,
                               const char *op,
                               int *exit_code) {
    UA_Client *client = make_client_unconnected(url, request_ms, op, exit_code);
    if (!client) return NULL;

    UA_StatusCode sc;
    const char *reverse_msg = NULL;
    if (g_sec.reverseListenPort > 0) {
        sc = reverse_connect(client, 1);
        if (sc == UA_STATUSCODE_GOOD && g_sec.reverseServerUri) {
            sc = reverse_check_server_uri(client);
            if (sc != UA_STATUSCODE_GOOD) {
                UA_Client_disconnect(client);
                reverse_msg = "the reverse-connected server does not have the "
                              "expected --reverse-server-uri";
            }
        }
    } else {
        sc = UA_Client_connect(client, url);
    }
    if (sc != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        const char *msg;
        int ec;
        if (sc == UA_STATUSCODE_BADTIMEOUT) {
            msg = g_sec.reverseListenPort > 0
                  ? "timed out waiting for the reverse connection"
                  : "connection timed out";
            ec  = 7;
        } else {
            msg = reverse_msg ? reverse_msg : "failed to connect";
            ec  = 3;
        }
        output_begin("open62541", op);
        output_success(0);
        output_service_result(sc);
        output_error((ec == 7) ? "timeout" : "transport", msg);
        output_end();
        *exit_code = ec;
        return NULL;
    }

    return client;
}

/* -------------------------------------------------------------------------
 * NodeId resolution helper — validate + parse all --node args
 * ---------------------------------------------------------------------- */

#define MAX_NODES 128

/*
 * Validate node strings, parse non-nsu forms, connect client (via make_client),
 * then resolve nsu= forms.
 *
 * nodes[]  - raw --node arg strings
 * n        - count
 * ids[]    - output UA_NodeId array (caller must UA_NodeId_clear each)
 * op       - operation name for error envelopes
 * url      - endpoint URL
 * req_ms   - request timeout in ms
 * exit_code - set on failure
 *
 * Returns connected client on success, NULL on failure (envelope already emitted).
 */
static UA_Client *resolve_node_ids(const char **nodes, int n,
                                    UA_NodeId *ids,
                                    const char *op,
                                    const char *url,
                                    int req_ms,
                                    int *exit_code) {
    /* Phase 1: structural validation (before any network I/O) */
    for (int i = 0; i < n; i++) {
        if (validate_nodeid_structure(nodes[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodes[i]);
            output_begin("open62541", op);
            output_success(0);
            output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
            output_error("input", msg);
            output_end();
            *exit_code = 2;
            return NULL;
        }
    }

    /* Phase 2: parse non-nsu forms */
    int has_nsu = 0;
    for (int i = 0; i < n; i++) {
        UA_NodeId_init(&ids[i]);
        if (strncmp(nodes[i], "nsu=", 4) == 0) {
            has_nsu = 1;
        } else {
            ids[i] = parse_nodeid_local(nodes[i]);
        }
    }

    /* Phase 3: connect */
    UA_Client *client = make_client(url, req_ms, op, exit_code);
    if (!client) {
        for (int i = 0; i < n; i++) UA_NodeId_clear(&ids[i]);
        return NULL;
    }

    /* Phase 4: resolve nsu= forms */
    if (has_nsu) {
        for (int i = 0; i < n; i++) {
            if (strncmp(nodes[i], "nsu=", 4) != 0) continue;

            int r = resolve_nsu_nodeid(client, nodes[i], &ids[i]);
            if (r != 0) {
                /* Clean up already-resolved ids */
                for (int j = 0; j < n; j++) UA_NodeId_clear(&ids[j]);
                UA_Client_disconnect(client);
                UA_Client_delete(client);

                char msg[512];
                if (r == -1) {
                    /* Extract URI for message */
                    const char *uri_end = strchr(nodes[i] + 4, ';');
                    if (uri_end) {
                        int uri_len = (int)(uri_end - (nodes[i] + 4));
                        snprintf(msg, sizeof(msg), "unknown namespace URI: '%.*s'",
                                 uri_len, nodes[i] + 4);
                    } else {
                        snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodes[i]);
                    }
                    output_begin("open62541", op);
                    output_success(0);
                    output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
                    output_error("input", msg);
                    output_end();
                } else {
                    snprintf(msg, sizeof(msg), "failed to resolve NodeId: '%s'", nodes[i]);
                    output_begin("open62541", op);
                    output_success(0);
                    output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
                    output_error("input", msg);
                    output_end();
                }
                *exit_code = 2;
                return NULL;
            }
        }
    }

    return client;
}

/* -------------------------------------------------------------------------
 * Session-less clients (discovery services)
 * ---------------------------------------------------------------------- */

UA_Client *cli_new_plain_client(int request_ms) {
    UA_Client *client = UA_Client_new();
    if (!client) return NULL;
    UA_ClientConfig *cfg = UA_Client_getConfig(client);
    client_silence_logger(cfg);
    UA_ClientConfig_setDefault(cfg);
    client_silence_logger(cfg);
    if (request_ms > 0) cfg->timeout = (UA_UInt32)request_ms;
    return client;
}

/*
 * Run one session-less service on a reverse connection. The stack may close
 * the first channel after its own GetEndpoints handshake (see
 * reverse_connect); the call is then repeated on the server's next attempt.
 */
static UA_StatusCode reverse_discovery_call(UA_Client *client,
                                            const void *req, const UA_DataType *reqType,
                                            void *resp, const UA_DataType *respType) {
    int timeout_ms = g_sec.reverseTimeoutMs > 0 ? g_sec.reverseTimeoutMs : 30000;
    long long deadline = mono_ms() + timeout_ms;
    UA_StatusCode sc = UA_STATUSCODE_BADTIMEOUT;
    while (mono_ms() < deadline) {
        sc = reverse_connect(client, 0);
        if (sc != UA_STATUSCODE_GOOD) return sc;
        UA_clear(resp, respType);
        UA_init(resp, respType);
        __UA_Client_Service(client, req, reqType, resp, respType);
        sc = ((UA_ResponseHeader *)resp)->serviceResult;
        if (sc != UA_STATUSCODE_BADCONNECTIONCLOSED &&
            sc != UA_STATUSCODE_BADSECURECHANNELCLOSED &&
            sc != UA_STATUSCODE_BADNOTCONNECTED &&
            sc != UA_STATUSCODE_BADSERVERNOTCONNECTED)
            return sc;
    }
    return sc;
}

/* -------------------------------------------------------------------------
 * Security mode name
 * ---------------------------------------------------------------------- */

static const char *security_mode_name(UA_MessageSecurityMode mode) {
    switch (mode) {
        case UA_MESSAGESECURITYMODE_NONE:           return "None";
        case UA_MESSAGESECURITYMODE_SIGN:           return "Sign";
        case UA_MESSAGESECURITYMODE_SIGNANDENCRYPT: return "SignAndEncrypt";
        default:                                    return "Invalid";
    }
}

/* -------------------------------------------------------------------------
 * endpoints subcommand
 * ---------------------------------------------------------------------- */

static int cmd_endpoints(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        output_begin("open62541", "endpoints");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    UA_Client *client = cli_new_plain_client(0);
    if (!client) {
        output_begin("open62541", "endpoints");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
        output_error("internal", "UA_Client_new failed");
        output_end();
        return 6;
    }

    UA_EndpointDescription *eps = NULL;
    size_t epCount = 0;
    UA_StatusCode sc;
    UA_GetEndpointsResponse revResp;
    UA_GetEndpointsResponse_init(&revResp);
    if (g_sec.reverseListenPort > 0) {
        /* GetEndpoints on the SecureChannel the server opened towards us. */
        UA_GetEndpointsRequest req;
        UA_GetEndpointsRequest_init(&req);
        req.endpointUrl = UA_STRING((char *)(uintptr_t)endpoint);
        sc = reverse_discovery_call(client, &req, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST],
                                    &revResp, &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE]);
        if (sc == UA_STATUSCODE_GOOD) {
            eps = revResp.endpoints;
            epCount = revResp.endpointsSize;
            revResp.endpoints = NULL;
            revResp.endpointsSize = 0;
        }
        UA_GetEndpointsResponse_clear(&revResp);
        UA_Client_disconnect(client);
    } else {
        sc = UA_Client_getEndpoints(client, endpoint, &epCount, &eps);
    }

    /* Milo/Netty warm-up: the very first GetEndpoints call occasionally fails with
     * BadSecureChannelClosed before Netty's thread pool is fully ready.  Retry once. */
    if (g_sec.reverseListenPort <= 0 &&
        (sc == UA_STATUSCODE_BADSECURECHANNELCLOSED ||
         sc == UA_STATUSCODE_BADSECURECHANNELIDINVALID)) {
        UA_Client_delete(client);
        client = cli_new_plain_client(0);
        if (!client) {
            output_begin("open62541", "endpoints");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
            output_error("internal", "UA_Client_new failed on retry");
            output_end();
            return 6;
        }
        sc = UA_Client_getEndpoints(client, endpoint, &epCount, &eps);
    }

    UA_Client_delete(client);

    int ok = (sc == UA_STATUSCODE_GOOD);
    output_begin("open62541", "endpoints");
    output_success(ok);
    output_service_result(sc);

    if (ok) {
        output_open_results();
        for (size_t i = 0; i < epCount; i++) {
            UA_EndpointDescription *ep = &eps[i];
            if (i > 0) printf(",");

            char url_buf[512] = "";
            if (ep->endpointUrl.data && ep->endpointUrl.length < sizeof(url_buf) - 1) {
                memcpy(url_buf, ep->endpointUrl.data, ep->endpointUrl.length);
                url_buf[ep->endpointUrl.length] = '\0';
            }

            char pol_buf[512] = "";
            if (ep->securityPolicyUri.data &&
                ep->securityPolicyUri.length < sizeof(pol_buf) - 1) {
                memcpy(pol_buf, ep->securityPolicyUri.data, ep->securityPolicyUri.length);
                pol_buf[ep->securityPolicyUri.length] = '\0';
            }

            printf("{\"url\":\"%s\",\"securityPolicy\":\"%s\",\"securityMode\":\"%s\"}",
                   url_buf, pol_buf, security_mode_name(ep->securityMode));
        }
        output_close_results();
        output_null_error();
    } else {
        output_error("transport", "GetEndpoints failed");
    }

    output_end();
    if (eps) UA_Array_delete(eps, epCount, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    return ok ? 0 : 3;
}

/* -------------------------------------------------------------------------
 * find-servers subcommand
 * ---------------------------------------------------------------------- */

static void copy_ua_string(char *buf, size_t bufsz, const UA_String *s) {
    if (!buf || bufsz == 0) return;
    buf[0] = '\0';
    if (!s || !s->data || s->length == 0 || s->length >= bufsz) return;
    memcpy(buf, s->data, s->length);
    buf[s->length] = '\0';
}

static int cmd_find_servers(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        output_begin("open62541", "find-servers");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    UA_Client *client = cli_new_plain_client(0);
    if (!client) {
        output_begin("open62541", "find-servers");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
        output_error("internal", "UA_Client_new failed");
        output_end();
        return 6;
    }

    UA_ApplicationDescription *apps = NULL;
    size_t appCount = 0;
    UA_StatusCode sc;
    if (g_sec.reverseListenPort > 0) {
        /* FindServers on the SecureChannel the server opened towards us. */
        UA_FindServersRequest req;
        UA_FindServersRequest_init(&req);
        UA_FindServersResponse resp;
        UA_FindServersResponse_init(&resp);
        sc = reverse_discovery_call(client, &req, &UA_TYPES[UA_TYPES_FINDSERVERSREQUEST],
                                    &resp, &UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE]);
        if (sc == UA_STATUSCODE_GOOD) {
            apps = resp.servers;
            appCount = resp.serversSize;
            resp.servers = NULL;
            resp.serversSize = 0;
        }
        UA_FindServersResponse_clear(&resp);
        UA_Client_disconnect(client);
    } else {
        sc = UA_Client_findServers(client, endpoint,
                                   0, NULL, 0, NULL,
                                   &appCount, &apps);
    }

    /* Milo/Netty warm-up retry (same as GetEndpoints). */
    if (g_sec.reverseListenPort <= 0 &&
        (sc == UA_STATUSCODE_BADSECURECHANNELCLOSED ||
         sc == UA_STATUSCODE_BADSECURECHANNELIDINVALID)) {
        UA_Client_delete(client);
        client = cli_new_plain_client(0);
        if (!client) {
            output_begin("open62541", "find-servers");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
            output_error("internal", "UA_Client_new failed on retry");
            output_end();
            return 6;
        }
        sc = UA_Client_findServers(client, endpoint,
                                   0, NULL, 0, NULL,
                                   &appCount, &apps);
    }

    UA_Client_delete(client);

    int ok = (sc == UA_STATUSCODE_GOOD);
    output_begin("open62541", "find-servers");
    output_success(ok);
    output_service_result(sc);

    if (ok) {
        output_open_results();
        for (size_t i = 0; i < appCount; i++) {
            UA_ApplicationDescription *app = &apps[i];
            if (i > 0) printf(",");

            char uri_buf[512] = "";
            char prod_buf[512] = "";
            char name_locale[64] = "";
            char name_text[512] = "";
            copy_ua_string(uri_buf, sizeof(uri_buf), &app->applicationUri);
            copy_ua_string(prod_buf, sizeof(prod_buf), &app->productUri);
            copy_ua_string(name_locale, sizeof(name_locale), &app->applicationName.locale);
            copy_ua_string(name_text, sizeof(name_text), &app->applicationName.text);

            printf("{\"applicationUri\":\"%s\",\"applicationName\":{\"locale\":\"%s\",\"text\":\"%s\"},"
                   "\"productUri\":\"%s\",\"discoveryUrls\":[",
                   uri_buf, name_locale, name_text, prod_buf);
            for (size_t j = 0; j < app->discoveryUrlsSize; j++) {
                char url_buf[512] = "";
                copy_ua_string(url_buf, sizeof(url_buf), &app->discoveryUrls[j]);
                if (j > 0) printf(",");
                printf("\"%s\"", url_buf);
            }
            printf("]}");
        }
        output_close_results();
        output_null_error();
    } else {
        output_error("transport", "FindServers failed");
    }

    output_end();
    if (apps) UA_Array_delete(apps, appCount, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    return ok ? 0 : 3;
}

/* -------------------------------------------------------------------------
 * translate subcommand
 * ---------------------------------------------------------------------- */

static int cmd_translate(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        output_begin("open62541", "translate");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    const char *startStr = find_arg(argc, argv, "--starting-node");
    if (!startStr) startStr = "i=85";

    const char *pathStr = find_arg(argc, argv, "--path");
    if (!pathStr || !*pathStr) {
        output_begin("open62541", "translate");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --path");
        output_end();
        return 2;
    }

    if (validate_nodeid_structure(startStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", startStr);
        output_begin("open62541", "translate");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    UA_UInt16 ns = 0;
    const char *nsStr = find_arg(argc, argv, "--namespace");
    if (nsStr) ns = (UA_UInt16)atoi(nsStr);

    /* Split --path on '.' into browse-name segments. */
    char *path_copy = strdup(pathStr);
    if (!path_copy) {
        output_begin("open62541", "translate");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADOUTOFMEMORY);
        output_error("internal", "strdup failed");
        output_end();
        return 6;
    }
    char *segments[64];
    int segCount = 0;
    char *tok = strtok(path_copy, ".");
    while (tok && segCount < 64) {
        if (*tok) segments[segCount++] = tok;
        tok = strtok(NULL, ".");
    }
    if (segCount == 0) {
        free(path_copy);
        output_begin("open62541", "translate");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "empty --path");
        output_end();
        return 2;
    }

    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "translate", &exit_code);
    if (!client) {
        free(path_copy);
        return exit_code;
    }

    UA_NodeId startingNode;
    UA_NodeId_init(&startingNode);
    if (strncmp(startStr, "nsu=", 4) == 0) {
        int r = resolve_nsu_nodeid(client, startStr, &startingNode);
        if (r != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            free(path_copy);
            char msg[512];
            snprintf(msg, sizeof(msg), "failed to resolve NodeId: '%s'", startStr);
            output_begin("open62541", "translate");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        startingNode = parse_nodeid_local(startStr);
    }

    UA_BrowsePath browsePath;
    UA_BrowsePath_init(&browsePath);
    UA_NodeId_copy(&startingNode, &browsePath.startingNode);
    browsePath.relativePath.elements = (UA_RelativePathElement *)
        UA_Array_new((size_t)segCount, &UA_TYPES[UA_TYPES_RELATIVEPATHELEMENT]);
    browsePath.relativePath.elementsSize = (size_t)segCount;
    for (int i = 0; i < segCount; i++) {
        UA_RelativePathElement *elem = &browsePath.relativePath.elements[i];
        elem->referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
        elem->isInverse = UA_FALSE;
        elem->includeSubtypes = UA_TRUE;
        elem->targetName = UA_QUALIFIEDNAME_ALLOC(ns, segments[i]);
    }

    UA_TranslateBrowsePathsToNodeIdsRequest req;
    UA_TranslateBrowsePathsToNodeIdsRequest_init(&req);
    req.browsePaths = &browsePath;
    req.browsePathsSize = 1;

    UA_TranslateBrowsePathsToNodeIdsResponse resp =
        UA_Client_Service_translateBrowsePathsToNodeIds(client, req);

    /* Clear browse path (owned elements) without freeing the stack request. */
    UA_BrowsePath_clear(&browsePath);
    free(path_copy);
    UA_NodeId_clear(&startingNode);

    UA_StatusCode sc = resp.responseHeader.serviceResult;
    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0 &&
        !UA_StatusCode_isGood(resp.results[0].statusCode)) {
        sc = resp.results[0].statusCode;
    }

    int ok = UA_StatusCode_isGood(sc);
    output_begin("open62541", "translate");
    output_success(ok);
    output_service_result(resp.responseHeader.serviceResult);

    if (UA_StatusCode_isGood(resp.responseHeader.serviceResult) && resp.resultsSize > 0) {
        output_open_results();
        UA_BrowsePathResult *bpr = &resp.results[0];
        printf("{\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"},\"targets\":[",
               output_status_code_name(bpr->statusCode),
               (uint32_t)bpr->statusCode,
               output_severity(bpr->statusCode));
        for (size_t i = 0; i < bpr->targetsSize; i++) {
            if (i > 0) printf(",");
            output_nodeid(&bpr->targets[i].targetId.nodeId);
        }
        printf("]}");
        output_close_results();
        output_null_error();
    } else if (ok) {
        output_no_results();
    } else {
        output_error("service", "TranslateBrowsePathsToNodeIds failed");
    }

    output_end();
    UA_TranslateBrowsePathsToNodeIdsResponse_clear(&resp);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * read subcommand
 * ---------------------------------------------------------------------- */

static int cmd_read(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        output_begin("open62541", "read");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;

    /* Collect all --node arguments */
    int node_count = count_flag(argc, argv, "--node");
    if (node_count == 0) {
        output_begin("open62541", "read");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --node");
        output_end();
        return 2;
    }
    if (node_count > MAX_NODES) node_count = MAX_NODES;

    const char *nodes[MAX_NODES];
    int n = 0;
    for (int i = 0; i < argc - 1 && n < MAX_NODES; i++) {
        if (strcmp(argv[i], "--node") == 0)
            nodes[n++] = argv[i + 1];
    }

    UA_NodeId ids[MAX_NODES];
    int exit_code = 3;
    UA_Client *client = resolve_node_ids(nodes, n, ids, "read", endpoint, req_ms, &exit_code);
    if (!client) return exit_code;

    /* Optional IndexRange applied to every ReadValueId. */
    const char *indexRange = find_arg(argc, argv, "--index-range");
    /* TimestampsToReturn: Source|Server|Both|Neither (default Source). */
    const char *tsStr = find_arg(argc, argv, "--timestamps");
    UA_TimestampsToReturn ts = UA_TIMESTAMPSTORETURN_SOURCE;
    if (tsStr) {
        if (strcmp(tsStr, "Source") == 0)       ts = UA_TIMESTAMPSTORETURN_SOURCE;
        else if (strcmp(tsStr, "Server") == 0)  ts = UA_TIMESTAMPSTORETURN_SERVER;
        else if (strcmp(tsStr, "Both") == 0)    ts = UA_TIMESTAMPSTORETURN_BOTH;
        else if (strcmp(tsStr, "Neither") == 0) ts = UA_TIMESTAMPSTORETURN_NEITHER;
    }

    /* Batch read via ReadService */
    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.timestampsToReturn = ts;
    req.nodesToRead = (UA_ReadValueId *)UA_Array_new((size_t)n,
                          &UA_TYPES[UA_TYPES_READVALUEID]);
    req.nodesToReadSize = (size_t)n;

    for (int i = 0; i < n; i++) {
        UA_ReadValueId_init(&req.nodesToRead[i]);
        UA_NodeId_copy(&ids[i], &req.nodesToRead[i].nodeId);
        req.nodesToRead[i].attributeId = UA_ATTRIBUTEID_VALUE;
        if (indexRange && indexRange[0])
            req.nodesToRead[i].indexRange = UA_STRING_ALLOC(indexRange);
    }

    UA_ReadResponse resp = UA_Client_Service_read(client, req);
    UA_ReadRequest_clear(&req);

    UA_StatusCode svc_sc = resp.responseHeader.serviceResult;

    /* Determine overall success: service must be Good, and all per-item Good */
    int all_good = UA_StatusCode_isGood(svc_sc);
    if (all_good) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i].status)) {
                all_good = 0;
                break;
            }
        }
    }

    /* Promote worst per-item status to serviceResult when service itself is Good */
    UA_StatusCode emit_sc = svc_sc;
    if (UA_StatusCode_isGood(svc_sc) && !all_good) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i].status)) {
                emit_sc = resp.results[i].status;
                break;
            }
        }
    }

    output_begin("open62541", "read");
    output_success(all_good);
    output_service_result(emit_sc);
    output_open_results();

    if (UA_StatusCode_isGood(svc_sc)) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            UA_DataValue *dv = &resp.results[i];
            const char *dt_name = (dv->hasValue && dv->value.type)
                                   ? type_name(dv->value.type) : "Unknown";
            int bi = (dv->hasValue && dv->value.type)
                      ? ua_type_to_builtin_id(dv->value.type) : 0;
            UA_DateTime src_ts = dv->hasSourceTimestamp ? dv->sourceTimestamp : 0;
            if (i > 0) printf(",");
            output_read_result_item(nodes[i], dv->status, dt_name, bi,
                                    dv->hasValue ? &dv->value : NULL, src_ts);
        }
    }

    output_close_results();
    output_null_error();
    output_end();

    UA_ReadResponse_clear(&resp);
    for (int i = 0; i < n; i++) UA_NodeId_clear(&ids[i]);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (svc_sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    if (!UA_StatusCode_isGood(svc_sc))      return 4;
    if (!all_good)                           return 4;
    return 0;
}

/* -------------------------------------------------------------------------
 * write subcommand
 * ---------------------------------------------------------------------- */

/* Literal -> Variant for `write --type/--value` and `call --input`. The
 * literal grammar (all 25 built-in types, `Type[]` arrays) lives in values.c.
 * An unknown type or unparsable literal yields an empty Variant, which the
 * server answers with its own status (typically BadTypeMismatch). */
static UA_Variant build_write_variant(const char *typeStr, const char *valStr) {
    UA_Variant var; UA_Variant_init(&var);
    if (!typeStr || !valStr) return var;
    char errBuf[256];
    if (value_parse(typeStr, valStr, NULL, &var, errBuf, sizeof(errBuf)) != 0) {
        fprintf(stderr, "[open62541] warn: %s\n", errBuf);
        UA_Variant_init(&var);
    }
    return var;
}

static int cmd_write(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    int node_count = count_flag(argc, argv, "--node");
    int type_count = count_flag(argc, argv, "--type");
    int val_count  = count_flag(argc, argv, "--value");

    if (!endpoint || node_count == 0 || type_count == 0 || val_count == 0 ||
        node_count != type_count || node_count != val_count) {
        output_begin("open62541", "write");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
                     "usage: write --endpoint <url> --node <id> --type <t> --value <v> "
                     "[--node ... --type ... --value ...] (equal counts required)");
        output_end();
        return 2;
    }
    if (node_count > MAX_NODES) node_count = MAX_NODES;

    const char *nodes[MAX_NODES];
    const char *types[MAX_NODES];
    const char *vals[MAX_NODES];
    int nn = 0, nt = 0, nv = 0;
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], "--node") == 0 && nn < MAX_NODES)
            nodes[nn++] = argv[i + 1];
        else if (strcmp(argv[i], "--type") == 0 && nt < MAX_NODES)
            types[nt++] = argv[i + 1];
        else if (strcmp(argv[i], "--value") == 0 && nv < MAX_NODES)
            vals[nv++] = argv[i + 1];
    }

    for (int i = 0; i < node_count; i++) {
        if (validate_nodeid_structure(nodes[i]) != 0) {
            char msg[512];
            snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodes[i]);
            output_begin("open62541", "write");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
            output_error("input", msg);
            output_end();
            return 2;
        }
    }

    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_NodeId ids[MAX_NODES];
    UA_Client *client = resolve_node_ids(nodes, node_count, ids, "write",
                                         endpoint, req_ms, &exit_code);
    if (!client) return exit_code;

    /* Optional IndexRange applied to every WriteValue. */
    const char *indexRange = find_arg(argc, argv, "--index-range");

    UA_WriteRequest req;
    UA_WriteRequest_init(&req);
    req.nodesToWrite = (UA_WriteValue *)UA_Array_new((size_t)node_count,
                            &UA_TYPES[UA_TYPES_WRITEVALUE]);
    req.nodesToWriteSize = (size_t)node_count;

    UA_Variant vars[MAX_NODES];
    for (int i = 0; i < node_count; i++) {
        UA_WriteValue_init(&req.nodesToWrite[i]);
        UA_NodeId_copy(&ids[i], &req.nodesToWrite[i].nodeId);
        req.nodesToWrite[i].attributeId = UA_ATTRIBUTEID_VALUE;
        if (indexRange && indexRange[0])
            req.nodesToWrite[i].indexRange = UA_STRING_ALLOC(indexRange);
        vars[i] = build_write_variant(types[i], vals[i]);
        UA_Variant_copy(&vars[i], &req.nodesToWrite[i].value.value);
        req.nodesToWrite[i].value.hasValue = true;
    }

    UA_WriteResponse resp = UA_Client_Service_write(client, req);
    UA_WriteRequest_clear(&req);

    UA_StatusCode svc_sc = resp.responseHeader.serviceResult;
    int all_good = UA_StatusCode_isGood(svc_sc);
    if (all_good) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i])) {
                all_good = 0;
                break;
            }
        }
    }

    UA_StatusCode emit_sc = svc_sc;
    if (UA_StatusCode_isGood(svc_sc) && !all_good && resp.resultsSize > 0) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i])) {
                emit_sc = resp.results[i];
                break;
            }
        }
    }

    output_begin("open62541", "write");
    output_success(all_good);
    output_service_result(emit_sc);
    output_open_results();
    if (UA_StatusCode_isGood(svc_sc)) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (i > 0) printf(",");
            output_write_result_item(nodes[i], resp.results[i]);
        }
    }
    output_close_results();
    output_null_error();
    output_end();

    int ret;
    if (svc_sc == UA_STATUSCODE_BADTIMEOUT) ret = 7;
    else if (!UA_StatusCode_isGood(svc_sc) || !all_good) ret = 4;
    else ret = 0;

    for (int i = 0; i < node_count; i++) {
        UA_Variant_clear(&vars[i]);
        UA_NodeId_clear(&ids[i]);
    }
    UA_WriteResponse_clear(&resp);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return ret;
}

/* -------------------------------------------------------------------------
 * browse subcommand
 * ---------------------------------------------------------------------- */

static int cmd_browse(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    if (!endpoint) {
        output_begin("open62541", "browse");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "missing --endpoint");
        output_end();
        return 2;
    }

    /* Default starting node: i=85 (Objects folder) */
    const char *nodeStr = find_arg(argc, argv, "--node");
    if (!nodeStr) nodeStr = "i=85";

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "browse");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int max_refs = parse_int_flag(argc, argv, "--max-refs", 0);
    int req_ms   = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    /* NodeClassMask: 0 = all classes. Variable = 2. */
    const char *ncmStr = find_arg(argc, argv, "--node-class-mask");
    UA_UInt32 nodeClassMask = ncmStr ? (UA_UInt32)strtoul(ncmStr, NULL, 0) : 0;
    /* IncludeSubtypes: default true; --include-subtypes false for exact RefType match. */
    const char *incStr = find_arg(argc, argv, "--include-subtypes");
    UA_Boolean includeSubtypes = UA_TRUE;
    if (incStr && (strcmp(incStr, "false") == 0 || strcmp(incStr, "0") == 0))
        includeSubtypes = UA_FALSE;
    /* ResultMask: default ALL; e.g. --result-mask 8 for BrowseName only. */
    const char *rmStr = find_arg(argc, argv, "--result-mask");
    UA_UInt32 resultMask = rmStr ? (UA_UInt32)strtoul(rmStr, NULL, 0)
                                 : UA_BROWSERESULTMASK_ALL;

    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "browse", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId;
    UA_NodeId_init(&nodeId);

    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        int r = resolve_nsu_nodeid(client, nodeStr, &nodeId);
        if (r != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            if (r == -1) {
                const char *uri_end = strchr(nodeStr + 4, ';');
                if (uri_end)
                    snprintf(msg, sizeof(msg), "unknown namespace URI: '%.*s'",
                             (int)(uri_end - (nodeStr + 4)), nodeStr + 4);
                else
                    snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            } else {
                snprintf(msg, sizeof(msg), "failed to resolve NodeId: '%s'", nodeStr);
            }
            output_begin("open62541", "browse");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    /* Initial browse request */
    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.requestedMaxReferencesPerNode = (UA_UInt32)max_refs;
    req.nodesToBrowse = UA_BrowseDescription_new();
    req.nodesToBrowseSize = 1;
    UA_NodeId_copy(&nodeId, &req.nodesToBrowse[0].nodeId);
    req.nodesToBrowse[0].browseDirection = UA_BROWSEDIRECTION_FORWARD;
    req.nodesToBrowse[0].referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
    req.nodesToBrowse[0].includeSubtypes  = includeSubtypes;
    req.nodesToBrowse[0].nodeClassMask    = nodeClassMask;
    req.nodesToBrowse[0].resultMask       = resultMask;

    UA_BrowseResponse resp = UA_Client_Service_browse(client, req);
    UA_BrowseRequest_clear(&req);

    UA_StatusCode sc = resp.responseHeader.serviceResult;
    /* Promote per-item BrowseResult status when the service header is Good. */
    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0 &&
        !UA_StatusCode_isGood(resp.results[0].statusCode)) {
        sc = resp.results[0].statusCode;
    }

    /* Accumulate all references, following continuation points */
    UA_ReferenceDescription *allRefs  = NULL;
    size_t                   allCount = 0;

    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0) {
        size_t initial = resp.results[0].referencesSize;
        if (initial > 0) {
            allRefs = (UA_ReferenceDescription *)UA_Array_new(
                initial, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
            if (allRefs) {
                for (size_t i = 0; i < initial; i++)
                    UA_ReferenceDescription_copy(&resp.results[0].references[i],
                                                 &allRefs[i]);
                allCount = initial;
            }
        }

        /* Follow continuation points */
        UA_ByteString cp = UA_BYTESTRING_NULL;
        UA_ByteString_copy(&resp.results[0].continuationPoint, &cp);

        while (cp.length > 0) {
            UA_BrowseNextRequest nreq;
            UA_BrowseNextRequest_init(&nreq);
            nreq.releaseContinuationPoints     = UA_FALSE;
            nreq.continuationPoints            = &cp;
            nreq.continuationPointsSize        = 1;

            UA_BrowseNextResponse nresp = UA_Client_Service_browseNext(client, nreq);

            if (nresp.responseHeader.serviceResult != UA_STATUSCODE_GOOD ||
                nresp.resultsSize == 0) {
                UA_BrowseNextResponse_clear(&nresp);
                break;
            }

            size_t extra = nresp.results[0].referencesSize;
            if (extra > 0) {
                size_t newCount = allCount + extra;
                UA_ReferenceDescription *newRefs = (UA_ReferenceDescription *)
                    UA_Array_new(newCount, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
                if (newRefs) {
                    for (size_t i = 0; i < allCount; i++)
                        UA_ReferenceDescription_copy(&allRefs[i], &newRefs[i]);
                    for (size_t i = 0; i < extra; i++)
                        UA_ReferenceDescription_copy(&nresp.results[0].references[i],
                                                     &newRefs[allCount + i]);
                    if (allRefs)
                        UA_Array_delete(allRefs, allCount,
                                        &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
                    allRefs  = newRefs;
                    allCount = newCount;
                }
            }

            UA_ByteString_clear(&cp);
            UA_ByteString_copy(&nresp.results[0].continuationPoint, &cp);
            UA_BrowseNextResponse_clear(&nresp);
        }
        UA_ByteString_clear(&cp);
    }

    UA_BrowseResponse_clear(&resp);

    int ok = UA_StatusCode_isGood(sc);
    output_begin("open62541", "browse");
    output_success(ok);
    output_service_result(sc);

    if (ok) {
        output_browse_results(allRefs, allCount);
    } else {
        output_error("service", "Browse service failed");
    }

    output_end();

    if (allRefs)
        UA_Array_delete(allRefs, allCount, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * call subcommand
 * ---------------------------------------------------------------------- */

static int cmd_call(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *objStr   = find_arg(argc, argv, "--object");
    const char *methStr  = find_arg(argc, argv, "--method");
    if (!endpoint || !objStr || !methStr) {
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: call --endpoint <url> --object <nodeId> --method <nodeId>"
            " [--input <type:val> ...]");
        output_end();
        return 2;
    }

    if (validate_nodeid_structure(objStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", objStr);
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }
    if (validate_nodeid_structure(methStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", methStr);
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int req_ms   = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "call", &exit_code);
    if (!client) return exit_code;

    UA_NodeId objectId; UA_NodeId_init(&objectId);
    UA_NodeId methodId; UA_NodeId_init(&methodId);

    int   resolve_rc = 0;
    char  resolve_msg[512] = "";

    if (strncmp(objStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, objStr, &objectId) != 0) {
            snprintf(resolve_msg, sizeof(resolve_msg),
                     "unknown namespace URI in object NodeId: '%s'", objStr);
            resolve_rc = 1;
        }
    } else {
        objectId = parse_nodeid_local(objStr);
    }

    if (resolve_rc == 0 && strncmp(methStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, methStr, &methodId) != 0) {
            snprintf(resolve_msg, sizeof(resolve_msg),
                     "unknown namespace URI in method NodeId: '%s'", methStr);
            resolve_rc = 1;
        }
    } else if (resolve_rc == 0) {
        methodId = parse_nodeid_local(methStr);
    }

    if (resolve_rc != 0) {
        UA_NodeId_clear(&objectId);
        UA_NodeId_clear(&methodId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        output_begin("open62541", "call");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
        output_error("input", resolve_msg);
        output_end();
        return 2;
    }

    int inCount = count_flag(argc, argv, "--input");
    UA_Variant *inputs = (UA_Variant *)calloc(
        (size_t)(inCount > 0 ? inCount : 1), sizeof(UA_Variant));
    if (!inputs) {
        UA_NodeId_clear(&objectId);
        UA_NodeId_clear(&methodId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        return 6;
    }

    int ni = 0;
    for (int i = 0; i < argc - 1 && ni < inCount; i++) {
        if (strcmp(argv[i], "--input") == 0) {
            const char *spec  = argv[i + 1];
            const char *colon = strchr(spec, ':');
            if (colon) {
                char typeStr[64];
                size_t tl = (size_t)(colon - spec);
                if (tl >= sizeof(typeStr)) tl = sizeof(typeStr) - 1;
                memcpy(typeStr, spec, tl);
                typeStr[tl] = '\0';
                inputs[ni] = build_write_variant(typeStr, colon + 1);
            }
            ni++;
        }
    }

    UA_Variant *outputs     = NULL;
    size_t      outputsSize = 0;
    UA_StatusCode sc = UA_Client_call(client, objectId, methodId,
                                      (size_t)inCount, inputs,
                                      &outputsSize, &outputs);

    int ok = UA_StatusCode_isGood(sc);
    output_begin("open62541", "call");
    output_success(ok);
    output_service_result(sc);
    output_open_results();
    output_call_result(objStr, methStr, sc, outputs, outputsSize);
    output_close_results();
    output_null_error();
    output_end();

    int ret;
    if      (sc == UA_STATUSCODE_BADTIMEOUT) ret = 7;
    else if (!ok)                             ret = 4;
    else                                      ret = 0;

    for (int i = 0; i < inCount; i++) UA_Variant_clear(&inputs[i]);
    free(inputs);
    /* UA_Array_delete: a method without outputs returns the empty-array
     * sentinel, which UA_free must not see. */
    if (outputs) UA_Array_delete(outputs, outputsSize, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_NodeId_clear(&objectId);
    UA_NodeId_clear(&methodId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return ret;
}

/* -------------------------------------------------------------------------
 * subscribe subcommand
 * ---------------------------------------------------------------------- */

#define MAX_NOTIFICATIONS 256

typedef struct {
    int      index;
    uint32_t statusCode;
    char     dataType[64];
    int      builtInType;
    char     valueJson[512];
    char     sourceTimestamp[64];
    char     serverTimestamp[64];
} NotifEntry;

typedef struct {
    int        wanted;
    int        count;
    NotifEntry entries[MAX_NOTIFICATIONS];
} NotifStore;

static void sub_data_change_cb(UA_Client *client, UA_UInt32 subId,
    void *subCtx, UA_UInt32 monId, void *monCtx, UA_DataValue *val) {
    (void)client; (void)subId; (void)subCtx; (void)monId;
    NotifStore *store = (NotifStore *)monCtx;
    if (!store || store->count >= MAX_NOTIFICATIONS) return;

    NotifEntry *e = &store->entries[store->count];
    e->index      = store->count;
    e->statusCode = (uint32_t)(val->hasStatus ? val->status : UA_STATUSCODE_GOOD);
    e->sourceTimestamp[0] = '\0';
    e->serverTimestamp[0] = '\0';
    if (val->hasSourceTimestamp)
        output_timestamp(val->sourceTimestamp, e->sourceTimestamp,
                         sizeof(e->sourceTimestamp));
    if (val->hasServerTimestamp)
        output_timestamp(val->serverTimestamp, e->serverTimestamp,
                         sizeof(e->serverTimestamp));

    if (val->hasValue && val->value.type) {
        strncpy(e->dataType, type_name(val->value.type), sizeof(e->dataType) - 1);
        e->dataType[sizeof(e->dataType) - 1] = '\0';
        e->builtInType = ua_type_to_builtin_id(val->value.type);
        output_variant_to_buf(&val->value, e->valueJson, sizeof(e->valueJson));
    } else {
        strcpy(e->dataType,  "Unknown");
        e->builtInType = 0;
        strcpy(e->valueJson, "null");
    }
    store->count++;
}

static int cmd_subscribe(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    const char *piStr    = find_arg(argc, argv, "--publishing-interval-ms");
    const char *siStr    = find_arg(argc, argv, "--sampling-interval-ms");
    const char *nStr     = find_arg(argc, argv, "--notifications");
    const char *toStr    = find_arg(argc, argv, "--timeout-ms");

    if (!endpoint || !nodeStr) {
        output_begin("open62541", "subscribe");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: subscribe --endpoint <url> --node <nodeId>"
            " [--notifications <n>] [--timeout-ms <ms>]");
        output_end();
        return 2;
    }

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "subscribe");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    double piMs    = piStr ? atof(piStr) : 500.0;
    double siMs    = siStr ? atof(siStr) : 100.0;
    int    nWanted = nStr  ? atoi(nStr)  : 5;
    int    toMs    = toStr ? atoi(toStr) : 10000;
    if (nWanted <= 0) nWanted = 5;
    if (nWanted > MAX_NOTIFICATIONS) nWanted = MAX_NOTIFICATIONS;

    /* Queue-size and discard-oldest options. */
    const char *qsStr     = find_arg(argc, argv, "--queue-size");
    const char *doStr     = find_arg(argc, argv, "--discard-oldest");
    UA_UInt32   queueSize = qsStr ? (UA_UInt32)atoi(qsStr) : 1;
    UA_Boolean  discardOldest = UA_TRUE; /* default: keep newest */
    if (doStr) {
        discardOldest = (strcmp(doStr, "false") == 0) ? UA_FALSE : UA_TRUE;
    }
    if (queueSize < 1) queueSize = 1;

    /* TimestampsToReturn: Source|Server|Both|Neither (default Both). */
    const char *tsStr = find_arg(argc, argv, "--timestamps");
    UA_TimestampsToReturn ts = UA_TIMESTAMPSTORETURN_BOTH;
    if (tsStr) {
        if (strcmp(tsStr, "Source") == 0)       ts = UA_TIMESTAMPSTORETURN_SOURCE;
        else if (strcmp(tsStr, "Server") == 0)  ts = UA_TIMESTAMPSTORETURN_SERVER;
        else if (strcmp(tsStr, "Neither") == 0) ts = UA_TIMESTAMPSTORETURN_NEITHER;
        else if (strcmp(tsStr, "Both") == 0)    ts = UA_TIMESTAMPSTORETURN_BOTH;
    }

    /* DataChangeFilter: --deadband-absolute | --deadband-percent, --trigger. */
    const char *dbAbsStr = find_arg(argc, argv, "--deadband-absolute");
    const char *dbPctStr = find_arg(argc, argv, "--deadband-percent");
    const char *trigStr  = find_arg(argc, argv, "--trigger");
    int useFilter = (dbAbsStr || dbPctStr || trigStr);
    UA_DataChangeFilter dcFilter;
    UA_DataChangeFilter_init(&dcFilter);
    dcFilter.trigger = UA_DATACHANGETRIGGER_STATUSVALUE;
    dcFilter.deadbandType = UA_DEADBANDTYPE_NONE;
    {
        const char *filterErr = NULL;
        if (dbAbsStr && dbPctStr)
            filterErr = "--deadband-absolute and --deadband-percent are mutually exclusive";
        if (trigStr) {
            if (strcmp(trigStr, "Status") == 0)
                dcFilter.trigger = UA_DATACHANGETRIGGER_STATUS;
            else if (strcmp(trigStr, "StatusValue") == 0)
                dcFilter.trigger = UA_DATACHANGETRIGGER_STATUSVALUE;
            else if (strcmp(trigStr, "StatusValueTimestamp") == 0)
                dcFilter.trigger = UA_DATACHANGETRIGGER_STATUSVALUETIMESTAMP;
            else
                filterErr = "--trigger must be Status, StatusValue or StatusValueTimestamp";
        }
        if (dbAbsStr) {
            dcFilter.deadbandType  = UA_DEADBANDTYPE_ABSOLUTE;
            dcFilter.deadbandValue = atof(dbAbsStr);
        } else if (dbPctStr) {
            dcFilter.deadbandType  = UA_DEADBANDTYPE_PERCENT;
            dcFilter.deadbandValue = atof(dbPctStr);
        }
        if (filterErr) {
            output_begin("open62541", "subscribe");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
            output_error("input", filterErr);
            output_end();
            return 2;
        }
    }

    int exit_code = 3;
    UA_Client *client = make_client(endpoint, 5000, "subscribe", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId; UA_NodeId_init(&nodeId);
    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            output_begin("open62541", "subscribe");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval  = piMs;
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode svc_sc = subResp.responseHeader.serviceResult;
    if (!UA_StatusCode_isGood(svc_sc)) {
        UA_NodeId_clear(&nodeId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        output_begin("open62541", "subscribe");
        output_success(0);
        output_service_result(svc_sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = nWanted;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    monReq.requestedParameters.samplingInterval = siMs;
    monReq.requestedParameters.queueSize        = queueSize;
    monReq.requestedParameters.discardOldest    = discardOldest;
    if (useFilter) {
        monReq.requestedParameters.filter.encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
        monReq.requestedParameters.filter.content.decoded.type =
            &UA_TYPES[UA_TYPES_DATACHANGEFILTER];
        monReq.requestedParameters.filter.content.decoded.data = &dcFilter;
    }
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subResp.subscriptionId, ts,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode mon_sc = monResp.statusCode;

    int timedOut = 0;
    if (UA_StatusCode_isGood(mon_sc)) {
        time_t start = time(NULL);
        while (store.count < nWanted) {
            if ((int)(difftime(time(NULL), start) * 1000.0) >= toMs) {
                timedOut = 1;
                break;
            }
            UA_Client_run_iterate(client, 100);
        }
    }

    int all_ok   = UA_StatusCode_isGood(mon_sc) && !timedOut;
    UA_StatusCode emit_sc = UA_StatusCode_isGood(mon_sc) ? svc_sc : mon_sc;

    output_begin("open62541", "subscribe");
    output_success(all_ok);
    output_service_result(emit_sc);

    printf(",\"results\":[{\"nodeId\":");
    output_nodeid(&nodeId);
    printf(",\"subscriptionId\":%" PRIu32, (uint32_t)subResp.subscriptionId);
    printf(",\"revisedPublishingInterval\":%.17g", subResp.revisedPublishingInterval);
    printf(",\"revisedLifetimeCount\":%" PRIu32, (uint32_t)subResp.revisedLifetimeCount);
    printf(",\"revisedMaxKeepAliveCount\":%" PRIu32, (uint32_t)subResp.revisedMaxKeepAliveCount);
    printf(",\"monitoredItemStatusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
           ",\"severity\":\"%s\"}",
           output_status_code_name(mon_sc), (uint32_t)mon_sc,
           output_severity(mon_sc));
    if (useFilter) {
        /* Only present when a DataChangeFilter was requested, so the result
         * of unfiltered subscriptions is unchanged. */
        static const char *trigNames[] = { "Status", "StatusValue", "StatusValueTimestamp" };
        static const char *dbNames[]   = { "None", "Absolute", "Percent" };
        printf(",\"monitoredItemId\":%" PRIu32, (uint32_t)monResp.monitoredItemId);
        printf(",\"revisedSamplingInterval\":%.17g", monResp.revisedSamplingInterval);
        printf(",\"revisedQueueSize\":%" PRIu32, (uint32_t)monResp.revisedQueueSize);
        printf(",\"filter\":{\"trigger\":\"%s\",\"deadbandType\":\"%s\",\"deadbandValue\":%.17g}",
               trigNames[dcFilter.trigger], dbNames[dcFilter.deadbandType],
               dcFilter.deadbandValue);
        printf(",\"filterResult\":");
        const UA_ExtensionObject *fr = &monResp.filterResult;
        if (fr->encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY) {
            printf("null");
        } else if (fr->encoding == UA_EXTENSIONOBJECT_DECODED ||
                   fr->encoding == UA_EXTENSIONOBJECT_DECODED_NODELETE) {
            printf("{\"typeId\":");
            output_nodeid(&fr->content.decoded.type->typeId);
            printf(",\"typeName\":\"%s\"}", fr->content.decoded.type->typeName
                                               ? fr->content.decoded.type->typeName : "");
        } else {
            printf("{\"typeId\":");
            output_nodeid(&fr->content.encoded.typeId);
            printf("}");
        }
    }
    printf(",\"notifications\":[");
    for (int i = 0; i < store.count; i++) {
        NotifEntry *e = &store.entries[i];
        if (i > 0) printf(",");
        printf("{\"sequenceNumber\":%d", e->index + 1);
        printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
               ",\"severity\":\"%s\"}",
               output_status_code_name((UA_StatusCode)e->statusCode),
               e->statusCode,
               output_severity((UA_StatusCode)e->statusCode));
        printf(",\"dataType\":\"%s\"", e->dataType);
        printf(",\"builtInType\":%d", e->builtInType);
        printf(",\"value\":%s", e->valueJson);
        if (e->sourceTimestamp[0])
            printf(",\"sourceTimestamp\":\"%s\"", e->sourceTimestamp);
        if (e->serverTimestamp[0])
            printf(",\"serverTimestamp\":\"%s\"", e->serverTimestamp);
        printf("}");
    }
    printf("]}]");

    if (timedOut)
        printf(",\"error\":{\"category\":\"timeout\","
               "\"message\":\"timeout waiting for notifications\"}");
    else if (!UA_StatusCode_isGood(mon_sc))
        printf(",\"error\":{\"category\":\"service\","
               "\"message\":\"CreateMonitoredItems rejected the monitored item\"}");
    else
        printf(",\"error\":null");
    output_end();

    UA_MonitoredItemCreateResult_clear(&monResp);
    UA_Client_Subscriptions_deleteSingle(client, subResp.subscriptionId);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    if (timedOut) return 7;
    return UA_StatusCode_isGood(mon_sc) ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * subscription-lifecycle subcommand helpers
 * ---------------------------------------------------------------------- */

static UA_StatusCode slc_set_publishing_mode(UA_Client *client, UA_UInt32 subId,
                                              UA_Boolean enabled) {
    UA_SetPublishingModeRequest req;
    UA_SetPublishingModeRequest_init(&req);
    req.publishingEnabled = enabled;
    req.subscriptionIdsSize = 1;
    req.subscriptionIds = &subId;
    UA_SetPublishingModeResponse resp;
    UA_SetPublishingModeResponse_init(&resp);
    __UA_Client_Service(client, &req,
        &UA_TYPES[UA_TYPES_SETPUBLISHINGMODEREQUEST],
        &resp,
        &UA_TYPES[UA_TYPES_SETPUBLISHINGMODERESPONSE]);
    UA_StatusCode sc = resp.responseHeader.serviceResult;
    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0)
        sc = resp.results[0];
    UA_SetPublishingModeResponse_clear(&resp);
    return sc;
}

static UA_StatusCode slc_set_monitoring_mode(UA_Client *client, UA_UInt32 subId,
                                              UA_UInt32 monId, UA_MonitoringMode mode) {
    UA_SetMonitoringModeRequest req;
    UA_SetMonitoringModeRequest_init(&req);
    req.subscriptionId = subId;
    req.monitoringMode = mode;
    req.monitoredItemIdsSize = 1;
    req.monitoredItemIds = &monId;
    UA_SetMonitoringModeResponse resp;
    UA_SetMonitoringModeResponse_init(&resp);
    __UA_Client_Service(client, &req,
        &UA_TYPES[UA_TYPES_SETMONITORINGMODEREQUEST],
        &resp,
        &UA_TYPES[UA_TYPES_SETMONITORINGMODERESPONSE]);
    UA_StatusCode sc = resp.responseHeader.serviceResult;
    if (UA_StatusCode_isGood(sc) && resp.resultsSize > 0)
        sc = resp.results[0];
    UA_SetMonitoringModeResponse_clear(&resp);
    return sc;
}

static UA_StatusCode slc_write_int32(UA_Client *client, UA_NodeId nodeId, UA_Int32 val) {
    UA_Variant var;
    UA_Variant_init(&var);
    UA_Variant_setScalar(&var, &val, &UA_TYPES[UA_TYPES_INT32]);
    return UA_Client_writeValueAttribute(client, nodeId, &var);
}

/* -------------------------------------------------------------------------
 * subscription-lifecycle scenarios
 * ---------------------------------------------------------------------- */

static int slc_revise(UA_Client *client, UA_NodeId nodeId, int toMs) {
    (void)nodeId; (void)toMs;
    UA_CreateSubscriptionRequest req;
    UA_CreateSubscriptionRequest_init(&req);
    req.requestedPublishingInterval = 1.0;
    req.requestedLifetimeCount      = 5;
    req.requestedMaxKeepAliveCount  = 10;
    req.publishingEnabled           = UA_TRUE;

    UA_CreateSubscriptionResponse resp =
        UA_Client_Subscriptions_create(client, req, NULL, NULL, NULL);
    UA_StatusCode sc  = resp.responseHeader.serviceResult;
    UA_UInt32     sid = resp.subscriptionId;
    double        rpi = resp.revisedPublishingInterval;
    UA_UInt32     rlt = resp.revisedLifetimeCount;
    UA_UInt32     rmk = resp.revisedMaxKeepAliveCount;
    UA_CreateSubscriptionResponse_clear(&resp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    UA_Client_Subscriptions_deleteSingle(client, sid);

    int ok = (rlt >= 3u * rmk) && (rpi >= 10.0);
    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, sid);
    printf(",\"requestedPublishingInterval\":1");
    printf(",\"requestedLifetimeCount\":5");
    printf(",\"requestedMaxKeepAliveCount\":10");
    printf(",\"revisedPublishingInterval\":%.17g", rpi);
    printf(",\"revisedLifetimeCount\":%" PRIu32, rlt);
    printf(",\"revisedMaxKeepAliveCount\":%" PRIu32, rmk);
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

static int slc_publishing_mode(UA_Client *client, UA_NodeId nodeId, int toMs) {
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = 500.0;
    subReq.publishingEnabled = UA_TRUE;

    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode sc  = subResp.responseHeader.serviceResult;
    UA_UInt32 subId   = subResp.subscriptionId;
    double    rpi     = subResp.revisedPublishingInterval;
    UA_UInt32 rlt     = subResp.revisedLifetimeCount;
    UA_UInt32 rmk     = subResp.revisedMaxKeepAliveCount;
    UA_CreateSubscriptionResponse_clear(&subResp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = MAX_NOTIFICATIONS;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    /* 0 = report every change: the queue-window assertions must not depend
     * on how a server throttles samples within a sampling interval. */
    monReq.requestedParameters.samplingInterval = 0.0;
    monReq.requestedParameters.queueSize        = 3;
    monReq.requestedParameters.discardOldest    = UA_TRUE;
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subId, UA_TIMESTAMPSTORETURN_SOURCE,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode monSc = monResp.statusCode;

    if (!UA_StatusCode_isGood(monSc)) {
        UA_Client_Subscriptions_deleteSingle(client, subId);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(monSc);
        output_error("service", "CreateMonitoredItem failed");
        output_end();
        return 4;
    }

    /* Drain initial notification (up to 500ms) */
    time_t t0 = time(NULL);
    while (store.count < 1) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= 500) break;
        UA_Client_run_iterate(client, 50);
    }

    /* SetPublishingMode false then reset counter */
    slc_set_publishing_mode(client, subId, UA_FALSE);
    store.count = 0;

    /* Write 1,2,3,4,5 */
    for (int v = 1; v <= 5; v++) {
        slc_write_int32(client, nodeId, (UA_Int32)v);
        UA_Client_run_iterate(client, 20);
    }

    /* Wait 200ms with publishing off */
    t0 = time(NULL);
    while ((int)(difftime(time(NULL), t0) * 1000.0) < 200)
        UA_Client_run_iterate(client, 50);

    /* SetPublishingMode true */
    slc_set_publishing_mode(client, subId, UA_TRUE);

    /* Collect queued notifications (expect up to queueSize=3) */
    int collectMs = toMs - 2000;
    if (collectMs < 2000) collectMs = 2000;
    if (collectMs > 5000) collectMs = 5000;
    t0 = time(NULL);
    while (store.count < 3) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= collectMs) break;
        UA_Client_run_iterate(client, 50);
    }

    UA_Client_Subscriptions_deleteSingle(client, subId);

    int nv = store.count;
    /* Overflow: wrote 5 values, queueSize=3 means 2 were discarded */
    int overflow = (nv < 5);
    for (int i = 0; i < nv; i++) {
        /* Overflow info bit: bit 10 in status code SubCode */
        if (store.entries[i].statusCode & 0x04800000u)
            overflow = 1;
    }

    /* success: last values should be [3,4,5] */
    int ok = 0;
    if (nv >= 3) {
        int a = atoi(store.entries[nv-3].valueJson);
        int b = atoi(store.entries[nv-2].valueJson);
        int c = atoi(store.entries[nv-1].valueJson);
        ok = (a == 3 && b == 4 && c == 5);
    } else if (nv >= 1) {
        ok = (atoi(store.entries[nv-1].valueJson) == 5);
    }

    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, subId);
    printf(",\"revisedPublishingInterval\":%.17g", rpi);
    printf(",\"revisedLifetimeCount\":%" PRIu32, rlt);
    printf(",\"revisedMaxKeepAliveCount\":%" PRIu32, rmk);
    printf(",\"overflow\":%s", overflow ? "true" : "false");
    printf(",\"values\":[");
    for (int i = 0; i < nv; i++) {
        if (i > 0) printf(",");
        printf("%s", store.entries[i].valueJson);
    }
    printf("]");
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

static int slc_monitoring_mode(UA_Client *client, UA_NodeId nodeId, int toMs) {
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = 100.0;
    subReq.publishingEnabled = UA_TRUE;

    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode sc  = subResp.responseHeader.serviceResult;
    UA_UInt32 subId   = subResp.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&subResp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = MAX_NOTIFICATIONS;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    /* 0 = report every change: the queue-window assertions must not depend
     * on how a server throttles samples within a sampling interval. */
    monReq.requestedParameters.samplingInterval = 0.0;
    monReq.requestedParameters.queueSize        = 5;
    monReq.requestedParameters.discardOldest    = UA_TRUE;
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subId, UA_TIMESTAMPSTORETURN_SOURCE,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode monSc = monResp.statusCode;
    UA_UInt32 monId     = monResp.monitoredItemId;

    if (!UA_StatusCode_isGood(monSc)) {
        UA_Client_Subscriptions_deleteSingle(client, subId);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(monSc);
        output_error("service", "CreateMonitoredItem failed");
        output_end();
        return 4;
    }

    /* Drain initial notification */
    time_t t0 = time(NULL);
    while (store.count < 1) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= 500) break;
        UA_Client_run_iterate(client, 50);
    }
    store.count = 0;

    /* SetMonitoringMode DISABLED; write 100; wait 300ms; expect 0 notifications */
    slc_set_monitoring_mode(client, subId, monId, UA_MONITORINGMODE_DISABLED);
    slc_write_int32(client, nodeId, 100);
    t0 = time(NULL);
    while ((int)(difftime(time(NULL), t0) * 1000.0) < 300)
        UA_Client_run_iterate(client, 50);
    int disabledCount = store.count;

    /* SetMonitoringMode SAMPLING; write 101,102; wait 300ms */
    slc_set_monitoring_mode(client, subId, monId, UA_MONITORINGMODE_SAMPLING);
    slc_write_int32(client, nodeId, 101);
    UA_Client_run_iterate(client, 20);
    slc_write_int32(client, nodeId, 102);
    t0 = time(NULL);
    while ((int)(difftime(time(NULL), t0) * 1000.0) < 300)
        UA_Client_run_iterate(client, 50);
    int samplingCount = store.count - disabledCount;

    /* SetMonitoringMode REPORTING; write 103; collect >= 1 notification */
    slc_set_monitoring_mode(client, subId, monId, UA_MONITORINGMODE_REPORTING);
    slc_write_int32(client, nodeId, 103);
    int beforeReporting = store.count;
    int collectMs = toMs - 2000;
    if (collectMs < 2000) collectMs = 2000;
    if (collectMs > 5000) collectMs = 5000;
    t0 = time(NULL);
    while (store.count <= beforeReporting) {
        if ((int)(difftime(time(NULL), t0) * 1000.0) >= collectMs) break;
        UA_Client_run_iterate(client, 50);
    }
    int reportingCount = store.count - beforeReporting;

    UA_Client_Subscriptions_deleteSingle(client, subId);

    int ok = (disabledCount == 0) && (reportingCount >= 1);
    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, subId);
    printf(",\"modeSteps\":[");
    printf("{\"mode\":\"Disabled\",\"notificationCount\":%d}", disabledCount);
    printf(",{\"mode\":\"Sampling\",\"notificationCount\":%d}", samplingCount);
    printf(",{\"mode\":\"Reporting\",\"notificationCount\":%d}", reportingCount);
    printf("]");
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

static int slc_delete(UA_Client *client, UA_NodeId nodeId, int toMs) {
    (void)toMs;
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = 500.0;
    subReq.publishingEnabled = UA_TRUE;

    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode sc  = subResp.responseHeader.serviceResult;
    UA_UInt32 subId   = subResp.subscriptionId;
    UA_CreateSubscriptionResponse_clear(&subResp);

    if (!UA_StatusCode_isGood(sc)) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    NotifStore store;
    memset(&store, 0, sizeof(store));
    store.wanted = 0;

    UA_MonitoredItemCreateRequest monReq =
        UA_MonitoredItemCreateRequest_default(nodeId);
    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createDataChange(
            client, subId, UA_TIMESTAMPSTORETURN_SOURCE,
            monReq, &store, sub_data_change_cb, NULL);
    UA_StatusCode monSc = monResp.statusCode;
    UA_UInt32 monId     = monResp.monitoredItemId;

    if (!UA_StatusCode_isGood(monSc)) {
        UA_Client_Subscriptions_deleteSingle(client, subId);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0); output_service_result(monSc);
        output_error("service", "CreateMonitoredItem failed");
        output_end();
        return 4;
    }

    /* DeleteMonitoredItems: first (expect Good), second (expect Bad) */
    UA_DeleteMonitoredItemsRequest dmReq;
    UA_DeleteMonitoredItemsRequest_init(&dmReq);
    dmReq.subscriptionId       = subId;
    dmReq.monitoredItemIds     = &monId;
    dmReq.monitoredItemIdsSize = 1;

    UA_DeleteMonitoredItemsResponse dmResp1;
    UA_DeleteMonitoredItemsResponse_init(&dmResp1);
    __UA_Client_Service(client, &dmReq,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST],
        &dmResp1,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
    UA_StatusCode delMon1 = (dmResp1.resultsSize > 0)
        ? dmResp1.results[0] : dmResp1.responseHeader.serviceResult;
    UA_DeleteMonitoredItemsResponse_clear(&dmResp1);

    UA_DeleteMonitoredItemsResponse dmResp2;
    UA_DeleteMonitoredItemsResponse_init(&dmResp2);
    __UA_Client_Service(client, &dmReq,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST],
        &dmResp2,
        &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
    UA_StatusCode delMon2 = (dmResp2.resultsSize > 0)
        ? dmResp2.results[0] : dmResp2.responseHeader.serviceResult;
    UA_DeleteMonitoredItemsResponse_clear(&dmResp2);

    /* DeleteSubscriptions: first (expect Good), second (expect Bad) */
    UA_DeleteSubscriptionsRequest dsReq;
    UA_DeleteSubscriptionsRequest_init(&dsReq);
    dsReq.subscriptionIds     = &subId;
    dsReq.subscriptionIdsSize = 1;

    UA_DeleteSubscriptionsResponse dsResp1;
    UA_DeleteSubscriptionsResponse_init(&dsResp1);
    __UA_Client_Service(client, &dsReq,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST],
        &dsResp1,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
    UA_StatusCode delSub1 = (dsResp1.resultsSize > 0)
        ? dsResp1.results[0] : dsResp1.responseHeader.serviceResult;
    UA_DeleteSubscriptionsResponse_clear(&dsResp1);

    UA_DeleteSubscriptionsResponse dsResp2;
    UA_DeleteSubscriptionsResponse_init(&dsResp2);
    __UA_Client_Service(client, &dsReq,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST],
        &dsResp2,
        &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
    UA_StatusCode delSub2 = (dsResp2.resultsSize > 0)
        ? dsResp2.results[0] : dsResp2.responseHeader.serviceResult;
    UA_DeleteSubscriptionsResponse_clear(&dsResp2);

    int ok = UA_StatusCode_isBad(delMon2) && UA_StatusCode_isBad(delSub2);
    output_begin("open62541", "subscription-lifecycle");
    output_success(ok);
    output_service_result(sc);
    printf(",\"results\":[{");
    printf("\"subscriptionId\":%" PRIu32, subId);
    printf(",\"deleteMonitoredItem\":{");
    printf("\"first\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delMon1), (uint32_t)delMon1,
           output_severity(delMon1));
    printf(",\"second\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delMon2), (uint32_t)delMon2,
           output_severity(delMon2));
    printf("}");
    printf(",\"deleteSubscription\":{");
    printf("\"first\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delSub1), (uint32_t)delSub1,
           output_severity(delSub1));
    printf(",\"second\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(delSub2), (uint32_t)delSub2,
           output_severity(delSub2));
    printf("}");
    printf("}]");
    output_null_error();
    output_end();
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * subscription-lifecycle subcommand
 * ---------------------------------------------------------------------- */

static int cmd_subscription_lifecycle(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    const char *scenario = find_arg(argc, argv, "--scenario");
    const char *toStr    = find_arg(argc, argv, "--timeout-ms");

    if (!endpoint || !nodeStr || !scenario) {
        output_begin("open62541", "subscription-lifecycle");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: subscription-lifecycle --endpoint <url> --node <nodeId>"
            " --scenario <revise|publishing-mode|monitoring-mode|delete>");
        output_end();
        return 2;
    }

    int toMs = toStr ? atoi(toStr) : 15000;

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int exit_code = 3;
    UA_Client *client =
        make_client(endpoint, 5000, "subscription-lifecycle", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId; UA_NodeId_init(&nodeId);
    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            output_begin("open62541", "subscription-lifecycle");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    int result;
    if      (strcmp(scenario, "revise")           == 0)
        result = slc_revise(client, nodeId, toMs);
    else if (strcmp(scenario, "publishing-mode")  == 0)
        result = slc_publishing_mode(client, nodeId, toMs);
    else if (strcmp(scenario, "monitoring-mode")  == 0)
        result = slc_monitoring_mode(client, nodeId, toMs);
    else if (strcmp(scenario, "delete")           == 0)
        result = slc_delete(client, nodeId, toMs);
    else {
        char msg[256];
        snprintf(msg, sizeof(msg), "unknown scenario: '%s'", scenario);
        output_begin("open62541", "subscription-lifecycle");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        result = 2;
    }

    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return result;
}

/* -------------------------------------------------------------------------
 * Base64 encode into a malloc'd NUL-terminated string.
 * Caller must free() the result. Returns NULL on OOM.
 * ---------------------------------------------------------------------- */

static char *b64_encode(const unsigned char *data, size_t len) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t outLen = ((len + 2) / 3) * 4;
    char *out = (char *)malloc(outLen + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned char a = data[i];
        unsigned char b = (i+1 < len) ? data[i+1] : 0;
        unsigned char c = (i+2 < len) ? data[i+2] : 0;
        out[j++] = b64[a >> 2];
        out[j++] = b64[((a & 3) << 4) | (b >> 4)];
        out[j++] = (i+1 < len) ? b64[((b & 0xf) << 2) | (c >> 6)] : '=';
        out[j++] = (i+2 < len) ? b64[c & 0x3f] : '=';
    }
    out[j] = '\0';
    return out;
}

/* -------------------------------------------------------------------------
 * RFC 3339 UTC timestamp parser → UA_DateTime
 * Accepts "YYYY-MM-DDTHH:MM:SS[.mmmm]Z".
 * Returns 0 on error.
 * ---------------------------------------------------------------------- */

static UA_DateTime parse_rfc3339_utc(const char *s) {
    if (!s || !*s) return 0;
    int Y, M, D, h, m, sec;
    unsigned millis = 0;
    int r = sscanf(s, "%d-%d-%dT%d:%d:%d.%uZ", &Y, &M, &D, &h, &m, &sec, &millis);
    if (r < 6) {
        millis = 0;
        r = sscanf(s, "%d-%d-%dT%d:%d:%dZ", &Y, &M, &D, &h, &m, &sec);
    }
    if (r < 6) return 0;

    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = Y - 1900;
    tm.tm_mon  = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min  = m;
    tm.tm_sec  = sec;
    tm.tm_isdst = 0;

    time_t t = timegm(&tm);
    if (t == (time_t)-1) return 0;

    /* Convert to UA_DateTime: 100-ns ticks since 1601-01-01.
     * Offset from 1601-01-01 to 1970-01-01 = 11644473600 seconds. */
    UA_DateTime dt = (UA_DateTime)((UA_Int64)t + 11644473600LL) * UA_DATETIME_SEC
                   + (UA_DateTime)millis * UA_DATETIME_MSEC;
    return dt;
}

/* -------------------------------------------------------------------------
 * event-subscribe subcommand
 * ---------------------------------------------------------------------- */

#define MAX_EVENTS 64
#define MAX_EVENT_FIELDS 8

typedef struct {
    char name[32];
    char dataType[64];
    int  builtInType;
    char valueJson[1024];
} EvField;

typedef struct {
    int     sequenceNumber;
    int     fieldCount;
    EvField fields[MAX_EVENT_FIELDS];
} EvEntry;

typedef struct {
    int        wanted;
    int        count;
    EvEntry    entries[MAX_EVENTS];
    const char *fieldNames[MAX_EVENT_FIELDS];
    int        fieldCount;
} EvStore;

/* open62541 1.5+ delivers event fields as a KeyValueMap (not Variant[]). */
static void event_notif_cb(UA_Client *client, UA_UInt32 subId, void *subCtx,
                            UA_UInt32 monId, void *monCtx,
                            const UA_KeyValueMap eventFields) {
    (void)client; (void)subId; (void)subCtx; (void)monId;
    EvStore *store = (EvStore *)monCtx;
    if (!store || store->count >= MAX_EVENTS) return;

    EvEntry *e = &store->entries[store->count];
    e->sequenceNumber = store->count + 1;

    /* Prefer SelectClause order from store->fieldNames when present. */
    int nWant = store->fieldCount > 0 ? store->fieldCount : (int)eventFields.mapSize;
    if (nWant > MAX_EVENT_FIELDS) nWant = MAX_EVENT_FIELDS;
    e->fieldCount = nWant;

    for (int i = 0; i < e->fieldCount; i++) {
        EvField *f = &e->fields[i];
        const char *wantName = (store->fieldCount > 0 && store->fieldNames[i])
            ? store->fieldNames[i] : NULL;
        if (wantName) {
            strncpy(f->name, wantName, sizeof(f->name) - 1);
        } else if (i < (int)eventFields.mapSize &&
                   eventFields.map[i].key.name.data) {
            size_t n = eventFields.map[i].key.name.length;
            if (n >= sizeof(f->name)) n = sizeof(f->name) - 1;
            memcpy(f->name, eventFields.map[i].key.name.data, n);
            f->name[n] = '\0';
        } else {
            snprintf(f->name, sizeof(f->name), "field%d", i);
        }
        f->name[sizeof(f->name) - 1] = '\0';

        const UA_Variant *v = NULL;
        if (wantName) {
            for (size_t j = 0; j < eventFields.mapSize; j++) {
                UA_String nm = eventFields.map[j].key.name;
                if (nm.data && nm.length == strlen(wantName) &&
                    memcmp(nm.data, wantName, nm.length) == 0) {
                    v = &eventFields.map[j].value;
                    break;
                }
            }
            if (!v && (size_t)i < eventFields.mapSize)
                v = &eventFields.map[i].value; /* positional fallback */
        } else if ((size_t)i < eventFields.mapSize) {
            v = &eventFields.map[i].value;
        }

        if (v && v->type) {
            strncpy(f->dataType, type_name(v->type), sizeof(f->dataType) - 1);
            f->dataType[sizeof(f->dataType) - 1] = '\0';
            f->builtInType = ua_type_to_builtin_id(v->type);
            output_variant_to_buf(v, f->valueJson, sizeof(f->valueJson));
        } else {
            strcpy(f->dataType, "Null");
            f->builtInType = 0;
            strcpy(f->valueJson, "null");
        }
    }
    store->count++;
}

static int cmd_event_subscribe(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeStr  = find_arg(argc, argv, "--node");
    const char *evStr    = find_arg(argc, argv, "--events");
    const char *toStr    = find_arg(argc, argv, "--timeout-ms");
    const char *piStr    = find_arg(argc, argv, "--publishing-interval-ms");
    const char *qsStr    = find_arg(argc, argv, "--queue-size");
    const char *ofTypeStr = find_arg(argc, argv, "--of-type");
    const char *minSevStr = find_arg(argc, argv, "--min-severity");

    if (!endpoint || !nodeStr) {
        output_begin("open62541", "event-subscribe");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: event-subscribe --endpoint <url> --node <nodeId>"
            " [--events <n>] [--timeout-ms <ms>]"
            " [--publishing-interval-ms <ms>] [--queue-size <n>]"
            " [--of-type <nodeId>] [--min-severity <n>]");
        output_end();
        return 2;
    }

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "event-subscribe");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    int       nWanted   = evStr ? atoi(evStr)  : 1;
    int       toMs      = toStr ? atoi(toStr)  : 10000;
    double    piMs      = piStr ? atof(piStr)  : 500.0;
    UA_UInt32 queueSize = qsStr ? (UA_UInt32)atoi(qsStr) : 10;
    if (nWanted <= 0) nWanted = 1;
    if (nWanted > MAX_EVENTS) nWanted = MAX_EVENTS;
    if (queueSize < 1) queueSize = 1;

    int exit_code = 3;
    UA_Client *client = make_client(endpoint, 5000, "event-subscribe", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId; UA_NodeId_init(&nodeId);
    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            output_begin("open62541", "event-subscribe");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    /* BaseEvent SelectClauses */
    static const char *kFieldNames[] = {
        "EventId", "EventType", "SourceName", "Message", "Severity", "Time"
    };
    const int nFields = 6;

    /* Create subscription */
    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = piMs;
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode svc_sc = subResp.responseHeader.serviceResult;
    if (!UA_StatusCode_isGood(svc_sc)) {
        UA_NodeId_clear(&nodeId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        output_begin("open62541", "event-subscribe");
        output_success(0);
        output_service_result(svc_sc);
        output_error("service", "CreateSubscription failed");
        output_end();
        return 4;
    }

    /* Build EventFilter with 6 BaseEvent SelectClauses */
    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = (UA_SimpleAttributeOperand *)
        UA_Array_new((size_t)nFields, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
    filter.selectClausesSize = (size_t)nFields;

    for (int i = 0; i < nFields; i++) {
        UA_SimpleAttributeOperand *op = &filter.selectClauses[i];
        UA_SimpleAttributeOperand_init(op);
        op->typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
        op->attributeId      = UA_ATTRIBUTEID_VALUE;
        op->browsePathSize   = 1;
        op->browsePath = (UA_QualifiedName *)
            UA_Array_new(1, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
        op->browsePath[0] = UA_QUALIFIEDNAME_ALLOC(0, kFieldNames[i]);
    }

    /* Optional WhereClause: --of-type and/or --min-severity (AND if both). */
    {
        UA_ContentFilterElement elems[3];
        size_t nElem = 0;
        memset(elems, 0, sizeof(elems));

        if (ofTypeStr && *ofTypeStr) {
            UA_NodeId typeId = parse_nodeid_local(ofTypeStr);
            if (strncmp(ofTypeStr, "nsu=", 4) == 0)
                resolve_nsu_nodeid(client, ofTypeStr, &typeId);
            UA_LiteralOperand lit;
            UA_LiteralOperand_init(&lit);
            UA_Variant_setScalarCopy(&lit.value, &typeId, &UA_TYPES[UA_TYPES_NODEID]);
            elems[nElem].filterOperator = UA_FILTEROPERATOR_OFTYPE;
            elems[nElem].filterOperandsSize = 1;
            elems[nElem].filterOperands = (UA_ExtensionObject *)
                UA_Array_new(1, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
            UA_ExtensionObject_setValueCopy(&elems[nElem].filterOperands[0],
                &lit, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
            UA_LiteralOperand_clear(&lit);
            UA_NodeId_clear(&typeId);
            nElem++;
        }
        if (minSevStr && *minSevStr) {
            UA_UInt16 minSev = (UA_UInt16)atoi(minSevStr);
            UA_SimpleAttributeOperand sao;
            UA_SimpleAttributeOperand_init(&sao);
            sao.typeDefinitionId = UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
            sao.attributeId = UA_ATTRIBUTEID_VALUE;
            sao.browsePathSize = 1;
            sao.browsePath = (UA_QualifiedName *)
                UA_Array_new(1, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
            sao.browsePath[0] = UA_QUALIFIEDNAME_ALLOC(0, "Severity");
            UA_LiteralOperand lit;
            UA_LiteralOperand_init(&lit);
            UA_Variant_setScalarCopy(&lit.value, &minSev, &UA_TYPES[UA_TYPES_UINT16]);
            elems[nElem].filterOperator = UA_FILTEROPERATOR_GREATERTHANOREQUAL;
            elems[nElem].filterOperandsSize = 2;
            elems[nElem].filterOperands = (UA_ExtensionObject *)
                UA_Array_new(2, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
            UA_ExtensionObject_setValueCopy(&elems[nElem].filterOperands[0],
                &sao, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
            UA_ExtensionObject_setValueCopy(&elems[nElem].filterOperands[1],
                &lit, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
            UA_SimpleAttributeOperand_clear(&sao);
            UA_LiteralOperand_clear(&lit);
            nElem++;
        }
        if (nElem == 2) {
            UA_ElementOperand a, b;
            UA_ElementOperand_init(&a); a.index = 0;
            UA_ElementOperand_init(&b); b.index = 1;
            elems[nElem].filterOperator = UA_FILTEROPERATOR_AND;
            elems[nElem].filterOperandsSize = 2;
            elems[nElem].filterOperands = (UA_ExtensionObject *)
                UA_Array_new(2, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
            UA_ExtensionObject_setValueCopy(&elems[nElem].filterOperands[0],
                &a, &UA_TYPES[UA_TYPES_ELEMENTOPERAND]);
            UA_ExtensionObject_setValueCopy(&elems[nElem].filterOperands[1],
                &b, &UA_TYPES[UA_TYPES_ELEMENTOPERAND]);
            nElem++;
        }
        if (nElem > 0) {
            filter.whereClause.elements = (UA_ContentFilterElement *)
                UA_Array_new(nElem, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENT]);
            filter.whereClause.elementsSize = nElem;
            for (size_t ei = 0; ei < nElem; ei++)
                UA_ContentFilterElement_copy(&elems[ei], &filter.whereClause.elements[ei]);
            for (size_t ei = 0; ei < nElem; ei++)
                UA_ContentFilterElement_clear(&elems[ei]);
        }
    }

    /* Build MonitoredItemCreateRequest targeting EventNotifier attribute */
    UA_MonitoredItemCreateRequest monReq;
    UA_MonitoredItemCreateRequest_init(&monReq);
    monReq.itemToMonitor.nodeId       = nodeId;  /* shallow copy for local use */
    monReq.itemToMonitor.attributeId  = UA_ATTRIBUTEID_EVENTNOTIFIER;
    monReq.monitoringMode             = UA_MONITORINGMODE_REPORTING;
    monReq.requestedParameters.samplingInterval = 0.0; /* event-driven */
    monReq.requestedParameters.queueSize        = queueSize;
    monReq.requestedParameters.discardOldest    = UA_TRUE;

    /* Copy filter into the ExtensionObject field */
    UA_ExtensionObject_setValueCopy(&monReq.requestedParameters.filter,
                                    &filter,
                                    &UA_TYPES[UA_TYPES_EVENTFILTER]);
    /* Free original filter — monReq now holds its own deep copy */
    UA_EventFilter_clear(&filter);

    EvStore store;
    memset(&store, 0, sizeof(store));
    store.wanted     = nWanted;
    store.fieldCount = nFields;
    for (int i = 0; i < nFields; i++) store.fieldNames[i] = kFieldNames[i];

    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createEvent(
            client, subResp.subscriptionId,
            UA_TIMESTAMPSTORETURN_BOTH,
            monReq, &store, event_notif_cb, NULL);
    UA_StatusCode mon_sc = monResp.statusCode;

    /* monReq is passed by value — free our local copy */
    monReq.itemToMonitor.nodeId = UA_NODEID_NULL; /* owned by nodeId var */
    UA_MonitoredItemCreateRequest_clear(&monReq);

    int timedOut = 0;
    if (UA_StatusCode_isGood(mon_sc)) {
        time_t start = time(NULL);
        while (store.count < nWanted) {
            if ((int)(difftime(time(NULL), start) * 1000.0) >= toMs) {
                timedOut = 1;
                break;
            }
            UA_Client_run_iterate(client, 100);
        }
    }

    int all_ok    = UA_StatusCode_isGood(mon_sc) && !timedOut;
    UA_StatusCode emit_sc = UA_StatusCode_isGood(mon_sc) ? svc_sc : mon_sc;

    output_begin("open62541", "event-subscribe");
    output_success(all_ok);
    output_service_result(emit_sc);

    printf(",\"results\":[{\"nodeId\":");
    output_nodeid(&nodeId);
    printf(",\"subscriptionId\":%" PRIu32, (uint32_t)subResp.subscriptionId);
    printf(",\"revisedPublishingInterval\":%.17g", subResp.revisedPublishingInterval);
    printf(",\"monitoredItemStatusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
           ",\"severity\":\"%s\"}",
           output_status_code_name(mon_sc), (uint32_t)mon_sc, output_severity(mon_sc));
    printf(",\"selectClauses\":[");
    for (int i = 0; i < nFields; i++) {
        if (i > 0) printf(",");
        printf("\"%s\"", kFieldNames[i]);
    }
    printf("],\"events\":[");
    for (int i = 0; i < store.count; i++) {
        EvEntry *e = &store.entries[i];
        if (i > 0) printf(",");
        printf("{\"sequenceNumber\":%d,\"fields\":[", e->sequenceNumber);
        for (int j = 0; j < e->fieldCount; j++) {
            EvField *f = &e->fields[j];
            if (j > 0) printf(",");
            printf("{\"name\":\"%s\",\"dataType\":\"%s\",\"builtInType\":%d,\"value\":%s}",
                   f->name, f->dataType, f->builtInType, f->valueJson);
        }
        printf("]}");
    }
    printf("]}]");

    if (timedOut)
        printf(",\"error\":{\"category\":\"timeout\","
               "\"message\":\"timeout waiting for events\"}");
    else
        printf(",\"error\":null");
    output_end();

    UA_Client_Subscriptions_deleteSingle(client, subResp.subscriptionId);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return timedOut ? 7 : (UA_StatusCode_isGood(mon_sc) ? 0 : 4);
}

/* -------------------------------------------------------------------------
 * history-read subcommand
 * ---------------------------------------------------------------------- */

/* Emit one history-read page JSON object (no surrounding array). */
static void emit_history_page_json(const UA_NodeId *nodeId, UA_StatusCode item_sc,
                                   const UA_ByteString *cp, const UA_HistoryData *hdata) {
    printf("{\"nodeId\":");
    output_nodeid(nodeId);
    printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           output_status_code_name(item_sc), (uint32_t)item_sc, output_severity(item_sc));
    if (cp && cp->length > 0 && cp->data) {
        char *cpB64 = b64_encode(cp->data, cp->length);
        if (cpB64) { printf(",\"continuationPoint\":\"%s\"", cpB64); free(cpB64); }
        else printf(",\"continuationPoint\":null");
    } else {
        printf(",\"continuationPoint\":null");
    }
    printf(",\"values\":[");
    if (hdata) {
        for (size_t i = 0; i < hdata->dataValuesSize; i++) {
            UA_DataValue *dv = &hdata->dataValues[i];
            if (i > 0) printf(",");
            UA_StatusCode dvSc = dv->hasStatus ? dv->status : UA_STATUSCODE_GOOD;
            const char *dtName = (dv->hasValue && dv->value.type)
                                 ? type_name(dv->value.type) : "Unknown";
            int bi = (dv->hasValue && dv->value.type)
                     ? ua_type_to_builtin_id(dv->value.type) : 0;
            printf("{");
            if (dv->hasValue) { printf("\"value\":"); output_ua_variant_value(&dv->value); }
            else printf("\"value\":null");
            printf(",\"dataType\":\"%s\",\"builtInType\":%d", dtName, bi);
            printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
                   ",\"severity\":\"%s\"}",
                   output_status_code_name(dvSc), (uint32_t)dvSc, output_severity(dvSc));
            if (dv->hasSourceTimestamp) {
                char tsbuf[64];
                output_timestamp(dv->sourceTimestamp, tsbuf, sizeof(tsbuf));
                if (tsbuf[0]) printf(",\"sourceTimestamp\":\"%s\"", tsbuf);
            }
            if (dv->hasServerTimestamp) {
                char tsbuf[64];
                output_timestamp(dv->serverTimestamp, tsbuf, sizeof(tsbuf));
                if (tsbuf[0]) printf(",\"serverTimestamp\":\"%s\"", tsbuf);
            }
            printf("}");
        }
    }
    printf("]}");
}

static int history_read_once(UA_Client *client, const UA_NodeId *nodeId,
                             UA_DateTime startTime, UA_DateTime endTime,
                             UA_UInt32 numValues, UA_Boolean returnBounds,
                             UA_TimestampsToReturn ts,
                             const char *cpStr, UA_Boolean releaseCp,
                             UA_StatusCode *outSvc, UA_StatusCode *outItem,
                             UA_ByteString *outCp, UA_HistoryData **outData,
                             UA_HistoryReadResponse *outResp) {
    UA_ReadRawModifiedDetails rawDetails;
    UA_ReadRawModifiedDetails_init(&rawDetails);
    rawDetails.isReadModified   = UA_FALSE;
    rawDetails.startTime        = startTime;
    rawDetails.endTime          = endTime;
    rawDetails.numValuesPerNode = numValues;
    rawDetails.returnBounds     = returnBounds;

    UA_HistoryReadRequest hrReq;
    UA_HistoryReadRequest_init(&hrReq);
    UA_ExtensionObject_setValueCopy(&hrReq.historyReadDetails, &rawDetails,
                                    &UA_TYPES[UA_TYPES_READRAWMODIFIEDDETAILS]);
    hrReq.timestampsToReturn = ts;
    hrReq.releaseContinuationPoints = releaseCp;
    hrReq.nodesToRead = (UA_HistoryReadValueId *)
        UA_Array_new(1, &UA_TYPES[UA_TYPES_HISTORYREADVALUEID]);
    hrReq.nodesToReadSize = 1;
    UA_HistoryReadValueId_init(&hrReq.nodesToRead[0]);
    UA_NodeId_copy(nodeId, &hrReq.nodesToRead[0].nodeId);
    if (cpStr && *cpStr) {
        size_t cpLen = 0;
        unsigned char *cpData = b64_decode(cpStr, &cpLen);
        if (cpData && cpLen > 0) {
            hrReq.nodesToRead[0].continuationPoint.data = cpData;
            hrReq.nodesToRead[0].continuationPoint.length = cpLen;
        } else {
            free(cpData);
        }
    }

    *outResp = UA_Client_Service_historyRead(client, hrReq);
    UA_HistoryReadRequest_clear(&hrReq);

    *outSvc = outResp->responseHeader.serviceResult;
    *outItem = UA_STATUSCODE_GOOD;
    UA_ByteString_init(outCp);
    *outData = NULL;
    if (UA_StatusCode_isGood(*outSvc) && outResp->resultsSize > 0) {
        UA_HistoryReadResult *hr = &outResp->results[0];
        *outItem = hr->statusCode;
        if (hr->continuationPoint.length > 0)
            UA_ByteString_copy(&hr->continuationPoint, outCp);
        UA_ExtensionObject *eo = &hr->historyData;
        if (eo->encoding == UA_EXTENSIONOBJECT_DECODED &&
            eo->content.decoded.type == &UA_TYPES[UA_TYPES_HISTORYDATA]) {
            *outData = (UA_HistoryData *)eo->content.decoded.data;
        }
    }
    return 0;
}

static int cmd_history_read(int argc, char **argv) {
    const char *endpoint   = find_arg(argc, argv, "--endpoint");
    const char *nodeStr    = find_arg(argc, argv, "--node");
    const char *startStr   = find_arg(argc, argv, "--start");
    const char *endStr     = find_arg(argc, argv, "--end");
    const char *numValStr  = find_arg(argc, argv, "--num-values");
    const char *cpStr      = find_arg(argc, argv, "--continuation-point");
    const char *relCpStr   = find_arg(argc, argv, "--release-continuation-point");
    const char *rbStr      = find_arg(argc, argv, "--return-bounds");
    const char *tsStr      = find_arg(argc, argv, "--timestamps");
    const char *scenario   = find_arg(argc, argv, "--scenario");

    if (!endpoint || !nodeStr || !startStr || !endStr) {
        output_begin("open62541", "history-read");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: history-read --endpoint <url> --node <nodeId>"
            " --start <rfc3339> --end <rfc3339>"
            " [--num-values <n>] [--continuation-point <b64>]"
            " [--release-continuation-point true|false]"
            " [--return-bounds true|false]"
            " [--timestamps Source|Server|Both|Neither]"
            " [--scenario continue]");
        output_end();
        return 2;
    }

    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        output_begin("open62541", "history-read");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", msg);
        output_end();
        return 2;
    }

    UA_DateTime startTime = parse_rfc3339_utc(startStr);
    UA_DateTime endTime   = parse_rfc3339_utc(endStr);
    if (startTime == 0 || endTime == 0) {
        output_begin("open62541", "history-read");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "invalid --start or --end timestamp (expect UTC RFC 3339)");
        output_end();
        return 2;
    }

    UA_UInt32 numValues    = numValStr ? (UA_UInt32)atoi(numValStr) : 0;
    UA_Boolean releaseCp   = (relCpStr && strcmp(relCpStr, "true") == 0) ? UA_TRUE : UA_FALSE;
    UA_Boolean returnBounds = (rbStr   && strcmp(rbStr, "true")    == 0) ? UA_TRUE : UA_FALSE;

    UA_TimestampsToReturn ts = UA_TIMESTAMPSTORETURN_BOTH;
    if (tsStr) {
        if      (strcmp(tsStr, "Source")  == 0) ts = UA_TIMESTAMPSTORETURN_SOURCE;
        else if (strcmp(tsStr, "Server")  == 0) ts = UA_TIMESTAMPSTORETURN_SERVER;
        else if (strcmp(tsStr, "Neither") == 0) ts = UA_TIMESTAMPSTORETURN_NEITHER;
    }

    int req_ms   = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "history-read", &exit_code);
    if (!client) return exit_code;

    UA_NodeId nodeId; UA_NodeId_init(&nodeId);
    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            output_begin("open62541", "history-read");
            output_success(0);
            output_service_result(UA_STATUSCODE_BADNAMESPACEURIINVALID);
            output_error("input", msg);
            output_end();
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    /* Single-session continue/release/reuse scenario (Wave 3B). */
    if (scenario && strcmp(scenario, "continue") == 0) {
        if (numValues == 0) numValues = 2;
        char lastCpB64[512];
        lastCpB64[0] = '\0';
        char reuseCpB64[512];
        reuseCpB64[0] = '\0';
        UA_StatusCode lastSvc = UA_STATUSCODE_GOOD, lastItem = UA_STATUSCODE_GOOD;
        UA_StatusCode releaseSc = UA_STATUSCODE_GOOD, reuseSc = UA_STATUSCODE_GOOD;
        int pageCount = 0;

        /* Collect pages first, then emit a well-formed envelope. */
        typedef struct {
            UA_StatusCode item;
            char cpB64[512];
            UA_HistoryReadResponse resp; /* owns HistoryData */
            UA_HistoryData *hdata;
            UA_ByteString cp;
        } ContPage;
        ContPage pages[8];
        memset(pages, 0, sizeof(pages));

        const char *curCp = NULL;
        for (int i = 0; i < 8; i++) {
            UA_StatusCode svc_sc = UA_STATUSCODE_GOOD, item_sc = UA_STATUSCODE_GOOD;
            UA_ByteString cpOut; UA_ByteString_init(&cpOut);
            UA_HistoryData *hdata = NULL;
            UA_HistoryReadResponse hrResp;
            history_read_once(client, &nodeId, startTime, endTime, numValues,
                              returnBounds, ts, curCp, UA_FALSE,
                              &svc_sc, &item_sc, &cpOut, &hdata, &hrResp);
            lastSvc = svc_sc; lastItem = item_sc;
            pages[pageCount].item = item_sc;
            pages[pageCount].resp = hrResp;
            pages[pageCount].hdata = hdata;
            pages[pageCount].cp = cpOut;
            pages[pageCount].cpB64[0] = '\0';
            if (cpOut.length > 0 && cpOut.data) {
                char *b64 = b64_encode(cpOut.data, cpOut.length);
                if (b64) {
                    snprintf(pages[pageCount].cpB64, sizeof(pages[pageCount].cpB64), "%s", b64);
                    snprintf(lastCpB64, sizeof(lastCpB64), "%s", b64);
                    snprintf(reuseCpB64, sizeof(reuseCpB64), "%s", b64);
                    free(b64);
                }
                curCp = lastCpB64;
            } else {
                curCp = NULL;
            }
            pageCount++;
            if (!UA_StatusCode_isGood(svc_sc) || !UA_StatusCode_isGood(item_sc) || !curCp)
                break;
        }

        if (reuseCpB64[0]) {
            UA_StatusCode svc_sc, item_sc;
            UA_ByteString cpOut; UA_ByteString_init(&cpOut);
            UA_HistoryData *hdata = NULL;
            UA_HistoryReadResponse hrResp;
            history_read_once(client, &nodeId, startTime, endTime, numValues,
                              returnBounds, ts, reuseCpB64, UA_TRUE,
                              &svc_sc, &item_sc, &cpOut, &hdata, &hrResp);
            releaseSc = UA_StatusCode_isGood(svc_sc) ? item_sc : svc_sc;
            UA_ByteString_clear(&cpOut);
            UA_HistoryReadResponse_clear(&hrResp);

            history_read_once(client, &nodeId, startTime, endTime, numValues,
                              returnBounds, ts, reuseCpB64, UA_FALSE,
                              &svc_sc, &item_sc, &cpOut, &hdata, &hrResp);
            reuseSc = UA_StatusCode_isGood(svc_sc) ? item_sc : svc_sc;
            UA_ByteString_clear(&cpOut);
            UA_HistoryReadResponse_clear(&hrResp);
        }

        int ok = UA_StatusCode_isGood(lastSvc) && UA_StatusCode_isGood(lastItem) && pageCount > 0;
        UA_StatusCode emit_sc = UA_StatusCode_isGood(lastSvc) ? lastItem : lastSvc;
        output_begin("open62541", "history-read");
        output_success(ok);
        output_service_result(emit_sc);
        output_open_results();
        printf("{\"scenario\":\"continue\",\"nodeId\":");
        output_nodeid(&nodeId);
        printf(",\"pages\":[");
        for (int i = 0; i < pageCount; i++) {
            if (i > 0) printf(",");
            emit_history_page_json(&nodeId, pages[i].item, &pages[i].cp, pages[i].hdata);
        }
        printf("],\"releaseStatusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
               ",\"severity\":\"%s\"}",
               output_status_code_name(releaseSc), (uint32_t)releaseSc,
               output_severity(releaseSc));
        printf(",\"reuseAfterReleaseStatusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
               ",\"severity\":\"%s\"}}",
               output_status_code_name(reuseSc), (uint32_t)reuseSc,
               output_severity(reuseSc));
        output_close_results();
        output_null_error();
        output_end();

        for (int i = 0; i < pageCount; i++) {
            UA_ByteString_clear(&pages[i].cp);
            UA_HistoryReadResponse_clear(&pages[i].resp);
        }
        UA_NodeId_clear(&nodeId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        return ok ? 0 : 4;
    }

    UA_StatusCode svc_sc = UA_STATUSCODE_GOOD, item_sc = UA_STATUSCODE_GOOD;
    UA_ByteString cpOut; UA_ByteString_init(&cpOut);
    UA_HistoryData *hdata = NULL;
    UA_HistoryReadResponse hrResp;
    history_read_once(client, &nodeId, startTime, endTime, numValues, returnBounds, ts,
                      cpStr, releaseCp, &svc_sc, &item_sc, &cpOut, &hdata, &hrResp);

    UA_StatusCode emit_sc = UA_StatusCode_isGood(svc_sc) ? item_sc : svc_sc;
    int ok = UA_StatusCode_isGood(svc_sc) && UA_StatusCode_isGood(item_sc);

    output_begin("open62541", "history-read");
    output_success(ok);
    output_service_result(emit_sc);
    output_open_results();
    emit_history_page_json(&nodeId, item_sc, &cpOut, hdata);
    output_close_results();
    output_null_error();
    output_end();

    UA_ByteString_clear(&cpOut);
    UA_HistoryReadResponse_clear(&hrResp);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (svc_sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * republish subcommand
 * ---------------------------------------------------------------------- */

static int cmd_republish(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *subIdStr = find_arg(argc, argv, "--subscription-id");
    const char *seqStr   = find_arg(argc, argv, "--sequence-number");

    if (!endpoint || !subIdStr || !seqStr) {
        output_begin("open62541", "republish");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: republish --endpoint <url>"
            " --subscription-id <n> --sequence-number <n>");
        output_end();
        return 2;
    }

    UA_UInt32 subId  = (UA_UInt32)strtoul(subIdStr, NULL, 10);
    UA_UInt32 seqNum = (UA_UInt32)strtoul(seqStr,   NULL, 10);

    int req_ms   = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_Client *client = make_client(endpoint, req_ms, "republish", &exit_code);
    if (!client) return exit_code;

    UA_RepublishRequest req;
    UA_RepublishRequest_init(&req);
    req.subscriptionId           = subId;
    req.retransmitSequenceNumber = seqNum;

    UA_RepublishResponse resp;
    UA_RepublishResponse_init(&resp);
    __UA_Client_Service(client, &req,
        &UA_TYPES[UA_TYPES_REPUBLISHREQUEST],
        &resp,
        &UA_TYPES[UA_TYPES_REPUBLISHRESPONSE]);

    UA_StatusCode sc = resp.responseHeader.serviceResult;
    int ok = UA_StatusCode_isGood(sc);

    output_begin("open62541", "republish");
    output_success(ok);
    output_service_result(sc);
    output_open_results();

    printf("{");
    printf("\"subscriptionId\":%" PRIu32, subId);
    printf(",\"retransmitSequenceNumber\":%" PRIu32, seqNum);
    if (ok) {
        printf(",\"sequenceNumber\":%" PRIu32,
               resp.notificationMessage.sequenceNumber);
        char tsbuf[64];
        output_timestamp(resp.notificationMessage.publishTime,
                         tsbuf, sizeof(tsbuf));
        if (tsbuf[0])
            printf(",\"publishTime\":\"%s\"", tsbuf);
        printf(",\"notificationDataCount\":%" PRIu64,
               (uint64_t)resp.notificationMessage.notificationDataSize);
    }
    printf("}");

    output_close_results();
    output_null_error();
    output_end();

    UA_RepublishResponse_clear(&resp);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * transfer-subscriptions subcommand
 * ---------------------------------------------------------------------- */

static int cmd_transfer_subscriptions(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *sivsStr  = find_arg(argc, argv, "--send-initial-values");

    int subIdCount = count_flag(argc, argv, "--subscription-id");
    if (!endpoint || subIdCount == 0) {
        output_begin("open62541", "transfer-subscriptions");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: transfer-subscriptions --endpoint <url>"
            " --subscription-id <n> [--subscription-id <n> ...]"
            " [--send-initial-values true|false]");
        output_end();
        return 2;
    }

    UA_Boolean sendInitial =
        (sivsStr && strcmp(sivsStr, "true") == 0) ? UA_TRUE : UA_FALSE;

    if (subIdCount > MAX_NODES) subIdCount = MAX_NODES;
    UA_UInt32 subIds[MAX_NODES];
    int n = 0;
    for (int i = 0; i < argc - 1 && n < MAX_NODES; i++) {
        if (strcmp(argv[i], "--subscription-id") == 0)
            subIds[n++] = (UA_UInt32)strtoul(argv[i + 1], NULL, 10);
    }

    int req_ms   = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;
    int exit_code = 3;
    UA_Client *client =
        make_client(endpoint, req_ms, "transfer-subscriptions", &exit_code);
    if (!client) return exit_code;

    UA_TransferSubscriptionsRequest req;
    UA_TransferSubscriptionsRequest_init(&req);
    req.subscriptionIds     = subIds;
    req.subscriptionIdsSize = (size_t)n;
    req.sendInitialValues   = sendInitial;

    UA_TransferSubscriptionsResponse resp;
    UA_TransferSubscriptionsResponse_init(&resp);
    __UA_Client_Service(client, &req,
        &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSREQUEST],
        &resp,
        &UA_TYPES[UA_TYPES_TRANSFERSUBSCRIPTIONSRESPONSE]);

    UA_StatusCode sc = resp.responseHeader.serviceResult;
    int ok = UA_StatusCode_isGood(sc);

    /* Check per-result statuses */
    if (ok) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            if (!UA_StatusCode_isGood(resp.results[i].statusCode)) {
                ok = 0;
                break;
            }
        }
    }

    output_begin("open62541", "transfer-subscriptions");
    output_success(ok);
    output_service_result(sc);
    output_open_results();

    if (UA_StatusCode_isGood(sc)) {
        for (size_t i = 0; i < resp.resultsSize; i++) {
            UA_TransferResult *r = &resp.results[i];
            if (i > 0) printf(",");
            printf("{");
            printf("\"subscriptionId\":%" PRIu32, subIds[i]);
            printf(",\"statusCode\":{\"name\":\"%s\",\"code\":%" PRIu32
                   ",\"severity\":\"%s\"}",
                   output_status_code_name(r->statusCode),
                   (uint32_t)r->statusCode,
                   output_severity(r->statusCode));
            printf(",\"availableSequenceNumbers\":[");
            for (size_t j = 0; j < r->availableSequenceNumbersSize; j++) {
                if (j > 0) printf(",");
                printf("%" PRIu32, r->availableSequenceNumbers[j]);
            }
            printf("]}");
        }
    }

    output_close_results();
    output_null_error();
    output_end();

    UA_TransferSubscriptionsResponse_clear(&resp);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    if (sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * register-nodes subcommand
 *
 * RegisterNodes -> Read Value through each registered alias -> UnregisterNodes.
 * ---------------------------------------------------------------------- */

static void print_sc_obj(const char *key, UA_StatusCode sc) {
    printf("\"%s\":{\"name\":\"%s\",\"code\":%" PRIu32 ",\"severity\":\"%s\"}",
           key, output_status_code_name(sc), (uint32_t)sc, output_severity(sc));
}

/* -------------------------------------------------------------------------
 * alarms subcommand (Part 9 Alarms & Conditions: ConditionRefresh,
 * Acknowledge, Confirm, AddComment; docs/CONTAINER_CONTRACT.md `alarms`)
 * ---------------------------------------------------------------------- */

#define AL_NF        16
#define AL_MAX_EVS   1024
#define AL_MAX_CONDS 64

/* SelectClauses {TypeDefinitionId, BrowsePath[0], BrowsePath[1]}; the last
 * one is the ConditionId (ConditionType, empty BrowsePath, AttributeId NodeId,
 * Part 9 §5.5.2). */
static const struct { UA_UInt32 type; const char *p0; const char *p1; } kAlSelect[AL_NF] = {
    {UA_NS0ID_BASEEVENTTYPE, "EventId", NULL},
    {UA_NS0ID_BASEEVENTTYPE, "EventType", NULL},
    {UA_NS0ID_BASEEVENTTYPE, "SourceNode", NULL},
    {UA_NS0ID_BASEEVENTTYPE, "SourceName", NULL},
    {UA_NS0ID_BASEEVENTTYPE, "Time", NULL},
    {UA_NS0ID_BASEEVENTTYPE, "Message", NULL},
    {UA_NS0ID_BASEEVENTTYPE, "Severity", NULL},
    {UA_NS0ID_CONDITIONTYPE, "ConditionName", NULL},
    {UA_NS0ID_CONDITIONTYPE, "BranchId", NULL},
    {UA_NS0ID_CONDITIONTYPE, "Retain", NULL},
    {UA_NS0ID_CONDITIONTYPE, "EnabledState", "Id"},
    {UA_NS0ID_CONDITIONTYPE, "Comment", NULL},
    {UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE, "AckedState", "Id"},
    {UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE, "ConfirmedState", "Id"},
    {UA_NS0ID_ALARMCONDITIONTYPE, "ActiveState", "Id"},
    {UA_NS0ID_CONDITIONTYPE, NULL, NULL},
};

enum { AL_EVENTID = 0, AL_EVENTTYPE, AL_SOURCENODE, AL_SOURCENAME, AL_TIME,
       AL_MESSAGE, AL_SEVERITY, AL_CONDNAME, AL_BRANCHID, AL_RETAIN,
       AL_ENABLED, AL_COMMENT, AL_ACKED, AL_CONFIRMED, AL_ACTIVE, AL_CONDID };

typedef struct { UA_Variant v[AL_NF]; } AlEvent;

typedef struct {
    AlEvent *evs;   /* condition events (non-null ConditionId), arrival order */
    size_t   n;
    int      phase; /* 0 before ConditionRefresh, 1 refreshing, 2 RefreshEnd seen */
    int      startSeen;
    int      endSeen;
    size_t   conds[AL_MAX_CONDS]; /* indices into evs: refreshed conditions, last per id */
    size_t   nConds;
} AlStore;

static const UA_NodeId *al_nodeid(const UA_Variant *v) {
    if (v && UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_NODEID]))
        return (const UA_NodeId *)v->data;
    return NULL;
}

static int al_bool(const UA_Variant *v, int *out) {
    if (v && UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_BOOLEAN])) {
        *out = *(const UA_Boolean *)v->data ? 1 : 0;
        return 1;
    }
    return 0;
}

/* Text of a LocalizedText or String field, NULL for any other type. */
static const UA_String *al_text(const UA_Variant *v) {
    if (v && UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]))
        return &((const UA_LocalizedText *)v->data)->text;
    if (v && UA_Variant_hasScalarType(v, &UA_TYPES[UA_TYPES_STRING]))
        return (const UA_String *)v->data;
    return NULL;
}

static int al_text_eq(const UA_String *t, const char *s) {
    size_t n = strlen(s);
    return t && t->length == n && (n == 0 || memcmp(t->data, s, n) == 0);
}

/* The client hands the event fields over in SelectClause order (the map keys
 * are derived from the BrowsePaths). Values are borrowed: copy them. */
static void alarm_notif_cb(UA_Client *client, UA_UInt32 subId, void *subCtx,
                           UA_UInt32 monId, void *monCtx,
                           const UA_KeyValueMap eventFields) {
    (void)client; (void)subId; (void)subCtx; (void)monId;
    AlStore *st = (AlStore *)monCtx;
    if (!st || eventFields.mapSize < AL_NF) return;
    const UA_NodeId *et = al_nodeid(&eventFields.map[AL_EVENTTYPE].value);
    if (et && et->namespaceIndex == 0 && et->identifierType == UA_NODEIDTYPE_NUMERIC) {
        if (et->identifier.numeric == UA_NS0ID_REFRESHSTARTEVENTTYPE) {
            if (st->phase == 1) st->startSeen = 1;
            return;
        }
        if (et->identifier.numeric == UA_NS0ID_REFRESHENDEVENTTYPE) {
            if (st->phase == 1) { st->endSeen = 1; st->phase = 2; }
            return;
        }
    }
    const UA_NodeId *cid = al_nodeid(&eventFields.map[AL_CONDID].value);
    if (!cid || UA_NodeId_isNull(cid)) return; /* not a condition (e.g. the Events.Source BaseEvents) */
    if (st->n >= AL_MAX_EVS) return;
    AlEvent *e = &st->evs[st->n];
    for (size_t i = 0; i < AL_NF; i++) {
        UA_Variant_init(&e->v[i]);
        UA_Variant_copy(&eventFields.map[i].value, &e->v[i]);
    }
    size_t idx = st->n++;
    if (st->phase == 1) {
        for (size_t i = 0; i < st->nConds; i++) {
            const UA_NodeId *o = al_nodeid(&st->evs[st->conds[i]].v[AL_CONDID]);
            if (o && UA_NodeId_equal(o, cid)) { st->conds[i] = idx; return; }
        }
        if (st->nConds < AL_MAX_CONDS) st->conds[st->nConds++] = idx;
    }
}

/* Index of the latest event of the condition, -1 if none. */
static long al_latest(const AlStore *st, const UA_NodeId *cid) {
    for (size_t i = st->n; i > 0; i--) {
        const UA_NodeId *o = al_nodeid(&st->evs[i - 1].v[AL_CONDID]);
        if (o && UA_NodeId_equal(o, cid)) return (long)(i - 1);
    }
    return -1;
}

typedef enum { AL_WANT_ACKED, AL_WANT_CONFIRMED, AL_WANT_COMMENT } AlWant;

/* First event of the condition at index >= from that shows the action's effect. */
static long al_find_followup(const AlStore *st, const UA_NodeId *cid, size_t from,
                             AlWant want, const char *comment) {
    for (size_t i = from; i < st->n; i++) {
        const AlEvent *e = &st->evs[i];
        const UA_NodeId *o = al_nodeid(&e->v[AL_CONDID]);
        if (!o || !UA_NodeId_equal(o, cid)) continue;
        int b = 0;
        if (want == AL_WANT_ACKED && al_bool(&e->v[AL_ACKED], &b) && b) return (long)i;
        if (want == AL_WANT_CONFIRMED && al_bool(&e->v[AL_CONFIRMED], &b) && b) return (long)i;
        if (want == AL_WANT_COMMENT && al_text_eq(al_text(&e->v[AL_COMMENT]), comment))
            return (long)i;
    }
    return -1;
}

static void al_print_nodeid(const UA_Variant *v) {
    const UA_NodeId *n = al_nodeid(v);
    if (n) output_nodeid(n); else printf("null");
}

static void al_print_bool(const UA_Variant *v) {
    int b;
    if (al_bool(v, &b)) printf(b ? "true" : "false"); else printf("null");
}

/* Text of a field of exactly `type` (String or LocalizedText), else null. */
static void al_print_text(const UA_Variant *v, const UA_DataType *type) {
    const UA_String *t = UA_Variant_hasScalarType(v, type) ? al_text(v) : NULL;
    if (t) output_json_string_len(t->data, t->length); else printf("null");
}

static void al_print_scalar(const UA_Variant *v, const UA_DataType *type) {
    if (UA_Variant_hasScalarType(v, type)) output_ua_scalar(v->data, type);
    else printf("null");
}

/* ConditionEntry of the contract (fixed key order). */
static void al_print_entry(const AlEvent *e) {
    if (!e) { printf("null"); return; }
    printf("{\"conditionId\":");   al_print_nodeid(&e->v[AL_CONDID]);
    printf(",\"eventId\":");       al_print_scalar(&e->v[AL_EVENTID], &UA_TYPES[UA_TYPES_BYTESTRING]);
    printf(",\"eventType\":");     al_print_nodeid(&e->v[AL_EVENTTYPE]);
    printf(",\"sourceNode\":");    al_print_nodeid(&e->v[AL_SOURCENODE]);
    printf(",\"sourceName\":");    al_print_text(&e->v[AL_SOURCENAME], &UA_TYPES[UA_TYPES_STRING]);
    printf(",\"conditionName\":"); al_print_text(&e->v[AL_CONDNAME], &UA_TYPES[UA_TYPES_STRING]);
    printf(",\"time\":");          al_print_scalar(&e->v[AL_TIME], &UA_TYPES[UA_TYPES_DATETIME]);
    printf(",\"message\":");       al_print_text(&e->v[AL_MESSAGE], &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    printf(",\"severity\":");
    if (UA_Variant_hasScalarType(&e->v[AL_SEVERITY], &UA_TYPES[UA_TYPES_UINT16]))
        printf("%u", (unsigned)*(const UA_UInt16 *)e->v[AL_SEVERITY].data);
    else
        printf("null");
    printf(",\"retain\":");    al_print_bool(&e->v[AL_RETAIN]);
    printf(",\"enabled\":");   al_print_bool(&e->v[AL_ENABLED]);
    printf(",\"acked\":");     al_print_bool(&e->v[AL_ACKED]);
    printf(",\"confirmed\":"); al_print_bool(&e->v[AL_CONFIRMED]);
    printf(",\"active\":");    al_print_bool(&e->v[AL_ACTIVE]);
    printf(",\"comment\":");   al_print_text(&e->v[AL_COMMENT], &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    printf("}");
}

/* Bare presence flag; "--flag false" switches it off. */
static int al_flag(int argc, char **argv, const char *flag) {
    int on = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], flag) != 0) continue;
        on = !(i + 1 < argc && strcmp(argv[i + 1], "false") == 0);
    }
    return on;
}

typedef struct {
    int           requested;
    int           called;
    UA_StatusCode sc;
    long          event;     /* index into evs, -1 none */
    int           hasRepeat;
    UA_StatusCode repeatSc;
} AlAction;

static UA_StatusCode al_call_condition_method(UA_Client *client, const UA_NodeId *cid,
                                              UA_UInt32 method, const UA_ByteString *eventId,
                                              const char *comment) {
    UA_Variant in[2];
    UA_Variant_init(&in[0]);
    UA_Variant_init(&in[1]);
    UA_Variant_setScalarCopy(&in[0], eventId, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_LocalizedText lt = UA_LOCALIZEDTEXT((char *)"en", (char *)comment);
    UA_Variant_setScalarCopy(&in[1], &lt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    size_t outSize = 0;
    UA_Variant *out = NULL;
    UA_StatusCode sc = UA_Client_call(client, *cid, UA_NODEID_NUMERIC(0, method),
                                      2, in, &outSize, &out);
    if (out) UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);
    UA_Variant_clear(&in[0]);
    UA_Variant_clear(&in[1]);
    return sc;
}

static void al_print_action(const char *key, const AlAction *a, const AlStore *st, int withRepeat) {
    printf(",\"%s\":", key);
    if (!a->called) { printf("null"); return; }
    printf("{");
    print_sc_obj("statusCode", a->sc);
    printf(",\"event\":");
    al_print_entry(a->event >= 0 ? &st->evs[a->event] : NULL);
    if (withRepeat) {
        printf(",");
        if (a->hasRepeat) print_sc_obj("repeatStatusCode", a->repeatSc);
        else printf("\"repeatStatusCode\":null");
    }
    printf("}");
}

static int cmd_alarms(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *nodeArg  = find_arg(argc, argv, "--node");
    const char *nodeStr  = nodeArg ? nodeArg : "i=2253";
    const char *condName = find_arg(argc, argv, "--condition-name");
    const char *comment  = find_arg(argc, argv, "--comment");
    const char *toStr    = find_arg(argc, argv, "--timeout-ms");
    const char *piStr    = find_arg(argc, argv, "--publishing-interval-ms");
    if (!comment) comment = "interop-comment";
    int    toMs = toStr ? atoi(toStr) : 15000;
    double piMs = piStr ? atof(piStr) : 200.0;
    if (toMs <= 0) toMs = 15000;

    AlAction ack, conf, cmt;
    memset(&ack, 0, sizeof(ack));
    memset(&conf, 0, sizeof(conf));
    memset(&cmt, 0, sizeof(cmt));
    ack.event = conf.event = cmt.event = -1;
    ack.requested  = al_flag(argc, argv, "--acknowledge");
    conf.requested = al_flag(argc, argv, "--confirm");
    cmt.requested  = al_flag(argc, argv, "--add-comment");

    if (!endpoint) {
        cli_emit_failure("alarms", UA_STATUSCODE_BADINVALIDARGUMENT, "input",
            "usage: alarms --endpoint <url> [--node <nodeId>] [--condition-name <name>]"
            " [--acknowledge] [--confirm] [--add-comment] [--comment <text>]"
            " [--timeout-ms <ms>] [--publishing-interval-ms <ms>]");
        return 2;
    }
    if (validate_nodeid_structure(nodeStr) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "malformed NodeId: '%s'", nodeStr);
        cli_emit_failure("alarms", UA_STATUSCODE_BADINVALIDARGUMENT, "input", msg);
        return 2;
    }

    int exit_code = 3;
    UA_Client *client = make_client(endpoint, 5000, "alarms", &exit_code);
    if (!client) return exit_code;
    UA_DateTime deadline = UA_DateTime_nowMonotonic() + (UA_DateTime)toMs * UA_DATETIME_MSEC;

    UA_NodeId nodeId; UA_NodeId_init(&nodeId);
    if (strncmp(nodeStr, "nsu=", 4) == 0) {
        if (resolve_nsu_nodeid(client, nodeStr, &nodeId) != 0) {
            UA_Client_disconnect(client);
            UA_Client_delete(client);
            char msg[512];
            snprintf(msg, sizeof(msg), "unknown namespace URI in '%s'", nodeStr);
            cli_emit_failure("alarms", UA_STATUSCODE_BADNAMESPACEURIINVALID, "input", msg);
            return 2;
        }
    } else {
        nodeId = parse_nodeid_local(nodeStr);
    }

    UA_CreateSubscriptionRequest subReq = UA_CreateSubscriptionRequest_default();
    subReq.requestedPublishingInterval = piMs;
    UA_CreateSubscriptionResponse subResp =
        UA_Client_Subscriptions_create(client, subReq, NULL, NULL, NULL);
    UA_StatusCode svc_sc = subResp.responseHeader.serviceResult;
    if (!UA_StatusCode_isGood(svc_sc)) {
        UA_NodeId_clear(&nodeId);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        cli_emit_failure("alarms", svc_sc, "service", "CreateSubscription failed");
        return 4;
    }
    UA_UInt32 subId = subResp.subscriptionId;

    UA_EventFilter filter;
    UA_EventFilter_init(&filter);
    filter.selectClauses = (UA_SimpleAttributeOperand *)
        UA_Array_new(AL_NF, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
    filter.selectClausesSize = AL_NF;
    for (size_t i = 0; i < AL_NF; i++) {
        UA_SimpleAttributeOperand *op = &filter.selectClauses[i];
        op->typeDefinitionId = UA_NODEID_NUMERIC(0, kAlSelect[i].type);
        if (!kAlSelect[i].p0) {
            op->attributeId = UA_ATTRIBUTEID_NODEID; /* ConditionId */
            continue;
        }
        op->attributeId = UA_ATTRIBUTEID_VALUE;
        size_t np = kAlSelect[i].p1 ? 2 : 1;
        op->browsePath = (UA_QualifiedName *)UA_Array_new(np, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
        op->browsePathSize = np;
        op->browsePath[0] = UA_QUALIFIEDNAME_ALLOC(0, kAlSelect[i].p0);
        if (np == 2) op->browsePath[1] = UA_QUALIFIEDNAME_ALLOC(0, kAlSelect[i].p1);
    }

    UA_MonitoredItemCreateRequest monReq;
    UA_MonitoredItemCreateRequest_init(&monReq);
    monReq.itemToMonitor.nodeId      = nodeId; /* shallow */
    monReq.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
    monReq.monitoringMode            = UA_MONITORINGMODE_REPORTING;
    monReq.requestedParameters.samplingInterval = 0.0;
    monReq.requestedParameters.queueSize        = 1000;
    monReq.requestedParameters.discardOldest    = UA_TRUE;
    UA_ExtensionObject_setValueCopy(&monReq.requestedParameters.filter,
                                    &filter, &UA_TYPES[UA_TYPES_EVENTFILTER]);
    UA_EventFilter_clear(&filter);

    AlStore st;
    memset(&st, 0, sizeof(st));
    st.evs = (AlEvent *)calloc(AL_MAX_EVS, sizeof(AlEvent));

    UA_MonitoredItemCreateResult monResp =
        UA_Client_MonitoredItems_createEvent(client, subId, UA_TIMESTAMPSTORETURN_BOTH,
                                             monReq, &st, alarm_notif_cb, NULL);
    UA_StatusCode mon_sc = monResp.statusCode;
    monReq.itemToMonitor.nodeId = UA_NODEID_NULL;
    UA_MonitoredItemCreateRequest_clear(&monReq);
    UA_MonitoredItemCreateResult_clear(&monResp);

    UA_StatusCode refresh_sc = mon_sc;
    UA_StatusCode final_sc = UA_STATUSCODE_GOOD;
    const char *errCat = NULL;
    char errMsg[256] = {0};
    long target = -1;

    if (!UA_StatusCode_isGood(mon_sc)) {
        final_sc = mon_sc;
        errCat = "service";
        snprintf(errMsg, sizeof(errMsg), "CreateMonitoredItems rejected the event monitored item");
        goto done;
    }

    /* ConditionRefresh(SubscriptionId), ObjectId = ConditionType */
    {
        st.phase = 1;
        UA_Variant in;
        UA_Variant_init(&in);
        UA_Variant_setScalarCopy(&in, &subId, &UA_TYPES[UA_TYPES_UINT32]);
        size_t outSize = 0;
        UA_Variant *out = NULL;
        refresh_sc = UA_Client_call(client, UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE),
                                    UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH),
                                    1, &in, &outSize, &out);
        if (out) UA_Array_delete(out, outSize, &UA_TYPES[UA_TYPES_VARIANT]);
        UA_Variant_clear(&in);
    }
    if (!UA_StatusCode_isGood(refresh_sc)) {
        final_sc = refresh_sc;
        errCat = "service";
        snprintf(errMsg, sizeof(errMsg), "ConditionRefresh failed");
        goto done;
    }
    while (!st.endSeen && UA_DateTime_nowMonotonic() < deadline)
        UA_Client_run_iterate(client, 50);
    if (!st.endSeen) {
        final_sc = UA_STATUSCODE_BADTIMEOUT;
        errCat = "timeout";
        snprintf(errMsg, sizeof(errMsg), "timeout waiting for the RefreshEndEvent");
        goto done;
    }

    for (size_t i = 0; i < st.nConds && target < 0; i++) {
        const AlEvent *e = &st.evs[st.conds[i]];
        int r = 0;
        if (condName ? al_text_eq(al_text(&e->v[AL_CONDNAME]), condName)
                     : (al_bool(&e->v[AL_RETAIN], &r) && r))
            target = (long)st.conds[i];
    }
    if (target < 0 && (ack.requested || conf.requested || cmt.requested)) {
        final_sc = UA_STATUSCODE_BADNODEIDUNKNOWN;
        errCat = "service";
        snprintf(errMsg, sizeof(errMsg), "no matching condition in the ConditionRefresh");
        goto done;
    }

    if (target >= 0) {
        AlAction *acts[3] = {&ack, &conf, &cmt};
        static const char *names[3] = {"Acknowledge", "Confirm", "AddComment"};
        const UA_UInt32 methods[3] = {
            UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE,
            UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_CONFIRM,
            UA_NS0ID_CONDITIONTYPE_ADDCOMMENT };
        const AlWant wants[3] = {AL_WANT_ACKED, AL_WANT_CONFIRMED, AL_WANT_COMMENT};
        UA_NodeId cid;
        UA_NodeId_copy(al_nodeid(&st.evs[target].v[AL_CONDID]), &cid);
        for (int k = 0; k < 3; k++) {
            AlAction *a = acts[k];
            if (!a->requested) continue;
            /* EventId of the latest event of the condition */
            long latest = al_latest(&st, &cid);
            UA_ByteString eventId;
            UA_ByteString_init(&eventId);
            if (latest >= 0 &&
                UA_Variant_hasScalarType(&st.evs[latest].v[AL_EVENTID], &UA_TYPES[UA_TYPES_BYTESTRING]))
                UA_ByteString_copy((const UA_ByteString *)st.evs[latest].v[AL_EVENTID].data, &eventId);
            size_t mark = st.n;
            a->called = 1;
            a->sc = al_call_condition_method(client, &cid, methods[k], &eventId, comment);
            if (!UA_StatusCode_isGood(a->sc)) {
                UA_ByteString_clear(&eventId);
                final_sc = a->sc;
                errCat = "service";
                snprintf(errMsg, sizeof(errMsg), "%s failed", names[k]);
                break;
            }
            while ((a->event = al_find_followup(&st, &cid, mark, wants[k], comment)) < 0 &&
                   UA_DateTime_nowMonotonic() < deadline)
                UA_Client_run_iterate(client, 50);
            if (k == 0) {
                /* the same, now stale EventId again */
                a->hasRepeat = 1;
                a->repeatSc = al_call_condition_method(client, &cid, methods[k], &eventId, comment);
            }
            UA_ByteString_clear(&eventId);
            if (a->event < 0) {
                final_sc = UA_STATUSCODE_BADTIMEOUT;
                errCat = "timeout";
                snprintf(errMsg, sizeof(errMsg), "timeout waiting for the %s event", names[k]);
                break;
            }
        }
        UA_NodeId_clear(&cid);
    }

done:;
    int ok = errCat == NULL;
    output_begin("open62541", "alarms");
    output_success(ok);
    output_service_result(final_sc);
    printf(",\"results\":[{\"nodeId\":");
    output_nodeid(&nodeId);
    printf(",\"subscriptionId\":%" PRIu32 ",", (uint32_t)subId);
    print_sc_obj("monitoredItemStatusCode", mon_sc);
    printf(",\"refresh\":{");
    print_sc_obj("statusCode", refresh_sc);
    printf(",\"startSeen\":%s,\"endSeen\":%s}", st.startSeen ? "true" : "false",
           st.endSeen ? "true" : "false");
    printf(",\"conditions\":[");
    for (size_t i = 0; i < st.nConds; i++) {
        if (i > 0) printf(",");
        al_print_entry(&st.evs[st.conds[i]]);
    }
    printf("],\"target\":");
    al_print_entry(target >= 0 ? &st.evs[target] : NULL);
    al_print_action("acknowledge", &ack, &st, 1);
    al_print_action("confirm", &conf, &st, 0);
    al_print_action("addComment", &cmt, &st, 0);
    printf("}]");
    if (ok) {
        printf(",\"error\":null");
    } else {
        printf(",\"error\":{\"category\":\"%s\",\"message\":", errCat);
        output_json_string(errMsg);
        printf("}");
    }
    output_end();

    UA_Client_Subscriptions_deleteSingle(client, subId);
    for (size_t i = 0; i < st.n; i++)
        for (size_t j = 0; j < AL_NF; j++)
            UA_Variant_clear(&st.evs[i].v[j]);
    free(st.evs);
    UA_NodeId_clear(&nodeId);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    if (ok) return 0;
    return strcmp(errCat, "timeout") == 0 ? 7 : 4;
}

static int cmd_register_nodes(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    int n = count_flag(argc, argv, "--node");
    if (!endpoint || n == 0) {
        output_begin("open62541", "register-nodes");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input", "usage: register-nodes --endpoint <url> --node <nodeId> [--node ...]");
        output_end();
        return 2;
    }
    if (n > MAX_NODES) n = MAX_NODES;
    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;

    const char *nodes[MAX_NODES];
    int k = 0;
    for (int i = 0; i < argc - 1 && k < n; i++)
        if (strcmp(argv[i], "--node") == 0) nodes[k++] = argv[i + 1];

    UA_NodeId ids[MAX_NODES];
    int exit_code = 3;
    UA_Client *client = resolve_node_ids(nodes, n, ids, "register-nodes",
                                         endpoint, req_ms, &exit_code);
    if (!client) return exit_code;

    UA_RegisterNodesRequest rreq;
    UA_RegisterNodesRequest_init(&rreq);
    rreq.nodesToRegister = ids;
    rreq.nodesToRegisterSize = (size_t)n;
    UA_RegisterNodesResponse rresp;
    UA_RegisterNodesResponse_init(&rresp);
    __UA_Client_Service(client, &rreq, &UA_TYPES[UA_TYPES_REGISTERNODESREQUEST],
                        &rresp, &UA_TYPES[UA_TYPES_REGISTERNODESRESPONSE]);
    UA_StatusCode reg_sc = rresp.responseHeader.serviceResult;
    if (UA_StatusCode_isGood(reg_sc) && rresp.registeredNodeIdsSize != (size_t)n)
        reg_sc = UA_STATUSCODE_BADUNEXPECTEDERROR;

    if (!UA_StatusCode_isGood(reg_sc)) {
        output_begin("open62541", "register-nodes");
        output_success(0);
        output_service_result(reg_sc);
        output_error("service", "RegisterNodes failed");
        output_end();
        UA_RegisterNodesResponse_clear(&rresp);
        for (int i = 0; i < n; i++) UA_NodeId_clear(&ids[i]);
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        return reg_sc == UA_STATUSCODE_BADTIMEOUT ? 7 : 4;
    }

    /* Read through the registered aliases. */
    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.timestampsToReturn = UA_TIMESTAMPSTORETURN_SOURCE;
    req.nodesToRead = (UA_ReadValueId *)UA_Array_new((size_t)n, &UA_TYPES[UA_TYPES_READVALUEID]);
    req.nodesToReadSize = (size_t)n;
    for (int i = 0; i < n; i++) {
        UA_ReadValueId_init(&req.nodesToRead[i]);
        UA_NodeId_copy(&rresp.registeredNodeIds[i], &req.nodesToRead[i].nodeId);
        req.nodesToRead[i].attributeId = UA_ATTRIBUTEID_VALUE;
    }
    UA_ReadResponse resp = UA_Client_Service_read(client, req);
    UA_ReadRequest_clear(&req);
    UA_StatusCode read_sc = resp.responseHeader.serviceResult;
    if (UA_StatusCode_isGood(read_sc) && resp.resultsSize != (size_t)n)
        read_sc = UA_STATUSCODE_BADUNEXPECTEDERROR;

    UA_UnregisterNodesRequest ureq;
    UA_UnregisterNodesRequest_init(&ureq);
    ureq.nodesToUnregister = rresp.registeredNodeIds;
    ureq.nodesToUnregisterSize = rresp.registeredNodeIdsSize;
    UA_UnregisterNodesResponse uresp;
    UA_UnregisterNodesResponse_init(&uresp);
    __UA_Client_Service(client, &ureq, &UA_TYPES[UA_TYPES_UNREGISTERNODESREQUEST],
                        &uresp, &UA_TYPES[UA_TYPES_UNREGISTERNODESRESPONSE]);
    UA_StatusCode unreg_sc = uresp.responseHeader.serviceResult;
    UA_UnregisterNodesResponse_clear(&uresp);

    int ok = UA_StatusCode_isGood(read_sc) && UA_StatusCode_isGood(unreg_sc);
    UA_StatusCode emit_sc = !UA_StatusCode_isGood(read_sc) ? read_sc : unreg_sc;
    if (UA_StatusCode_isGood(read_sc)) {
        for (int i = 0; i < n; i++) {
            if (!UA_StatusCode_isGood(resp.results[i].status)) {
                ok = 0;
                if (UA_StatusCode_isGood(emit_sc)) emit_sc = resp.results[i].status;
            }
        }
    }

    output_begin("open62541", "register-nodes");
    output_success(ok);
    output_service_result(emit_sc);
    output_open_results();
    for (int i = 0; i < n; i++) {
        if (i > 0) printf(",");
        printf("{\"nodeId\":");
        output_nodeid(&ids[i]);
        printf(",\"registeredNodeId\":");
        output_nodeid(&rresp.registeredNodeIds[i]);
        printf(",");
        if (UA_StatusCode_isGood(read_sc)) {
            UA_DataValue *dv = &resp.results[i];
            print_sc_obj("statusCode", dv->status);
            if (dv->hasValue && dv->value.type) {
                printf(",\"dataType\":\"%s\",\"builtInType\":%d",
                       type_name(dv->value.type), ua_type_to_builtin_id(dv->value.type));
                output_ua_variant_field("value", &dv->value);
            }
        } else {
            print_sc_obj("statusCode", read_sc);
        }
        printf(",");
        print_sc_obj("unregisterStatusCode", unreg_sc);
        printf("}");
    }
    output_close_results();
    output_null_error();
    output_end();

    UA_ReadResponse_clear(&resp);
    UA_RegisterNodesResponse_clear(&rresp);
    for (int i = 0; i < n; i++) UA_NodeId_clear(&ids[i]);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    if (emit_sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * node-management subcommand
 *
 * AddNodes (Int32 Variable under --parent) -> Read -> DeleteNodes -> Read.
 * ---------------------------------------------------------------------- */

static int cmd_node_management(int argc, char **argv) {
    const char *endpoint = find_arg(argc, argv, "--endpoint");
    const char *parent   = find_arg(argc, argv, "--parent");
    const char *node     = find_arg(argc, argv, "--node");
    const char *bname    = find_arg(argc, argv, "--browse-name");
    const char *valStr   = find_arg(argc, argv, "--value");
    if (!endpoint || !parent || !node) {
        output_begin("open62541", "node-management");
        output_success(0);
        output_service_result(UA_STATUSCODE_BADINVALIDARGUMENT);
        output_error("input",
            "usage: node-management --endpoint <url> --parent <nodeId> --node <newNodeId>"
            " [--browse-name <name>] [--value <int32>]");
        output_end();
        return 2;
    }
    if (!bname) bname = "InteropAdded";
    UA_Int32 value = valStr ? (UA_Int32)atoi(valStr) : 42;
    int req_ms = parse_int_flag(argc, argv, "--request-timeout", 5) * 1000;

    const char *nodes[2] = { parent, node };
    UA_NodeId ids[2];
    int exit_code = 3;
    UA_Client *client = resolve_node_ids(nodes, 2, ids, "node-management",
                                         endpoint, req_ms, &exit_code);
    if (!client) return exit_code;

    UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName = UA_LOCALIZEDTEXT_ALLOC("en", bname);
    attr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
    attr.valueRank = UA_VALUERANK_SCALAR;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    attr.userAccessLevel = attr.accessLevel;
    UA_Variant_setScalarCopy(&attr.value, &value, &UA_TYPES[UA_TYPES_INT32]);

    UA_NodeId added = UA_NODEID_NULL;
    UA_StatusCode add_sc = UA_Client_addVariableNode(
        client, ids[1], ids[0],
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
        UA_QUALIFIEDNAME_ALLOC(ids[1].namespaceIndex, bname),
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
        attr, &added);
    UA_VariableAttributes_clear(&attr);

    UA_StatusCode read_sc = UA_STATUSCODE_BADNOTHINGTODO;
    UA_StatusCode del_sc  = UA_STATUSCODE_BADNOTHINGTODO;
    UA_StatusCode read2_sc = UA_STATUSCODE_BADNOTHINGTODO;
    UA_Variant readVal; UA_Variant_init(&readVal);
    int valueMatches = 0;

    if (UA_StatusCode_isGood(add_sc)) {
        read_sc = UA_Client_readValueAttribute(client, added, &readVal);
        if (UA_StatusCode_isGood(read_sc) &&
            UA_Variant_hasScalarType(&readVal, &UA_TYPES[UA_TYPES_INT32]))
            valueMatches = (*(UA_Int32 *)readVal.data == value);

        del_sc = UA_Client_deleteNode(client, added, UA_TRUE);

        UA_Variant gone; UA_Variant_init(&gone);
        read2_sc = UA_Client_readValueAttribute(client, added, &gone);
        UA_Variant_clear(&gone);
    }

    int ok = UA_StatusCode_isGood(add_sc) && UA_StatusCode_isGood(read_sc) &&
             valueMatches && UA_StatusCode_isGood(del_sc) && UA_StatusCode_isBad(read2_sc);
    UA_StatusCode emit_sc = UA_STATUSCODE_GOOD;
    if (!UA_StatusCode_isGood(add_sc)) emit_sc = add_sc;
    else if (!UA_StatusCode_isGood(read_sc)) emit_sc = read_sc;
    else if (!UA_StatusCode_isGood(del_sc)) emit_sc = del_sc;

    output_begin("open62541", "node-management");
    output_success(ok);
    output_service_result(emit_sc);
    output_open_results();
    printf("{\"parentNodeId\":");
    output_nodeid(&ids[0]);
    printf(",\"requestedNodeId\":");
    output_nodeid(&ids[1]);
    printf(",");
    print_sc_obj("addStatusCode", add_sc);
    if (UA_StatusCode_isGood(add_sc)) {
        printf(",\"addedNodeId\":");
        output_nodeid(&added);
        printf(",");
        print_sc_obj("readStatusCode", read_sc);
        if (UA_StatusCode_isGood(read_sc) && readVal.type) {
            printf(",\"dataType\":\"%s\",\"builtInType\":%d",
                   type_name(readVal.type), ua_type_to_builtin_id(readVal.type));
            output_ua_variant_field("value", &readVal);
        }
        printf(",");
        print_sc_obj("deleteStatusCode", del_sc);
        printf(",");
        print_sc_obj("readAfterDeleteStatusCode", read2_sc);
    }
    printf("}");
    output_close_results();
    output_null_error();
    output_end();

    UA_Variant_clear(&readVal);
    UA_NodeId_clear(&added);
    UA_NodeId_clear(&ids[0]);
    UA_NodeId_clear(&ids[1]);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    if (emit_sc == UA_STATUSCODE_BADTIMEOUT) return 7;
    return ok ? 0 : 4;
}

/* -------------------------------------------------------------------------
 * client_internal.h wrappers
 * ---------------------------------------------------------------------- */

const char *cli_find_arg(int argc, char **argv, const char *flag) {
    return find_arg(argc, argv, flag);
}

int cli_count_flag(int argc, char **argv, const char *flag) {
    return count_flag(argc, argv, flag);
}

int cli_validate_nodeid(const char *s) {
    return validate_nodeid_structure(s);
}

UA_NodeId cli_parse_nodeid_local(const char *s) {
    return parse_nodeid_local(s);
}

int cli_resolve_nsu_nodeid(UA_Client *client, const char *s, UA_NodeId *out) {
    return resolve_nsu_nodeid(client, s, out);
}

UA_Client *cli_make_client(const char *url, int request_ms, const char *op,
                           int *exit_code) {
    return make_client(url, request_ms, op, exit_code);
}

UA_Client *cli_make_channel_client(const char *url, int request_ms, const char *op,
                                   int *exit_code) {
    UA_Client *client = make_client_unconnected(url, request_ms, op, exit_code);
    if (!client) return NULL;
    /* Discovery services run on a SecureChannel without a Session. */
    UA_StatusCode sc = UA_Client_connectSecureChannel(client, url);
    if (sc != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        int timeout = (sc == UA_STATUSCODE_BADTIMEOUT);
        cli_emit_failure(op, sc, timeout ? "timeout" : "transport",
                         timeout ? "connection timed out" : "failed to connect");
        *exit_code = timeout ? 7 : 3;
        return NULL;
    }
    return client;
}

void cli_emit_failure(const char *op, UA_StatusCode sc, const char *category,
                      const char *message) {
    output_begin("open62541", op);
    output_success(0);
    output_service_result(sc);
    output_error(category, message);
    output_end();
}

void cli_print_status(const char *key, UA_StatusCode sc) {
    print_sc_obj(key, sc);
}

/* -------------------------------------------------------------------------
 * Dispatch
 * ---------------------------------------------------------------------- */

int client_run(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: client <endpoints|find-servers|read|write|browse|translate|"
            "call|subscribe|subscription-lifecycle|event-subscribe|alarms|history-read|"
            "history-read-events|history-update-events|"
            "republish|transfer-subscriptions|register-nodes|node-management|"
            "find-servers-on-network|register-server|codec|push|gds-pull> ...\n");
        return 2;
    }

    /* Parse global security flags from the full argv array.
     * Each subcommand receives the full argv so these flags are visible. */
    {
        const char *v;
        if ((v = find_arg(argc, argv, "--security-policy")) != NULL)
            g_sec.policyName = v;
        if ((v = find_arg(argc, argv, "--security-mode")) != NULL)
            g_sec.modeName = v;
        if ((v = find_arg(argc, argv, "--certificate")) != NULL)
            g_sec.certFile = v;
        if ((v = find_arg(argc, argv, "--private-key")) != NULL)
            g_sec.keyFile = v;
        if ((v = find_arg(argc, argv, "--username")) != NULL)
            g_sec.username = v;
        if ((v = find_arg(argc, argv, "--password")) != NULL)
            g_sec.password = v;
        if ((v = find_arg(argc, argv, "--channel-lifetime-ms")) != NULL)
            g_sec.channelLifetimeMs = atoi(v);
        if ((v = find_arg(argc, argv, "--application-uri")) != NULL)
            g_sec.applicationUri = v;
        if ((v = find_arg(argc, argv, "--reverse-listen")) != NULL)
            g_sec.reverseListenPort = atoi(v);
        if ((v = find_arg(argc, argv, "--reverse-timeout-ms")) != NULL)
            g_sec.reverseTimeoutMs = atoi(v);
        if ((v = find_arg(argc, argv, "--reverse-server-uri")) != NULL)
            g_sec.reverseServerUri = v;

        /* Collect all --trust-list values */
        int tc = count_flag(argc, argv, "--trust-list");
        if (tc > 0) {
            static const char **trust_arr = NULL;
            static int trust_cap = 0;
            if (tc > trust_cap) {
                free((void *)trust_arr);
                trust_arr = (const char **)malloc((size_t)tc * sizeof(const char *));
                trust_cap = tc;
            }
            int ti = 0;
            for (int i = 0; i < argc - 1 && ti < tc; i++) {
                if (strcmp(argv[i], "--trust-list") == 0)
                    trust_arr[ti++] = argv[i + 1];
            }
            g_sec.trustFiles = trust_arr;
            g_sec.trustCount = tc;
        }
    }

    const char *sub = argv[1];
    if (strcmp(sub, "endpoints")              == 0) return cmd_endpoints(argc - 1, argv + 1);
    if (strcmp(sub, "find-servers")           == 0) return cmd_find_servers(argc - 1, argv + 1);
    if (strcmp(sub, "read")                   == 0) return cmd_read(argc - 1, argv + 1);
    if (strcmp(sub, "write")                  == 0) return cmd_write(argc - 1, argv + 1);
    if (strcmp(sub, "browse")                 == 0) return cmd_browse(argc - 1, argv + 1);
    if (strcmp(sub, "translate")              == 0) return cmd_translate(argc - 1, argv + 1);
    if (strcmp(sub, "call")                   == 0) return cmd_call(argc - 1, argv + 1);
    if (strcmp(sub, "subscribe")              == 0) return cmd_subscribe(argc - 1, argv + 1);
    if (strcmp(sub, "subscription-lifecycle") == 0) return cmd_subscription_lifecycle(argc - 1, argv + 1);
    if (strcmp(sub, "event-subscribe")        == 0) return cmd_event_subscribe(argc - 1, argv + 1);
    if (strcmp(sub, "alarms")                 == 0) return cmd_alarms(argc - 1, argv + 1);
    if (strcmp(sub, "history-read")           == 0) return cmd_history_read(argc - 1, argv + 1);
    if (strcmp(sub, "history-read-events")    == 0) return cmd_history_read_events(argc - 1, argv + 1);
    if (strcmp(sub, "history-update-events")  == 0) return cmd_history_update_events(argc - 1, argv + 1);
    if (strcmp(sub, "republish")              == 0) return cmd_republish(argc - 1, argv + 1);
    if (strcmp(sub, "transfer-subscriptions") == 0) return cmd_transfer_subscriptions(argc - 1, argv + 1);
    if (strcmp(sub, "register-nodes")         == 0) return cmd_register_nodes(argc - 1, argv + 1);
    if (strcmp(sub, "node-management")        == 0) return cmd_node_management(argc - 1, argv + 1);
    if (strcmp(sub, "find-servers-on-network") == 0) return cmd_find_servers_on_network(argc - 1, argv + 1);
    if (strcmp(sub, "register-server")        == 0) return cmd_register_server(argc - 1, argv + 1);
    if (strcmp(sub, "codec")                  == 0) return cmd_codec(argc - 1, argv + 1);
    if (strcmp(sub, "push")                   == 0) return cmd_push(argc - 1, argv + 1);
    if (strcmp(sub, "gds-pull")               == 0) return cmd_gds_pull(argc - 1, argv + 1);
    fprintf(stderr, "unknown client subcommand: %s\n", sub);
    return 2;
}
