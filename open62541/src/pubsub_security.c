/*
 * PubSub message security policies PubSub-Aes128-CTR and PubSub-Aes256-CTR
 * (OPC UA Part 14 §7.2.2.4.3, Part 7) on OpenSSL.
 *
 * open62541 v1.5.9 ships these two UA_PubSubSecurityPolicy implementations
 * only for the mbedTLS backend (plugins/crypto/mbedtls/
 * securitypolicy_pubsub_aes{128,256}ctr.c); with UA_ENABLE_ENCRYPTION=OPENSSL
 * UA_PubSubSecurityPolicy_Aes128Ctr / _Aes256Ctr are declared but not
 * defined. The adapter is built on OpenSSL (for the ECC SecureChannel
 * policies), so it carries this port: same structure and the same algorithms
 * as the mbedTLS files, OpenSSL primitives instead.
 *
 *   Signature   HMAC-SHA256 over the NetworkMessage, 32 bytes
 *   Encryption  AES-CTR; counter block = KeyNonce (4) | MessageNonce (8) |
 *               block counter (4, big endian, starting at 1)
 *   Key data    SigningKey (32) | EncryptingKey (16 or 32) | KeyNonce (4) —
 *               the layout of the keys an SKS returns from GetSecurityKeys
 *   generateKey P_SHA256(secret, seed) (Part 6 §6.7.5), used by the SKS when
 *               it creates the keys of a SecurityGroup
 */

#include "pubsub_security.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define SHA256_LENGTH            32
#define SIGNING_KEY_LENGTH       32
#define KEYNONCE_LENGTH          4
#define MESSAGENONCE_LENGTH      8
#define AES_BLOCK                16
#define MAX_ENCRYPTING_KEY       32

typedef struct {
    size_t encryptingKeyLength; /* 16 (AES-128) or 32 (AES-256) */
} PolicyContext;

typedef struct {
    size_t  encryptingKeyLength;
    UA_Byte signingKey[SIGNING_KEY_LENGTH];
    UA_Byte encryptingKey[MAX_ENCRYPTING_KEY];
    UA_Byte keyNonce[KEYNONCE_LENGTH];
    UA_Byte messageNonce[MESSAGENONCE_LENGTH];
} GroupContext;

static size_t enc_len(const UA_PubSubSecurityPolicy *p) {
    return ((const PolicyContext *)p->policyContext)->encryptingKeyLength;
}

static int hmac_sha256(const UA_Byte *key, size_t keyLen, const UA_Byte *msg,
                       size_t msgLen, UA_Byte out[SHA256_LENGTH]) {
    unsigned int outLen = 0;
    if (!HMAC(EVP_sha256(), key, (int)keyLen, msg, msgLen, out, &outLen))
        return -1;
    return outLen == SHA256_LENGTH ? 0 : -1;
}

static UA_StatusCode
verify_ctr(const UA_PubSubSecurityPolicy *policy, void *gContext,
           const UA_ByteString *message, const UA_ByteString *signature) {
    (void)policy;
    if (!gContext || !message || !signature)
        return UA_STATUSCODE_BADINTERNALERROR;
    if (signature->length != SHA256_LENGTH)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    GroupContext *gc = (GroupContext *)gContext;
    UA_Byte mac[SHA256_LENGTH];
    if (hmac_sha256(gc->signingKey, SIGNING_KEY_LENGTH, message->data,
                    message->length, mac) != 0)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    if (CRYPTO_memcmp(mac, signature->data, SHA256_LENGTH) != 0)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
sign_ctr(const UA_PubSubSecurityPolicy *policy, void *gContext,
         const UA_ByteString *message, UA_ByteString *signature) {
    (void)policy;
    if (!gContext || !message || !signature || signature->length != SHA256_LENGTH)
        return UA_STATUSCODE_BADINTERNALERROR;
    GroupContext *gc = (GroupContext *)gContext;
    if (hmac_sha256(gc->signingKey, SIGNING_KEY_LENGTH, message->data,
                    message->length, signature->data) != 0)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    return UA_STATUSCODE_GOOD;
}

static size_t
signature_size(const UA_PubSubSecurityPolicy *policy, const void *gContext) {
    (void)policy; (void)gContext;
    return SHA256_LENGTH;
}

static size_t
signing_key_length(const UA_PubSubSecurityPolicy *policy, const void *gContext) {
    (void)policy; (void)gContext;
    return SIGNING_KEY_LENGTH;
}

static size_t
encrypting_key_length(const UA_PubSubSecurityPolicy *policy, const void *gContext) {
    (void)gContext;
    return enc_len(policy);
}

/* AES-CTR is its own inverse: encrypt and decrypt are the same operation. */
static UA_StatusCode
crypt_ctr(const UA_PubSubSecurityPolicy *policy, void *gContext, UA_ByteString *data) {
    (void)policy;
    if (!gContext || !data)
        return UA_STATUSCODE_BADINTERNALERROR;
    if (data->length == 0)
        return UA_STATUSCODE_GOOD;
    GroupContext *gc = (GroupContext *)gContext;

    /* Part 14 §7.2.2.4.3.2: the block counter starts at 1 */
    UA_Byte iv[AES_BLOCK];
    memcpy(iv, gc->keyNonce, KEYNONCE_LENGTH);
    memcpy(iv + KEYNONCE_LENGTH, gc->messageNonce, MESSAGENONCE_LENGTH);
    iv[12] = 0; iv[13] = 0; iv[14] = 0; iv[15] = 1;

    const EVP_CIPHER *cipher = gc->encryptingKeyLength == 32
        ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    int outLen = 0, finLen = 0;
    int ok = EVP_EncryptInit_ex(ctx, cipher, NULL, gc->encryptingKey, iv) == 1 &&
             EVP_EncryptUpdate(ctx, data->data, &outLen, data->data,
                               (int)data->length) == 1 &&
             EVP_EncryptFinal_ex(ctx, data->data + outLen, &finLen) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINTERNALERROR;
}

/* P_SHA256 (RFC 5246 §5 / OPC UA Part 6 §6.7.5) */
static UA_StatusCode
generate_key_ctr(UA_PubSubSecurityPolicy *policy, void *gContext,
                 const UA_ByteString *secret, const UA_ByteString *seed,
                 UA_ByteString *out) {
    (void)gContext;
    if (!policy || !secret || !seed || !out)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_Byte a[SHA256_LENGTH];
    UA_Byte block[SHA256_LENGTH];
    size_t bufLen = SHA256_LENGTH + seed->length;
    UA_Byte *buf = (UA_Byte *)UA_malloc(bufLen);
    if (!buf)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* A(1) = HMAC(secret, seed) */
    if (hmac_sha256(secret->data, secret->length, seed->data, seed->length, a) != 0) {
        UA_free(buf);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    size_t off = 0;
    while (off < out->length) {
        memcpy(buf, a, SHA256_LENGTH);
        memcpy(buf + SHA256_LENGTH, seed->data, seed->length);
        UA_Byte next[SHA256_LENGTH];
        if (hmac_sha256(secret->data, secret->length, buf, bufLen, block) != 0 ||
            hmac_sha256(secret->data, secret->length, a, SHA256_LENGTH, next) != 0) {
            UA_free(buf);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        memcpy(a, next, SHA256_LENGTH);
        size_t n = out->length - off < SHA256_LENGTH ? out->length - off : SHA256_LENGTH;
        memcpy(out->data + off, block, n);
        off += n;
    }
    UA_free(buf);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
generate_nonce_ctr(UA_PubSubSecurityPolicy *policy, void *gContext, UA_ByteString *out) {
    (void)policy; (void)gContext;
    if (!out)
        return UA_STATUSCODE_BADINTERNALERROR;
    if (out->length == 0)
        return UA_STATUSCODE_GOOD;
    return RAND_bytes(out->data, (int)out->length) == 1
        ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADUNEXPECTEDERROR;
}

static int keys_valid(const UA_PubSubSecurityPolicy *policy,
                      const UA_ByteString *signingKey,
                      const UA_ByteString *encryptingKey,
                      const UA_ByteString *keyNonce) {
    return signingKey && signingKey->length == SIGNING_KEY_LENGTH &&
           encryptingKey && encryptingKey->length == enc_len(policy) &&
           keyNonce && keyNonce->length == KEYNONCE_LENGTH;
}

static UA_StatusCode
new_context_ctr(UA_PubSubSecurityPolicy *policy, const UA_ByteString *signingKey,
                const UA_ByteString *encryptingKey, const UA_ByteString *keyNonce,
                void **gContext) {
    if ((signingKey && signingKey->length != SIGNING_KEY_LENGTH) ||
        (encryptingKey && encryptingKey->length != enc_len(policy)) ||
        (keyNonce && keyNonce->length != KEYNONCE_LENGTH))
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    GroupContext *gc = (GroupContext *)UA_calloc(1, sizeof(GroupContext));
    if (!gc)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    gc->encryptingKeyLength = enc_len(policy);
    if (signingKey)    memcpy(gc->signingKey, signingKey->data, signingKey->length);
    if (encryptingKey) memcpy(gc->encryptingKey, encryptingKey->data, encryptingKey->length);
    if (keyNonce)      memcpy(gc->keyNonce, keyNonce->data, keyNonce->length);
    *gContext = gc;
    return UA_STATUSCODE_GOOD;
}

static void
delete_context_ctr(UA_PubSubSecurityPolicy *policy, void *gContext) {
    (void)policy;
    if (gContext) {
        OPENSSL_cleanse(gContext, sizeof(GroupContext));
        UA_free(gContext);
    }
}

static UA_StatusCode
set_keys_ctr(UA_PubSubSecurityPolicy *policy, void *gContext,
             const UA_ByteString *signingKey, const UA_ByteString *encryptingKey,
             const UA_ByteString *keyNonce) {
    if (!gContext)
        return UA_STATUSCODE_BADINTERNALERROR;
    if (!keys_valid(policy, signingKey, encryptingKey, keyNonce))
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    GroupContext *gc = (GroupContext *)gContext;
    memcpy(gc->signingKey, signingKey->data, SIGNING_KEY_LENGTH);
    memcpy(gc->encryptingKey, encryptingKey->data, encryptingKey->length);
    memcpy(gc->keyNonce, keyNonce->data, KEYNONCE_LENGTH);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
set_message_nonce_ctr(UA_PubSubSecurityPolicy *policy, void *gContext,
                      const UA_ByteString *nonce) {
    (void)policy;
    if (!gContext || !nonce || nonce->length != MESSAGENONCE_LENGTH)
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    memcpy(((GroupContext *)gContext)->messageNonce, nonce->data, MESSAGENONCE_LENGTH);
    return UA_STATUSCODE_GOOD;
}

static void clear_ctr(UA_PubSubSecurityPolicy *policy) {
    if (!policy || !policy->policyContext)
        return;
    UA_free(policy->policyContext);
    policy->policyContext = NULL;
}

static UA_StatusCode
init_ctr(UA_PubSubSecurityPolicy *sp, const UA_Logger *logger, const char *uri,
         size_t encryptingKeyLength) {
    memset(sp, 0, sizeof(*sp));
    PolicyContext *pc = (PolicyContext *)UA_calloc(1, sizeof(PolicyContext));
    if (!pc)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    pc->encryptingKeyLength = encryptingKeyLength;
    sp->policyContext = pc;
    sp->logger = logger;
    sp->policyUri = UA_STRING((char *)(uintptr_t)uri); /* static, never freed */
    sp->newGroupContext = new_context_ctr;
    sp->deleteGroupContext = delete_context_ctr;
    sp->verify = verify_ctr;
    sp->sign = sign_ctr;
    sp->getSignatureSize = signature_size;
    sp->getSignatureKeyLength = signing_key_length;
    sp->getEncryptionKeyLength = encrypting_key_length;
    sp->encrypt = crypt_ctr;
    sp->decrypt = crypt_ctr;
    sp->setSecurityKeys = set_keys_ctr;
    sp->generateKey = generate_key_ctr;
    sp->generateNonce = generate_nonce_ctr;
    sp->nonceLength = SIGNING_KEY_LENGTH + encryptingKeyLength + KEYNONCE_LENGTH;
    sp->setMessageNonce = set_message_nonce_ctr;
    sp->clear = clear_ctr;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
adapter_PubSubSecurityPolicy_Aes128Ctr(UA_PubSubSecurityPolicy *sp, const UA_Logger *logger) {
    return init_ctr(sp, logger, PUBSUB_POLICY_AES128CTR, 16);
}

UA_StatusCode
adapter_PubSubSecurityPolicy_Aes256Ctr(UA_PubSubSecurityPolicy *sp, const UA_Logger *logger) {
    return init_ctr(sp, logger, PUBSUB_POLICY_AES256CTR, 32);
}

UA_StatusCode
adapter_pubsub_install_security_policies(UA_ServerConfig *cfg) {
    UA_PubSubSecurityPolicy *pols =
        (UA_PubSubSecurityPolicy *)UA_calloc(2, sizeof(UA_PubSubSecurityPolicy));
    if (!pols)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    UA_StatusCode sc = adapter_PubSubSecurityPolicy_Aes128Ctr(&pols[0], cfg->logging);
    if (sc == UA_STATUSCODE_GOOD)
        sc = adapter_PubSubSecurityPolicy_Aes256Ctr(&pols[1], cfg->logging);
    if (sc != UA_STATUSCODE_GOOD) {
        clear_ctr(&pols[0]);
        clear_ctr(&pols[1]);
        UA_free(pols);
        return sc;
    }
    /* Replace whatever the default config installed (nothing on OpenSSL). */
    if (cfg->pubSubConfig.securityPolicies) {
        for (size_t i = 0; i < cfg->pubSubConfig.securityPoliciesSize; i++)
            if (cfg->pubSubConfig.securityPolicies[i].clear)
                cfg->pubSubConfig.securityPolicies[i].clear(
                    &cfg->pubSubConfig.securityPolicies[i]);
        UA_free(cfg->pubSubConfig.securityPolicies);
    }
    cfg->pubSubConfig.securityPolicies = pols;
    cfg->pubSubConfig.securityPoliciesSize = 2;
    return UA_STATUSCODE_GOOD;
}

UA_PubSubSecurityPolicy *
adapter_pubsub_find_policy(UA_ServerConfig *cfg, const char *uri) {
    UA_String u = UA_STRING((char *)(uintptr_t)uri);
    for (size_t i = 0; i < cfg->pubSubConfig.securityPoliciesSize; i++)
        if (UA_String_equal(&cfg->pubSubConfig.securityPolicies[i].policyUri, &u))
            return &cfg->pubSubConfig.securityPolicies[i];
    return NULL;
}
