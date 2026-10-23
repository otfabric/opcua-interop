#pragma once

#include <stddef.h>

#include <open62541.h>

/*
 * OPC UA PubSub (Part 14) for the server mode.
 *
 *   pubsub_server_prepare_config  before UA_Server_newWithConfig: installs the
 *                                 PubSub-Aes128-CTR / PubSub-Aes256-CTR
 *                                 message security policies (OpenSSL).
 *   pubsub_server_init            after the server exists (always): adapter
 *                                 callbacks for AddSecurityGroup /
 *                                 RemoveSecurityGroup, SupportedTransportProfiles.
 *   pubsub_server_apply           --pubsub-config <file>: build the
 *                                 configuration through the open62541 API and
 *                                 enable it. Runs after UA_Server_run_startup.
 *
 * The file format is documented in docs/CLIENT_CONTRACT.md §14 and README.md.
 */

typedef struct {
    const char *configPath;  /* --pubsub-config */
    const char *certFile;    /* --certificate (SKS client identity) */
    const char *keyFile;     /* --private-key */
    const char *pkiDir;      /* --pki-dir (trust list of the SKS client) */
} PubSubOptions;

UA_StatusCode pubsub_server_prepare_config(UA_ServerConfig *cfg);

UA_StatusCode pubsub_server_init(UA_Server *server);

/* Returns 0 on success; on failure fills errBuf and returns non-zero. */
int pubsub_server_apply(UA_Server *server, const PubSubOptions *opt,
                        char *errBuf, size_t errLen);

/* Release what pubsub_server_apply kept for the lifetime of the server. */
void pubsub_server_cleanup(void);

/*
 * Normalise OPC UA 1.05 JSON ExtensionObjects for open62541's decoder (shared
 * with the codec): an object with "UaTypeId" and the structure fields in-situ
 * (the 1.05 compact form, which open62541 v1.5.9 encodes but cannot decode) is
 * rewritten to {"UaTypeId":…,"UaBody":{fields}}; a UaTypeId that names a
 * DataTypeEncoding (DefaultBinary / DefaultXml / DefaultJson) is replaced by
 * the DataType NodeId. Returns a malloc'd JSON text, or NULL on parse error.
 */
char *pubsub_normalize_json(const char *json, size_t len);

/* Decode an OPC UA JSON document into `type`, resolving nsu= NodeIds against
 * `namespaceUris` (may be NULL). Applies pubsub_normalize_json first. */
UA_StatusCode pubsub_decode_json(const char *json, size_t len, void *dst,
                                 const UA_DataType *type,
                                 const UA_String *namespaceUris, size_t nsCount);
