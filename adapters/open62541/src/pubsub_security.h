#pragma once

#include <open62541.h>

/*
 * OpenSSL implementation of the PubSub message security policies
 * PubSub-Aes128-CTR and PubSub-Aes256-CTR (open62541 v1.5.9 only provides
 * them for mbedTLS). See pubsub_security.c.
 */

#define PUBSUB_POLICY_AES128CTR "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR"
#define PUBSUB_POLICY_AES256CTR "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR"

UA_StatusCode adapter_PubSubSecurityPolicy_Aes128Ctr(UA_PubSubSecurityPolicy *sp,
                                                     const UA_Logger *logger);
UA_StatusCode adapter_PubSubSecurityPolicy_Aes256Ctr(UA_PubSubSecurityPolicy *sp,
                                                     const UA_Logger *logger);

/* Install both policies as cfg->pubSubConfig.securityPolicies (owned by the
 * config, freed by the server). Call before UA_Server_newWithConfig. */
UA_StatusCode adapter_pubsub_install_security_policies(UA_ServerConfig *cfg);

/* The installed policy with this URI, or NULL. */
UA_PubSubSecurityPolicy *adapter_pubsub_find_policy(UA_ServerConfig *cfg, const char *uri);
