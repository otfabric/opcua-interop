#pragma once

#include <stddef.h>
#include <stdint.h>

#include <cjson/cJSON.h>

typedef enum {
    NODE_OBJECT,
    NODE_VARIABLE,
    NODE_METHOD
} NodeClass;

typedef enum {
    BEH_COUNTER,
    BEH_TOGGLE,
    BEH_RAMP,
    BEH_STATIC,
    BEH_TIMESTAMP,
    BEH_STATUS_SEQUENCE,
    BEH_FIXED_STATUS
} BehaviorKind;

typedef struct {
    char *name;
    char *dataType;
    int   valueRank;
    char *description;
} Argument;

typedef struct {
    NodeClass nodeClass;
    char     *nodeId;
    char     *browseName;
    char     *displayName;
    char     *description;
    char     *parentNodeId;
    char     *referenceType;
    char     *typeDefinition;

    /* Variable fields */
    char      *dataType;
    int        valueRank;
    uint32_t  *arrayDimensions;
    size_t     arrayDimensionsSize;
    uint8_t    accessLevel;
    cJSON     *initialValue;

    /* Method fields */
    char     *methodBehavior;
    Argument *inputArgs;
    size_t    inputArgCount;
    Argument *outputArgs;
    size_t    outputArgCount;
} FixtureNode;

typedef struct {
    char        *target;
    BehaviorKind kind;
    double       initial;
    double       increment;
    double       minimum;
    double       maximum;
    int          intervalMs;
} Behavior;

typedef struct {
    char *alias;
    char *uri;
} Namespace;

typedef struct {
    char *policy;   /* e.g. "None", "Basic256Sha256", "Aes128_Sha256_RsaOaep" */
    char *mode;     /* "None", "Sign", "SignAndEncrypt" */
} SecurityProfile;

typedef struct {
    char *username;
    char *password;
} UserCredential;

typedef struct {
    char *schemaVersion;
    char *id;
    char *description;

    /* server metadata */
    char *applicationUri;
    char *productUri;
    char *applicationName;

    /* endpoint */
    int   port;
    char *endpointPath;

    /* namespaces */
    Namespace *namespaces;
    size_t     namespaceCount;

    /* nodes */
    FixtureNode *nodes;
    size_t       nodeCount;

    /* behaviors */
    Behavior *behaviors;
    size_t    behaviorCount;

    /* security */
    SecurityProfile *securityProfiles;
    size_t           securityProfileCount;

    /* user credentials */
    UserCredential *users;
    size_t          userCount;
} Fixture;

/*
 * Load and parse a fixture JSON file.
 * Returns a heap-allocated Fixture on success, NULL on error (errBuf filled).
 */
Fixture *fixture_load(const char *path, char *errBuf, size_t errLen);

/*
 * Free all memory owned by a Fixture returned from fixture_load.
 */
void fixture_free(Fixture *f);
