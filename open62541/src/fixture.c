#include "fixture.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* UA_ACCESSLEVELMASK bit values (matching open62541 defines) */
#define AL_CURRENT_READ    0x01u
#define AL_CURRENT_WRITE   0x02u
#define AL_HISTORY_READ    0x04u
#define AL_HISTORY_WRITE   0x10u
#define AL_SEMANTIC_CHANGE 0x40u
#define AL_STATUS_WRITE    0x20u
#define AL_TIMESTAMP_WRITE 0x80u

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

static char *str_dup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char  *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

static char *json_str_dup(const cJSON *obj, const char *key) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item)) return NULL;
    return str_dup(item->valuestring);
}

static int json_int(const cJSON *obj, const char *key, int fallback) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return fallback;
    return (int)item->valuedouble;
}

static double json_double(const cJSON *obj, const char *key, double fallback) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return fallback;
    return item->valuedouble;
}

static uint8_t parse_access_level(const cJSON *arr) {
    uint8_t mask = 0;
    if (!arr || !cJSON_IsArray(arr)) return AL_CURRENT_READ;
    cJSON *el;
    cJSON_ArrayForEach(el, arr) {
        if (!cJSON_IsString(el)) continue;
        const char *s = el->valuestring;
        if (strcmp(s, "CurrentRead")    == 0) mask |= AL_CURRENT_READ;
        else if (strcmp(s, "CurrentWrite")   == 0) mask |= AL_CURRENT_WRITE;
        else if (strcmp(s, "HistoryRead")    == 0) mask |= AL_HISTORY_READ;
        else if (strcmp(s, "HistoryWrite")   == 0) mask |= AL_HISTORY_WRITE;
        else if (strcmp(s, "SemanticChange") == 0) mask |= AL_SEMANTIC_CHANGE;
        else if (strcmp(s, "StatusWrite")    == 0) mask |= AL_STATUS_WRITE;
        else if (strcmp(s, "TimestampWrite") == 0) mask |= AL_TIMESTAMP_WRITE;
    }
    return mask;
}

static NodeClass parse_node_class(const char *s) {
    if (!s) return NODE_OBJECT;
    if (strcmp(s, "Variable") == 0) return NODE_VARIABLE;
    if (strcmp(s, "Method")   == 0) return NODE_METHOD;
    return NODE_OBJECT;
}

static BehaviorKind parse_behavior_kind(const char *s) {
    if (!s) return BEH_STATIC;
    if (strcmp(s, "counter")         == 0) return BEH_COUNTER;
    if (strcmp(s, "toggle")          == 0) return BEH_TOGGLE;
    if (strcmp(s, "ramp")            == 0) return BEH_RAMP;
    if (strcmp(s, "static")          == 0) return BEH_STATIC;
    if (strcmp(s, "timestamp")       == 0) return BEH_TIMESTAMP;
    if (strcmp(s, "status-sequence") == 0) return BEH_STATUS_SEQUENCE;
    return BEH_STATIC;
}

static int parse_arguments(const cJSON *arr, Argument **out, size_t *count,
                            char *errBuf, size_t errLen) {
    *out   = NULL;
    *count = 0;
    if (!arr || !cJSON_IsArray(arr)) return 0;

    size_t n = (size_t)cJSON_GetArraySize(arr);
    if (n == 0) return 0;

    Argument *args = calloc(n, sizeof(Argument));
    if (!args) {
        snprintf(errBuf, errLen, "out of memory allocating arguments");
        return -1;
    }

    size_t i = 0;
    cJSON *el;
    cJSON_ArrayForEach(el, arr) {
        args[i].name        = json_str_dup(el, "name");
        args[i].dataType    = json_str_dup(el, "dataType");
        args[i].valueRank   = json_int(el, "valueRank", -1);
        args[i].description = json_str_dup(el, "description");
        i++;
    }

    *out   = args;
    *count = n;
    return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

Fixture *fixture_load(const char *path, char *errBuf, size_t errLen) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        snprintf(errBuf, errLen, "cannot open fixture '%s': %s",
                 path, strerror(errno));
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);
    if (len <= 0) {
        snprintf(errBuf, errLen, "fixture file '%s' is empty or unreadable", path);
        fclose(fp);
        return NULL;
    }

    char *buf = malloc((size_t)len + 1);
    if (!buf) {
        snprintf(errBuf, errLen, "out of memory reading fixture '%s'", path);
        fclose(fp);
        return NULL;
    }
    size_t nread = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    buf[nread] = '\0';

    const char *parse_err = NULL;
    cJSON *root = cJSON_ParseWithOpts(buf, &parse_err, 0);
    if (!root) {
        /* parse_err points into buf — copy context before freeing */
        char ctx[96] = "(unknown)";
        if (parse_err) {
            snprintf(ctx, sizeof(ctx), "%.80s", parse_err);
        }
        free(buf);
        snprintf(errBuf, errLen, "JSON parse error in '%s' near: %s", path, ctx);
        return NULL;
    }
    free(buf);

    Fixture *f = calloc(1, sizeof(Fixture));
    if (!f) {
        snprintf(errBuf, errLen, "out of memory");
        cJSON_Delete(root);
        return NULL;
    }

    /* Top-level scalar fields */
    f->schemaVersion = json_str_dup(root, "schemaVersion");
    f->id            = json_str_dup(root, "id");
    f->description   = json_str_dup(root, "description");

    /* server metadata */
    cJSON *srv = cJSON_GetObjectItemCaseSensitive(root, "server");
    if (srv) {
        f->applicationUri  = json_str_dup(srv, "applicationUri");
        f->productUri      = json_str_dup(srv, "productUri");
        f->applicationName = json_str_dup(srv, "applicationName");
    }

    /* endpoint */
    cJSON *ep = cJSON_GetObjectItemCaseSensitive(root, "endpoint");
    if (ep) {
        f->port         = json_int(ep, "port", 4840);
        f->endpointPath = json_str_dup(ep, "path");
    }

    /* namespaces */
    cJSON *ns_arr = cJSON_GetObjectItemCaseSensitive(root, "namespaces");
    if (ns_arr && cJSON_IsArray(ns_arr)) {
        size_t n = (size_t)cJSON_GetArraySize(ns_arr);
        f->namespaces = calloc(n, sizeof(Namespace));
        if (!f->namespaces && n > 0) {
            snprintf(errBuf, errLen, "out of memory");
            cJSON_Delete(root);
            fixture_free(f);
            return NULL;
        }
        cJSON *el;
        cJSON_ArrayForEach(el, ns_arr) {
            f->namespaces[f->namespaceCount].alias = json_str_dup(el, "alias");
            f->namespaces[f->namespaceCount].uri   = json_str_dup(el, "uri");
            f->namespaceCount++;
        }
    }

    /* nodes */
    cJSON *nodes_arr = cJSON_GetObjectItemCaseSensitive(root, "nodes");
    if (nodes_arr && cJSON_IsArray(nodes_arr)) {
        size_t n = (size_t)cJSON_GetArraySize(nodes_arr);
        f->nodes = calloc(n, sizeof(FixtureNode));
        if (!f->nodes && n > 0) {
            snprintf(errBuf, errLen, "out of memory");
            cJSON_Delete(root);
            fixture_free(f);
            return NULL;
        }
        cJSON *el;
        cJSON_ArrayForEach(el, nodes_arr) {
            FixtureNode *nd = &f->nodes[f->nodeCount];

            char *nc_str = json_str_dup(el, "nodeClass");
            nd->nodeClass      = parse_node_class(nc_str);
            free(nc_str);

            nd->nodeId        = json_str_dup(el, "nodeId");
            nd->browseName    = json_str_dup(el, "browseName");
            nd->displayName   = json_str_dup(el, "displayName");
            nd->description   = json_str_dup(el, "description");
            nd->parentNodeId  = json_str_dup(el, "parentNodeId");
            nd->referenceType = json_str_dup(el, "referenceType");
            nd->typeDefinition = json_str_dup(el, "typeDefinition");

            if (nd->nodeClass == NODE_VARIABLE) {
                nd->dataType   = json_str_dup(el, "dataType");
                nd->valueRank  = json_int(el, "valueRank", -1);
                cJSON *ad = cJSON_GetObjectItemCaseSensitive(el, "arrayDimensions");
                if (ad && cJSON_IsArray(ad)) {
                    size_t adN = (size_t)cJSON_GetArraySize(ad);
                    nd->arrayDimensions = calloc(adN, sizeof(uint32_t));
                    if (!nd->arrayDimensions && adN > 0) {
                        snprintf(errBuf, errLen,
                                 "out of memory for arrayDimensions of '%s'",
                                 nd->nodeId ? nd->nodeId : "(unknown)");
                        cJSON_Delete(root);
                        fixture_free(f);
                        return NULL;
                    }
                    cJSON *dim;
                    size_t di = 0;
                    cJSON_ArrayForEach(dim, ad) {
                        if (!cJSON_IsNumber(dim) ||
                            dim->valuedouble < 0 ||
                            dim->valuedouble > UINT32_MAX ||
                            floor(dim->valuedouble) != dim->valuedouble) {
                            snprintf(errBuf, errLen,
                                     "invalid arrayDimensions entry at index %zu "
                                     "for node '%s'",
                                     di, nd->nodeId ? nd->nodeId : "(unknown)");
                            cJSON_Delete(root);
                            fixture_free(f);
                            return NULL;
                        }
                        nd->arrayDimensions[di++] = (uint32_t)dim->valuedouble;
                    }
                    nd->arrayDimensionsSize = adN;
                }
                cJSON *al = cJSON_GetObjectItemCaseSensitive(el, "accessLevel");
                nd->accessLevel = parse_access_level(al);
                /* Keep a reference into the cJSON tree for initialValue; the
                 * cJSON root is NOT deleted until fixture_free is called.
                 * We detach the item so it survives independent of root. */
                cJSON *iv = cJSON_DetachItemFromObjectCaseSensitive(el, "initialValue");
                nd->initialValue = iv; /* may be NULL */
            }

            if (nd->nodeClass == NODE_METHOD) {
                nd->methodBehavior = json_str_dup(el, "methodBehavior");
                cJSON *ia = cJSON_GetObjectItemCaseSensitive(el, "inputArguments");
                cJSON *oa = cJSON_GetObjectItemCaseSensitive(el, "outputArguments");
                if (parse_arguments(ia, &nd->inputArgs,  &nd->inputArgCount,
                                    errBuf, errLen) != 0 ||
                    parse_arguments(oa, &nd->outputArgs, &nd->outputArgCount,
                                    errBuf, errLen) != 0) {
                    cJSON_Delete(root);
                    fixture_free(f);
                    return NULL;
                }
            }

            f->nodeCount++;
        }
    }

    /* behaviors */
    cJSON *beh_arr = cJSON_GetObjectItemCaseSensitive(root, "behaviors");
    if (beh_arr && cJSON_IsArray(beh_arr)) {
        size_t n = (size_t)cJSON_GetArraySize(beh_arr);
        f->behaviors = calloc(n, sizeof(Behavior));
        if (!f->behaviors && n > 0) {
            snprintf(errBuf, errLen, "out of memory");
            cJSON_Delete(root);
            fixture_free(f);
            return NULL;
        }
        cJSON *el;
        cJSON_ArrayForEach(el, beh_arr) {
            Behavior *b = &f->behaviors[f->behaviorCount];

            b->target  = json_str_dup(el, "target");
            char *k    = json_str_dup(el, "kind");
            b->kind    = parse_behavior_kind(k);
            free(k);

            b->initial    = json_double(el, "initial",    0.0);
            b->increment  = json_double(el, "increment",  1.0);
            b->minimum    = json_double(el, "minimum",    0.0);
            b->maximum    = json_double(el, "maximum",    100.0);
            b->intervalMs = json_int(el,    "intervalMs", 250);

            f->behaviorCount++;
        }
    }

    /* securityProfiles */
    cJSON *sec_arr = cJSON_GetObjectItemCaseSensitive(root, "securityProfiles");
    if (sec_arr && cJSON_IsArray(sec_arr)) {
        size_t n = (size_t)cJSON_GetArraySize(sec_arr);
        if (n > 0) {
            f->securityProfiles = calloc(n, sizeof(SecurityProfile));
            if (!f->securityProfiles) {
                snprintf(errBuf, errLen, "out of memory");
                cJSON_Delete(root);
                fixture_free(f);
                return NULL;
            }
            cJSON *el;
            cJSON_ArrayForEach(el, sec_arr) {
                SecurityProfile *sp = &f->securityProfiles[f->securityProfileCount];
                sp->policy = json_str_dup(el, "securityPolicy");
                sp->mode   = json_str_dup(el, "securityMode");
                f->securityProfileCount++;
            }
        }
    }

    /* users */
    cJSON *users_arr = cJSON_GetObjectItemCaseSensitive(root, "users");
    if (users_arr && cJSON_IsArray(users_arr)) {
        size_t n = (size_t)cJSON_GetArraySize(users_arr);
        if (n > 0) {
            f->users = calloc(n, sizeof(UserCredential));
            if (!f->users) {
                snprintf(errBuf, errLen, "out of memory");
                cJSON_Delete(root);
                fixture_free(f);
                return NULL;
            }
            cJSON *el;
            cJSON_ArrayForEach(el, users_arr) {
                UserCredential *u = &f->users[f->userCount];
                u->username = json_str_dup(el, "username");
                u->password = json_str_dup(el, "password");
                f->userCount++;
            }
        }
    }

    cJSON_Delete(root);
    return f;
}

void fixture_free(Fixture *f) {
    if (!f) return;

    free(f->schemaVersion);
    free(f->id);
    free(f->description);
    free(f->applicationUri);
    free(f->productUri);
    free(f->applicationName);
    free(f->endpointPath);

    for (size_t i = 0; i < f->namespaceCount; i++) {
        free(f->namespaces[i].alias);
        free(f->namespaces[i].uri);
    }
    free(f->namespaces);

    for (size_t i = 0; i < f->nodeCount; i++) {
        FixtureNode *nd = &f->nodes[i];
        free(nd->nodeId);
        free(nd->browseName);
        free(nd->displayName);
        free(nd->description);
        free(nd->parentNodeId);
        free(nd->referenceType);
        free(nd->typeDefinition);
        free(nd->dataType);
        free(nd->arrayDimensions);
        cJSON_Delete(nd->initialValue);
        free(nd->methodBehavior);
        for (size_t j = 0; j < nd->inputArgCount; j++) {
            free(nd->inputArgs[j].name);
            free(nd->inputArgs[j].dataType);
            free(nd->inputArgs[j].description);
        }
        free(nd->inputArgs);
        for (size_t j = 0; j < nd->outputArgCount; j++) {
            free(nd->outputArgs[j].name);
            free(nd->outputArgs[j].dataType);
            free(nd->outputArgs[j].description);
        }
        free(nd->outputArgs);
    }
    free(f->nodes);

    for (size_t i = 0; i < f->behaviorCount; i++) {
        free(f->behaviors[i].target);
    }
    free(f->behaviors);

    for (size_t i = 0; i < f->securityProfileCount; i++) {
        free(f->securityProfiles[i].policy);
        free(f->securityProfiles[i].mode);
    }
    free(f->securityProfiles);

    for (size_t i = 0; i < f->userCount; i++) {
        free(f->users[i].username);
        free(f->users[i].password);
    }
    free(f->users);

    free(f);
}
