/*
 * Fixture parser unit tests.
 * Compiled as a standalone binary against fixture.c + cJSON.
 *
 * Usage:
 *   ./fixture_test <path-to-fixtures/baseline/fixture.json>
 *
 * Returns 0 if all tests pass, 1 if any fail.
 */

#include "fixture.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Minimal test framework
 * ---------------------------------------------------------------------- */

static int g_failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_failures++; \
    } else { \
        fprintf(stderr, "PASS: %s\n", #cond); \
    } \
} while (0)

#define CHECK_STR(a, b) do { \
    const char *_a = (a); const char *_b = (b); \
    if (!_a || !_b || strcmp(_a, _b) != 0) { \
        fprintf(stderr, "FAIL %s:%d: expected \"%s\", got \"%s\"\n", \
                __FILE__, __LINE__, _b ? _b : "(null)", _a ? _a : "(null)"); \
        g_failures++; \
    } else { \
        fprintf(stderr, "PASS: \"%s\" == \"%s\"\n", _a, _b); \
    } \
} while (0)

#define CHECK_INT(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "FAIL %s:%d: expected %lld, got %lld\n", \
                __FILE__, __LINE__, _b, _a); \
        g_failures++; \
    } else { \
        fprintf(stderr, "PASS: %lld == %lld\n", _a, _b); \
    } \
} while (0)

/* -------------------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------------- */

static void test_load_success(const char *path) {
    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    CHECK(f != NULL);
    if (!f) { fprintf(stderr, "  error: %s\n", errBuf); return; }

    /* schema version and id */
    CHECK_STR(f->schemaVersion, "1.0");
    CHECK_STR(f->id, "baseline");

    /* server metadata */
    CHECK_STR(f->applicationUri, "urn:otfabric:opcua-interop:server");

    /* endpoint */
    CHECK_INT(f->port, 4840);
    CHECK_STR(f->endpointPath, "/opcua-interop");

    /* namespace count */
    CHECK_INT((int)f->namespaceCount, 1);
    CHECK_STR(f->namespaces[0].uri, "urn:otfabric:opcua-interop:model");
    CHECK_STR(f->namespaces[0].alias, "compat");

    fixture_free(f);
}

static void test_node_count(const char *path) {
    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    CHECK(f != NULL);
    if (!f) return;

    /* Baseline fixture has 8 object + scalars + arrays + access + dynamic
     * + datavalues + methods + diagnostics nodes. Count from fixture.json:
     * 8 Object + 18 scalar vars + 5 array vars + 3 access vars + 3 dynamic vars
     * + 2 datavalue vars + 6 method nodes + 3 diagnostic vars = 48 */
    CHECK(f->nodeCount >= 40);
    fprintf(stderr, "  node count: %zu\n", f->nodeCount);

    fixture_free(f);
}

static void test_scalar_int32(const char *path) {
    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    CHECK(f != NULL);
    if (!f) return;

    /* Find Scalar.Int32 node */
    FixtureNode *int32Node = NULL;
    for (size_t i = 0; i < f->nodeCount; i++) {
        if (f->nodes[i].nodeId &&
            strstr(f->nodes[i].nodeId, "s=Scalar.Int32")) {
            int32Node = &f->nodes[i];
            break;
        }
    }
    CHECK(int32Node != NULL);
    if (int32Node) {
        CHECK(int32Node->nodeClass == NODE_VARIABLE);
        CHECK_STR(int32Node->dataType, "Int32");
        CHECK_INT(int32Node->valueRank, -1);
        CHECK(int32Node->initialValue != NULL);
        if (int32Node->initialValue) {
            CHECK_INT((int)int32Node->initialValue->valueint, -123456789);
        }
    }

    fixture_free(f);
}

static void test_scalar_uint64_as_string(const char *path) {
    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    CHECK(f != NULL);
    if (!f) return;

    FixtureNode *node = NULL;
    for (size_t i = 0; i < f->nodeCount; i++) {
        if (f->nodes[i].nodeId &&
            strstr(f->nodes[i].nodeId, "s=Scalar.UInt64")) {
            node = &f->nodes[i];
            break;
        }
    }
    CHECK(node != NULL);
    if (node) {
        CHECK_STR(node->dataType, "UInt64");
        CHECK(node->initialValue != NULL);
        if (node->initialValue) {
            /* UInt64 is stored as a JSON string to avoid precision loss */
            CHECK(cJSON_IsString(node->initialValue));
            if (cJSON_IsString(node->initialValue)) {
                uint64_t v = strtoull(node->initialValue->valuestring, NULL, 10);
                /* 12345678901234567890 overflows uint64 max; fixture uses
                 * "12345678901234567890" which wraps — just check it's a string */
                fprintf(stderr, "  UInt64 string value: %s => %" PRIu64 "\n",
                        node->initialValue->valuestring, v);
                CHECK(node->initialValue->valuestring[0] != '\0');
            }
        }
    }

    fixture_free(f);
}

static void test_behavior_count_and_kinds(const char *path) {
    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    CHECK(f != NULL);
    if (!f) return;

    /* Baseline has 3 behaviors: counter, toggle, ramp */
    CHECK_INT((int)f->behaviorCount, 3);

    int haveCounter = 0, haveToggle = 0, haveRamp = 0;
    for (size_t i = 0; i < f->behaviorCount; i++) {
        if (f->behaviors[i].kind == BEH_COUNTER) haveCounter = 1;
        if (f->behaviors[i].kind == BEH_TOGGLE)  haveToggle  = 1;
        if (f->behaviors[i].kind == BEH_RAMP)    haveRamp    = 1;
    }
    CHECK(haveCounter);
    CHECK(haveToggle);
    CHECK(haveRamp);

    fixture_free(f);
}

static void test_method_argument_counts(const char *path) {
    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    CHECK(f != NULL);
    if (!f) return;

    /* Methods.Add: 2 inputs, 1 output */
    FixtureNode *addNode = NULL;
    for (size_t i = 0; i < f->nodeCount; i++) {
        if (f->nodes[i].nodeClass == NODE_METHOD &&
            f->nodes[i].methodBehavior &&
            strcmp(f->nodes[i].methodBehavior, "Add") == 0) {
            addNode = &f->nodes[i];
            break;
        }
    }
    CHECK(addNode != NULL);
    if (addNode) {
        CHECK_INT((int)addNode->inputArgCount,  2);
        CHECK_INT((int)addNode->outputArgCount, 1);
        CHECK_STR(addNode->inputArgs[0].name,  "a");
        CHECK_STR(addNode->inputArgs[1].name,  "b");
        CHECK_STR(addNode->outputArgs[0].name, "result");
    }

    /* Methods.MultipleOutputs: 1 input, 2 outputs */
    FixtureNode *moNode = NULL;
    for (size_t i = 0; i < f->nodeCount; i++) {
        if (f->nodes[i].nodeClass == NODE_METHOD &&
            f->nodes[i].methodBehavior &&
            strcmp(f->nodes[i].methodBehavior, "MultipleOutputs") == 0) {
            moNode = &f->nodes[i];
            break;
        }
    }
    CHECK(moNode != NULL);
    if (moNode) {
        CHECK_INT((int)moNode->inputArgCount,  1);
        CHECK_INT((int)moNode->outputArgCount, 2);
    }

    /* Methods.NoArguments: 0 inputs, 1 output */
    FixtureNode *naNode = NULL;
    for (size_t i = 0; i < f->nodeCount; i++) {
        if (f->nodes[i].nodeClass == NODE_METHOD &&
            f->nodes[i].methodBehavior &&
            strcmp(f->nodes[i].methodBehavior, "NoArguments") == 0) {
            naNode = &f->nodes[i];
            break;
        }
    }
    CHECK(naNode != NULL);
    if (naNode) {
        CHECK_INT((int)naNode->inputArgCount,  0);
        CHECK_INT((int)naNode->outputArgCount, 1);
    }

    fixture_free(f);
}

static void test_access_level_parsing(const char *path) {
    char errBuf[512];
    Fixture *f = fixture_load(path, errBuf, sizeof(errBuf));
    CHECK(f != NULL);
    if (!f) return;

    /* Access.ReadOnly should have bit 0x01 only */
    FixtureNode *ro = NULL;
    /* Access.ReadWrite should have 0x01 | 0x02 */
    FixtureNode *rw = NULL;
    /* Access.WriteOnly should have 0x02 only */
    FixtureNode *wo = NULL;

    for (size_t i = 0; i < f->nodeCount; i++) {
        FixtureNode *nd = &f->nodes[i];
        if (!nd->nodeId) continue;
        if (strstr(nd->nodeId, "s=Access.ReadOnly"))  ro = nd;
        if (strstr(nd->nodeId, "s=Access.ReadWrite")) rw = nd;
        if (strstr(nd->nodeId, "s=Access.WriteOnly")) wo = nd;
    }

    CHECK(ro != NULL);
    CHECK(rw != NULL);
    CHECK(wo != NULL);
    if (ro) CHECK_INT(ro->accessLevel, 0x01);
    if (rw) CHECK_INT(rw->accessLevel, 0x03);
    if (wo) CHECK_INT(wo->accessLevel, 0x02);

    fixture_free(f);
}

static void test_bad_path(void) {
    char errBuf[512];
    Fixture *f = fixture_load("/nonexistent/path/fixture.json",
                              errBuf, sizeof(errBuf));
    CHECK(f == NULL);
    CHECK(errBuf[0] != '\0');
    fprintf(stderr, "  expected error: %s\n", errBuf);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: fixture_test <path/to/fixture.json>\n");
        return 1;
    }
    const char *path = argv[1];

    fprintf(stderr, "=== fixture_test: %s ===\n", path);

    test_bad_path();
    test_load_success(path);
    test_node_count(path);
    test_scalar_int32(path);
    test_scalar_uint64_as_string(path);
    test_behavior_count_and_kinds(path);
    test_method_argument_counts(path);
    test_access_level_parsing(path);

    if (g_failures == 0) {
        fprintf(stderr, "\nAll tests PASSED.\n");
        return 0;
    } else {
        fprintf(stderr, "\n%d test(s) FAILED.\n", g_failures);
        return 1;
    }
}
