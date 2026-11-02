// SPDX-License-Identifier: MIT

import assert from "node:assert/strict";
import * as fs from "node:fs";
import { test } from "node:test";

import { capabilitiesDocument, stackVersion } from "./capabilities.js";
import { capabilityProblems } from "./selftest.js";

test("print-capabilities declares what is not provided as such", () => {
    const c = capabilitiesDocument();
    assert.equal(c.adapter.name, "node-opcua");
    assert.ok(!c.clientOperations.includes("codec"), "no codec operation");
    assert.ok(c.clientOperations.includes("find-servers-on-network"));
    assert.equal(c.pubsub.supported, false);
    assert.equal((c as Record<string, unknown>).codec, undefined);
    const features = [...c.clientFeatures, ...c.serverFeatures];
    for (const f of ["ecc-security", "ecc-user-token", "pubsub", "codec-json", "codec-xml", "node-management"]) {
        assert.ok(!features.includes(f), `${f} must not be declared`);
    }
    for (const p of c.securityProfiles) assert.ok(!p.policy.startsWith("ECC_"), p.policy);
    assert.ok(!c.serverServices.includes("AddNodes"), "the node-opcua server answers AddNodes with BadServiceUnsupported");
});

test("print-capabilities matches the dispatched client operations and the policies", () => {
    assert.deepEqual(capabilityProblems(), []);
});

test("the stack version is the exact pin of package.json", () => {
    const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.match(pkg.dependencies["node-opcua"], /^\d+\.\d+\.\d+$/, "node-opcua is pinned exactly");
    assert.equal(stackVersion(), pkg.dependencies["node-opcua"]);
    assert.equal(capabilitiesDocument().adapter.version, pkg.version);
    // node-opcua-types (imported directly) is the release node-opcua itself uses.
    const stack = JSON.parse(fs.readFileSync(new URL("../node_modules/node-opcua/package.json", import.meta.url), "utf8"));
    assert.equal(pkg.dependencies["node-opcua-types"], stack.dependencies["node-opcua-types"]);
});
