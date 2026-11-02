// SPDX-License-Identifier: MIT
//
// PKI helpers and the fixture address space (what `test` checks at runtime).

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";

import { Fixture } from "./fixture.js";
import { certificateUri, fixtureProblems, readCertificateDer, toPemFiles } from "./server.js";

const pki = (name: string) => fileURLToPathSafe(new URL(`../testdata/pki/${name}`, import.meta.url));
function fileURLToPathSafe(u: URL): string {
    return decodeURIComponent(u.pathname);
}

test("readCertificateDer: PEM and DER files give the same DER", () => {
    const fromPem = readCertificateDer(pki("leaf.crt"));
    const fromDer = readCertificateDer(pki("leaf.der"));
    assert.deepEqual(fromPem, fromDer);
    assert.equal(fromDer[0], 0x30, "DER SEQUENCE");
});

test("certificateUri: the URI SAN is the ApplicationUri", () => {
    assert.equal(certificateUri(readCertificateDer(pki("leaf.crt"))), "urn:otfabric:opcua-interop:test:leaf");
    assert.equal(certificateUri(readCertificateDer(pki("ca.crt"))), undefined);
});

test("toPemFiles: DER certificate and PKCS#1 / PKCS#8 keys become PEM node-opcua reads", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pem-test-"));
    try {
        const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
        const pkcs1 = path.join(dir, "k1.pem");
        fs.writeFileSync(pkcs1, privateKey.export({ format: "pem", type: "pkcs1" }));
        const der = path.join(dir, "k8.der");
        fs.writeFileSync(der, privateKey.export({ format: "der", type: "pkcs8" }));
        for (const key of [pkcs1, der]) {
            const out = toPemFiles(pki("leaf.der"), key, path.join(dir, `out-${path.basename(key)}`));
            assert.match(fs.readFileSync(out.cert, "utf8"), /^-----BEGIN CERTIFICATE-----\n/);
            assert.match(fs.readFileSync(out.key, "utf8"), /^-----BEGIN PRIVATE KEY-----\n/);
            assert.deepEqual(readCertificateDer(out.cert), readCertificateDer(pki("leaf.der")));
        }
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

const NS = "urn:otfabric:opcua-interop:model";
function fixture(extra: Partial<Fixture> = {}): Fixture {
    return {
        schemaVersion: "1.0",
        id: "unit",
        server: { applicationUri: "urn:unit", productUri: "urn:unit", applicationName: "unit" },
        endpoint: { path: "/x", port: 4840 },
        namespaces: [{ alias: "m", uri: NS }],
        nodes: [
            { nodeClass: "Object", nodeId: `nsu=${NS};s=Root`, browseName: "1:Root", parentNodeId: "i=85", referenceType: "Organizes", typeDefinition: "i=61" },
            { nodeClass: "Variable", nodeId: `nsu=${NS};s=V.Int64`, browseName: "1:V.Int64", parentNodeId: `nsu=${NS};s=Root`, referenceType: "HasComponent", dataType: "Int64", valueRank: -1, initialValue: "-9223372036854775808", accessLevel: ["CurrentRead", "CurrentWrite"] },
            { nodeClass: "Variable", nodeId: `nsu=${NS};s=M`, browseName: "1:M", parentNodeId: `nsu=${NS};s=Root`, referenceType: "HasComponent", dataType: "Int32", valueRank: 2, arrayDimensions: [3, 2], initialValue: [1, 2, 3, 4, 5, 6] },
            { nodeClass: "Variable", nodeId: `nsu=${NS};s=History.Temperature`, browseName: "1:History.Temperature", parentNodeId: `nsu=${NS};s=Root`, referenceType: "HasComponent", dataType: "Double", initialValue: 20 },
            { nodeClass: "Method", nodeId: `nsu=${NS};s=Add`, browseName: "1:Add", parentNodeId: `nsu=${NS};s=Root`, referenceType: "HasComponent", methodBehavior: "Add",
              inputArguments: [{ name: "a", dataType: "Int32" }, { name: "b", dataType: "Int32" }], outputArguments: [{ name: "sum", dataType: "Int32" }] },
        ],
        behaviors: [{ target: `nsu=${NS};s=V.Int64`, kind: "counter", intervalMs: 100 }],
        securityProfiles: [{ securityPolicy: "None", securityMode: "None" }, { securityPolicy: "Basic256Sha256", securityMode: "SignAndEncrypt" }, { securityPolicy: "ECC_nistP256", securityMode: "Sign" }],
        ...extra,
    };
}

test("fixtureProblems: a fixture the server can build has none", async () => {
    assert.deepEqual(await fixtureProblems(fixture()), []);
});

test("fixtureProblems: what the server cannot build is reported", async () => {
    const f = fixture({
        behaviors: [{ target: `nsu=${NS};s=Missing`, kind: "counter" }, { target: `nsu=${NS};s=V.Int64`, kind: "sawtooth" }],
        securityProfiles: [{ securityPolicy: "Basic512", securityMode: "Sign" }],
    });
    f.nodes!.push({ nodeClass: "Method", nodeId: `nsu=${NS};s=Bogus`, browseName: "1:Bogus", parentNodeId: `nsu=${NS};s=Root`, methodBehavior: "Teleport" });
    const p = await fixtureProblems(f);
    assert.ok(p.some((x) => x.includes("Missing") && x.includes("target")), p.join("; "));
    assert.ok(p.some((x) => x.includes("unknown kind sawtooth")), p.join("; "));
    assert.ok(p.some((x) => x.includes("Basic512")), p.join("; "));
    assert.ok(p.some((x) => x.includes("Teleport")), p.join("; "));
});
