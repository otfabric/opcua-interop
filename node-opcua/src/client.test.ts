// SPDX-License-Identifier: MIT
//
// `client push` (the 0.15.0 flags) and `client query`: flag parsing, input
// errors before connecting, and the result of a query against a server that
// does not serve the Query service set.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";

import { AttributeIds, OPCUACertificateManager, OPCUAServer } from "node-opcua";

import { clientCommand, parseDataToReturn, privateKeyFormat, PUSH_GROUPS } from "./client.js";
import { Args, EXIT_INPUT, EXIT_SERVICE } from "./util.js";

/** Runs `client <argv>` and returns the exit code and the JSON it printed. */
async function run(argv: string[]): Promise<{ code: number; out: Record<string, unknown> }> {
    const write = process.stdout.write.bind(process.stdout);
    let buf = "";
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = (chunk: string | Uint8Array) => {
        buf += chunk.toString();
        return true;
    };
    let code: number;
    try {
        code = await clientCommand(argv);
    } finally {
        process.stdout.write = write;
    }
    return { code, out: JSON.parse(buf.trim().split("\n").pop()!) };
}

test("parseDataToReturn: Part 4 A.2 relative path, # attribute (Value by default)", () => {
    const own = parseDataToReturn("#BrowseName");
    assert.equal(own.attributeId, AttributeIds.BrowseName);
    assert.equal(own.relativePath.elements?.length ?? 0, 0);

    const prop = parseDataToReturn(".Serial");
    assert.equal(prop.attributeId, AttributeIds.Value);
    assert.equal(prop.relativePath.elements!.length, 1);
    assert.equal(prop.relativePath.elements![0].referenceTypeId.toString(), "ns=0;i=44"); // Aggregates
    assert.equal(prop.relativePath.elements![0].targetName.name, "Serial");

    const deep = parseDataToReturn("/2:Folder.Var#DisplayName");
    assert.equal(deep.attributeId, AttributeIds.DisplayName);
    assert.equal(deep.relativePath.elements!.length, 2);
    assert.equal(deep.relativePath.elements![0].referenceTypeId.toString(), "ns=0;i=33"); // HierarchicalReferences
    assert.equal(deep.relativePath.elements![0].targetName.namespaceIndex, 2);

    assert.equal(parseDataToReturn("#1").attributeId, AttributeIds.NodeId);
    assert.throws(() => parseDataToReturn("#NoSuchAttribute"), /unknown attribute/);
});

test("privateKeyFormat: --private-key-format, else by the file extension", () => {
    assert.equal(privateKeyFormat(new Args([]), "/k/key.pem"), "PEM");
    assert.equal(privateKeyFormat(new Args([]), "/k/key.PFX"), "PFX");
    assert.equal(privateKeyFormat(new Args([]), "/k/key.p12"), "PFX");
    assert.equal(privateKeyFormat(new Args(["--private-key-format", "PEM"]), "/k/key.pfx"), "PEM");
    assert.throws(() => privateKeyFormat(new Args(["--private-key-format", "DER"]), "/k/key"), /PEM or PFX/);
});

test("PUSH_GROUPS: the well-known certificate groups and their default types", () => {
    assert.deepEqual(Object.keys(PUSH_GROUPS), ["Application", "Https", "UserToken"]);
    assert.equal(PUSH_GROUPS.Application.groupId, "i=14156");
    assert.equal(PUSH_GROUPS.Https.groupId, "i=14088");
    assert.equal(PUSH_GROUPS.UserToken.groupId, "i=14122");
});

test("client push / query: bad flags are input errors before connecting", async () => {
    const ep = ["--endpoint", "opc.tcp://127.0.0.1:1"];
    for (const argv of [
        ["push", ...ep, "--group", "Bogus"],
        ["push", ...ep, "--update-private-key", "/nonexistent.pem"],
        ["push", ...ep, "--update-certificate", "/nonexistent.der"],
        ["push", ...ep, "--lifetime-days", "70000"],
        ["push", ...ep, "--delete-certificate", "not a node id"],
        ["query", ...ep],
        ["query", ...ep, "--type-definition", "i=58", "--data-to-return", "#Bogus"],
        ["query", ...ep, "--type-definition", "i=58", "--max-data-sets", "-1"],
    ]) {
        const { code, out } = await run(argv);
        assert.equal(code, EXIT_INPUT, argv.join(" "));
        assert.equal(out.success, false);
        assert.equal((out.error as { category: string }).category, "input", argv.join(" "));
    }
});

test("client query: QueryFirst refused by the server is a service failure with the result", async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-query-"));
    const server = new OPCUAServer({
        port: 0,
        serverCertificateManager: new OPCUACertificateManager({ rootFolder: path.join(work, "pki"), disableFileWatchers: true }),
    });
    try {
        await server.start();
        const url = server.getEndpointUrl().replace(/\/\/[^:/]+:/, "//127.0.0.1:");
        const { code, out } = await run(["query", "--endpoint", url, "--type-definition", "i=58", "--data-to-return", "#BrowseName", "--max-data-sets", "2"]);
        assert.equal(code, EXIT_SERVICE);
        assert.equal(out.operation, "query");
        // node-opcua 2.187.12 does not serve the Query service set.
        assert.match((out.serviceResult as { name: string }).name, /^Bad/);
        const res = (out.results as Record<string, unknown>[])[0];
        assert.equal(res.typeDefinitionNode, "i=58");
        assert.deepEqual(res.queryNext, []);
        assert.deepEqual(res.queryDataSets, []);
        assert.match(((res.queryFirst as Record<string, unknown>).statusCode as { name: string }).name, /^Bad/);
    } finally {
        await server.shutdown(0).catch(() => undefined);
        fs.rmSync(work, { recursive: true, force: true });
    }
});
