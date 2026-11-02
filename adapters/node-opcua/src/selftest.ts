// SPDX-License-Identifier: MIT
//
// `test`: the adapter's self-test inside the image.
//
// The unit tests (`node --test`, src/*.test.ts) run when the image is built;
// this command repeats the checks that depend on the runtime inputs: every
// fixture under /fixtures (or given with --fixture) is loaded and the server
// address space is built from it (node classes, data types, initial values,
// method behaviours, behaviour targets, history, security profiles), and the
// capabilities document is checked against the operations the client
// dispatches. Exit 0 when everything passes, 1 otherwise.

import * as fs from "node:fs";
import * as path from "node:path";

import { capabilitiesDocument } from "./capabilities.js";
import { OPERATIONS } from "./client.js";
import { loadFixture } from "./fixture.js";
import { fixtureProblems, POLICIES } from "./server.js";
import { log } from "./util.js";

export function findFixtures(dir: string): string[] {
    const out: string[] = [];
    let entries: fs.Dirent[];
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
        return out;
    }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
        const p = path.join(dir, e.name);
        // fixtures/schema holds the JSON Schema, not a fixture.
        if (e.isDirectory() && e.name !== "schema") out.push(...findFixtures(p));
        else if (e.isFile() && e.name === "fixture.json") out.push(p);
    }
    return out;
}

export function capabilityProblems(): string[] {
    const caps = capabilitiesDocument() as unknown as Record<string, unknown>;
    const p: string[] = [];
    for (const key of [
        "schemaVersion", "adapter", "stack", "fixtureSchemaVersions", "roles", "transports",
        "encodings", "clientOperations", "serverServices", "securityProfiles", "userTokenTypes",
    ]) {
        if (caps[key] === undefined) p.push(`print-capabilities: ${key} missing`);
    }
    const ops = caps.clientOperations as string[];
    for (const op of OPERATIONS) if (!ops.includes(op)) p.push(`print-capabilities: client operation ${op} not declared`);
    for (const op of ops) if (!OPERATIONS.includes(op)) p.push(`print-capabilities: client operation ${op} declared but not dispatched`);
    for (const sp of caps.securityProfiles as { policy: string }[]) {
        if (!POLICIES[sp.policy]) p.push(`print-capabilities: security policy ${sp.policy} is not implemented`);
    }
    return p;
}

export async function selftestCommand(argv: string[]): Promise<number> {
    const fixtures: string[] = [];
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === "--fixture" && i + 1 < argv.length) {
            fixtures.push(argv[++i]);
        } else {
            log("error", `test: unknown argument ${argv[i]} (usage: test [--fixture <path>]...)`);
            return 1;
        }
    }
    if (fixtures.length === 0) fixtures.push(...findFixtures("/fixtures"));
    let failed = 0;
    const problems = capabilityProblems();
    for (const p of problems) log("error", `test: ${p}`);
    failed += problems.length;
    if (fixtures.length === 0) {
        log("error", "test: no fixture.json under /fixtures (mount the fixtures directory or pass --fixture)");
        return 1;
    }
    for (const f of fixtures) {
        let fp: string[];
        try {
            fp = await fixtureProblems(loadFixture(f));
        } catch (e) {
            fp = [`cannot load: ${(e as Error).message}`];
        }
        for (const p of fp) log("error", `test: ${f}: ${p}`);
        failed += fp.length;
        if (fp.length === 0) log("info", `test: ${f}: OK`);
    }
    if (failed > 0) {
        log("error", `test: ${failed} problem(s)`);
        return 1;
    }
    log("info", `test: OK (${fixtures.length} fixture(s), capabilities consistent)`);
    return 0;
}
