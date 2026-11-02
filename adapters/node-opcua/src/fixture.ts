// SPDX-License-Identifier: MIT
//
// Fixture model (fixtures/schema/opcua-fixture.schema.json) and the
// validate-fixture command.

import * as fs from "node:fs";

export interface ArgumentDef {
    name: string;
    dataType: string;
    valueRank?: number;
    description?: string;
}

export interface NodeDef {
    nodeClass: "Object" | "Variable" | "Method";
    nodeId: string;
    browseName: string;
    displayName?: string;
    description?: string;
    parentNodeId?: string;
    referenceType?: string;
    typeDefinition?: string;
    dataType?: string;
    valueRank?: number;
    arrayDimensions?: number[];
    accessLevel?: string[];
    initialValue?: unknown;
    euRange?: { low: number; high: number };
    methodBehavior?: string;
    inputArguments?: ArgumentDef[];
    outputArguments?: ArgumentDef[];
}

export interface BehaviorDef {
    target: string;
    kind: string;
    initial?: number;
    increment?: number;
    minimum?: number;
    maximum?: number;
    intervalMs?: number;
}

export interface Fixture {
    schemaVersion: string;
    id: string;
    description?: string;
    server: { applicationUri: string; productUri: string; applicationName: string };
    endpoint: { path?: string; port?: number };
    namespaces: { alias: string; uri: string }[];
    nodes?: NodeDef[];
    behaviors?: BehaviorDef[];
    users?: { username: string; password?: string; roles?: string[] }[];
    securityProfiles?: { securityPolicy: string; securityMode: string }[];
}

export function loadFixture(path: string): Fixture {
    const raw = fs.readFileSync(path, "utf8");
    return JSON.parse(raw) as Fixture;
}

export function validateFixtureCommand(argv: string[]): number {
    let path: string | undefined;
    for (let i = 0; i < argv.length - 1; i++) if (argv[i] === "--fixture") path = argv[i + 1];
    if (!path && argv.length > 0 && !argv[0].startsWith("--")) path = argv[0];
    if (!path) {
        process.stderr.write("usage: validate-fixture --fixture <path>\n");
        return 1;
    }
    const errors: string[] = [];
    try {
        const f = loadFixture(path);
        if (!f.schemaVersion) errors.push("missing schemaVersion");
        if (!f.id) errors.push("missing id");
        if (!f.server) errors.push("missing server");
        if (!f.endpoint) errors.push("missing endpoint");
        if (!f.namespaces) errors.push("missing namespaces");
        for (const n of f.nodes ?? []) {
            if (!n.nodeId) errors.push("node without nodeId");
            if (!["Object", "Variable", "Method"].includes(n.nodeClass)) errors.push(`${n.nodeId}: unknown nodeClass ${n.nodeClass}`);
        }
    } catch (e) {
        errors.push((e as Error).message);
    }
    if (errors.length === 0) {
        process.stdout.write('{"valid":true}\n');
        return 0;
    }
    process.stdout.write(JSON.stringify({ valid: false, errors }) + "\n");
    return 5;
}
