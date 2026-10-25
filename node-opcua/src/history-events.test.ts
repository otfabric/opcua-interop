// SPDX-License-Identifier: MIT
//
// `client history-read-events` / `history-update-events`: the SelectClauses,
// the WhereClause, the --event literals, input errors before connecting, and
// the node-opcua server, which has no event history (no s=History.Events,
// HistoryUpdate is not served).

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";

import { DataType, FilterOperator, NodeId, OPCUACertificateManager, OPCUAServer, TimestampsToReturn } from "node-opcua";

import { capabilitiesDocument } from "./capabilities.js";
import {
    clientCommand,
    eventFieldVariant,
    eventTimestamps,
    eventWhere,
    HISTORY_EVENT_SELECT,
    parseEventJson,
    selectOperand,
} from "./client.js";
import { EXIT_INPUT, EXIT_SERVICE, parseNodeIdString, resolveParsed } from "./util.js";

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

const nodeOf = (s: string) => resolveParsed(parseNodeIdString(s), undefined);

test("history events: default SelectClauses and the --select path syntax", () => {
    assert.deepEqual(HISTORY_EVENT_SELECT, ["EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"]);
    const op = selectOperand("2:Foo/Bar");
    assert.equal(op.typeDefinitionId.toString(), "ns=0;i=2041");
    assert.equal(op.browsePath!.length, 2);
    assert.equal(op.browsePath![0].namespaceIndex, 2);
    assert.equal(op.browsePath![0].name, "Foo");
    assert.equal(op.browsePath![1].namespaceIndex, 0);
    assert.throws(() => selectOperand("a//b"), /--select/);
});

test("history events: WhereClause of --of-type / --min-severity", () => {
    assert.equal(eventWhere(undefined, undefined).elements?.length ?? 0, 0);
    assert.equal(eventWhere(undefined, 300).elements![0].filterOperator, FilterOperator.GreaterThanOrEqual);
    const both = eventWhere(nodeOf("i=2130"), 300);
    assert.deepEqual(both.elements!.map((e) => e.filterOperator), [FilterOperator.And, FilterOperator.OfType, FilterOperator.GreaterThanOrEqual]);
    assert.equal(eventTimestamps(undefined), TimestampsToReturn.Both);
    assert.equal(eventTimestamps("Neither"), TimestampsToReturn.Neither);
    assert.throws(() => eventTimestamps("all"), /--timestamps/);
});

test("history events: --event literals", () => {
    const ev = parseEventJson(JSON.stringify({
        EventId: { type: "ByteString", value: Buffer.from("hist-evt-9").toString("base64") },
        EventType: { type: "NodeId", value: "i=2041" },
        Time: { type: "DateTime", value: "2026-07-24T10:00:30Z" },
        Severity: { type: "UInt16", value: 700 },
        Message: { type: "LocalizedText", value: { text: "x" } },
        SourceName: "src",
    }));
    assert.deepEqual(ev.map((f) => f.path), ["EventId", "EventType", "Time", "Severity", "Message", "SourceName"]);
    const v = (p: string) => eventFieldVariant(ev.find((f) => f.path === p)!, nodeOf);
    assert.equal(Buffer.from(v("EventId").value as Buffer).toString(), "hist-evt-9");
    assert.ok((v("EventType").value as NodeId).toString() === "ns=0;i=2041");
    assert.equal((v("Time").value as Date).toISOString(), "2026-07-24T10:00:30.000Z");
    assert.equal(v("Severity").dataType, DataType.UInt16);
    assert.equal(v("Severity").value, 700);
    assert.equal(v("Message").value.text, "x");
    assert.equal(v("SourceName").dataType, DataType.String);
    for (const bad of ["[]", '{"Severity":{"type":"UInt16","value":70000}}', '{"EventId":{"type":"ByteString","value":"%%"}}', '{"":1}', "nope"]) {
        assert.throws(() => parseEventJson(bad), /--event|--select|JSON/, bad);
    }
});

test("history events: bad flags are input errors before connecting", async () => {
    const ep = ["--endpoint", "opc.tcp://127.0.0.1:1"];
    for (const argv of [
        ["history-read-events", ...ep],
        ["history-read-events", ...ep, "--node", "i=2253", "--start", "yesterday"],
        ["history-read-events", ...ep, "--node", "i=2253", "--min-severity", "70000"],
        ["history-read-events", ...ep, "--node", "i=2253", "--timestamps", "all"],
        ["history-read-events", ...ep, "--node", "i=2253", "--scenario", "nope"],
        ["history-read-events", ...ep, "--node", "i=2253", "--release-continuation-point"],
        ["history-read-events", ...ep, "--node", "i=2253", "--node", "i=85", "--continuation-point", "AAAA"],
        ["history-update-events", ...ep, "--node", "i=2253"],
        ["history-update-events", ...ep, "--node", "i=2253", "--perform", "remove"],
        ["history-update-events", ...ep, "--node", "i=2253", "--perform", "delete"],
        ["history-update-events", ...ep, "--node", "i=2253", "--perform", "insert"],
        ["history-update-events", ...ep, "--node", "i=2253", "--perform", "insert", "--select", "Time", "--event", '{"Severity":1}'],
    ]) {
        const { code, out } = await run(argv);
        assert.equal(code, EXIT_INPUT, argv.join(" "));
        assert.equal((out.error as { category: string }).category, "input", argv.join(" "));
    }
});

test("history events: the node-opcua server has no event history", async () => {
    const c = capabilitiesDocument();
    assert.ok(c.clientOperations.includes("history-read-events") && c.clientOperations.includes("history-update-events"));
    assert.ok(!c.serverFeatures.includes("history-events") && !c.serverFeatures.includes("history-events-update"));

    const work = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-hev-"));
    const server = new OPCUAServer({
        port: 0,
        serverCertificateManager: new OPCUACertificateManager({ rootFolder: path.join(work, "pki"), disableFileWatchers: true }),
    });
    try {
        await server.start();
        const url = server.getEndpointUrl().replace(/\/\/[^:/]+:/, "//127.0.0.1:");
        const read = await run(["history-read-events", "--endpoint", url, "--node", "i=2253", "--start", "2026-07-24T10:00:00Z", "--end", "2026-07-24T10:01:00Z"]);
        assert.equal(read.code, EXIT_SERVICE);
        const item = (read.out.results as Record<string, unknown>[])[0];
        assert.equal(item.nodeId, "i=2253");
        assert.deepEqual(item.events, []);
        assert.match((item.statusCode as { name: string }).name, /^Bad/);

        const upd = await run(["history-update-events", "--endpoint", url, "--node", "i=2253", "--perform", "delete", "--event-id", "AAAA"]);
        assert.equal(upd.code, EXIT_SERVICE);
        assert.match((upd.out.serviceResult as { name: string }).name, /^Bad/);
    } finally {
        await server.shutdown(0).catch(() => undefined);
        fs.rmSync(work, { recursive: true, force: true });
    }
});
