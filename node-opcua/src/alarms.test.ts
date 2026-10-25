// SPDX-License-Identifier: MIT
//
// The Alarms & Conditions fixture (serverFeatures "alarms") and the ConditionEntry
// encoding of `client alarms`.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";

import { DataType, LocalizedText, NodeId, NodeIdType, OPCUACertificateManager, OPCUAServer, StatusCodes, Variant } from "node-opcua";

import {
    ALARM_AUDIBLE_LIST_ID,
    ALARM_AUDIBLE_SOUND,
    ALARM_CONDITION_NAME,
    ALARM_MESSAGE,
    ALARM_SEVERITY,
    ALARMS_SOURCE,
} from "./alarms.js";
import { conditionEntry, flagArg } from "./client.js";
import { AddressSpaceBuilder } from "./server.js";
import { Args } from "./util.js";

const NS = "urn:otfabric:opcua-interop:model";

test("alarms fixture: InteropAlarm is armed, acknowledge / confirm / Reset drive its states", async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), "node-opcua-alarms-"));
    const server = new OPCUAServer({
        port: 0,
        serverCertificateManager: new OPCUACertificateManager({ rootFolder: path.join(work, "pki"), disableFileWatchers: true }),
    });
    try {
        await server.initialize();
        const ns = server.engine.addressSpace!.registerNamespace(NS);
        const builder = new AddressSpaceBuilder(server, {
            schemaVersion: "1.0", id: "unit",
            server: { applicationUri: "urn:unit", productUri: "urn:unit", applicationName: "unit" },
            endpoint: { path: "/x", port: 4840 },
            namespaces: [{ alias: "m", uri: NS }],
            nodes: [{ nodeClass: "Object", nodeId: `nsu=${NS};s=Compatibility`, browseName: "1:Compatibility", parentNodeId: "i=85", referenceType: "Organizes", typeDefinition: "i=61" }],
        }, ns);
        builder.build();
        assert.deepEqual(builder.problems, []);
        const fx = builder.alarms!;
        assert.ok(fx, "alarm fixture installed");
        const alarm = fx.alarm;
        assert.equal(alarm.nodeId.toString(), new NodeId(NodeIdType.STRING, "Alarms.InteropAlarm", ns.index).toString());
        assert.equal(alarm.typeDefinitionObj.browseName.name, "AlarmConditionType");
        assert.ok(alarm.confirmedState, "optional ConfirmedState present");
        const b = alarm.currentBranch();
        const armed = () => {
            assert.equal(alarm.getEnabledState(), true);
            assert.equal(b.getActiveState(), true);
            assert.equal(b.getAckedState(), false);
            assert.equal(b.getConfirmedState(), false);
            assert.equal(b.getRetain(), true);
            assert.equal(b.getSeverity(), ALARM_SEVERITY);
            assert.equal(b.getMessage().text, ALARM_MESSAGE);
        };
        armed();
        assert.equal(alarm.conditionName.readValue().value.value, ALARM_CONDITION_NAME);
        assert.equal(alarm.sourceName.readValue().value.value, ALARMS_SOURCE);
        assert.equal(alarm.sourceNode.readValue().value.value.toString(), fx.source.nodeId.toString());

        assert.equal(alarm._acknowledge_branch(b.getEventId(), "ack", b, "unit").value, StatusCodes.Good.value);
        assert.equal(b.getAckedState(), true);
        assert.equal(b.getConfirmedState(), false);
        alarm._confirm_branch(b.getEventId(), new LocalizedText({ locale: "en", text: "ok" }), b, "unit");
        assert.equal(b.getConfirmedState(), true);
        assert.equal(b.getRetain(), true, "an active alarm stays retained after Confirm");

        alarm.setEnabledState(false);
        fx.rearm();
        armed();

        // AudibleEnabled / AudibleSound (AudioVariableType with ListId).
        assert.equal(alarm.audibleEnabled.readValue().value.value, true);
        assert.deepEqual(Buffer.from(alarm.audibleSound.readValue().value.value), ALARM_AUDIBLE_SOUND);
        assert.equal(alarm.audibleSound.typeDefinitionObj.browseName.name, "AudioVariableType");
        assert.equal(alarm.audibleSound.listId.readValue().value.value, ALARM_AUDIBLE_LIST_ID);

        // Clear: branch zero back to normal, the unacknowledged active state in a branch.
        assert.equal(fx.clear().value, StatusCodes.Good.value);
        assert.equal(b.getActiveState(), false);
        assert.equal(b.getAckedState(), true);
        assert.equal(alarm.getBranchCount(), 1);
        const branch = alarm.getBranches()[0];
        assert.ok(!branch.getBranchId().isEmpty(), "the branch has a BranchId");
        assert.equal(branch.getActiveState(), true);
        assert.equal(branch.getAckedState(), false);
        assert.equal(branch.getRetain(), true);
        assert.equal(fx.clear().value, StatusCodes.BadInvalidState.value, "Clear of a normal alarm");
        // Acknowledge + Confirm of the branch: it is not retained any more and goes.
        assert.equal(alarm._acknowledge_branch(branch.getEventId(), "ack", branch, "unit").value, StatusCodes.Good.value);
        assert.equal(alarm.getBranchCount(), 1);
        alarm._confirm_branch(branch.getEventId(), new LocalizedText({ locale: "en", text: "ok" }), branch, "unit");
        assert.equal(alarm.getBranchCount(), 0, "a confirmed branch is deleted");
        // Reset drops remaining branches.
        fx.rearm();
        assert.equal(fx.clear().value, StatusCodes.Good.value);
        assert.equal(alarm.getBranchCount(), 1);
        fx.rearm();
        assert.equal(alarm.getBranchCount(), 0);
        armed();
        alarm.setEnabledState(false);
        assert.equal(fx.clear().value, StatusCodes.BadConditionDisabled.value);
        fx.rearm();
    } finally {
        await server.shutdown(0).catch(() => undefined);
        fs.rmSync(work, { recursive: true, force: true });
    }
});

test("conditionEntry: the 16 SelectClause fields; Null / StatusCode / wrong types are null", () => {
    const eventId = Buffer.from("evt");
    const t = new Date("2026-01-02T03:04:05.000Z");
    const v = (dataType: DataType, value: unknown) => new Variant({ dataType, value });
    const fields = [
        v(DataType.ByteString, eventId),
        v(DataType.NodeId, new NodeId(NodeIdType.NUMERIC, 2915, 0)),
        v(DataType.NodeId, new NodeId(NodeIdType.STRING, "Alarms.Source", 2)),
        v(DataType.String, "Alarms.Source"),
        v(DataType.DateTime, t),
        v(DataType.LocalizedText, new LocalizedText({ locale: "en", text: "interop-alarm" })),
        v(DataType.UInt16, 500),
        v(DataType.String, "InteropAlarm"),
        v(DataType.Null, null),
        v(DataType.Boolean, true),
        v(DataType.Boolean, true),
        v(DataType.LocalizedText, new LocalizedText({ locale: "en", text: "c" })),
        v(DataType.Boolean, false),
        v(DataType.StatusCode, StatusCodes.BadAttributeIdInvalid),
        v(DataType.Boolean, true),
        v(DataType.NodeId, new NodeId(NodeIdType.STRING, "Alarms.InteropAlarm", 2)),
    ];
    assert.deepEqual(conditionEntry(fields), {
        conditionId: "ns=2;s=Alarms.InteropAlarm",
        eventId: eventId.toString("base64"),
        eventType: "i=2915",
        sourceNode: "ns=2;s=Alarms.Source",
        sourceName: "Alarms.Source",
        conditionName: "InteropAlarm",
        time: "2026-01-02T03:04:05.000Z",
        message: "interop-alarm",
        severity: 500,
        retain: true,
        enabled: true,
        acked: false,
        confirmed: null,
        active: true,
        comment: "c",
    });
    // A BaseEvent (no condition fields): ConditionId and the rest are null.
    const base = conditionEntry(fields.slice(0, 7));
    assert.equal(base.conditionId, null);
    assert.equal(base.retain, null);
    assert.equal(base.comment, null);
});

test("flagArg: bare presence flags, explicit true / false", () => {
    const a = new Args(["--acknowledge", "--confirm", "false", "--add-comment", "true", "--comment", "x"]);
    assert.equal(flagArg(a, "--acknowledge"), true);
    assert.equal(flagArg(a, "--confirm"), false);
    assert.equal(flagArg(a, "--add-comment"), true);
    assert.equal(flagArg(a, "--missing"), false);
});
