// SPDX-License-Identifier: MIT
//
// The Alarms & Conditions fixture (serverFeatures "alarms", fixtures/baseline/README.md):
// an AlarmConditionType instance `s=Alarms.InteropAlarm` (with the optional
// ConfirmedState / Confirm) on the notifier `s=Alarms.Source`, and the method
// `s=Alarms.Reset` that re-arms it. Since adapter 0.15.0 the alarm has the
// optional AudibleEnabled / AudibleSound (serverFeatures "alarms-audible") and
// `s=Alarms.Clear` returns it to normal; the unacknowledged state it leaves is
// kept in a condition branch (serverFeatures "alarms-branches"). Acknowledge / Confirm / AddComment / Enable /
// Disable / ConditionRefresh(2) are node-opcua's own handlers
// (addressSpace.installAlarmsAndConditionsService()).

import { DataType, LocalizedText, NodeId, StatusCode, StatusCodes } from "node-opcua";

export const ALARMS_FOLDER = "Alarms";
export const ALARMS_SOURCE = "Alarms.Source";
export const ALARM_NODE = "Alarms.InteropAlarm";
export const ALARM_RESET = "Alarms.Reset";
export const ALARM_CLEAR = "Alarms.Clear";
/** AudibleSound of InteropAlarm (AudioDataType, a ByteString) and its ListId. */
export const ALARM_AUDIBLE_SOUND = Buffer.from("RIFF\x24\x00\x00\x00WAVEfmt interop-alarm-sound", "latin1");
export const ALARM_AUDIBLE_LIST_ID = "urn:otfabric:opcua-interop:sounds";
export const ALARM_CONDITION_NAME = "InteropAlarm";
export const ALARM_MESSAGE = "interop-alarm";
export const ALARM_SEVERITY = 500;

export interface AlarmFixture {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    source: any;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    alarm: any;
    /** Re-arms the alarm (what `s=Alarms.Reset` does): Enabled, Active, unacknowledged, unconfirmed, Retain, new event; drops the branches. */
    rearm: () => void;
    /** Returns the alarm to normal (what `s=Alarms.Clear` does); the unacknowledged state goes to a new branch. */
    clear: () => StatusCode;
}

/**
 * Creates the alarm fixture in namespace `ns` below `parent` (the fixture's
 * `s=Compatibility` folder, else Objects).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function installAlarmFixture(addressSpace: any, ns: any, parent: any): AlarmFixture {
    addressSpace.installAlarmsAndConditionsService();
    const id = (s: string) => new NodeId(NodeId.NodeIdType.STRING, s, ns.index);
    const folder = ns.addObject({
        nodeId: id(ALARMS_FOLDER),
        browseName: ALARMS_FOLDER,
        displayName: new LocalizedText({ locale: "en", text: ALARMS_FOLDER }),
        description: new LocalizedText({ locale: "en", text: "Alarms & Conditions (Part 9) interoperability fixture." }),
        organizedBy: parent ?? addressSpace.rootFolder.objects,
        typeDefinition: "FolderType",
    });
    const source = ns.addObject({
        nodeId: id(ALARMS_SOURCE),
        browseName: ALARMS_SOURCE,
        displayName: new LocalizedText({ locale: "en", text: "Alarm Source" }),
        description: new LocalizedText({ locale: "en", text: "SourceNode of the InteropAlarm condition." }),
        organizedBy: folder,
        eventNotifier: 1, // SubscribeToEvents
    });
    // Server --HasEventSource--> Alarms.Source: node-opcua requires a condition
    // source to be the target of a HasEventSource (not only HasNotifier,
    // ua_condition_impl.js "conditionSourceNode must be an event source"). An
    // event item on the Server object gets the condition's events (node-opcua
    // also bubbles every event to the Server object).
    const server = addressSpace.rootFolder.objects.server;
    server.addReference({ referenceType: "HasEventSource", nodeId: source.nodeId });

    const alarm = ns.instantiateAlarmCondition("AlarmConditionType", {
        nodeId: id(ALARM_NODE),
        browseName: ALARM_CONDITION_NAME,
        displayName: new LocalizedText({ locale: "en", text: ALARM_CONDITION_NAME }),
        componentOf: source,
        conditionSource: source,
        conditionName: ALARM_CONDITION_NAME,
        // AlarmConditionType's InputNode is mandatory; the fixture alarm is
        // driven by s=Alarms.Reset and the A&C methods, not by a variable.
        inputNode: NodeId.nullNodeId,
        optionals: ["ConfirmedState", "Confirm", "AudibleEnabled", "AudibleSound", "AudibleSound.ListId"],
    });
    // node-opcua derives SourceName from the source's BrowseName ("2:Alarms.Source").
    alarm.setSourceName(ALARMS_SOURCE);

    // AudibleEnabled / AudibleSound (Part 9 §5.8.2, AudioVariableType §8.3): a
    // fixed sound and its ListId; AudibleEnabled true.
    alarm.audibleEnabled.setValueFromSource({ dataType: DataType.Boolean, value: true });
    alarm.audibleSound.setValueFromSource({ dataType: DataType.ByteString, value: ALARM_AUDIBLE_SOUND });
    alarm.audibleSound.listId?.setValueFromSource({ dataType: DataType.String, value: ALARM_AUDIBLE_LIST_ID });

    // Enable on a plain AlarmConditionType throws "Unimplemented, please override"
    // (UAConditionImplBase.evaluateConditionsAfterEnabled): the fixture alarm has
    // no input to re-evaluate, it keeps its states (and _setEnabledState then
    // restores Retain and reports the event).
    alarm.evaluateConditionsAfterEnabled = () => undefined;

    // node-opcua's Confirm sets Retain=false also while the alarm is still
    // Active (_confirm_branch); Part 9 keeps an active condition retained, so
    // the fixture keeps Retain true while ActiveState is true. Only for the
    // condition itself: a confirmed branch (a past state) is not retained and
    // node-opcua deletes it.
    const confirmBranch = alarm._confirm_branch.bind(alarm);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    alarm._confirm_branch = (eventId: Buffer, comment: unknown, branch: any, message: string) => {
        if (branch !== alarm.currentBranch()) return confirmBranch(eventId, comment, branch, message);
        const setRetain = branch.setRetain;
        branch.setRetain = (v: boolean) => setRetain.call(branch, v || branch.getActiveState() === true);
        try {
            return confirmBranch(eventId, comment, branch, message);
        } finally {
            delete branch.setRetain;
        }
    };

    const rearm = () => {
        if (!alarm.getEnabledState()) alarm.setEnabledState(true);
        // The branches of earlier Clear calls go: the condition starts afresh.
        for (const b of alarm.getBranches()) alarm.deleteBranch(b);
        const branch = alarm.currentBranch();
        branch.setActiveState(true);
        branch.setAckedState(false);
        branch.setConfirmedState(false);
        alarm.raiseNewCondition({
            message: new LocalizedText({ locale: "en", text: ALARM_MESSAGE }),
            severity: ALARM_SEVERITY,
            quality: StatusCodes.Good,
            retain: true,
        });
    };

    const reset = ns.addMethod(source, {
        nodeId: id(ALARM_RESET),
        browseName: "Reset",
        displayName: new LocalizedText({ locale: "en", text: "Reset" }),
        description: new LocalizedText({ locale: "en", text: "Re-arms InteropAlarm: Enabled, Active, unacknowledged, unconfirmed, Retain." }),
        inputArguments: [],
        outputArguments: [],
    });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    reset.bindMethod(async (_inputs: unknown[], _context: unknown) => {
        try {
            rearm();
            return { statusCode: StatusCodes.Good, outputArguments: [] };
        } catch {
            return { statusCode: StatusCodes.BadInternalError };
        }
    });

    // Clear: back to normal by node-opcua's own signalNewCondition (stateName
    // null, inactive). An unacknowledged retained state is kept in a new branch
    // (ua_alarm_condition_impl signalNewCondition: createBranch +
    // raiseNewBranchState): an event with that BranchId, Active, unacknowledged.
    // Branch zero becomes inactive and acknowledged ("Back to normal", severity
    // 0, node-opcua's default ConditionInfo). Bad_ConditionDisabled when the
    // condition is disabled, Bad_InvalidState when it is already normal.
    const clear = (): StatusCode => {
        if (!alarm.getEnabledState()) return StatusCodes.BadConditionDisabled;
        if (alarm.currentBranch().getActiveState() !== true) return StatusCodes.BadInvalidState;
        alarm.signalNewCondition(null, false, "");
        return StatusCodes.Good;
    };

    const clearMethod = ns.addMethod(source, {
        nodeId: id(ALARM_CLEAR),
        browseName: "Clear",
        displayName: new LocalizedText({ locale: "en", text: "Clear" }),
        description: new LocalizedText({ locale: "en", text: "Returns InteropAlarm to normal; an unacknowledged state is kept in a condition branch." }),
        inputArguments: [],
        outputArguments: [],
    });
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    clearMethod.bindMethod(async (_inputs: unknown[], _context: unknown) => {
        try {
            return { statusCode: clear(), outputArguments: [] };
        } catch {
            return { statusCode: StatusCodes.BadInternalError };
        }
    });

    rearm();
    return { source, alarm, rearm, clear };
}
