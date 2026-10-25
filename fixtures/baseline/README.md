# Baseline Fixture

The baseline fixture defines the primary interoperability address space. Both adapters (open62541 and Milo) must construct an equivalent namespace from this single file.

## Address space layout

```
Objects (i=85)
└── Compatibility  (nsu=urn:otfabric:opcua-interop:model;s=Compatibility)
    ├── Scalars       — one readable/writable variable per built-in scalar type
    ├── Arrays        — empty, one-element, multi-element, string, ByteString, 2D matrix
    ├── Dynamic       — deterministic value generators (counter, toggle, ramp)
    ├── Access        — read-write, read-only, write-only
    ├── Methods       — Add, Multiply, Echo, NoArguments, MultipleOutputs, Fail
    ├── DataValues    — variables with specific status codes and timestamp behavior
    ├── Diagnostics   — adapter name, stack version, fixture id
    ├── Events        — EventNotifier source emitting deterministic BaseEvents
    ├── Alarms        — Alarms & Conditions condition (only adapters with serverFeatures "alarms")
    ├── History       — gate-compliant fixed raw HistoryRead samples; History.Events (only
    │                   adapters with serverFeatures "history-events")
    ├── Analog        — AnalogItemType variables with EURange (deadband filters)
    └── PubSub        — writable PubSub fields / TargetVariables, one per type
```

## Namespace

| Alias | URI |
|---|---|
| `compat` | `urn:otfabric:opcua-interop:model` |

Runtime namespace indices differ between stacks. Always reference nodes by namespace URI in tests.

## Scalar initial values

These values are chosen to reveal binary encoding errors:

| Node | Type | Value |
|---|---|---|
| `Scalar.Boolean` | Boolean | `true` |
| `Scalar.SByte` | SByte | `-100` |
| `Scalar.Byte` | Byte | `200` |
| `Scalar.Int16` | Int16 | `-12345` |
| `Scalar.UInt16` | UInt16 | `54321` |
| `Scalar.Int32` | Int32 | `-123456789` |
| `Scalar.UInt32` | UInt32 | `3234567890` |
| `Scalar.Int64` | Int64 | `-1234567890123456789` |
| `Scalar.UInt64` | UInt64 | `12345678901234567890` |
| `Scalar.Float` | Float | `12.5` |
| `Scalar.Double` | Double | `-12345.6789` |
| `Scalar.String` | String | `"OPC UA – 兼容性 – Δ"` |
| `Scalar.DateTime` | DateTime | `2024-01-01T00:00:00Z` |
| `Scalar.Guid` | Guid | `72962b91-fa75-4ae6-8d28-b404dc7daf63` |
| `Scalar.ByteString` | ByteString | `opcua-interop` (base64) |
| `Scalar.XmlElement` | XmlElement | `<compat>test</compat>` |
| `Scalar.NodeId` | NodeId | `i=85` |
| `Scalar.QualifiedName` | QualifiedName | `0:Objects` |
| `Scalar.LocalizedText` | LocalizedText | `en:OPC UA Compatibility` |
| `Scalar.StatusCode` | StatusCode | `0x00000000` (Good) |

## Dynamic behaviors

| Node | Kind | Interval | Description |
|---|---|---|---|
| `Dynamic.Counter` | counter | 250 ms | Int64, starts at 0, increments by 1 |
| `Dynamic.Toggle` | toggle | 500 ms | Boolean, alternates true/false |
| `Dynamic.Ramp` | ramp | 100 ms | Double, 0.0→100.0 then resets |
| `Analog.Level` | ramp | 100 ms | Double, 0.0→100.0 in steps of 2.0, then resets |

## Analog items (DataChangeFilter)

| Node | Type | Access | EURange | Behavior |
|---|---|---|---|---|
| `Analog.Level` | Double, AnalogItemType (`i=2368`) | read | 0..100 | ramp, +2.0 every 100 ms |
| `Analog.Setpoint` | Double, AnalogItemType (`i=2368`) | read/write | 0..100 | static, initial `50.0` |

Both have a `0:EURange` property (HasProperty, DataType Range), declared in the
fixture with the node property `"euRange": {"low": 0.0, "high": 100.0}`. The
property's NodeId is adapter-specific (open62541: the numeric id of the child
instantiated from AnalogItemType; Milo: `<node>.EURange`) — find it by browse
name. Servers accept a **percent deadband** only on these nodes (percent of
EURange, i.e. 10 % = 10.0) and reject it elsewhere
(`BadMonitoredItemFilterUnsupported`); an **absolute deadband** works on every
numeric node and is rejected on non-numeric ones (`BadFilterNotAllowed`). A
notification is sent when `|value − last reported| > deadband`. Write
`Analog.Setpoint` to drive a filter deterministically; `Analog.Level` gives a
steady stream (deadband 10 → every 6th sample).

## PubSub

Writable variables without behaviours under
`nsu=urn:otfabric:opcua-interop:model;s=PubSub` (Organizes, added in fixture
content for adapter v0.8.0, schema unchanged). On a publisher they are
published fields (a test writes them, the next NetworkMessage carries the new
value); on a subscriber they are DataSetReader TargetVariables (written by the
reader). Both adapters load them; only the open62541 adapter does PubSub.

| Node | Type | ValueRank | Initial value |
|---|---|---|---|
| `PubSub.Boolean` | Boolean | -1 | `false` |
| `PubSub.Int32` | Int32 | -1 | `0` |
| `PubSub.Int64` | Int64 | -1 | `0` (the smoke publishes `Dynamic.Counter` into it) |
| `PubSub.UInt64` | UInt64 | -1 | `0` |
| `PubSub.Double` | Double | -1 | `0.0` |
| `PubSub.String` | String | -1 | `""` |
| `PubSub.DateTime` | DateTime | -1 | `2026-01-01T00:00:00Z` |
| `PubSub.ByteString` | ByteString | -1 | empty |
| `PubSub.Int32Array` | Int32 | 1 (ArrayDimensions `[0]`) | `[0, 0, 0]` |
| `PubSub.DoubleArray` | Double | 1 (ArrayDimensions `[0]`) | `[0.0, 0.0, 0.0]` |

Access: CurrentRead + CurrentWrite. `Dynamic.Counter` (Int64, +1 every
250 ms) is a continuously changing source for publishers. The configurations
in `pubsub/examples/` use these nodes (docs/CLIENT_CONTRACT.md §14).

## Methods

| Method | Behavior |
|---|---|
| `Methods.Add` | Returns `Int32(a + b)` |
| `Methods.Multiply` | Returns `Double(a * b)` |
| `Methods.Echo` | Returns input String unchanged |
| `Methods.NoArguments` | Returns `Boolean(true)` |
| `Methods.MultipleOutputs` | Returns `Int32(input * 2)` and `String(input)` |
| `Methods.Fail` | Returns `BadInternalError` service result |

## Access levels

| Node | Access |
|---|---|
| `Access.ReadWrite` | CurrentRead + CurrentWrite |
| `Access.ReadOnly` | CurrentRead only |
| `Access.WriteOnly` | CurrentWrite only (reads return BadNotReadable) |

## Events

| Node | Behavior |
|---|---|
| `Events.Source` | EventNotifier; adapters emit a BaseEvent about every 2s with Severity=`500`, Message=`peer-event` (locale `en`), SourceName=`Events.Source` |

## Alarms

Alarms & Conditions (OPC UA Part 9) fixture, since adapter 0.12.0. Only the
servers that declare `"alarms"` in `print-capabilities` → `serverFeatures`
build it: UA-.NETStandard, node-opcua and open62541 (experimental A&C of
v1.5.9). The nodes are **not** in `fixture.json` — every adapter realises the
`fixture.json` nodes generically, and the condition needs the stack's own A&C
model — so they are created in code; adapters without the feature simply have
no `s=Alarms` folder.

```
Compatibility
└── Alarms            (nsu=urn:otfabric:opcua-interop:model;s=Alarms, FolderType, Organizes)
    └── Alarms.Source (s=Alarms.Source, BaseObjectType, EventNotifier SubscribeToEvents, Organizes)
        ├── InteropAlarm  (s=Alarms.InteropAlarm, AlarmConditionType, HasComponent + HasCondition)
        ├── Reset         (s=Alarms.Reset, Method, HasComponent, no arguments)
        └── Clear         (s=Alarms.Clear, Method, HasComponent, no arguments; node-opcua since 0.15.0)
```

`Alarms.Source` is a notifier of the Server object (HasNotifier Server →
Alarms.Source; node-opcua: HasEventSource), so an event monitored item on
`i=2253` receives the condition's events and its ConditionRefresh.

| Property of `InteropAlarm` | Value |
|---|---|
| Type | AlarmConditionType (`i=2915`), with the optional ConfirmedState / Confirm |
| ConditionName | `InteropAlarm` |
| SourceNode / SourceName | `s=Alarms.Source` / `Alarms.Source` |
| Initial state (and after `Reset`) | EnabledState true, ActiveState true, AckedState false, ConfirmedState false, Retain true, Severity `500`, Message `interop-alarm` (locale `en`), Comment empty |
| AudibleEnabled / AudibleSound (serverFeatures `alarms-audible`, node-opcua since 0.15.0) | AudibleEnabled `true`; AudibleSound (AudioVariableType, AudioDataType) the 35 bytes `RIFF$\0\0\0WAVEfmt interop-alarm-sound` (Latin-1), its ListId `urn:otfabric:opcua-interop:sounds` |

The stack's own handlers serve Acknowledge (`i=9111`), Confirm (`i=9113`),
AddComment (`i=9029`), Enable (`i=9027`), Disable (`i=9028`) and
ConditionRefresh (`i=3875` on ConditionType `i=2782`; ConditionRefresh2
`i=12912` is the stack's too but not exercised by `client alarms`); each
method reports a new condition event. Calling `Reset` on
`s=Alarms.Source` re-arms the alarm (re-enables a disabled condition, new
EventId, reports an event) and returns Good — call it first, the server
container is shared by several tests.

**Condition branches** (serverFeatures `alarms-branches`, node-opcua since
0.15.0). `Clear` on `s=Alarms.Source` returns the alarm to normal; while it is
active, unacknowledged and retained (as after `Reset`) the stack keeps that
state in a new condition branch (Part 9 §4.4, §5.5.2). In this order it
reports an event of the branch (BranchId non-null, ActiveState true,
AckedState false, Retain true, the EventId to acknowledge the branch with)
and an event of the condition itself (BranchId null, ActiveState false,
AckedState true). Acknowledge and Confirm with the branch's EventId act on
the branch (events with its BranchId); after Confirm the branch is not
retained and is deleted. `Clear` returns `Bad_InvalidState` when the alarm is
not active and `Bad_ConditionDisabled` when it is disabled; `Reset` also
drops the branches. ConditionRefresh reports the condition, not its branches
(node-opcua 2.187.12 `_resend_conditionEvents`). node-opcua's own
`signalNewCondition(null, false, "")` does this; branch zero then has its
default normal state: Message `Back to normal`, Severity `0`.

Per-stack differences (repeated
Acknowledge status, Message after an action, RefreshStart/End on other
notifiers, Time): docs/CLIENT_CONTRACT.md §13 "Alarm servers"; the client side
is `client alarms` (§1 / §4).

## Alarms (1.05)

The Part 9 1.05 extension of the alarm fixture, since adapter 0.15.0, built by
the servers that declare `"alarms-105"` in `serverFeatures`: UA-.NETStandard
only. It sits next to `InteropAlarm`, which is unchanged.

```
Alarms
├── Group              (s=Alarms.Group, AlarmGroupType i=16405, Organizes; AlarmGroupMember → ExtAlarm)
└── Alarms.Source
    ├── ExtAlarm       (s=Alarms.ExtAlarm, AlarmConditionType, HasComponent + HasCondition)
    ├── Dialog         (s=Alarms.Dialog, DialogConditionType, HasComponent + HasCondition)
    ├── ResetExt       (s=Alarms.ResetExt, Method, no arguments)
    ├── Deactivate     (s=Alarms.Deactivate, Method, no arguments)
    └── Branch         (s=Alarms.Branch, Method, output EventId: ByteString)
```

| Node | Content |
|---|---|
| `ExtAlarm` | ConditionName `ExtAlarm`, Severity `400`, Message `ext-alarm`; the optional SuppressedState, OutOfServiceState, SilenceState, LatchedState, ShelvingState (TimedShelve, OneShotShelve, Unshelve), AudibleEnabled, AudibleSound (AudioVariableType, value the ASCII bytes `interop-horn`, ListId `interop-sounds`) and the methods Silence, Suppress, Suppress2, Unsuppress, Unsuppress2, RemoveFromService, RemoveFromService2, PlaceInService, PlaceInService2, Reset, Reset2, GetGroupMemberships. No ConfirmedState: an acknowledged branch ends. |
| `Dialog` | ConditionName `InteropDialog`, Prompt `interop-dialog`, ResponseOptionSet `[Yes, No]` (locale `en`), DefaultResponse / OkResponse `0`, CancelResponse `1`, the method Respond |
| `Group` | GetGroupMemberships of ExtAlarm returns `[s=Alarms.Group]` |
| `ResetExt` | re-arms ExtAlarm — enabled, active, unacknowledged, latched, not suppressed / silenced / out of service, unshelved, AudibleEnabled true, retained, no branches, new EventId — and the dialog (enabled, DialogState active, LastResponse `-1`); reports an event of each |
| `Deactivate` | ExtAlarm inactive (it stays latched until Reset); reports an event |
| `Branch` | creates a branch of ExtAlarm (BranchId a new GUID NodeId in the fixture namespace), reports it and returns its EventId |

The condition methods are the stack's own handlers (UA-.NETStandard 2.0.1
AlarmConditionState / DialogConditionState): a transition to the current
state (e.g. a second Suppress) is `Bad_NothingToDo`; Reset / Reset2 need the
alarm latched, inactive and acknowledged, else `Bad_InvalidState`; Respond
answers `Bad_DialogResponseInvalid` for an index outside the
ResponseOptionSet and `Bad_DialogNotActive` after a response. The adapter
answers only the shelving request (OnShelve) and the response (OnRespond).
The stack has no handler for TimedShelve2 / OneShotShelve2 / Unshelve2 and
Respond2, so the fixture has none of them (a call is refused as a method the
object does not have). Each method raises its AuditCondition*EventType; the
server delivers audit events only with `--auditing` (CLIENT_CONTRACT §11) and
to SignAndEncrypt sessions. Call `ResetExt` first: the container is shared.

## History

Gate-compliant raw samples only (no DB, no update/delete, no aggregates/interpolation).

| Node | Type | Samples |
|---|---|---|
| `History.Temperature` | Double | 5 values `20`…`24` at `2026-07-24T10:00:00Z` step 5s |

## History (events)

Event history (OPC UA Part 11) fixture, since adapter 0.17.0. Only the
servers that declare `"history-events"` in `print-capabilities` →
`serverFeatures` build it: UA-.NETStandard (also `"history-events-update"`)
and asyncua. Like the alarm fixture, the nodes are **not** in `fixture.json`;
they are created in code (CLIENT_CONTRACT §17).

```
Compatibility
└── History                (nsu=urn:otfabric:opcua-interop:model;s=History)
    └── History.Events     (s=History.Events, BaseObjectType, Organizes)
        └── ResetEvents    (s=History.ResetEvents, Method, HasComponent, no arguments; history-events-update only)
```

`History.Events` has EventNotifier `0x0D` (SubscribeToEvents |
HistoryRead | HistoryWrite) on servers with `history-events-update`, else
`0x05` (SubscribeToEvents | HistoryRead). It emits no live events; its
history holds five seeded events:

| # | EventId (ASCII bytes) | EventType | Time | Severity | Message |
|---|---|---|---|---|---|
| 0 | `hist-evt-0` | BaseEventType `i=2041` | `2026-07-24T10:00:00Z` | 100 | `history-event-0` |
| 1 | `hist-evt-1` | BaseEventType `i=2041` | `2026-07-24T10:00:05Z` | 200 | `history-event-1` |
| 2 | `hist-evt-2` | BaseEventType `i=2041` | `2026-07-24T10:00:10Z` | 300 | `history-event-2` |
| 3 | `hist-evt-3` | SystemEventType `i=2130` | `2026-07-24T10:00:15Z` | 400 | `history-event-3` |
| 4 | `hist-evt-4` | BaseEventType `i=2041` | `2026-07-24T10:00:20Z` | 500 | `history-event-4` |

Every event: SourceNode `s=History.Events`, SourceName `History.Events`,
ReceiveTime = Time. Compare the Message text: its locale is the server's
(`en` on UA-.NETStandard). HistoryUpdate (insert / replace /
update / delete) changes the shared archive; `ResetEvents` restores these
five events — call it first when a test reads after updates.

## Users

| Username | Password | Roles |
|---|---|---|
| `test-user` | `test-password` | AuthenticatedUser |

These credentials are for isolated test environments only.

## Security profiles

`None/None`, `Basic256Sha256` (Sign, SignAndEncrypt), `Aes128_Sha256_RsaOaep`,
`Aes256_Sha256_RsaPss` (SignAndEncrypt) and the ECC policies `ECC_nistP256`,
`ECC_nistP384` (Sign, SignAndEncrypt), `ECC_brainpoolP256r1`,
`ECC_brainpoolP384r1`, `ECC_curve25519`, `ECC_curve448`, `ECC_nistP256_AesGcm`,
`ECC_nistP256_ChaChaPoly` (SignAndEncrypt).

The ECC entries only take effect on the open62541 server and only when it is
started with `--ecc-dir`; the Milo server skips them (Milo 1.1.8 has no ECC
policies). The open62541 server advertises every RSA policy its stack enables
in both modes regardless of this list (unchanged behaviour).

## Schema version

`1.0`
