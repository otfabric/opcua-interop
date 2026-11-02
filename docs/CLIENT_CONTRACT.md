# opcua-interop Client Command Contract

Version: **1.0**

This document defines the stable external interface for the `client` subcommand of
every opcua-interop adapter image. `go-opcua` (and any other consumer) depends on
this contract. Changes that break it require a major schema version bump.

---

## 1. Command-line interface

```
<image> client <subcmd> --endpoint <url> [flags]
```

### Subcommands

| Subcmd | Description |
|--------|-------------|
| `endpoints` | Discover and list server endpoints |
| `find-servers` | Call FindServers and list ApplicationDescriptions |
| `read` | Read one or more node values |
| `write` | Write a value to one node |
| `browse` | Browse forward hierarchical references from a node |
| `translate` | TranslateBrowsePathsToNodeIDs for a dot-separated browse path |
| `call` | Call a method node and collect output arguments |
| `subscribe` | Create a subscription and collect a bounded number of data-change notifications |
| `subscription-lifecycle` | Test subscription lifecycle scenarios (revise, publishing-mode, monitoring-mode, delete) |
| `event-subscribe` | Create an event monitored item with a BaseEvent SelectClauses filter; collect N events |
| `history-read` | HistoryRead with ReadRawModifiedDetails (raw only); optional continuation point |
| `history-read-events` | HistoryRead with ReadEventDetails (Part 11 §6.5.2): SelectClauses, an optional OfType / Severity WhereClause, continuation points (adapter 0.17.0, §17) |
| `history-update-events` | HistoryUpdate with UpdateEventDetails insert / replace / update (Part 11 §6.9.4) or DeleteEventDetails (§6.9.7) (adapter 0.17.0, §17) |
| `republish` | RepublishRequest for a subscription sequence number |
| `transfer-subscriptions` | TransferSubscriptions for one or more subscription ids |
| `register-nodes` | RegisterNodes, Read through the registered aliases, UnregisterNodes |
| `node-management` | AddNodes (Int32 Variable), Read, DeleteNodes, Read-after-delete |
| `find-servers-on-network` | FindServersOnNetwork against a Local Discovery Server (mDNS records) |
| `register-server` | RegisterServer2 / RegisterServer of an arbitrary server description with an LDS |
| `codec` | Encode / decode built-in values in the OPC UA JSON and XML DataEncodings (no session needed for literals); PubSub NetworkMessages (UADP / JSON, §14) |
| `alarms` | Alarms & Conditions (Part 9): ConditionRefresh on an event monitored item, then optionally Acknowledge / Confirm / AddComment on the refreshed condition |
| `push` | Push certificate management (Part 12 §7, §15): read a certificate group's TrustList, AddCertificate / RemoveCertificate, GetCertificates, CreateSelfSignedCertificate, DeleteCertificate, UpdateCertificate, CreateSigningRequest, GetRejectedList, ResetToServerDefaults, ApplyChanges / CancelChanges, TransactionDiagnostics |
| `query` | Query service set (Part 4 §5.9): QueryFirst for one NodeTypeDescription, then QueryNext with the continuation point until none is left |
| `gds-pull` | GDS pull model (Part 12 §6, §7.9, §16), `dotnet-gds` (adapter 0.14.0) and asyncua, async-opcua, Milo, open62541 and dotnet (adapter 0.15.0): FindApplications / RegisterApplication, StartSigningRequest or StartNewKeyPairRequest, FinishRequest, GetCertificateGroups, GetTrustList + TrustList read, GetCertificateStatus, RevokeCertificate / CheckRevocationStatus, UnregisterApplication |

Which of these (and which optional features) an image provides is declared by
`print-capabilities` (§13). A feature the underlying stack does not implement is
refused with exit 2 / `error.category = "input"` — never silently ignored.

### Global flags

| Flag | Description | Default |
|------|-------------|---------|
| `--endpoint <url>` | OPC UA endpoint URL (required) | — |
| `--connect-timeout <s>` | Connection timeout in seconds | 5 |
| `--request-timeout <s>` | Per-request timeout in seconds | 5 |
| `--disconnect-timeout <s>` | Disconnect timeout in seconds | 2 |
| `--security-policy <name>` | Security policy name | `None` |
| `--security-mode <mode>` | Message security mode | `None` |
| `--certificate <path>` | Client application certificate (PEM or DER file) | — |
| `--private-key <path>` | Client private key (PEM or DER file) | — |
| `--trust-list <path>` | Trusted CA certificate (PEM or DER file); may be repeated | — |
| `--username <name>` | Username for UserName identity token | — |
| `--password <secret>` | Password for UserName identity token | — |
| `--channel-lifetime-ms <n>` | Requested SecureChannel lifetime in ms; small values force SecurityToken renewals during the command | stack default |
| `--application-uri <uri>` | Client ApplicationUri sent in CreateSession (open62541, async-opcua, dotnet, node-opcua, asyncua) | URI SAN of `--certificate`, else stack default |
| `--reverse-listen <port>` | Do not dial: listen on `<port>` and wait for the server's ReverseHello (open62541, async-opcua, node-opcua; see below) | — |
| `--reverse-timeout-ms <n>` | How long to wait for the reverse connection | 30000 |
| `--reverse-server-uri <uri>` | Fail (exit 3, `BadServerUriInvalid`) unless the reverse-connected server's `ServerArray[0]` equals `<uri>` | — |

Security policy names: `None`, `Basic128Rsa15`, `Basic256`, `Basic256Sha256`,
`Aes128_Sha256_RsaOaep`, `Aes256_Sha256_RsaPss`, and — open62541 only — the ECC
policies `ECC_nistP256`, `ECC_nistP384`, `ECC_brainpoolP256r1`,
`ECC_brainpoolP384r1`, `ECC_curve25519`, `ECC_curve448`, `ECC_nistP256_AesGcm`,
`ECC_nistP256_ChaChaPoly`. An unknown or unsupported policy name is an input
error (exit 2); it never falls back to `None`.

**ECC policies.** Pass the application certificate of the policy's curve with
the usual `--certificate` / `--private-key` flags (test PKI:
`<identity>/ecc-<curve>/cert.crt|cert.key`, see `certs/README.md`):

| Policy | Certificate directory |
|--------|-----------------------|
| `ECC_nistP256`, `ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly` | `ecc-nistp256` |
| `ECC_nistP384` | `ecc-nistp384` |
| `ECC_brainpoolP256r1` / `ECC_brainpoolP384r1` | `ecc-brainpoolp256r1` / `ecc-brainpoolp384r1` |
| `ECC_curve25519` / `ECC_curve448` | `ecc-curve25519` (Ed25519) / `ecc-curve448` (Ed448) |

`--username` / `--password` on an ECC endpoint are sent as an
`EccEncryptedSecret`. A certificate / key that cannot be used with the policy
yields exit 6 (`error.category = "internal"`).

**Reverse connect (`--reverse-listen`, Part 6 §7.1.3).** Works with every
session command and with `endpoints` / `find-servers`. `--endpoint` stays
required but is not dialled. The client listens on all interfaces; the server
must be started with `--reverse-connect opc.tcp://<client-host>:<port>` (§11).
With a non-None security policy open62541 uses the first reverse connection for
GetEndpoints (SecurityPolicy None), closes it, and opens the secured channel on
the server's next attempt, so the command needs two ReverseHello attempts (the
adapter server retries every second by default). No connection within
`--reverse-timeout-ms` → exit 7, `BadTimeout`, `error.category = "timeout"`.

Security mode values: `None`, `Sign`, `SignAndEncrypt`.

When `--certificate` and `--private-key` are supplied, the client uses them as its
application instance certificate. When `--username` is supplied without `--password`,
the password is treated as an empty string.

When `--security-policy` is not `None`, `--certificate` and `--private-key` are
required.

### `find-servers` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--endpoint <url>` | Discovery / server endpoint URL | required |

No additional flags. Emits one result object per `ApplicationDescription`.

### `read` flags

| Flag | Description |
|------|-------------|
| `--node <nodeId>` | NodeId to read (repeatable for batch) |
| `--index-range <range>` | Optional NumericRange applied to every ReadValueId (e.g. `1:3`, `0,1`) |

### `write` flags

| Flag | Description |
|------|-------------|
| `--node <nodeId>` | NodeId to write |
| `--type <dataType>` | OPC UA type name (e.g. `Int32`, `Boolean`, `String`, `Int32[]`) |
| `--value <literal>` | Value string |
| `--index-range <range>` | Optional NumericRange applied to the WriteValue |

### `browse` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | Starting node | `i=85` (Objects folder) |
| `--max-refs <n>` | Max references per Browse request | 0 (server default) |

### `translate` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--starting-node <nodeId>` | Starting NodeId for the browse path | `i=85` (Objects folder) |
| `--path <names>` | Dot-separated browse names (e.g. `Server` or `Server.ServerStatus`) | required |
| `--namespace <n>` | Namespace index applied to every path segment | `0` |

Each relative path element uses `HierarchicalReferences` with `IncludeSubtypes=true`.

### `call` flags

| Flag | Description |
|------|-------------|
| `--object <nodeId>` | NodeId of the object that owns the method |
| `--method <nodeId>` | NodeId of the method node |
| `--input <type:value>` | Input argument (repeatable); format `Type:value` e.g. `Int32:10` |

### `subscribe` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | Node to monitor |  required |
| `--publishing-interval-ms <n>` | Requested publishing interval in ms | 500 |
| `--sampling-interval-ms <n>` | Requested sampling interval in ms | 100 |
| `--notifications <n>` | Stop after receiving this many data-change notifications | 5 |
| `--timeout-ms <n>` | Absolute command timeout in ms | 10000 |
| `--queue-size <n>` | Monitored item queue size | 1 |
| `--discard-oldest <true\|false>` | Queue overflow policy | `true` |
| `--timestamps <Source\|Server\|Both\|Neither>` | `TimestampsToReturn` for CreateMonitoredItems | `Both` |
| `--deadband-absolute <x>` | DataChangeFilter with `DeadbandType=Absolute`, `DeadbandValue=x` | no filter |
| `--deadband-percent <x>` | DataChangeFilter with `DeadbandType=Percent`, `DeadbandValue=x` (percent of the node's EURange) | no filter |
| `--trigger <Status\|StatusValue\|StatusValueTimestamp>` | DataChangeFilter trigger | `StatusValue` |

Any of the last three flags makes the monitored item carry a `DataChangeFilter`
(`--trigger` alone uses `DeadbandType=None`). The two deadband flags are
mutually exclusive (exit 2). A server that rejects the filter
(`BadFilterNotAllowed`, `BadMonitoredItemFilterUnsupported`,
`BadDeadbandFilterInvalid`) is visible in `monitoredItemStatusCode`; the command
then exits 4 with `success: false` and no notifications.

### `subscription-lifecycle` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | Writable Int32 node for scenarios that write values | required |
| `--scenario <name>` | Scenario to run: `revise`, `publishing-mode`, `monitoring-mode`, `delete` | required |
| `--timeout-ms <n>` | Absolute command timeout in ms | 15000 |

The `publishing-mode` and `monitoring-mode` scenarios create their monitored
item with **SamplingInterval 0** (report every change; was 100 ms before
v0.7.0), so the queue-window assertion does not depend on how a server throttles
back-to-back writes inside one sampling interval. A server that revises 0 to a
periodic sampling rate (the Milo reference server does) can still coalesce the
five writes; the scenario then reports `success: false` with the values it saw.

### `event-subscribe` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | EventNotifier source node | required |
| `--events <n>` | Stop after receiving this many events | 1 |
| `--timeout-ms <n>` | Absolute command timeout in ms | 10000 |
| `--publishing-interval-ms <n>` | Requested publishing interval in ms | 500 |
| `--queue-size <n>` | Monitored item queue size | 10 |
| `--of-type <nodeId>` | Optional OfType ContentFilterElement (e.g. `i=2041`) | — |
| `--min-severity <n>` | Optional Severity ≥ threshold ContentFilterElement | — |

The EventFilter SelectClauses always request BaseEventType fields:
`EventId`, `EventType`, `SourceName`, `Message`, `Severity`, `Time`.

When both `--of-type` and `--min-severity` are set, the WhereClause ANDs them.
These flags prove narrow filter baselines only — not the general WhereClause
expression surface.

Adapter servers emit deterministic BaseEvents from `Events.Source`
(Severity=500, Message=`peer-event`) about every 2 seconds. Against the Go
server, peer tests may still call `EmitBaseEvent` for tighter timing.

### `alarms` flags

Alarms & Conditions (OPC UA Part 9) client baseline, all six adapters (since
adapter 0.12.0). Generic Call services plus one event monitored item, so it
works against any A&C server; the adapter servers with the alarm fixture
declare `serverFeatures: "alarms"` (§13, fixtures/baseline/README.md "Alarms").

```
<image> client alarms --endpoint <url> [--node <nodeId>] [--condition-name <name>]
        [--acknowledge] [--confirm] [--add-comment] [--comment <text>]
        [--timeout-ms <n>] [--publishing-interval-ms <n>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | EventNotifier of the event monitored item | `i=2253` (Server) |
| `--condition-name <name>` | Target = the refreshed condition with this ConditionName | first condition with Retain = true |
| `--acknowledge` | Acknowledge the target, then repeat the call with the now stale EventId | off |
| `--confirm` | Confirm the target (after the acknowledge) | off |
| `--add-comment` | AddComment on the target (after acknowledge / confirm) | off |
| `--comment <text>` | Comment of all three methods (LocalizedText, locale `en`) | `interop-comment` |
| `--timeout-ms <n>` | Absolute budget of the whole command after connect | 15000 |
| `--publishing-interval-ms <n>` | Requested publishing interval | 200 |

`--acknowledge`, `--confirm` and `--add-comment` are presence flags; a following
`true` / `false` (`1` / `0`) is accepted too. Global flags (security, user
identity, …) as for every session command.

Steps:

1. CreateSubscription; CreateMonitoredItems with one event item on `--node`
   (AttributeId EventNotifier, SamplingInterval 0, QueueSize 1000,
   DiscardOldest true, MonitoringMode Reporting) and an EventFilter without
   WhereClause and with these SelectClauses, in this order (BrowsePath in
   namespace 0, AttributeId Value unless noted):

   | # | TypeDefinitionId | BrowsePath | ConditionEntry field |
   |---|------------------|------------|----------------------|
   | 0 | BaseEventType `i=2041` | `EventId` | `eventId` |
   | 1 | `i=2041` | `EventType` | `eventType` |
   | 2 | `i=2041` | `SourceNode` | `sourceNode` |
   | 3 | `i=2041` | `SourceName` | `sourceName` |
   | 4 | `i=2041` | `Time` | `time` |
   | 5 | `i=2041` | `Message` | `message` |
   | 6 | `i=2041` | `Severity` | `severity` |
   | 7 | ConditionType `i=2782` | `ConditionName` | `conditionName` |
   | 8 | `i=2782` | `BranchId` | — |
   | 9 | `i=2782` | `Retain` | `retain` |
   | 10 | `i=2782` | `EnabledState`, `Id` | `enabled` |
   | 11 | `i=2782` | `Comment` | `comment` |
   | 12 | AcknowledgeableConditionType `i=2881` | `AckedState`, `Id` | `acked` |
   | 13 | `i=2881` | `ConfirmedState`, `Id` | `confirmed` |
   | 14 | AlarmConditionType `i=2915` | `ActiveState`, `Id` | `active` |
   | 15 | `i=2782` | *(empty)*, AttributeId NodeId (1) | `conditionId` (Part 9 §5.5.2) |

   The publish loop runs before CreateMonitoredItems, so no event is missed.
2. Call ConditionRefresh: ObjectId `i=2782`, MethodId `i=3875`, input
   `[UInt32 subscriptionId]`. `refresh.statusCode` is the CallMethodResult
   status (or the service fault).
3. Collect events until a RefreshEndEvent (EventType `i=2788`) arrives or the
   timeout expires; `startSeen` records a RefreshStartEvent (`i=2787`). Every
   event with a non-null ConditionId (field 15) that arrives after the
   ConditionRefresh call and before the RefreshEnd is a refreshed condition
   (`conditions`, deduplicated by conditionId keeping the last event, in
   first-seen order). Events with a null ConditionId (e.g. the BaseEvents of
   `Events.Source` arriving on the Server object) are ignored. Every condition
   event, also later ones, updates the "latest event" of its conditionId.
4. Target: the refreshed condition whose ConditionName is `--condition-name`,
   else the first one with `retain = true`. An action is requested and there is
   no target → `success: false`, `BadNodeIdUnknown`, exit 4.
5. `--acknowledge`: Call ObjectId = target conditionId, MethodId `i=9111`
   (AcknowledgeableConditionType_Acknowledge), inputs `[EventId (ByteString) of
   the target's latest event, Comment (LocalizedText en, --comment)]`. If Good,
   wait for the next event of that condition with `acked = true`. Then call
   Acknowledge again with the same (now stale) EventId: `repeatStatusCode`
   (servers answer `Bad_ConditionBranchAlreadyAcked` or `Bad_EventIdUnknown`,
   see §13); it never affects `success`.
6. `--confirm`: MethodId `i=9113` (AcknowledgeableConditionType_Confirm), same
   inputs with the EventId of the target's latest event at that moment; if Good
   wait for the event with `confirmed = true`.
7. `--add-comment`: MethodId `i=9029` (ConditionType_AddComment), same inputs;
   if Good wait for the event whose `comment` is `--comment`.
8. DeleteSubscriptions, disconnect.

A follow-up event is any matching event of the target that arrives after the
method call was issued. The actions run in the order acknowledge → confirm →
add-comment and stop at the first failure.

`success` = refresh Good AND RefreshEnd seen AND every requested action Good
with its follow-up event seen. `serviceResult` is Good on success, else the
first failing status (CreateMonitoredItems, ConditionRefresh or the method),
`BadTimeout` for a missing RefreshEnd or follow-up event, `BadNodeIdUnknown`
for a missing target. Exit codes (§5): 0 success, 2 bad input (before
connecting), 3 connect / transport, 4 service failure, 7 timeout. The result
is printed in every case once the subscription exists.

### `push` flags

Push certificate management client (Part 12 §7) against the ServerConfiguration
object (`i=12637`) of the server: node-opcua since adapter 0.13.0 (the
flags marked 0.15.0 since adapter 0.15.0), asyncua, async-opcua, Eclipse Milo,
open62541 and UA-.NETStandard (`dotnet`) since adapter 0.15.0 with every flag
below (§15). The methods need an encrypted
channel and a user with the SecurityAdmin role, so the command is run with
`--security-policy … --security-mode SignAndEncrypt` and `--username` /
`--password`.

```
<image> client push --endpoint <url> [--group <Application|Https|UserToken>]
        [--add-certificate <file>] [--remove-certificate <thumbprint>] [--issuer]
        [--get-certificates]
        [--create-self-signed [--certificate-type-id <nodeId>] [--subject <name>] [--dns <name>]...
                              [--ip <address>]... [--lifetime-days <n>] [--key-size <n>]]
        [--delete-certificate <certificateTypeId>]
        [--update-certificate <file> [--update-private-key <file>] [--private-key-format PEM|PFX]
                                     [--issuer-certificate <file>]...]
        [--csr] [--reset-to-defaults] [--apply | --cancel] [--transaction-diagnostics]
```

| Flag | Description | Default | Feature (§13) |
|------|-------------|---------|---------------|
| `--group <name>` | The CertificateGroup every step works on: `Application` = DefaultApplicationGroup `i=14156`, `Https` = DefaultHttpsGroup `i=14088`, `UserToken` = DefaultUserTokenGroup `i=14122` (Part 12 §7.8.4); its TrustList is the one read, added to and removed from | `Application` | `push-groups` |
| `--certificate-type-id <nodeId>` | CertificateType of `--create-self-signed`, `--update-certificate` and `--csr` | `Application`: RsaSha256ApplicationCertificateType `i=12560`; `Https`: HttpsCertificateType `i=12558`; `UserToken`: UserCredentialCertificateType `i=15181` | `push-groups` |
| `--add-certificate <file>` | AddCertificate with this certificate (PEM or DER file) | — | |
| `--remove-certificate <thumbprint>` | RemoveCertificate (hexadecimal SHA-1 thumbprint) | — | |
| `--issuer` | AddCertificate / RemoveCertificate with `isTrustedCertificate` false (issuer list) | trusted list | |
| `--get-certificates` | GetCertificates (`i=32333`) of the group | off | `push-certificates` |
| `--create-self-signed` | CreateSelfSignedCertificate (`i=19342`) for the group and `--certificate-type-id`, with SubjectName `--subject` (`""`: the server's choice), DnsNames `--dns` (repeatable), IpAddresses `--ip` (repeatable), LifetimeInDays `--lifetime-days` (UInt16, default 365) and KeySizeInBits `--key-size` (UInt16, default 0: the server's choice) | off | `push-certificates` |
| `--delete-certificate <typeId>` | DeleteCertificate (`i=19345`) of the group and this CertificateType | — | `push-certificates` |
| `--update-certificate <file>` | UpdateCertificate (`i=13737`, node-opcua's `updateCertificate`) of the group and `--certificate-type-id` with this certificate (PEM or DER) and the issuers `--issuer-certificate` (repeatable, PEM or DER) | — | `push-certificates` |
| `--update-private-key <file>` | The new private key of `--update-certificate`, sent as the PrivateKey ByteString as the file holds it | none (PrivateKeyFormat `""`) | `push-certificates` |
| `--private-key-format PEM\|PFX` | PrivateKeyFormat of `--update-private-key` | `PFX` for `.pfx` / `.p12` files, else `PEM` | `push-certificates` |
| `--csr` | CreateSigningRequest (group, `--certificate-type-id`, no subject, `regeneratePrivateKey` false) | off | |
| `--reset-to-defaults` | ResetToServerDefaults (`i=25709`) | off | `push-certificates` |
| `--apply` | ApplyChanges after the changes | off | |
| `--cancel` | CancelChanges (`i=25708`) after the changes; implied by `--create-self-signed` and `--delete-certificate` without `--apply`, so the created / deleted certificate is not installed | off | `push-certificates` |
| `--transaction-diagnostics` | Read the TransactionDiagnostics of ServerConfiguration (`i=32337`…`i=32342`, Part 12 §7.10.12) after ApplyChanges / CancelChanges; also after a failed ApplyChanges | off | `push-transaction-diagnostics` |

`--issuer`, `--csr`, `--apply`, `--cancel`, `--get-certificates`,
`--create-self-signed`, `--reset-to-defaults` and `--transaction-diagnostics`
are presence flags. A file that cannot be read, an unknown `--group`, a
malformed NodeId or a `--lifetime-days` / `--key-size` outside UInt16 is an
input error (exit 2) before connecting.

Steps, on one session (the transaction of Part 12 §7.10.2 is the session's),
stopping at the first Bad status: read the group's trust list (OpenWithMasks
All, Read, Close) → AddCertificate → RemoveCertificate → GetCertificates →
CreateSelfSignedCertificate → DeleteCertificate → UpdateCertificate →
CreateSigningRequest → GetRejectedList → ResetToServerDefaults → ApplyChanges
or CancelChanges → TransactionDiagnostics → read the trust list again. Exit
codes (§5): 0 success, 2 bad input, 3 connect / transport, 4 a method returned
a Bad status (`serviceResult` is that status, e.g. `BadUserAccessDenied`
without the SecurityAdmin role) or a TransactionDiagnostics variable could not
be read.

### `query` flags

Query service set (Part 4 §5.9), node-opcua and async-opcua (adapter 0.15.0,
`clientOperations` `query`). One QueryFirst with one NodeTypeDescription, no
View (the whole address space) and an empty ContentFilter (every node of the
type), then QueryNext while the server returns a continuation point.

```
<image> client query --endpoint <url> --type-definition <nodeId> [--include-subtypes]
        [--data-to-return <relativePath>[#<attribute>]]... [--max-data-sets <n>]
        [--max-references <n>] [--release-continuation-point] [--max-query-next <n>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--type-definition <nodeId>` | TypeDefinitionNode of the NodeTypeDescription (required) | — |
| `--include-subtypes` | IncludeSubTypes (presence flag, also `true` / `false`) | false |
| `--data-to-return <spec>` | A QueryDataDescription (repeatable, in order): a RelativePath in the text form of Part 4 Annex A.2 (`.Serial`: Aggregates; `/2:Name`: HierarchicalReferences; `<HasProperty>1:Name`; empty: the node itself), then `#` and an AttributeId by name (`Value`, `NodeId`, `BrowseName`, `DisplayName`, …) or number. `#` is reserved in the path syntax (`&#` escapes it), so the last unescaped `#` separates the attribute | no data, only NodeId and TypeDefinitionNode |
| `--max-data-sets <n>` | MaxDataSetsToReturn (UInt32) | 0 (no limit) |
| `--max-references <n>` | MaxReferencesToReturn (UInt32) | 0 (no limit) |
| `--release-continuation-point` | The first QueryNext has ReleaseContinuationPoint true; it is the last request | off |
| `--max-query-next <n>` | Most QueryNext requests | 100 |

Exit codes (§5): 0 every request Good, 2 bad input (before connecting), 3
connect / transport, 4 QueryFirst or a QueryNext failed (`serviceResult`; the
result is printed with the steps so far). The ParsingResults are reported,
they do not affect `success`.

### `history-read` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | Node to read historically | required |
| `--start <rfc3339>` | Start time (inclusive), UTC RFC 3339 | required |
| `--end <rfc3339>` | End time (inclusive), UTC RFC 3339 | required |
| `--num-values <n>` | Max values per node (`NumValuesPerNode`) | 0 (server default / unlimited) |
| `--continuation-point <b64>` | Continue a prior HistoryRead | — |
| `--release-continuation-point <true\|false>` | Release the continuation point instead of reading | `false` |
| `--return-bounds <true\|false>` | `ReadRawModifiedDetails.ReturnBounds` | `false` |
| `--timestamps <Source\|Server\|Both\|Neither>` | `TimestampsToReturn` | `Both` |
| `--scenario continue` | Single-session page → continue → release → reuse-after-release | — |

Raw HistoryRead only (`IsReadModified = false`). Continuation points are
Base64-encoded ByteStrings when present.

With `--scenario continue`, one connected session pages with `--num-values`
(default 2), follows continuation points, releases the last CP, then attempts
reuse after release. The result item includes `scenario`, `pages`,
`releaseStatusCode`, and `reuseAfterReleaseStatusCode`.

Adapter servers expose gate-compliant fixed raw samples on
`History.Temperature` (5 values from `2026-07-24T10:00:00Z` step 5s).

### `history-read-events` flags

HistoryRead with ReadEventDetails (Part 11 §6.5.2) on one or more nodes
(adapter 0.17.0, `clientOperations` `history-read-events`, §17).

```
<image> client history-read-events --endpoint <url> --node <nodeId> [--node <nodeId>]...
        [--start <rfc3339>] [--end <rfc3339>] [--num-values <n>] [--select <path>]...
        [--of-type <nodeId>] [--min-severity <n>] [--continuation-point <b64>]
        [--release-continuation-point] [--timestamps source|server|both|neither]
        [--scenario continue [--max-pages <n>]]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | Event notifier to read (repeatable: one HistoryReadValueId each, one result each) | required |
| `--start <rfc3339>` | `ReadEventDetails.StartTime` | null DateTime |
| `--end <rfc3339>` | `ReadEventDetails.EndTime` | null DateTime |
| `--num-values <n>` | `NumValuesPerNode` (UInt32) | 0 (no client limit) |
| `--select <path>` | A SelectClause (repeatable, in order): `TypeDefinitionId` BaseEventType (`i=2041`), AttributeId Value, the BrowsePath from `/`-separated names; a name is `ns:Name` in another namespace, else namespace 0 (`Severity`, `2:Vendor/2:Detail`) | `EventId`, `EventType`, `SourceNode`, `SourceName`, `Time`, `ReceiveTime`, `Message`, `Severity` |
| `--of-type <nodeId>` | WhereClause element OfType with this event type (subtypes match) | — |
| `--min-severity <n>` | WhereClause element GreaterThanOrEqual(`Severity`, UInt16 `n`) | — |
| `--continuation-point <b64>` | The ContinuationPoint of the HistoryReadValueId (one `--node` only) | — |
| `--release-continuation-point` | `ReleaseContinuationPoints` true (presence flag; `false` after it turns it off); needs `--continuation-point` | off |
| `--timestamps <v>` | `TimestampsToReturn`, sent as given (any case). Part 11 ignores it for events | `both` |
| `--scenario continue` | Per node on one session: HistoryRead, then HistoryRead with each returned continuation point until none is left or `--max-pages` requests were sent; then release the last continuation point received and send it once more | — |
| `--max-pages <n>` | Most HistoryRead requests per node of `--scenario continue` | 8 |

The WhereClause is empty without `--of-type` and `--min-severity`, a single
element with one of them, and with both
`[And(ElementOperand 1, ElementOperand 2), OfType, GreaterThanOrEqual]`:
element 0 is the root of a ContentFilter and an ElementOperand refers to a
later element (Part 4 §7.7.1; UA-.NETStandard 2.0.1 answers
`BadEventFilterInvalid` for an `And` after its operands). The SelectClauses
of `event-subscribe` are unchanged.

Exit codes (§5): 0 the service result is Good and no node result is Bad
(`GoodNoData` included), 2 bad input (before connecting), 3 connect /
transport, 4 a service fault or a Bad node result (`serviceResult` is the
fault or the first Bad node status; the results are printed), 7 timeout.

### `history-update-events` flags

HistoryUpdate of events on one node (adapter 0.17.0, `clientOperations`
`history-update-events`, §17): UpdateEventDetails (Part 11 §6.9.4) for
`insert`, `replace` and `update`, DeleteEventDetails (§6.9.7) for `delete`.

```
<image> client history-update-events --endpoint <url> --node <nodeId>
        --perform insert|replace|update [--select <path>]... --event <json> [--event <json>]...
<image> client history-update-events --endpoint <url> --node <nodeId>
        --perform delete --event-id <b64> [--event-id <b64>]...
```

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | The historizing notifier (`UpdateEventDetails.NodeId`) | required |
| `--perform <op>` | `insert`, `replace`, `update` (`PerformInsertReplace` Insert / Replace / Update) or `delete` (DeleteEventDetails) | required |
| `--select <path>` | The SelectClauses of the UpdateEventDetails filter (repeatable, in order; the path syntax of `history-read-events`); no WhereClause is sent | the keys of the `--event` objects, in order of first appearance |
| `--event <json>` | One `EventData` entry (repeatable, in order): a JSON object keyed by select path; the fields are sent in `--select` order, a path the object does not have is a null Variant. A value is `{"type": "<built-in type>", "value": <§7 encoding>}`, or a bare JSON string (String), boolean (Boolean), integer (Int32), other number (Double) or `{"locale", "text"}` object (LocalizedText). A key that is not a `--select` path is an input error | — |
| `--event-id <b64>` | `DeleteEventDetails.EventIds` entry (repeatable) | — |

```bash
--event '{"EventId":{"type":"ByteString","value":"aGlzdC1ldnQtNQ=="},"EventType":{"type":"NodeId","value":"i=2041"},
          "Time":{"type":"DateTime","value":"2026-07-24T10:00:25Z"},"Severity":{"type":"UInt16","value":600},
          "Message":{"type":"LocalizedText","value":{"locale":"en","text":"inserted"}},"SourceName":"History.Events"}'
```

The value of a `NodeId` field is a NodeId string (§8, `nsu=` resolved on the
server), a `ByteString` Base64, a `DateTime` RFC 3339, a `StatusCode` a
number or `{"code": n}`, a `QualifiedName` `"ns:Name"` or `{"ns", "name"}`.

Exit codes (§5): 0 the service result and the node's StatusCode are not Bad;
the `operationResults` are reported as the server returns them, also when
some are Bad (tests assert them). 2 bad input (before connecting), 3 connect
/ transport, 4 a service fault or a Bad node StatusCode, 7 timeout.

### `republish` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--subscription-id <n>` | Subscription to republish from | required |
| `--sequence-number <n>` | `RetransmitSequenceNumber` | required |

### `transfer-subscriptions` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--subscription-id <n>` | Subscription id to transfer (repeatable) | required (≥1) |
| `--send-initial-values <true\|false>` | `SendInitialValues` | `false` |

### `register-nodes` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | NodeId to register (repeatable) | required (≥1) |

One session: RegisterNodes → Read `Value` through each returned alias →
UnregisterNodes. `success` when every read and the unregister are Good.

### `node-management` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--parent <nodeId>` | Parent node; the new node is added with `HasComponent` | required |
| `--node <nodeId>` | Requested NodeId of the new Variable | required |
| `--browse-name <name>` | BrowseName / DisplayName (namespace of `--node`) | `InteropAdded` |
| `--value <int32>` | Initial Int32 value | `42` |

One session: AddNodes (Int32 `BaseDataVariableType` Variable) → Read →
DeleteNodes (`DeleteTargetReferences=true`) → Read again. `success` when the add,
read-back (value equals `--value`) and delete are Good **and** the read after
delete is Bad. A server without NodeManagement yields exit 4 with the service
fault (typically `BadServiceUnsupported`) in `serviceResult`.

### `find-servers-on-network` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--endpoint <url>` | Discovery URL of the LDS | required |
| `--starting-record-id <n>` | `StartingRecordId` | 0 |
| `--max-records <n>` | `MaxRecordsToReturn` (0 = no limit) | 0 |
| `--capability <cap>` | `ServerCapabilityFilter` entry (repeatable) | none |

Runs on a SecureChannel without a Session. A server without an mDNS-enabled LDS
answers with a service fault (`BadNotImplemented` / `BadServiceUnsupported`) →
exit 4.

### `register-server` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--endpoint <url>` | Discovery URL of the LDS | required |
| `--server-uri <uri>` | `RegisteredServer.ServerUri` | required |
| `--discovery-url <url>` | `RegisteredServer.DiscoveryUrls` entry (repeatable) | required (≥1) |
| `--server-name <text>` | `ServerNames[0].Text` | the server URI |
| `--server-name-locale <l>` | `ServerNames[0].Locale` | `en` |
| `--product-uri <uri>` | `ProductUri` | empty |
| `--server-type <t>` | `Server`, `Client`, `ClientAndServer`, `DiscoveryServer` | `Server` |
| `--gateway-server-uri <uri>` | `GatewayServerUri` | — |
| `--semaphore-file <path>` | `SemaphoreFilePath` | — |
| `--online <true\|false>` | `IsOnline`; `false` unregisters | `true` |
| `--service <auto\|RegisterServer2\|RegisterServer>` | Service to call. `auto`: RegisterServer2, then RegisterServer when the LDS answers `BadServiceUnsupported` / `BadNotImplemented` / `BadNotSupported` | `auto` |
| `--mdns-name <name>` | `MdnsDiscoveryConfiguration.MdnsServerName` (RegisterServer2) | the server name |
| `--capability <cap>` | `MdnsDiscoveryConfiguration.ServerCapabilities` entry (repeatable) | none |

Runs on a SecureChannel without a Session (the open62541 adapter honours the
global security flags for the channel; the Milo adapter always uses
None/None). Unregister with the same `--server-uri` and `--mdns-name` that were
registered.

### `codec` flags

```
codec encode --format json|xml --type <Type|Type[]> --value <literal> [--dimensions d1,d2,..]
             [--status <uint32>] [--source-timestamp <rfc3339>] [--server-timestamp <rfc3339>]
             [--source-picoseconds <n>] [--server-picoseconds <n>]
codec encode --format json|xml --endpoint <url> --node <nodeId>
codec decode --format json|xml --type <BuiltInType|Variant|DataValue>
             [--document <text> | --input <file>]          (default: stdin)

codec --endpoint <url> --node <nodeId> [--node ...]        (short form: both formats per node)
codec --decode json|xml --type <BuiltInType|Variant|DataValue>   (short form of decode)

codec pubsub-uadp-encode | pubsub-uadp-decode | pubsub-json-encode | pubsub-json-decode
             [--document <text> | --input <file>]          (default: stdin)
             [--metadata <json> | --metadata-file <file>]   (PubSub NetworkMessages, §14.9)

pubsub-discover --url opc.udp://<host>:<port>
             [--type DataSetMetaData|DataSetWriterConfiguration] [--writer-ids <id>,…]
             [--publisher-id <UInt16>] [--timeout-ms <n>]   (UADP discovery probe, dotnet, §14.13)
```

| Flag | Description |
|------|-------------|
| `--format json\|xml` | DataEncoding (`--decode json\|xml` is accepted as a synonym in the short form) |
| `--type` / `--value` / `--dimensions` | Locally constructed value, literal grammar of §12. `--dimensions` turns a `Type[]` into a matrix |
| `--status`, `--source-timestamp`, `--server-timestamp`, `--source-picoseconds`, `--server-picoseconds` | Optional members of the DataValue built around a literal (decimal or `0x` status) |
| `--node` + `--endpoint` | Read the Value attribute (TimestampsToReturn=Both) and encode what the server returned. Global security / identity flags apply |
| `--json-mode compact\|verbose` | JSON flavour. open62541: `compact` only (anything else is exit 2). Milo: both |
| `--namespace-uri <uri>` | Milo only, repeatable: namespace table (index 1, 2, …) for literals. The 1.05 JSON encoding writes namespace **URIs**, so Milo cannot encode a NodeId / QualifiedName / ExpandedNodeId with a non-zero namespace index it has no URI for (`Bad_EncodingError`). For `--node` the server's NamespaceArray is used |
| `--document <text>` / `--input <file>` | Document to decode; otherwise it is read from stdin (run the container with `-i`). Trailing whitespace is ignored |

Both stacks implement the **OPC UA 1.05 JSON encoding** (`UaType` / `Value` /
`Dimensions`, NodeIds as strings, StatusCode as `{"Code":…}`), not the legacy
1.04 `Type` / `Body` form. Arrays are decoded with `--type Variant`.

### Channel renewal (`--channel-lifetime-ms`)

Combine with a long-running command (typically `subscribe` with enough
`--notifications` to span several lifetimes) to prove SecurityToken renewal:
both stacks renew at 75% of the revised lifetime, so the command only completes
if every renewal succeeded and traffic continued on the new token. Use
lifetimes of 5000 ms or more: the open62541 client schedules renewal coarsely,
so with very short lifetimes its old token can expire inside the 25% window.

---

## 2. Output streams

**Stdout** — exactly one JSON object per invocation, terminated by `\n`, valid UTF-8.
No other text is written to stdout.

**Stderr** — human-readable diagnostics, log lines. Never machine-parsed.

---

## 3. Result envelope

Every command produces exactly this top-level shape:

```json
{
  "schemaVersion": "1.0",
  "adapter":        "<string>",
  "operation":      "<string>",
  "success":        <bool>,
  "serviceResult":  { "name": "<string>", "code": <uint32>, "severity": "<string>" },
  "results":        [ ... ],
  "error":          null | { "category": "<string>", "message": "<string>" }
}
```

Fields are always present in this order. `results` is always an array (empty `[]`
when not applicable). `error` is always either `null` or an error object.

### `adapter`

One of: `"open62541"`, `"milo"`, `"async-opcua"`, `"dotnet"`, `"node-opcua"`, `"asyncua"`, and `"otfabric"` for the image of OT Fabric's own stack (`own/go-opcua/README.md`). Never abbreviated or versioned in this field.

### `serviceResult`

The top-level OPC UA service-call status code:

```json
{ "name": "Good",              "code": 0,          "severity": "Good" }
{ "name": "BadNodeIdUnknown",  "code": 2150891520,  "severity": "Bad"  }
{ "name": "BadTypeMismatch",   "code": 2155085824,  "severity": "Bad"  }
```

`name` is the symbolic OPC UA name (see Part 6, Annex A). `code` is the 32-bit
unsigned decimal integer. `severity` is one of `"Good"`, `"Uncertain"`, `"Bad"`.

For commands that do not correspond to a single OPC UA service call (e.g.
`endpoints` discovery), use `{"name":"Good","code":0,"severity":"Good"}` on
success, or the transport error code on failure.

### `error`

Present (non-null) only when `success` is `false`.

```json
{
  "category": "input",
  "message":  "malformed NodeId: 'nsu=missing'"
}
```

Error categories:

| Category | Meaning |
|----------|---------|
| `input` | Invalid command-line argument, malformed NodeId, unresolvable namespace URI |
| `transport` | TCP connect failure, hello timeout, network error |
| `service` | OPC UA service returned a bad status code |
| `timeout` | Operation exceeded its configured timeout |
| `internal` | Unexpected adapter-internal failure |

`message` is free-form human text. Do not parse it.

---

## 4. Operation-specific `results` shapes

### `endpoints`

```json
"results": [
  {
    "url":            "opc.tcp://server:4840/opcua-interop",
    "securityPolicy": "http://opcfoundation.org/UA/SecurityPolicy#None",
    "securityMode":   "None"
  }
]
```

### `find-servers`

```json
"results": [
  {
    "applicationUri":  "urn:example:server",
    "applicationName": { "locale": "en", "text": "Example Server" },
    "productUri":      "urn:example:product",
    "discoveryUrls":   ["opc.tcp://server:4840/opcua-interop"]
  }
]
```

`applicationName` is a LocalizedText object (§7). Empty locale/text are emitted as `""`.

### `read`

```json
"results": [
  {
    "nodeId":          "ns=1;s=Scalar.Int32",
    "statusCode":      { "name": "Good", "code": 0, "severity": "Good" },
    "dataType":        "Int32",
    "builtInType":     6,
    "value":           -123456789,
    "sourceTimestamp": "2024-01-01T00:00:00.000Z"
  }
]
```

`nodeId` is the canonical compact string form (see §6).
`dataType` is the OPC UA built-in type name.
`builtInType` is the built-in type integer (1=Boolean … 25=DiagnosticInfo).
`sourceTimestamp` is RFC 3339 UTC; omitted when zero/null.

### `write`

```json
"results": [
  {
    "nodeId":     "ns=1;s=Access.ReadWrite",
    "statusCode": { "name": "Good", "code": 0, "severity": "Good" }
  }
]
```

### `browse`

```json
"results": [
  {
    "referenceTypeId": "ns=0;i=35",
    "isForward":       true,
    "nodeId":          "ns=1;s=Compatibility",
    "browseName":      { "ns": 1, "name": "Compatibility" },
    "displayName":     { "locale": "en", "text": "Compatibility" },
    "nodeClass":       "Object"
  }
]
```

`nodeClass` is the symbolic name from OPC UA Part 3: `"Object"`, `"Variable"`,
`"Method"`, `"ObjectType"`, `"VariableType"`, `"ReferenceType"`, `"DataType"`,
`"View"`.

### `translate`

```json
"results": [
  {
    "statusCode": { "name": "Good", "code": 0, "severity": "Good" },
    "targets":    ["i=2253"]
  }
]
```

One result object for the single requested browse path. `targets` is an ordered
array of canonical NodeId strings (§6) from `BrowsePathTarget.TargetId`.
`success` is `true` when the service result and the path `statusCode` are both Good.

### `call`

```json
"results": [
  {
    "objectNodeId": "ns=1;s=Methods",
    "methodNodeId": "ns=1;s=Methods.Add",
    "statusCode":   { "name": "Good", "code": 0, "severity": "Good" },
    "outputArguments": [ 30 ]
  }
]
```

`outputArguments` is an ordered array of values encoded per §7. An empty array `[]`
means the method returned no output arguments.

### `subscribe`

```json
"results": [
  {
    "nodeId":                    "ns=1;s=Dynamic.Counter",
    "subscriptionId":            1,
    "revisedPublishingInterval": 500.0,
    "revisedLifetimeCount":      150,
    "revisedMaxKeepAliveCount":  50,
    "monitoredItemStatusCode":   { "name": "Good", "code": 0, "severity": "Good" },
    "notifications": [
      {
        "sequenceNumber":  1,
        "value":           0,
        "dataType":        "UInt32",
        "builtInType":     7,
        "statusCode":      { "name": "Good", "code": 0, "severity": "Good" },
        "sourceTimestamp": "2024-01-01T00:00:00.000Z",
        "serverTimestamp": "2024-01-01T00:00:00.100Z"
      }
    ]
  }
]
```

When (and only when) a DataChangeFilter was requested with `--deadband-absolute`,
`--deadband-percent` or `--trigger`, the result item additionally carries,
between `monitoredItemStatusCode` and `notifications`:

```json
    "monitoredItemId":         1,
    "revisedSamplingInterval": 100.0,
    "revisedQueueSize":        1,
    "filter":       { "trigger": "StatusValue", "deadbandType": "Absolute", "deadbandValue": 10.0 },
    "filterResult": null,
```

`filter` echoes the request (`deadbandType` is `None`, `Absolute` or `Percent`).
`filterResult` is `null` when the server returned no filter result (the normal
case for a DataChangeFilter), otherwise `{"typeId": "<NodeId>"}`. When the
monitored item is rejected, `success` is `false`, `serviceResult` and
`monitoredItemStatusCode` carry the status, `error.category` is `"service"`,
`notifications` is empty and the exit code is 4.

`subscriptionId` is the server-assigned subscription identifier (uint32, always present).  
`revisedPublishingInterval` is the server-revised publishing interval in milliseconds.  
`revisedLifetimeCount` and `revisedMaxKeepAliveCount` are the server-revised subscription counts.

`sourceTimestamp` / `serverTimestamp` are omitted when the corresponding timestamp is
absent from the DataValue (for example under `--timestamps Neither`).

The command collects exactly `--notifications` data-change events then disconnects.
If the timeout expires before enough notifications arrive, the command emits whatever
was collected, sets `success: false`, and exits 7.

### `subscription-lifecycle`

Operation name in the JSON envelope: `"subscription-lifecycle"`.

#### scenario `revise`

```json
"results": [
  {
    "subscriptionId":              1,
    "requestedPublishingInterval": 1,
    "requestedLifetimeCount":      5,
    "requestedMaxKeepAliveCount":  10,
    "revisedPublishingInterval":   100.0,
    "revisedLifetimeCount":        30,
    "revisedMaxKeepAliveCount":    10
  }
]
```

`success` is `true` when `revisedLifetimeCount >= 3 * revisedMaxKeepAliveCount` AND
`revisedPublishingInterval >= 10`.

#### scenario `publishing-mode`

```json
"results": [
  {
    "subscriptionId":            1,
    "revisedPublishingInterval": 500.0,
    "revisedLifetimeCount":      150,
    "revisedMaxKeepAliveCount":  50,
    "overflow":                  true,
    "values":                    [3, 4, 5]
  }
]
```

`values` holds the Int32 values received after re-enabling publishing.
`overflow` is `true` when the server discarded items from the queue.
`success` when the final window of received values equals `[3,4,5]` (newest 3 of 5 writes).

#### scenario `monitoring-mode`

```json
"results": [
  {
    "subscriptionId": 1,
    "modeSteps": [
      { "mode": "Disabled",  "notificationCount": 0 },
      { "mode": "Sampling",  "notificationCount": 0 },
      { "mode": "Reporting", "notificationCount": 1 }
    ]
  }
]
```

`success` when `Disabled.notificationCount == 0` AND `Reporting.notificationCount >= 1`.

#### scenario `delete`

```json
"results": [
  {
    "subscriptionId": 1,
    "deleteMonitoredItem": {
      "first":  { "name": "Good", "code": 0, "severity": "Good" },
      "second": { "name": "BadMonitoredItemIdInvalid", "code": 2153644032, "severity": "Bad" }
    },
    "deleteSubscription": {
      "first":  { "name": "Good", "code": 0, "severity": "Good" },
      "second": { "name": "BadSubscriptionIdInvalid", "code": 2149580800, "severity": "Bad" }
    }
  }
]
```

`success` when the `second` statuses are both `Bad` severity.

### `event-subscribe`

```json
"results": [
  {
    "nodeId":                    "ns=1;s=Events.Source",
    "subscriptionId":            1,
    "revisedPublishingInterval": 500.0,
    "monitoredItemStatusCode":   { "name": "Good", "code": 0, "severity": "Good" },
    "selectClauses":             ["EventId", "EventType", "SourceName", "Message", "Severity", "Time"],
    "events": [
      {
        "sequenceNumber": 1,
        "fields": [
          { "name": "EventId",    "dataType": "ByteString",    "builtInType": 15, "value": "dGVzdA==" },
          { "name": "EventType",  "dataType": "NodeId",        "builtInType": 17, "value": "i=2041" },
          { "name": "SourceName", "dataType": "String",        "builtInType": 12, "value": "Events.Source" },
          { "name": "Message",    "dataType": "LocalizedText", "builtInType": 21, "value": { "locale": "en", "text": "peer-event" } },
          { "name": "Severity",   "dataType": "UInt16",        "builtInType": 5,  "value": 500 },
          { "name": "Time",       "dataType": "DateTime",      "builtInType": 13, "value": "2024-01-01T00:00:00Z" }
        ]
      }
    ]
  }
]
```

If the timeout expires before `--events` arrive, emit whatever was collected,
set `success: false`, and exit 7.

### `alarms`

```json
"results": [
  {
    "nodeId":                  "i=2253",
    "subscriptionId":          1,
    "monitoredItemStatusCode": { "name": "Good", "code": 0, "severity": "Good" },
    "refresh":    { "statusCode": { "name": "Good", "code": 0, "severity": "Good" }, "startSeen": true, "endSeen": true },
    "conditions": [ <ConditionEntry>, ... ],
    "target":     <ConditionEntry> | null,
    "acknowledge": { "statusCode": {…}, "event": <ConditionEntry> | null, "repeatStatusCode": {…} | null } | null,
    "confirm":     { "statusCode": {…}, "event": <ConditionEntry> | null } | null,
    "addComment":  { "statusCode": {…}, "event": <ConditionEntry> | null } | null
  }
]
```

ConditionEntry (keys in this order):

```json
{ "conditionId": "ns=2;s=Alarms.InteropAlarm", "eventId": "wR6R9sSPvESOnQdbmEapRQ==", "eventType": "i=2915",
  "sourceNode": "ns=2;s=Alarms.Source", "sourceName": "Alarms.Source", "conditionName": "InteropAlarm",
  "time": "2026-10-25T01:35:19.464Z", "message": "interop-alarm", "severity": 500,
  "retain": true, "enabled": true, "acked": true, "confirmed": false, "active": true, "comment": "interop-comment" }
```

NodeIds in the canonical form (§6), `eventId` base64, `time` the adapter's
DateTime string (RFC 3339 UTC; the fractional digits are adapter-specific as in
`event-subscribe`), `message` / `comment` the LocalizedText text only. A field
whose event value is null, absent, a StatusCode (e.g. `confirmed` of a
condition without ConfirmedState), of an unexpected type, or the null DateTime
(1601-01-01, encoded 0) is JSON `null`. A non-requested action is `null`;
`repeatStatusCode` is `null` unless the first Acknowledge was Good and its
event arrived. When CreateMonitoredItems fails, `refresh` carries that status
with `startSeen` / `endSeen` false.

### `push`

```json
"results": [
  {
    "trustList": { "specifiedLists": 15, "trustedCertificates": ["<base64 DER>", …],
                   "trustedCrls": […], "issuerCertificates": […], "issuerCrls": […] },
    "addCertificateStatus":       { "name": "Good", "code": 0, "severity": "Good" },
    "removeCertificateStatus":    { … },
    "createSigningRequestStatus": { … },
    "certificateSigningRequest":  "<base64 PKCS #10 DER>",
    "getRejectedListStatus":      { … },
    "rejectedCertificates":       ["<base64 DER>", …],
    "applyChangesStatus":         { … },
    "trustListAfter":             { … }
  }
]
```

Since adapter 0.15.0 (the 0.15.0 flags of §1 "push flags"):

```json
"results": [
  {
    "certificateGroupId":                "i=14156",
    "trustList":                         { … },
    "addCertificateStatus":              { … },
    "removeCertificateStatus":           { … },
    "getCertificatesStatus":             { … },
    "certificateTypeIds":                ["i=12560", …],
    "certificates":                      ["<base64 DER>", …],
    "createSelfSignedCertificateStatus": { … },
    "selfSignedCertificate":             "<base64 DER>",
    "deleteCertificateStatus":           { … },
    "updateCertificateStatus":           { … },
    "applyChangesRequired":              true,
    "createSigningRequestStatus":        { … },
    "certificateSigningRequest":         "<base64 PKCS #10 DER>",
    "getRejectedListStatus":             { … },
    "rejectedCertificates":              ["<base64 DER>", …],
    "resetToServerDefaultsStatus":       { … },
    "applyChangesStatus":                { … },
    "cancelChangesStatus":               { … },
    "transactionDiagnosticsStatus":      { … },
    "transactionDiagnostics": {
      "startTime": "2026-10-25T10:00:00.000Z", "endTime": "2026-10-25T10:00:00.010Z",
      "result": { "name": "Good", "code": 0, "severity": "Good" },
      "affectedTrustLists": ["i=12642"], "affectedCertificateGroups": ["i=14156"],
      "errors": [ { "targetId": "i=14156", "error": { … }, "message": "…" } ]
    },
    "trustListAfter":                    { … }
  }
]
```

`certificateGroupId` (the group of `--group`) is always present. A `…Status`
key and the values of its step are present only for a step that ran; the keys
after a failed step are absent, except `transactionDiagnosticsStatus` /
`transactionDiagnostics`, which follow a failed ApplyChanges too.
`certificateTypeIds[i]` is the type of `certificates[i]` (GetCertificates).
`transactionDiagnostics` is absent when a variable could not be read
(`transactionDiagnosticsStatus` is then that status); its times are the
adapter's DateTime strings (null for the null DateTime), `errors` the
TransactionErrorType entries (`message` the LocalizedText text or null).
`trustList` / `trustListAfter` hold all four lists (base64 DER certificates
and CRLs) of the group's TrustList.

### `query`

```json
"results": [
  {
    "typeDefinitionNode": "ns=2;s=QueryType",
    "queryFirst": {
      "statusCode": { "name": "Good", "code": 0, "severity": "Good" },
      "continuationPoint": "<base64>" | null,
      "parsingResults": [ { "statusCode": {…}, "dataStatusCodes": [ {…}, … ] } ],
      "queryDataSets": [ <QueryDataSet>, … ]
    },
    "queryNext": [
      { "statusCode": {…}, "releaseContinuationPoint": false,
        "revisedContinuationPoint": "<base64>" | null, "queryDataSets": [ <QueryDataSet>, … ] }
    ],
    "queryDataSets": [ <QueryDataSet>, … ]
  }
]
```

QueryDataSet: `{ "nodeId": "ns=2;s=Query.1", "typeDefinitionNode": "ns=2;s=QueryType", "values": [ { "dataType": "String", "builtInType": 12, "value": "A-1" }, … ] }`
— NodeIds in the canonical form (§6; an ExpandedNodeId with a namespace URI
or server index in the `nsu=` / `svr=` form), one value per
`--data-to-return`, in order, as in `read` (§7; a value the server leaves
empty is `{"dataType": "Null", "builtInType": 0, "value": null}`).
`queryDataSets` at the top level is QueryFirst's followed by every
QueryNext's. `queryNext` has one entry per QueryNext request.

`queryFirst.statusCode` is the service result of QueryFirst (with its
`queryDataSets` empty and `queryNext` `[]` when it failed).

### `history-read`

```json
"results": [
  {
    "nodeId":            "ns=1;s=History.Temperature",
    "statusCode":        { "name": "Good", "code": 0, "severity": "Good" },
    "continuationPoint": null,
    "values": [
      {
        "value":           20.0,
        "dataType":        "Double",
        "builtInType":     11,
        "statusCode":      { "name": "Good", "code": 0, "severity": "Good" },
        "sourceTimestamp": "2026-07-24T10:00:00Z",
        "serverTimestamp": "2026-07-24T10:00:00Z"
      }
    ]
  }
]
```

`continuationPoint` is a Base64 string when the server returns one, otherwise
`null`. Timestamps omitted when absent. Fixture baseline returns five Doubles
`20`…`24` at 5s steps from `2026-07-24T10:00:00Z`.

### `history-read-events`

```json
"results": [
  {
    "nodeId":            "ns=2;s=History.Events",
    "statusCode":        { "name": "Good", "code": 0, "severity": "Good" },
    "continuationPoint": "<base64>" | null,
    "selectClauses":     ["EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"],
    "events": [
      {
        "fields": [
          { "name": "EventId",     "dataType": "ByteString",    "builtInType": 15, "value": "aGlzdC1ldnQtMA==" },
          { "name": "EventType",   "dataType": "NodeId",        "builtInType": 17, "value": "i=2041" },
          { "name": "SourceNode",  "dataType": "NodeId",        "builtInType": 17, "value": "ns=2;s=History.Events" },
          { "name": "SourceName",  "dataType": "String",        "builtInType": 12, "value": "History.Events" },
          { "name": "Time",        "dataType": "DateTime",      "builtInType": 13, "value": "2026-07-24T10:00:00.000Z" },
          { "name": "ReceiveTime", "dataType": "DateTime",      "builtInType": 13, "value": "2026-07-24T10:00:00.000Z" },
          { "name": "Message",     "dataType": "LocalizedText", "builtInType": 21, "value": { "locale": "en", "text": "history-event-0" } },
          { "name": "Severity",    "dataType": "UInt16",        "builtInType": 5,  "value": 100 }
        ]
      }
    ]
  }
]
```

One result per `--node`, in order. `statusCode` is the node's
HistoryReadResult StatusCode (`GoodNoData` for a range without events), or
the service result when the request failed. `selectClauses` are the
`--select` paths as given, and each event's `fields` follow them by index
(`name` is the path); a server that returns fewer fields gives fewer. The
values are encoded as in §7 (as `event-subscribe`): a field the server leaves
empty is `builtInType` 0 with `value` null (`dataType` `"Null"`, or
`"Unknown"` in the dotnet and Milo adapters), a StatusCode field is the §7
StatusCode object. DateTime values have the §7 precision of the adapter;
the fixture times are whole seconds.

With `--scenario continue` each result also has

```json
"scenario": "continue",
"pages": [
  { "statusCode": {…}, "continuationPoint": "<base64>" | null, "events": [ … ] }
],
"releaseStatusCode":           { "name": "BadContinuationPointInvalid", … } | null,
"reuseAfterReleaseStatusCode": { "name": "BadContinuationPointInvalid", … } | null
```

`pages` has one entry per HistoryRead request; `events` at the result level
is all pages' events in order, `statusCode` / `continuationPoint` are the
last page's. `releaseStatusCode` is the node status of the request with
`ReleaseContinuationPoints` true and the last continuation point the node
returned, `reuseAfterReleaseStatusCode` that of reading with it once more;
both are `null` when the server returned no continuation point. When the
pages run out normally, that last continuation point has already been
consumed by the next request.

### `history-update-events`

```json
"results": [
  {
    "nodeId":            "ns=2;s=History.Events",
    "performUpdateType": "Insert",
    "statusCode":        { "name": "Good", "code": 0, "severity": "Good" },
    "operationResults":  [
      { "name": "GoodEntryInserted", "code": 10616832, "severity": "Good" },
      { "name": "BadEntryExists",    "code": 2157903872, "severity": "Bad" }
    ]
  }
]
```

`performUpdateType` is `Insert`, `Replace`, `Update` or `Delete`;
`statusCode` the HistoryUpdateResult StatusCode, `operationResults` its
OperationResults (one per `--event` / `--event-id`, as the server returns
them). Status names as in §3 (Milo spells them with an underscore,
`Good_EntryInserted`; compare `code`). A service fault gives `results: []`.

### `republish`

```json
"results": [
  {
    "subscriptionId":           1,
    "retransmitSequenceNumber": 3,
    "sequenceNumber":           3,
    "publishTime":              "2024-01-01T00:00:00.000Z",
    "notificationDataCount":    1
  }
]
```

`sequenceNumber` / `publishTime` / `notificationDataCount` come from the
returned `NotificationMessage` on success. On service failure they may be
omitted or zeroed; `serviceResult` carries the fault.

### `transfer-subscriptions`

```json
"results": [
  {
    "subscriptionId":           1,
    "statusCode":               { "name": "Good", "code": 0, "severity": "Good" },
    "availableSequenceNumbers": [2, 3]
  }
]
```

One result object per requested `--subscription-id`, in request order.

### `register-nodes`

```json
"results": [
  {
    "nodeId":               "ns=1;s=Scalar.Int32",
    "registeredNodeId":     "ns=1;s=Scalar.Int32",
    "statusCode":           { "name": "Good", "code": 0, "severity": "Good" },
    "dataType":             "Int32",
    "builtInType":          6,
    "value":                -123456789,
    "unregisterStatusCode": { "name": "Good", "code": 0, "severity": "Good" }
  }
]
```

One result object per `--node`, in request order. `registeredNodeId` is whatever
alias the server returned (servers may return the original NodeId).
`dataType` / `builtInType` / `value` are present only when the read is Good.

### `node-management`

```json
"results": [
  {
    "parentNodeId":              "ns=1;s=Compatibility",
    "requestedNodeId":           "ns=1;s=Interop.Added",
    "addStatusCode":             { "name": "Good", "code": 0, "severity": "Good" },
    "addedNodeId":               "ns=1;s=Interop.Added",
    "readStatusCode":            { "name": "Good", "code": 0, "severity": "Good" },
    "dataType":                  "Int32",
    "builtInType":               6,
    "value":                     42,
    "deleteStatusCode":          { "name": "Good", "code": 0, "severity": "Good" },
    "readAfterDeleteStatusCode": { "name": "BadNodeIdUnknown", "code": 2150891520, "severity": "Bad" }
  }
]
```

Fields after `addStatusCode` are present only when the add succeeded.

### `find-servers-on-network`

```json
"results": [
  {
    "recordId":             1,
    "serverName":           "smoke-member-a1b2c3",
    "discoveryUrl":         "opc.tcp://member:4840/opcua-interop",
    "serverCapabilities":   ["NA"],
    "lastCounterResetTime": "2026-10-11T15:26:38.230Z"
  }
]
```

One item per `ServerOnNetwork` record. `lastCounterResetTime` is the response's
value repeated on every record (omitted when the server sent none).

### `register-server`

```json
"results": [
  {
    "service":                   "RegisterServer2",
    "serverUri":                 "urn:example:server",
    "isOnline":                  true,
    "statusCode":                { "name": "Good", "code": 0, "severity": "Good" },
    "fallback":                  false,
    "registerServer2StatusCode": { "name": "Good", "code": 0, "severity": "Good" },
    "configurationResults":      [ { "name": "Good", "code": 0, "severity": "Good" } ]
  }
]
```

`service` is the service whose result counts (`statusCode`, also the envelope's
`serviceResult`). `fallback` is `true` when RegisterServer2 was answered with
"unsupported" and RegisterServer was called instead. `registerServer2StatusCode`
is present whenever RegisterServer2 was attempted. `configurationResults` are
the RegisterServer2 per-configuration results (empty for RegisterServer).
`success` when `statusCode` and every configuration result are Good; otherwise
exit 4.

### `codec`

Operation name `"codec"`. Documents are embedded as JSON **strings**, byte-exact
as the stack produced them. `binary` values are the OPC UA Binary encoding of
the same value in Base64 — compare these for bit-exactness.

`codec encode`:

```json
"results": [
  {
    "action":      "encode",
    "format":      "json",
    "jsonMode":    "compact",
    "source":      "literal",
    "dataType":    "Int32",
    "builtInType": 6,
    "valueRank":   2,
    "arrayDimensions": [2, 3],
    "value":       [1, 2, 3, 4, 5, 6],
    "dataValue":   { "dataType": "Int32", "builtInType": 6, "arrayDimensions": [2, 3], "value": [1, 2, 3, 4, 5, 6] },
    "encoded": {
      "variant":   "{\"UaType\":6,\"Value\":[1,2,3,4,5,6],\"Dimensions\":[2,3]}",
      "dataValue": "{\"UaType\":6,\"Value\":[1,2,3,4,5,6],\"Dimensions\":[2,3]}"
    },
    "statusCodes": {
      "variant":   { "name": "Good", "code": 0, "severity": "Good" },
      "dataValue": { "name": "Good", "code": 0, "severity": "Good" }
    },
    "binary": {
      "variant":   "xgYAAAABAAAAAgAAAAMAAAAEAAAABQAAAAYAAAACAAAAAgAAAAMAAAA=",
      "dataValue": "AcYGAAAAAQAAAAIAAAADAAAABAAAAAUAAAAGAAAAAgAAAAIAAAADAAAA"
    }
  }
]
```

- `jsonMode` only for `format: "json"`. `source` is `"literal"` or `"node"`
  (then `nodeId` follows it).
- `valueRank` is `-1` (scalar), `1` (array) or the number of dimensions;
  `arrayDimensions` only for matrices. `value` is the canonical encoding (§7),
  matrices flattened in row-major order. An empty Variant has `dataType: "Null"`,
  `builtInType: 0`, `value: null`.
- `dataValue` is the canonical DataValue object (§7).
- `encoded.variant` / `encoded.dataValue` are the documents for the Variant and
  the DataValue; for scalars `encoded.value` (and `statusCodes.value`,
  `binary.value`) additionally hold the bare built-in value (`42`,
  `<Int32>42</Int32>`). A document the stack cannot produce is `null` and its
  entry in `statusCodes` says why.
- `success` / `serviceResult` / exit code follow the **Variant** document
  (exit 4 when it could not be encoded).

`codec decode`:

```json
"results": [
  {
    "action":      "decode",
    "format":      "json",
    "jsonMode":    "compact",
    "type":        "Variant",
    "statusCode":  { "name": "Good", "code": 0, "severity": "Good" },
    "dataType":    "String",
    "builtInType": 12,
    "valueRank":   -1,
    "value":       "hi",
    "binary":      "DAIAAABoaQ==",
    "reencoded":   "{\"UaType\":12,\"Value\":\"hi\"}"
  }
]
```

`type` echoes `--type`. `binary` is the Binary encoding of the decoded value
**as that type** (a bare `Int32` is 4 bytes, a `Variant` includes its encoding
byte). `reencoded` is the stack's own encoding of what it decoded. `--type
DataValue` adds the canonical `dataValue` object. On a decode failure only
`action`, `format`, `[jsonMode]`, `type` and `statusCode` are present, `success`
is `false`, `serviceResult` is the decoder's status (`BadDecodingError`, …) and
the exit code is 4.

Short form `codec --endpoint <url> --node <id> [--node …]` — one item per node:

```json
"results": [
  {
    "nodeId":          "ns=2;s=Scalar.Int32",
    "statusCode":      { "name": "Good", "code": 0, "severity": "Good" },
    "dataType":        "Int32",
    "builtInType":     6,
    "valueRank":       -1,
    "value":           -123456789,
    "json":            "{\"UaType\":6,\"Value\":-123456789}",
    "xml":             "<Variant><Value><Int32>-123456789</Int32></Value></Variant>",
    "dataValueJson":   "{\"UaType\":6,\"Value\":-123456789,\"SourceTimestamp\":\"2026-10-11T14:53:24.774898Z\"}",
    "dataValueXml":    null,
    "binary":          "BusypPg=",
    "dataValueBinary": "DQbrMqT4dMdXRJBZ3QGWASSMkVndAQ=="
  }
]
```

`json` / `xml` are the Variant documents, `dataValueJson` / `dataValueXml` the
DataValue documents (`null` when the stack cannot produce one), `binary` /
`dataValueBinary` the Binary encodings. A node whose read status is Bad only has
`nodeId`, `statusCode` and `json` / `xml` set to `null`. `success` when every node was read and JSON-encoded.

**Stack limits (reported, not worked around):**

| | open62541 v1.5.9 | Eclipse Milo 1.1.8 | UA-.NETStandard 2.0.1 (v0.9.0) |
|---|---|---|---|
| JSON flavour | 1.05, one mode (`compact`); `useReversible` has no effect | 1.05, `compact` and `verbose` (`verbose` adds `Status.Symbol`) | 1.05, `compact` and `verbose` |
| JSON DataValue | Variant members flattened: `{"UaType":6,"Value":7,…}` | Variant nested: `{"Value":{"UaType":6,"Value":7},…}`; does not decode the flattened form | Variant members flattened, like open62541 |
| JSON NodeId / QualifiedName, ns ≠ 0 | namespace index (`"ns=2;s=x"`, `"2:Name"`) | namespace URI (`"nsu=…;s=x"`); `Bad_EncodingError` without `--namespace-uri` (a bare NodeId is emitted as the malformed `"s=ns=2;s=x"`) | namespace index (`"ns=2;s=x"`, `"2:Name"`) |
| JSON StatusCode | `{"Code":n,"Symbol":"…"}` | `{"Code":n}` (`Symbol` only in `verbose`) | `{"Code":n}` |
| JSON ExtensionObject | known types structurally (`{"UaTypeId":…,<fields>}`), cannot decode that in-place form back; unknown types as `UaEncoding`/`UaBody` | always `UaTypeId` / `UaEncoding` / `UaBody` | not exercised by the smoke |
| XML element names | no namespace (`<Variant><Value><Int32>`) | `uax:` prefix with `xmlns:uax` / `xmlns:xsi` on the root | default namespace `xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd"` on the root |
| XML encode | no DataValue, DiagnosticInfo, matrices, structures (`BadNotImplemented`) | all built-in types, matrices as `<Matrix>` | Variant and DataValue, matrices as `<Matrix>` |
| XML decode | no DataValue, DiagnosticInfo, XmlElement (`BadNotImplemented`) | all built-in types | namespace-qualified elements only: open62541's unqualified documents fail with `BadDecodingError` |
| XML Guid | `<Guid><String>…</String></Guid>` | `<Guid>…</Guid>` | `<Guid><String>…</String></Guid>` |
| Status names | `BadDecodingError` | `Bad_DecodingError` (Milo's symbol table; compare `code`) | `BadDecodingError` |

---

## 5. Exit codes

| Code | Meaning |
|------|---------|
| 0 | Command completed; `success` is `true` |
| 2 | Invalid command-line input (bad flag, malformed NodeId, missing required arg) |
| 3 | Transport or connect failure |
| 4 | OPC UA service-level failure (`success` is `false`, protocol completed) |
| 5 | Fixture validation failure |
| 6 | Internal adapter failure |
| 7 | Timeout |

A `BadNodeIdUnknown` read result exits 4: the OPC UA protocol succeeded, but the
service result is bad. A TCP connect failure exits 3.

---

## 6. NodeId canonical string form

NodeIds are serialized as compact strings.

| Form | Example |
|------|---------|
| Numeric, ns=0 | `i=85` |
| Numeric, ns≠0 | `ns=2;i=1001` |
| String, ns≠0 | `ns=1;s=Scalar.Int32` |
| GUID | `ns=1;g=72962b91-fa75-4ae6-8d28-b404dc7daf63` |
| ByteString | `ns=1;b=YWJj` (Base64) |

All adapters must produce and accept this form. The `nsu=URI;s=name` input form is
accepted on the command line (as client input) but is **never** used in output.
Output always uses the resolved numeric namespace index form.

---

## 7. Value encoding

| OPC UA type | JSON representation | Notes |
|-------------|--------------------|-|
| Boolean | `true` / `false` | |
| SByte | number | −128 … 127 |
| Byte | number | 0 … 255 |
| Int16 | number | |
| UInt16 | number | |
| Int32 | number | |
| UInt32 | number | |
| Int64 | **decimal string** | `"-9007199254740993"` — exceeds JS safe integer |
| UInt64 | **decimal string** | `"18446744073709551615"` |
| Float | number | `%g` format; `null` for NaN/Infinity |
| Double | number | `%.17g` format; `null` for NaN/Infinity |
| String | string | UTF-8, JSON-escaped |
| DateTime | RFC 3339 UTC string | `"2024-01-01T12:00:00.000Z"` (millisecond precision) |
| Guid | UUID string | lowercase hex with dashes `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` |
| ByteString | Base64 string | RFC 4648, with padding |
| XmlElement | string | UTF-8 XML text |
| NodeId | canonical compact string | see §6 |
| QualifiedName | `{"ns":1,"name":"Foo"}` | |
| LocalizedText | `{"locale":"en","text":"Foo"}` | |
| StatusCode | `{"name":"Good","code":0,"severity":"Good"}` | |
| array | JSON array | |
| `null` / empty | `null` | |
| ExpandedNodeId | string `[svr=<n>;][nsu=<uri>;\|ns=<n>;]<i\|s\|g\|b>=<id>` | `"svr=2;nsu=urn:x;s=Foo"`, `"ns=4;i=1234"` |
| ExtensionObject | `{"typeId":"i=886","encoding":"binary","body":"<Base64>"}` | `encoding` is `binary` or `xml`; open62541 adds `"dataTypeName"` for types it decoded. `null` when empty |
| Variant (inside an array) | `{"dataType":"Int32","builtInType":6,"value":1}` | |
| DataValue | `{"dataType":…,"builtInType":…,["arrayDimensions":…,]"value":…,"statusCode":{…},"sourceTimestamp":…,"sourcePicoseconds":n,"serverTimestamp":…,"serverPicoseconds":n}` | only the members that are present; Milo omits a Good `statusCode` |
| DiagnosticInfo | `{"symbolicId":n,"namespaceUri":n,"localizedText":n,"locale":n,"additionalInfo":"…","innerStatusCode":{…},"innerDiagnosticInfo":{…}}` | only the members that are present |

The last five rows are produced by `codec` (and, in the open62541 adapter, by
every command that prints a Variant of such a type; before v0.7.0 these were
`null` with `builtInType: 0`). `builtInType` for them is 18, 22, 24, 23 and 25.

**Float/Double special values** — NaN and ±Infinity are not valid JSON numbers.
Emit `null`. Consumers must treat `null` as a non-finite value in a float context.

**Int64/UInt64 strings** — all adapters must emit strings for all 64-bit integer
values, without exception. Consumers must parse them as strings.

---

## 8. NodeId input parsing

The `--node` flag accepts the following forms:

| Form | Example |
|------|---------|
| `i=N` | `i=85` → `NodeId(0, 85)` |
| `ns=N;i=N` | `ns=1;i=1001` |
| `ns=N;s=name` | `ns=1;s=Scalars` |
| `ns=N;g=GUID` | `ns=1;g=72962b91-…` |
| `ns=N;b=base64` | `ns=1;b=YWJj` |
| `nsu=URI;s=name` | resolved to numeric ns at connect time |
| `nsu=URI;i=N` | resolved to numeric ns at connect time |
| `nsu=URI;g=GUID` | resolved to numeric ns at connect time |
| `nsu=URI;b=base64` | resolved to numeric ns at connect time |

**Error behavior**:
- Malformed NodeId string → exit 2, `error.category = "input"`, no network request.
- Unknown namespace URI → exit 2, `error.category = "input"`, message includes the URI.
- NodeId resolves but server returns `BadNodeIdUnknown` → exit 4, `success: false`.

---

## 9. Endpoint selection

When `--security-policy None --security-mode None` (the default), the client must
select exactly the endpoint matching `SecurityPolicy#None` and `None` mode. If no
such endpoint exists, the client must fail with exit 3 and `error.category = "transport"`.

When a non-None policy is requested, the client must select the endpoint that matches
both the requested policy URI and mode. If no matching endpoint exists, exit 3.

No arbitrary fallback to the first available endpoint.

The endpoint must also be of the transport of `--endpoint`: an `opc.tcp://`
URL selects a `uatcp-uasc-uabinary` endpoint, `opc.wss://` (or `wss://`) a
`wss-uasc-uabinary` endpoint and `opc.https://` (or `https://`) an
`https-uabinary` endpoint (Part 6 §7.4, §7.5; adapters that declare
`transport-wss` / `transport-https`, §13). An endpoint without a
TransportProfileUri counts by the scheme of its URL. The JSON twins of the
WSS / HTTPS endpoints (`wss-uajson`, `https-uajson`, the OpenAPI profiles) are
never selected. Over TLS the client validates the server's TLS certificate
against `--trust-list` (without `--trust-list` every certificate is accepted,
as for the application certificate).

With `--reverse-listen` the endpoint list is read on the reverse connection
itself; the same matching rules apply.

---

## 10. Server readiness file

After the address space is fully populated and the server is accepting connections,
the adapter writes a readiness file (default: `/run/opcua-interop/ready`).

Content:

```json
{
  "ready":    true,
  "adapter":  "milo",
  "fixture":  "baseline",
  "endpoint": "opc.tcp://localhost:4840/opcua-interop"
}
```

Write protocol:
1. On startup, remove any stale ready file from a prior run.
2. Write to `<path>.tmp`.
3. Atomically rename `<path>.tmp` → `<path>`.
4. On clean shutdown, remove the ready file.

Failure to write the readiness file is **fatal** when `--ready-file` is explicitly
supplied. The server must exit with code 6.

---

## 11. Server lifecycle flags

| Flag | Description | Default |
|------|-------------|---------|
| `--fixture <path>` | Fixture JSON file | required |
| `--bind-address <host>` | Address to bind the TCP listener | `0.0.0.0` |
| `--bind-port <n>` | Port to bind | from fixture (`endpoint.port`) |
| `--advertised-host <host>` | Hostname in endpoint URLs | `localhost` |
| `--advertised-port <n>` | Port in endpoint URLs | same as bind port |
| `--endpoint-path <path>` | URL path component | from fixture (`endpoint.path`) |
| `--ready-file <path>` | Path to write readiness file | `/run/opcua-interop/ready` |
| `--pki-dir <path>` | PKI directory for certificate stores | `/run/opcua-interop/pki` |
| `--certificate <path>` | Server application certificate (PEM or DER file) | — |
| `--private-key <path>` | Server private key (PEM or DER file) | — |
| `--ecc-dir <dir>` | open62541: directory with ECC application certificates `ecc-<curve>/cert.crt` + `cert.key` (an identity directory of the test PKI). Each ECC `securityProfile` of the fixture whose certificate exists gets an endpoint. Milo: accepted and ignored with a warning | — (no ECC endpoints) |
| `--reverse-connect <url>` | open62541: dial `opc.tcp://<client-host>:<port>` and send ReverseHello; repeatable. Retried until the client is there and again after every disconnect. Milo: refused (exit 2) | — |
| `--reverse-connect-interval-ms <n>` | Retry interval of `--reverse-connect` | 1000 |
| `--lds` | open62541: act as Local Discovery Server — ApplicationType `DiscoveryServer`, RegisterServer / RegisterServer2 accepted, FindServers lists registered servers, mDNS on, FindServersOnNetwork served. Milo: refused (exit 2) | off |
| `--lds-cleanup-timeout <s>` | Seconds after which a registration that was not renewed is dropped (> 10) | 3600 |
| `--mdns-name <name>` | open62541: announce the server via mDNS under `<name>` (also the `MdnsServerName` sent in RegisterServer2). Milo: refused (exit 2) | off (`--lds`: `opcua-interop-lds`) |
| `--mdns-capability <cap>` | mDNS / RegisterServer2 server capability (repeatable) | `NA` (`--lds`: `LDS`) |
| `--register-with <lds-url>` | Register with an LDS: RegisterServer2, falling back to RegisterServer; repeated periodically; unregistered (`IsOnline=false`) on SIGTERM | — |
| `--register-interval-ms <n>` | Re-registration period | 30000 |
| `--https-port <n>` | UA-.NETStandard: also listen for `opc.https://<advertised-host>:<n><endpoint-path>` (Part 6 §7.4, https-uabinary, Kestrel). Needs `--certificate` / `--private-key`: the application certificate serves TLS. Without mutual TLS the stack offers SecurityPolicy None only and requires a UserName token (Anonymous is filtered out of HTTPS endpoints) | 0 (off) |
| `--wss-port <n>` | UA-.NETStandard: also listen for `opc.wss://<advertised-host>:<n><endpoint-path>` (Part 6 §7.5, wss-uasc-uabinary, sub-protocol `opcua+uacp`). Needs `--certificate` / `--private-key`; SecurityPolicy None only (TLS protects the channel), Anonymous and UserName | 0 (off) |
| `--pubsub-config <file>` | open62541: OPC UA PubSub (Part 14) configuration — a JSON file with a `PubSubConfigurationDataType`, security groups and SKS settings (§14). Applied after startup; the ready file is only written once it is applied; an invalid configuration exits 1. UA-.NETStandard: the same file on Opc.Ua.PubSub, without SKS and information model (§14.13). Milo, async-opcua, node-opcua, asyncua: refused (exit 2) | — |
| `--auditing` | UA-.NETStandard (adapter 0.15.0, `serverFeatures` `auditing`): ServerConfiguration AuditingEnabled, i.e. Server/Auditing true. The stack delivers audit events (AuditEventType subtypes) to event monitored items of sessions on SignAndEncrypt channels (and HTTPS) only. Other adapters: unknown flag | off |
| `--no-certificate-chain` | UA-.NETStandard (`dotnet` and `dotnet-gds`, adapter 0.16.0, a presence flag): the ServerCertificate of GetEndpoints and of CreateSession is the application certificate alone (`SecurityConfiguration.SendCertificateChain = false`). By default it is the certificate followed by its issuers (Part 6 §6.2.3); the OpenSecureChannel SenderCertificate keeps the chain either way. For clients that take no chain (§16.3). Other adapters: unknown flag | off (chain) |

Notes on the discovery flags:

- The registered `DiscoveryUrls` (and the open62541 server's own FindServers
  entry and ReverseHello `EndpointUrl`) are the advertised endpoint URL
  (`opc.tcp://<advertised-host>:<advertised-port><endpoint-path>`).
- mDNS records carry the container **hostname** (`opc.tcp://<hostname>:4840`,
  server name `<mdns-name>-<hostname>`); a server registered through
  RegisterServer2 appears in FindServersOnNetwork with its registered discovery
  URL. mDNS needs multicast between the containers (same Docker network).
- A server that is not an LDS answers RegisterServer(2) with
  `BadServiceUnsupported` and FindServersOnNetwork with `BadNotImplemented`
  (open62541) / `Bad_ServiceUnsupported` (Milo).

When `--certificate` and `--private-key` are supplied and the fixture contains at
least one non-None `securityProfile`, the server registers those secure endpoints in
addition to the `None`/`None` endpoint that is always present.

The `--pki-dir` directory layout must follow the OPC UA PKI store convention:
```
<pki-dir>/
├── trusted/certs/    # Trusted CA certs and explicitly trusted client certs
├── trusted/crl/      # Certificate revocation lists
├── issuers/certs/    # Intermediate CA certs
└── rejected/         # Auto-populated by the server when an untrusted cert connects
```

Clients presenting a certificate not signed by a CA in `trusted/certs` and not
individually listed there are rejected with `BadCertificateUntrusted`.

---

## 12. Value literals (`--type` / `--value`)

Used by `write`, `call --input <Type>:<literal>` and `codec encode`. `--type` is
a built-in type name or `<Type>[]` for a one-dimensional array.

| Type | Literal | Example |
|------|---------|---------|
| Boolean | `true` \| `false` \| `1` \| `0` | `true` |
| SByte … UInt64 | decimal integer | `-123456789` |
| Float, Double | decimal; `NaN`, `Infinity`, `-Infinity` | `12.5` |
| String | the text | `hello` |
| DateTime | RFC 3339 UTC, up to 7 fractional digits | `2024-01-01T12:34:56.1234567Z` |
| Guid | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | |
| ByteString | Base64 | `b3BjdWE=` |
| XmlElement | the XML text | `<a>b</a>` |
| NodeId | `i=85`, `ns=1;s=x`, `ns=1;g=<guid>`, `ns=1;b=<base64>` (no `nsu=`) | `ns=2;s=Demo` |
| ExpandedNodeId | `[svr=<n>;][nsu=<uri>;\|ns=<n>;]<i\|s\|g\|b>=<id>` | `svr=2;nsu=urn:x;s=Foo` |
| StatusCode | decimal or `0x` hex uint32 | `0x80340000` |
| QualifiedName | `<ns>:<name>` | `2:Name` |
| LocalizedText | `<locale>:<text>` (`:<text>` for no locale) | `en:Hello` |
| ExtensionObject | `<typeId NodeId>\|<Base64 binary body>` | `i=886\|AAAAAAAAAAAAAAAAAABZQA==` |
| DataValue | `<Type>:<literal>` (value only) | `Int32:7` |
| Variant | `<Type>:<literal>`; as a scalar it *is* the inner value | `String:x` |
| DiagnosticInfo | `key=value;…` with `symbolicId`, `namespaceUri`, `localizedText`, `locale`, `additionalInfo`, `innerStatusCode` | `symbolicId=1;innerStatusCode=0x80010000` |

Arrays: comma-separated (`1,2,3`) or a JSON array when elements contain commas
(`["a,b","c"]`); an empty literal is an empty array. `Variant[]` elements are
`<Type>:<literal>`. Matrices (`codec` only): `--type Int32[] --value 1,2,3,4,5,6
--dimensions 2,3`.

`write` and `call` keep their pre-v0.7.0 leniency (an unknown type or malformed
literal is sent as an empty / String Variant and the server answers);
`codec encode` rejects it with exit 2.

---

## 13. `print-capabilities`

Schema: `schemas/capabilities.schema.json`. Consumers gate tests on:

| Field | Meaning |
|-------|---------|
| `adapter.version` | `0.8.1` |
| `clientOperations` | the `client` subcommands the image has |
| `clientFeatures` | optional client-side features (strings below) |
| `serverFeatures` | optional server-side features (strings below) |
| `securityProfiles` | `{policy, mode}` pairs usable on both the client and the server side |
| `codec` | `{formats, jsonVersion, jsonModes, xmlEncodeUnsupported, xmlDecodeUnsupported}` |
| `pubsub` | PubSub (Part 14) support, §14.11. Milo: `{"supported": false, …}` with empty lists |
| `upstream` | only in an image of OT Fabric's own stack: `{name, version, revision, independentEngine}`, with `independentEngine` false. It is not a reference: `own/go-opcua/README.md`, which also says what it leaves out of this contract |

| Feature string | In | open62541 | Milo | async-opcua | UA-.NETStandard | node-opcua | asyncua | Meaning |
|----------------|----|:---------:|:----:|:-----------:|:---------------:|:----------:|:-------:|---------|
| `channel-lifetime` | client | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `--channel-lifetime-ms` |
| `deadband` | client | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `subscribe --deadband-absolute/--deadband-percent/--trigger` |
| `reverse-listen` | client | ✓ | — | ✓ | — | ✓ | — | `--reverse-listen` |
| `ecc-security` | client, server | ✓ | — | — | — | — | — | ECC SecurityPolicies (`securityProfiles` lists them) |
| `ecc-user-token` | client, server | ✓ | — | — | — | — | — | UserName token over an ECC endpoint (EccEncryptedSecret) |
| `application-uri` | client | ✓ | — | ✓ | ✓ | ✓ | ✓ | `--application-uri`, ApplicationUri from the certificate |
| `register-server2` | client | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `register-server` can call RegisterServer2 |
| `codec-json`, `codec-xml` | client | ✓ | ✓ | — | ✓ | — | — | `codec` formats |
| `codec-json-verbose` | client | — | ✓ | — | ✓ | — | — | `codec --json-mode verbose` |
| `codec-pubsub` | client | ✓ | — | — | ✓ | — | — | `codec pubsub-{uadp,json}-{encode,decode}` (§14.9) |
| `deadband` | server | ✓ | ✓ | ✓ | ✓ | ✓ | — | DataChangeFilter absolute deadband / trigger honoured |
| `percent-deadband` | server | ✓ | ✓ | ✓ | ✓ | ✓ | — | percent deadband on AnalogItems with EURange (`Analog.*`) |
| `reverse-connect` | server | ✓ | — | ✓ | — | ✓ | — | `--reverse-connect` |
| `lds` | server | ✓ | — | — | — | — | — | `--lds` |
| `mdns` | server | ✓ | — | — | — | — | — | `--mdns-name`, FindServersOnNetwork |
| `register-with` | server | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `--register-with` |
| `node-management` | server | ✓ | — | ✓ | ✓ | — | — | AddNodes / DeleteNodes served |
| `pubsub` | server | ✓ | — | — | ✓ | — | — | `--pubsub-config` (§14); open62541 also the PubSub information model and SKS, UA-.NETStandard static keys only (§14.13) |
| `transport-wss` | client, server | — | — | — | ✓ | — | — | `--endpoint opc.wss://…` (§9); server `--wss-port` (§11) |
| `transport-https` | client, server | — | — | — | ✓ | — | — | `--endpoint opc.https://…` (§9); server `--https-port` (§11) |
| `push-management` | server | ✓ | — | — | ✓ | ✓ | — | ServerConfiguration push certificate management (Part 12 §7, §15) with `--certificate` / `--private-key` / `--pki-dir`; fixture users get the well-known roles of their `roles` (SecurityAdmin) |
| `gds-pull` | server | — | — | — | — | — | — | `dotnet-gds` only (§16): the server is a Global Discovery Server (Directory, DefaultApplicationGroup, pull certificate management) |
| `push-groups` | client | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `push --group`, `--certificate-type-id` (adapter 0.15.0, §1 "push flags") |
| `push-certificates` | client | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `push --get-certificates`, `--create-self-signed`, `--delete-certificate`, `--update-certificate` (PEM / PFX key), `--reset-to-defaults`, `--cancel` (adapter 0.15.0) |
| `push-transaction-diagnostics` | client | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `push --transaction-diagnostics` (adapter 0.15.0) |
| `alarms-branches` | server | — | — | — | — | ✓ | — | the alarm fixture's `s=Alarms.Clear`: condition branches (fixtures/baseline/README.md "Alarms", adapter 0.15.0) |
| `alarms-audible` | server | — | — | — | — | ✓ | — | InteropAlarm has AudibleEnabled / AudibleSound (AudioVariableType with ListId; adapter 0.15.0) |
| `alarms` | server | ✓ (experimental) | — | — | ✓ | ✓ | — | the Alarms & Conditions fixture (`s=Alarms.*`, fixtures/baseline/README.md "Alarms"); Acknowledge / Confirm / AddComment / Enable / Disable / ConditionRefresh by the stack's own handlers (ConditionRefresh2 too, not exercised by `alarms`) |
| `alarms-105` | server | — | — | — | ✓ | — | — | adapter 0.15.0: the Part 9 1.05 extension of the Alarms fixture (`s=Alarms.ExtAlarm`, `s=Alarms.Dialog`, `s=Alarms.Group`, fixtures/baseline/README.md "Alarms (1.05)"): Suppress / Silence / OutOfService / Latched / Shelving state methods, a dialog, condition branches, an alarm group and AudibleSound |
| `auditing` | server | — | — | — | ✓ | — | — | adapter 0.15.0: `--auditing` (§11) turns the server's auditing on: audit events (AuditCondition*EventType of the alarm methods among them) reach event monitored items of SignAndEncrypt sessions |
| `pubsub-multicast-loopback` | server | — | — | — | ✓ | — | — | adapter 0.15.0: the PubSub runtime (§14) loops its own UDP multicast back to the host (IP_MULTICAST_LOOP), so a subscriber on the same host (e.g. `--network host`) receives the publisher's multicast |
| `history-events` | server | — | — | — | ✓ | — | ✓ | adapter 0.17.0: the event history fixture `s=History.Events` (§17, fixtures/baseline/README.md "History (events)"): HistoryRead with ReadEventDetails of the five seeded events, SelectClauses, WhereClause and continuation points |
| `history-events-update` | server | — | — | — | ✓ | — | — | adapter 0.17.0: HistoryUpdate of `s=History.Events` with UpdateEventDetails (insert / replace / update) and DeleteEventDetails, and the method `s=History.ResetEvents` (§17) |

`transports` in `print-capabilities` lists the endpoint schemes the adapter
dials and serves: `["opc.tcp"]`, UA-.NETStandard (adapter 0.11.0)
`["opc.tcp", "opc.https", "opc.wss"]`. open62541 1.5.9 has no WebSocket or
HTTPS transport (the libwebsockets provider `UA_ENABLE_LWS` is on master
only), Milo 1.1.8 has incubating, unpublished client transports only, and
async-opcua, node-opcua and asyncua implement `opc.tcp` only.

The `alarms` client operation (§1 `alarms` flags) is in `clientOperations` of
all six adapters since adapter 0.12.0; `push`, `query`, `gds-pull`,
`history-read-events` and `history-update-events` are in those of the
adapters below:

| Client operation | open62541 | Milo | async-opcua | UA-.NETStandard | node-opcua | asyncua |
|------------------|:---------:|:----:|:-----------:|:---------------:|:----------:|:-------:|
| `alarms` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `push` (adapter 0.13.0, §15; the others since 0.15.0) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `query` (adapter 0.15.0) | — | — | ✓ | — | ✓ | — |
| `gds-pull` (§16; `dotnet-gds` since adapter 0.14.0, the others since 0.15.0) | ✓ | ✓ | ✓ | ✓ (`dotnet-gds` ✓) | — | ✓ |
| `history-read-events` (adapter 0.17.0, §17) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `history-update-events` (adapter 0.17.0, §17) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Alarm servers** (all three give `success: true` for
`alarms --node i=2253 --condition-name InteropAlarm --acknowledge --confirm --add-comment`
from every adapter client, after `s=Alarms.Reset`):

| | UA-.NETStandard 2.0.1 | node-opcua 2.187.12 | open62541 1.5.9 |
|---|---|---|---|
| Condition | AlarmConditionType `s=Alarms.InteropAlarm`, ConfirmedState | AlarmConditionType `s=Alarms.InteropAlarm`, ConfirmedState | AlarmConditionType `s=Alarms.InteropAlarm`, ConfirmedState (always added by the stack) |
| Server → Alarms.Source | HasNotifier (root notifier) | HasEventSource (node-opcua rejects a condition source that is only a HasNotifier target) | HasNotifier |
| RefreshStart / RefreshEnd | also on `--node s=Alarms.Source` | only on the Server object (`--node i=2253`): on `s=Alarms.Source` the condition is refreshed but no RefreshEnd arrives (exit 7) | as node-opcua |
| Repeated Acknowledge (stale EventId) | `BadConditionBranchAlreadyAcked` | `BadEventIdUnknown` | `BadEventIdUnknown` |
| Message after an action | unchanged (`interop-alarm`) | `The alarm was acknowledged`, … | `The alarm was acknowledged`, `The alarm was confirmed`, `A comment was added` |
| Time | new Time on every event | Time of the condition, not updated by the methods | not updated by Acknowledge; the Confirm event has the null DateTime (`time: null`) |

All three set Comment to the Acknowledge / Confirm comment. open62541 runs the
alarm fixture only because the image enables
`UA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS` (experimental in 1.5.9, full
namespace zero); the adapter patches v1.5.9's `checkConditionRefreshArguments`
to accept the UInt32 SubscriptionId the Call service converts to IntegerId
(`adapters/open62541/amalgam/fix_condition_refresh_args.py`; unpatched ConditionRefresh
returns `BadInvalidArgument`). Eclipse Milo 1.1.8 has no condition state
machine (the Acknowledge / Confirm / AddComment / Enable / Disable methods of
`opc-ua-sdk/sdk-server/.../model/objects/AcknowledgeableConditionType` /
`ConditionType` are abstract generated stubs, and
`OpcUaNamespace$ConditionRefreshMethodImpl` only posts RefreshStart /
RefreshEnd); asyncua 2.1.0 replays registered conditions on ConditionRefresh
(`asyncua/server/subscription_service.py`) but has no Acknowledge / Confirm /
AddComment / Enable / Disable handlers; an async-opcua server fixture was not
attempted. Those three servers do not declare `alarms`. On all three alarm
servers Disable / Enable answer Good and then `BadConditionAlreadyDisabled` /
`BadConditionAlreadyEnabled`; a disabled condition is not refreshed
(`conditions: []`); `s=Alarms.Reset` re-enables it.
Milo's client spells status names with an underscore (`Bad_EventIdUnknown`), as
in all its results; compare `code`.


Eclipse Milo 1.1.8 has no ReverseHello in its transports
(`opc-ua-stack/stack-core/.../channel/messages/MessageType.java` knows only
Hello / Acknowledge / Error), no ECC `SecurityPolicy`
(`opc-ua-stack/stack-core/.../security/SecurityPolicy.java` ends at
`Aes256_Sha256_RsaPss`) and its server answers RegisterServer, RegisterServer2
and FindServersOnNetwork with `Bad_ServiceUnsupported`
(`opc-ua-sdk/sdk-server/.../servicesets/impl/DefaultDiscoveryServiceSet.java`).
It has no PubSub implementation either (§14.12).

async-opcua 0.19.0 (added in adapter 0.9.0) implements no ECC
`SecurityPolicy` (`async-opcua-crypto/src/security_policy.rs` ends at
`Aes256Sha256RsaPss`), its server answers FindServersOnNetwork,
RegisterServer and RegisterServer2 with `BadServiceUnsupported`
(`docs/compatibility.md`: "stub"), and it has no PubSub; the adapter refuses
`--lds`, `--mdns-name` and `--pubsub-config` (exit 2) and ignores `--ecc-dir`
with a warning. Its JSON encoding of a Variant is the 1.04 form
(`{"Type":…,"Body":…}`), not the 1.05 encoding of `codec`, and its XML
encoding of a Variant is the NodeSet2 value form (`<Int32>5</Int32>` directly
inside `<Variant>`, without the Part 6 §5.3.1.17 `<Value>` element), so the
adapter has no `codec` operation (exit 2, not listed in `clientOperations`). Trust is by exact certificate: the server
trusts the certificates in `<pki-dir>/trusted/certs` (a client certificate
that is only signed by a listed CA is rejected); the client validates the
server certificate against `--trust-list` itself (exact match or issued by a
listed certificate). See `adapters/async-opcua/README.md` for the stack deviations the
go-opcua suite found.

OPC Foundation UA-.NETStandard 2.0.1 (adapter name `dotnet`, added in adapter
0.9.0) is the only adapter besides Milo with the Verbose JSON form: its `codec`
encodes and decodes JSON (compact and verbose) and XML (see the codec table
above), and its server serves AddNodes / DeleteNodes. The adapter does not wire
the stack's ReverseConnectManager (`--reverse-listen` and `--reverse-connect`
exit 2), and 2.0.1 does not accept the test PKI's RSA-CA-signed ECC
certificates, so no `ecc-security` is declared and `--ecc-dir` is ignored with a
warning. Its server runs no LDS or mDNS (`--lds`, `--mdns-name` and
`--mdns-capability` exit 2); since adapter 0.10.0 it runs PubSub on the stack's
Opc.Ua.PubSub runtime (§14.13). The test PKI is copied into
the stack's directory stores (own / trusted / issuer / rejected, DER);
SHA-1-signed certificates are rejected. See "Reference stacks" in the README for
the stack deviations the go-opcua suite found.

node-opcua 2.187.12 (added in adapter 0.9.0) implements no ECC
`SecurityPolicy` (`node-opcua-secure-channel` ends at `Aes256_Sha256_RsaPss`;
`--ecc-dir` is ignored with a warning, an `ECC_*` client policy is an input
error). Its `OPCUAServer` answers AddNodes / DeleteNodes with
`BadServiceUnsupported` (no `node-management`) and RegisterServer /
RegisterServer2 / FindServersOnNetwork with a service fault; node-opcua ships
the LDS as a separate server (`OPCUADiscoveryServer`, without the fixture
address space) that the adapter does not run, so `--lds`, `--mdns-name` and
`--mdns-capability` are refused (exit 2). It has no open-source PubSub
(`--pubsub-config` → exit 2, `pubsub.supported: false`). The adapter has no
`codec` operation yet (exit 2, not listed in `clientOperations`): node-opcua
has an OPC UA 1.05 JSON encoder (`node-opcua-json`) but no Part 6 XML
encoding of Variants, and the JSON half is not wired into the adapter. Trust is by the
CA of `<pki-dir>/trusted/certs` with its CRL, as for open62541 and Milo. See
`adapters/node-opcua/README.md` for the stack deviations the go-opcua suite found.

opcua-asyncio (PyPI `asyncua` 2.1.0, adapter name `asyncua`, added in adapter
0.9.0) declares `channel-lifetime`, `deadband`, `application-uri`,
`register-server2` and (since adapter 0.15.0) `push-groups`,
`push-certificates` and `push-transaction-diagnostics` on the client side and only `register-with` on the
server side. It has no ECC `SecurityPolicy`, no ReverseHello, no LDS / mDNS
server and no PubSub: the client refuses `ECC_*` policies and
`--reverse-listen` (exit 2), the server refuses `--reverse-connect`, `--lds`,
`--mdns-name`, `--mdns-capability` and `--pubsub-config` (exit 2), and AddNodes
/ DeleteNodes are not served (`BadUserAccessDenied`). The adapter has no
`codec` operation (exit 2, not listed in `clientOperations`). The server does
not declare `deadband` / `percent-deadband`: asyncua 2.1.0 compares an absolute
deadband with the previous sample instead of the last reported value, and
accepts a percent deadband (also without EURange) without applying it. Trust:
`<pki-dir>/trusted/certs` are the anchors, `issuers/certs` only completes a
chain, CRLs of `trusted/crl` and `issuers/crl` are honoured; the client checks
the server certificate against `--trust-list` with the stack's
`CertificateValidator`. See `adapters/asyncua/README.md` for the stack deviations the
go-opcua suite found.

---

## 14. PubSub (OPC UA Part 14)

Added in adapter **0.8.0** for open62541 and in **0.10.0** for UA-.NETStandard
2.0.1, whose differences are in §14.13 (Eclipse Milo 1.1.8 has no PubSub
implementation, §14.12; async-opcua, node-opcua and asyncua refuse it).
Declared in `print-capabilities` → `pubsub` (§14.11), `serverFeatures`
`pubsub`, `clientFeatures` `codec-pubsub`. Unless a section says otherwise,
§14.1–§14.12 describe the open62541 adapter.

The open62541 image is built with `UA_ENABLE_PUBSUB`,
`UA_ENABLE_PUBSUB_INFORMATIONMODEL` (with the configuration methods),
`UA_ENABLE_PUBSUB_SKS`, `UA_ENABLE_PUBSUB_FILE_CONFIG`, `UA_ENABLE_MQTT` and
the JSON encoding, still as the single-file amalgamation. Three adapter-side
additions make that work and are the only places where the adapter goes beyond
stock v1.5.9 (all in `adapters/open62541/`):

| What | Why |
|------|-----|
| `amalgam/inline_mqtt.py` | `tools/amalgamate.py` drops the two quoted `#include` lines through which `arch/common/eventloop_mqtt.c` pulls in the MQTT-C submodule, so the amalgamation does not compile with `UA_ENABLE_MQTT`. The script inlines `deps/mqtt-c/include/mqtt.h` and `src/mqtt.c` before the amalgamation is generated. No behaviour change |
| `amalgam/backport_json_reader.py` | In v1.5.9 `UA_DataSetReader_checkIdentifier` is an unimplemented TODO for JSON and rejects **every** JSON NetworkMessage, so no open62541 subscriber could receive `pubsub-mqtt-json`. The script applies the matching logic of upstream master: PublisherId compared by value across the numeric widths (JSON carries numeric PublisherIds as strings), DataSetWriterId matched against the decoded JSON DataSetMessages (0 = any) |
| `src/pubsub_security.c` | v1.5.9 implements the PubSub message security policies `PubSub-Aes128-CTR` / `PubSub-Aes256-CTR` for mbedTLS only; the adapter is built on OpenSSL (ECC SecureChannel policies). The file is an OpenSSL port of the mbedTLS plugins (HMAC-SHA256 signature, AES-CTR with KeyNonce‖MessageNonce‖counter starting at 1, P_SHA256 key derivation) installed as `pubSubConfig.securityPolicies` |

### 14.1 `server --pubsub-config <file>`

```
server --fixture /fixtures/baseline/fixture.json --pubsub-config /pubsub/udp-unicast-publisher.json
       [--certificate … --private-key … --pki-dir …]     (only for sksClient / serveSks)
```

The configuration is applied **after** the server started (the EventLoop with
the UDP and MQTT connection managers and the SKS client must be running) and
**before** the ready file is written: a ready server has its PubSub
configuration in place. Any error (malformed JSON, a configuration open62541
rejects, an unknown SecurityGroupId, …) is logged as
`[open62541] error: --pubsub-config: <reason>: <StatusCode>` and the server
exits 1. Progress is logged on stderr (`[open62541] info: pubsub: …`), e.g.
the created components and `configuration applied (…)`.

The file is one JSON object; unknown top-level members are an error:

| Member | Type | Meaning |
|--------|------|---------|
| `configuration` | object, **required** | A `PubSubConfigurationDataType` in the OPC UA 1.05 JSON encoding (§14.2) |
| `securityGroups` | array | SecurityGroups referenced by `SecurityGroupId` of WriterGroups / ReaderGroups with `SecurityMode` Sign (2) or SignAndEncrypt (3), and the groups an SKS serves (§14.5) |
| `serveSks` | boolean | This server is the Security Key Service of every listed group: the groups are created under `PublishSubscribe.SecurityGroups` (i=15443) with keys generated by open62541, `GetSecurityKeys` serves them, local groups use them. Default `false` |
| `sksClient` | object | Pull the keys of the listed groups that have no `keys` from a remote SKS with `GetSecurityKeys` (§14.5) |
| `deltaFrames` | boolean | Let DataSetWriters send DeltaFrames between KeyFrames (open62541 `pubSubConfig.enableDeltaFrames`, server-wide). Default `false`, see §14.10 |
| `mqtt` | object | UA-.NETStandard only: `{"protocolVersion": "5.0" \| "3.1.1" \| "3.1"}`, the MQTT version of every MQTT connection (default `"5.0"`, §14.13). open62541 refuses the member |

`securityGroups[]`:

| Member | Type | Default | Meaning |
|--------|------|---------|---------|
| `securityGroupId` | string | required | The `SecurityGroupId` (open62541 uses the SecurityGroup *name* as its id) |
| `securityPolicyUri` | string | `…#PubSub-Aes256-CTR` | `http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR` or `…#PubSub-Aes256-CTR` |
| `keyLifetimeMs` | number | 60000 | KeyLifetime (SKS only) |
| `maxFutureKeyCount` / `maxPastKeyCount` | number | 2 / 1 | SKS only |
| `keys` | array of `{"tokenId": n, "key": "<Base64>"}` | — | Static keys. `key` is the key data exactly as `GetSecurityKeys` returns it: `SigningKey ‖ EncryptingKey ‖ KeyNonce` = 32+16+4 = **52 bytes** (Aes128-CTR) or 32+32+4 = **68 bytes** (Aes256-CTR). The **first** entry is activated with its `tokenId` as SecurityTokenId; static keys do not roll over. Not allowed together with `serveSks` |

`sksClient`:

| Member | Default | Meaning |
|--------|---------|---------|
| `endpointUrl` | required | `opc.tcp://…` endpoint of the SKS |
| `securityPolicyUri` | `…#Basic256Sha256` | SecureChannel policy (full URI or short name) |
| `securityMode` | `SignAndEncrypt` | `Sign` or `SignAndEncrypt` (`GetSecurityKeys` requires SignAndEncrypt on an open62541 SKS) |
| `username` / `password` | — | UserName identity (otherwise Anonymous) |

The SKS client uses the server's `--certificate` / `--private-key` as its
application certificate (ApplicationUri = the certificate's URI SAN) and trusts
`<--pki-dir>/trusted/certs/*` (default `/run/opcua-interop/pki`). The first
`GetSecurityKeys` is retried every 2 s until it succeeds (the SKS may start
later); afterwards open62541 refreshes the keys itself (at half the KeyLifetime
before the last key is used) and rolls over at `TimeToNextKey`.

### 14.2 JSON encoding of `configuration`

`configuration` is decoded by open62541's `UA_decodeJson` into
`UA_TYPES[UA_TYPES_PUBSUBCONFIGURATIONDATATYPE]`, i.e. the OPC UA 1.05 JSON
DataEncoding ("compact"/non-reversible field names as in the NodeSet:
`PublishedDataSets`, `Connections`, `Enabled`, …). Conventions:

- **ExtensionObjects** (`Address`, `TransportSettings`, `MessageSettings`,
  `DataSetSource`, `SubscribedDataSet`): `{"UaTypeId": "<DataType NodeId>",
  "UaBody": { …fields… }}`. The 1.05 in-situ form `{"UaTypeId": "…", …fields…}`
  is accepted too (the adapter rewrites it to `UaBody`, open62541 v1.5.9 only
  decodes that), and a `UaTypeId` naming the DefaultBinary / DefaultXml
  encoding NodeId is mapped to the DataType NodeId.
- **NodeIds** are strings; `nsu=<uri>;…` is resolved against the server's
  NamespaceArray, so use `nsu=urn:otfabric:opcua-interop:model;s=PubSub.Int32`
  instead of a namespace index.
- **PublisherId** is a Variant: `{"UaType": 5, "Value": 2234}` (UaType 3 Byte,
  5 UInt16, 7 UInt32, 9 UInt64 — Value then a decimal string —, 12 String).
- **Enumerations** are numbers: `SecurityMode` 1 None, 2 Sign, 3
  SignAndEncrypt; `AttributeId` 13 = Value.
- **Masks** are numbers (`NetworkMessageContentMask`, `DataSetMessageContentMask`,
  `DataSetFieldContentMask`).
- Durations in milliseconds (`PublishingInterval`, `MessageReceiveTimeout`).

DataType NodeIds used in `UaTypeId`:

| DataType | NodeId | Where |
|----------|--------|-------|
| NetworkAddressUrlDataType | `i=15510` | `Connection.Address`, `DatagramWriterGroupTransport2DataType.Address` |
| PublishedDataItemsDataType | `i=15581` | `PublishedDataSet.DataSetSource` |
| UadpWriterGroupMessageDataType | `i=15645` | `WriterGroup.MessageSettings` (UADP) |
| UadpDataSetWriterMessageDataType | `i=15652` | `DataSetWriter.MessageSettings` (UADP) |
| UadpDataSetReaderMessageDataType | `i=15653` | `DataSetReader.MessageSettings` (UADP) |
| JsonWriterGroupMessageDataType | `i=15657` | `WriterGroup.MessageSettings` (JSON) |
| JsonDataSetWriterMessageDataType | `i=15664` | `DataSetWriter.MessageSettings` (JSON) |
| JsonDataSetReaderMessageDataType | `i=15665` | `DataSetReader.MessageSettings` (JSON) |
| DatagramWriterGroupTransport2DataType | `i=23613` | `WriterGroup.TransportSettings` (UDP unicast destination) |
| BrokerWriterGroupTransportDataType | `i=15667` | `WriterGroup.TransportSettings` (MQTT `QueueName`) |
| BrokerDataSetReaderTransportDataType | `i=15670` | `DataSetReader.TransportSettings` (MQTT `QueueName`) |
| TargetVariablesDataType | `i=15631` | `DataSetReader.SubscribedDataSet` |

### 14.3 Which fields are honoured

The adapter builds the configuration with the open62541 API
(`UA_Server_addPubSubConnection`, `_addPublishedDataSet`, `_addDataSetField`,
`_addWriterGroup`, `_addDataSetWriter`, `_addReaderGroup`,
`_addDataSetReader`, `_setDataSetReaderTargetVariables`, then the
`_enable…` calls) rather than `UA_Server_loadPubSubConfigFromByteString`,
whose v1.5.9 implementation drops the WriterGroup / ReaderGroup
`SecurityGroupId`, the ReaderGroup and DataSetReader `TransportSettings` (the
MQTT QueueName of a subscriber) and ignores errors of nested components.
"Passed" = handed to open62541 unchanged; what open62541 then does with it is
noted.

| Structure | Honoured | Ignored |
|-----------|----------|---------|
| PubSubConfigurationDataType | `PublishedDataSets`, `Connections`, `Enabled` (false: everything is created but nothing enabled) | — |
| PublishedDataSetDataType | `Name`, `DataSetSource` (**PublishedDataItemsDataType only**; PublishedEvents → error `BadNotImplemented`), `DataSetMetaData.Fields[i]`: `Name` (field name = JSON key), `FieldFlags` bit 0 (PromotedField), `MaxStringLength`, `Description`, `DataSetFieldId`; `DataSetMetaData.ConfigurationVersion` → field configuration version | `DataSetFolder`, `ExtensionFields`, the other `DataSetMetaData` members (types are taken from the published Variables; open62541 generates the DataSetMetaData and its ConfigurationVersion itself) |
| PublishedVariableDataType | `PublishedVariable`, `AttributeId` (0 → Value), `IndexRange` (applied when sampling); `SamplingIntervalHint`, `DeadbandType`, `DeadbandValue`, `SubstituteValue`, `MetaDataProperties` passed (not evaluated by v1.5.9: every publish reads the current value) | — |
| PubSubConnectionDataType | `Name`, `Enabled`, `PublisherId`, `TransportProfileUri`, `Address` (NetworkAddressUrlDataType: `Url`, `NetworkInterface`), `ConnectionProperties`, `TransportSettings` (passed), `WriterGroups`, `ReaderGroups`. `mqtt://` URLs are rewritten to `opc.mqtt://` (the only MQTT scheme v1.5.9 parses); `mqtts://` → error | — |
| WriterGroupDataType | `Name`, `Enabled`, `WriterGroupId`, `PublishingInterval`, `SecurityMode`, `SecurityGroupId`, `GroupProperties`, `TransportSettings` (DatagramWriterGroupTransport2DataType `Address` for UDP unicast, BrokerWriterGroupTransportDataType `QueueName` for MQTT), `MessageSettings` (UADP: `NetworkMessageContentMask`, `GroupVersion`; JSON: the type selects the JSON encoding), `DataSetWriters`. `KeepAliveTime`, `Priority` passed (unused by v1.5.9). Up to 255 DataSetMessages per NetworkMessage | `SecurityKeyServices`, `MaxNetworkMessageSize`, `LocaleIds`, `HeaderLayoutUri`; JSON `NetworkMessageContentMask` (v1.5.9 always writes the full NetworkMessage header and the `Messages` array) |
| DataSetWriterDataType | `Name`, `Enabled`, `DataSetWriterId`, `DataSetFieldContentMask` (0 = Variant, `RawData` 0x20, else DataValue with the selected StatusCode / timestamps / picoseconds), `KeyFrameCount`, `DataSetName` (→ PublishedDataSet; empty = heartbeat writer), `DataSetWriterProperties`, `MessageSettings` (UADP / JSON `DataSetMessageContentMask`), `TransportSettings` (passed) | UADP `ConfiguredSize` / `NetworkMessageNumber` / `DataSetOffset` (fixed layouts: open62541 warns and resets them) |
| ReaderGroupDataType | `Name`, `Enabled`, `SecurityMode`, `SecurityGroupId`, `GroupProperties`, `TransportSettings` if a BrokerDataSetReaderTransportDataType, `DataSetReaders`. The encoding (JSON / UADP) follows the connection's TransportProfileUri (`pubsub-mqtt-json`) or a JsonDataSetReaderMessageDataType on the first reader. MQTT: the group subscribes one topic — its own BrokerDataSetReaderTransportDataType, else the readers' (all must name the same `QueueName`) | `SecurityKeyServices`, `MaxNetworkMessageSize`, `MessageSettings` |
| DataSetReaderDataType | `Name`, `Enabled`, `PublisherId` (an empty Variant leaves the reader at Byte 0: v1.5.9 has no "any publisher" — set it), `WriterGroupId`, `DataSetWriterId`, `DataSetMetaData` (field count, names for JSON, types for RawData; `MaxStringLength` is required for String/ByteString with RawData), `DataSetFieldContentMask`, `MessageReceiveTimeout` (ms; 0 = none, §14.10), `MessageSettings`, `TransportSettings` (passed; MQTT QueueName see ReaderGroup), `SubscribedDataSet` = TargetVariablesDataType | `KeyFrameCount`, `HeaderLayoutUri`, `SecurityMode` / `SecurityGroupId` / `SecurityKeyServices` (security is per ReaderGroup), `DataSetReaderProperties`; `SubscribedDataSetMirrorDataType` → error `BadNotImplemented` |
| FieldTargetDataType | `TargetNodeId`, `AttributeId`, `ReceiverIndexRange` (v1.5.9 uses it as the IndexRange of the write), `WriteIndexRange` (passed). TargetVariables[i] receives DataSetMetaData.Fields[i] (position, not `DataSetFieldId`) | `DataSetFieldId`, `OverrideValueHandling`, `OverrideValue` |

Reader matching (UADP): a NetworkMessage is accepted when its PublisherId (if
present) equals the reader's (same integer width!), its WriterGroupId (if the
group header carries one) equals the reader's `WriterGroupId`, and — with a
payload header — one of its DataSetWriterIds equals the reader's. JSON: the
PublisherId is compared by value, `DataSetWriterId` 0 accepts any writer.

### 14.4 Transports, addresses and the Docker networking contract

| Profile | `TransportProfileUri` | Connection `Address.Url` | Extra |
|---------|----------------------|--------------------------|-------|
| UDP UADP | `http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp` | `opc.udp://<host>:<port>` | see below |
| MQTT UADP | `…/pubsub-mqtt-uadp` | `mqtt://<broker>:<port>` (or `opc.mqtt://`) | WriterGroup BrokerWriterGroupTransportDataType `QueueName` = topic; DataSetReader (or ReaderGroup) BrokerDataSetReaderTransportDataType `QueueName` |
| MQTT JSON | `…/pubsub-mqtt-json` | same | same; JSON message settings |

**How open62541 v1.5.9 opens UDP sockets** (`ua_pubsub_connection.c`):

- Connection `Url` host `localhost` or empty → *receive-all*: a socket bound to
  `<port>` on all interfaces (IPv4 and IPv6), and **no** connection-level send
  socket.
- Any other host → a receive socket bound to that address (`bind()` — so it
  must be a local address, `0.0.0.0`, or a multicast group, which is joined)
  **and** a send socket to that address. A unicast destination that is not a
  local address therefore cannot be the connection Url (`Cannot assign
  requested address` → `BadConnectionRejected`).
- Unicast publishing therefore uses a receive-all connection
  (`opc.udp://localhost:<any free port>`) and the destination in the
  WriterGroup `TransportSettings` = DatagramWriterGroupTransport2DataType
  `{"Address": NetworkAddressUrlDataType {"Url": "opc.udp://<dest>:<port>"}}`.
  The destination host name is resolved when the configuration is applied:
  it must resolve then (start the subscriber container first; a host name that
  does not resolve fails the WriterGroup).

| Direction | Configuration | Docker |
|-----------|---------------|--------|
| container publishes → host (unicast) | connection `opc.udp://localhost:<p>`, WriterGroup DatagramWriterGroupTransport2DataType `opc.udp://host.docker.internal:<host-port>` | Linux: `--add-host host.docker.internal:host-gateway` (Docker Desktop resolves it by itself; the flag is harmless there). The host listens on `0.0.0.0:<host-port>`; on Docker Desktop the datagrams arrive from `127.0.0.1` |
| host publishes → container (unicast) | subscriber connection `opc.udp://0.0.0.0:<p>` (or `opc.udp://localhost:<p>`, receive-all) | `-p <p>:<p>/udp`; the host sends to `127.0.0.1:<p>` (or the host's address) |
| container ↔ container (unicast) | as above, destination = the peer's container name / network alias | same Docker network |
| multicast | publisher and subscriber connection `opc.udp://224.0.0.22:<p>` (any group) | container ↔ container on the same Docker network (bridge networks forward multicast between containers). **Not** between the macOS host and Docker Desktop (the VM boundary drops multicast); on Linux use `--network host` for host ↔ container multicast |

Verified on macOS / Docker Desktop with the exact addresses above (host
listener on `0.0.0.0:5555` ← container `opc.udp://host.docker.internal:5555`;
host sender → `127.0.0.1:4841` → container `opc.udp://0.0.0.0:4841` with
`-p 4841:4841/udp`, also with `opc.udp://localhost:4841`), and container ↔
container unicast and multicast by `scripts/pubsub-smoke.sh` (`make smoke-pubsub`;
`make smoke-pubsub-dotnet` runs the same scenarios on the dotnet adapter, §14.13).

**MQTT** (v1.5.9 MQTT-C client): MQTT 3.1.1, clean session, empty client id
(the broker assigns one), keep-alive 400 s, QoS 0 publish and subscribe, no
retain, no TLS, and the PubSubConnection `ConnectionProperties` /
`authenticationProfileUri` are not used for MQTT credentials (anonymous only).
The MQTT-C send and receive buffers are **1024 bytes**: a NetworkMessage
(including the MQTT header) must stay below about 1000 bytes. The JSON
message of the example data set (10 fields) is ~690 bytes. `MetaDataQueueName`
is not used (no metadata publishing). The broker for the tests:
`eclipse-mosquitto:2.0.22@sha256:09b62ff32c2e7b64d4b431b9a89236073289b68db273de2b089edeb9b0d92b5c`
with `mqtt/mosquitto.conf` (README "MQTT broker").

### 14.5 Message security and keys

UADP only: `SecurityMode` 2 (Sign) / 3 (SignAndEncrypt) on the WriterGroup /
ReaderGroup with a `SecurityGroupId` listed in `securityGroups`. JSON message
security is not defined by Part 14 and refused by open62541
(`BadInternalError` when keys are set). Key sources per SecurityGroup:

| Source | Configuration | Behaviour |
|--------|---------------|-----------|
| static | `keys` | The first key is set with `UA_Server_setWriterGroupEncryptionKeys` / `…ReaderGroup…` (SecurityTokenId = `tokenId`) |
| SKS (this server) | `"serveSks": true` | `UA_Server_addSecurityGroup` under PublishSubscribe.SecurityGroups; open62541 generates the current and `maxFutureKeyCount` future keys (P_SHA256 of random secret / seed), rolls over every `keyLifetimeMs`; local groups activate the SKS keys; remote clients read them with `GetSecurityKeys` |
| SKS pull | `sksClient` | `UA_Server_setSksClient` per group: `GetSecurityKeys(SecurityGroupId, 0, UInt32.Max)` on the SKS, keys activated when they arrive |
| SKS push | none of the above | The groups start without keys; an SKS pushes them with `SetSecurityKeys` (PublishSubscribe i=17364) on a SignAndEncrypt session |

The SecurityHeader carries the SecurityTokenId and an 8-byte MessageNonce
(PubSub-Aes*-CTR); the signature is 32 bytes (HMAC-SHA256) over the whole
message; the payload (DataSetMessages) is encrypted with AES-CTR, counter block
= KeyNonce (4) ‖ MessageNonce (8) ‖ BlockCounter (4, big endian, from 1).

### 14.6 Information model

Available with or without `--pubsub-config`: `Server` →
`PublishSubscribe` (i=14443) with every configured component as an object
(connections are `ns=1;i=…` objects under PublishSubscribe, groups under their
connection, writers / readers under their group; each has a `Status` object
with `State` (Int32 PubSubState: 0 Disabled, 1 Paused, 2 Operational, 3 Error,
4 PreOperational) and the `Enable` (i=14645) / `Disable` (i=14646) methods).
`SupportedTransportProfiles` (i=17481) lists the three profiles above.
Method argument conventions of open62541 v1.5.9 (call on the object noted;
ExtensionObject arguments are binary-encoded with the DefaultBinary encoding
NodeId, e.g. PubSubConnectionDataType i=15694):

| Method (NodeId) | Object | Inputs | Outputs | Notes |
|-----------------|--------|--------|---------|-------|
| AddConnection (i=17366) | PublishSubscribe i=14443 | PubSubConnectionDataType | NodeId | Creates the connection with its WriterGroups / DataSetWriters / ReaderGroups / DataSetReaders. The **connection is created Disabled** (State 0) regardless of `Enabled`: call Enable on its Status object. With `Enabled` true the groups are set Operational and therefore wait as Paused (1) until the connection is enabled; DataSetWriters / DataSetReaders stay Disabled (`Enabled` of the nested structures is not evaluated) — enable them through their Status objects. WriterGroup `TransportSettings` / `MessageSettings` / `SecurityGroupId` are kept (JSON needs BrokerWriterGroupTransportDataType); DataSetWriters only get Name, DataSetWriterId, KeyFrameCount, DataSetFieldContentMask and the PublishedDataSet named by `DataSetName`; ReaderGroups only get `Name` (no security, no transport settings, always UADP — MQTT / JSON subscriptions cannot be built this way); DataSetReaders get PublisherId, WriterGroupId, DataSetWriterId, the field Name / DataType / BuiltInType / ValueRank of the metadata, and TargetVariables. On error the connection is removed again |
| RemoveConnection (i=17369) | i=14443 | NodeId | — | `BadNodeIdUnknown` if unknown |
| AddWriterGroup (i=17427) | the connection object | WriterGroupDataType | NodeId | As in AddConnection; JSON needs BrokerWriterGroupTransportDataType (`BadConfigurationError`); the group is created disabled (call Enable) |
| AddReaderGroup (i=17465) | the connection object | ReaderGroupDataType | NodeId | Only `Name` is used (created disabled). A ReaderGroup added to a running connection receives nothing until the connection is disabled and enabled again |
| RemoveGroup (i=14225) | the connection object | NodeId | — | WriterGroup or ReaderGroup of that connection |
| AddDataSetWriter (i=17969) | the WriterGroup object | DataSetWriterDataType | NodeId | PublishedDataSet by `DataSetName` (`BadParentNodeIdInvalid` if none) |
| RemoveDataSetWriter (i=17992) | the WriterGroup object | NodeId | — | |
| AddDataSetReader (i=21082) | the ReaderGroup object | DataSetReaderDataType | NodeId | TargetVariables: each `TargetNodeId` is *added* as a new Variable under a folder (BrowseName = metadata `Name`) in Objects; when the NodeId already exists (a fixture variable) the add fails and every write of the reader fails with `BadNodeIdUnknown` — use a NodeId that does not exist yet |
| RemoveDataSetReader (i=21085) | the ReaderGroup object | NodeId | — | Fails with `BadInternalError` while the ReaderGroup is enabled: disable the group first |
| AddPublishedDataItems (i=14493, DataSetFolderType method referenced by PublishedDataSets) | PublishedDataSets i=17371 | String Name, String[] FieldNameAliases, DataSetFieldFlags[] (UInt16; 1 = PromotedField), PublishedVariableDataType[] | **3 outputs expected** (DataSetNodeId, ConfigurationVersion, AddResults); only DataSetNodeId is set | The three arrays must have the same length |
| RemovePublishedDataSet (i=14499) | i=17371 | NodeId | — | |
| AddDataSetFolder / RemoveDataSetFolder (i=16994 / i=16997) | i=17371 | String / NodeId | NodeId / — | |
| AddVariables / RemoveVariables (i=14555 / i=14558) | PublishedDataItems object | — | — | Bound to a no-op that returns Good (not implemented) |
| ReserveIds (i=25474) | PublishSubscribe.PubSubConfiguration (i=25451) | String TransportProfileUri, UInt16 #WriterGroupIds, UInt16 #DataSetWriterIds | Variant DefaultPublisherId (ApplicationUri String for MQTT profiles, else UInt64), UInt16[], UInt16[] | |
| Enable / Disable (i=14645 / i=14646) | a component's `Status` object (or PublishSubscribe.Status i=17405) | — | — | Enable only from Disabled, Disable only when not Disabled (`BadInvalidState`). A reader in Error must be disabled and enabled again |
| GetSecurityKeys (i=15215) | i=14443 | String SecurityGroupId, UInt32 StartingTokenId (0 = current), UInt32 RequestedKeyCount | String SecurityPolicyUri, UInt32 FirstTokenId, ByteString[] Keys, Duration TimeToNextKey, Duration KeyLifetime | **SignAndEncrypt session required** (`BadSecurityModeInsufficient` otherwise); unknown group `BadNotFound`; returns current + RequestedKeyCount future keys (capped). v1.5.9 bug: `TimeToNextKey` is a large negative number (it subtracts a monotonic clock from a wall-clock base time) — use KeyLifetime |
| SetSecurityKeys (i=17364) | i=14443 | String SecurityGroupId, String SecurityPolicyUri, UInt32 CurrentTokenId, ByteString CurrentKey, ByteString[] FutureKeys, Duration TimeToNextKey, Duration KeyLifetime | — | SignAndEncrypt required; the group must exist locally (a WriterGroup / ReaderGroup with that SecurityGroupId) |
| AddSecurityGroup (i=15444 on PublishSubscribe.SecurityGroups i=15443; i=15461 on SecurityGroupFolderType) | SecurityGroups folder | String SecurityGroupName, Duration KeyLifetime (Double accepted), String SecurityPolicyUri, UInt32 MaxFutureKeyCount, UInt32 MaxPastKeyCount | String SecurityGroupId (= the name), NodeId SecurityGroupNodeId | **Adapter binding**: v1.5.9 has no callback for this method; the adapter binds it to `UA_Server_addSecurityGroup`. Not restricted to encrypted sessions |
| RemoveSecurityGroup (i=15447; i=15464 on SecurityGroupFolderType) | SecurityGroups folder | NodeId SecurityGroupNodeId | — | Adapter binding to `UA_Server_removeSecurityGroup` |
| LoadPubSubConfigurationFile ("PubSub configuration", ns=0 numeric id assigned at startup) / DeletePubSubConfiguration | i=14443 | ByteString (UABinaryFileDataType holding a PubSubConfigurationDataType) / — | — | open62541 extensions from `UA_ENABLE_PUBSUB_FILE_CONFIG` |

### 14.7 Fixture nodes

The baseline fixture has a `PubSub` folder (`nsu=urn:otfabric:opcua-interop:model;s=PubSub`)
with writable variables without behaviours — published fields on a publisher,
TargetVariables on a subscriber: `PubSub.Boolean`, `PubSub.Int32`,
`PubSub.Int64`, `PubSub.UInt64`, `PubSub.Double`, `PubSub.String`,
`PubSub.DateTime`, `PubSub.ByteString`, `PubSub.Int32Array` (Int32[]),
`PubSub.DoubleArray` (Double[]) — see `fixtures/baseline/README.md`.
`Dynamic.Counter` (Int64, +1 every 250 ms) is a continuously changing source.

### 14.8 Worked examples

`pubsub/examples/` holds the configurations `scripts/pubsub-smoke.sh` runs
(regenerate with `python3 pubsub/examples/generate.py pubsub/examples`). They
use the network aliases `pubsub-publisher`, `pubsub-subscriber` and
`mosquitto`; replace them with your addresses. All publish the same data set
(`InteropDataSet`: `PubSub.Boolean`, `PubSub.Int32`, `Dynamic.Counter` as
`Counter`, `PubSub.UInt64`, `PubSub.Double`, `PubSub.String`,
`PubSub.DateTime`, `PubSub.ByteString`, `PubSub.Int32Array`,
`PubSub.DoubleArray`) with PublisherId UInt16 2234, WriterGroupId 100,
DataSetWriterId 1, PublishingInterval 100 ms, and the subscribers write it into
the `PubSub.*` variables (Counter → `PubSub.Int64`).

| Files | Transport |
|-------|-----------|
| `udp-unicast-{publisher,subscriber}.json` | UADP, unicast to `pubsub-subscriber:4841` |
| `udp-multicast-{publisher,subscriber}.json` | UADP, `opc.udp://224.0.0.22:4840` |
| `mqtt-uadp-{publisher,subscriber}.json` | UADP over `mqtt://mosquitto:1883`, topic `opcua-interop/uadp` |
| `mqtt-json-{publisher,subscriber}.json` | JSON over MQTT, topic `opcua-interop/json` |
| `udp-secure-{publisher,subscriber}.json` | UADP unicast, SignAndEncrypt, PubSub-Aes256-CTR, static key (token 1) |
| `sks-{publisher,subscriber}.json` | publisher = SKS (`serveSks`), subscriber pulls with `sksClient` (Basic256Sha256 SignAndEncrypt, `test-user`) |
| `sks-push-subscriber.json` | subscriber without keys (with `udp-secure-publisher.json`); the keys are pushed with SetSecurityKeys |

Publisher, UDP unicast (two of the ten fields shown):

```json
{
  "configuration": {
    "PublishedDataSets": [{
      "Name": "InteropDataSet",
      "DataSetMetaData": {
        "Name": "InteropDataSet",
        "Fields": [
          {"Name": "Int32",   "BuiltInType": 6, "DataType": "i=6", "ValueRank": -1},
          {"Name": "Counter", "BuiltInType": 8, "DataType": "i=8", "ValueRank": -1}
        ]
      },
      "DataSetSource": {"UaTypeId": "i=15581", "UaBody": {"PublishedData": [
        {"PublishedVariable": "nsu=urn:otfabric:opcua-interop:model;s=PubSub.Int32",   "AttributeId": 13},
        {"PublishedVariable": "nsu=urn:otfabric:opcua-interop:model;s=Dynamic.Counter", "AttributeId": 13}
      ]}}
    }],
    "Connections": [{
      "Name": "InteropPublisher", "Enabled": true,
      "PublisherId": {"UaType": 5, "Value": 2234},
      "TransportProfileUri": "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp",
      "Address": {"UaTypeId": "i=15510", "UaBody": {"Url": "opc.udp://localhost:4840"}},
      "WriterGroups": [{
        "Name": "InteropWriterGroup", "Enabled": true, "WriterGroupId": 100,
        "PublishingInterval": 100,
        "MessageSettings": {"UaTypeId": "i=15645", "UaBody": {"NetworkMessageContentMask": 231}},
        "TransportSettings": {"UaTypeId": "i=23613", "UaBody": {
          "Address": {"UaTypeId": "i=15510", "UaBody": {"Url": "opc.udp://pubsub-subscriber:4841"}}}},
        "DataSetWriters": [{
          "Name": "InteropWriter", "Enabled": true, "DataSetWriterId": 1,
          "DataSetName": "InteropDataSet", "KeyFrameCount": 1, "DataSetFieldContentMask": 0,
          "MessageSettings": {"UaTypeId": "i=15652", "UaBody": {"DataSetMessageContentMask": 61}}
        }]
      }]
    }],
    "Enabled": true
  }
}
```

(`NetworkMessageContentMask` 231 = PublisherId | GroupHeader | WriterGroupId
| SequenceNumber | PayloadHeader | Timestamp; `DataSetMessageContentMask` 61 =
Timestamp | Status | MajorVersion | MinorVersion | SequenceNumber.)

Subscriber, UDP unicast:

```json
{
  "configuration": {
    "Connections": [{
      "Name": "InteropSubscriber", "Enabled": true,
      "PublisherId": {"UaType": 5, "Value": 2235},
      "TransportProfileUri": "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp",
      "Address": {"UaTypeId": "i=15510", "UaBody": {"Url": "opc.udp://0.0.0.0:4841"}},
      "ReaderGroups": [{
        "Name": "InteropReaderGroup", "Enabled": true,
        "DataSetReaders": [{
          "Name": "InteropReader", "Enabled": true,
          "PublisherId": {"UaType": 5, "Value": 2234},
          "WriterGroupId": 100, "DataSetWriterId": 1,
          "DataSetMetaData": {"Name": "InteropDataSet", "Fields": [
            {"Name": "Int32",   "BuiltInType": 6, "DataType": "i=6", "ValueRank": -1},
            {"Name": "Counter", "BuiltInType": 8, "DataType": "i=8", "ValueRank": -1}
          ]},
          "MessageReceiveTimeout": 0,
          "MessageSettings": {"UaTypeId": "i=15653", "UaBody": {
            "NetworkMessageContentMask": 231, "DataSetMessageContentMask": 61}},
          "SubscribedDataSet": {"UaTypeId": "i=15631", "UaBody": {"TargetVariables": [
            {"TargetNodeId": "nsu=urn:otfabric:opcua-interop:model;s=PubSub.Int32", "AttributeId": 13},
            {"TargetNodeId": "nsu=urn:otfabric:opcua-interop:model;s=PubSub.Int64", "AttributeId": 13}
          ]}}
        }]
      }]
    }],
    "Enabled": true
  }
}
```

MQTT JSON — the differences: `TransportProfileUri`
`…/pubsub-mqtt-json`, `Address` `mqtt://mosquitto:1883`, WriterGroup
`"TransportSettings": {"UaTypeId": "i=15667", "UaBody": {"QueueName": "opcua-interop/json"}}`
and `"MessageSettings": {"UaTypeId": "i=15657", "UaBody": {"NetworkMessageContentMask": 11}}`,
DataSetWriter `"MessageSettings": {"UaTypeId": "i=15664", "UaBody": {"DataSetMessageContentMask": 63}}`,
DataSetReader `"TransportSettings": {"UaTypeId": "i=15670", "UaBody": {"QueueName": "opcua-interop/json"}}`
and `"MessageSettings": {"UaTypeId": "i=15665", …}`. What open62541 publishes:

```json
{"MessageId":null,"MessageType":"ua-data","PublisherId":"2234","Messages":[{"DataSetWriterId":1,
 "SequenceNumber":99,"MetaDataVersion":{"MajorVersion":2369083044,"MinorVersion":2369080796},
 "Timestamp":"2026-10-23T20:54:39.758101Z","Status":{},"MessageType":"ua-keyframe",
 "Payload":{"Boolean":{"UaType":1,"Value":false},"Int32":{"UaType":6,"Value":7731},
  "Counter":{"UaType":8,"Value":"39"}, … ,"ByteString":{"UaType":15,"Value":null},
  "Int32Array":{"UaType":6,"Value":[1,2,7731]}}}]}
```

Security — on both the WriterGroup and the ReaderGroup
`"SecurityMode": 3, "SecurityGroupId": "InteropGroup"`, plus on both sides:

```json
"securityGroups": [{
  "securityGroupId": "InteropGroup",
  "securityPolicyUri": "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR",
  "keys": [{"tokenId": 1,
            "key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyBlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhKGio6Q="}]
}]
```

(signing key 0x01…0x20, encrypting key 0x65…0x84, key nonce A1 A2 A3 A4.)
With an SKS instead of static keys: the publisher has `"serveSks": true` and
the group without `keys`; the subscriber has the group without `keys` and
`"sksClient": {"endpointUrl": "opc.tcp://pubsub-publisher:4840/opcua-interop",
"securityPolicyUri": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
"securityMode": "SignAndEncrypt", "username": "test-user", "password": "test-password"}`
— both servers started with `--certificate`, `--private-key`, `--pki-dir`.

### 14.9 `codec` PubSub operations

Byte-level interop of the message mappings without a transport, with
open62541's `UA_NetworkMessage_encodeBinary` / `_decodeBinary` /
`_encodeJson` / `_decodeJson`:

| Op | Input (`--document`, `--input` or stdin) | Result |
|----|------------------------------------------|--------|
| `pubsub-uadp-encode` | description (JSON) | `encoded` = UADP NetworkMessage (Base64), `length` |
| `pubsub-uadp-decode` | UADP NetworkMessage (Base64 text) | `networkMessage` = description, `reencoded` (Base64), `reencodeStatusCode` |
| `pubsub-json-encode` | description (JSON) | `encoded` = the JSON NetworkMessage (as a JSON string), `length` |
| `pubsub-json-decode` | JSON NetworkMessage | `networkMessage`, `reencoded` (JSON string), `reencodeStatusCode` |

`--metadata <json>` / `--metadata-file <file>`: a `DataSetMetaDataType` (OPC
UA JSON, applies to every DataSetMessage) or
`[{"dataSetWriterId": n, "metaData": <DataSetMetaDataType>}, …]`. Needed to
decode **RawData** (field types, ValueRank, ArrayDimensions,
MaxStringLength) and a UADP message without payload header (the
DataSetMessage count); for JSON it orders the Payload keys and names the
fields. Encoding builds the metadata from the description's field `name` /
value types unless `--metadata` is given (e.g. for MaxStringLength padding).

Result envelope (operation `codec`), e.g.:

```json
{"action":"pubsub-uadp-encode","mapping":"uadp","statusCode":{"name":"Good","code":0,"severity":"Good"},
 "encoded":"8SG6CAlkAAcAAU30hyYcRNVi3QEJAwAEAAb7////DAIAAABoaQn//////////4YDAAAAAQAAAAIAAAADAAAA","length":63}
```

An encode / decode failure: `success: false`, `serviceResult` = the stack's
status (`BadDecodingError`, `BadEncodingError`, `BadNotImplemented`, …), exit
4; a malformed description or option: exit 2 (`error.category: "input"`).

**Description of a NetworkMessage.** Members are present only when the
corresponding header field / flag is present (on decode) and enable it when
present (on encode):

| Member | Type | Mapping |
|--------|------|---------|
| `mapping` | `"uadp"` \| `"json"` | output only |
| `version` | number | UADP version (low 4 bits of the first byte; default 1). UADP only |
| `messageId` | string | JSON `MessageId` |
| `publisherId` | `{"type": "Byte"\|"UInt16"\|"UInt32"\|"UInt64"\|"String", "value": …}` | UInt64 value as a decimal string. JSON decoding yields `UInt64` for numeric ids (JSON has no width) |
| `dataSetClassId` | Guid string | |
| `groupHeader` | `{"writerGroupId", "groupVersion", "networkMessageNumber", "sequenceNumber"}` — each optional | UADP GroupHeader |
| `payloadHeader` | boolean | UADP PayloadHeader (DataSetWriterIds on the wire; default `true` on encode). Always true for JSON |
| `timestamp` | RFC 3339 UTC, **7 fractional digits** (full 100 ns resolution) | NetworkMessage Timestamp |
| `picoseconds` | number | |
| `promotedFields` | `[{"dataType", "builtInType", "value"}, …]` | UADP PromotedFields |
| `security` | `{"signed", "encrypted", "forceKeyReset", "securityTokenId", "nonce": "<Base64>", ["securityFooterSize"]}` | UADP SecurityHeader — **fields only**: nothing is signed, encrypted, verified or decrypted (the standalone API has no security; signed / encrypted traffic is covered by the live path, §14.5) |
| `securityFooter` | Base64 | |
| `chunk` | boolean | UADP chunk flag (decoded; chunked payloads are not reassembled) |
| `messages` | array of DataSetMessages (max 32) | |

DataSetMessage:

| Member | Type | Mapping |
|--------|------|---------|
| `dataSetWriterId` | number | from the payload header (UADP) / `DataSetWriterId` (JSON); absent on decode when not on the wire |
| `messageType` | `KeyFrame` \| `DeltaFrame` \| `KeepAlive` \| `Event` | JSON: KeyFrame only; Event: `BadNotImplemented` |
| `fieldEncoding` | `Variant` \| `RawData` \| `DataValue` | JSON decode always reports `DataValue` |
| `valid` | boolean | DataSetFlags1 bit 0 (default true) |
| `sequenceNumber` | number (UInt16) | |
| `timestamp`, `picoseconds` | as above | |
| `status` | number (UInt16) | UADP: the 16-bit status; JSON `Status` (a StatusCode; open62541 rejects values > 65535 on decode) |
| `configVersion` | `{"majorVersion", "minorVersion"}` | UADP ConfigurationVersion / JSON `MetaDataVersion` |
| `fields` | array | KeyFrame: one per field; DeltaFrame: with `index` |

Field: `{["name"], ["index"], "dataType", "builtInType", ["arrayDimensions"], "value"}` —
the canonical Variant encoding of §7 (`dataType` "Null" / `value` null for an
empty Variant; arrays are JSON arrays). With `fieldEncoding: "DataValue"` also
`statusCode` (§7 object; on encode also a number), `sourceTimestamp`,
`sourcePicoseconds`, `serverTimestamp`, `serverPicoseconds` (timestamps with 7
fractional digits). `name` comes from the metadata (or the JSON Payload key);
on encode it becomes the JSON Payload key. Field values follow §7 (DateTime
values at millisecond precision; Int64 / UInt64 as strings).

Example (`pubsub-uadp-decode` of the message above):

```json
{"mapping":"uadp","version":1,"publisherId":{"type":"UInt16","value":2234},
 "groupHeader":{"writerGroupId":100,"sequenceNumber":7},"payloadHeader":true,
 "timestamp":"2026-10-23T10:00:00.1234567Z","chunk":false,
 "messages":[{"dataSetWriterId":62541,"messageType":"KeyFrame","fieldEncoding":"Variant","valid":true,
   "sequenceNumber":3,"fields":[{"dataType":"Int32","builtInType":6,"value":-5},
     {"dataType":"String","builtInType":12,"value":"hi"},
     {"dataType":"UInt64","builtInType":9,"value":"18446744073709551615"},
     {"dataType":"Int32","builtInType":6,"value":[1,2,3]}]}]}
```

JSON example — description
`{"messageId":"m-1","publisherId":{"type":"String","value":"pub-a"},"messages":[{"dataSetWriterId":7,"messageType":"KeyFrame","fieldEncoding":"DataValue","sequenceNumber":9,"timestamp":"2026-10-23T10:00:00Z","status":0,"configVersion":{"majorVersion":1,"minorVersion":2},"fields":[{"name":"Temp","dataType":"Double","value":21.5,"sourceTimestamp":"2026-10-23T09:59:59.5Z"}]}]}`
encodes to
`{"MessageId":"m-1","MessageType":"ua-data","PublisherId":"pub-a","Messages":[{"DataSetWriterId":7,"SequenceNumber":9,"MetaDataVersion":{"MajorVersion":1,"MinorVersion":2},"Timestamp":"2026-10-23T10:00:00Z","Status":{},"MessageType":"ua-keyframe","Payload":{"Temp":{"UaType":11,"Value":21.5,"SourceTimestamp":"2026-10-23T09:59:59.5Z"}}}]}`.

### 14.10 open62541 v1.5.9 behaviour and limits

| Feature | Status |
|---------|--------|
| UADP over UDP unicast / multicast, MQTT | ✓ publish and subscribe |
| JSON over MQTT | ✓ publish; subscribe with the backport above. JSON over UDP is not a Part 14 profile (not offered) |
| Field encodings | Variant, DataValue, RawData (RawData subscribing needs `MaxStringLength` for String / ByteString fields) |
| KeyFrames | ✓ |
| DeltaFrames | UADP encode / decode ✓ (not RawData). Published only with `"deltaFrames": true`; v1.5.9 then sends KeyFrameCount DeltaFrames after each KeyFrame (one more than Part 14 — even KeyFrameCount 1 alternates Key / Delta). **The v1.5.9 DataSetReader discards DeltaFrames** ("Only keyframes are supported"), hence off by default |
| KeepAlive DataSetMessages | codec ✓; a writer with an empty `DataSetName` sends heartbeat KeyFrames with 0 fields |
| Event DataSetMessages, PublishedEvents | ✗ (`BadNotImplemented`) |
| Chunked NetworkMessages | ✗ (flag only) |
| Promoted fields, DataSetClassId, GroupVersion, picoseconds | ✓ |
| Discovery messages (DataSetMetaData / announcements), MetaDataQueueName | ✗ |
| SubscribedDataSetMirror, StandaloneSubscribedDataSets via the configuration | ✗ (TargetVariables only) |
| Fixed layouts (ConfiguredSize, NetworkMessageNumber, DataSetOffset) | ✗ (reset with a warning) |
| MessageReceiveTimeout | ✓ — the reader goes to **Error** and stays there: later messages are dropped until it is disabled and enabled again (Status methods). The examples use 0 |
| JSON `MessageId` | always `null` |
| JSON metadata version | generated by open62541 (not the configured ConfigurationVersion) |
| Security | UADP only, PubSub-Aes128-CTR / PubSub-Aes256-CTR (OpenSSL port) |
| SKS | server (`GetSecurityKeys`, `SetSecurityKeys`), pull client, push target; `AddSecurityGroup` / `RemoveSecurityGroup` via the adapter binding; `TimeToNextKey` from GetSecurityKeys is wrong (negative) |
| MQTT | QoS 0, anonymous, no TLS, 1024-byte buffers |
| `UA_NetworkMessage_encodeJson` | needs encoding metadata for every DataSetWriterId (v1.5.9 dereferences NULL otherwise); the codec always provides it |

### 14.11 `print-capabilities` → `pubsub`

open62541:

```json
"pubsub": {
  "supported": true,
  "serverFlag": "--pubsub-config",
  "roles": ["publisher", "subscriber"],
  "transports": ["udp-uadp", "mqtt-uadp", "mqtt-json"],
  "transportProfiles": ["http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp", "…/pubsub-mqtt-uadp", "…/pubsub-mqtt-json"],
  "udp": {"unicast": true, "multicast": true},
  "encodings": ["uadp", "json"],
  "fieldEncodings": ["Variant", "DataValue", "RawData"],
  "dataSetMessageTypes": {"uadp": ["KeyFrame", "DeltaFrame", "KeepAlive"], "json": ["KeyFrame"]},
  "publishedDataSets": ["PublishedDataItems"],
  "subscribedDataSets": ["TargetVariables"],
  "securityPolicies": ["http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR", "…#PubSub-Aes256-CTR"],
  "securityModes": ["None", "Sign", "SignAndEncrypt"],
  "securityEncodings": ["uadp"],
  "keySources": ["static", "sks-pull", "sks-push", "sks-server"],
  "sks": {"server": true, "pull": true, "push": true, "methods": ["GetSecurityKeys", "SetSecurityKeys", "AddSecurityGroup", "RemoveSecurityGroup"]},
  "informationModel": true,
  "informationModelMethods": ["AddConnection", "RemoveConnection", "AddWriterGroup", "AddReaderGroup", "RemoveGroup", "…"],
  "codecOps": ["pubsub-uadp-encode", "pubsub-uadp-decode", "pubsub-json-encode", "pubsub-json-decode"],
  "codecSecurity": false
}
```

UA-.NETStandard (adapter 0.10.0):

```json
"pubsub": {
  "supported": true,
  "serverFlag": "--pubsub-config",
  "roles": ["publisher", "subscriber"],
  "transports": ["udp-uadp", "mqtt-uadp", "mqtt-json"],
  "transportProfiles": ["http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp", "…/pubsub-mqtt-uadp", "…/pubsub-mqtt-json"],
  "udp": {"unicast": true, "multicast": true},
  "mqttVersions": ["5.0", "3.1.1", "3.1"],
  "encodings": ["uadp", "json"],
  "fieldEncodings": ["Variant", "DataValue", "RawData"],
  "dataSetMessageTypes": {"uadp": ["KeyFrame", "DeltaFrame", "KeepAlive"], "json": ["KeyFrame", "DeltaFrame", "KeepAlive"]},
  "publishedDataSets": ["PublishedDataItems"],
  "subscribedDataSets": ["TargetVariables"],
  "securityPolicies": ["http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR", "…#PubSub-Aes256-CTR"],
  "securityModes": ["None", "Sign", "SignAndEncrypt"],
  "securityEncodings": ["uadp"],
  "keySources": ["static"],
  "sks": {"server": false, "pull": false, "push": false},
  "informationModel": false,
  "chunking": true,
  "discovery": {"layout": "dotnet", "respond": ["DataSetMetaData", "DataSetWriterConfiguration"],
                "probe": ["DataSetMetaData", "DataSetWriterConfiguration"], "clientOperation": "pubsub-discover"},
  "codecOps": ["pubsub-uadp-encode", "pubsub-uadp-decode", "pubsub-json-encode", "pubsub-json-decode"],
  "codecSecurity": false
}
```

Members added in adapter 0.10.0 (absent = not offered): `mqttVersions` (the
MQTT versions the MQTT transports connect with, the default first),
`chunking` (a WriterGroup `MaxNetworkMessageSize` below the NetworkMessage
size makes the publisher send chunk NetworkMessages, and subscribers
reassemble them), `discovery` (UADP discovery, Part 14 §7.2.4.6: `layout`
`spec` or `dotnet` (§14.13), the announcement types a publisher sends when
probed (`respond`), the probe types `clientOperation` sends (`probe`)).

Milo:

```json
"pubsub": {"supported": false, "reason": "Eclipse Milo 1.1.8 has no PubSub (Part 14) implementation",
           "transports": [], "encodings": [], "roles": [], "securityPolicies": [],
           "sks": {"server": false, "pull": false, "push": false},
           "informationModel": false, "codecOps": []}
```

### 14.12 Eclipse Milo 1.1.8

Not implemented by the stack. The Milo 1.1.8 artifacts (`milo-stack-core`,
`milo-sdk-core`, `milo-sdk-server`, `milo-sdk-client`, `milo-transport`,
`milo-encoding-json`, `milo-encoding-xml`; Maven Central has no other Milo
PubSub artifact) contain only the generated PubSub DataTypes
(`stack-core …/types/structured/PubSubConnectionDataType`, `Uadp…`, `Json…`)
and ObjectType / Method stubs (`sdk-server …/model/objects/PubSub…Type`) —
no NetworkMessage encoder, no UDP / MQTT transport, no PublishSubscribe
runtime, no SKS. The Milo adapter therefore refuses `--pubsub-config` and
`codec pubsub-*` (exit 2, `error.category: "input"`) and declares
`pubsub.supported: false`.

### 14.13 UA-.NETStandard 2.0.1

Added in adapter **0.10.0**. The dotnet server runs the stack's PubSub runtime
(NuGet `OPCFoundation.NetStandard.Opc.Ua.PubSub`, `.PubSub.Udp`,
`.PubSub.Mqtt` 2.0.1) next to the fixture server, from the same
`--pubsub-config` file as open62541 (§14.1). `configuration` is decoded by the
stack's JSON decoder with the conventions of §14.2, PublishedDataItems read the
fixture variables at every publish, and TargetVariables write them. As for
open62541, the configuration is applied before the ready file is written; an
error is logged as `[dotnet] error: --pubsub-config: <reason>` and the server
exits 1. Progress: `[dotnet] info: pubsub: configuration applied (…)`;
`OPCUA_INTEROP_LOG_LEVEL=Debug` shows the stack's state machines and
transports.

**Adaptations.** Opc.Ua.PubSub 2.0.1 reads some members of the configuration
differently from open62541; the adapter rewrites them so a file means the same
on both adapters:

| Contract | Opc.Ua.PubSub 2.0.1 | The adapter |
|----------|---------------------|-------------|
| `opc.mqtt://` broker URL | parses `mqtt://` only | rewrites `opc.mqtt://` to `mqtt://` |
| `opc.udp://localhost:<p>` (receive-all) | binds the address | rewrites it to `opc.udp://0.0.0.0:<p>` |
| WriterGroup unicast destination (DatagramWriterGroupTransport2DataType `Address`) | sends to the connection address only | moves the WriterGroup to a send-only connection `<connection>/<writer group>` of its own (same PublisherId) whose address is the destination |
| A publisher connection on a receive-all or multicast address | a connection without ReaderGroups only sends | adds an empty ReaderGroup `<connection>/probes`, so it receives on its port (and joins the group) and answers discovery probes |
| `MessageReceiveTimeout` 0 (no timeout) | rejected | one day |
| `KeepAliveTime` below `PublishingInterval` | rejected | `PublishingInterval` |
| Static keys (`securityGroups[].keys`) | a secured group needs a `SecurityKeyServices` entry | a placeholder endpoint that is never contacted; the first key is the current key of the group's key ring with its `tokenId` |
| Security per ReaderGroup | per DataSetReader too | clears the DataSetReader `SecurityMode` / `SecurityGroupId` / `SecurityKeyServices` |
| `deltaFrames` false (default) | DeltaFrames between KeyFrames per `KeyFrameCount` | `KeyFrameCount` 1 on every DataSetWriter |
| WriterGroup `MaxNetworkMessageSize` | taken per connection, from a resolver `PubSubApplicationBuilder` cannot set | the smallest `MaxNetworkMessageSize` of a connection's WriterGroups; a larger NetworkMessage is sent as chunk NetworkMessages (Part 14 §7.2.4.4.4), each secured on its own |
| MQTT DataSetReader / ReaderGroup `QueueName` | subscribes only the default discovery topics (`opcua/<encoding>/metadata/…`) | adds the QueueNames of the BrokerDataSetReaderTransportDataType (and ReaderGroup) to the subscriptions |
| UDP TTL | `UdpTransportOptions.Ttl` (default 1) is applied to unicast datagrams too: a datagram to the Docker host through its gateway is dropped | `Ttl` 64 (unicast and multicast) |
| UDP multicast loopback | `UdpTransportOptions.MulticastLoopback` false: a subscriber on the publisher's host never receives its multicast | `MulticastLoopback` true (adapter 0.15.0, `serverFeatures` `pubsub-multicast-loopback`) |

A publisher on a receive-all address (`opc.udp://0.0.0.0:<p>`) without a
WriterGroup destination sends its NetworkMessages to the last address it
received a datagram from (the stack's unicast behaviour).

**MQTT.** MQTTnet client, clean session, keep-alive 60 s, QoS 1 (AtLeastOnce)
unless the WriterGroup's BrokerWriterGroupTransportDataType
`RequestedDeliveryGuarantee` asks for another, anonymous, no TLS, NetworkMessages
up to 65535 bytes. The version is the top-level `mqtt.protocolVersion`:

| `protocolVersion` | Subscribe | Publish |
|-------------------|:---------:|:-------:|
| `"5.0"` (default) | ✓ | ✓ (ContentType `application/opcua+uadp` / `application/json`) |
| `"3.1.1"`, `"3.1"` | ✓ | — the stack sets the MQTT 5 ContentType on every publication and MQTTnet refuses it below 5.0; a WriterGroup on an MQTT connection is refused (exit 1) |

**Not offered** (refused with exit 1, or absent): `serveSks` and `sksClient`
(static keys only, `keySources: ["static"]`), SKS push (the server has no
`PublishSubscribe` object: `informationModel: false`, no SetSecurityKeys),
the PublishSubscribe information model, raw Ethernet and AMQP (not in the
stack), PublishedEvents and SubscribedDataSetMirror, JSON message security.

**Codec** (§14.9, with the stack's UadpEncoder / UadpDecoder and
JsonEncoder / JsonDecoder; `codecSecurity: false`). The description format is
the same; where the encoding differs from open62541 and go-opcua:

| Case | Opc.Ua.PubSub 2.0.1 |
|------|---------------------|
| An empty String field | written with length 0 (`0c 00000000`); a null String with length −1 (`0c ffffffff`), as it was decoded |
| A DataSetMessage with `valid: false` (DataSetFlags1 bit 0 clear) | dropped on decode (Part 14 §7.2.4.5.4: its content is invalid), so `reencoded` has no DataSetMessage; the encoder always sets the flag |
| JSON encode with `--metadata` | fields whose type the metadata gives are written without `UaType` (`"Fa":1`, DataValue `{"Value":21.5,"SourceTimestamp":…}`); without `--metadata` the encoding stays self-describing (`UaType` on every field) |
| JSON DataSetMessage `Status` | `{"Code":n,"Symbol":"…"}` |
| JSON DataSetMessage types | KeyFrame, DeltaFrame and KeepAlive |

**Discovery** (`discovery` in §14.11). Part 14 §7.2.4.6 discovery request /
response over UDP in the layout of the .NET stack (`layout: "dotnet"`, the
stack's UadpDiscoveryCoder): a probe carries one type byte (the
InformationType, no ProbeType) and the DataSetWriterIds; every structure of an
announcement is preceded by its length as a UInt32. A dotnet publisher answers
DataSetMetaData and DataSetWriterConfiguration probes that reach its
connection (the probe ReaderGroup above; probes for the other types are not
answered), and announces its DataSetMetaData when it starts.

```
client pubsub-discover --url opc.udp://<host>:<port>
       [--type DataSetMetaData|DataSetWriterConfiguration]   (default DataSetMetaData)
       [--writer-ids <id>,…]          (DataSetWriterIds of the probe; default none)
       [--publisher-id <UInt16>]      (PublisherId of the probing connection)
       [--timeout-ms <n>]             (default 3000)
```

opens a UDP connection on `--url` (bound to its port; a multicast group is
joined), sends the probe there and collects the announcements until
`--timeout-ms`. Result (operation `pubsub-discover`):

```json
{"url":"opc.udp://224.0.0.22:4840","type":"DataSetMetaData","dataSetWriterIds":[],
 "dataSetMetaData":[{"publisherId":{"type":"UInt16","value":2234},"writerGroupId":100,"dataSetWriterId":1,
   "statusCode":{"name":"Good","code":0,"severity":"Good"},
   "metaData":{"name":"InteropDataSet","configurationVersion":{"majorVersion":1,"minorVersion":1},
     "fields":[{"name":"Boolean","builtInType":1,"dataType":"i=1","valueRank":-1}, …]}}],
 "writerConfigurations":[]}
```

`writerConfigurations[]`: `publisherId`, `writerGroupId`, `dataSetWriterIds`,
`statusCode`, `writerGroup` (`name`, `writerGroupId`, `publishingInterval`,
`dataSetWriters[]` with `name`, `dataSetWriterId`, `dataSetName`). No
announcement within the timeout: `success: false`, `serviceResult`
`BadTimeout`, exit 7. The probe is the stack's; a peer must speak the .NET
layout to answer it.

**Smoke.** `make smoke-pubsub-dotnet` (`scripts/pubsub-smoke.sh` with the
dotnet image) runs the scenarios `codec`, `udp-unicast`, `udp-multicast`,
`mqtt-uadp`, `mqtt-json`, `udp-secure` and `discovery` (a
`pubsub-discover` of both types against the multicast publisher) on the
example files of `pubsub/examples/`; the SKS and information-model scenarios
do not apply.

## 15. Push certificate management (OPC UA Part 12 §7)

Added in adapter **0.13.0**. The adapter servers that declare
`serverFeatures` `push-management` serve the ServerConfiguration object
(i=12637) of their stack when started with `--certificate`, `--private-key`
and `--pki-dir`: the DefaultApplicationGroup with its TrustList (FileType and
TrustListType methods), UpdateCertificate, CreateSigningRequest,
GetRejectedList and ApplyChanges. The trust list is the one the server
validates new channels with (`--pki-dir`, §11); the pushed changes stay in
the container.

**Roles.** A fixture user is granted the well-known roles (Part 3 §4.9.2)
named in its `roles` by BrowseName: `Observer`, `Operator`, `Engineer`,
`Supervisor`, `ConfigureAdmin`, `SecurityAdmin` (AuthenticatedUser always).
Part 12 §7.2 limits the methods to SecurityAdmin on a SignAndEncrypt channel;
a test adds such a user to a copy of the baseline fixture, e.g.

```json
{ "username": "sec-admin", "password": "sec-admin-password", "roles": ["AuthenticatedUser", "SecurityAdmin"] }
```

| | open62541 1.5.9 | UA-.NETStandard 2.0.1 | node-opcua 2.187.12 |
|---|---|---|---|
| Implementation | `UA_ENABLE_GDS_PUSHMANAGEMENT` (in-memory certificate group of `UA_ServerConfig_setDefaultWithSecurityPolicies`) | the stack's ConfigurationNodeManager | `installPushCertificateManagementOnServer` (node-opcua-server-configuration), `closeChannelsOnApplyChanges: false` |
| Access | any session on a SignAndEncrypt channel (no roles in v1.5.9) | SecurityAdmin (fixture roles), SignAndEncrypt; others `BadUserAccessDenied` | as UA-.NETStandard |
| CertificateTypes | RsaMin, RsaSha256 | RsaMin (empty slot), RsaSha256 | RsaSha256 |
| SupportedPrivateKeyFormats | PEM, DER | PFX, PEM | PEM |
| ApplyChanges without a pending change | `BadNothingToDo` | Good | `BadNothingToDo` |
| After ApplyChanges | the channels whose certificates changed are closed shortly after the response | — | open channels keep the old certificate |
| ServerCertificate of the endpoints after UpdateCertificate with issuers | the certificate | the certificate followed by its issuers (a chain) | the certificate followed by its issuers |
| RemoveCertificate thumbprint | hexadecimal, either case | upper-case hexadecimal only (`BadInvalidArgument` otherwise) | hexadecimal |

The node-opcua server serves the certificate manager's own pair, so the
adapter copies `--certificate` / `--private-key` to
`<pki-dir>/own/certs/certificate.pem` and the manager's private key file.

**Client.** `client push` (§1) is node-opcua's ClientPushCertificateManagement
and TrustListClient. Since adapter 0.15.0 it also works on the DefaultHttpsGroup
and DefaultUserTokenGroup (`--group`, clientFeatures `push-groups`) and calls
the Part 12 1.05 methods node-opcua-server-configuration 2.187.12 has no
client helper for — GetCertificates, CreateSelfSignedCertificate,
DeleteCertificate, ResetToServerDefaults, CancelChanges — as plain Call
requests on the standard NodeIds of ServerConfiguration
(`push-certificates`, with UpdateCertificate with a PEM or PFX private key),
and reads the TransactionDiagnostics variables (`push-transaction-diagnostics`).
The node-opcua server answers these 1.05 methods with `Bad_MethodInvalid` or
`Bad_InternalError` (unbound) and cannot encode its TransactionDiagnostics;
they are meant for servers that implement Part 12 1.05.

Since adapter 0.15.0 `client push`, with every flag of §1 "push flags" and the
§4 `push` result, is also on asyncua, async-opcua, Eclipse Milo,
open62541 and UA-.NETStandard (`dotnet`) (clientOperations `push`,
clientFeatures `push-groups`, `push-certificates`,
`push-transaction-diagnostics`). None of opcua-asyncio 2.1.0, async-opcua
0.19, Milo 1.1.8 or open62541 v1.5.9 has a push client, and UA-.NETStandard's
(ServerPushConfigurationClient) is not used, so these adapters send plain Call requests on the standard NodeIds of
ServerConfiguration and of the group's TrustList (OpenWithMasks / Read /
Close), on one session, and decode the TrustListDataType and the
TransactionDiagnostics themselves where the stack has no codec for them.

---

## 16. GDS pull model (OPC UA Part 12 §6, §7.9)

Added in adapter **0.14.0** as a separate adapter, `dotnet-gds` (image
`ghcr.io/otfabric/opcua-interop-dotnet-gds`, project `adapters/dotnet-gds/`): a Global
Discovery Server and a GDS pull-model client on OPC Foundation
UA-.NETStandard. Since adapter **0.15.0** it runs on UA-.NETStandard
**2.0.1** (every `OPCFoundation.NetStandard.Opc.Ua.*` package pinned to
exactly that version: Server, Client, Configuration, Gds.Server, Gds.Client —
the 2.0 names of the Gds.Server.Common / Gds.Client.Common packages);
adapter 0.14.0 ran on 1.5.378.182. It stays a project of its own, next to the
`dotnet` adapter: its server is a Global Discovery Server, not the fixture
address space, and it has its own capability document. Its
`print-capabilities` (§13):

| Field | Value |
|-------|-------|
| `adapter` | `{"name": "dotnet-gds", "version": "0.15.0"}` (also the server's BuildInfo SoftwareVersion) |
| `stack` | `{"name": "opcfoundation-uanetstandard", "version": "2.0.1"}` |
| `clientOperations` | `["endpoints", "gds-pull"]` |
| `clientFeatures` | `["application-uri"]` |
| `serverFeatures` | `["gds-pull"]` |
| `securityProfiles` | None/None, Basic256Sha256 Sign and SignAndEncrypt, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss SignAndEncrypt |
| `transports` | `["opc.tcp"]`; `pubsub.supported` is false |

`validate-fixture`, `test` (offline self-test) and the exit codes of §5 are as
for the other adapters.

### 16.1 Server

```
<image> server --fixture <file> [--certificate <crt> --private-key <key> --pki-dir <dir>]
        [--bind-port <n>] [--advertised-host <host>] [--advertised-port <n>]
        [--endpoint-path <path>] [--ready-file <path>] [--no-certificate-chain]
```

The server is a Global Discovery Server, the stack's
`GlobalDiscoverySampleServer` (`Opc.Ua.Gds.Server`): the
ApplicationsNodeManager with **autoApprove** (StartSigningRequest /
StartNewKeyPairRequest are approved at once, FinishRequest issues on its first
call), a JSON applications database in a temporary directory (empty at every
start), and the CertificateGroup `Default` (the DefaultApplicationGroup) with
CertificateTypes RsaSha256ApplicationCertificateType and
EccNistP256ApplicationCertificateType. The group's CAs
(`CN=opcua-interop dotnet-gds CA, O=OTFabric`, one RSA 2048 and one ECC P-256)
are generated at startup inside the container; issued certificates get the
subject of the CSR, or `<subjectName>, O=OTFabric` for a new key pair. The
fixture's address space is **not** served — only `server`, `endpoint` and
`users` of the fixture are used (`fixtures/gds/fixture.json` is the baseline
plus the GDS administrator).

- Endpoint: `opc.tcp://<advertised-host>:<port><endpoint-path>`, port 4840 and
  path `/opcua-interop` with the fixtures (§11 defaults). The listener binds
  every interface (`--bind-address` is accepted and has no effect).
- Security: None/None always; with `--certificate` / `--private-key` also the
  secure profiles of `securityProfiles` above, with that certificate as the
  application instance certificate. `--pki-dir` uses the §11 layout:
  `trusted/certs` (+ `trusted/crl`) and `issuers/certs` (+ `issuers/crl`) are
  copied into the stack's directory stores; clients signed by a CA in
  `trusted/certs` are accepted; rejected certificates go to
  `<pki-dir>/rejected` when writable.
- ApplicationUri: the URI SAN of `--certificate`, else the fixture's
  `server.applicationUri` — `urn:otfabric:opcua-interop:server` either way
  with the test PKI's `dotnet-server` identity and the fixtures.
  ApplicationType Server, ServerCapabilities `["GDS"]`, ServerProfileArray
  `GlobalDiscoveryAndCertificateManagement2017`.
- Namespaces: `ns=1` the server's ApplicationUri, `ns=2`
  `http://opcfoundation.org/UA/GDS/`: Directory `ns=2;i=141`,
  DefaultApplicationGroup `ns=2;i=615`, its TrustList `ns=2;i=616`; `ns=3`
  `http://opcfoundation.org/UA/GDS/applications/` (ApplicationIds and
  RequestIds are GUID NodeIds in it, e.g. `ns=3;g=7322e67a-…`); `ns=4`
  `http://opcfoundation.org/UA/Diagnostics`. Adapter 0.14.0 (1.5.378) had
  the two GDS namespaces the other way round: `ns=2` the applications
  namespace (`ns=2;g=…`), `ns=3` the GDS namespace (Directory `ns=3;i=141`,
  DefaultApplicationGroup `ns=3;i=615`, TrustList `ns=3;i=616`). Clients
  should resolve the indexes from the NamespaceArray.
- Users: the fixture `users` (UserName tokens; an unknown user or a wrong
  password is `BadUserAccessDenied` at ActivateSession) and Anonymous. A user
  is granted AuthenticatedUser and the roles named in its `roles` by
  BrowseName: `DiscoveryAdmin`, `CertificateAuthorityAdmin`,
  `RegistrationAuthorityAdmin` (GdsRole, Part 12 §6.2), `SecurityAdmin`,
  `ConfigureAdmin`, `Observer`, `Operator`, `Engineer`, `Supervisor` (Part 3
  §4.9.2). The sample server's own UserName authenticator checks the
  password against the in-memory `LinqUserDatabase` and turns the roles into
  a `GdsRoleBasedIdentity`. The administrator of `fixtures/gds/fixture.json`:

  ```json
  { "username": "gds-admin", "password": "gds-admin-password",
    "roles": ["AuthenticatedUser", "DiscoveryAdmin", "CertificateAuthorityAdmin", "SecurityAdmin"] }
  ```

- Who may call what (the 2.0.1 ApplicationsNodeManager; ApplicationAdmin is
  the Part 12 §7.2 privilege, not granted to any fixture user):

  | Method | Required |
  |--------|----------|
  | QueryServers, QueryApplications | anyone, also Anonymous |
  | FindApplications | anyone, also Anonymous (Part 12 §6.5.3); an empty ApplicationUri is `BadInvalidArgument` |
  | GetApplication | AuthenticatedUser or ApplicationSelfAdmin |
  | RegisterApplication | DiscoveryAdmin or ApplicationAdmin |
  | UpdateApplication, UnregisterApplication | DiscoveryAdmin, ApplicationSelfAdmin or ApplicationAdmin |
  | StartSigningRequest, StartNewKeyPairRequest, FinishRequest | CertificateAuthorityAdmin, ApplicationSelfAdmin or ApplicationAdmin, **and** a SignAndEncrypt channel (Sign or None: `BadSecurityModeInsufficient`) |
  | GetCertificateGroups, GetTrustList, GetCertificateStatus, GetCertificates | CertificateAuthorityAdmin, ApplicationSelfAdmin or ApplicationAdmin |
  | RevokeCertificate | CertificateAuthorityAdmin |
  | TrustList Open / Read / Close | CertificateAuthorityAdmin or SecurityAdmin (or the application's own trust list); writing it needs CertificateAuthorityAdmin |
  | CheckRevocationStatus | a Sign or SignAndEncrypt channel, any user (None: `BadSecurityModeInsufficient`) |

  ApplicationSelfAdmin is granted by the stack to a session whose channel
  client certificate is the one the GDS holds for a registered application
  with the certificate's ApplicationUri, whatever the user token (the sample
  server's rule, not exercised by the suite).
- Certificate chain: by default the ServerCertificate of the endpoints
  (GetEndpoints) and of CreateSession is the certificate followed by its
  issuers, DER certificates concatenated (Part 6 §6.2.3); with the test PKI
  the `dotnet-server` certificate (994 bytes) and `OTFabric Test CA` (854
  bytes). `--no-certificate-chain` (adapter **0.16.0**, a presence flag) sets
  the stack's `SecurityConfiguration.SendCertificateChain` to false, so both
  carry the certificate alone; the OpenSecureChannel SenderCertificate keeps
  the chain either way (§16.3). The default is the spec behaviour; the flag is
  there to test clients that do not take a chain (§16.3).
- Ready file (§10) once the server listens; SIGTERM / SIGINT → exit 0.
- Refused (exit 2): `--lds`, `--lds-cleanup-timeout`, `--mdns-name`,
  `--mdns-capability`, `--reverse-connect`, `--reverse-connect-interval-ms`,
  `--pubsub-config`, `--https-port`, `--wss-port`, `--register-with`.

### 16.2 `client gds-pull`

```
<image> client gds-pull --endpoint <url> [global flags (§1)] [gds-pull flags]
```

The pull-model client of Part 12 §6.6 / §7.9. `dotnet-gds` (adapter 0.14.0)
uses the stack's `GlobalDiscoveryServerClient` (`Opc.Ua.Gds.Client`), and so
does the `dotnet` adapter since 0.15.0 (Opc.Ua.Gds.Client 2.0.1). Since
adapter 0.15.0 asyncua, async-opcua, Eclipse Milo and open62541 also have
`gds-pull` (clientOperations): their stacks have no GDS client, so they run
the same steps as plain Call requests on the Directory of the GDS namespace
`http://opcfoundation.org/UA/GDS/` (its index read from the NamespaceArray),
encode ApplicationRecordDataType themselves and make the PKCS #10 request
with their own crypto library (`cryptography`, the RustCrypto `x509-cert` /
`rsa` / `p256` crates, Bouncy Castle, OpenSSL). They take the same flags and give
the same `results`. For `dotnet-gds` and `dotnet`, global flags as
in §1: `--security-policy`, `--security-mode`, `--certificate`,
`--private-key`, `--trust-list`, `--username`, `--password`,
`--application-uri`, `--connect-timeout`, `--request-timeout`,
`--disconnect-timeout` (RSA policies only). The session is created on the
endpoint of `--security-policy` / `--security-mode` that GetEndpoints lists,
dialled at `--endpoint` (§9); the domain check of the server certificate is
skipped, and without `--trust-list` every server certificate is accepted. The
other adapters connect as for their other client commands (§1, §9).
Most GDS methods need a user with the GDS roles, and the certificate
requests a SignAndEncrypt channel (§16.1), so a run normally has
`--username` / `--password` and SignAndEncrypt.

| Flag | Meaning | Default |
|------|---------|---------|
| `--app-uri <uri>` | ApplicationUri of the record to register / find | `urn:opcua-interop:gds-pull:app` |
| `--app-type <Server\|Client\|ClientAndServer>` | ApplicationType of the record | `Server` |
| `--discovery-url <url>` | DiscoveryUrl of the record (repeatable; required by the spec for servers) | `opc.tcp://localhost:4850` |
| `--request <csr\|new-key-pair>` | StartSigningRequest with a CSR the adapter makes, or StartNewKeyPairRequest | `csr` |
| `--certificate-type <RsaSha256\|NistP256>` | certificateTypeId of the request: RsaSha256ApplicationCertificateType (i=12560) or EccNistP256ApplicationCertificateType (i=23538) | `RsaSha256` |
| `--revoke` | RevokeCertificate of the issued certificate, then CheckRevocationStatus of it | off |
| `--unregister` | UnregisterApplication at the end | off |
| `--finish-timeout-ms <n>` | how long FinishRequest is polled while it answers `BadNothingToDo` | 30000 |

`--revoke` and `--unregister` are presence flags. An invalid `--app-type`,
`--request`, `--certificate-type` or `--finish-timeout-ms` is exit 2 before
connecting.

Steps, stopping at the first Bad status:

1. **FindApplications**(app uri).
2. **RegisterApplication** if nothing was found: ApplicationUri = app uri,
   ApplicationType, ApplicationNames `[en-US: <name>]` where `<name>` is the
   last `:` / `/` segment of the app uri (`"opcua-interop gds-pull app"` if
   empty), ProductUri `urn:opcua-interop:<adapter>` (`urn:opcua-interop:dotnet-gds`,
   `…:dotnet`, `…:asyncua`, `…:async-opcua`, `…:milo`, `…:open62541`), DiscoveryUrls (none for
   `Client`), ServerCapabilities `["NA"]` (none for `Client`). If a record was
   found, its ApplicationId (the first one) is used and nothing is registered.
3. **StartSigningRequest** (DefaultApplicationGroup, the certificate type, a
   PKCS #10 request with a fresh RSA 2048 / ECC P-256 key, subject
   `CN=<name>`, URI SAN = app uri, DNS SAN `localhost`, SHA-256) or
   **StartNewKeyPairRequest** (DefaultApplicationGroup, the certificate type,
   subject `CN=<name>`, domainNames `["localhost"]`, privateKeyFormat `PEM`,
   empty password).
4. **FinishRequest** every 200 ms while it answers `BadNothingToDo` (pending),
   at most `--finish-timeout-ms`.
5. **GetCertificateGroups**(applicationId).
6. **GetTrustList**(applicationId, DefaultApplicationGroup), then the
   TrustList object is read: `Open` (mode Read, i.e. all lists), `Read` in
   4096-byte chunks, `Close`.
7. **GetCertificateStatus**(applicationId, DefaultApplicationGroup, certificate type).
8. `--revoke`: **RevokeCertificate**(applicationId, issued certificate), then
   **CheckRevocationStatus**(issued certificate).
9. `--unregister`: **UnregisterApplication**(applicationId).

`results` has one element; a key is present only when its step ran:

```json
{
  "findApplications": ["ns=3;g=…"],
  "registered": true,
  "registerStatus": { "name": "Good", "code": 0, "severity": "Good" },
  "applicationId": "ns=3;g=…",
  "requestKind": "csr",
  "startRequestStatus": { … },
  "requestId": "ns=3;g=…",
  "finishRequestStatus": { … },
  "certificate": "<base64 DER>",
  "privateKeyFormat": "PEM",
  "privateKey": "<base64 of the returned key bytes>",
  "issuerCertificates": ["<base64 DER>", …],
  "certificateGroups": ["ns=2;i=615"],
  "trustListId": "ns=2;i=616",
  "trustList": { "specifiedLists": 15, "trustedCertificates": […], "trustedCrls": […],
                 "issuerCertificates": […], "issuerCrls": […] },
  "getCertificateStatusStatus": { … },
  "updateRequired": false,
  "revokeStatus": { … },
  "checkRevocationStatus": { … },
  "certificateStatus": { "name": "BadCertificateRevoked", … },
  "unregisterStatus": { … }
}
```

| Key | Meaning |
|-----|---------|
| `findApplications` | the ApplicationIds of the records FindApplications returned (empty array if none) |
| `registered` | true if step 2 registered the record, false if an existing record was used |
| `registerStatus` | status of RegisterApplication (only when it ran) |
| `applicationId` | the ApplicationId the later steps use |
| `requestKind` | `csr` or `new-key-pair` |
| `startRequestStatus`, `requestId` | status and RequestId of StartSigningRequest / StartNewKeyPairRequest |
| `finishRequestStatus` | status of the FinishRequest that ended the polling |
| `certificate` | the issued certificate (base64 DER) |
| `privateKeyFormat`, `privateKey` | new-key-pair only: `"PEM"` and the base64 of the returned private key bytes (the PEM text) |
| `issuerCertificates` | the issuer chain FinishRequest returned (the group's CA) |
| `certificateGroups` | GetCertificateGroups result |
| `trustListId`, `trustList` | GetTrustList result and the decoded TrustListDataType (base64 DER certificates and CRLs) |
| `getCertificateStatusStatus`, `updateRequired` | GetCertificateStatus status and its output |
| `revokeStatus` | status of RevokeCertificate |
| `checkRevocationStatus` | the method result status of CheckRevocationStatus |
| `certificateStatus` | the CertificateStatus output of CheckRevocationStatus |
| `unregisterStatus` | status of UnregisterApplication |

NodeIds are in the canonical form of §6 with the namespace index the server
reports. Status objects are as in §3. When a step without a status key of its
own fails (FindApplications, GetCertificateGroups, GetTrustList, the TrustList
read) the result carries `findApplicationsStatus`,
`getCertificateGroupsStatus`, `getTrustListStatus` or `readTrustListStatus`
with the Bad status instead. `success` is true when every step that ran was
Good; otherwise `success` is false, `serviceResult` is the failing status,
`error.category` is `service` and the exit code is 4. Connect failures
(including `BadUserAccessDenied` at ActivateSession for a wrong password) are
exit 3, bad input exit 2 (§5).

### 16.3 UA-.NETStandard 2.0.1 behaviour

- The GDS server and client of 2.0.1 implement every Part 12 pull method the
  command uses, including CheckRevocationStatus and GetCertificates
  (`GetCertificates` is not called by `gds-pull`). EccNistP256 issuing works
  for CSRs and new key pairs (`--certificate-type NistP256`).
- Every StartSigningRequest / StartNewKeyPairRequest creates a new request:
  two runs on the same record report different `requestId`s (1.5.378 reused
  the application's RequestId).
- StartSigningRequest, StartNewKeyPairRequest and FinishRequest need a
  SignAndEncrypt channel; on a Sign channel they are
  `BadSecurityModeInsufficient` (1.5.378 accepted Sign).
- CheckRevocationStatus validates a certificate the GDS issued offline
  against the GDS CA and its CRL: for a certificate the GDS issued and
  revoked, `certificateStatus` is `BadCertificateRevoked` (RSA and
  EccNistP256, CSR and new key pair; the method itself is Good). A
  certificate of another CA is checked online (platform trust, CRL
  distribution point / OCSP). It needs a Sign or SignAndEncrypt channel.
  1.5.378 checked online only and reported
  `BadCertificateRevocationUnknown`.
- UnregisterApplication also revokes the certificates the GDS issued to the
  application (as in 1.5.378).
- The test PKI CA is not in the GDS trust list: `trustList` holds the GDS's
  own CAs (RSA and ECC) and their CRLs (`trustedCertificates`,
  `trustedCrls`), the issuer lists are empty.
- QueryServers / QueryApplications and FindApplications have no access check,
  so Anonymous sessions may call them; an anonymous `gds-pull` gets an empty
  `findApplications` and then `registerStatus` `BadUserAccessDenied`
  (1.5.378 already refused FindApplications with `BadUserAccessDenied`).
- Both CRLs are well formed: the TBSCertList and the outer
  signatureAlgorithm are both ecdsa-with-SHA256 (ECC CA) or both
  sha256WithRSAEncryption (RSA CA), and strict parsers (Go's crypto/x509)
  accept them. 1.5.378 named sha256WithRSAEncryption inside the ECDSA-signed
  CRL of the ECC CA, which RFC 5280 §5.1.1.2 forbids.
- StartNewKeyPairRequest with privateKeyFormat `PFX` returns a PKCS #12
  with the key and the certificate, protected with the password (not
  exercised by `gds-pull`, which asks for PEM).
- **Certificate chains.** With a CA-signed application certificate whose
  issuer is in the trusted or issuer store, the 2.0.1 server sends its
  certificate as a chain (leaf, then issuers) in three places:
  - the ServerCertificate of GetEndpoints and of the CreateSession response,
    when `SecurityConfiguration.SendCertificateChain` is true — the
    default of the 2.0.1 configuration builder
    (`Opc.Ua.Configuration/ApplicationConfigurationBuilder.cs:1432`;
    `Opc.Ua.Server/Server/StandardServer.cs:895`,
    `Opc.Ua.Core/Stack/Server/ServerBase.cs:868`);
  - the SenderCertificate of the OpenSecureChannel response, **always**: the
    channel takes the entry's issuer chain without looking at
    SendCertificateChain (`Opc.Ua.Core/Stack/Tcp/UaSCBinaryChannel.cs:188-217`,
    `TcpServerChannel.cs:1332`).

  Part 6 §6.2.3 allows a chain in these ByteStrings, and the stack verifies a
  client signature over either the leaf or the whole blob
  (`Opc.Ua.Server/Session/Session.cs:1039`, `:1532`). The `dotnet` adapter's
  server (same stack, same `dotnet-server` identity) behaves the same way and
  takes the same `--no-certificate-chain` (§11).
  Clients on Basic256Sha256 SignAndEncrypt against the adapter 0.16.0 server
  (`gds-pull` of the adapter images; go-opcua: a session and a Read):

  | Client | Default (chain) | `--no-certificate-chain` | Why |
  |---|---|---|---|
  | UA-.NETStandard (dotnet, dotnet-gds), Eclipse Milo 1.1.8, go-opcua | connects | connects | parse the leaf and keep the rest as intermediates |
  | asyncua (opcua-asyncio 2.1.0) | connects since adapter 0.16.0 | connects | the stack takes chains (`asyncua/client/client.py:56` `_first_cert_from_chain`, used at `:292` and `:790`; `crypto/uacrypto.py:60` `x509_from_der`), but adapter 0.15.0 passed the endpoint's ServerCertificate to `Client.set_security(server_certificate=…)`, which loads it as one certificate (`crypto/uacrypto.py:57`, cryptography `ParseError { kind: ExtraData }`). Adapter 0.16.0 passes the leaf. |
  | open62541 v1.5.9 | `BadCertificateInvalid` after CreateSession | connects | the channel keeps the leaf of the endpoint's certificate (`src/client/ua_client_connect.c:1899-1902`, `getLeafCertificate`), then CreateSession compares the response's ServerCertificate with it byte for byte (`ua_client_connect.c:1694`): chain ≠ leaf. A stack limitation; no client option skips the comparison. |
  | async-opcua 0.19.0 | `BadCertificateInvalid` (X509Error) | `BadCertificateInvalid` (X509Error) | `X509::from_der` parses exactly one certificate and rejects trailing data (`async-opcua-crypto/src/x509.rs:423-427`); it parses the endpoint's ServerCertificate (`async-opcua-client/src/transport/channel.rs:342`), the OpenSecureChannel SenderCertificate (`async-opcua-core/src/comms/secure_channel.rs:794`, 1848 bytes also with `--no-certificate-chain`) and the CreateSession ServerCertificate, which must also equal the endpoint's byte for byte (`async-opcua-client/src/session/services/session.rs:208-213`). A stack limitation with no hook; it fails against every UA-.NETStandard 2.0.1 server whose certificate has an issuer in its stores (adapters/async-opcua/README.md, deviation 10). |

  The default stays the chain. `scripts/smoke.sh dotnet-gds` runs `gds-pull`
  against both kinds of server; `scripts/smoke.sh cross-dotnet` reads with the
  open62541 client from both kinds of `dotnet` server (Good with
  `--no-certificate-chain`, `BadCertificateInvalid` with the chain).

---

## 17. Historical events (OPC UA Part 11)

Adapter 0.17.0: the client operations `history-read-events` and
`history-update-events` (§1 flags, §4 results) on all six adapters, and the
server fixture `s=History.Events` on the servers that declare
`history-events` (§13).

### 17.1 Server fixture `s=History.Events`

Built in code (not in `fixture.json`), like the alarm fixture; servers
without `history-events` have no such node. fixtures/baseline/README.md
"History (events)" has the table.

- Object `nsu=urn:otfabric:opcua-interop:model;s=History.Events`
  (BaseObjectType), Organizes from `s=History`. EventNotifier `0x0D`
  (SubscribeToEvents | HistoryRead | HistoryWrite) where the server also
  declares `history-events-update`, else `0x05`.
- Five seeded events, no live emission: EventId the ASCII bytes
  `hist-evt-0` … `hist-evt-4`, Time `2026-07-24T10:00:00Z` + 5 s × n,
  ReceiveTime = Time, Severity `100` … `500`, Message text
  `history-event-n` (the locale is the server's; `en` on UA-.NETStandard),
  SourceNode the object, SourceName `History.Events`; EventType
  BaseEventType (`i=2041`), except `hist-evt-3`: SystemEventType (`i=2130`).
- With `history-events-update`: the method `s=History.ResetEvents`
  (HasComponent of `s=History.Events`, no arguments) restores the seed —
  call it before a read that follows updates; the archive is shared by all
  sessions.

Reference results (`scripts/smoke.sh dotnet`, `cross-dotnet`; any client
against a `history-events` server after `ResetEvents`). The dotnet and
node-opcua clients get the same results from a go-opcua server (`Historian`
with `EnableEvents`, `EnableEventHistory(…, Writable: true)`, the seed
recorded with `RecordEvent`), except where noted:

| Request | Events (EventId) |
|---|---|
| `--start 2026-07-24T10:00:00Z --end 2026-07-24T10:01:00Z` | `hist-evt-0` … `hist-evt-4`, oldest first |
| `--start 2026-07-24T10:01:00Z --end 2026-07-24T09:59:00Z` (end before start: newest first) | `hist-evt-4` … `hist-evt-0` |
| forward, `--num-values 2 --scenario continue` | pages of 2, 2, 1; `reuseAfterReleaseStatusCode` `BadContinuationPointInvalid`; `releaseStatusCode` (the last continuation point was already consumed) `BadContinuationPointInvalid` (Part 4 §5.10.3; go-opcua since v1.26.0, which answered `Good` before; asyncua answers `Good`, §17.4) |
| forward, `--of-type i=2130` | `hist-evt-3` |
| forward, `--min-severity 300` | `hist-evt-2`, `hist-evt-3`, `hist-evt-4` |
| forward, `--of-type i=2041 --min-severity 300` | `hist-evt-2`, `hist-evt-3`, `hist-evt-4` (OfType matches subtypes) |
| `--start 2027-01-01T00:00:00Z --end 2027-01-02T00:00:00Z` | none, node status `GoodNoData`, exit 0 |

| Update (SelectClauses EventId, EventType, Time, Severity, Message) | operationResults |
|---|---|
| `insert` of a new EventId and of `hist-evt-0` | `GoodEntryInserted`, `BadEntryExists` |
| `replace` of `hist-evt-0` and of an unknown EventId | `GoodEntryReplaced`, `BadNoEntryExists` |
| `update` of an unknown EventId and of `hist-evt-0` | `GoodEntryInserted`, `GoodEntryReplaced` |
| `delete` of `hist-evt-1` and of an unknown EventId | `Good`, `BadNoEntryExists` (go-opcua: `Good`, `BadNoData`, the node status Part 11 §6.9.7.2 gives when no event matches) |

### 17.2 UA-.NETStandard 2.0.1 (dotnet)

The fixture is the stack's historian dispatcher (`AsyncCustomNodeManager`
→ `HistorianDispatcher`) on an `InMemoryHistorianProvider` with
`HistorianNodeCapabilities.EventReadWrite`; `ResetEvents` replaces the
provider with a freshly seeded one. Behaviour of the stack:

- The time range includes StartTime and excludes EndTime (both directions);
  StartTime = EndTime reads that instant only. Null StartTime and EndTime
  together are the node status `BadInvalidTimestampArgument` (exit 4). Only
  `--start`: oldest first from StartTime; only `--end`: newest first from
  EndTime, EndTime included (`--end 2026-07-24T10:00:10Z --num-values 10`
  gives `hist-evt-2`, `hist-evt-1`, `hist-evt-0`).
- The WhereClause is evaluated after a page was cut at `NumValuesPerNode`: a
  filtered page can hold fewer events than `--num-values` and still return a
  continuation point. An `And` element after its operands is
  `BadEventFilterInvalid` (§1 `history-read-events` flags).
- Continuation points belong to the session: one from another `client` run
  is `BadContinuationPointInvalid`, also for `--release-continuation-point`.
  Releasing a continuation point that was not consumed is `Good`.
- Insert and update need EventType and Time in the SelectClauses, replace
  needs EventId: otherwise the node status and every operation result are
  `BadArgumentsMissing`. An insert without an EventId gets 16 random bytes. An inserted event keeps only the
  fields it was given (a later read returns null for the others); replace and
  update merge the given fields into the stored event.
- Delete reports `Good`, not a `GoodEntry*` code, for a deleted event.
- When every operation of a HistoryUpdate fails, the node's StatusCode is
  that Bad operation status (e.g. `BadEntryExists`), so the command exits 4
  with the `operationResults` printed; with at least one Good operation the
  node status is Good.
- The fixture does not report the updates as live events, and
  HistoricalEventConfiguration / the server's HistoryServerCapabilities are
  not populated.

### 17.3 node-opcua 2.187.12 (server)

node-opcua historizes variables only. A HistoryRead with ReadEventDetails
makes its address-space engine throw, and the server answers the whole
request with the service fault `BadHistoryOperationInvalid`
(`node-opcua-server/dist/opcua_server.js`); HistoryUpdate is not served
(`BadServiceUnsupported`). The node-opcua server has no `s=History.Events`
and declares neither `history-events` nor `history-events-update`; its
client operations work against the dotnet fixture.

### 17.4 asyncua 2.1.0 (server)

The fixture is created in code with EventNotifier `0x05` (no HistoryWrite) and
the seed written straight into the history storage. The adapter's storage
(`fixture.History`, a subclass of asyncua's `HistoryDict`) adds what the stack
leaves out: it evaluates the WhereClause with asyncua's own evaluator and pages
at `NumValuesPerNode` with a continuation point. The adapter declares
`history-events` only. Behaviour that remains:

- OfType compares the event type exactly: `--of-type i=2041` does not match
  `hist-evt-3` (a SystemEventType), so `--of-type i=2041 --min-severity 300`
  gives `hist-evt-2` and `hist-evt-4`.
- Continuation points are stateless: release and reuse both answer `Good`.
- Both range ends are inclusive, and a range with no events answers `Good`,
  not `GoodNoData`.
- The HistoryRead bit of the EventNotifier is not checked.
- HistoryUpdate is refused with `BadUserAccessDenied` (the request is denied
  before dispatch; asyncua has no handler for it), not `BadServiceUnsupported`.
  No `History.ResetEvents`.
- Events raised through asyncua's event generator get random EventIds; the
  fixture writes the seed directly so the EventIds are the contract's.

### 17.5 Client notes

- open62541 1.5.9 uses the raw HistoryRead / HistoryUpdate services:
  `UA_Client_HistoryRead_events` stops on `GoodNoData`. open62541 has no event
  store, so its server has no fixture.
- Milo 1.1.8 prints status names with an underscore (`Good_EntryInserted`), as
  for every other operation; compare the numeric `code`.
- async-opcua 0.19 and Milo have no event-history server; async-opcua uses the
  generic HistoryRead / HistoryUpdate of its client.
