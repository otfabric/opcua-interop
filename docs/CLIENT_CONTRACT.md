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
| `republish` | RepublishRequest for a subscription sequence number |
| `transfer-subscriptions` | TransferSubscriptions for one or more subscription ids |
| `register-nodes` | RegisterNodes, Read through the registered aliases, UnregisterNodes |
| `node-management` | AddNodes (Int32 Variable), Read, DeleteNodes, Read-after-delete |
| `find-servers-on-network` | FindServersOnNetwork against a Local Discovery Server (mDNS records) |
| `register-server` | RegisterServer2 / RegisterServer of an arbitrary server description with an LDS |
| `codec` | Encode / decode built-in values in the OPC UA JSON and XML DataEncodings (no session needed for literals) |

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
| `--application-uri <uri>` | Client ApplicationUri sent in CreateSession (open62541 only) | URI SAN of `--certificate`, else stack default |
| `--reverse-listen <port>` | Do not dial: listen on `<port>` and wait for the server's ReverseHello (open62541 only, see below) | — |
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

One of: `"open62541"`, `"milo"`. Never abbreviated or versioned in this field.

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

| | open62541 v1.5.9 | Eclipse Milo 1.1.8 |
|---|---|---|
| JSON flavour | 1.05, one mode (`compact`); `useReversible` has no effect | 1.05, `compact` and `verbose` (`verbose` adds `Status.Symbol`) |
| JSON DataValue | Variant members flattened: `{"UaType":6,"Value":7,…}` | Variant nested: `{"Value":{"UaType":6,"Value":7},…}`; does not decode the flattened form |
| JSON NodeId / QualifiedName, ns ≠ 0 | namespace index (`"ns=2;s=x"`, `"2:Name"`) | namespace URI (`"nsu=…;s=x"`); `Bad_EncodingError` without `--namespace-uri` (a bare NodeId is emitted as the malformed `"s=ns=2;s=x"`) |
| JSON StatusCode | `{"Code":n,"Symbol":"…"}` | `{"Code":n}` (`Symbol` only in `verbose`) |
| JSON ExtensionObject | known types structurally (`{"UaTypeId":…,<fields>}`), cannot decode that in-place form back; unknown types as `UaEncoding`/`UaBody` | always `UaTypeId` / `UaEncoding` / `UaBody` |
| XML element names | no namespace (`<Variant><Value><Int32>`) | `uax:` prefix with `xmlns:uax` / `xmlns:xsi` on the root |
| XML encode | no DataValue, DiagnosticInfo, matrices, structures (`BadNotImplemented`) | all built-in types, matrices as `<Matrix>` |
| XML decode | no DataValue, DiagnosticInfo, XmlElement (`BadNotImplemented`) | all built-in types |
| XML Guid | `<Guid><String>…</String></Guid>` | `<Guid>…</Guid>` |
| Status names | `BadDecodingError` | `Bad_DecodingError` (Milo's symbol table; compare `code`) |

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

**Int64/UInt64 strings** — both adapters must emit strings for all 64-bit integer
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
| `adapter.version` | `0.7.0` |
| `clientOperations` | the `client` subcommands the image has |
| `clientFeatures` | optional client-side features (strings below) |
| `serverFeatures` | optional server-side features (strings below) |
| `securityProfiles` | `{policy, mode}` pairs usable on both the client and the server side |
| `codec` | `{formats, jsonVersion, jsonModes, xmlEncodeUnsupported, xmlDecodeUnsupported}` |

| Feature string | In | open62541 | Milo | Meaning |
|----------------|----|:---------:|:----:|---------|
| `channel-lifetime` | client | ✓ | ✓ | `--channel-lifetime-ms` |
| `deadband` | client | ✓ | ✓ | `subscribe --deadband-absolute/--deadband-percent/--trigger` |
| `reverse-listen` | client | ✓ | — | `--reverse-listen` |
| `ecc-security` | client, server | ✓ | — | ECC SecurityPolicies (`securityProfiles` lists them) |
| `ecc-user-token` | client, server | ✓ | — | UserName token over an ECC endpoint (EccEncryptedSecret) |
| `application-uri` | client | ✓ | — | `--application-uri`, ApplicationUri from the certificate |
| `register-server2` | client | ✓ | ✓ | `register-server` can call RegisterServer2 |
| `codec-json`, `codec-xml` | client | ✓ | ✓ | `codec` formats |
| `codec-json-verbose` | client | — | ✓ | `codec --json-mode verbose` |
| `deadband` | server | ✓ | ✓ | DataChangeFilter absolute deadband / trigger honoured |
| `percent-deadband` | server | ✓ | ✓ | percent deadband on AnalogItems with EURange (`Analog.*`) |
| `reverse-connect` | server | ✓ | — | `--reverse-connect` |
| `lds` | server | ✓ | — | `--lds` |
| `mdns` | server | ✓ | — | `--mdns-name`, FindServersOnNetwork |
| `register-with` | server | ✓ | ✓ | `--register-with` |
| `node-management` | server | ✓ | — | AddNodes / DeleteNodes served |

Eclipse Milo 1.1.8 has no ReverseHello in its transports
(`opc-ua-stack/stack-core/.../channel/messages/MessageType.java` knows only
Hello / Acknowledge / Error), no ECC `SecurityPolicy`
(`opc-ua-stack/stack-core/.../security/SecurityPolicy.java` ends at
`Aes256_Sha256_RsaPss`) and its server answers RegisterServer, RegisterServer2
and FindServersOnNetwork with `Bad_ServiceUnsupported`
(`opc-ua-sdk/sdk-server/.../servicesets/impl/DefaultDiscoveryServiceSet.java`).
