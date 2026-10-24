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
| `codec` | Encode / decode built-in values in the OPC UA JSON and XML DataEncodings (no session needed for literals); PubSub NetworkMessages (UADP / JSON, §14) |

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
| `--application-uri <uri>` | Client ApplicationUri sent in CreateSession (open62541, async-opcua, node-opcua) | URI SAN of `--certificate`, else stack default |
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

codec pubsub-uadp-encode | pubsub-uadp-decode | pubsub-json-encode | pubsub-json-decode
             [--document <text> | --input <file>]          (default: stdin)
             [--metadata <json> | --metadata-file <file>]   (PubSub NetworkMessages, §14.9)
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

One of: `"open62541"`, `"milo"`, `"async-opcua"`, `"node-opcua"`. Never abbreviated or versioned in this field.

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
| `--pubsub-config <file>` | open62541: OPC UA PubSub (Part 14) configuration — a JSON file with a `PubSubConfigurationDataType`, security groups and SKS settings (§14). Applied after startup; the ready file is only written once it is applied; an invalid configuration exits 1. Milo: refused (exit 2) | — |

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

| Feature string | In | open62541 | Milo | async-opcua | node-opcua | Meaning |
|----------------|----|:---------:|:----:|:-----------:|:----------:|---------|
| `channel-lifetime` | client | ✓ | ✓ | ✓ | ✓ | `--channel-lifetime-ms` |
| `deadband` | client | ✓ | ✓ | ✓ | ✓ | `subscribe --deadband-absolute/--deadband-percent/--trigger` |
| `reverse-listen` | client | ✓ | — | ✓ | ✓ | `--reverse-listen` |
| `ecc-security` | client, server | ✓ | — | — | — | ECC SecurityPolicies (`securityProfiles` lists them) |
| `ecc-user-token` | client, server | ✓ | — | — | — | UserName token over an ECC endpoint (EccEncryptedSecret) |
| `application-uri` | client | ✓ | — | ✓ | ✓ | `--application-uri`, ApplicationUri from the certificate |
| `register-server2` | client | ✓ | ✓ | ✓ | ✓ | `register-server` can call RegisterServer2 |
| `codec-json`, `codec-xml` | client | ✓ | ✓ | — | — | `codec` formats |
| `codec-json-verbose` | client | — | ✓ | — | — | `codec --json-mode verbose` |
| `codec-pubsub` | client | ✓ | — | — | — | `codec pubsub-{uadp,json}-{encode,decode}` (§14.9) |
| `deadband` | server | ✓ | ✓ | ✓ | ✓ | DataChangeFilter absolute deadband / trigger honoured |
| `percent-deadband` | server | ✓ | ✓ | ✓ | ✓ | percent deadband on AnalogItems with EURange (`Analog.*`) |
| `reverse-connect` | server | ✓ | — | ✓ | ✓ | `--reverse-connect` |
| `lds` | server | ✓ | — | — | — | `--lds` |
| `mdns` | server | ✓ | — | — | — | `--mdns-name`, FindServersOnNetwork |
| `register-with` | server | ✓ | ✓ | ✓ | ✓ | `--register-with` |
| `node-management` | server | ✓ | — | ✓ | — | AddNodes / DeleteNodes served |
| `pubsub` | server | ✓ | — | — | — | `--pubsub-config`, PubSub information model, SKS (§14) |

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
listed certificate). See `async-opcua/README.md` for the stack deviations the
go-opcua suite found.

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
`node-opcua/README.md` for the stack deviations the go-opcua suite found.

---

## 14. PubSub (OPC UA Part 14)

Added in adapter **0.8.0**, open62541 adapter only (Eclipse Milo 1.1.8 has no
PubSub implementation, §14.12). Declared in `print-capabilities` →
`pubsub` (§14.11), `serverFeatures` `pubsub`, `clientFeatures` `codec-pubsub`.

The open62541 image is built with `UA_ENABLE_PUBSUB`,
`UA_ENABLE_PUBSUB_INFORMATIONMODEL` (with the configuration methods),
`UA_ENABLE_PUBSUB_SKS`, `UA_ENABLE_PUBSUB_FILE_CONFIG`, `UA_ENABLE_MQTT` and
the JSON encoding, still as the single-file amalgamation. Three adapter-side
additions make that work and are the only places where the adapter goes beyond
stock v1.5.9 (all in `open62541/`):

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
container unicast and multicast by `scripts/pubsub-smoke.sh`.

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
