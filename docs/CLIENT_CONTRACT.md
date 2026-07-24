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
| `read` | Read one or more node values |
| `write` | Write a value to one node |
| `browse` | Browse forward hierarchical references from a node |
| `call` | Call a method node and collect output arguments |
| `subscribe` | Create a subscription and collect a bounded number of data-change notifications |
| `subscription-lifecycle` | Test subscription lifecycle scenarios (revise, publishing-mode, monitoring-mode, delete) |
| `event-subscribe` | Create an event monitored item with a BaseEvent SelectClauses filter; collect N events |
| `history-read` | HistoryRead with ReadRawModifiedDetails (raw only); optional continuation point |
| `republish` | RepublishRequest for a subscription sequence number |
| `transfer-subscriptions` | TransferSubscriptions for one or more subscription ids |

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

Security policy names: `None`, `Basic128Rsa15`, `Basic256`, `Basic256Sha256`,
`Aes128_Sha256_RsaOaep`, `Aes256_Sha256_RsaPss`.

Security mode values: `None`, `Sign`, `SignAndEncrypt`.

When `--certificate` and `--private-key` are supplied, the client uses them as its
application instance certificate. When `--username` is supplied without `--password`,
the password is treated as an empty string.

When `--security-policy` is not `None`, `--certificate` and `--private-key` are
required.

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

### `subscription-lifecycle` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | Writable Int32 node for scenarios that write values | required |
| `--scenario <name>` | Scenario to run: `revise`, `publishing-mode`, `monitoring-mode`, `delete` | required |
| `--timeout-ms <n>` | Absolute command timeout in ms | 15000 |

### `event-subscribe` flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node <nodeId>` | EventNotifier source node | required |
| `--events <n>` | Stop after receiving this many events | 1 |
| `--timeout-ms <n>` | Absolute command timeout in ms | 10000 |
| `--publishing-interval-ms <n>` | Requested publishing interval in ms | 500 |
| `--queue-size <n>` | Monitored item queue size | 10 |

The EventFilter SelectClauses always request BaseEventType fields:
`EventId`, `EventType`, `SourceName`, `Message`, `Severity`, `Time`.

**Limitation:** Adapters are client-only for event delivery. Against the Go
server, peer tests should call `EmitBaseEvent` after the monitored item is
created. Adapter servers do not currently emit fixture events automatically.

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

Raw HistoryRead only (`IsReadModified = false`). Continuation points are
Base64-encoded ByteStrings when present.

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

---

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
          { "name": "Message",    "dataType": "LocalizedText", "builtInType": 21, "value": { "locale": "", "text": "hi" } },
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
    "nodeId":            "ns=1;s=History.Int32",
    "statusCode":        { "name": "Good", "code": 0, "severity": "Good" },
    "continuationPoint": null,
    "values": [
      {
        "value":           42,
        "dataType":        "Int32",
        "builtInType":     6,
        "statusCode":      { "name": "Good", "code": 0, "severity": "Good" },
        "sourceTimestamp": "2024-01-01T00:00:00.000Z",
        "serverTimestamp": "2024-01-01T00:00:00.100Z"
      }
    ]
  }
]
```

`continuationPoint` is a Base64 string when the server returns one, otherwise
`null`. Timestamps omitted when absent.

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
