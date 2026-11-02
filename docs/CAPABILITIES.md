# Capabilities

What each adapter can do. `print-capabilities` is the source: a consumer reads the
image, not this page. A feature is declared only when the self-tests exercise it
for that adapter, or the image's own unit tests do; what a stack lacks is declared
absent and refused with exit code 2, never faked.

```sh
docker run --rm ghcr.io/otfabric/opcua-interop-<adapter>:<tag> print-capabilities
```

Section numbers are those of [CONTAINER_CONTRACT.md](CONTAINER_CONTRACT.md).

## Reference stacks

| Adapter | Language | Stack | Why included |
|---|---|---|---|
| open62541 | C | open62541 v1.5.9 (OpenSSL crypto backend, mDNS via mdnsd, PubSub with MQTT and SKS) | Native/embedded diversity, OPC UA Binary, certified example-server history |
| Eclipse Milo | Java | Eclipse Milo v1.1.8 (+ `milo-encoding-json`, `milo-encoding-xml`) | JVM/enterprise diversity, independent serialization and security code paths |
| async-opcua | Rust | async-opcua 0.19.0 (crates.io, RustCrypto) | Memory-safe Rust stack, independent encoder/decoder and crypto (no OpenSSL); see [`adapters/async-opcua/README.md`](../adapters/async-opcua/README.md) |
| UA-.NETStandard (`dotnet`) | C# | OPC Foundation UA-.NETStandard 2.0.1 (NuGet `OPCFoundation.NetStandard.Opc.Ua.*`) on .NET 10 | The OPC Foundation reference implementation, the stack most commercial servers and clients build on |
| node-opcua | TypeScript | node-opcua 2.187.12 (npm, Node.js 24 / OpenSSL) | JavaScript ecosystem stack, independent encoder/decoder and session/subscription engine; see [`adapters/node-opcua/README.md`](../adapters/node-opcua/README.md) |
| opcua-asyncio (`asyncua`) | Python | opcua-asyncio 2.1.0 (PyPI `asyncua`, `cryptography`) on CPython 3.14 | The most used Python stack, independent encoder/decoder and security code; see [`adapters/asyncua/README.md`](../adapters/asyncua/README.md) |
| UA-.NETStandard GDS (`dotnet-gds`) | C# | OPC Foundation UA-.NETStandard 2.0.1 with `Opc.Ua.Gds.Server` / `Opc.Ua.Gds.Client` on .NET 10 | The reference Global Discovery Server and GDS client (Part 12 pull model, §16); a separate image (the GDS packages had no 2.0.x release until v0.14.0) |

Feature support differs per stack and is declared by `print-capabilities`:

| Feature | open62541 | Eclipse Milo | async-opcua | UA-.NETStandard | node-opcua | opcua-asyncio |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| DataChangeFilter (absolute / percent deadband, trigger) — client and server | ✓ | ✓ | ✓ | ✓ | ✓ | client ✓; server — (absolute deadband against the previous sample, percent deadband accepted but not applied) |
| Reverse connect (server `--reverse-connect`, client `--reverse-listen`) | ✓ | — (no ReverseHello in Milo 1.1.8) | ✓ | — (not wired in the adapter) | ✓ | — (no ReverseHello in the adapter) |
| ECC security policies | ✓ | — (no ECC `SecurityPolicy` in Milo 1.1.8) | — (none in async-opcua 0.19) | — (2.0.1 refuses the test PKI's ECC certificates issued by the RSA CA) | — (none in node-opcua 2.187) | — (RSA policies only) |
| LDS server (`--lds`), mDNS | ✓ | — (Milo answers `Bad_ServiceUnsupported`) | — (stubs answer `BadServiceUnsupported`) | — (not an LDS) | — (the stack's LDS is a separate server, not run) | — (not an LDS) |
| `--register-with`, `register-server`, `find-servers-on-network` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| AddNodes / DeleteNodes served (`node-management`) | ✓ | — | ✓ | ✓ | — (`BadServiceUnsupported`) | — (`BadUserAccessDenied`) |
| `codec` JSON (OPC UA 1.05) | ✓ compact | ✓ compact + verbose | — (the stack's JSON is the 1.04 `Type` / `Body` form) | ✓ compact + verbose | — (not wired into the adapter) | — (not wired into the adapter) |
| `codec` XML | ✓ (no DataValue / DiagnosticInfo / matrices) | ✓ | — (the stack's Variant XML is the NodeSet2 value form, without the Part 6 `<Value>` element) | ✓ (decodes namespace-qualified documents only) | — (no Part 6 XML Variant encoding) | — (not wired into the adapter) |
| PubSub (Part 14): UDP / MQTT, UADP / JSON, security, SKS, information model (v0.8.0) | ✓ | — (no PubSub in Milo 1.1.8) | — (no PubSub in async-opcua 0.19) | ✓ (v0.10.0) UDP / MQTT, UADP / JSON, static keys, chunking, discovery; no SKS, no information model | — (no open-source PubSub) | — (not wired into the adapter) |
| `codec pubsub-*` (UADP / JSON NetworkMessages) | ✓ | — | — | ✓ (v0.10.0) | — | — |

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
| `alarms-branches` | server | — | — | — | — | ✓ | — | the alarm fixture's `s=Alarms.Clear`: condition branches (docs/FIXTURES.md "Alarms", adapter 0.15.0) |
| `alarms-audible` | server | — | — | — | — | ✓ | — | InteropAlarm has AudibleEnabled / AudibleSound (AudioVariableType with ListId; adapter 0.15.0) |
| `alarms` | server | ✓ (experimental) | — | — | ✓ | ✓ | — | the Alarms & Conditions fixture (`s=Alarms.*`, docs/FIXTURES.md "Alarms"); Acknowledge / Confirm / AddComment / Enable / Disable / ConditionRefresh by the stack's own handlers (ConditionRefresh2 too, not exercised by `alarms`) |
| `alarms-105` | server | — | — | — | ✓ | — | — | adapter 0.15.0: the Part 9 1.05 extension of the Alarms fixture (`s=Alarms.ExtAlarm`, `s=Alarms.Dialog`, `s=Alarms.Group`, docs/FIXTURES.md "Alarms (1.05)"): Suppress / Silence / OutOfService / Latched / Shelving state methods, a dialog, condition branches, an alarm group and AudibleSound |
| `auditing` | server | — | — | — | ✓ | — | — | adapter 0.15.0: `--auditing` (§11) turns the server's auditing on: audit events (AuditCondition*EventType of the alarm methods among them) reach event monitored items of SignAndEncrypt sessions |
| `pubsub-multicast-loopback` | server | — | — | — | ✓ | — | — | adapter 0.15.0: the PubSub runtime (§14) loops its own UDP multicast back to the host (IP_MULTICAST_LOOP), so a subscriber on the same host (e.g. `--network host`) receives the publisher's multicast |
| `history-events` | server | — | — | — | ✓ | — | ✓ | adapter 0.17.0: the event history fixture `s=History.Events` (§17, docs/FIXTURES.md "History (events)"): HistoryRead with ReadEventDetails of the five seeded events, SelectClauses, WhereClause and continuation points |
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

## Commands by adapter

The container modes:

| Mode | Description |
|---|---|
| `server` | Start an OPC UA server from a fixture |
| `client` | Run composable client probe operations |
| `test` | Run the adapter's built-in unit tests |
| `validate-fixture` | Validate a fixture file against the schema |
| `print-capabilities` | Print adapter capabilities as JSON |

### Server command

```sh
# Anonymous, unsecured
server \
  --fixture      /fixtures/baseline/fixture.json \
  --bind-address 0.0.0.0 \
  --bind-port    4840 \
  --advertised-host localhost \
  --endpoint-path /opcua-interop \
  --ready-file   /run/opcua-interop/ready

# With security (certificate + PKI trust directory)
server \
  --fixture      /fixtures/baseline/fixture.json \
  --certificate  /certs/cert.crt \
  --private-key  /certs/cert.key \
  --pki-dir      /certs/pki \
  --bind-port    4840
```

The fixture's `securityProfiles` array controls which secure endpoints are advertised.
The fixture's `users` array controls which username/password credentials are accepted.

Optional server features (v0.7.0, PubSub v0.8.0; see [`docs/CONTAINER_CONTRACT.md`](CONTAINER_CONTRACT.md) §11 / §14
and `print-capabilities` → `serverFeatures`, `pubsub`):

```sh
# open62541: ECC endpoints (one certificate per curve under <dir>/ecc-<curve>/)
server ... --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
           --pki-dir /pki/open62541-server/pki --ecc-dir /pki/open62541-server

# open62541: reverse connect — the server dials the client and sends ReverseHello
server ... --reverse-connect opc.tcp://client-host:4855

# open62541: Local Discovery Server with mDNS (RegisterServer/2, FindServersOnNetwork)
server ... --lds
server ... --mdns-name my-server            # announce a plain server via mDNS

# all adapters: register with an LDS (RegisterServer2, fallback RegisterServer)
server ... --register-with opc.tcp://lds:4840/opcua-interop

# open62541 (v0.8.0), UA-.NETStandard (v0.10.0): OPC UA PubSub configuration, see "PubSub" below
server ... --pubsub-config /pubsub/udp-unicast-subscriber.json

# UA-.NETStandard (v0.11.0): opc.https and opc.wss listeners next to opc.tcp
# (needs --certificate / --private-key: the application certificate serves TLS)
server ... --certificate /certs/cert.crt --private-key /certs/cert.key --https-port 4843 --wss-port 4844
# UA-.NETStandard, node-opcua, open62541 (v0.12.0, serverFeatures "alarms"): no flag — the server
# carries the Alarms & Conditions fixture s=Alarms.InteropAlarm (docs/FIXTURES.md "Alarms")
# open62541, UA-.NETStandard, node-opcua (v0.13.0, serverFeatures "push-management"): with
# --certificate / --private-key / --pki-dir the ServerConfiguration push certificate management of
# Part 12 §7; fixture users with role "SecurityAdmin" may call it (docs/CONTAINER_CONTRACT.md §15)
# node-opcua (v0.15.0, serverFeatures "alarms-branches", "alarms-audible"): s=Alarms.Clear keeps the
# unacknowledged state in a condition branch; InteropAlarm has AudibleEnabled / AudibleSound
```

### Client commands

Nineteen client operations, plus `pubsub-discover` on the dotnet adapter, `push` on node-opcua, asyncua, async-opcua, Milo, open62541 and dotnet, `query` on node-opcua and async-opcua, and `gds-pull` on dotnet-gds, asyncua, async-opcua, Milo, open62541 and dotnet (see `print-capabilities` → `clientOperations` and
[`docs/CONTAINER_CONTRACT.md`](CONTAINER_CONTRACT.md)):

```sh
client endpoints --endpoint opc.tcp://host:4840/opcua-interop
client find-servers --endpoint ...
client read      --endpoint ... --node 'nsu=...;s=Scalar.Int32' [--index-range '1:3']
client write     --endpoint ... --node '...' --type Int32 --value 100 [--index-range '0']
client browse    --endpoint ... --node 'i=85'
client translate --endpoint ... --starting-node 'i=85' --path 'Server' [--namespace 0]
client call      --endpoint ... --object '...' --method '...' --input 'Int32:10' --input 'Int32:20'
client subscribe --endpoint ... --node '...' --notifications 5 --timeout-ms 10000 \
                 [--queue-size 3] [--discard-oldest true] [--timestamps Both]
client subscription-lifecycle --endpoint ... --node '...' \
                 --scenario revise|publishing-mode|monitoring-mode|delete
client event-subscribe --endpoint ... --node '...' [--events 1] [--timeout-ms 10000] \
                 [--of-type i=2041] [--min-severity 100]
client alarms    --endpoint ... [--node i=2253] [--condition-name InteropAlarm] \
                 [--acknowledge] [--confirm] [--add-comment] [--comment interop-comment]
client push      --endpoint ... --security-mode SignAndEncrypt --username ... --password ... \
                 [--add-certificate cert.der] [--remove-certificate <thumbprint>] [--issuer] \
                 [--csr] [--apply]                        # node-opcua (v0.13.0), §15
                 [--group Application|Https|UserToken] [--get-certificates] \
                 [--create-self-signed --subject CN=x --dns host] [--delete-certificate <typeId>] \
                 [--update-certificate cert.der [--update-private-key key.pfx] [--issuer-certificate ca.der]] \
                 [--reset-to-defaults] [--cancel] [--transaction-diagnostics]   # node-opcua, asyncua, async-opcua, Milo, open62541, dotnet (v0.15.0)
client query     --endpoint ... --type-definition '<typeId>' [--include-subtypes] \
                 [--data-to-return '.Serial'] [--data-to-return '#BrowseName'] [--max-data-sets 2] \
                 [--release-continuation-point]           # node-opcua, async-opcua (v0.15.0), QueryFirst / QueryNext
client history-read --endpoint ... --node '...' --start <rfc3339> --end <rfc3339> \
                 [--num-values 0] [--timestamps Both] [--scenario continue]
client republish --endpoint ... --subscription-id <n> --sequence-number <n>
client transfer-subscriptions --endpoint ... --subscription-id <n> \
                 [--send-initial-values false]
client register-nodes --endpoint ... --node '...' [--node '...']
client node-management --endpoint ... --parent '...' --node '...' \
                 [--browse-name Name] [--value 42]
client find-servers-on-network --endpoint <lds-url> [--starting-record-id 0] \
                 [--max-records 0] [--capability LDS]
client register-server --endpoint <lds-url> --server-uri urn:x --discovery-url opc.tcp://x:4840 \
                 [--server-name ...] [--online false] [--service auto|RegisterServer2|RegisterServer]
client codec encode --format json|xml --type 'Int32[]' --value 1,2,3 [--dimensions 3,1]
client codec encode --format json|xml --endpoint ... --node '...'
client codec decode --format json|xml --type Variant|DataValue|<BuiltInType>   # document on stdin
client codec --endpoint ... --node '...' [--node '...']                        # JSON + XML per node
client codec pubsub-uadp-encode|pubsub-json-encode [--document <description>] # PubSub NetworkMessage (open62541, dotnet)
client codec pubsub-uadp-decode|pubsub-json-decode [--document <message>] [--metadata <DataSetMetaDataType>]
client pubsub-discover --url opc.udp://<host>:<port> [--type DataSetMetaData|DataSetWriterConfiguration] # UADP discovery probe (dotnet)
client gds-pull  --endpoint ... --security-mode SignAndEncrypt --username ... --password ... \
                 [--app-uri urn:x] [--app-type Server|Client|ClientAndServer] [--discovery-url ...] \
                 [--request csr|new-key-pair] [--certificate-type RsaSha256|NistP256] \
                 [--revoke] [--unregister] [--finish-timeout-ms 30000]   # dotnet-gds (v0.14.0); asyncua, async-opcua, Milo, open62541, dotnet (v0.15.0), §16
```

The `dotnet-gds` image (v0.14.0) is a separate adapter: its `server` is a Global
Discovery Server (Part 12 §6 Directory and §7.9 pull certificate management,
the stack's GlobalDiscoverySampleServer with auto-approved requests) and its
client has `endpoints` and `gds-pull` only. It runs on UA-.NETStandard
2.0.1 with `Opc.Ua.Gds.Server` / `Opc.Ua.Gds.Client` (v0.14.0: 1.5.378.182); see
[`docs/CONTAINER_CONTRACT.md`](CONTAINER_CONTRACT.md) §16.

`subscribe` takes a DataChangeFilter (`--deadband-absolute <x>` | `--deadband-percent <x>`,
`--trigger Status|StatusValue|StatusValueTimestamp`); the baseline fixture's
`Analog.Level` / `Analog.Setpoint` AnalogItems (EURange 0..100) are there for it.

The open62541 client can wait for a reverse connection instead of dialling
(`--reverse-listen <port>`) and speaks the ECC security policies
(`--security-policy ECC_nistP256 --certificate <identity>/ecc-nistp256/cert.crt ...`).

The dotnet client speaks the RSA policies only (no `--reverse-listen`, no ECC; see
"Reference stacks" below). Since v0.11.0 it also dials `opc.wss://` (wss-uasc-uabinary)
and `opc.https://` (https-uabinary) endpoints, validating the server's TLS certificate
against `--trust-list` (`print-capabilities` → `clientFeatures`: `transport-wss`,
`transport-https`).

The asyncua (opcua-asyncio) client speaks the RSA policies only and has no `codec`
(no `--reverse-listen`, no ECC; see [`adapters/asyncua/README.md`](../adapters/asyncua/README.md)). Since v0.15.0
it has `push` (all the flags above) and `gds-pull` (§16.2), built on plain Calls.

Every client command also accepts `--channel-lifetime-ms <n>` to request a short
SecureChannel lifetime and force SecurityToken renewals mid-command:

```sh
client subscribe --endpoint ... --node '...' --notifications 24 --timeout-ms 40000 \
                 --channel-lifetime-ms 6000
```

`subscribe` JSON includes `subscriptionId` and revised CreateSubscription fields
(`revisedPublishingInterval`, `revisedLifetimeCount`, `revisedMaxKeepAliveCount`)
plus optional `sourceTimestamp` / `serverTimestamp` on notifications.

All client operations write JSON to stdout and diagnostics to stderr.
