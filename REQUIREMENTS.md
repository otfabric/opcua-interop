# Requirements

What this repository must do and must not do. [PLAN.md](PLAN.md) says in
which order; [docs/CONTAINER_CONTRACT.md](docs/CONTAINER_CONTRACT.md) and
[docs/FIXTURES.md](docs/FIXTURES.md) are the specifications that follow from
it.

## Purpose

Independent, reproducible interoperability validation for OPC UA libraries:
established third-party implementations, packaged as containers that all behave
the same way, so that a library can be tested against real implementation
diversity without owning any of it. Consumer repositories use these containers to
make defensible interoperability claims about their own implementations.

It is not another OPC UA implementation and not a general protocol-testing
framework.

## R1 - Repository isolation

- R1.1 This repository does not import, build, link against or depend on any
  library under test, and contains no test logic or expectation specific to
  one. The one exception is `own/` with its workflow: images of OT Fabric's own stacks, published for others to test against (`own/go-opcua/README.md`). The rest of the repository does not know them, and they are not part of a release.
- R1.2 A consumer depends on published images, the documented contract and the
  test PKI script `certs/generate.sh`.
- R1.3 No third-party code from here is copied into a consumer, and the
  contract does not shape a consumer's public API.

| Responsibility | Here | Consumer |
|----------------|:----:|:--------:|
| Third-party implementations, adapters, Dockerfiles | yes | no |
| Fixtures, fixture schema and validation | yes | no |
| Container contract, capability declarations | yes | no |
| Image builds and publishing, licence compliance | yes | no |
| Self-tests of the reference stacks | yes | no |
| Scenarios and assertions about a library | no | yes |
| Compatibility claims and release qualification of a library | no | yes |

## R2 - Reference implementations

- R2.1 These are in scope, in this order of priority:

  | Priority | Implementation | Language | Independent engine |
  |----------|----------------|----------|:------------------:|
  | P0 | open62541 | C | yes |
  | P0 | Eclipse Milo | Java | yes |
  | P0 | OPC Foundation UA-.NETStandard | C# | yes |
  | P1 | async-opcua | Rust | yes |
  | P1 | node-opcua | TypeScript | yes |
  | P1 | opcua-asyncio | Python | yes |
  | P1 | UA-.NETStandard GDS | C# | no: the engine of UA-.NETStandard, a separate image for the Part 12 pull model |

- R2.2 Each is its own image. No image contains two implementations.
- R2.3 An adapter on another adapter's protocol engine says so and does not count
  as an additional independent implementation.
- R2.4 An adapter is published only when it builds from pinned sources and
  passes the smoke test and the cross-stack self-test for what it declares.

## R3 - Container contract

- R3.1 Every image has the same entry points: `server`, `client`, `test`,
  `validate-fixture`, `print-capabilities`, with the same flags and semantics.
- R3.2 Servers signal readiness when they actually accept OPC UA connections, by
  a file. Nothing relies on delays.
- R3.3 Machine-readable output is JSON on stdout with stable field names;
  diagnostics go to stderr; exit codes have fixed meanings.
- R3.4 Every operation is bounded by a configurable timeout.
- R3.5 Servers stop cleanly on SIGTERM and exit non-zero when they cannot start.
- R3.6 Capabilities are machine-readable and declared only for behaviour that is
  exercised.

## R4 - Fixtures

- R4.1 Fixtures describe the address space and its observable behaviour,
  independent of any implementation.
- R4.2 Fixtures contain no assertions and no names from any library under test.
- R4.3 Dynamic behaviour is deterministic.
- R4.4 Fixtures are validated against a schema, in CI and by each adapter.

## R5 - Reproducibility

- R5.1 Every upstream is pinned to an exact version, every base image to a
  digest. `versions.yaml` records all of them and is checked against the build
  files.
- R5.2 Releases are immutable tags; images are published with their digests.
- R5.3 Images are published for linux/amd64 and linux/arm64.

## R6 - Self-tests

- R6.1 The reference stacks are tested against each other in every supported
  direction, with an expectation on each result document, not just on success.
- R6.2 These results are about the references and are never presented as
  results for a consumer.
- R6.3 Malformed messages, invalid sequence numbers and timer-boundary cases are
  out of scope: reference implementations are not misused as fault injectors.

## R7 - Licensing and safety

- R7.1 Licence notices of all bundled software are preserved in the images.
- R7.2 Test services are exposed on loopback or private networks by default.

## R8 - Scope discipline

- R8.1 Adapters are small and explicit. No generic interoperability framework.
- R8.2 Structure is added when an implementation requires it, not before.

---

The detailed requirements of each release follow. They are the history of how the
contract grew; the two stacks of the early goals are now the ones above.

## Original purpose

`opcua-interop` provides containerized OPC UA reference implementations and a shared fixture format for interoperability testing. Consumer repositories use these containers to make defensible interoperability claims about their own OPC UA implementations.

## Original goals

- Provide two containerized OPC UA reference implementations from independent implementation families
- Define a stack-neutral, versioned fixture format that describes deterministic OPC UA address spaces
- Expose deterministic reference-client operations for testing consumer server implementations
- Produce readiness signals suitable for automated test orchestration
- Support `linux/amd64` and `linux/arm64` container architectures
- Provide documented, stable Make targets and Docker commands that consumer repositories can invoke
- Enable cross-stack self-verification between the two reference implementations

## Original reference stacks

| Adapter | Language | Implementation family |
|---|---|---|
| open62541 | C | Native / embedded |
| Eclipse Milo | Java/JVM | Enterprise / JVM |

These two stacks provide the strongest initial implementation diversity. A third stack (e.g. NodeOPCUA) may be added later if driven by concrete consumer needs.

## Scope by release

### v0.1.0 (released) — Baseline unsecured interoperability

- UA-TCP transport (`opc.tcp://`)
- OPC UA Binary encoding
- SecureChannel None/None
- Anonymous session
- GetEndpoints, Browse, Read, Write, Call
- CreateSubscription, CreateMonitoredItems, Publish
- Baseline scalar types, methods, and dynamic value generators
- First go-opcua consumer integration (70+ tests, all four directions)

### v0.1.1 (released) — Security infrastructure

- Full test PKI: CA, open62541-server, open62541-client, milo-server, milo-client, consumer, go-server, untrusted identities
- Server security flags: `--certificate`, `--private-key`, `--pki-dir` (both adapters)
- Secure endpoint advertisement from fixture `securityProfiles`
- Trust list validation (both adapters)
- Username/password identity validator (both adapters)
- Username token policy on None/None endpoints (allows testing auth independently of message security)
- Fixture schema: `securityProfiles` and `users` fields
- go-opcua harness: secure client dial, username client dial, trust-rejection assertions

### v0.2.0 (released) — Security verification complete

Confirmed with green test runs in go-opcua (125 tests, 0 skips, 0 failures):

- Basic256Sha256/Sign — all four directions ✓
- Basic256Sha256/SignAndEncrypt — all four directions ✓
- Trust rejection — positive and negative certificate test per server stack (open62541 ✓, Milo ✓)
- Username/valid credentials — all four directions ✓ (open62541 ✓, Milo ✓, go-server ✓)
- Username/invalid credentials — all four directions ✓ (open62541 ✓, Milo ✓, go-server ✓)
- go-opcua server with OPC UA SecureChannel (adapter clients → Go server, both Sign and SignAndEncrypt) ✓
- open62541 client `UA_ExtensionObject_setValueCopy` argument-order bug fix ✓

### v0.2.1 (released) — Phase 9 fixture / adapter hardening

Phase 9 consumer scenarios (methods, DataValue metadata, access levels, arrays,
browse, subscription queue flags, Aes128/Aes256) verified in go-opcua. Historical
count at Phase 9 close: 212 tests, 0 skips (consumer suite has grown since).

### v0.3.0 (released) — go-opcua Phase 13 subscribe timestamps

- `subscribe --timestamps` (`Source` \| `Server` \| `Both` \| `Neither`)
- `subscribe` JSON `serverTimestamp` when present
- Read/write `--index-range` for NumericRange consumer tests

### v0.4.0 (released) — go-opcua Phase 14 subscription lifecycle

- `subscribe` revised CreateSubscription fields (`subscriptionId`,
  `revisedPublishingInterval`, `revisedLifetimeCount`, `revisedMaxKeepAliveCount`)
- New `subscription-lifecycle` command (`revise`, `publishing-mode`,
  `monitoring-mode`, `delete`)
- Capabilities `adapter.version` = `0.4.0`; seven `clientOperations`

### v0.5.0 (released) — WP1B baseline (go-opcua Phase 18)

- New `event-subscribe` command: `EventFilter` with BaseEvent SelectClauses (EventId,
  EventType, SourceName, Message, Severity, Time); collect *N* events or timeout (exit 7)
- New `history-read` command: `ReadRawModifiedDetails` (`isReadModified=false`); flags
  `--node`, `--start`, `--end`, `--num-values`, `--continuation-point`,
  `--release-continuation-point`, `--return-bounds`, `--timestamps`,
  `--scenario continue`
- New `republish` command: `--subscription-id`, `--sequence-number`
- New `transfer-subscriptions` command: repeatable `--subscription-id`,
  `--send-initial-values`
- Milo `ClientCommand.newRequestHeader` uses the active session `AuthenticationToken`
  (raw `sendRequest` does not inject it)
- `find-servers` (FindServers → ApplicationDescription JSON) and `translate`
  (TranslateBrowsePathsToNodeIDs with `--starting-node`, `--path`, optional `--namespace`)
- `event-subscribe --of-type` / `--min-severity`; `history-read --scenario continue`
- Reference-server BaseEvent emission and gate-compliant `History.Temperature` raw samples
- Capabilities `adapter.version` = `0.5.0`; thirteen `clientOperations`

### v0.6.0 — upstream refresh, renewal and node services

- Upstream pins: open62541 `v1.5.9` (was `v1.5.5`), Eclipse Milo `1.1.8` (was `1.1.5`)
- New `register-nodes` command: RegisterNodes → Read via alias → UnregisterNodes
- New `node-management` command: AddNodes (Int32 Variable) → Read → DeleteNodes → Read
- Global `--channel-lifetime-ms` client flag to force SecurityToken renewals mid-command
  (use ≥ 5000 ms; the open62541 client schedules renewal coarsely)
- Smoke covers `register-nodes` and a subscribe across SecureChannel renewals in every
  adapter↔adapter direction
- Capabilities `adapter.version` = `0.6.0`; fifteen `clientOperations`
- Releases are immutable: a change to the adapter surface gets a new tag

### v0.7.0 — filters, reverse connect, ECC, discovery, data encodings

Supports go-opcua v1.6.0. Features are provided where the stack implements them
and declared per adapter in `print-capabilities` (`clientFeatures`,
`serverFeatures`, `codec`, `securityProfiles`); an unsupported feature flag is
refused, never ignored.

- **DataChangeFilter** (both adapters): `subscribe --deadband-absolute`,
  `--deadband-percent`, `--trigger`; result reports `monitoredItemStatusCode`,
  `filter`, `filterResult`, revised sampling interval / queue size. Baseline
  fixture gains the AnalogItems `Analog.Level` (ramp) and `Analog.Setpoint`
  (writable) with `EURange` 0..100 (fixture node property `euRange`)
- **Reverse connect** (open62541): server `--reverse-connect <url>`, client
  `--reverse-listen <port>` (`--reverse-timeout-ms`, `--reverse-server-uri`)
- **ECC security policies** (open62541, OpenSSL backend): `ECC_nistP256`,
  `ECC_nistP384`, `ECC_brainpoolP256r1`, `ECC_brainpoolP384r1`, `ECC_curve25519`,
  `ECC_curve448`, `ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly`; server
  `--ecc-dir`; test PKI gains `ecc-<curve>/` certificates per identity
  (`certs/generate.sh --add-ecc`); fixture `securityProfiles` lists the ECC entries
- **Discovery**: open62541 server `--lds` (RegisterServer/2, FindServers,
  FindServersOnNetwork, mDNS), `--mdns-name`; both adapters `--register-with`;
  client `find-servers-on-network` and `register-server` (both adapters)
- **JSON / XML DataEncoding**: client `codec` (encode literals of all 25
  built-in types, arrays and matrices or a node's value; decode a document;
  Binary encoding as Base64 for bit-exact comparison) in both adapters
- `subscription-lifecycle` `publishing-mode` / `monitoring-mode` request
  SamplingInterval 0
- Value literals (`write`, `call`, `codec`) for all built-in types
- Smoke covers every new feature in each adapter↔adapter direction that both
  ends support
- Capabilities `adapter.version` = `0.7.0`; eighteen `clientOperations`
- Backward compatible: existing commands, flags, result shapes and the RSA PKI
  are unchanged

### v0.8.0 — PubSub (OPC UA Part 14)

Supports the go-opcua PubSub implementation. open62541 only (Eclipse Milo 1.1.8
has no PubSub; the Milo adapter declares `pubsub.supported: false` and refuses
the PubSub flags with exit 2).

- **Build**: open62541 v1.5.9 amalgamation with `UA_ENABLE_PUBSUB`,
  `UA_ENABLE_PUBSUB_INFORMATIONMODEL`, `UA_ENABLE_PUBSUB_SKS`,
  `UA_ENABLE_PUBSUB_FILE_CONFIG`, `UA_ENABLE_MQTT`; MQTT-C inlined into the
  amalgamation (`amalgam/inline_mqtt.py`); JSON DataSetReader matching
  backported from upstream (`amalgam/backport_json_reader.py`); PubSub-Aes128-CTR
  / PubSub-Aes256-CTR ported to OpenSSL (`src/pubsub_security.c`)
- **Server** `--pubsub-config <file>`: a `PubSubConfigurationDataType` (OPC UA
  1.05 JSON) plus security groups (static keys), `serveSks` (this server is the
  SKS) and `sksClient` (pull keys from an SKS); UDP unicast / multicast and MQTT
  connections, UADP and JSON writer groups, PublishedDataItems, DataSetReaders
  with TargetVariables, message receive timeouts, Sign / SignAndEncrypt
- **Information model**: `PublishSubscribe` browsable and configurable through
  its methods, also without `--pubsub-config`; AddSecurityGroup /
  RemoveSecurityGroup bound by the adapter
- **Codec**: `codec pubsub-uadp-encode|-decode`, `pubsub-json-encode|-decode`
  with a canonical JSON description of a NetworkMessage (`--metadata` for
  RawData)
- **Fixture**: baseline `PubSub` folder (writable Boolean, Int32, Int64,
  UInt64, Double, String, DateTime, ByteString, Int32[], Double[] variables)
- **MQTT broker**: `eclipse-mosquitto:2.0.22` pinned by digest,
  `fixtures/pubsub/mosquitto.conf`, compose service, `make run-mosquitto`
- **Networking contract** for UDP between the host and containers (documented
  addresses, verified on macOS / Docker Desktop); multicast container ↔
  container only
- **Capabilities**: `pubsub` section, `serverFeatures` `pubsub`,
  `clientFeatures` `codec-pubsub`; `adapter.version` = `0.8.0` in both adapters
- **Smoke**: `scripts/pubsub-smoke.sh` (codec, UDP unicast / multicast, MQTT
  UADP / JSON, SignAndEncrypt static keys, SKS pull, information model) in
  `make smoke` and CI
- Backward compatible: existing commands, flags and result shapes are
  unchanged; the fixture only gains nodes

### Later (planned) — remaining type surface

- Remaining structured types / enumerations / edge-case fixture expansion as needed

## Fixture requirements

A fixture must be:

- Stack-neutral (no open62541 or Milo internals)
- Declarative and human-readable
- JSON Schema validated
- Deterministic (same input → same address space)
- Explicit about namespace URIs and NodeIds
- Independently versioned from container images
- Implementable identically by both adapters

A fixture must not expose:

- open62541 callback names or C function names
- Milo namespace class names or Java class names
- SDK-specific access-control structures

## Server contract

Each container image must:

1. Accept `--fixture`, `--bind-address`, `--bind-port`, `--advertised-host`, `--advertised-port`, `--endpoint-path`, `--ready-file` flags (and, where the stack implements PubSub, `--pubsub-config`)
2. Accept `--certificate`, `--private-key`, `--pki-dir` for secure operation
3. Load and validate the fixture before reporting ready
4. Advertise secure endpoints according to the fixture `securityProfiles` field when a certificate is provided
5. Accept username/password credentials declared in the fixture `users` field
6. Write a readiness file only after the address space is available
7. Handle `SIGTERM` and shut down cleanly
8. Return nonzero on fixture or startup failure
9. Not mix log output into JSON client output

## Client contract

Each container image must expose client subcommands:

- `endpoints` — discover endpoints
- `find-servers` — FindServers → ApplicationDescription JSON
- `read` — read one or more nodes, JSON to stdout
- `write` — write a node value
- `browse` — browse a node
- `translate` — TranslateBrowsePathsToNodeIDs (`--starting-node`, `--path`, optional `--namespace`)
- `call` — call a method
- `subscribe` — collect a bounded number of notifications (includes revised subscription fields)
- `subscription-lifecycle` — deterministic lifecycle scenarios (revise / publishing-mode / monitoring-mode / delete)
- `event-subscribe` — EventFilter BaseEvent SelectClauses; optional `--of-type` / `--min-severity`; collect N events or timeout
- `history-read` — HistoryRead with `ReadRawModifiedDetails` (raw); continuation points; optional `--scenario continue`
- `republish` — RepublishRequest for a subscription sequence number
- `transfer-subscriptions` — TransferSubscriptions for one or more subscription ids
- `register-nodes`, `node-management`
- `find-servers-on-network`, `register-server` — discovery against an LDS
- `codec` — JSON / XML DataEncoding of built-in values; PubSub NetworkMessages (UADP / JSON) where the stack implements PubSub

Client output rules:

- JSON to stdout
- Diagnostics to stderr
- Stable field names across versions
- Stable exit-code meanings
- No log output mixed into JSON

## Capability declaration

Each image must implement `print-capabilities` and emit a JSON document describing
adapter version, stack version, supported services, security policies, and user token types.

Capability output describes what the adapter is **configured and able to support** —
not what has been verified against a specific consumer. Capability claims ahead of
verified interoperability tests must not be used to populate a compatibility matrix.

## Security requirements

### Test PKI

- Generated by `make certs` (requires openssl >= 1.1)
- Certificates are for isolated test environments only; private keys are intentionally checked in
- Each certificate must include the correct application URI in its Subject Alternative Name
- The PKI directory layout must match what both adapters expect (`trusted/certs/`, `trusted/crl/`, `issuers/certs/`, `rejected/`)
- PKCS#12 bundles (`.pfx`) are debug artifacts; adapters must load identity from PEM files

### Trust validation

- Both adapters must reject connections from clients whose certificates are not in the trust store
- Trust validation must be active for all non-None security policies
- At least one negative trust test (untrusted cert → rejected) must pass per server stack before a security policy is considered verified

### Username authentication

- Passwords over None/None channels travel unencrypted; this is acceptable for test-only environments
- Passwords over secure channels must use the channel's security policy for encryption
- Invalid credentials must be rejected at `ActivateSession`

## Cross-stack self-check

The repository must include a smoke process that runs each reference client against each reference server. This self-check proves both adapters realize the same baseline contract. It is not a product compatibility matrix and must not include assertions that belong to consumer repositories.

## Non-goals

`opcua-interop` is not:

- A replacement for the OPC Foundation CTT
- An OPC UA conformance certification suite
- A test framework for every OPC UA stack
- A database of every supported service and stack version combination
- A generic protocol laboratory
- The owner of `go-opcua` interoperability assertions
- A benchmark framework
- A production OPC UA server
- A production PKI

Consumer repositories own:

- Test scenarios and assertions
- Pass/fail decisions
- Compatibility claims and regression tracking
- Release qualification for their own implementations

## Out of scope (no concrete requirement yet)

- PubSub on Eclipse Milo (no implementation in Milo 1.1.8)
- AMQP transport, MQTT over TLS, Ethernet (`opc.eth://`) PubSub transport
- PubSub events (PublishedEvents), SubscribedDataSetMirror, discovery messages
- WebSockets transport
- HTTPS transport
- Alarms and conditions
- Complex companion specifications
- Global Discovery Server
- Certificate enrollment
- Redundancy
- Full OPC Foundation CTT coverage
- NodeOPCUA or other third stacks
