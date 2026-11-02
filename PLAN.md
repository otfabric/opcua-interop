# Implementation Plan

## Governing principle

`opcua-interop` owns reference implementations and deterministic test environments.
Consuming repositories own test scenarios, assertions, coverage, pass/fail decisions,
and compatibility claims.

---

## Phase 0 — Repository bootstrap ✓

Deliverables: README, REQUIREMENTS, PLAN, LICENSE, directory structure, Makefile,
compose.yaml, basic CI skeletons, fixture schema stub, Docker image naming.

---

## Phase 1 — Fixture schema and baseline model ✓

Deliverables:
- `fixtures/schema/opcua-fixture.schema.json` (v1.0)
- `fixtures/baseline/fixture.json`
- `fixtures/baseline/README.md`
- Schema validation in CI

---

## Phase 2 — open62541 adapter foundation ✓

Deliverables:
- `adapters/open62541/Dockerfile` (multi-stage, pinned release)
- `adapters/open62541/CMakeLists.txt`
- `open62541/src/` — fixture parser, server, client, readiness, signal handling, output
- `adapters/open62541/tests/` — fixture parser unit tests

Client commands at foundation: endpoints, read, write, browse, call, subscribe
(later extended — see Phase 14 / v0.4.0).

---

## Phase 3 — Eclipse Milo adapter foundation ✓

Deliverables:
- `adapters/milo/Dockerfile` (multi-stage, JDK 25 + Maven 3.9)
- `adapters/milo/pom.xml`
- `adapters/milo/src/main/java/` — fixture loader, namespace, server, client, shutdown, readiness
- `adapters/milo/src/test/java/` — fixture loading unit tests (8 tests, all pass)

Client commands at foundation: endpoints, read, write, browse, call, subscribe
(later extended — see Phase 14 / v0.4.0).

---

## Phase 4 — Contract freeze and adapter parity ✓

The two adapters produce identical output shapes for identical inputs.

### Workstream A — Command and output contract ✓

- `docs/CLIENT_CONTRACT.md`
- `schemas/client-result.schema.json`
- `schemas/capabilities.schema.json`

### Workstream B — Adapter hardening (both adapters) ✓

| Item | Description |
|------|-------------|
| Canonical envelope | Every command: `schemaVersion`, `adapter`, `operation`, `success`, `serviceResult` (structured), `results`, `error` |
| Exact status codes | `serviceResult` and per-item `statusCode` as `{name, code, severity}` |
| Complete NodeId parsing | All forms: `i=`, `ns=N;i=`, `ns=N;s=`, `ns=N;g=`, `ns=N;b=`, `nsu=URI;*` |
| Hard NodeId failure | Malformed/unknown NodeId → exit 2 before any network activity |
| Bind vs. advertised | `--bind-address`, `--bind-port`, `--advertised-host`, `--advertised-port` |
| Atomic readiness | tmp-file then rename; JSON content; fatal on failure |
| Operation timeouts | `--connect-timeout`, `--request-timeout`, `--disconnect-timeout` |
| Stable exit codes | 0/2/3/4/5/6/7 as defined in CONTRACT |
| Exact endpoint selection | No fallback to first endpoint; fail if None/None absent |
| Browse continuation | Handle BrowseNext continuation points |
| Value encoding | Int64/UInt64 as decimal strings; DateTime RFC 3339 UTC; Guid lowercase UUID; ByteString Base64 |

---

## Phase 5 — Complete reference-client surface ✓

New client subcommands in both adapters:
- `call` — invoke a method node
- `subscribe` — create a subscription, collect N notifications, emit JSON array, disconnect

Batch read (multiple `--node` flags) implemented in Phase 4.
Smoke script extended to cover `call` and `subscribe` in all four cross-stack directions.

---

## Phase 6 — Cross-stack equivalence smoke ✓

All four directions verified:
- open62541 client → open62541 server
- open62541 client → Milo server
- Milo client → open62541 server
- Milo client → Milo server

`scripts/smoke.sh cross` automates all four directions.
Cross-stack CI job in `.github/workflows/ci.yml` runs in parallel with the single-adapter jobs, on the same images.

---

## Phase 7 — First go-opcua consumer integration ✓

Released v0.1.0. Consumer tests in `go-opcua/interop/` cover all four directions:

| Direction | Coverage |
|-----------|----------|
| Go client → open62541 server | connect, namespace, browse, 8 scalar reads, write, read-back, method call, subscription |
| Go client → Milo server | same |
| open62541 client → Go server | endpoints, browse, scalar reads, write, method call, subscription |
| Milo client → Go server | same |

70 tests passing at None/None; methods and subscriptions included.

---

## Phase 8 — Security ✓

### Infrastructure (done, shipped in v0.1.1)

| Item | Status |
|------|--------|
| `certs/generate.sh` — full test PKI (CA + 6 identities + go-server identity) | ✓ |
| `certs/test-pki/` — checked-in test certificates with SAN URIs | ✓ |
| Fixture `securityProfiles` field — declares server security policies | ✓ |
| Fixture `users` field — declares username/password credentials | ✓ |
| open62541 server: `--certificate`, `--private-key`, `--pki-dir` flags | ✓ |
| open62541 server: `UA_ServerConfig_setDefaultWithSecurityPolicies` with trust list | ✓ |
| open62541 server: username/password via `UA_AccessControl_default` | ✓ |
| Milo server: `FileBasedTrustListManager`, `DefaultServerCertificateValidator` | ✓ |
| Milo server: `DefaultApplicationGroup`, `DefaultCertificateManager` | ✓ |
| Milo server: secure endpoints from fixture `securityProfiles` | ✓ |
| Milo server: username token policy on None/None endpoint | ✓ |
| Milo server: username token policy on secure endpoints | ✓ |
| Milo server: `UsernameIdentityValidator` + `CompositeValidator` | ✓ |
| Bouncy Castle idempotent registration (server + client) | ✓ |
| go-opcua: PKCS#8 PEM private key support in `loadPrivateKey` | ✓ |
| go-opcua harness: `pkiDir()`, `startSecureAdapterServer()`, `dialSecureClient()` | ✓ |
| go-opcua harness: `dialUsernameClient()` for positive/negative username tests | ✓ |
| go-opcua harness: `startSecureGoServer()` with Basic256Sha256 endpoints | ✓ |
| go-opcua harness: `runSecureAdapterClient()` for adapter→Go server tests | ✓ |
| go-opcua server: OPN asymmetric decryption fixed (was incorrectly skipped when SecurityMode=None) | ✓ |

### Verified interoperability

| Scenario | go-opcua client → open62541 | go-opcua client → Milo | open62541 client → go server | Milo client → go server |
|----------|:---:|:---:|:---:|:---:|
| Basic256Sha256 / Sign | **verified** | **verified** | **verified** | **verified** |
| Basic256Sha256 / SignAndEncrypt | **verified** | **verified** | **verified** | **verified** |
| Trust rejection (untrusted cert) | **verified** | **verified** | — | — |
| Username / valid credentials | **verified** | **verified** | **verified** | **verified** |
| Username / invalid credentials | **verified** | **verified** | **verified** | **verified** |
| Aes128_Sha256_RsaOaep / SignAndEncrypt | **verified** | **verified** | **verified** | **verified** |
| Aes256_Sha256_RsaPss / SignAndEncrypt | **verified** | **verified** | **verified** | **verified** |

### Phase 8 acceptance boundary

**Phase 8 is complete** (shipped as v0.2.0; Aes128/Aes256 closed in Phase 9).

---

## Phase 9 — Method completeness, DataValue metadata, service semantics ✓

Shipped across v0.2.1 → go-opcua consumer Phase 9 work. Verified in go-opcua interop
(historical count at Phase 9 close: 212 tests, 0 skips — consumer suite has grown since).

| Scenario | go-opcua client → open62541 | go-opcua client → Milo | open62541 client → go server | Milo client → go server |
|----------|:---:|:---:|:---:|:---:|
| Method call — Multiply (Double) | **✓** | **✓** | **✓** | **✓** |
| Method call — Echo (String round-trip) | **✓** | **✓** | **✓** | **✓** |
| Method call — NoArguments | **✓** | **✓** | **✓** | **✓** |
| Method call — MultipleOutputs | **✓** | **✓** | **✓** | **✓** |
| Method call — Fail (Bad result) | **✓** | **✓** | **✓** | **✓** |
| DataValue source + server timestamp | **✓** | **✓** | **✓** | **✓** |
| DataValue Uncertain status code | **✓** | **✓** | **✓** | **✓** |
| Access.ReadOnly write rejection | **✓** | **✓** | **✓** | **✓** |
| Access.WriteOnly read rejection | **✓** | **✓** | **✓** | **✓** |
| Batch Read (4 scalars in one request) | **✓** | **✓** | **✓** | **✓** |
| Write/read-back — Boolean | **✓** | **✓** | **✓** | **✓** |
| Write/read-back — Float | **✓** | **✓** | **✓** | **✓** |
| Write/read-back — String | **✓** | **✓** | **✓** | **✓** |
| Subscription — Dynamic.Toggle (bool alternation) | **✓** | **✓** | **✓** | **✓** |
| Subscription — Dynamic.Ramp (float64 sawtooth) | **✓** | **✓** | **✓** | **✓** |
| Array read — Boolean | **✓** | **✓** | **✓** | **✓** |
| Array read — Double | **✓** | **✓** | **✓** | **✓** |
| Browse interop namespace (top-level folders) | **✓** | **✓** | — | — |
| Browse Scalars folder (variable node list) | **✓** | **✓** | — | — |
| Browse interop Objects folder (node name check) | — | — | **✓** | **✓** |
| Browse with BrowseNext pagination | — | — | **✓** | **✓** |
| Subscription queue size > 1 (batch delivery) | **✓** | **✓** | — | — |
| Subscription discard-oldest=false (keep-oldest) | **✓** | **✓** | — | — |
| Aes128_Sha256_RsaOaep / SignAndEncrypt | **✓** | **✓** | **✓** | **✓** |
| Aes256_Sha256_RsaPss / SignAndEncrypt | **✓** | **✓** | **✓** | **✓** |

### Phase 9 is complete

---

## Phase 13 consumer support — subscribe timestamps ✓

Adapter release **v0.3.0** (supports go-opcua Phase 13):

- `subscribe --timestamps` (`Source` \| `Server` \| `Both` \| `Neither`, default `Both`)
- `subscribe` JSON emits `serverTimestamp` when present (alongside `sourceTimestamp`)
- Existing `--queue-size` / `--discard-oldest` retained
- Read/write support `--index-range` in code (for NumericRange / matrix consumer tests)

---

## Phase 14 consumer support — subscription lifecycle ✓

Adapter release **v0.4.0** (supports go-opcua Phase 14):

- `subscribe` result fields: `subscriptionId`, `revisedPublishingInterval`,
  `revisedLifetimeCount`, `revisedMaxKeepAliveCount`
- New client command `subscription-lifecycle` with scenarios:
  `revise`, `publishing-mode`, `monitoring-mode`, `delete`
- `print-capabilities` `adapter.version` = `0.4.0`
- `clientOperations` includes `subscription-lifecycle`
- `serverServices` extended with `SetPublishingMode`, `SetMonitoringMode`,
  `DeleteMonitoredItems`, `DeleteSubscriptions`

**As of v0.4.0 adapter client surface (7 operations):**
`endpoints`, `read`, `write`, `browse`, `call`, `subscribe`, `subscription-lifecycle`

---

## Phase 18 — WP1B baseline event / history / republish / transfer (0.5.0)

Adds four new client commands to both adapters; `adapter.version` = `0.5.0`:

1. **`event-subscribe`** — `EventFilter` with six BaseEvent SelectClauses (EventId, EventType,
   SourceName, Message, Severity, Time); manual Publish loop; collect *N* events or timeout
   (exit 7).
2. **`history-read`** — `ReadRawModifiedDetails` (`isReadModified=false`); flags `--node`,
   `--start`, `--end`, `--num-values`, `--continuation-point`,
   `--release-continuation-point`, `--return-bounds`, `--timestamps`,
   `--scenario continue`.
3. **`republish`** — flags `--subscription-id`, `--sequence-number`.
4. **`transfer-subscriptions`** — repeatable `--subscription-id`, `--send-initial-values`.

**As of v0.5.0 adapter client surface (13 operations):**
`endpoints`, `find-servers`, `read`, `write`, `browse`, `translate`, `call`,
`subscribe`, `subscription-lifecycle`, `event-subscribe`, `history-read`,
`republish`, `transfer-subscriptions`

v0.5.0 also carries BaseEvent emission, the gate-compliant raw historian, and the
narrow `event-subscribe` / `history-read --scenario continue` controls.

---

## Upstream refresh, channel renewal and node services (0.6.0) ✓

Adapter release **v0.6.0**; `adapter.version` = `0.6.0`:

1. **Upstream pins** — open62541 `v1.5.5` → `v1.5.9`, Eclipse Milo `1.1.5` → `1.1.8`
   (decided from the *Upstream candidates* workflow report).
2. **`register-nodes`** — RegisterNodes → Read through the returned aliases →
   UnregisterNodes; repeatable `--node`.
3. **`node-management`** — AddNodes (Int32 `BaseDataVariableType` Variable under
   `--parent`) → Read → DeleteNodes → Read-after-delete.
4. **`--channel-lifetime-ms`** — global client flag requesting a short SecureChannel
   lifetime so a long-running command crosses several SecurityToken renewals.
5. **Smoke** — `register-nodes` and a 24-notification subscribe at a 6 s channel
   lifetime run in every adapter↔adapter direction.

**As of v0.6.0 adapter client surface (15 operations):**
`endpoints`, `find-servers`, `read`, `write`, `browse`, `translate`, `call`,
`subscribe`, `subscription-lifecycle`, `event-subscribe`, `history-read`,
`republish`, `transfer-subscriptions`, `register-nodes`, `node-management`

Known limits recorded for consumers: the Milo reference server has no
NodeManagement service set (AddNodes → `BadNotSupported`), and Milo's SDK does not
pass `ReleaseContinuationPoints` to the history backend, so the Milo server cannot
invalidate a released HistoryRead continuation point.

---

## Filters, reverse connect, ECC, discovery, data encodings (0.7.0) ✓

Adapter release **v0.7.0** (supports go-opcua v1.6.0); `adapter.version` = `0.7.0`:

1. **DataChangeFilter** — `subscribe --deadband-absolute | --deadband-percent`,
   `--trigger`; fixture AnalogItems `Analog.Level` / `Analog.Setpoint` with
   `EURange`. Both adapters, client and server.
2. **Reverse connect** — server `--reverse-connect`, client `--reverse-listen`.
   open62541 only.
3. **ECC security policies** — open62541 rebuilt on the OpenSSL backend; eight
   ECC policies; `--ecc-dir`; ECC certificates in the test PKI. open62541 only.
4. **Discovery** — open62541 `--lds` / `--mdns-name` (mdnsd); `--register-with`,
   `find-servers-on-network`, `register-server` in both adapters.
5. **JSON / XML DataEncoding** — `codec` in both adapters (open62541
   `UA_encodeJson` / `UA_encodeXml`; Milo `milo-encoding-json` /
   `milo-encoding-xml`).
6. **Capabilities** — `clientFeatures`, `serverFeatures`, `codec`, ECC
   `securityProfiles`.
7. **Smoke** — deadband and codec in every direction; RSA-over-OpenSSL, ECC,
   reverse connect and LDS / mDNS on a dedicated Docker network.

| Feature | open62541 | Milo | Why not |
|---------|:---------:|:----:|---------|
| DataChangeFilter client / server | ✓ | ✓ | |
| Reverse connect | ✓ | — | no ReverseHello message type in Milo 1.1.8 transports |
| ECC policies | ✓ | — | `SecurityPolicy` enum of Milo 1.1.8 ends at `Aes256_Sha256_RsaPss` |
| LDS server / mDNS | ✓ | — | `DefaultDiscoveryServiceSet` → `Bad_ServiceUnsupported` |
| Register with an LDS (server), `register-server`, `find-servers-on-network` | ✓ | ✓ | |
| `codec` JSON | ✓ (compact) | ✓ (compact, verbose) | |
| `codec` XML | ✓ (partial) | ✓ | open62541 XML: no DataValue / DiagnosticInfo / matrices |

**Current adapter client surface (18 operations):**
`endpoints`, `find-servers`, `read`, `write`, `browse`, `translate`, `call`,
`subscribe`, `subscription-lifecycle`, `event-subscribe`, `history-read`,
`republish`, `transfer-subscriptions`, `register-nodes`, `node-management`,
`find-servers-on-network`, `register-server`, `codec`

Known limits recorded for consumers:

- open62541 client, secure reverse connect: two ReverseHello rounds (GetEndpoints
  on a None channel first), so it takes at least one server retry interval.
- open62541 v1.5.9 with `UA_ENABLE_AMALGAMATION` + mDNS only builds the
  amalgamation target; `UA_Server_setRegisterServerCallback` is declared but
  not implemented.
- The Milo reference server samples periodically even when SamplingInterval 0
  is requested, so `subscription-lifecycle --scenario publishing-mode` against
  it can coalesce back-to-back writes (unchanged from earlier releases).
- JSON DataValue: open62541 flattens the Variant members into the DataValue
  object, Milo nests them under `Value`; neither decodes the other's form.

---

## PubSub (0.8.0)

Adapter release **v0.8.0** (supports the go-opcua PubSub work); `adapter.version` = `0.8.0`:

1. **open62541 build** — PubSub, PubSub information model, SKS, file config and
   MQTT enabled in the amalgamation. Three adapter-side additions:
   `amalgam/inline_mqtt.py` (the amalgamation dropped MQTT-C),
   `amalgam/backport_json_reader.py` (v1.5.9 DataSetReaders rejected every JSON
   NetworkMessage; upstream master's matching), `src/pubsub_security.c`
   (PubSub-Aes128/256-CTR existed for mbedTLS only; OpenSSL port).
2. **`--pubsub-config`** — PubSubConfigurationDataType (OPC UA 1.05 JSON)
   built through the open62541 API (`src/pubsub_server.c`), security groups
   with static keys, SKS server (`serveSks`) and SKS pull (`sksClient`,
   retried until the SKS answers); AddSecurityGroup / RemoveSecurityGroup bound
   in the information model; SupportedTransportProfiles completed.
3. **Codec** — `codec pubsub-{uadp,json}-{encode,decode}` with a canonical
   NetworkMessage description (`src/pubsub_codec.c`).
4. **Fixture** — baseline `PubSub` folder (10 writable variables).
5. **MQTT broker** — `eclipse-mosquitto:2.0.22` by digest, `mqtt/mosquitto.conf`.
6. **Networking contract** — host ↔ container UDP unicast verified on
   macOS / Docker Desktop; multicast container ↔ container.
7. **Capabilities** — `pubsub` section (Milo: `supported: false`),
   `serverFeatures` `pubsub`, `clientFeatures` `codec-pubsub`.
8. **Smoke** — `scripts/pubsub-smoke.sh` (`make smoke-pubsub`, CI job
   `PubSub smoke`, candidate workflow).

| Feature | open62541 | Milo | Notes |
|---------|:---------:|:----:|-------|
| UADP over UDP unicast / multicast | ✓ | — | multicast container ↔ container only |
| UADP / JSON over MQTT | ✓ | — | QoS 0, anonymous, no TLS, ~1000-byte messages |
| Variant / DataValue / RawData fields | ✓ | — | RawData decoding needs metadata |
| KeyFrame / KeepAlive | ✓ | — | |
| DeltaFrame | codec ✓, publish opt-in | — | v1.5.9 readers drop DeltaFrames |
| Events, chunking, discovery messages, Mirror | — | — | not in open62541 1.5.9 |
| Sign / SignAndEncrypt (PubSub-Aes128/256-CTR) | ✓ UADP | — | |
| SKS server / pull / push | ✓ | — | GetSecurityKeys TimeToNextKey wrong in v1.5.9 |
| Information-model configuration methods | ✓ | — | AddReaderGroup via methods: name only (no MQTT / JSON / security) |
| `codec pubsub-*` | ✓ | — | no message security in the standalone API |

Known limits recorded for consumers (docs/CLIENT_CONTRACT.md §14.10): a
DataSetReader that hit its MessageReceiveTimeout stays in Error; JSON
`MessageId` is null; KeyFrameCount 1 with delta frames enabled alternates Key /
Delta; the unicast destination host must resolve when the publisher starts.

---

## Current status ← here

| Item | Status |
|------|--------|
| Latest released image tag | **v0.7.0** (next: v0.8.0, PubSub) |
| Publication model | Immutable tags: every adapter-surface change gets a new release (see `RELEASE.md`) |
| Capabilities `adapter.version` | **0.8.0** |
| Upstream stacks | open62541 **v1.5.9** (OpenSSL, mdnsd, PubSub + MQTT + SKS), Eclipse Milo **1.1.8** |
| Client operations | 18 (see above) |
| Optional features | declared in `print-capabilities` (`clientFeatures`, `serverFeatures`, `codec`, `pubsub`) |
| PubSub | open62541 only (`--pubsub-config`, `codec pubsub-*`); Milo declares `pubsub.supported: false` |
| Consumer pin | go-opcua re-pins to the published `v0.8.0` digests after release |

---

## Release sequence

| Release | Content | Status |
|---------|---------|--------|
| v0.1.0 | Phases 0–7: open62541 + Milo, anonymous, baseline scalars, methods, subscriptions, cross-stack smoke, first go-opcua integration | **released** |
| v0.1.1 | Phase 8 infrastructure: test PKI, security endpoint scaffolding, Milo security APIs, username token policy, go-opcua PKCS#8 fix | **released** |
| v0.2.0 | Phase 8 complete: Basic256Sha256 Sign/SignAndEncrypt and username auth verified in all four directions; trust rejection verified | **released** |
| v0.2.1 | Phase 9 fixture/docs/adapter hardening (arrays, browse, subscription queue flags, Aes profiles in fixture/docs) | **released** |
| v0.3.0 | go-opcua Phase 13: `subscribe --timestamps`, `serverTimestamp` in subscribe JSON | **released** |
| v0.4.0 | go-opcua Phase 14: subscribe revised fields + `subscription-lifecycle` command; capabilities 0.4.0 | **released** |
| v0.5.0-dev | Phase 18 (WP1B) development capabilities label | **superseded** |
| v0.5.0 | Phase 18 WP1B + events/historian/find-servers/translate/continue | **released** |
| v0.6.0 | open62541 v1.5.9 / Milo 1.1.8; `register-nodes`, `node-management`, `--channel-lifetime-ms`; capabilities 0.6.0 | **released** |
| v0.7.0 | DataChangeFilter deadbands, reverse connect, ECC policies, LDS / mDNS, `codec` (JSON / XML); feature capabilities; capabilities 0.7.0 | **released** |
| v0.8.0 | PubSub (open62541): `--pubsub-config`, UDP / MQTT, UADP / JSON, security, SKS, information model, `codec pubsub-*`; fixture `PubSub` folder; Mosquitto broker; capabilities 0.8.0 | **in preparation** |
| Later | Alarms; NodeSet2 import | — |

---

## Fixture schema versioning

`schemaVersion` is independent of the repository release version. A release may
upgrade upstream stacks without changing the fixture schema. A schema change
increments `schemaVersion` and requires both adapters to be updated before release.
