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
- `open62541/Dockerfile` (multi-stage, pinned release)
- `open62541/CMakeLists.txt`
- `open62541/src/` — fixture parser, server, client, readiness, signal handling, output
- `open62541/tests/` — fixture parser unit tests

Client commands at foundation: endpoints, read, write, browse, call, subscribe
(later extended — see Phase 14 / v0.4.0).

---

## Phase 3 — Eclipse Milo adapter foundation ✓

Deliverables:
- `milo/Dockerfile` (multi-stage, JDK 25 + Maven 3.9)
- `milo/pom.xml`
- `milo/src/main/java/` — fixture loader, namespace, server, client, shutdown, readiness
- `milo/src/test/java/` — fixture loading unit tests (8 tests, all pass)

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
Cross-stack CI job in `.github/workflows/smoke.yml` runs after both single-adapter jobs pass.

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

**Current adapter client surface (7 operations):**
`endpoints`, `read`, `write`, `browse`, `call`, `subscribe`, `subscription-lifecycle`

---

## Current status ← here

| Item | Status |
|------|--------|
| Latest released image tag | **v0.4.0** |
| Capabilities `adapter.version` | **0.4.0** (both adapters) |
| Client operations | 7 (see above) |
| Peer Event / HistoryRead / Republish / Transfer CLI | **not implemented** (deferred) |

Next consumer-driven work (go-opcua Phase 18 peer closure) would add adapter commands for
events, Republish, TransferSubscriptions, and raw HistoryRead — not yet scheduled here.

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
| Later | Event subscribe, HistoryRead, Republish, Transfer CLI; alarms; reverse connect; NodeSet2 import; PubSub | — |

---

## Fixture schema versioning

`schemaVersion` is independent of the repository release version. A release may
upgrade upstream stacks without changing the fixture schema. A schema change
increments `schemaVersion` and requires both adapters to be updated before release.
