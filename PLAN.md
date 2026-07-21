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

All six client commands (endpoints, read, write, browse, call, subscribe) implemented.

---

## Phase 3 — Eclipse Milo adapter foundation ✓

Deliverables:
- `milo/Dockerfile` (multi-stage, JDK 25 + Maven 3.9)
- `milo/pom.xml`
- `milo/src/main/java/` — fixture loader, namespace, server, client, shutdown, readiness
- `milo/src/test/java/` — fixture loading unit tests (8 tests, all pass)

All six client commands (endpoints, read, write, browse, call, subscribe) implemented.

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

## Phase 8 — Security ← current

### Infrastructure (done, shipped in v0.1.1)

| Item | Status |
|------|--------|
| `certs/generate.sh` — full test PKI (CA + 6 identities) | ✓ |
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

### Verified interoperability (pending — next steps)

The test infrastructure is in place. The following directions need a passing test run
against the `:dev` images before they can be called verified:

| Scenario | go-opcua client → open62541 | go-opcua client → Milo | open62541 client → go server | Milo client → go server |
|----------|:---:|:---:|:---:|:---:|
| Basic256Sha256 / Sign | written | written | not started | not started |
| Basic256Sha256 / SignAndEncrypt | written | written | not started | not started |
| Trust rejection (untrusted cert) | written | written | — | — |
| Username / valid credentials | written | written | not started | not started |
| Username / invalid credentials | written | written | not started | not started |
| Aes128_Sha256_RsaOaep / SignAndEncrypt | not started | not started | not started | not started |
| Aes256_Sha256_RsaPss / SignAndEncrypt | not started | not started | not started | not started |

"written" = test exists in go-opcua/interop/ but has not yet had a confirmed green run.

### Phase 8 acceptance boundary

Phase 8 is complete when:

- Basic256Sha256/Sign — all four directions pass
- Basic256Sha256/SignAndEncrypt — all four directions pass
- Username (valid + invalid) — tested against all three server stacks
- Trust rejection — at least one positive + one negative certificate test per server stack
- All 70+ existing None/None tests remain green

Aes128 and Aes256 policies are stretch goals for Phase 8; they can move to Phase 9 if
Basic256Sha256 coverage is solid.

### Remaining work for Phase 8 completion

1. Confirm Basic256Sha256 Sign + SignAndEncrypt against `:dev` Milo and open62541 images
2. Add go-opcua server TLS support (adapter clients → Go server secure channel)
3. Add open62541 client and Milo client secure-channel tests (adapter as TLS client)
4. Confirm username tests against both adapter servers
5. One negative trust test per server stack

---

## Phase 9 — Arrays, DataValue metadata, complex types

- Array and matrix variables (all built-in scalar types)
- DataValue timestamp and status-code metadata
- Structured types, enumerations
- Edge-case fixture (`fixtures/edge-cases/`)

---

## Release sequence

| Release | Content | Status |
|---------|---------|--------|
| v0.1.0 | Phases 0–7: open62541 + Milo, anonymous, baseline scalars, methods, subscriptions, cross-stack smoke, first go-opcua integration | released |
| v0.1.1 | Phase 8 infrastructure: test PKI, security endpoint scaffolding, Milo security APIs, username token policy, go-opcua PKCS#8 fix | released |
| v0.2.0 | Phase 8 complete: all four directions verified for Basic256Sha256 Sign/SignAndEncrypt, username auth, trust rejection | pending |
| v0.3.0 | Phase 9: arrays, DataValue metadata, custom structures, enumerations | pending |
| Later | Alarms, history, events, reverse connect, NodeSet2 import, PubSub | — |

---

## Fixture schema versioning

`schemaVersion` is independent of the repository release version. A release may
upgrade upstream stacks without changing the fixture schema. A schema change
increments `schemaVersion` and requires both adapters to be updated before release.
