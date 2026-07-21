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

Status: structurally complete. Semantic validation and corpus hardening deferred to Phase 4.

---

## Phase 2 — open62541 adapter foundation ✓

Deliverables:
- `open62541/Dockerfile` (multi-stage, pinned release)
- `open62541/CMakeLists.txt`
- `open62541/src/` — fixture parser, server, client, readiness, signal handling, output
- `open62541/tests/` — fixture parser unit tests

Status: complete. All six client commands (endpoints, read, write, browse, call, subscribe)
implemented. Contract hardening deferred to Phase 4.

---

## Phase 3 — Eclipse Milo adapter foundation ✓

Deliverables:
- `milo/Dockerfile` (multi-stage, JDK 25 + Maven 3.9)
- `milo/pom.xml`
- `milo/src/main/java/` — fixture loader, namespace, server, client, shutdown, readiness
- `milo/src/test/java/` — fixture loading unit tests (8 tests, all pass)

Status: complete. All six client commands (endpoints, read, write, browse, call, subscribe)
implemented. Contract hardening deferred to Phase 4.

---

## Phase 4 — Contract freeze and adapter parity ✓

The two adapters must produce identical output shapes for identical inputs before
the feature surface grows further. This is the gate for go-opcua consumer integration.

### Workstream A — Command and output contract

Deliverables:
- `docs/CLIENT_CONTRACT.md` ✓
- `schemas/client-result.schema.json` ✓
- `schemas/capabilities.schema.json` ✓

### Workstream B — Adapter hardening (both adapters)

For each item, both adapters must comply before it is considered done.

| Item | Description |
|------|-------------|
| Canonical envelope | Every command: `schemaVersion`, `adapter`, `operation`, `success`, `serviceResult` (structured), `results`, `error` |
| Exact status codes | `serviceResult` and per-item `statusCode` as `{name, code, severity}` — not string summary |
| Complete NodeId parsing | All forms: `i=`, `ns=N;i=`, `ns=N;s=`, `ns=N;g=`, `ns=N;b=`, `nsu=URI;*` |
| Hard NodeId failure | Malformed/unknown NodeId → exit 2 before any network activity |
| Bind vs. advertised | `--bind-address`, `--bind-port`, `--advertised-host`, `--advertised-port` |
| Atomic readiness | tmp-file then rename; JSON content; fatal on failure |
| Operation timeouts | `--connect-timeout`, `--request-timeout`, `--disconnect-timeout` |
| Stable exit codes | 0/2/3/4/5/6/7 as defined in CONTRACT |
| Exact endpoint selection | No fallback to first endpoint; fail if None/None absent |
| Browse continuation | Handle BrowseNext continuation points |
| Value encoding | Int64/UInt64 as decimal strings; DateTime RFC 3339 UTC; Guid lowercase UUID; ByteString Base64 |

### Workstream C — Makefile

- ✓ Separate `image-*` (local host-arch) from `buildx-*` (multi-arch push)
- Remove placeholder `DEBIAN_DIGEST` from Milo Dockerfile or pin properly

### Acceptance

For the same operation against the same fixture, both adapters must produce:
- output that validates against `schemas/client-result.schema.json`
- identical `serviceResult.name` and `serviceResult.code` values
- identical `statusCode.name` and `statusCode.code` per result item
- identical canonical NodeId strings
- identical value representations (Int64 as string, not number; etc.)
- identical exit-code category for the same error type
- no stdout contamination from logs

---

## Phase 5 — Complete reference-client surface ✓

New client subcommands implemented in both adapters:
- `call` — invoke a method node (`--object`, `--method`, `--input Type:value`)
- `subscribe` — create a subscription, collect N notifications, emit JSON array, disconnect

Batch read (multiple `--node` flags) was implemented in Phase 4.
Batch write deferred to Phase 6 (single-item write covers Phase 5 and Phase 6 needs).

Smoke script extended to cover `call` and `subscribe` in all four cross-stack directions.

---

## Phase 6 — Cross-stack equivalence smoke ✓

All four directions:
- open62541 client → open62541 server
- open62541 client → Milo server
- Milo client → open62541 server
- Milo client → Milo server

Assertions limited to fixture realization:
1. Connect anonymously
2. Namespace resolution
3. Browse Compatibility root
4. Read a representative scalar set
5. Write Access.ReadWrite
6. Call Methods.Add
7. Receive three Dynamic.Counter notifications
8. Disconnect

`scripts/smoke.sh cross` automates all four directions with exit 0/1.
Cross-stack CI job in `.github/workflows/smoke.yml` runs after both single-adapter jobs pass.

---

## Phase 7 — First go-opcua consumer integration ← current

Release a provisional tagged image (v0.1.0 candidate) and begin consumer tests in
`go-opcua/interop/`.

Scope for first integration:
- Go client → open62541 server
- Go client → Milo server
- open62541 client → Go server
- Milo client → Go server

Each direction: connect, namespace, browse, scalar reads (8 types), write, read-back, close.

Methods and subscriptions added in separate commits after baseline passes.

---

## Phase 8 — Security

- `certs/generate.sh` — full test PKI (CA, server certs, client certs)
- `certs/test-pki/` — checked-in test certificates
- Security endpoints: None/None, Basic256Sha256/Sign, Basic256Sha256/SignAndEncrypt,
  Aes128_Sha256_RsaOaep/SignAndEncrypt, Aes256_Sha256_RsaPss/SignAndEncrypt
- Client flags: `--security-policy`, `--security-mode`, `--certificate`, `--private-key`,
  `--trust-list`, `--username`, `--password`
- Untrusted clients rejected; incorrect credentials rejected
- Failure output remains machine-readable JSON

---

## Release sequence

| Release | Content |
|---------|---------|
| v0.1.0 | Phases 0–7: open62541 + Milo, anonymous, baseline scalars, methods, subscriptions, cross-stack smoke, first go-opcua integration |
| v0.2.0 | Phase 8: test PKI, modern security policies, username/password |
| v0.3.0 | Arrays, matrices, DataValue metadata, custom structures, enumerations |
| Later | Alarms, history, events, reverse connect, NodeSet2 import, PubSub |

---

## Fixture schema versioning

`schemaVersion` is independent of the repository release version. A release may
upgrade upstream stacks without changing the fixture schema. A schema change
increments `schemaVersion` and requires both adapters to be updated before release.
