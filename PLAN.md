# Implementation Plan

## Governing principle

`opcua-interop` owns reference implementations and deterministic test environments. Consuming repositories own test scenarios, assertions, coverage, pass/fail decisions, and compatibility claims.

## Implementation phases

### Phase 0 — Repository bootstrap ✓

Deliverables:
- `README.md`
- `REQUIREMENTS.md`
- `PLAN.md`
- `LICENSE`
- Directory structure
- `Makefile` with all standard targets
- `compose.yaml`
- Basic CI skeletons
- Fixture schema stub
- Docker image naming convention

Acceptance: `make validate` passes (fixture schema validates; both Dockerfiles parse).

---

### Phase 1 — Fixture schema and baseline model

Deliverables:
- `fixtures/schema/opcua-fixture.schema.json` (v1.0)
- `fixtures/baseline/fixture.json`
- `fixtures/baseline/README.md`
- Schema validation in CI

Baseline fixture covers:
- Server and endpoint metadata
- Namespace declaration
- Object and Folder nodes
- Variable nodes for all scalar built-in types
- Read/write, read-only, write-only access
- Explicit NodeIds (namespace-URI form)
- Deterministic initial values

Acceptance:
- `make validate-fixtures` passes
- Invalid fixtures fail clearly with JSON path errors
- Schema is documented with examples

---

### Phase 2 — open62541 server

Deliverables:
- `open62541/Dockerfile` (multi-stage, pinned release)
- `open62541/CMakeLists.txt`
- `open62541/src/` — fixture parser, server, readiness, signal handling
- `open62541/tests/` — fixture parser unit tests
- Image: `ghcr.io/otfabric/opcua-interop-open62541`

Acceptance:
- `docker run ... server --fixture /fixtures/baseline/fixture.json` starts a usable OPC UA server
- Readiness file is written only after address space is ready
- `SIGTERM` causes clean shutdown with nonzero on failure

---

### Phase 3 — Milo server

Deliverables:
- `milo/Dockerfile` (multi-stage, pinned JDK and release)
- `milo/pom.xml`
- `milo/src/main/java/` — fixture loader, server, namespace, readiness, shutdown
- `milo/src/test/java/` — fixture loading unit tests
- Image: `ghcr.io/otfabric/opcua-interop-milo`

Acceptance:
- Both servers expose equivalent namespace URIs, NodeIds, and values
- Both enforce equivalent read/write behavior

---

### Phase 4 — Reference client commands

Deliverables:
- Client binary in both adapter images
- Subcommands: `endpoints`, `read`, `write`, `browse`, `call` (placeholder), `subscribe` (placeholder)
- JSON stdout, diagnostics stderr
- Stable exit codes
- `validate-fixture` mode

Acceptance:
- Either client reads either server
- JSON output is parseable by `jq`
- Command errors do not corrupt stdout

---

### Phase 5 — Methods

Schema additions:
- Method nodes with input/output argument definitions
- Deterministic behavior declaration (Add, Multiply, Echo, MultipleOutputs, Fail)

Implementation:
- Both adapters implement the baseline method set
- Type validation and error returns are deterministic

Acceptance:
- Both clients call methods on both servers
- Output types and argument metadata agree

---

### Phase 6 — Subscriptions and dynamic behavior

Schema additions:
- `behaviors` array with `counter`, `toggle`, `ramp`, `status-sequence`
- `intervalMs`, `initial`, `increment`, `bounds`

Implementation:
- Both servers generate deterministic value sequences
- Client `subscribe` subcommand collects a bounded count of notifications
- Client emits JSON and exits without hanging

Acceptance:
- Both clients receive deterministic notifications from both servers
- Shutdown does not leave client processes running

---

### Phase 7 — Security

Deliverables:
- `certs/generate.sh` — generates full test PKI
- `certs/test-pki/` — CA, server certs, client certs, trust stores
- Security endpoints: `None/None`, `Basic256Sha256/Sign`, `Basic256Sha256/SignAndEncrypt`, `Aes128_Sha256_RsaOaep/SignAndEncrypt`, `Aes256_Sha256_RsaPss/SignAndEncrypt`
- Client flags: `--security-policy`, `--security-mode`, `--certificate`, `--private-key`, `--trust-list`, `--username`, `--password`

Acceptance:
- Trusted clients connect with all active security profiles
- Untrusted clients are rejected
- Incorrect credentials are rejected
- Failure output remains machine-readable JSON

---

### Phase 8 — go-opcua consumer integration

This phase is implemented in `go-opcua`, not `opcua-interop`.

Pattern:
```
go-opcua/interop/
    go_client_open62541_server_test.go
    go_client_milo_server_test.go
    open62541_client_go_server_test.go
    milo_client_go_server_test.go
    fixtures_test.go
    testdata/
```

Test helpers:
1. Locate Docker
2. Pull pinned compatibility image
3. Mount selected fixture
4. Wait for readiness
5. Run Go test scenario
6. Collect container logs on failure
7. Stop and remove container

Run selector:
```sh
OPCUA_COMPAT_STACK=open62541 go test ./interop/...
OPCUA_COMPAT_STACK=milo go test ./interop/...
go test -tags=interop ./interop/...
```

---

## Release sequence

| Release | Content |
|---|---|
| v0.1.0 | Phases 0–6: open62541 and Milo, UA-TCP binary, anonymous, baseline scalars, arrays, methods, basic subscriptions, cross-stack smoke |
| v0.2.0 | Phase 7: test PKI, modern security policies, username/password |
| v0.3.0 | Arrays, matrices, richer DataValues, custom structures, enumerations, optional NodeSet2 import |
| Later | Alarms, historical access, events, reverse connect, NodeOPCUA, PubSub (separate scope) |

## Cross-stack self-check scope

The repository smoke test verifies both adapters realize the same baseline contract:

1. Connect
2. Create session
3. Browse root fixture node
4. Read representative scalar
5. Write representative variable
6. Call `Add`
7. Receive two counter notifications
8. Disconnect

This is not a product compatibility matrix. It is a repository self-check.

## Fixture schema versioning

The fixture schema version (`schemaVersion`) is independent of the repository release version. A repository release may upgrade upstream stacks without changing the fixture schema. A schema change increments the schema version and requires both adapters to be updated before release.
