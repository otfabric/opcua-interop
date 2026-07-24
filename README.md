# opcua-interop

Containerized OPC UA reference implementations for interoperability testing.

## Purpose

`opcua-interop` provides two independently implemented OPC UA stacks—**open62541** (C) and **Eclipse Milo** (Java/JVM)—as deterministic Docker containers with a shared fixture format. Consumer repositories such as [`go-opcua`](https://github.com/otfabric/go-opcua) use these containers to make defensible client and server interoperability claims.

**This repository owns:**
- Containerized reference servers and clients
- The fixture schema and bundled fixtures
- Deterministic address-space construction
- Test PKI and certificate generation
- Health checks and readiness signals
- Documented commands for consumer repositories

**Consumer repositories own:**
- Test scenarios, assertions, and coverage decisions
- Pass/fail evaluation
- Compatibility claims and regression tracking

## Quick start

### Prerequisites

- Docker (with BuildKit)
- `make`
- `jq` (for fixture validation)
- `openssl` >= 1.1 (for `make certs`)

### Run a reference server

```sh
# open62541 server on port 4840
make run-open62541

# Milo server on port 4841
make run-milo
```

### Run a reference client probe

```sh
# Linux (--network host reaches the host's published port)
docker run --rm --network host \
  ghcr.io/otfabric/opcua-interop-open62541:latest \
  client read \
  --endpoint opc.tcp://localhost:4840/opcua-interop \
  --node 'nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32'

# macOS / Docker Desktop (host.docker.internal instead of --network host)
docker run --rm --add-host=host.docker.internal:host-gateway \
  ghcr.io/otfabric/opcua-interop-open62541:latest \
  client read \
  --endpoint opc.tcp://host.docker.internal:4840/opcua-interop \
  --node 'nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32'

# Browse from the Milo server
docker run --rm --network host \
  ghcr.io/otfabric/opcua-interop-milo:latest \
  client browse \
  --endpoint opc.tcp://localhost:4841/opcua-interop \
  --node 'i=85'
```

### Print adapter capabilities

```sh
docker run --rm ghcr.io/otfabric/opcua-interop-open62541:latest print-capabilities
docker run --rm ghcr.io/otfabric/opcua-interop-milo:latest print-capabilities
```

## Architecture

```
opcua-interop/
├── fixtures/           # Shared, stack-neutral fixture definitions
│   ├── schema/         # JSON Schema for fixture validation
│   ├── baseline/       # Baseline fixture (scalars, access, browse, methods, subscriptions)
│   ├── subscriptions/  # Dynamic-value and subscription fixture
│   ├── methods/        # Method fixture
│   ├── security/       # Security policy fixture (Phase 8)
│   └── edge-cases/     # Edge-case and stress fixture
├── certs/              # Test PKI generation script and generated tree
│   ├── generate.sh     # Generates test-pki/ from scratch (requires openssl >= 1.1)
│   └── test-pki/       # Generated certificates (checked in for convenience)
├── open62541/          # C adapter (Dockerfile, CMakeLists, source)
├── milo/               # Java adapter (Dockerfile, pom.xml, source)
├── scripts/            # Readiness, smoke, and validation helpers
├── compose.yaml        # Docker Compose service definitions
└── .github/            # CI workflows and Dependabot config
```

### Fixture format

Fixtures are stack-neutral JSON documents validated against `fixtures/schema/opcua-fixture.schema.json`. Each fixture describes a deterministic OPC UA address space including nodes, behaviors, security profiles, and user credentials. Both adapters construct an equivalent namespace from the same fixture file.

See [`fixtures/baseline/README.md`](fixtures/baseline/README.md) for the baseline fixture documentation.

### Container modes

Each image supports the same command contract:

| Mode | Description |
|---|---|
| `server` | Start an OPC UA server from a fixture |
| `client` | Run composable client probe operations |
| `test` | Run the adapter's built-in unit tests |
| `validate-fixture` | Validate a fixture file against the schema |
| `print-capabilities` | Print adapter capabilities as JSON |

### Container images

| Image | Architecture |
|---|---|
| `ghcr.io/otfabric/opcua-interop-open62541:<version>` | linux/amd64, linux/arm64 |
| `ghcr.io/otfabric/opcua-interop-milo:<version>` | linux/amd64, linux/arm64 |

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

### Client commands

Seven client operations (see `print-capabilities` → `clientOperations` and
[`docs/CLIENT_CONTRACT.md`](docs/CLIENT_CONTRACT.md)):

```sh
client endpoints --endpoint opc.tcp://host:4840/opcua-interop
client read      --endpoint ... --node 'nsu=...;s=Scalar.Int32' [--index-range '1:3']
client write     --endpoint ... --node '...' --type Int32 --value 100 [--index-range '0']
client browse    --endpoint ... --node 'i=85'
client call      --endpoint ... --object '...' --method '...' --input 'Int32:10' --input 'Int32:20'
client subscribe --endpoint ... --node '...' --notifications 5 --timeout-ms 10000 \
                 [--queue-size 3] [--discard-oldest true] [--timestamps Both]
client subscription-lifecycle --endpoint ... --node '...' \
                 --scenario revise|publishing-mode|monitoring-mode|delete
```

`subscribe` JSON includes `subscriptionId` and revised CreateSubscription fields
(`revisedPublishingInterval`, `revisedLifetimeCount`, `revisedMaxKeepAliveCount`)
plus optional `sourceTimestamp` / `serverTimestamp` on notifications.

All client operations write JSON to stdout and diagnostics to stderr.

## Test PKI

The test PKI lives under `certs/test-pki/` and is regenerated by `make certs`.

```
certs/test-pki/
├── ca/                    # Self-signed test CA (10-year validity)
├── open62541-server/      # open62541 server identity
├── open62541-client/      # open62541 client identity
├── milo-server/           # Milo server identity
├── milo-client/           # Milo client identity
├── consumer/              # Consumer client identity (used by go-opcua test client)
├── go-server/             # go-opcua server identity (DNS:host.docker.internal SAN)
└── untrusted/             # Self-signed cert for trust-rejection tests
```

Each identity directory contains:
- `cert.crt` — PEM certificate with correct SAN URI
- `cert.key` — PEM private key (PKCS#8)
- `cert.pfx` — PKCS#12 bundle (debug/inspection artifact; adapters use PEM directly)
- `pki/` — OPC UA PKI directory pre-populated with the CA trust anchor

**WARNING:** These certificates are for isolated test environments only. Private keys
are checked in intentionally. Never use them in production or expose them to untrusted
networks.

## Consumer integration model

```
opcua-interop
    ├── deterministic reference servers
    ├── reference client commands
    ├── shared fixtures
    └── container lifecycle

go-opcua
    ├── starts selected compat container
    ├── runs Go client/server tests
    ├── evaluates results
    ├── owns regressions
    └── publishes compatibility claims
```

Four test directions:

| Direction | Owner |
|---|---|
| Go client → open62541 server | go-opcua |
| Go client → Milo server | go-opcua |
| open62541 client → Go server | go-opcua |
| Milo client → Go server | go-opcua |

## Make targets

```sh
make ci                  # Full local CI gate: validate → build → test → smoke → shutdown
make image               # Build both images for host architecture
make image-open62541     # Build open62541 image (host arch)
make image-milo          # Build Milo image (host arch)
make validate            # Validate fixtures and schema
make validate-fixtures   # Validate all fixture files
make test                # Run unit tests for both adapters
make test-open62541      # Run open62541 unit tests
make test-milo           # Run Milo unit tests
make smoke               # Run all smoke tests (images must be built)
make smoke-open62541     # Smoke test open62541 only
make smoke-milo          # Smoke test Milo only
make smoke-cross-stack   # Cross-stack interop self-check
make shutdown            # Test graceful shutdown for both adapters
make run-open62541       # Start open62541 server (foreground, port 4840)
make run-milo            # Start Milo server (foreground, port 4841)
make certs               # Generate test PKI (requires openssl >= 1.1)
make clean               # Remove build artifacts and containers
make release VERSION=v0.4.0  # Build and push multi-arch release images
```

## Versioning

| Version type | Location |
|---|---|
| Repository release | Git tag and image tag — latest released **`v0.5.0`**; next **`v0.5.1-rc.1`** (Milo session auth fix) |
| Adapter capabilities version | `print-capabilities` → `adapter.version` — working tree **`0.5.1-rc.1`** |
| Upstream stack version | Image label and `print-capabilities` → `stack.version` |
| Fixture schema version | `schemaVersion` field in every fixture |

Released tags: `v0.1.0`, `v0.1.1`, `v0.2.0`, `v0.2.1`, `v0.3.0`, `v0.4.0`, `v0.5.0`
([latest release](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0)).
Working tree has the Milo `AuthenticationToken` fix for WP1B event-subscribe — see `PLAN.md`.

## Reference stacks

| Adapter | Language | Stack | Why included |
|---|---|---|---|
| open62541 | C | open62541 v1.5.5 | Native/embedded diversity, OPC UA Binary, certified example-server history |
| Eclipse Milo | Java | Eclipse Milo v1.1.5 | JVM/enterprise diversity, independent serialization and security code paths |

## Security

The test PKI (`certs/test-pki/`) landed in v0.1.1; Basic256Sha256 / username verification
completed in v0.2.0; Aes128 / Aes256 profiles are verified as of Phase 9 (v0.2.1 era).

**What is implemented and verified:**
- Full test PKI with CA, seven identities (including go-server), and OPC UA PKI directory layout
- Server `--certificate`, `--private-key`, `--pki-dir` flags on both adapters
- Secure endpoint advertisement driven by fixture `securityProfiles`
- Trust list validation via open62541 `UA_ServerConfig_setDefaultWithSecurityPolicies`
- Trust list validation via Milo `FileBasedTrustListManager` + `DefaultServerCertificateValidator`
- Username/password authentication on both None/None and secure endpoints
- Basic256Sha256 / Sign — all four directions: go-opcua client ↔ adapter servers; adapter clients ↔ go-opcua server
- Basic256Sha256 / SignAndEncrypt — all four directions
- Aes128_Sha256_RsaOaep / SignAndEncrypt — all four directions
- Aes256_Sha256_RsaPss / SignAndEncrypt — all four directions
- Untrusted certificate rejection — go-opcua client vs. both adapter servers
- Username valid/invalid — all four directions (go-opcua client ↔ adapter servers; adapter clients ↔ go-opcua server)
- go-opcua server OPN asymmetric decryption (Part 6 §6.7.4 conformance fix)
- open62541 client `UA_ExtensionObject_setValueCopy` argument-order fix (data first, type second)

**Test PKI runtime note:** PKI directories must be writable at container runtime because rejected certificates may be quarantined. The go-opcua test harness copies the PKI tree to a writable temporary directory before mounting it.

## License

MIT. See [LICENSE](LICENSE).
