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

### Run a reference server

```sh
# open62541 server on port 4840
make run-open62541

# Milo server on port 4841
make run-milo

# Both servers
docker compose up
```

### Run a reference client probe

```sh
# Read a node from the open62541 server
docker run --rm --network host \
  ghcr.io/otfabric/opcua-interop-open62541:latest \
  client read \
  --endpoint opc.tcp://localhost:4840/opcua-interop \
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
│   ├── baseline/       # Baseline fixture (scalars, access, browse)
│   ├── subscriptions/  # Dynamic-value and subscription fixture
│   ├── methods/        # Method fixture
│   ├── security/       # Security policy fixture
│   └── edge-cases/     # Edge-case and stress fixture
├── certs/              # Test PKI generation scripts and output
├── open62541/          # C adapter (Dockerfile, CMakeLists, source)
├── milo/               # Java adapter (Dockerfile, pom.xml, source)
├── scripts/            # Readiness, smoke, and validation helpers
├── compose.yaml        # Docker Compose service definitions
└── .github/            # CI workflows and Dependabot config
```

### Fixture format

Fixtures are stack-neutral JSON documents validated against `fixtures/schema/opcua-fixture.schema.json`. Each fixture describes a deterministic OPC UA address space. Both adapters construct an equivalent namespace from the same fixture file.

See [`fixtures/baseline/README.md`](fixtures/baseline/README.md) for the baseline fixture documentation.

### Container modes

Each image supports the same command contract:

| Mode | Description |
|---|---|
| `server` | Start an OPC UA server from a fixture |
| `client` | Run composable client probe operations |
| `validate-fixture` | Validate a fixture file against the schema |
| `print-capabilities` | Print adapter capabilities as JSON |

### Container images

| Image | Architecture |
|---|---|
| `ghcr.io/otfabric/opcua-interop-open62541:<version>` | linux/amd64, linux/arm64 |
| `ghcr.io/otfabric/opcua-interop-milo:<version>` | linux/amd64, linux/arm64 |

### Server command

```sh
/server \
  --fixture /fixtures/baseline/fixture.json \
  --endpoint opc.tcp://0.0.0.0:4840/opcua-interop \
  --pki-dir /pki \
  --ready-file /run/opcua-interop/ready
```

Environment variable equivalents: `OPCUA_FIXTURE`, `OPCUA_PORT`, `OPCUA_ENDPOINT_PATH`, `OPCUA_LOG_LEVEL`, `OPCUA_PKI_DIR`, `OPCUA_TRUST_MODE`.

### Client commands

```sh
/client endpoints --endpoint opc.tcp://host:4840/opcua-interop
/client read      --endpoint ... --node 'nsu=...;s=Scalar.Int32'
/client write     --endpoint ... --node '...' --type Int32 --value 100
/client browse    --endpoint ... --node 'i=85'
/client call      --endpoint ... --object '...' --method '...' --input 'Int32:10' --input 'Int32:20'
/client subscribe --endpoint ... --node '...' --notifications 5 --timeout 10s
```

All client operations write JSON to stdout and diagnostics to stderr.

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
make build               # Build both images
make build-open62541     # Build open62541 image only
make build-milo          # Build Milo image only
make validate            # Validate fixtures and schema
make validate-fixtures   # Validate all fixture files
make smoke               # Run all smoke tests
make smoke-open62541     # Smoke test open62541 only
make smoke-milo          # Smoke test Milo only
make smoke-cross-stack   # Cross-stack interop self-check
make run-open62541       # Start open62541 server (foreground)
make run-milo            # Start Milo server (foreground)
make certs               # Generate test PKI
make clean               # Remove build artifacts and containers
make image-open62541     # Build and tag open62541 image
make image-milo          # Build and tag Milo image
make release VERSION=v0.1.0
```

## Versioning

| Version type | Location |
|---|---|
| Repository release | Git tag and image tag, e.g. `v0.1.0` |
| Upstream stack version | Image label and `print-capabilities` output |
| Fixture schema version | `schemaVersion` field in every fixture |

## Reference stacks

| Adapter | Language | Stack | Why included |
|---|---|---|---|
| open62541 | C | open62541 ≥ 1.3 | Native/embedded diversity, OPC UA Binary, certified example-server history |
| Eclipse Milo | Java | Eclipse Milo ≥ 0.6 | JVM/enterprise diversity, independent serialization and security code paths |

## Security

Security profiles are implemented after baseline unsecured interoperability is stable (v0.2.0). The test PKI is generated by `make certs` and must never be used outside isolated test environments.

## License

MIT. See [LICENSE](LICENSE).
