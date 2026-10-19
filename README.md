# opcua-interop — OPC UA Interoperability Testing with Docker

**opcua-interop is an open-source OPC UA (OPC Unified Architecture)
interoperability testing infrastructure providing Dockerized
reference clients and servers based on independent OPC UA
protocol implementations.**

Test OPC UA client and server implementations against two established
reference stacks:

- **open62541 (C)** — Open-source OPC UA implementation for
  embedded, industrial and native applications.
- **Eclipse Milo (Java)** — Independent OPC UA implementation
  for Java and JVM-based industrial applications.

The infrastructure provides deterministic test fixtures, simulated
OPC UA servers, reference client operations, secure communication,
certificate-based authentication, subscriptions, events, historical
data and automated protocol compatibility testing.

## Key features

- **Independent reference implementations** — Two independently
  implemented OPC UA stacks written in C and Java.
- **Dockerized clients and servers** — Reproducible OPC UA
  test environments without installing native protocol libraries.
- **Deterministic fixtures** — Shared OPC UA address spaces,
  data types, values and expected server behavior.
- **Client/server interoperability** — Validate OPC UA clients
  against reference servers and OPC UA servers against
  reference clients.
- **Security testing** — Test PKI, X.509 certificates, secure
  endpoints, encryption policies and authentication.
- **Subscriptions and events** — Data-change monitoring,
  event subscriptions and subscription lifecycle testing.
- **Historical data** — HistoryRead operations, continuation
  points and historical value retrieval.
- **Method calls and node management** — Exercise advanced
  OPC UA services using documented client commands.
- **Cross-platform containers** — Docker images for
  Linux AMD64 and ARM64.
- **CI integration** — Automated testing with consistent
  fixtures and machine-readable results.

## Independent interoperability infrastructure

This repository provides reusable OPC UA reference environments.
It does not depend on any particular OPC UA library under test.

Applications and protocol libraries consume the published Docker
images and implement their own test assertions.

For example,
[OTFabric go-opcua](https://github.com/otfabric/go-opcua)
uses these reference implementations to verify its client
and server interoperability.

**Open Source · Docker · open62541 · Eclipse Milo · OPC UA**

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
│   ├── baseline/       # Baseline fixture (scalars, access, browse, methods, subscriptions, events, history)
│   ├── subscriptions/  # Dynamic-value and subscription fixture
│   ├── methods/        # Method fixture
│   ├── security/       # Security policy fixture
│   └── edge-cases/     # Edge-case and stress fixture
├── certs/              # Test PKI generation script and generated tree
│   ├── generate.sh     # Generates test-pki/ from scratch (requires openssl >= 1.1)
│   └── test-pki/       # Generated certificates (git-ignored; `make certs`)
├── open62541/          # C adapter (Dockerfile, CMakeLists, source)
├── milo/               # Java adapter (Dockerfile, pom.xml, source)
├── schemas/            # JSON Schemas for client results and print-capabilities
├── docs/               # Client command contract (CLIENT_CONTRACT.md)
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

Optional server features (v0.7.0; see [`docs/CLIENT_CONTRACT.md`](docs/CLIENT_CONTRACT.md) §11
and `print-capabilities` → `serverFeatures`):

```sh
# open62541: ECC endpoints (one certificate per curve under <dir>/ecc-<curve>/)
server ... --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
           --pki-dir /pki/open62541-server/pki --ecc-dir /pki/open62541-server

# open62541: reverse connect — the server dials the client and sends ReverseHello
server ... --reverse-connect opc.tcp://client-host:4855

# open62541: Local Discovery Server with mDNS (RegisterServer/2, FindServersOnNetwork)
server ... --lds
server ... --mdns-name my-server            # announce a plain server via mDNS

# both adapters: register with an LDS (RegisterServer2, fallback RegisterServer)
server ... --register-with opc.tcp://lds:4840/opcua-interop
```

### Client commands

Eighteen client operations (see `print-capabilities` → `clientOperations` and
[`docs/CLIENT_CONTRACT.md`](docs/CLIENT_CONTRACT.md)):

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
```

`subscribe` takes a DataChangeFilter (`--deadband-absolute <x>` | `--deadband-percent <x>`,
`--trigger Status|StatusValue|StatusValueTimestamp`); the baseline fixture's
`Analog.Level` / `Analog.Setpoint` AnalogItems (EURange 0..100) are there for it.

The open62541 client can wait for a reverse connection instead of dialling
(`--reverse-listen <port>`) and speaks the ECC security policies
(`--security-policy ECC_nistP256 --certificate <identity>/ecc-nistp256/cert.crt ...`).

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
- `ecc-<curve>/cert.crt|cert.key` — ECC application certificates for the ECC security
  policies (`open62541-server`, `open62541-client`, `consumer`, `go-server`; curves
  `nistp256`, `nistp384`, `brainpoolp256r1`, `brainpoolp384r1`, `curve25519`, `curve448`),
  same subject / SAN URI, issued by the same test CA. `untrusted/ecc-nistp256/` is the
  self-signed ECC counterpart. `certs/generate.sh --add-ecc` adds them to an existing PKI
  without touching the CA or the RSA files.

**WARNING:** These certificates are for isolated test environments only. They are not
checked in: `certs/test-pki/` is git-ignored and generated locally with `make certs`.
The private keys are unprotected, so never use them in production or expose them to
untrusted networks.

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
make release VERSION=v0.7.0  # Build and push multi-arch release images
```

## Versioning

| Version type | Location |
|---|---|
| Repository release | Git tag and image tag — latest **`v0.7.0`** |
| Adapter capabilities version | `print-capabilities` → `adapter.version` — **`0.7.0`** (must match the tag) |
| Upstream stack version | Image label and `print-capabilities` → `stack.version` |
| Fixture schema version | `schemaVersion` field in every fixture |

Released tags: `v0.1.0`, `v0.1.1`, `v0.2.0`, `v0.2.1`, `v0.3.0`, `v0.4.0`, `v0.5.0`, `v0.6.0`,
`v0.7.0` ([latest release](https://github.com/otfabric/opcua-interop/releases/tag/v0.7.0)).
`v0.6.0` moved the reference stacks to open62541 v1.5.9 / Eclipse Milo 1.1.8 and added
`register-nodes`, `node-management` and `--channel-lifetime-ms`. `v0.7.0` adds
DataChangeFilter deadbands, reverse connect, the ECC security policies, LDS / mDNS
discovery and the JSON / XML `codec` command, and declares optional features in
`print-capabilities` (`clientFeatures`, `serverFeatures`, `codec`). Every change to the
adapter surface gets a new tag; published tags are not moved. See [`PUBLISH.md`](PUBLISH.md).

## Reference stacks

| Adapter | Language | Stack | Why included |
|---|---|---|---|
| open62541 | C | open62541 v1.5.9 (OpenSSL crypto backend, mDNS via mdnsd) | Native/embedded diversity, OPC UA Binary, certified example-server history |
| Eclipse Milo | Java | Eclipse Milo v1.1.8 (+ `milo-encoding-json`, `milo-encoding-xml`) | JVM/enterprise diversity, independent serialization and security code paths |

Feature support differs per stack and is declared by `print-capabilities`:

| Feature (v0.7.0) | open62541 | Eclipse Milo |
|---|:---:|:---:|
| DataChangeFilter (absolute / percent deadband, trigger) — client and server | ✓ | ✓ |
| Reverse connect (server `--reverse-connect`, client `--reverse-listen`) | ✓ | — (no ReverseHello in Milo 1.1.8) |
| ECC security policies | ✓ | — (no ECC `SecurityPolicy` in Milo 1.1.8) |
| LDS server (`--lds`), mDNS | ✓ | — (Milo answers `Bad_ServiceUnsupported`) |
| `--register-with`, `register-server`, `find-servers-on-network` | ✓ | ✓ |
| `codec` JSON (OPC UA 1.05) | ✓ compact | ✓ compact + verbose |
| `codec` XML | ✓ (no DataValue / DiagnosticInfo / matrices) | ✓ |

## Security

The test PKI (`certs/test-pki/`) landed in v0.1.1; Basic256Sha256 / username verification
completed in v0.2.0; Aes128 / Aes256 profiles followed in v0.2.1; SecureChannel renewal
(`--channel-lifetime-ms`) is exercised cross-stack as of v0.6.0. v0.7.0 moves the
open62541 adapter to the OpenSSL crypto backend and adds the ECC security policies.

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
- ECC (open62541 ↔ open62541, verified by `make smoke`): `ECC_nistP256`, `ECC_nistP384`,
  `ECC_brainpoolP256r1`, `ECC_brainpoolP384r1`, `ECC_curve25519`, `ECC_curve448`,
  `ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly` — SecureChannel, username/password as
  EccEncryptedSecret, wrong password and untrusted certificate rejected. The server takes
  the ECC certificates from `--ecc-dir`; ECC endpoints are opt-in, so servers started
  without it advertise exactly the RSA endpoints of v0.6.0
- The open62541 client sends the certificate's SAN URI as its ApplicationUri (an
  open62541 server rejects a mismatch with `BadCertificateUriInvalid`); override with
  `--application-uri`

**Test PKI runtime note:** PKI directories must be writable at container runtime because rejected certificates may be quarantined. The go-opcua test harness copies the PKI tree to a writable temporary directory before mounting it.

## License

MIT. See [LICENSE](LICENSE).
