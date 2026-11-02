# opcua-interop — OPC UA Interoperability Testing with Docker

A Docker-based interoperability testing framework for OPC UA (OPC Unified Architecture), providing independent client and server implementations, deterministic fixtures, and automated protocol compatibility testing.
Test OPC UA libraries against established implementations without integrating third-party protocol stacks into production applications. Reference implementations are independently containerized, for reproducible testing on linux/amd64 and linux/arm64.

| Adapter | Implementation | Language | Server | Client | Image |
|---------|----------------|----------|:------:|:------:|-------|
| `open62541` | [open62541](https://github.com/open62541/open62541) v1.5.9 | C | yes | yes | `ghcr.io/otfabric/opcua-interop-open62541` |
| `milo` | [Eclipse Milo](https://github.com/eclipse-milo/milo) 1.1.8 | Java | yes | yes | `ghcr.io/otfabric/opcua-interop-milo` |
| `async-opcua` | [async-opcua](https://github.com/FreeOpcUa/async-opcua) 0.19.0 | Rust | yes | yes | `ghcr.io/otfabric/opcua-interop-async-opcua` |
| `dotnet` | [OPC Foundation UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard) 2.0.1 | C# | yes | yes | `ghcr.io/otfabric/opcua-interop-dotnet` |
| `node-opcua` | [node-opcua](https://github.com/node-opcua/node-opcua) 2.187.12 | TypeScript | yes | yes | `ghcr.io/otfabric/opcua-interop-node-opcua` |
| `asyncua` | [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0 | Python | yes | yes | `ghcr.io/otfabric/opcua-interop-asyncua` |
| `dotnet-gds` | UA-.NETStandard 2.0.1, Global Discovery Server | C# | yes | yes | `ghcr.io/otfabric/opcua-interop-dotnet-gds` |

The stacks do not all do the same: ECC policies, LDS and mDNS are served by
open62541, PubSub by open62541 and UA-.NETStandard, `codec` by open62541, Milo and
UA-.NETStandard, and the GDS pull model by its own image. Each image says what it
supports (`print-capabilities`); see [docs/CAPABILITIES.md](docs/CAPABILITIES.md).

**Docs:** [docs/CONTAINER_CONTRACT.md](docs/CONTAINER_CONTRACT.md) (commands, JSON documents, exit codes) · [docs/FIXTURES.md](docs/FIXTURES.md) (address spaces, PubSub configurations, test PKI) · [docs/CAPABILITIES.md](docs/CAPABILITIES.md) · [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) (pins, cross-stack matrix, findings) · [COVERAGE.md](COVERAGE.md) · [REQUIREMENTS.md](REQUIREMENTS.md) · [PLAN.md](PLAN.md) · [RELEASE.md](RELEASE.md)

## Table of contents

- [opcua-interop — OPC UA Interoperability Testing with Docker](#opcua-interop--opc-ua-interoperability-testing-with-docker)
  - [Table of contents](#table-of-contents)
  - [What this repository is, and is not](#what-this-repository-is-and-is-not)
  - [Quick start](#quick-start)
  - [OT Fabric's own stack](#ot-fabrics-own-stack)
  - [Using the images from a library's tests](#using-the-images-from-a-librarys-tests)
  - [Repository layout](#repository-layout)
  - [Development](#development)
  - [Security](#security)
  - [License](#license)

## What this repository is, and is not

It owns the reference implementations, their adapters, the fixtures, the
container contract, the images and the self-tests that show the references
agree with each other.

It does not contain, import, build or know about any library under test, apart
from [one image](#ot-fabrics-own-stack) kept out of its releases.
[otfabric/go-opcua](https://github.com/otfabric/go-opcua) is a consumer: it
pulls the images and owns its own scenarios, assertions and compatibility
claims. A passing self-test here says the *references* interoperate; it says
nothing about a consumer.

The fixtures describe what a server is; the adapters make each
implementation behave that way; the consumer decides what to assert.

## Quick start

Needs Docker, `jq`, and `openssl` >= 1.1 for the test PKI.

```sh
make images      # build the adapter images for this machine
make smoke       # container contract of each image
make interop     # every client against every server
```

A reference server on loopback, and a reference client against it:

```sh
make run-open62541       # 127.0.0.1:4840, baseline fixture, Ctrl-C to stop
```

```sh
docker run --rm --add-host=host.docker.internal:host-gateway \
  ghcr.io/otfabric/opcua-interop-milo:dev \
  client read --endpoint opc.tcp://host.docker.internal:4840/opcua-interop \
  --node 'nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32' | jq .
```

Every image has the same commands:

```text
server               an OPC UA server serving a fixture
client <operation>   endpoints, read, write, browse, call, subscribe, and the others
                     of the contract; refused with exit code 2 when not supported
test                 the adapter's built-in self-test (not on the otfabric image)
validate-fixture     check a fixture file
print-capabilities   what this adapter supports, as JSON
```

## OT Fabric's own stack

`ghcr.io/otfabric/opcua-interop-otfabric` is go-opcua behind the same contract, a
core subset of it, so you can test your stack against ours the way we test ours
against yours. Despite the name it shares with the reference images, it is not an
independent implementation and not part of a release of this repository, so its
tags are go-opcua versions and the release does not list it: see
[own/go-opcua/README.md](own/go-opcua/README.md).

## Using the images from a library's tests

A consumer needs Docker, the image references and its own test code. It does
not clone this repository, except for `certs/generate.sh` when it tests secured
channels.

**Library as client, reference as server.** Start the server, wait for the
readiness file (never for a delay), connect:

```sh
docker run -d --name ref -p 127.0.0.1:4840:4840 ghcr.io/otfabric/opcua-interop-open62541:<tag> \
  server --fixture /fixtures/baseline/fixture.json
until docker exec ref test -f /run/opcua-interop/ready; do sleep 0.1; done
```

**Library as server, reference as client.** Serve the fixture with the
library, run a client operation, assert on the result document and exit code:

```sh
docker run --rm --add-host=host.docker.internal:host-gateway \
  ghcr.io/otfabric/opcua-interop-milo:<tag> \
  client browse --endpoint opc.tcp://host.docker.internal:<port>/<path> --node 'i=85'
```

**Secured channels.** `certs/generate.sh` writes the test PKI to `certs/test-pki/`;
mount a writable copy, because rejected certificates are quarantined there. See
[docs/FIXTURES.md](docs/FIXTURES.md#test-pki) and the
[flags](docs/CONTAINER_CONTRACT.md#11-server-lifecycle-flags).

**Expected values** come from the fixture, baked into the image under
`/fixtures`, so expectations cannot drift from the image.

**What a stack supports** comes from the image too: `print-capabilities`.
Skip, do not fail, a scenario that needs a feature an image does not declare.

**Pin by digest** in release qualification
(`ghcr.io/otfabric/opcua-interop-open62541@sha256:...`); the digests are in each
release's notes. The directions a consumer owns, and the versioning, are in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Repository layout

```text
opcua-interop/
├── adapters/
│   ├── open62541/       C adapter: Dockerfile, CMakeLists.txt, src/
│   ├── milo/            Java adapter: Dockerfile, pom.xml, src/
│   ├── async-opcua/     Rust adapter: Dockerfile, Cargo.toml, src/
│   ├── dotnet/          C# adapter: Dockerfile, csproj, src/
│   ├── dotnet-gds/      C# adapter, Global Discovery Server: Dockerfile, csproj, src/
│   ├── node-opcua/      TypeScript adapter: Dockerfile, package.json, src/
│   └── asyncua/         Python adapter: Dockerfile, hashed requirements, src/
├── certs/               test PKI: generate.sh, generated test-pki/ (git-ignored)
├── fixtures/
│   ├── schema/          JSON Schema of the fixture format
│   ├── baseline/ gds/ subscriptions/ methods/ security/ edge-cases/
│   └── pubsub/          PubSub configurations and the MQTT broker configuration
├── own/go-opcua/        the one image of OT Fabric's own stack, not in a release
├── schemas/             JSON Schemas of the capability and client result documents, interop-result-v1
├── tests/cases.tsv      self-test cases: operation, expected outcome, features needed
├── tests/secure-cases.tsv  secured channels and user tokens
├── tests/codec-cases.tsv   `codec` documents between stacks
├── tests/known-bugs.tsv deviations of the pinned upstreams, with evidence
├── scripts/             validate, smoke, cross-stack self-test, PubSub, upstream check
├── docs/                contract, fixtures, capabilities, compatibility
├── versions.yaml        every upstream pin and base image digest
├── compose.yaml         the reference servers on loopback
└── Makefile
```

## Development

```sh
make help        # all targets
make ci          # validate, lint, build, smoke, cross-stack self-test, document schemas
make validate    # fixtures against the schema and the cross-field rules
make pubsub      # PubSub between containers, with a broker
make buildx      # check the other architecture locally, under emulation (CI builds both natively)
make candidate-milo CANDIDATE=1.2.0   # self-test the adapter on another upstream version
```

The **Upstream** workflow checks every pin daily against the latest upstream
(`scripts/latest-upstream.py`) and the base-image digests. It runs that probe
for every stack that is behind and reports pin versus latest in its job summary
and in an issue.

`make documents` also writes `reports/results.json`, the organisation's
[interop-result-v1](schemas/interop-result-v1.schema.json). A run with no pass,
or with a known bug that no longer reproduces, fails.

`make smoke ADAPTERS=milo` and `VERBOSE=1 make interop` narrow and expand what
is run and shown. See [CONTRIBUTING.md](CONTRIBUTING.md) for adding an adapter, a
fixture or a client operation.

## Security

The servers are test fixtures with fixture users and fixture passwords, and they
accept anonymous sessions and SecurityPolicy None. The PKI is generated, with
keys that are not secret. `compose.yaml` and the `run-*` targets publish them on
loopback only, and they must never be attached to a plant network. See
[SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE). The images contain the upstream libraries under
their own licences: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
