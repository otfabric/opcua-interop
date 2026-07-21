# Requirements

## Purpose

`opcua-interop` provides containerized OPC UA reference implementations and a shared fixture format for interoperability testing. Consumer repositories use these containers to make defensible interoperability claims about their own OPC UA implementations.

## Goals

- Provide two containerized OPC UA reference implementations from independent implementation families
- Define a stack-neutral, versioned fixture format that describes deterministic OPC UA address spaces
- Expose deterministic reference-client operations for testing consumer server implementations
- Produce readiness signals suitable for automated test orchestration
- Support `linux/amd64` and `linux/arm64` container architectures
- Provide documented, stable Make targets and Docker commands that consumer repositories can invoke
- Enable cross-stack self-verification between the two reference implementations

## Reference stacks

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

- Full test PKI: CA, open62541-server, open62541-client, milo-server, milo-client, consumer, untrusted identities
- Server security flags: `--certificate`, `--private-key`, `--pki-dir` (both adapters)
- Secure endpoint advertisement from fixture `securityProfiles`
- Trust list validation (both adapters)
- Username/password identity validator (both adapters)
- Username token policy on None/None endpoints (allows testing auth independently of message security)
- Fixture schema: `securityProfiles` and `users` fields
- go-opcua harness: secure client dial, username client dial, trust-rejection assertions

### v0.2.0 (target) — Security verification complete

All of the following confirmed with green test runs in go-opcua:

- Basic256Sha256/Sign — all four directions
- Basic256Sha256/SignAndEncrypt — all four directions
- Trust rejection — positive and negative certificate test per server stack
- Username/valid credentials — all three server stacks
- Username/invalid credentials — rejected by all three server stacks
- go-opcua server with TLS (adapter clients → Go server secure channel)

Stretch goal (may move to v0.3.0 if Basic256Sha256 coverage is solid first):
- Aes128_Sha256_RsaOaep/SignAndEncrypt
- Aes256_Sha256_RsaPss/SignAndEncrypt

### v0.3.0 (planned) — Arrays, DataValue metadata, complex types

- Array and matrix variables (all built-in scalar types)
- DataValue timestamp and status-code metadata
- Structured types, enumerations
- Edge-case fixture (`fixtures/edge-cases/`)

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

1. Accept `--fixture`, `--bind-address`, `--bind-port`, `--advertised-host`, `--advertised-port`, `--endpoint-path`, `--ready-file` flags
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
- `read` — read one or more nodes, JSON to stdout
- `write` — write a node value
- `browse` — browse a node
- `call` — call a method
- `subscribe` — collect a bounded number of notifications

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

- PubSub (distinct communication model; separate workstream)
- MQTT and AMQP transport
- UDP multicast
- WebSockets transport
- HTTPS transport
- Historical access
- Alarms and conditions
- Complex companion specifications
- Global Discovery Server
- Certificate enrollment
- Reverse connect
- Redundancy
- Full OPC Foundation CTT coverage
- NodeOPCUA or other third stacks
