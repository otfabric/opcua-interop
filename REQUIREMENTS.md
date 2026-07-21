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

## Reference stacks (v0.1.0)

| Adapter | Language | Implementation family |
|---|---|---|
| open62541 | C | Native / embedded |
| Eclipse Milo | Java/JVM | Enterprise / JVM |

These two stacks provide the strongest initial implementation diversity. A third stack (e.g. NodeOPCUA) may be added later if driven by concrete consumer needs.

## Initial scope (v0.1.0)

The first release covers OPC UA Client/Server over UA-TCP with OPC UA Binary encoding:

- UA-TCP transport (`opc.tcp://`)
- OPC UA Binary encoding
- SecureChannel (`None / None` for v0.1.0)
- Anonymous session
- GetEndpoints, Browse, Read, Write, Call
- CreateSubscription, CreateMonitoredItems, Publish
- Baseline scalar types, arrays, and methods
- Deterministic dynamic value generators (counter, toggle, ramp)

## Out of scope

The following are explicitly excluded from the initial scope and should not be added without a concrete consumer requirement:

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
- Security profiles (deferred to v0.2.0)
- NodeOPCUA or other third stacks (deferred)

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

1. Accept `--fixture`, `--endpoint`, `--pki-dir`, and `--ready-file` flags
2. Load and validate the fixture before reporting ready
3. Write a readiness file only after the address space is available
4. Handle `SIGTERM` and shut down cleanly
5. Return nonzero on fixture or startup failure
6. Not mix log output into JSON client output

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

Each image must implement `print-capabilities` and emit a JSON document describing adapter version, stack version, supported services, security policies, and user token types.

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
