# opcua-interop Releases

## How a release is made

1. `make ci` on the commit to release (validates fixtures, builds both images,
   runs the adapter unit tests, the single-adapter, cross-stack and PubSub
   smoke tests and the graceful-shutdown checks). The `Build` and `Smoke`
   workflows run the same gate on every push.
2. Set the version everywhere it is reported — `make check-release
   VERSION=vX.Y.Z` lists what does not match:
   - `open62541/src/main.c` (`adapter.version`)
   - `milo/src/main/java/io/otfabric/opcuainterop/CapabilitiesCommand.java`
     (`adapter.version`)
   - `milo/src/main/java/io/otfabric/opcuainterop/ServerCommand.java`
     (`BuildInfo` software version)
3. Write the section `## vX.Y.Z` below, with its **Date**; `make release-notes
   VERSION=vX.Y.Z` prints what the GitHub release will say. Commit and push
   to `main`.
4. Run the `Release` workflow on `main` (Actions → Release → Run workflow)
   with the bump: `patch`, `minor` or `major`. From the command line:

   ```bash
   gh workflow run release.yml --repo otfabric/opcua-interop --ref main -f bump=minor
   ```

   The workflow
   - derives the next version from the latest `vX.Y.Z` tag and the bump, and
     stops if that tag exists, if the adapters report another version, or if
     this file has no dated section for it (`scripts/check-release.sh`); it
     validates the fixtures,
   - builds both images natively on an amd64 and an arm64 runner, runs the
     adapter unit tests, the smoke tests (single-adapter, cross-stack, PubSub)
     and the shutdown checks on exactly those images, and pushes them as
     `<image>:vX.Y.Z-amd64` / `-arm64`,
   - joins them into the multi-arch `<image>:vX.Y.Z`, `:vX.Y` and `:vX`,
   - creates the git tag `vX.Y.Z` on the released commit and the GitHub
     release with this file's section as notes, the image digests,
     `manifest.json` (upstream pins and digests) and `checksums.txt`.

   The tag is created last: a failed run leaves no tag, fix and run again.
5. Consumers pin the digests from the release (`manifest.json`). For go-opcua:
   update `defaultOpen62541Image` / `defaultMiloImage` in
   `interop/harness_test.go`, `.github/workflows/interop.yml`, `INTEROP.md` and
   `interop/BUCKET_B.md`, then run its interop suite against the published
   images:

   ```bash
   OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 go test -count=1 -tags=interop -timeout 60m ./interop/...
   ```

Tags are immutable. A fix is a new version; a published tag is never moved
(`:vX.Y` and `:vX` follow the latest release of their line).

| What changed | Version |
|--------------|---------|
| Command contract, result envelope or fixture format changed incompatibly | major (minor while 0.x) |
| New command, flag, result field, capability, fixture node or reference-stack feature | minor |
| Upstream pin, base image or bug fix with unchanged contract | patch |

Upstream pins: `open62541/Dockerfile` (`ARG OPEN62541_COMMIT`),
`milo/pom.xml` (`milo.version`), the MQTT broker `eclipse-mosquitto:2.0.22` by
digest (`Makefile`, `compose.yaml`, `scripts/pubsub-smoke.sh`).

---

## v0.8.1

**Date:** 2026-10-24
**Previous release:** v0.8.0

### Changed

- **Milo adapter dependencies:** jackson-databind 2.17.2 → 2.22.3, logback-classic 1.5.6 → 1.6.5, slf4j-api 2.0.18 → 2.0.20, junit-jupiter 6.1.2 → 6.1.3, maven-surefire-plugin 3.3.1 → 3.6.0.

### Docs

- CLIENT_CONTRACT §14.6, open62541 information-model methods, corrected from the go-opcua interop tests: AddDataSetReader cannot target an existing variable (the reader's writes fail with `BadNodeIdUnknown`); a ReaderGroup added to a running connection receives nothing until the connection is disabled and enabled again; RemoveDataSetReader fails with `BadInternalError` while its ReaderGroup is enabled.



**Date:** 2026-10-23
**Previous release:** v0.7.0

### Summary

OPC UA PubSub (Part 14) in the open62541 adapter, for the go-opcua PubSub
implementation: publishers and subscribers over UDP and MQTT with the UADP and
JSON message mappings, message security with static keys and a Security Key
Service, the PubSub information model with its configuration methods, and a
NetworkMessage codec. Eclipse Milo 1.1.8 has no PubSub; the Milo adapter says
so in `print-capabilities` and refuses the PubSub flags. Backward compatible:
existing commands, flags and result shapes are unchanged, and the fixture only
gains nodes.

### Added

- **open62541 build with PubSub** — the v1.5.9 amalgamation now has
  `UA_ENABLE_PUBSUB`, `UA_ENABLE_PUBSUB_INFORMATIONMODEL`,
  `UA_ENABLE_PUBSUB_SKS`, `UA_ENABLE_PUBSUB_FILE_CONFIG` and `UA_ENABLE_MQTT`.
  Three adapter-side additions make that work on v1.5.9:
  `open62541/amalgam/inline_mqtt.py` inlines MQTT-C, which the amalgamation
  drops; `open62541/amalgam/backport_json_reader.py` backports upstream's
  DataSetReader matching, without which v1.5.9 rejects every JSON
  NetworkMessage; `open62541/src/pubsub_security.c` ports PubSub-Aes128-CTR /
  PubSub-Aes256-CTR to OpenSSL (v1.5.9 has them for mbedTLS only). Both
  scripts patch only the exact v1.5.9 code and warn otherwise.
- **Server `--pubsub-config <file>`** (open62541) — a
  `PubSubConfigurationDataType` in the OPC UA 1.05 JSON encoding plus
  `securityGroups` (static keys), `serveSks` (this server is the SKS),
  `sksClient` (pull keys from a remote SKS) and `deltaFrames`. UDP unicast and
  multicast and MQTT connections, UADP and JSON writer groups,
  PublishedDataItems, DataSetReaders with TargetVariables, message receive
  timeouts, Sign and SignAndEncrypt. The fields honoured per structure are
  listed in [docs/CLIENT_CONTRACT.md](docs/CLIENT_CONTRACT.md) §14.3; worked
  examples are in `pubsub/examples/`.
- **PubSub information model** (open62541) — `PublishSubscribe` is browsable
  and configurable through its methods, also without `--pubsub-config`;
  AddSecurityGroup / RemoveSecurityGroup are bound by the adapter (v1.5.9 has
  no callback for them). Method argument conventions: CLIENT_CONTRACT §14.6.
- **Codec** (open62541) — `client codec pubsub-uadp-encode|pubsub-uadp-decode|pubsub-json-encode|pubsub-json-decode`
  with a canonical JSON description of a NetworkMessage and `--metadata` for
  RawData (CLIENT_CONTRACT §14.9). The standalone v1.5.9 API has no message
  security; signed and encrypted messages are covered by the live path.
- **Fixture** — a `PubSub` folder in the baseline fixture with writable
  `PubSub.Boolean`, `.Int32`, `.Int64`, `.UInt64`, `.Double`, `.String`,
  `.DateTime`, `.ByteString`, `.Int32Array` and `.DoubleArray` variables.
- **MQTT broker** — `eclipse-mosquitto:2.0.22` pinned by digest with
  `mqtt/mosquitto.conf` (anonymous, port 1883), compose service `mosquitto`,
  `make run-mosquitto`.
- **Networking contract** for UDP between the host and containers, verified on
  macOS / Docker Desktop (README, PubSub section); multicast container to
  container only.
- **Capabilities** — `pubsub` section (`supported`, transports, encodings,
  security policies, SKS, information model, codec), `serverFeatures`
  `pubsub`, `clientFeatures` `codec-pubsub`; Milo reports
  `pubsub.supported: false`. `adapter.version` = `0.8.0`.
- **Smoke** — `scripts/pubsub-smoke.sh` (`make smoke-pubsub`, part of
  `make smoke` and CI): codec, UDP unicast and multicast, MQTT with UADP and
  JSON, SignAndEncrypt with static keys, SKS pull and push, information model.

### Release process

- `RELEASE.md` replaces `PUBLISH.md`: the release procedure and the notes of
  every release.
- The `Release` workflow is started by hand with a `patch` / `minor` / `major`
  bump, like the other otfabric repositories. It derives the version, checks
  it against the adapter versions and this file first, builds each
  architecture natively, runs the full test gate on exactly the images it
  pushes, and only then creates the tag and the release with these notes, the
  image digests, `manifest.json` and `checksums.txt`.
- `make check-release`, `make release-notes`, `make publish-arch`,
  `make publish-manifest`, `make digests`; `make release` is replaced by
  `make publish` (multi-arch under emulation, for a manual fallback).

### Known limits of open62541 1.5.9 (recorded for consumers)

- No events, chunked NetworkMessages, discovery / metadata messages or
  SubscribedDataSetMirror; message security for UADP only.
- Delta frames are off unless `deltaFrames: true`: v1.5.9 alternates key and
  delta frames even with KeyFrameCount 1, and its own reader discards them.
- MQTT: 3.1.1, QoS 0, no TLS, messages below about 1000 bytes; JSON
  subscribers accept key frames only and sequence numbers up to 65535.
- A DataSetReader that hit its MessageReceiveTimeout stays in Error until it is
  disabled and enabled again.
- GetSecurityKeys returns a negative TimeToNextKey (wall clock minus monotonic
  clock); use KeyLifetime.
- AddReaderGroup through the information model keeps only the name.

---

## v0.7.0

**Date:** 2026-10-11
**Previous release:** v0.6.0

### Summary

Filters, reverse connect, ECC, discovery and data encodings, for go-opcua
v1.6.0. Optional features are declared per adapter in `print-capabilities`
(`clientFeatures`, `serverFeatures`, `codec`, `securityProfiles`); an
unsupported feature flag is refused, never ignored.

### Added

- **DataChangeFilter** (both adapters) — `subscribe --deadband-absolute`,
  `--deadband-percent`, `--trigger`; results report the monitored item status,
  filter, filter result and revised sampling interval / queue size. Fixture
  AnalogItems `Analog.Level` (ramp) and `Analog.Setpoint` (writable) with
  `EURange` 0..100.
- **Reverse connect** (open62541) — server `--reverse-connect <url>`; client
  `--reverse-listen <port>`, `--reverse-timeout-ms`, `--reverse-server-uri`.
- **ECC security policies** (open62541, now on the OpenSSL backend) —
  `ECC_nistP256`, `ECC_nistP384`, `ECC_brainpoolP256r1`, `ECC_brainpoolP384r1`,
  `ECC_curve25519`, `ECC_curve448`, `ECC_nistP256_AesGcm`,
  `ECC_nistP256_ChaChaPoly`; server `--ecc-dir`; ECC certificates in the test
  PKI (`certs/generate.sh --add-ecc`).
- **Discovery** — open62541 server `--lds` (RegisterServer / RegisterServer2,
  FindServers, FindServersOnNetwork, mDNS) and `--mdns-name`; both adapters
  `--register-with`; client `find-servers-on-network` and `register-server`.
- **JSON / XML DataEncoding** — client `codec` in both adapters: encode
  literals of all built-in types, arrays and matrices or a node's value, decode
  a document, Binary encoding as Base64 for bit-exact comparison.
- Value literals for all built-in types in `write`, `call` and `codec`.
- Smoke covers every new feature in each adapter-to-adapter direction both
  ends support. `adapter.version` = `0.7.0`; eighteen client operations.

---

## v0.6.0

**Date:** 2026-10-11
**Previous release:** v0.5.1

### Summary

Upstream refresh to open62541 v1.5.9 and Eclipse Milo 1.1.8, SecureChannel
renewal and the node services.

### Added

- `register-nodes` — RegisterNodes, Read through the aliases, UnregisterNodes.
- `node-management` — AddNodes (Int32 variable), Read, DeleteNodes, Read.
- Global client flag `--channel-lifetime-ms` to force SecurityToken renewals
  during a command (use at least 5000 ms).
- Smoke: `register-nodes` and a subscribe across channel renewals in every
  adapter-to-adapter direction. `adapter.version` = `0.6.0`; fifteen client
  operations.

### Changed

- open62541 `v1.5.5` → `v1.5.9`, Eclipse Milo `1.1.5` → `1.1.8`.

### Known limits

- The Milo reference server has no NodeManagement service set (AddNodes →
  `BadNotSupported`), and Milo does not pass ReleaseContinuationPoints to the
  history backend.

---

## v0.5.1

**Date:** 2026-07-25
**Previous release:** v0.5.0

Tag only, without a GitHub release. `adapter.version` = `0.5.1` and
documentation updates (README, PLAN, REQUIREMENTS, contract, PKI and fixture
READMEs); the adapters behave as in v0.5.0.

---

## v0.5.0

**Date:** 2026-07-25
**Previous release:** v0.4.0

### Summary

Events, history, Republish and TransferSubscriptions (go-opcua WP1B).

### Added

- `event-subscribe` — EventFilter with the BaseEvent SelectClauses (EventId,
  EventType, SourceName, Message, Severity, Time); collect *N* events or time
  out (exit 7).
- `history-read` — ReadRawModifiedDetails with `--start`, `--end`,
  `--num-values`, `--continuation-point`, `--release-continuation-point`,
  `--return-bounds`, `--timestamps`.
- `republish` and `transfer-subscriptions`.
- `find-servers` and `translate` (TranslateBrowsePathsToNodeIds).
- Reference servers emit BaseEvents and serve raw history for
  `History.Temperature`.
- `adapter.version` = `0.5.0`; thirteen client operations.

---

## v0.4.0

**Date:** 2026-07-24
**Previous release:** v0.3.0

### Added

- `subscribe` reports the revised CreateSubscription fields
  (`subscriptionId`, `revisedPublishingInterval`, `revisedLifetimeCount`,
  `revisedMaxKeepAliveCount`).
- `subscription-lifecycle` with the scenarios `revise`, `publishing-mode`,
  `monitoring-mode` and `delete`.
- `adapter.version` = `0.4.0`; seven client operations.

---

## v0.3.0

**Date:** 2026-07-24
**Previous release:** v0.2.1

### Added

- `subscribe --timestamps` (`Source`, `Server`, `Both`, `Neither`) and
  `serverTimestamp` in the subscribe result.
- `--index-range` for `read` and `write`.

---

## v0.2.1

**Date:** 2026-07-22
**Previous release:** v0.2.0

### Changed

- Fixture and adapter hardening for method, DataValue metadata, access level,
  array, browse and subscription queue scenarios; Aes128_Sha256_RsaOaep and
  Aes256_Sha256_RsaPss in the fixture and documentation.

---

## v0.2.0

**Date:** 2026-07-22
**Previous release:** v0.1.1

### Added

- Basic256Sha256 Sign and SignAndEncrypt and username authentication verified
  in all four client/server directions; certificate trust rejection per server
  stack.

### Fixed

- open62541 client: argument order of `UA_ExtensionObject_setValueCopy`.

---

## v0.1.1

**Date:** 2026-07-22
**Previous release:** v0.1.0

### Added

- Test PKI (CA, server and client identities per stack, consumer, Go server,
  untrusted identities).
- Server flags `--certificate`, `--private-key`, `--pki-dir`; secure endpoints
  from the fixture's `securityProfiles`; trust list validation; username /
  password validation and a username token policy on None endpoints.

---

## v0.1.0

**Date:** 2026-07-21

### Summary

First release: open62541 and Eclipse Milo reference adapters, each as a server
and a client behind one command contract, serving one deterministic fixture.

### Added

- UA-TCP, OPC UA Binary, SecureChannel None, anonymous sessions.
- GetEndpoints, Browse, Read, Write, Call, CreateSubscription,
  CreateMonitoredItems, Publish.
- Baseline fixture with scalar types, methods and dynamic values; cross-stack
  smoke test.
