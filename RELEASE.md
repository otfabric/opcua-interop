# opcua-interop Releases

## How a release is made

1. `make ci` on the commit to release (validates fixtures, builds the adapter images,
   runs the adapter unit tests, the single-adapter, cross-stack and PubSub
   smoke tests and the graceful-shutdown checks). The `CI` workflow runs
   the same gate on every push and pull request.
2. Set the version everywhere it is reported — `make check-release
   VERSION=vX.Y.Z` lists what does not match:
   - `open62541/src/main.c` (`adapter.version`)
   - `milo/src/main/java/io/otfabric/opcuainterop/CapabilitiesCommand.java`
     (`adapter.version`)
   - `milo/src/main/java/io/otfabric/opcuainterop/ServerCommand.java`
     (`BuildInfo` software version)
   - `async-opcua/src/common.rs` (`ADAPTER_VERSION`) and
     `async-opcua/Cargo.toml` (crate `version`)
   - `dotnet/src/Capabilities.cs` (`AdapterVersion`, also the server's
     `BuildInfo` software version)
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
   - builds the adapter images natively on an amd64 and an arm64 runner, runs the
     adapter unit tests, the smoke tests (single-adapter, cross-stack, PubSub)
     and the shutdown checks on exactly those images, and pushes them as
     `<image>:vX.Y.Z-amd64` / `-arm64`,
   - joins them into the multi-arch `<image>:vX.Y.Z`, `:vX.Y` and `:vX`,
   - creates the git tag `vX.Y.Z` on the released commit and the GitHub
     release with this file's section as notes, the image digests,
     `manifest.json` (upstream pins and digests) and `checksums.txt`.

   The tag is created last: a failed run leaves no tag, fix and run again.
5. Consumers pin the digests from the release (`manifest.json`). For go-opcua:
   update `defaultOpen62541Image` / `defaultMiloImage` (and, from v0.9.0,
   `defaultAsyncOpcuaImage` in `interop/asyncopcua_harness_test.go` and
   `defaultDotnetImage` in `interop/dotnet_harness_test.go`) in
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
`milo/pom.xml` (`milo.version`), `async-opcua/Cargo.toml` (`async-opcua =
"=X.Y.Z"`, with `Cargo.lock`), `dotnet/Dockerfile` (`ARG OPCUA_VERSION`, the
`OPCFoundation.NetStandard.Opc.Ua.*` NuGet version; `ARG DOTNET_SDK_VERSION` /
`DOTNET_RUNTIME_VERSION` for .NET), the MQTT broker `eclipse-mosquitto:2.0.22` by
digest (`Makefile`, `compose.yaml`, `scripts/pubsub-smoke.sh`).

---

## v0.15.0

**Date:** 2026-10-25
**Previous release:** v0.14.0

### Summary

The node-opcua adapter's `client push` reaches the rest of Part 12 1.05 push management, a new `client query` runs the Query service set, and the node-opcua alarm fixture gains condition branches and an audible sound.

### Added

- **node-opcua `client push`** (CLIENT_CONTRACT.md §1 "push flags", §4 `push`, §15):
  - `--group Application|Https|UserToken` and `--certificate-type-id` select the certificate group and type (clientFeatures `push-groups`).
  - `--get-certificates`, `--create-self-signed` (`--subject`, `--dns`, `--ip`, `--lifetime-days`, `--key-size`), `--delete-certificate`, `--update-certificate` with `--update-private-key` (PEM or PFX, `--private-key-format`) and `--issuer-certificate`, `--reset-to-defaults` and `--cancel` (clientFeatures `push-certificates`). Without `--apply`, a created or deleted certificate is cancelled with CancelChanges on the same session.
  - `--transaction-diagnostics` reads ServerConfiguration.TransactionDiagnostics after ApplyChanges (clientFeatures `push-transaction-diagnostics`).
  - The result gains `certificateGroupId` and a status and values for each new step; the existing keys are unchanged.
- **`client query`, node-opcua** (clientOperations `query`, §1 "query flags", §4 `query`): QueryFirst for one NodeTypeDescription. `--data-to-return` takes a Part 4 Annex A.2 relative path plus `#<attribute>`; `--max-data-sets` and `--max-references` are also accepted. QueryNext then follows the continuation points, or releases the first one with `--release-continuation-point`.
- **node-opcua alarm fixture** (fixtures/baseline/README.md "Alarms"):
  - The method `s=Alarms.Clear` returns InteropAlarm to normal, and the stack keeps the unacknowledged state in a condition branch (serverFeatures `alarms-branches`). `s=Alarms.Reset` drops the branches.
  - InteropAlarm has AudibleEnabled and AudibleSound, an AudioVariableType with ListId (serverFeatures `alarms-audible`).
- `schemas/capabilities.schema.json`: the five new feature strings. `schemas/client-result.schema.json`: the operations `push` and `query`.

### Changed

- **node-opcua alarm fixture:** the Retain override of Confirm, which keeps an active alarm retained, now applies to the condition itself only. A confirmed branch is not retained, and node-opcua deletes it.

### Not supported

- The node-opcua server serves neither the Query service set nor the Part 12 1.05 methods that the new `push` flags call. The flags are for servers that implement them, such as go-opcua.

---

## v0.14.0

**Date:** 2026-10-25
**Previous release:** v0.13.0

### Summary

The GDS pull model (Part 12 §6 and §7.9): a new adapter, `dotnet-gds`, has a Global Discovery Server and a GDS pull client. It is built on UA-.NETStandard 1.5.378.182, whose GDS packages have no 2.0.x release.

### Added

- **dotnet-gds adapter** (image `ghcr.io/otfabric/opcua-interop-dotnet-gds`, compose port 4846), with every Opc.Ua.* package pinned to 1.5.378.182:
  - The server runs a GDS (serverFeatures `gds-pull`): Directory, CertificateDirectory, request approval and revocation.
  - The client has the pull operations (clientOperations `gds-pull`): register an application, StartSigningRequest, StartNewKeyPairRequest, FinishRequest, read the trust list, and revoke.
  - CLIENT_CONTRACT.md §16 lists the flags and results.
- **CI and release:** the adapter is built, smoke-tested and released with the others.

### Notes

- CLIENT_CONTRACT.md §16.3 records three behaviours of UA-.NETStandard 1.5.378:
  - The CRL of its ECC CA names sha256WithRSAEncryption inside the TBSCertList but ecdsa-with-SHA256 outside, which RFC 5280 §5.1.1.2 forbids.
  - Its GDS client reads a TrustList through the FileType methods of the type.
  - Its new key pairs come as PFX.

---

## v0.13.0

**Date:** 2026-10-25
**Previous release:** v0.12.0

### Summary

Certificate management by the Part 12 push model: the UA-.NETStandard, node-opcua and open62541 servers carry it (serverFeatures `push-management`), and the node-opcua client has a `push` command.

### Added

- **Push management (serverFeatures `push-management`) in the UA-.NETStandard, node-opcua and open62541 servers:** ServerConfiguration with the DefaultApplicationGroup TrustList, UpdateCertificate, CreateSigningRequest, GetRejectedList and ApplyChanges, for a SecurityAdmin session over SignAndEncrypt (open62541 checks no roles). CLIENT_CONTRACT.md §15 lists the flags, the results and how each stack behaves.
- **node-opcua `client push`:** `--add-certificate`, `--remove-certificate`, `--issuer`, `--csr` and `--apply` against a server's push interface.
- **UA-.NETStandard server:** fixture users get the well-known roles of their `roles`, SecurityAdmin among them.
- **open62541:** the image is built with `UA_ENABLE_GDS_PUSHMANAGEMENT`; `amalgam/fix_gds_amalgamation.py` renames two static functions that clash in the amalgamation.

### Not supported

- No push client for UA-.NETStandard (Gds.Client.Common has no 2.0.1 release), open62541 v1.5.9 (no push client API), Eclipse Milo, asyncua or async-opcua; Milo, asyncua and async-opcua servers do not declare `push-management`.

---

## v0.12.0

**Date:** 2026-10-25
**Previous release:** v0.11.0

### Summary

Alarms & Conditions (Part 9): every adapter client has the `alarms` operation, and the UA-.NETStandard, node-opcua and open62541 servers carry an alarm fixture.

### Added

- **`alarms` client operation, all six adapters:** subscribes to events of `--node`, runs ConditionRefresh and reports the retained conditions; `--condition-name`, `--acknowledge`, `--confirm`, `--add-comment`, `--disable` / `--enable` call the Part 9 methods with the condition's latest EventId. CLIENT_CONTRACT.md §1 describes the flags and the result.
- **Alarm fixture (serverFeatures `alarms`) in the UA-.NETStandard, node-opcua and open62541 servers:** an AlarmConditionType condition `s=Alarms.InteropAlarm` with ConfirmedState on the source `s=Alarms.Source`, and the method `s=Alarms.Reset` that makes it active, unacknowledged and enabled again (fixtures/baseline/README.md "Alarms").
- **open62541:** the image is built with `UA_ENABLE_SUBSCRIPTIONS_ALARMS_CONDITIONS` (experimental in 1.5.9), and `amalgam/fix_condition_refresh_args.py` patches v1.5.9's ConditionRefresh argument check to accept the SubscriptionId the Call service converts to IntegerId.

### Not supported

- Eclipse Milo 1.1.8 has no condition state machine, asyncua 2.1.0 has no Acknowledge / Confirm / AddComment / Enable / Disable handlers, and no async-opcua server fixture was attempted: those servers do not declare `alarms`.

---

## v0.11.0

**Date:** 2026-10-25
**Previous release:** v0.10.1

### Summary

The UA-.NETStandard adapter serves and dials the HTTPS (`opc.https`, Part 6 §7.4) and WebSocket (`opc.wss`, Part 6 §7.5) transports.

### Added

- **dotnet server:** `--https-port` and `--wss-port` open `opc.https` (https-uabinary) and `opc.wss` (wss-uasc-uabinary) listeners next to `opc.tcp`. Both need `--certificate` and `--private-key`. The capabilities list the server features `transport-https` and `transport-wss`, and the transports `opc.https` and `opc.wss`.
- **dotnet client:** an `--endpoint` of `opc.https://…` or `opc.wss://…` selects the endpoint with that transport profile (client features `transport-https`, `transport-wss`).
- CLIENT_CONTRACT.md §9, §11 and §13 describe the transports.

### Changed

- **dotnet:** the runtime image is `mcr.microsoft.com/dotnet/aspnet` (Kestrel hosts the HTTPS and WebSocket listeners), and it exposes 4840, 4843 and 4844.

---

## v0.10.1

**Date:** 2026-10-24
**Previous release:** v0.10.0

### Summary

Build dependency and base image updates; the command contract, the fixtures and the reference stack versions are unchanged.

### Changed

- **asyncua**: base image `python:3.15.0-slim-trixie` (was 3.14.9).
- **milo**: `maven-compiler-plugin` 3.16.0 (was 3.15.0), `jackson-databind` 2.22.4 (was 2.22.3).
- **node-opcua**: TypeScript 7.0.2 (was 5.9.3); the compiled output is unchanged.
- **async-opcua**: `base64` 0.23.1 (was 0.22.1).
- Dependabot keeps `@types/node` on the major of the Node.js runtime (24) instead of proposing newer type definitions than the runtime provides.

---

## v0.10.0

**Date:** 2026-10-24
**Previous release:** v0.9.0

### Summary

PubSub on the UA-.NETStandard adapter: the second reference stack with PubSub, after open62541, and the first one with chunked NetworkMessages and UADP discovery.

### Added

- **PubSub on the UA-.NETStandard adapter** (`dotnet/`): `server --pubsub-config` runs the Opc.Ua.PubSub runtime of UA-.NETStandard 2.0.1 (NuGet `OPCFoundation.NetStandard.Opc.Ua.PubSub`, `.PubSub.Udp`, `.PubSub.Mqtt`) from the same file as the open62541 adapter: PublishedDataItems read the fixture `PubSub.*` variables, TargetVariables write them. UDP unicast and multicast, MQTT (top-level `mqtt.protocolVersion` `"5.0"` (default), `"3.1.1"` or `"3.1"`; publishing needs 5.0), UADP and JSON, Variant / DataValue / RawData, Sign and SignAndEncrypt (PubSub-Aes128-CTR / -Aes256-CTR) with static keys, chunked NetworkMessages from the WriterGroup `MaxNetworkMessageSize`, and answers to UADP discovery probes (DataSetMetaData, DataSetWriterConfiguration) in the .NET layout. `serveSks` and `sksClient` are refused; there is no PublishSubscribe information model. Contract §14.13 lists the adaptations and limits.
- `codec pubsub-uadp-encode` / `-decode` / `pubsub-json-encode` / `-decode` on the dotnet adapter (stack coders; differences from open62541 in §14.13), and the client operation `pubsub-discover` (UADP discovery probe).
- `print-capabilities`: the dotnet adapter declares `pubsub` (`serverFeatures` `pubsub`, `clientFeatures` `codec-pubsub`); the schema gains `pubsub.mqttVersions`, `pubsub.chunking` and `pubsub.discovery`. `schemas/client-result.schema.json`: operation `pubsub-discover`.
- `make smoke-pubsub-dotnet` (part of `make smoke`) and the CI job `pubsub-dotnet`: `scripts/pubsub-smoke.sh` takes any adapter image and gains a `discovery` scenario.
- `docker run <dotnet image> test` checks the PubSub capabilities and re-encodes the §14.9 UADP example byte for byte.

### Fixed

- dotnet: UDP datagrams of the Opc.Ua.PubSub transport carried TTL 1 (the stack's `UdpTransportOptions.Ttl` also applies to unicast) and were dropped on the way to the Docker host; the adapter uses 64.

---

## v0.9.0

**Date:** 2026-10-24
**Previous release:** v0.8.2

### Added

- **async-opcua (Rust) adapter** (`async-opcua/`, image `ghcr.io/otfabric/opcua-interop-async-opcua`), on the [async-opcua](https://github.com/FreeOpcUa/async-opcua) crate 0.19.0 (pinned with `=` in `Cargo.toml` and `Cargo.lock`; RustCrypto, no OpenSSL; linux/amd64 and linux/arm64). Server mode with the baseline fixture: dynamic values, the six methods, events, raw HistoryRead with continuation points, AddNodes / DeleteNodes, DataChangeFilter (absolute and percent deadband, trigger), `--reverse-connect`, `--register-with`, ready file, SIGTERM → exit 0. Client operations `endpoints`, `find-servers`, `read`, `write`, `browse`, `translate`, `call`, `subscribe`, `subscription-lifecycle`, `event-subscribe`, `history-read`, `republish`, `transfer-subscriptions`, `register-nodes`, `node-management`, `register-server`, `find-servers-on-network`, with `--reverse-listen`, `--channel-lifetime-ms` and `--application-uri`. Security profiles declared: None, Basic256Sha256 (Sign, SignAndEncrypt), Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss (SignAndEncrypt); Anonymous and UserName tokens.
- Declared as not provided in `print-capabilities` and refused with exit 2: ECC security policies (none in async-opcua 0.19), the LDS / mDNS server (`--lds`, `--mdns-name`: the stack answers RegisterServer / FindServersOnNetwork with `BadServiceUnsupported`), PubSub (`--pubsub-config`, `pubsub.supported: false`) and `codec` (the stack's JSON Variant encoding is the 1.04 `Type` / `Body` form, its XML Variant encoding the NodeSet2 value form without the Part 6 `<Value>` element).
- The adapter's unit tests (`cargo test`) run in the image build; `docker run <image> test` checks every mounted fixture against what the server builds and the capabilities against the dispatched operations.
- Stack deviations found by the go-opcua suite and the cross-stack smoke are listed in `async-opcua/README.md`. One affects other stacks: over SecurityPolicy None async-opcua answers ActivateSession with a null ServerNonce, which the open62541 1.5.9 client rejects (`BadSecurityChecksFailed`); open62541 ↔ async-opcua is verified over secured channels.
- Test PKI: `async-opcua-server` / `async-opcua-client` identities. async-opcua trusts certificates by exact match only, so `async-opcua-server/pki/trusted/certs` lists the consumer and adapter client certificates; the other servers trust the async-opcua client certificate. `certs/generate.sh --add-async-opcua` adds them to an existing PKI.
- `make image-async-opcua`, `test-async-opcua`, `smoke-async-opcua`, `shutdown-async-opcua`, `run-async-opcua` (port 4842), `compose.yaml` service `async-opcua`; CI and Release build, test and publish the third image (manifest.json records the async-opcua pin). `scripts/smoke.sh async-opcua <image>`; `smoke.sh cross` takes the async-opcua image as an optional third argument and then also runs the open62541 and Milo clients against it, the async-opcua client against all three servers, and secured channels (Basic256Sha256, Aes128 / Aes256, UserName, untrusted certificate).
- `Upstream candidates` workflow: an async-opcua job compares the `Cargo.toml` pin with the latest crates.io release, builds the adapter at that release (Cargo.toml / Cargo.lock edited in the job checkout only) and runs the smoke; Dependabot covers the `async-opcua/` Dockerfile and the adapter's other crates (the `async-opcua` crate itself is ignored there, its pin is exact).
- `schemas/client-result.schema.json`: `adapter` may be `async-opcua`.
- **UA-.NETStandard (C#) adapter** (`dotnet/`, image `ghcr.io/otfabric/opcua-interop-dotnet`), on the OPC Foundation UA-.NETStandard stack 2.0.1 (NuGet `OPCFoundation.NetStandard.Opc.Ua.Server`, `.Client`, `.Configuration`) on .NET 10; multi-stage image (portable IL built on the build platform, no compilation under emulation for arm64; .NET runtime on Alpine as the non-root user `app`; linux/amd64 and linux/arm64). The same command contract as the open62541 and Milo adapters: `server`, the eighteen `client` operations, `codec`, `validate-fixture`, `print-capabilities`, `test`. The server serves the baseline fixture (all node classes, dynamic values, methods, events, raw history with continuation points, AnalogItems with EURange, AddNodes / DeleteNodes, DataChangeFilter with absolute and percent deadband), the RSA security profiles (Basic256Sha256 Sign / SignAndEncrypt, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss), Anonymous and UserName tokens, `--register-with` and the trust lists of `--pki-dir`. Monitored items are sampled at their revised sampling interval (the node manager uses the stack's sampling groups; event-driven reporting would send every value change). The client covers all eighteen operations, including `--channel-lifetime-ms`, DataChangeFilter deadbands, `register-server` / `find-servers-on-network` and `codec` JSON (compact and verbose) and XML.
- Declared as not provided in `print-capabilities`: reverse connect, ECC (2.0.1 refuses the test PKI's ECC certificates, which the RSA test CA issues), LDS / mDNS and PubSub (the stack has a PubSub runtime, the adapter does not wire it).
- `docker run <image> test` for the dotnet adapter: in-process checks of the capability document, literal parsing and the OPC UA Binary encodings it produces, and a binary round trip of every Variable value of the mounted fixture.
- Test PKI: `dotnet-server` / `dotnet-client` identities (RSA), trusted by the other server identities (async-opcua's by exact certificate) and trusting the other clients. `certs/generate.sh --add-dotnet` adds them to an existing PKI without regenerating the CA or the other certificates.
- `make image-dotnet`, `buildx-dotnet`, `test-dotnet`, `smoke-dotnet`, `smoke-cross-dotnet`, `shutdown-dotnet`, `run-dotnet` (port 4843), `compose.yaml` service `dotnet`; `image`, `test`, `smoke`, `shutdown`, `publish-*` and `digests` include the dotnet adapter. `scripts/smoke.sh dotnet <image>` and `scripts/smoke.sh cross-dotnet <dotnet> <open62541> <milo>`: the dotnet client against the open62541 and Milo servers, both reference clients against the dotnet server, and codec documents of each stack decoded by the other.
- CI builds the dotnet image once per run, runs its unit tests, smoke and shutdown check in the adapter matrix and the dotnet cross-stack smoke in its own job; on `main` it builds the arm64 image as well. The Release workflow builds, tests and publishes the dotnet image with the others (`manifest.json`: `images.dotnet`, `upstream.opcfoundation-uanetstandard`). The `Upstream candidates` workflow probes the latest NuGet release of the stack.
- `schemas/client-result.schema.json`: `adapter` may be `dotnet`.
- **node-opcua (TypeScript / Node.js) adapter** (`node-opcua/`, image `ghcr.io/otfabric/opcua-interop-node-opcua`), on [node-opcua](https://github.com/node-opcua/node-opcua) 2.187.12 (pinned exactly in `package.json` and `package-lock.json`, `npm ci`; Node.js 24.22.1 on Alpine 3.24, base image pinned by digest; linux/amd64 and linux/arm64). Server mode with the baseline fixture: dynamic values, the six methods, events, raw HistoryRead with continuation points, DataChangeFilter (absolute and percent deadband, trigger), `--reverse-connect`, `--register-with`, ready file, SIGTERM → exit 0. Client operations `endpoints`, `find-servers`, `read`, `write`, `browse`, `translate`, `call`, `subscribe`, `subscription-lifecycle`, `event-subscribe`, `history-read`, `republish`, `transfer-subscriptions`, `register-nodes`, `node-management`, `register-server`, `find-servers-on-network`, with `--reverse-listen`, `--channel-lifetime-ms` and `--application-uri`. Security profiles declared: None, Basic256Sha256 (Sign, SignAndEncrypt), Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss (SignAndEncrypt); Anonymous and UserName tokens. Trust is CA-based (`trusted/certs` and `trusted/crl`), like open62541 and Milo.
- Declared as not provided in `print-capabilities` and refused with exit 2: ECC security policies (none in node-opcua), the `node-management` server feature (the node-opcua server answers AddNodes / DeleteNodes with `BadServiceUnsupported`; the client operation is provided), the LDS / mDNS server (`--lds`, `--mdns-name`, `--mdns-capability`: node-opcua's LDS is a separate `OPCUADiscoveryServer` without the fixture address space), PubSub (`--pubsub-config`, `pubsub.supported: false`; node-opcua has no open-source PubSub) and `codec` (no Part 6 XML Variant encoding; the 1.05 JSON encoder `node-opcua-json` is not wired into the adapter).
- The adapter's unit tests (`npm test`, `node --test`) run in the image build; `docker run <image> test` builds the address space of every mounted fixture in a server that is not started and checks the capabilities against the dispatched operations. Stack deviations are listed in `node-opcua/README.md`. One affects other stacks: after a SecureChannel renewal the node-opcua server answers requests sent under the old token with that token, also after the client has moved to the new one; the open62541 1.5.9 client drops such a late response once the old token has expired and its subscription stalls (`smoke.sh cross` reports it as a known deviation).
- Test PKI: `node-opcua-server` / `node-opcua-client` identities; `certs/generate.sh --add-node-opcua` adds them to an existing PKI.
- `make image-node-opcua`, `test-node-opcua`, `smoke-node-opcua`, `shutdown-node-opcua`, `run-node-opcua` (port 4844), `compose.yaml` service `node-opcua`; CI and Release build, test and publish the fourth image (manifest.json records the node-opcua pin). `scripts/smoke.sh node-opcua <image>`; `smoke.sh cross` takes the node-opcua image as an optional fourth argument and then runs the open62541, Milo (and async-opcua) clients against it, the node-opcua client against the other servers, and secured channels (Basic256Sha256, Aes128 / Aes256, UserName, untrusted certificate).
- `Upstream candidates` workflow: a node-opcua job compares the `package.json` pin with the latest npm release, builds the adapter at that release (with the matching `node-opcua-types`, lockfile regenerated in the job checkout only) and runs the smoke; Dependabot covers the `node-opcua/` Dockerfile and the adapter's other npm packages (`node-opcua` and `node-opcua-*` are ignored there, their pins are exact).
- `schemas/client-result.schema.json`: `adapter` may be `node-opcua`.
- **opcua-asyncio (Python) adapter** (`asyncua/`, image `ghcr.io/otfabric/opcua-interop-asyncua`), on [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) (PyPI `asyncua` 2.1.0, hash-locked `requirements.txt`, wheels only) on CPython 3.14.9 (`python:3.14.9-slim-trixie`, pinned by digest; non-root, linux/amd64 and linux/arm64). Server and client implement the CLI contract with every client operation except `codec`, the RSA security profiles, Anonymous and UserName, and `--register-with`.
- Declared as not provided in `print-capabilities` and refused with exit 2: ECC security policies and reverse connect (neither exists in asyncua 2.1.0), `codec` (no Part 6 JSON / XML DataEncoding), the LDS / mDNS server options, and PubSub (`asyncua.pubsub` is experimental and not wired). The `deadband` / `percent-deadband` server features are not declared: asyncua compares the absolute deadband with the previous sample and accepts a percent deadband without applying it. Server node management is refused with `BadUserAccessDenied`, because asyncua serves it only to its Admin role, which also bypasses Write's AccessLevel checks.
- The adapter loads the test PKI itself (`*.crt` / `*.crl`, issuers as intermediates) and hands it to asyncua's CertificateValidator: asyncua's TrustStore reads only `*.der` / `*.pem` and has no issuer list. The unit tests (`unittest`) run in the image build; `docker run <image> test` checks every mounted fixture and the capabilities against the dispatched operations. The stack deviations found by the go-opcua suite and the cross-stack smoke are listed in `asyncua/README.md`, among them: TimestampsToReturn and IndexRange are ignored, Browse and HistoryRead return no continuation points, ModifySubscription / ModifyMonitoredItems / MonitoringMode Sampling are not applied, Republish of an unknown message answers Good, and TransferSubscriptions checks no identity.
- Test PKI: `asyncua-server` / `asyncua-client` identities (RSA), trusted by the other server identities (async-opcua's by exact certificate) and trusting the other clients; `certs/generate.sh --add-asyncua` adds them to an existing PKI without regenerating the CA.
- `make image-asyncua`, `buildx-asyncua`, `test-asyncua`, `smoke-asyncua`, `smoke-cross-asyncua`, `shutdown-asyncua`, `run-asyncua` (port 4845), `compose.yaml` service `asyncua`. CI and Release build, test and publish the sixth image (manifest.json records the opcua-asyncio pin). `scripts/smoke.sh asyncua` / `cross-asyncua` cover the asyncua client and server against open62541 and Milo (and async-opcua / dotnet when given), with secured channels, untrusted certificates and LDS registration.
- `Upstream candidates` workflow: an asyncua job compares the `requirements.in` pin with the latest PyPI release, builds the adapter at that release and runs the smoke. Dependabot covers the `asyncua/` Dockerfile and pip dependencies (except `asyncua` itself).
- `schemas/client-result.schema.json`: `adapter` may be `asyncua`.

### Changed

- **Milo adapter:** the server no longer applies Milo's per-address connection rate limit (`Stack.ConnectionLimits`: at most 4 connection attempts per second per remote address). Test clients reach the server through the Docker gateway, all from one address; the async-opcua client, which opens GetEndpoints and the session on separate connections, had connections closed before the Acknowledge.
- All adapters report `0.9.0` (`print-capabilities` → `adapter.version`, the servers' BuildInfo); `scripts/check-release.sh` checks the async-opcua and dotnet adapters too.

### Docs

- README: the async-opcua and UA-.NETStandard stacks in the reference-stack and feature tables, the images, make targets, test PKI and test directions.
- README, `certs/README.md` and CLIENT_CONTRACT: the opcua-asyncio adapter (feature-table column, image, make targets, PKI identities and trust, `--application-uri`).
- CLIENT_CONTRACT §4: the UA-.NETStandard column of the codec stack limits. Its XmlDecoder reads namespace-qualified elements only, so the open62541 XML documents (no namespace) fail with `BadDecodingError`; the cross-stack smoke checks exactly that instead of a round trip.

---

## v0.8.2

**Date:** 2026-10-24
**Previous release:** v0.8.1

### Fixed

- **open62541 adapter, PubSub error recovery:** open62541 puts a WriterGroup and its PubSubConnection into Error when a send fails (an MQTT publish before the broker has accepted the connection) and leaves them there, so a publisher started just before its broker was ready published nothing for good. This made the go-opcua `mqtt-json` interop test fail intermittently. The adapter now re-enables a connection, WriterGroup or ReaderGroup that its configuration enabled and that is in Error, also when a re-enable itself fails (Error to Error reports no state change). The first retry comes after 200 ms, then the delay doubles up to 5 s and only starts over after 10 s without an error. Components disabled on purpose, through the information model, are left alone.
- **open62541 adapter, crash when the MQTT broker refuses connections:** open62541 v1.5.9 double-frees an MQTT topic connection when its broker connection drops while the topic connection is already shutting down (a refused or lost broker while a WriterGroup goes to Error); the server aborted with `double free or corruption`. The build applies the delayed-removal fix of upstream master (`open62541/amalgam/backport_mqtt_teardown.py`).

### Tests

- PubSub smoke scenario `mqtt-late-broker`: the publisher starts while the broker refuses connections (the name resolves, nothing listens), must enter Error without crashing, and must recover and deliver data to a subscriber once the real broker is up.

---

## v0.8.1

**Date:** 2026-10-24
**Previous release:** v0.8.0

### Changed

- **Milo adapter dependencies:** jackson-databind 2.17.2 → 2.22.3, logback-classic 1.5.6 → 1.6.5, slf4j-api 2.0.18 → 2.0.20, junit-jupiter 6.1.2 → 6.1.3, maven-surefire-plugin 3.3.1 → 3.6.0.

### Docs

- CLIENT_CONTRACT §14.6, open62541 information-model methods, corrected from the go-opcua interop tests: AddDataSetReader cannot target an existing variable (the reader's writes fail with `BadNodeIdUnknown`); a ReaderGroup added to a running connection receives nothing until the connection is disabled and enabled again; RemoveDataSetReader fails with `BadInternalError` while its ReaderGroup is enabled.

---

## v0.8.0


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
