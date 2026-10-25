# async-opcua adapter (Rust)

opcua-interop adapter for [async-opcua](https://github.com/FreeOpcUa/async-opcua)
(crate `async-opcua` on crates.io, pinned `=0.19.0` in `Cargo.toml` and
`Cargo.lock`), the asynchronous Rust OPC UA client and server library of
FreeOpcUa. Added in opcua-interop **0.9.0**; it implements
`docs/CLIENT_CONTRACT.md` like the open62541 and Milo adapters.

Image: `ghcr.io/otfabric/opcua-interop-async-opcua:<version>`. Adapter name in
the result envelope, ready file and `print-capabilities`: `async-opcua`.

## Build and run

```sh
docker build -t ghcr.io/otfabric/opcua-interop-async-opcua:dev async-opcua/

# server with the baseline fixture
docker run --rm -p 4842:4840 -v "$PWD/fixtures:/fixtures:ro" \
  ghcr.io/otfabric/opcua-interop-async-opcua:dev \
  server --fixture /fixtures/baseline/fixture.json

# client
docker run --rm --add-host=host.docker.internal:host-gateway \
  ghcr.io/otfabric/opcua-interop-async-opcua:dev \
  client read --endpoint opc.tcp://host.docker.internal:4842/opcua-interop \
  --node 'nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32'

docker run --rm ghcr.io/otfabric/opcua-interop-async-opcua:dev print-capabilities
```

Multi-stage Dockerfile: `rust:1.99.0-slim-bookworm` builds a release binary
(dependencies in their own cached layer, `cargo build --locked`; `cargo test`
must pass before the binary is built), the runtime
is `debian:bookworm-20261005-slim` with the single binary, user `opcua`
(uid 10001), `/run/opcua-interop` writable for the ready file. async-opcua
uses RustCrypto (no OpenSSL), so the same Dockerfile builds natively for
`linux/amd64` and `linux/arm64`.

Sources: `src/main.rs` (dispatch, logging to stderr), `server.rs` (server
mode, fixture node manager), `client.rs` (client operations), `discovery.rs`
(RegisterServer2 / RegisterServer / FindServersOnNetwork on a session-less
channel), `values.rs` / `nodeid.rs` (§6, §7, §12), `pki.rs` (certificates and
trust), `caps.rs` (`print-capabilities`), `fixture.rs`, `selftest.rs` (`test`),
`common.rs` (envelope, exit codes, `ADAPTER_VERSION`); `client/push.rs`,
`client/gds_pull.rs`, `client/query.rs` and `client/part12.rs` (method
calls and the TrustList file shared by push and gds-pull) for the operations
async-opcua has no client API for.

## What it provides

**Client operations:** `endpoints`, `find-servers`, `read` (`--index-range`,
`--timestamps`), `write`, `browse` (BrowseNext followed), `translate`, `call`,
`subscribe` (queue size, discard-oldest, timestamps, DataChangeFilter
deadband / trigger), `subscription-lifecycle` (`revise`, `publishing-mode`,
`monitoring-mode`, `delete`), `event-subscribe` (`--of-type`,
`--min-severity`), `history-read` (raw, continuation points,
`--scenario continue`), `republish`, `transfer-subscriptions`,
`register-nodes`, `node-management`, `register-server` (RegisterServer2 with
fallback), `find-servers-on-network`, `alarms`, and since 0.15.0:

- `push` (§1 "push flags", §15): the trust list of `--group`
  (OpenWithMasks / Read / Close of its TrustList), AddCertificate /
  RemoveCertificate, GetCertificates, CreateSelfSignedCertificate,
  DeleteCertificate, UpdateCertificate (PEM / PFX `--update-private-key`),
  CreateSigningRequest, GetRejectedList, ResetToServerDefaults, ApplyChanges
  / CancelChanges and TransactionDiagnostics. async-opcua 0.19 has no push
  client: every step is a plain Call on the standard NodeIds of
  ServerConfiguration and of the group's TrustList, on one session.
- `gds-pull` (§16.2): FindApplications / RegisterApplication,
  StartSigningRequest (a PKCS #10 request with a fresh RSA 2048 or ECC P-256
  key, RustCrypto `x509-cert` / `p256`) or StartNewKeyPairRequest,
  FinishRequest, GetCertificateGroups, GetTrustList and the TrustList read,
  GetCertificateStatus, RevokeCertificate / CheckRevocationStatus,
  UnregisterApplication: plain Calls on the GDS Directory; the adapter encodes
  and decodes ApplicationRecordDataType itself (a GDS-namespace type the stack
  does not know).
- `query` (§1 "query flags"): QueryFirst / QueryNext. The Session has no
  Query API; the requests are sent on the session's secure channel
  (`Session::channel().send`) with the session's request header.

**Client features:** `channel-lifetime`, `deadband`, `reverse-listen`
(also with security), `application-uri`, `register-server2`, `push-groups`,
`push-certificates`, `push-transaction-diagnostics` (0.15.0).

**Server:** the baseline fixture address space in namespace
`urn:otfabric:opcua-interop:model` (scalars, arrays incl. the 3×2 matrix,
access levels, DataValues, Diagnostics, Analog items with an `EURange`
property, PubSub folder), the fixture behaviours (counter, toggle, ramps,
fixed status), the six methods, a BaseEvent from `Events.Source` every 2 s
(Severity 500, Message `peer-event`, also notified on the Server object), raw
HistoryRead of `History.Temperature` with continuation points (paged per
`NumValuesPerNode`, released continuation points are invalid), AddNodes /
DeleteNodes of Variables and Objects in the interop namespace, the fixture
user (`test-user`) on every endpoint, `--reverse-connect`
(`--reverse-connect-interval-ms`), `--register-with`
(`--register-interval-ms`, unregistered on SIGTERM), ready file, SIGTERM →
exit 0.

**Server features:** `deadband`, `percent-deadband`, `reverse-connect`,
`register-with`, `node-management`.

**Security profiles** declared (verified on the client and the server side):
None/None, Basic256Sha256 Sign and SignAndEncrypt, Aes128_Sha256_RsaOaep and
Aes256_Sha256_RsaPss SignAndEncrypt — the RSA profiles of the baseline
fixture. The stack also implements Basic128Rsa15, Basic256 and the Sign mode
of the Aes policies; the adapter accepts those names but does not claim them.
The server offers the non-None profiles of the fixture when started with
`--certificate` / `--private-key`. User tokens: Anonymous,
UserName (encrypted per policy; plaintext over None like the other adapters).

## Not provided (declared, refused with exit 2)

| What | Why |
|---|---|
| ECC security policies (`ECC_*`), `--ecc-dir` | async-opcua 0.19 has no ECC `SecurityPolicy` (`--ecc-dir` is ignored with a warning, an `ECC_*` client policy is an input error) |
| `--lds`, `--mdns-name`, `--mdns-capability` | the async-opcua server answers RegisterServer, RegisterServer2 and FindServersOnNetwork with `BadServiceUnsupported` ("stub", `docs/compatibility.md`); no mDNS |
| `--pubsub-config`, `codec pubsub-*` | no PubSub (Part 14) in async-opcua 0.19; `print-capabilities` → `pubsub.supported: false` |
| `codec` | async-opcua's JSON encoding of a Variant is the 1.04 form (`{"Type":6,"Body":…}`, `async-opcua-types/src/variant/json.rs`), not the OPC UA 1.05 encoding the contract's `codec` specifies; its XML encoding of a Variant is the NodeSet2 value form (`<Variant><Int32>5</Int32></Variant>`, `async-opcua-types/src/variant/xml.rs`), without the `<Value>` element of Part 6 §5.3.1.17, and it does not decode the Part 6 form. Neither can be handed to another stack's decoder as the contract requires, so `codec` is not offered (not in `clientOperations`, exit 2) |
| `--advertised-port` ≠ bind port | the stack advertises the port it is bound to (a warning is logged) |

## PKI and trust

async-opcua keeps its own PKI layout (`own/cert.der`, `private/private.pem`,
`trusted/<CN> [<thumbprint>].der`, `rejected/`) and trusts a peer only when
that exact certificate is in `trusted/` — its `CertificateStore` does not
validate chains. The adapter maps the contract onto that:

- **Server:** `--certificate` / `--private-key` (PEM or DER) are installed in
  a private stack PKI; every certificate of `<pki-dir>/trusted/certs` is
  copied into the stack's trusted directory. A client certificate that is
  listed there is trusted; one that is only *signed* by a listed CA is
  rejected (`BadCertificateUntrusted`) — a stack limit. The test PKI of 0.9.0
  therefore lists the consumer and adapter client certificates in
  `async-opcua-server/pki/trusted/certs` (`certs/generate.sh`; an existing PKI
  gets the async-opcua identities with `certs/generate.sh --add-async-opcua`).
- **Client:** `--trust-list` is a list of trust anchors. Before the session
  is created the adapter validates the server certificate from the selected
  endpoint itself (exact match, or issued by a listed certificate with an RSA
  PKCS#1 v1.5 SHA-256 signature, within its validity period) and only then
  places it in the stack's trusted directory; otherwise the stack rejects it.
  Without `--trust-list` the server certificate is accepted (as Milo does).
  Hostname / ApplicationUri checks of the server certificate are off
  (`verify_server_certs(false)`), like the other adapter clients.

## Stack deviations found by the go-opcua interop suite

The go-opcua tests skip or log these with the reason; none is hidden.

| # | Deviation (async-opcua 0.19.0) | Where | go-opcua test |
|---|---|---|---|
| 1 | A Write of a String to an Int32 variable is accepted (`Good`, value replaced) instead of `BadTypeMismatch`: `validate_value_to_write` only rejects a mismatched scalar when it is a ByteString | `async-opcua-server/src/address_space/utils.rs` | `TestAsyncOpcuaServer_WriteTypeMismatch` (skip) |
| 2 | Browse of an unknown NodeId returns `Good` with no references instead of `BadNodeIdUnknown` | server browse | `TestAsyncOpcuaServer_InvalidNodeId/Browse` (skip) |
| 3 | No `EventQueueOverflowEventType` event when an event monitored item's queue overflows (oldest events are dropped silently) | `async-opcua-server/src/subscriptions/monitored_item.rs` | `TestAsyncOpcuaServer_EventQueueOverflow` (skip) |
| 4 | Under trigger `StatusValueTimestamp` a SourceTimestamp change is reported even inside an absolute / percent deadband (open62541 and Milo apply the deadband); Part 4 §7.22.2 leaves the combination open | `ParsedDataChangeFilter::is_changed`, `async-opcua-types/src/data_change.rs` | `TestAsyncOpcuaServer_DataChangeFilter` (logged, not asserted) |
| 5 | Percent deadband: a change of exactly the deadband is reported, because normalised values are subtracted (`0.56 - 0.46 = 0.10000000000000009 > 0.1`) | `Deadband::is_changed`, same file | `TestAsyncOpcuaServer_DataChangeFilter` percent subtest (logged) |
| 6 | A Write with a SourceTimestamp in the DataValue is accepted (`Good`) instead of `BadWriteNotSupported` (same as Milo) | server write | `TestAsyncOpcuaServer_WriteEncodingMask` (qualification, logged) |
| 7 | A percent deadband on a variable without EURange is rejected with `BadDeadbandFilterInvalid` (Part 4 names `BadMonitoredItemFilterUnsupported`; the suite accepts both) | `ParsedDataChangeFilter::parse` | `TestAsyncOpcuaServer_DataChangeFilter` |
| 8 | Certificates are trusted by exact match only (no CA chains) | `async-opcua-crypto/src/certificate_store.rs` | PKI layout above |
| 9 | Over SecurityPolicy None the ActivateSession response carries a null ServerNonce (`SecurityPolicy::random_nonce` returns null for None; Part 4 §5.6.3.2 asks for at least 32 bytes). The open62541 1.5.9 client rejects the session (`BadSecurityChecksFailed`); over a secured channel the nonce is 32 bytes and open62541 interoperates | `activate_session`, `async-opcua-server/src/session/manager.rs` | `scripts/smoke.sh cross` (`check_o62541_none_deviation`, `run_async_opcua_secure_cross`) |
| 10 | The client takes no certificate chain: `X509::from_der` rejects a DER certificate followed by more certificates ("trailing data"), which Part 6 §6.2.3 allows in a ServerCertificate / SenderCertificate. It parses the endpoint's ServerCertificate, the OpenSecureChannel SenderCertificate and the CreateSession ServerCertificate (and compares the last with the endpoint's byte for byte), so it cannot connect over Sign / SignAndEncrypt to a UA-.NETStandard 2.0.1 server (`dotnet`, `dotnet-gds`) whose certificate is CA-signed: that server sends the chain in the OpenSecureChannel response even with `--no-certificate-chain`. The adapter's own `--trust-list` check (`src/pki.rs` `validate_against`) validates the chain's first certificate since adapter 0.16.0 (0.15.0 logged `server certificate not trusted: … trailing data`); the stack still rejects the chain | `async-opcua-crypto/src/x509.rs:423-427`; `async-opcua-client/src/transport/channel.rs:342`, `async-opcua-core/src/comms/secure_channel.rs:794`, `async-opcua-client/src/session/services/session.rs:208-213` | CLIENT_CONTRACT.md §16.3 (not in the smoke) |

## Testing

```sh
make test-async-opcua       # image build runs `cargo test`; `test` checks the fixtures
make smoke-async-opcua      # single-adapter smoke
make shutdown-async-opcua   # SIGTERM → exit 0
make smoke-cross-stack      # with open62541 and Milo, both directions
```

The unit tests (`cargo test`, in `src/*.rs`, test certificates in
`testdata/pki/`) run while the image is built, so an image only exists when
they pass. `docker run <image> test` loads every `fixture.json` under the
mounted `/fixtures` (or `--fixture <path>`) and checks that the server can
build all of it (node classes, data types, initial values, method
behaviours, behaviour targets, security profiles), and that
`print-capabilities` declares exactly the client operations the adapter
dispatches.

The single-adapter smoke runs every check of `scripts/smoke.sh` except the
codec checks. `smoke.sh cross` runs the open62541 and Milo clients against the
async-opcua server and the async-opcua client against all three servers, plus
secured channels (Basic256Sha256, Aes128 / Aes256, UserName, an untrusted
certificate) on a Docker network. `go-opcua/interop` runs the adapter in both
directions with `ASYNC_OPCUA_IMAGE` (`asyncopcua_*_test.go`, ledger
`interop/testdata/ledger-async-opcua.json`).
