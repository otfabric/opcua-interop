# asyncua adapter (opcua-asyncio, Python)

[opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) (PyPI `asyncua`)
**2.1.0** on CPython **3.14.9** (`python:3.14.9-slim-trixie`, pinned by
digest), adapter version **0.9.0**, image `ghcr.io/otfabric/opcua-interop-asyncua`.
It implements the CLI contract of `docs/CLIENT_CONTRACT.md` (`server`,
`client <subcmd>`, `print-capabilities`, `validate-fixture`, `test`); result
envelopes carry `"adapter": "asyncua"`.

```
asyncua/
├── Dockerfile            # venv with the locked wheels → slim runtime, non-root (uid 10001); runs the unit tests
├── requirements.in       # direct dependency: asyncua==2.1.0
├── requirements.txt      # lock with hashes (uv pip compile --universal --generate-hashes)
├── src/opcua_interop_asyncua/
│   ├── __main__.py       # subcommand dispatch
│   ├── server.py         # server mode: endpoints, security, users, ready file, --register-with
│   ├── fixture.py        # fixture → asyncua address space, behaviours, events, history
│   ├── methods.py        # fixture methods (Add, Multiply, Echo, NoArguments, MultipleOutputs, Fail)
│   ├── client.py         # client subcommands
│   ├── pki.py            # test PKI loading, chain / CRL validation on asyncua's validator
│   ├── common.py         # envelope, status codes, NodeId / value encoding
│   ├── capabilities.py   # print-capabilities
│   └── selftest.py       # `test`
├── tests/                # unittest suite (run during the image build)
└── testdata/             # fixture and test certificates (no private keys)
```

Every dependency is a pure-Python or manylinux / abi3 wheel
(`--only-binary=:all:`), so the image builds for linux/amd64 and linux/arm64
without a compiler. Refreshing the lock (same Python as the image):

```sh
docker run --rm -v "$PWD:/w" -w /w python:3.14.9-slim-trixie sh -c \
  'pip install -q uv==0.9.5 && uv pip compile requirements.in --universal --python-version 3.14 --generate-hashes -o requirements.txt'
```

## Build and run

```sh
make image-asyncua                     # ghcr.io/otfabric/opcua-interop-asyncua:dev
make run-asyncua                       # server with the baseline fixture on port 4845
docker run --rm ghcr.io/otfabric/opcua-interop-asyncua:dev print-capabilities
docker run --rm ghcr.io/otfabric/opcua-interop-asyncua:dev \
    client read --endpoint opc.tcp://host.docker.internal:4840 --node 'ns=0;i=2259'
```

## What it provides

`print-capabilities` lists only what works:

| | |
|---|---|
| `clientOperations` | `endpoints`, `find-servers`, `read`, `write`, `browse`, `translate`, `call`, `subscribe`, `subscription-lifecycle`, `event-subscribe`, `alarms`, `history-read`, `republish`, `transfer-subscriptions`, `register-nodes`, `node-management`, `find-servers-on-network`, `register-server`, `push` and `gds-pull` (since 0.15.0; everything except `codec` and `query`) |
| `clientFeatures` | `channel-lifetime`, `deadband` (the client sends DataChangeFilters), `application-uri`, `register-server2`; since 0.15.0 `push-groups`, `push-certificates`, `push-transaction-diagnostics` |
| `serverFeatures` | `register-with` (RegisterServer / RegisterServer2 with an LDS); no `alarms`: asyncua 2.1.0 answers ConditionRefresh (`asyncua/server/subscription_service.py` replays the condition events it was given) but implements no condition state machine (no Acknowledge / Confirm / AddComment / Enable / Disable handlers), so the server has no `Alarms.*` fixture |
| `securityProfiles` | None; Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss, Sign and SignAndEncrypt |
| `userTokenTypes` | Anonymous, UserName |
| `pubsub` | `supported: false` |

**`client push` and `client gds-pull` (0.15.0).** opcua-asyncio 2.1.0 has no
push certificate management client and no GDS client, so both commands are
built on its generic services (`src/opcua_interop_asyncua/push.py`):

- `push` (CLIENT_CONTRACT §1 "push flags", §15) calls the Part 12 §7.10
  methods on the standard NodeIds of ServerConfiguration (`i=12637`), with
  every flag of adapter 0.15.0 (`--group`, `--get-certificates`,
  `--create-self-signed`, `--delete-certificate`, `--update-certificate` with
  a PEM / PFX key, `--reset-to-defaults`, `--cancel`,
  `--transaction-diagnostics`). The group's TrustList is found by
  TranslateBrowsePath (`<group>/TrustList`) and read with OpenWithMasks /
  Read / Close; its content is decoded with asyncua's `TrustListDataType`.
- `gds-pull` (§16.2) calls the Directory methods of the GDS namespace
  `http://opcfoundation.org/UA/GDS/` (index looked up on the server). The
  ApplicationRecordDataType of RegisterApplication is encoded by hand
  (asyncua has no GDS types); the CSR is made with `cryptography` (RSA 2048
  or ECC P-256, URI SAN = `--app-uri`, DNS SAN `localhost`). ProductUri of
  the record: `urn:opcua-interop:asyncua`.

Neither is served by the asyncua server (no `push-management` or `gds-pull`
server feature); the commands are for servers that implement Part 12, such as
go-opcua.

The server serves the full baseline fixture. Some of it is adapter code,
because an asyncua server has to supply that logic itself:

- **Access.WriteOnly**: asyncua's Read does not check `AccessLevel.CurrentRead`,
  so a value callback answers `BadNotReadable` and a setter keeps the written values.
- **Methods**: asyncua passes the raw input Variants to the callback, so the
  methods check the count and types themselves (`BadArgumentsMissing`,
  `BadTooManyArguments`, `BadInvalidArgument` with `BadTypeMismatch`).
- **History.Temperature**: the five fixed samples sit in asyncua's own
  `HistoryDict` backend, so HistoryRead is asyncua's.
- **AnalogItems**: the adapter adds the EURange property, because asyncua's
  AddNodes does not instantiate type children.
- **Discovery URLs**: `set_match_discovery_endpoint_url(False)` and
  `set_match_discovery_client_ip(False)`, so endpoints advertise exactly
  `--advertised-host` / `--advertised-port`, as the other adapters do.

## Not provided (declared, refused with exit 2)

| What | Why |
|---|---|
| ECC security policies (`ECC_*`), `--ecc-dir` | `asyncua.crypto.security_policies` implements only the RSA policies. `--ecc-dir` is ignored with a warning (as Milo does), the fixture's ECC profiles are skipped, and an `ECC_*` client policy is an input error |
| Reverse connect (`--reverse-connect`, `--reverse-listen`) | asyncua has no ReverseHello in its transports |
| `query` | asyncua's client has no QueryFirst / QueryNext service calls |
| `codec` | asyncua has only the Binary encoding: there is no Part 6 JSON, and its NodeSet2 XML import / export is not the Part 6 XML DataEncoding |
| `--lds`, `--mdns-name`, `--mdns-capability`; FindServersOnNetwork on the server | asyncua has no mDNS and does not dispatch FindServersOnNetwork. The server does accept RegisterServer / RegisterServer2 (see deviation 13) |
| `--pubsub-config`, `codec pubsub-*` | `asyncua.pubsub` (UADP over UDP) is experimental and has no JSON encoding, MQTT, security / SKS or JSON configuration loader, so it is not wired to the adapter |
| Server node management (AddNodes / DeleteNodes / AddReferences / DeleteReferences) | asyncua serves these only to its `Admin` role, which also skips the AccessLevel check on Write. The adapter gives every session the `User` role (AccessLevel enforced), so they are refused with `BadUserAccessDenied`. The client operation `node-management` is provided |
| `deadband` / `percent-deadband` server features | see deviations 6 and 7 |

## PKI and trust

The test PKI has `asyncua-server` and `asyncua-client` identities, new in
v0.9.0 (`certs/generate.sh`, or `certs/generate.sh --add-asyncua` for an
existing PKI). The ApplicationUri of a certificate is the first URI of its
SubjectAlternativeName. Certificates and keys may be PEM or DER (detected by
content).

asyncua's own TrustStore reads only `*.der` / `*.pem` files, so it would skip
the PKI's `*.crt` certificates and `*.crl` lists. It also has no issuer list,
and cryptography cannot build an empty store, so a server with an empty trust
list would stop. `pki.py` loads the files itself and hands them to asyncua's
`CertificateValidator`:

- **Server:** a client certificate must chain to a certificate in
  `<pki-dir>/trusted/certs`, with `issuers/certs` as intermediates only. It is
  also checked for its validity period, URI SAN = ApplicationUri, and the CRLs
  in `trusted/crl` and `issuers/crl`. asyncua matches a revoked certificate by
  serial number. A rejected certificate is copied to `<pki-dir>/rejected/`
  (best effort), and the client gets `BadCertificateUntrusted` at CreateSession.
- **Client:** the `--trust-list` files (the CA or the server certificate) are
  the only trust anchors (chain, validity, revocation). Without `--trust-list`
  every server certificate is accepted (as Milo does).
  A ServerCertificate that is a chain (leaf, then issuers, as UA-.NETStandard
  2.0.1 servers send it) is reduced to its leaf before it is handed to
  `Client.set_security`, which reads its `server_certificate` as a single
  certificate (since 0.16.0; 0.15.0 failed with `ExtraData`,
  CLIENT_CONTRACT.md §16.3).
- **Browse view:** `client browse` sends the null ViewDescription (Part 4
  §7.45: ViewId null, Timestamp null, ViewVersion 0), with Timestamp set to
  `ua.get_win_epoch()` as asyncua's own `Node.get_references` does
  (`common/node.py:475`). asyncua 2.1.0's `ua.ViewDescription()` fills
  Timestamp with the current time (`ua/uaprotocol_auto.py`, also used as is by
  `Client.browse_nodes`, `client/client.py:1503`); a Timestamp without a
  ViewId names no view version, and UA-.NETStandard and async-opcua servers
  answer `BadViewTimestampInvalid`. Adapter 0.15.0 and earlier sent it so
  (open62541, Milo and asyncua servers ignore the Timestamp).

## Stack deviations found by the go-opcua interop suite

The adapter does not patch asyncua. Each deviation below is a go-opcua test
that skips with the reason (`asyncuaDeviation`), backed by an `unsupported` row
in `interop/testdata/ledger-asyncua.json`, or a smoke check that pins it. None
is hidden.

| # | Deviation (asyncua 2.1.0) | Where | Pinned by |
|---|---|---|---|
| 1 | TimestampsToReturn is ignored: Read and monitored items always return both timestamps | `asyncua/server` never reads it | `TestAsyncuaServer_TimestampsToReturn`, `TestAsyncuaServer_SubscribeTimestampsToReturn` |
| 2 | ReadValueId.IndexRange is ignored: on a scalar the answer is `Good` (want `BadIndexRangeInvalid` / `BadIndexRangeNoData`), and a subset returns the whole array | `AttributeService.read` | `TestAsyncuaServer_IndexRange`, `TestAsyncuaServer_IndexRangeSubset` |
| 3 | A Write that carries a SourceTimestamp is accepted (`Good`) instead of `BadWriteNotSupported`, as Milo, async-opcua and node-opcua do | server write | `TestAsyncuaServer_WriteEncodingMask` |
| 4 | Write to an unknown node answers `BadUserAccessDenied`, and Browse of an unknown node `BadNodeIdInvalid` (want `BadNodeIdUnknown`) | `AttributeService.write` checks the AccessLevel of the missing node first | `TestAsyncuaServer_InvalidNodeId`, `TestAsyncuaServer_BatchWrite` |
| 5 | Browse ignores RequestedMaxReferencesPerNode: there is never a ContinuationPoint, so BrowseNext and its release cannot be exercised | `ViewService.browse` | `TestAsyncuaServer_BrowseNext`, `TestAsyncuaServer_BrowseNextRelease` |
| 6 | The absolute deadband is compared with the previous *sample*, not the last reported value, so a slow ramp is reported only at its reset | `MonitoredItemService._is_deadband_exceeded` | `TestAsyncuaServer_DataChangeFilter` (deadband case) |
| 7 | A PercentDeadband is accepted on any node (also without EURange) and not applied | `MonitoredItemService` | smoke `check_asyncua_deadband_deviation` |
| 8 | No sampling: the RevisedSamplingInterval is the publishing interval and every write of the value is reported | `MonitoredItemService` | `TestAsyncuaServer_DataChangeFilter` (sampling-interval case) |
| 9 | MonitoringMode Sampling still reports notifications, so SetTriggering cannot be asserted either | `MonitoredItemService.datachange_callback` checks only for Disabled | `TestAsyncuaServer_SetMonitoringMode`, `TestAsyncuaServer_SetTriggering` |
| 10 | ModifySubscription ignores the requested values and returns the create-time ones; ModifyMonitoredItems does not apply a new ClientHandle | `SubscriptionService.modify_subscription`, `MonitoredItemService._modify_monitored_item` | `TestAsyncuaServer_ModifySubscription`, `TestAsyncuaServer_ModifyMonitoredItems` |
| 11 | HistoryRead with NumValuesPerNode truncates without a ContinuationPoint | `HistoryDict` | `TestAsyncuaServer_HistoryReadContinuation` |
| 12 | No EventQueueOverflowEventType when an event queue overflows: the oldest event is dropped silently | `InternalSubscription._enqueue_event` | `TestAsyncuaServer_EventQueueOverflow` |
| 13 | RegisterServer with IsOnline=false is stored like a registration, so the unregistered server stays in FindServers | `InternalServer.register_server` | `TestAsyncuaServer_DiscoveryServer` |
| 14 | Republish of a sequence number the server does not hold answers `Good` with an empty NotificationMessage (want `BadMessageNotAvailable`) | `InternalSubscription.republish` | `TestAsyncuaServer_ClientRepublish` |
| 15 | TransferSubscriptions checks no identity: a subscription of a user moves to an anonymous session (Part 4 §5.14.7 requires `BadUserAccessDenied`) | `SubscriptionService.transfer_subscriptions` | `TestAsyncuaServer_TransferSubscriptionsIdentity` |
| 16 | No server diagnostics: `ServerDiagnostics.EnabledFlag` has a null value, and ReturnDiagnostics yields no DiagnosticInfos | server | `TestAsyncuaServer_Diagnostics` |
| 17 | CreateSession revises MaxRequestMessageSize to 65536, so a request fits into one chunk and multi-chunk messages cannot be provoked | server | `TestAsyncuaServer_ChunkedSecureMessages` |
| 18 | `subscription-lifecycle --scenario revise`: a PublishingInterval of 1 ms and a LifetimeCount of 5 (< 3 × MaxKeepAliveCount) are accepted unrevised | `SubscriptionService.create_subscription` | not asserted (`subscription.lifecycle.revise` against the asyncua server is not-applicable in the ledger) |

The suite also found two go-opcua bugs, both fixed in go-opcua v1.8.1:

- A token replaced by `Renew` was renewed again from an already used sequence
  number. asyncua closes the channel on that, which open62541 and Milo tolerate.
- A Republish answered without the requested message rewound the subscription's
  sequence numbers (deviation 14).

go-opcua encodes an empty Go string as a null String, which the asyncua
client reads as `None`.

## Testing

```sh
make test-asyncua          # image build runs the unittest suite; `test` checks the fixtures
make smoke-asyncua         # single-adapter smoke
make shutdown-asyncua      # SIGTERM → exit 0
make smoke-cross-asyncua   # with open62541 and Milo (and async-opcua / dotnet), both directions
```

The unit tests (`tests/`, with certificates without private keys in
`testdata/pki/`) run while the image is built. `docker run <image> test` loads
every `fixture.json` under the mounted `/fixtures` (or `--fixture <path>`),
builds its address space, and checks that `print-capabilities` declares
exactly the client operations the adapter dispatches.

The single-adapter smoke runs every check of `scripts/smoke.sh` except the
codec checks; `check_deadband` is replaced by `check_asyncua_deadband_deviation`
(deviation 7). `smoke.sh cross-asyncua` runs the
asyncua client against the open62541 and Milo servers and their clients
against the asyncua server. It adds secured channels on a Docker network
(Basic256Sha256 SignAndEncrypt, Sign with UserName, Basic256, Aes128 / Aes256,
untrusted certificates in both directions) and registration with an
open62541 LDS (`--register-with`, find-servers-on-network, RegisterServer2).
`go-opcua/interop` runs the adapter in both directions with `ASYNCUA_IMAGE`
(`asyncua_*_test.go`, ledger `interop/testdata/ledger-asyncua.json`).
