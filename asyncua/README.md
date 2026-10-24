# asyncua adapter (opcua-asyncio)

Third adapter of opcua-interop: [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio)
(PyPI `asyncua`) **2.1.0** on CPython **3.14.9** (`python:3.14.9-slim-trixie`),
adapter version **0.9.0**, image `ghcr.io/otfabric/opcua-interop-asyncua`.
It implements the same CLI contract as `open62541/` and `milo/`
(`docs/CLIENT_CONTRACT.md`): `server`, `client <subcmd>`, `print-capabilities`,
`validate-fixture`, `test`. Result envelopes carry `"adapter": "asyncua"`.

```
asyncua/
├── Dockerfile            # 2 stages: venv with the locked wheels → slim runtime, non-root (uid 10001)
├── requirements.in       # direct dependency: asyncua==2.1.0
├── requirements.txt      # lock with hashes (uv pip compile --universal --generate-hashes)
├── src/opcua_interop_asyncua/
│   ├── __main__.py       # subcommand dispatch
│   ├── server.py         # server mode: endpoints, security, PKI, users, ready file, --register-with
│   ├── fixture.py        # fixture → asyncua address space, behaviours, events, history
│   ├── methods.py        # fixture methods (Add, Multiply, Echo, NoArguments, MultipleOutputs, Fail)
│   ├── client.py         # client subcommands
│   ├── common.py         # envelope, status codes, NodeId / value encoding, literals
│   ├── capabilities.py   # print-capabilities
│   └── selftest.py       # `test`
├── WIRING.patch          # changes to shared files (Makefile, smoke.sh, CI, docs …)
└── README.md
```

Refreshing the lock (same Python as the image):

```sh
docker run --rm -v "$PWD:/w" -w /w python:3.14.9-slim-trixie sh -c \
  'pip install -q uv==0.9.5 && uv pip compile requirements.in --universal --python-version 3.14 --generate-hashes -o requirements.txt'
```

Every dependency is a pure-Python or manylinux/abi3 wheel (`--only-binary=:all:`),
so the image builds for linux/amd64 and linux/arm64 without a compiler.

## Capabilities

`print-capabilities` lists only what works:

| | |
|---|---|
| `clientOperations` | `endpoints`, `find-servers`, `read`, `write`, `browse`, `translate`, `call`, `subscribe`, `subscription-lifecycle`, `event-subscribe`, `history-read`, `republish`, `transfer-subscriptions`, `register-nodes`, `node-management`, `find-servers-on-network`, `register-server` — everything except `codec` |
| `clientFeatures` | `channel-lifetime`, `deadband` (the client sends DataChangeFilters), `register-server2` |
| `serverFeatures` | `register-with` |
| `securityProfiles` | None; Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss — Sign and SignAndEncrypt (the server offers the fixture's RSA profiles) |
| `userTokenTypes` | Anonymous, UserName |
| `pubsub` | `supported: false` |

Refused with exit 2 / `error.category: "input"` (never ignored):
`client codec`, `--reverse-listen` (and the reverse flags), ECC
`--security-policy` names; server `--reverse-connect`, `--lds`, `--mdns-name`,
`--mdns-capability`, `--pubsub-config`. `--ecc-dir` is accepted and ignored
with a warning (as Milo does).

### Not provided by asyncua 2.1.0

| Feature | Why |
|---|---|
| ECC security policies | `asyncua.crypto.security_policies` ends at the RSA policies |
| Reverse connect | no ReverseHello in the transports |
| `codec` (JSON / XML DataEncoding) | asyncua has the Binary encoding only (NodeSet2 XML import/export is not the Part 6 XML DataEncoding) |
| LDS / mDNS, FindServersOnNetwork | no mDNS; FindServersOnNetwork is not dispatched (the server answers `BadUserAccessDenied`, the request has no session) |
| PubSub | `asyncua.pubsub` (UADP over UDP) is marked experimental and has no JSON encoding, MQTT, security / SKS or JSON configuration loader; wiring it to `--pubsub-config` (a PubSubConfigurationDataType in OPC UA JSON) and `codec pubsub-*` would mean writing those parts in the adapter. Declared unsupported |
| Server `node-management` | AddNodes / DeleteNodes are only served to asyncua's `Admin` role, which also skips the AccessLevel check on Write. The adapter gives every session the `User` role (AccessLevel enforced), so AddNodes is refused (`BadUserAccessDenied`) |

## Server behaviour and deviations

The adapter does not patch asyncua. Where asyncua does not behave as OPC UA
specifies, the go-opcua suite records it (test skip with the reason, ledger
row `unsupported`) instead of the adapter hiding it:

| Area | asyncua 2.1.0 behaviour |
|---|---|
| Absolute deadband | compared with the previous *sample*, not the last reported value (`MonitoredItemService._is_deadband_exceeded`): a ramp of step 2 with deadband 10 is only reported at its reset. `deadband` not declared |
| Percent deadband | accepted on any node and ignored (logs "not implemented"); no `BadMonitoredItemFilterUnsupported` without EURange. `percent-deadband` not declared |
| ModifySubscription | requested values ignored, the create-time values are returned (source comment says so) |
| ModifyMonitoredItems | new ClientHandle not applied |
| MonitoringMode Sampling | still reports notifications |
| HistoryRead paging | `NumValuesPerNode` truncates without a ContinuationPoint (`HistoryDict`); ReleaseContinuationPoints ignored |
| Browse paging | `RequestedMaxReferencesPerNode` ignored: no ContinuationPoint, BrowseNext cannot be exercised |
| Read IndexRange | ignored (whole value returned, also for scalars) |
| Error codes | Write to an unknown node → `BadUserAccessDenied` (want `BadNodeIdUnknown`); Browse of an unknown node → `BadNodeIdInvalid` (want `BadNodeIdUnknown`) |
| Republish | unknown sequence number → Good with an empty NotificationMessage (want `BadMessageNotAvailable`) |
| CreateSubscription revision | `subscription-lifecycle --scenario revise` against the asyncua server: PublishingInterval 1 ms and LifetimeCount 5 < 3 × MaxKeepAliveCount are accepted unrevised |
| RegisterServer | IsOnline=false is stored like a registration (the server stays in FindServers) |
| Event queue | no EventQueueOverflowEventType |

Adapter-side code (application logic an asyncua server has to supply itself):

- **Access.WriteOnly**: asyncua's Read does not check `AccessLevel.CurrentRead`;
  the node is served by a value callback answering `BadNotReadable` and a
  setter that keeps written values.
- **Methods**: asyncua passes raw input Variants to the callback; the
  methods check count and types (`BadArgumentsMissing`, `BadTooManyArguments`,
  `BadInvalidArgument` + `BadTypeMismatch`).
- **History.Temperature**: the five fixed samples are stored in asyncua's own
  `HistoryDict` backend (no live historizing), so HistoryRead is asyncua's.
- **AnalogItems**: the EURange property is added by the adapter (asyncua
  AddNodes does not instantiate type children).
- **Discovery URLs**: `set_match_discovery_endpoint_url(False)` /
  `set_match_discovery_client_ip(False)`: endpoints advertise exactly
  `--advertised-host` / `--advertised-port` like the other adapters.

## Security and PKI

- PEM or DER certificates / keys (detected by content; asyncua itself goes by
  the file suffix).
- Server: the fixture's RSA `securityProfiles` get endpoints when
  `--certificate` / `--private-key` are given; ECC profiles are skipped with a
  log line. Client certificates are validated against `<pki-dir>/trusted/certs`
  + `issuers/certs` (CA chain, `*.crt` accepted), validity period, URI SAN =
  ApplicationUri and `trusted/crl`; rejected certificates are copied to
  `<pki-dir>/rejected/`. An untrusted client gets `BadCertificateUntrusted`
  at CreateSession.
- Client: ApplicationUri = URI SAN of `--certificate`; `--trust-list` files
  validate the server certificate (chain, validity, CRL).
- The test PKI has no asyncua identities yet: the go-opcua suite uses
  `milo-server` / `milo-client` for the asyncua server / client (same
  ApplicationUris). Adding `asyncua-server` / `asyncua-client` to
  `certs/generate.sh` is a possible follow-up.

## Local checks

```sh
docker build -t ghcr.io/otfabric/opcua-interop-asyncua:dev asyncua/
docker run --rm -v "$PWD/fixtures:/fixtures:ro" ghcr.io/otfabric/opcua-interop-asyncua:dev test
scripts/smoke.sh asyncua ghcr.io/otfabric/opcua-interop-asyncua:dev \
    ghcr.io/otfabric/opcua-interop-open62541:dev ghcr.io/otfabric/opcua-interop-milo:dev   # with WIRING.patch
scripts/shutdown-test.sh asyncua ghcr.io/otfabric/opcua-interop-asyncua:dev
```

The smoke `asyncua` mode (WIRING.patch) runs the self checks except
`check_deadband` / `check_codec_*`, then asyncua client → open62541 / Milo
server (with `check_deadband`) and open62541 / Milo client → asyncua server.
