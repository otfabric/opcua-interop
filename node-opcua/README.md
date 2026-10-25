# node-opcua adapter (TypeScript / Node.js)

opcua-interop adapter for [node-opcua](https://github.com/node-opcua/node-opcua)
(npm package `node-opcua`, pinned exactly to `2.187.12` in `package.json` and
`package-lock.json`, with `node-opcua-types` `2.187.9`, the version
node-opcua itself depends on), the OPC UA client and server SDK for Node.js
by Sterfive. Added in opcua-interop **0.9.0**; it implements
`docs/CLIENT_CONTRACT.md` like the open62541, Milo and async-opcua adapters.

Image: `ghcr.io/otfabric/opcua-interop-node-opcua:<version>`. Adapter name in
the result envelope, ready file and `print-capabilities`: `node-opcua`.

## Build and run

```sh
docker build -t ghcr.io/otfabric/opcua-interop-node-opcua:dev node-opcua/

# server with the baseline fixture
docker run --rm -p 4844:4840 -v "$PWD/fixtures:/fixtures:ro" \
  ghcr.io/otfabric/opcua-interop-node-opcua:dev \
  server --fixture /fixtures/baseline/fixture.json

# client
docker run --rm --add-host=host.docker.internal:host-gateway \
  ghcr.io/otfabric/opcua-interop-node-opcua:dev \
  client read --endpoint opc.tcp://host.docker.internal:4844/opcua-interop \
  --node 'nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32'

docker run --rm ghcr.io/otfabric/opcua-interop-node-opcua:dev print-capabilities
```

Multi-stage Dockerfile on `node:24.22.1-alpine3.24` (pinned by its
multi-arch index digest): the build stage runs `npm ci`, compiles the
TypeScript (`tsc`) and runs the unit tests (`npm test`); the image is only
produced when they pass. A second stage installs the production dependencies
only (`npm ci --omit=dev`). The runtime has the compiled adapter and
`node_modules`, no npm / corepack / yarn, runs as the image's `node` user
(uid 1000) with `/run/opcua-interop` writable for the ready file and the
default PKI. node-opcua is pure JavaScript on Node.js' OpenSSL crypto, so the
same Dockerfile builds natively for `linux/amd64` and `linux/arm64`.

Sources: `src/main.ts` (dispatch, logging to stderr), `server.ts` (server
mode, fixture address space, PKI), `client.ts` (client operations),
`util.ts` (envelope, exit codes, NodeId and value encoding of §6, §7, §12,
`ADAPTER_VERSION`), `capabilities.ts` (`print-capabilities`), `fixture.ts`,
`selftest.ts` (`test`); unit tests in `src/*.test.ts`.

## What it provides

**Client operations:** `endpoints`, `find-servers`, `read` (`--index-range`,
`--timestamps`), `write`, `browse` (BrowseNext followed), `translate`, `call`,
`subscribe` (queue size, discard-oldest, timestamps, DataChangeFilter
deadband / trigger), `subscription-lifecycle` (`revise`, `publishing-mode`,
`monitoring-mode`, `delete`), `event-subscribe` (`--of-type`,
`--min-severity`), `history-read` (raw, continuation points,
`--scenario continue`), `republish`, `transfer-subscriptions`,
`register-nodes`, `node-management`, `register-server` (RegisterServer2 with
fallback), `find-servers-on-network`, `alarms` (ConditionRefresh on
ConditionType with the RefreshStart / RefreshEnd bracket, then Acknowledge /
Confirm / AddComment of a condition, each followed by its event; contract §1 /
§4 `alarms`).

**Client features:** `channel-lifetime`, `deadband`, `reverse-listen`
(also with security), `application-uri`, `register-server2`.

**Server:** the baseline fixture address space in namespace
`urn:otfabric:opcua-interop:model` (scalars, arrays incl. the 3×2 matrix,
access levels, DataValues, Diagnostics, Analog items with an `EURange`
property, PubSub folder), the fixture behaviours (counter, toggle, ramps,
fixed status), the six methods, a BaseEvent from `Events.Source` every 2 s
(Severity 500, Message `peer-event`, also notified on the Server object), raw
HistoryRead of `History.Temperature` with continuation points, the fixture
user (`test-user`), `--reverse-connect` (`--reverse-connect-interval-ms`),
`--register-with` (`--register-interval-ms`, unregistered on SIGTERM), ready
file, SIGTERM → exit 0.

**Alarms & Conditions** (`src/alarms.ts`, serverFeatures `alarms`, built in
code, not from `fixture.json`): folder `s=Alarms` (Organizes from
`s=Compatibility`), notifier `s=Alarms.Source` (EventNotifier
SubscribeToEvents, `Server --HasEventSource--> Alarms.Source`), the condition
`s=Alarms.InteropAlarm` of **AlarmConditionType** with the optional
**ConfirmedState** / Confirm (ConditionName `InteropAlarm`, SourceName
`Alarms.Source`, HasCondition from the source, InputNode null), armed at start
(Enabled, Active, unacknowledged, unconfirmed, Retain, Severity 500, Message
`interop-alarm`), and the method `s=Alarms.Reset` (HasComponent of
`Alarms.Source`, no arguments) that re-arms it with a new event.
Acknowledge, Confirm, AddComment, Enable, Disable, ConditionRefresh and
ConditionRefresh2 are node-opcua's own handlers
(`addressSpace.installAlarmsAndConditionsService()`). Two stack behaviours are
overridden on the fixture alarm: Confirm keeps Retain true while the alarm is
Active (node-opcua sets it false, deviation 7), and Enable does not throw
(deviation 8).

**Server features:** `deadband`, `percent-deadband`, `reverse-connect`,
`register-with`, `alarms`.

**Security profiles** declared (verified on the client and the server side):
None/None, Basic256Sha256 Sign and SignAndEncrypt, Aes128_Sha256_RsaOaep and
Aes256_Sha256_RsaPss SignAndEncrypt — the RSA profiles of the baseline
fixture. The stack also implements Basic128Rsa15 and Basic256; the adapter
accepts those names but does not claim them. The server offers the non-None
profiles of the fixture when started with `--certificate` / `--private-key`.
User tokens: Anonymous, UserName (see deviation 4 for UserName over None).

## Not provided (declared, refused with exit 2)

| What | Why |
|---|---|
| ECC security policies (`ECC_*`), `--ecc-dir` | node-opcua 2.187 implements the RSA policies only (`--ecc-dir` is ignored with a warning, the fixture's ECC profiles are skipped, an `ECC_*` client policy is an input error) |
| AddNodes / DeleteNodes on the server (`node-management` server feature) | `OPCUAServer` answers AddNodes, DeleteNodes, AddReferences and DeleteReferences with `BadServiceUnsupported` (`node-opcua-server/dist/opcua_server.js`); the client operation `node-management` is provided |
| `--lds`, `--lds-cleanup-timeout`, `--mdns-name`, `--mdns-capability` | `OPCUAServer` is no discovery server: it answers RegisterServer, RegisterServer2 and FindServersOnNetwork with `BadServiceUnsupported`. node-opcua's LDS (and its mDNS) is the separate `OPCUADiscoveryServer` application, which has no fixture address space; it is not wired into this adapter |
| `--pubsub-config`, `codec pubsub-*` | node-opcua has no open-source PubSub (Part 14; PubSub is a commercial add-on); `print-capabilities` → `pubsub.supported: false` |
| `codec` | node-opcua has no Part 6 XML encoding of a Variant / DataValue, and its OPC UA 1.05 JSON encoder (`node-opcua-json`) is not wired into the adapter; `codec` is not in `clientOperations` (exit 2) |

## PKI and trust

node-opcua's `OPCUACertificateManager` keeps the usual layout
(`own/`, `trusted/certs`, `trusted/crl`, `issuers/certs`, `issuers/crl`,
`rejected/`) and validates a peer certificate as a chain: a certificate
issued by a CA in `trusted/certs` is trusted when the CA's CRL is in
`trusted/crl` — like open62541 and Milo, unlike async-opcua's exact-match
store. No per-certificate copies are needed.

- **Server:** `--certificate` / `--private-key` (PEM or DER; node-opcua reads
  PEM, so DER inputs are converted into a private work directory) and
  `--pki-dir`. A read-only `--pki-dir` is copied into a writable temporary
  directory first (node-opcua writes rejected certificates and lock files).
  The `node-opcua-server` identity of the test PKI is new in 0.9.0
  (`certs/generate.sh`, or `certs/generate.sh --add-node-opcua` for an
  existing PKI).
- **Client:** `--trust-list` certificates are the only trust anchors
  (`trusted/certs` of a private client PKI). Without `--trust-list` every
  server certificate is accepted (as Milo does).

## Stack deviations found by the go-opcua interop suite

The go-opcua tests and the cross-stack smoke skip or log these with the reason; none is hidden.

| # | Deviation (node-opcua 2.187.12) | Where | go-opcua test |
|---|---|---|---|
| 1 | A Read with IndexRange `0:1` of a scalar Value returns `Good` with the scalar instead of `BadIndexRangeNoData` (Part 4 §7.27); array subsets are correct | server read | `TestNodeOpcuaServer_IndexRange` (skip), `TestNodeOpcuaServer_IndexRangeSubset` |
| 2 | The queue size of an event monitored item is revised to at least 100 (`minimumEventQueueSize`, default 1000), so a small event queue cannot be requested and its overflow (`EventQueueOverflowEventType`) cannot be provoked at the fixture's event rate | `node-opcua-server/dist/monitored_item.js` (`_adjust_event_queue_size`) | `TestNodeOpcuaServer_EventQueueOverflow` (skip) |
| 3 | A Write with a SourceTimestamp in the DataValue is accepted (`Good`) instead of `BadWriteNotSupported` (as Milo and async-opcua) | server write | `TestNodeOpcuaServer_WriteEncodingMask` (logged) |
| 4 | UserName is offered on the None endpoint only with an encrypted password (a token policy with a SecurityPolicy URI); `allowUnsecurePassword` is not honoured. The adapter adds the Basic256Sha256 and Aes128 token policies to the None endpoint so the fixture user can log on over None | server endpoints | username tests over None |
| 5 | The server's `RegisterServerManager` registers only over an LDS endpoint that carries a server certificate (it picks the most secure endpoint); against an LDS with a None-only endpoint it never registers. A failed registration is not reported: errors are only logged when the state changed meanwhile, and the manager goes to `REGISTERED` | `node-opcua-server/dist/register_server_manager.js` | `TestGoLDS_NodeOpcuaServerRegisters` (secured LDS variant) |
| 6 | After a SecureChannel renewal the server keeps securing each response with the token of its request (`ServerSecureChannelLayer` `send_response`), so a Publish request sent before the renewal is answered under the old token after the client has switched to the new one; Part 6 §6.7.4 has the server switch once it receives a message with the new token. The open62541 1.5.9 client drops such a response once the old token's lifetime has passed (`SecurityToken timed out`) and its subscription stalls; the go-opcua, Milo, async-opcua and node-opcua clients continue | `node-opcua-secure-channel/dist/source/server/server_secure_channel_layer.js` | `scripts/smoke.sh cross` (`check_o62541_node_renewal_deviation`) |
| 7 | Confirm sets Retain to false also while the alarm is still Active (Part 9 §5.5.2: an active Condition stays of interest); the adapter keeps Retain true while ActiveState is true | `node-opcua-address-space/dist/impl/alarms_and_conditions/ua_acknowledgeable_condition_impl.js` (`_confirm_branch`) | fixed in the adapter |
| 8 | Enable (after Disable) of an AlarmConditionType instance without an input to evaluate throws `Unimplemented, please override` (Call → `BadInternalError`) | `ua_condition_impl.js` (`evaluateConditionsAfterEnabled`) | fixed in the adapter |
| 9 | The RefreshStartEvent / RefreshEndEvent of ConditionRefresh are raised on the Server object only: an event item on another notifier (e.g. `s=Alarms.Source`) gets the refreshed conditions but no bracket, so `client alarms --node` other than `i=2253` times out waiting for RefreshEnd | `ua_condition_impl.js` (`_perform_condition_refresh`) | use `--node i=2253` |
| 10 | A repeated Acknowledge with the now stale EventId is answered `Bad_EventIdUnknown` (the EventId changes with every condition event); an Acknowledge of an already acknowledged branch with its current EventId is answered `Good` (the `Bad_ConditionBranchAlreadyAcked` of `_setAckedState` is dropped by `_acknowledge_method`) | `ua_acknowledgeable_condition_impl.js` | logged |

## Testing

```sh
make test-node-opcua       # image build runs `npm test`; `test` checks the fixtures
make smoke-node-opcua      # single-adapter smoke
make shutdown-node-opcua   # SIGTERM → exit 0
make smoke-cross-stack     # with open62541, Milo (and async-opcua), both directions
```

The unit tests (`node --test`, `src/*.test.ts`, test certificates without
private keys in `testdata/pki/`) run while the image is built.
`docker run <image> test` loads every `fixture.json` under the mounted
`/fixtures` (or `--fixture <path>`), builds its address space in a node-opcua
server that is initialised but not started (node classes, data types,
initial values, method behaviours, behaviour targets, security profiles,
history), and checks that `print-capabilities` declares exactly the client
operations the adapter dispatches.

The single-adapter smoke runs every check of `scripts/smoke.sh` except the
codec checks. `smoke.sh cross` runs the open62541 and Milo (and, when given,
async-opcua) clients against the node-opcua server and the node-opcua client
against the other servers, plus secured channels (Basic256Sha256, Aes128 /
Aes256, UserName, an untrusted certificate) on a Docker network.
`go-opcua/interop` runs the adapter in both directions with
`NODE_OPCUA_IMAGE` (`nodeopcua_*_test.go`, ledger
`interop/testdata/ledger-node-opcua.json`).
