# opcua-interop-otfabric

[go-opcua](https://github.com/otfabric/go-opcua), OT Fabric's own OPC UA stack,
behind the [container contract](../../docs/CONTAINER_CONTRACT.md), so that
other stacks can test against it. Unlike the images under `adapters/`, it is not
a reference: its tags are go-opcua versions, and no harness release or
`manifest.json` contains it.

**For testing only.** It has fixture users with fixture passwords and accepts
anonymous sessions and SecurityPolicy None. Do not expose it to a network you do
not control. Old images stay available, so check
[go-opcua advisories](https://github.com/otfabric/go-opcua/security/advisories)
for the version you pull.

**Not an independent implementation.** The image declares
`upstream.independentEngine: false`, and `results.json` records
`independent: false`. A result against it says nothing independent about go-opcua
when OT Fabric produces it. A result you publish, naming the implementation and
version, is independent evidence, and we would like to hear about it.

## Use

```sh
docker run -d --name go-opcua -p 127.0.0.1:4840:4840 ghcr.io/otfabric/opcua-interop-otfabric:<tag> \
  server --fixture /fixtures/baseline/fixture.json
until docker exec go-opcua test -f /run/opcua-interop/ready; do sleep 0.1; done
```

`<tag>` is a go-opcua version such as `v1.29.4`, or `latest`, the newest one
published. A rebuild of a version replaces its tag, so pin the digest if you need
an exact build. The digest is in the summary of the
[workflow run](https://github.com/otfabric/opcua-interop/actions/workflows/own-go-opcua.yml),
and `docker run --rm <image> version` prints the versions.

| | |
|---|---|
| Upstream | go-opcua, the latest release when the image was built |
| Licence | MIT; every module's licence is in the image under `/licenses` |
| Adapter name | `otfabric` |
| Language | Go |
| Protocol engine | OT Fabric's own |

## Why it is apart from the other adapters

Nothing under `adapters/`, `scripts/`, `tests/` or the top-level `Makefile` knows
the library under test: the scripts take the image from `ADAPTER_IMAGE_otfabric`
and recognise it by its capabilities. This directory and
`.github/workflows/own-go-opcua.yml` are the one exception.

No release loop can form (`otfabric/engineering` ADR-0012). This image is built
by hand, from the latest go-opcua release, and nothing is committed: this
repository has no pin of go-opcua to bump. No release or required check of
go-opcua needs the image, and go-opcua commits no pin of it. It is not in a
harness release or `manifest.json`.

## Publishing

Run the **Own stack (go-opcua)** workflow by hand, from `main`. It finds the
latest go-opcua release and the latest harness release, and prints them. It
builds the image, runs the two smoke modes on both architectures, then publishes
`:<go-opcua version>` and `:latest`. Run from a branch, it stops before
publishing. Nothing runs it automatically, so after a go-opcua release the image
stays on the old version until someone does.

```sh
make -f own/go-opcua/Makefile image smoke interop    # from the repository root
```

`smoke` is `scripts/smoke.sh otfabric`: the image against itself, unsecured and
secured. `interop` is `scripts/interop.sh otfabric <references>`, as in the other
interop repositories: each released reference against this image in both roles,
for the cases of `tests/cases.tsv`, then the secured path of
`tests/secure-cases.tsv`.

## What it covers

Every capability is declared in `print-capabilities` and exercised by
`scripts/smoke.sh` or `scripts/interop.sh`. Anything else reads as not declared and
never as a pass.

| Feature | Client | Server | Exercised with |
|---------|--------|--------|----------------|
| Discovery, read, write, browse, call, subscribe, register-nodes, channel renewal, deadbands | yes | yes | every reference, `tests/cases.tsv` |
| Raw history (`history-read`, continuation points) | yes | yes | every reference |
| Event history (`history-read-events`, `history-update-events`) | yes | yes | references with `history-events`, `history-events-update` |
| Events (`event-subscribe`, `--of-type`, `--min-severity`) | yes | yes | every reference |
| Alarms (`alarms`, the fixture of docs/FIXTURES.md) | yes | yes | open62541, dotnet, node-opcua servers; every client with `alarms` |
| ECC policies (nistP256, nistP384, brainpool, curve25519, curve448, AEAD), UserName over ECC | yes | yes | open62541 |
| X.509 user tokens | yes | yes | itself only: no reference declares them |
| Reverse connect | yes | yes | open62541, async-opcua, node-opcua |
| opc.https, opc.wss | yes | yes | dotnet |
| `codec` JSON, verbose JSON, XML | yes | - | open62541, milo, dotnet documents |
| Security None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss; Anonymous, UserName | yes | yes | every reference |

An image of a go-opcua version lacks what that version's adapter did not have when
it was built: read `print-capabilities`.

Flags only this image has: `--user-certificate`, `--user-private-key` (client, an
X.509 user token), `--ecc-dir` (server, one certificate per curve under
`<dir>/ecc-<curve>/`). Flags of the features left out are refused with exit code 2.

## Left out

The library has them, and the contract has no operation that would exercise them, so
they stay undeclared:

- HistoryUpdate of data values: `Server.SetHistorian` takes updates and
  `Client.HistoryUpdate` sends them, but the contract only updates events.
- Condition branches and other Part 9 features behind `alarms-branches`,
  `alarms-audible`, `alarms-105`: `AddCondition` takes them, and this fixture has
  no scenario that shows them.

Not part of this round, to follow: certificate management, GDS, PubSub.

## What it cannot do

Limits of the public API of go-opcua, or of this adapter:

- `--endpoint-path` is not advertised: `server.EndPoint` takes a host and a port.
  A path in the URL a client dials is accepted, and the ready file names it.
- `sequenceNumber` in a `subscribe` result is the position in the result, since
  go-opcua does not expose the number of the NotificationMessage.
- `history-read --timestamps` other than `Both` is refused with exit code 2:
  `Client.HistoryReadRawModified` always asks for both.
- The `--trust-list` of opc.https and opc.wss checks the chain, not the host name,
  as the contract asks (the test certificates name other hosts).
- The UserTokenPolicies of opc.https and opc.wss name no security policy. The dotnet
  client refuses to send a password on them: `own-token-policy-over-tls`.
- Revocation lists in the trust directories are not read.

The other deviations of the versions under test are in
[docs/COMPATIBILITY.md](../../docs/COMPATIBILITY.md).
