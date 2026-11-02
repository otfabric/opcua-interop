# Compatibility

Which upstream versions the adapters are built on, what the reference stacks
were verified to do against each other, and what was found on the way.

Everything here is about the reference stacks. It makes no statement about
any library that consumes the images.

## Pinned upstreams

The rule is the latest upstream release, also when it has a bug: the bug is
listed in [tests/known-bugs.tsv](../tests/known-bugs.tsv) and described
below, and the cases it explains count as known differences instead of failures.

| Adapter | Upstream | Pinned | Pin | Engine |
|---------|----------|--------|-----|--------|
| `open62541` | [open62541](https://github.com/open62541/open62541) | v1.5.9 | commit in `adapters/open62541/Dockerfile` | independent, C |
| `milo` | [Eclipse Milo](https://github.com/eclipse-milo/milo) | 1.1.8 | Maven Central, `adapters/milo/pom.xml` | independent, Java |
| `async-opcua` | [async-opcua](https://github.com/FreeOpcUa/async-opcua) | 0.19.0 | crates.io, `adapters/async-opcua/Cargo.lock` | independent, Rust |
| `dotnet` | [UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard) | 2.0.1 | NuGet, `adapters/dotnet/src/*.csproj` | independent, C# |
| `dotnet-gds` | the same, GDS packages | 2.0.1 | NuGet, `adapters/dotnet-gds/src/*.csproj` | the engine of `dotnet` |
| `node-opcua` | [node-opcua](https://github.com/node-opcua/node-opcua) | 2.187.12 | npm, `adapters/node-opcua/package-lock.json` | independent, TypeScript |
| `asyncua` | [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) | 2.1.0 | PyPI, hashed `adapters/asyncua/requirements.txt` | independent, Python |

The pins live in the build files and are mirrored in
[versions.yaml](../versions.yaml); `scripts/check-versions.sh` keeps them in
step. The **Upstream** workflow (`.github/workflows/upstream.yml`, daily and on
demand) resolves the latest release of each stack (`scripts/latest-upstream.py`),
builds the adapters on those that are newer than the pin, runs the smoke and
cross-stack self-tests and reports pin versus latest in its job summary and in an
issue. It never changes a pin.

## Known deviations

[tests/known-bugs.tsv](../tests/known-bugs.tsv) has one line per deviation, with
the pair, the pinned version, the signature it must show and pinned evidence. A
case it explains is reported as `known-difference`, never as a pass. A signature
that does not match is a failure, and so is an entry that no longer reproduces,
except the one marked as depending on timing.

| Waiver | Stack | What happens | Specification |
|--------|-------|--------------|---------------|
| `async-opcua-null-session-nonce` | async-opcua 0.19.0 server | A None/None session of the open62541 client is refused: null ActivateSession nonce. [Evidence](https://github.com/FreeOpcUa/async-opcua/blob/9ad28fc011002398f2e8a95696a50408a14531d9/async-opcua-crypto/src/security_policy.rs#L179-L184) | OPC 10000-4 (v1.05) 5.7.3 ActivateSession |
| `node-opcua-renewal-old-token` | node-opcua 2.187.12 server | Responses keep the token of the request across a SecureChannel renewal; the open62541 subscription can stall. Depends on publish timing. [Evidence](https://github.com/node-opcua/node-opcua/blob/9c009a2e5f27957885938510e424a8f95a7a633f/packages/node-opcua-secure-channel/source/server/server_secure_channel_layer.ts#L838-L843) | OPC 10000-6 (v1.05) 6.7.4 |
| `open62541-chain-leaf-compare` | open62541 v1.5.9 client | The client compares the CreateSession server certificate with the leaf byte for byte, so it refuses a server that sends its chain ([contract 16.3](CONTAINER_CONTRACT.md)). [Evidence](https://github.com/open62541/open62541/blob/05c2b389b65cc35884eb40d800301af1f3d130cf/src/client/ua_client_connect.c#L1692-L1696) | OPC 10000-6 (v1.05) 6.2.6 Certificate Chains |
| `asyncua-percent-deadband` | asyncua 2.1.0 server | A percent deadband on a node without EURange is accepted ([adapter README](../adapters/asyncua/README.md)). [Evidence](https://github.com/FreeOpcUa/opcua-asyncio/blob/a5a3ce0f6c012e8b09d3e9a948e25a64b2e29b37/asyncua/server/monitored_item_service.py#L298-L300) | OPC 10000-8 (v1.05) 7.2 PercentDeadband |
| `asyncua-no-history-update` | asyncua 2.1.0 server | HistoryUpdate is refused: the server has no handler for it ([adapter README](../adapters/asyncua/README.md)). [Evidence](https://github.com/FreeOpcUa/opcua-asyncio/blob/a5a3ce0f6c012e8b09d3e9a948e25a64b2e29b37/asyncua/server/uaprocessor.py#L562-L564) | |

Each adapter README lists the deviations of its stack found by its consumers.

## Cross-stack matrix

`make interop` runs every client against every server for the cases of
[tests/cases.tsv](../tests/cases.tsv), with the secured channels of
[tests/secure-cases.tsv](../tests/secure-cases.tsv), and the `codec` documents of
[tests/codec-cases.tsv](../tests/codec-cases.tsv) between the stacks that declare
them. What a pair cannot do by its capabilities is reported as `unsupported`,
never as a pass. Each CI run uploads the result as `results.json`.

## Consumer integration

```
opcua-interop
    ├── deterministic reference servers
    ├── reference client commands
    ├── shared fixtures
    └── container lifecycle

go-opcua
    ├── starts selected compat container
    ├── runs Go client/server tests
    ├── evaluates results
    ├── owns regressions
    └── publishes compatibility claims
```

Test directions:

| Direction | Owner |
|---|---|
| Go client → open62541 server | go-opcua |
| Go client → Milo server | go-opcua |
| Go client → UA-.NETStandard server | go-opcua |
| open62541 client → Go server | go-opcua |
| Milo client → Go server | go-opcua |
| Go client → async-opcua server | go-opcua |
| async-opcua client → Go server | go-opcua |
| UA-.NETStandard client → Go server | go-opcua |
| Go client → node-opcua server | go-opcua |
| node-opcua client → Go server | go-opcua |
| Go client → opcua-asyncio server | go-opcua |
| opcua-asyncio client → Go server | go-opcua |

## Versioning

| Version type | Location |
|---|---|
| Repository release | Git tag and image tag — **`v0.9.0`** |
| Adapter capabilities version | `print-capabilities` → `adapter.version` — **`0.9.0`**, the same for every adapter (must match the tag) |
| Upstream stack version | Image label and `print-capabilities` → `stack.version` |
| Fixture schema version | `schemaVersion` field in every fixture |

Released tags: `v0.1.0` … `v0.7.0`, `v0.8.0`, `v0.8.1`, `v0.8.2`, `v0.9.0`
([releases](https://github.com/otfabric/opcua-interop/releases)).
`v0.6.0` moved the reference stacks to open62541 v1.5.9 / Eclipse Milo 1.1.8 and added
`register-nodes`, `node-management` and `--channel-lifetime-ms`. `v0.7.0` adds
DataChangeFilter deadbands, reverse connect, the ECC security policies, LDS / mDNS
discovery and the JSON / XML `codec` command, and declares optional features in
`print-capabilities` (`clientFeatures`, `serverFeatures`, `codec`). `v0.8.0` adds
OPC UA PubSub (Part 14) to the open62541 adapter (`--pubsub-config`, UDP / MQTT,
UADP / JSON, message security, SKS, `codec pubsub-*`, `print-capabilities` →
`pubsub`), the baseline fixture's `PubSub` folder and an MQTT broker. `v0.9.0` adds four
reference stacks: async-opcua (Rust), the OPC Foundation UA-.NETStandard (C#), node-opcua
(TypeScript) and opcua-asyncio (Python) (`opcua-interop-{async-opcua,dotnet,node-opcua,asyncua}`). Every change to the
adapter surface gets a new tag; published tags are not moved. Release notes and the release procedure: [`RELEASE.md`](../RELEASE.md).

## Security verification

The test PKI (`certs/test-pki/`) landed in v0.1.1; Basic256Sha256 / username verification
completed in v0.2.0; Aes128 / Aes256 profiles followed in v0.2.1; SecureChannel renewal
(`--channel-lifetime-ms`) is exercised cross-stack as of v0.6.0. v0.7.0 moves the
open62541 adapter to the OpenSSL crypto backend and adds the ECC security policies.

**What is implemented and verified:**
- Full test PKI with CA, fifteen identities (including go-server and, since v0.9.0, the async-opcua, dotnet, node-opcua and asyncua server / client pairs), and OPC UA PKI directory layout
- Server `--certificate`, `--private-key`, `--pki-dir` flags on all adapters
- Secure endpoint advertisement driven by fixture `securityProfiles`
- Trust list validation via open62541 `UA_ServerConfig_setDefaultWithSecurityPolicies`
- Trust list validation via Milo `FileBasedTrustListManager` + `DefaultServerCertificateValidator`
- node-opcua (v0.9.0): trust by the CA in `<pki-dir>/trusted/certs` with its CRL; RSA profiles and UserName tokens, no ECC in node-opcua 2.187
- async-opcua (v0.9.0): the stack trusts exact certificates only, so the server trusts the certificates listed in `<pki-dir>/trusted/certs` and the client checks the server certificate against `--trust-list` itself (exact match or issued by a listed CA); RSA profiles and UserName tokens verified in both directions against go-opcua, ECC not available in async-opcua 0.19
- UA-.NETStandard (v0.9.0): trust list validation via the stack's directory certificate stores (`--pki-dir`
  `trusted/` / `issuers/`, rejected certificates under `rejected/`)
- opcua-asyncio (v0.9.0): trust list validation with the stack's `TrustStore` / `CertificateValidator`
  (`--pki-dir` `trusted/` anchors, `issuers/` only to complete a chain, CRLs, rejected certificates under
  `rejected/`); the adapter loads the test PKI's `*.crt` / `*.crl` files itself, which the stack skips
- Username/password authentication on both None/None and secure endpoints
- Basic256Sha256 / Sign — all four directions: go-opcua client ↔ adapter servers; adapter clients ↔ go-opcua server
- Basic256Sha256 / SignAndEncrypt — all four directions
- Aes128_Sha256_RsaOaep / SignAndEncrypt — all four directions
- Aes256_Sha256_RsaPss / SignAndEncrypt — all four directions
- Untrusted certificate rejection — go-opcua client vs. all adapter servers
- Username valid/invalid — all four directions (go-opcua client ↔ adapter servers; adapter clients ↔ go-opcua server)
- go-opcua server OPN asymmetric decryption (Part 6 §6.7.4 conformance fix)
- open62541 client `UA_ExtensionObject_setValueCopy` argument-order fix (data first, type second)
- ECC (open62541 ↔ open62541, verified by `make smoke`): `ECC_nistP256`, `ECC_nistP384`,
  `ECC_brainpoolP256r1`, `ECC_brainpoolP384r1`, `ECC_curve25519`, `ECC_curve448`,
  `ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly` — SecureChannel, username/password as
  EccEncryptedSecret, wrong password and untrusted certificate rejected. The server takes
  the ECC certificates from `--ecc-dir`; ECC endpoints are opt-in, so servers started
  without it advertise exactly the RSA endpoints of v0.6.0
- The open62541 client sends the certificate's SAN URI as its ApplicationUri (an
  open62541 server rejects a mismatch with `BadCertificateUriInvalid`); override with
  `--application-uri`

**Test PKI runtime note:** PKI directories must be writable at container runtime because rejected certificates may be quarantined. The go-opcua test harness copies the PKI tree to a writable temporary directory before mounting it.
