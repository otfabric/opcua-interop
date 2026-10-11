# Publish gate — `v0.7.0`

`print-capabilities` → `adapter.version` and the git/GHCR tag must agree:
**`0.7.0` / `v0.7.0`**. Tags are immutable — a change to the adapter surface
gets a new version; do not move a published tag.

Version strings live in:

- `open62541/src/main.c` (`adapter.version`, `stack.version`)
- `milo/src/main/java/io/otfabric/opcuainterop/CapabilitiesCommand.java`
  (`adapter.version`, Milo version fallback)
- `milo/src/main/java/io/otfabric/opcuainterop/ServerCommand.java` (`BuildInfo`)

Upstream pins live in `open62541/Dockerfile` (`ARG OPEN62541_COMMIT`) and
`milo/pom.xml` (`milo.version`).

## Surface added in v0.7.0

- open62541 built with the OpenSSL crypto backend and mDNS (mdnsd); Milo gains
  `milo-encoding-json` / `milo-encoding-xml`
- Client: `subscribe` DataChangeFilter flags (`--deadband-absolute`,
  `--deadband-percent`, `--trigger`)
- Client: `find-servers-on-network`, `register-server`, `codec` (eighteen
  `clientOperations`)
- Client (open62541): `--reverse-listen`, ECC `--security-policy` names,
  `--application-uri`
- Server (open62541): `--ecc-dir`, `--reverse-connect`, `--lds`, `--mdns-name`;
  both adapters: `--register-with`
- Fixture: `Analog.Level`, `Analog.Setpoint` (`euRange`), ECC `securityProfiles`
- Test PKI: `ecc-<curve>/` certificates (`certs/generate.sh --add-ecc`)
- Capabilities: `clientFeatures`, `serverFeatures`, `codec`, ECC
  `securityProfiles`, `adapter.version` = `0.7.0`
- `subscription-lifecycle` `publishing-mode` / `monitoring-mode` request
  SamplingInterval 0
- Smoke: deadband and codec in every direction; RSA over OpenSSL, ECC, reverse
  connect, LDS / mDNS (open62541, with Milo as registering peer and RSA client)

Carried over from v0.6.0: open62541 `v1.5.9` / Eclipse Milo `1.1.8`,
`register-nodes`, `node-management`, `--channel-lifetime-ms`, and everything
from v0.5.0.

## Before tagging

```bash
make ci
```

`make ci` validates fixtures, builds both images, runs the adapter unit tests,
the single-adapter and cross-stack smoke, and the graceful-shutdown checks. The
`Build` and `Smoke` workflows run the same gate on every push.

## Release

```bash
git tag v0.7.0
```

```bash
git push origin v0.7.0
```

The `Release` workflow builds the multi-arch images, pushes
`:v0.7.0` / `:v0.7` / `:v0`, and creates the GitHub release.

## After publish — re-pin digests in go-opcua

```bash
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-open62541:v0.7.0
```

```bash
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-milo:v0.7.0
```

Update `defaultOpen62541Image` / `defaultMiloImage` in
`go-opcua/interop/harness_test.go` and `.github/workflows/interop.yml` (and
`INTEROP.md` / `interop/BUCKET_B.md`) to the new multi-arch `@sha256:…` digests,
then run the consumer suite against the published images:

```bash
OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 go test -count=1 -tags=interop -timeout 45m ./interop/...
```
