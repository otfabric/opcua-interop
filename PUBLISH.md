# Publish gate — `v0.6.0`

`print-capabilities` → `adapter.version` and the git/GHCR tag must agree:
**`0.6.0` / `v0.6.0`**. Tags are immutable — a change to the adapter surface
gets a new version; do not move a published tag.

Version strings live in:

- `open62541/src/main.c` (`adapter.version`, `stack.version`)
- `milo/src/main/java/io/otfabric/opcuainterop/CapabilitiesCommand.java`
  (`adapter.version`, Milo version fallback)
- `milo/src/main/java/io/otfabric/opcuainterop/ServerCommand.java` (`BuildInfo`)

Upstream pins live in `open62541/Dockerfile` (`ARG OPEN62541_COMMIT`) and
`milo/pom.xml` (`milo.version`).

## Surface added in v0.6.0

- Upstream stacks: open62541 `v1.5.9`, Eclipse Milo `1.1.8`
- Client: `register-nodes`, `node-management` (fifteen `clientOperations`)
- Client: global `--channel-lifetime-ms` (SecureChannel renewal mid-command)
- Smoke: `register-nodes` and subscribe-across-renewals in every adapter↔adapter
  direction
- Capabilities `adapter.version` = `0.6.0`

Carried over from v0.5.0: `find-servers`, `translate`, `event-subscribe`
(`--of-type` / `--min-severity`), `history-read` (`--scenario continue`),
`republish`, `transfer-subscriptions`, `Events.Source` BaseEvent emission, and the
fixed `History.Temperature` raw samples.

## Before tagging

```bash
make ci
```

`make ci` validates fixtures, builds both images, runs the adapter unit tests,
the single-adapter and cross-stack smoke, and the graceful-shutdown checks. The
`Build` and `Smoke` workflows run the same gate on every push.

## Release

```bash
git tag v0.6.0
```

```bash
git push origin v0.6.0
```

The `Release` workflow builds the multi-arch images, pushes
`:v0.6.0` / `:v0.6` / `:v0`, and creates the GitHub release.

## After publish — re-pin digests in go-opcua

```bash
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-open62541:v0.6.0
```

```bash
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-milo:v0.6.0
```

Update `defaultOpen62541Image` / `defaultMiloImage` in
`go-opcua/interop/harness_test.go` and `.github/workflows/interop.yml` (and
`INTEROP.md` / `interop/BUCKET_B.md`) to the new multi-arch `@sha256:…` digests,
then run the consumer suite against the published images:

```bash
OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 go test -count=1 -tags=interop -timeout 45m ./interop/...
```
