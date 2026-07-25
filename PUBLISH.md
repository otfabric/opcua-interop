# Publish gate — v0.5.1

Agent-prepared adapter work for events, raw history, find-servers/translate, and
narrow client controls. Local smoke used `:dev` images (not promotion-eligible).

## What this release adds

- Client: `find-servers`, `translate`
- Client: `event-subscribe --of-type` / `--min-severity`
- Client: `history-read --scenario continue` (single-session page/continue/release/reuse)
- Server: `Events.Source` BaseEvent emission (~2s)
- Server: gate-compliant `History.Temperature` fixed raw samples + HistoryRead
- Milo `serverServices` includes `HistoryRead`
- Capabilities `adapter.version` = `0.5.1`

## Publication (tag → Release workflow)

```bash
git status
git add -A
git commit -m "$(cat <<'EOF'
Add BaseEvent emission, raw historian, and narrow event/history client controls.

EOF
)"
git tag v0.5.1
git push origin HEAD
git push origin v0.5.1
```

The `Release` workflow builds multi-arch images and creates the GitHub release.

## After publish — pin digests in go-opcua

```bash
docker pull ghcr.io/otfabric/opcua-interop-open62541:v0.5.1
docker pull ghcr.io/otfabric/opcua-interop-milo:v0.5.1
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-open62541:v0.5.1
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-milo:v0.5.1
```

Update `defaultOpen62541Image` / `defaultMiloImage` in
`go-opcua/interop/harness_test.go` and `.github/workflows/interop.yml` to the
published multi-arch `@sha256:…` digests, set `interopVersion` to `v0.5.1`, then:

```bash
cd go-opcua
unset OPEN62541_IMAGE MILO_IMAGE
OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 go test -count=1 -tags=interop ./interop/...
# Promote ready rows in interop/coverage.json
go generate ./interop
```
