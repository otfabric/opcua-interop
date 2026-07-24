# Publish gate — fix-forward `v0.5.0`

`adapter.version` and the git/GHCR tag must stay **`0.5.0` / `v0.5.0`**.
Do not introduce `v0.5.1` or RC tags.

> If a published image’s `print-capabilities` → `adapter.version` drifts (for
> example reports `0.5.1` while the tag is `v0.5.0`), fix the source strings and
> republish with the commands below.

## Current surface (included in v0.5.0)

- Client: `find-servers`, `translate`
- Client: `event-subscribe --of-type` / `--min-severity`
- Client: `history-read --scenario continue` (single-session page/continue/release/reuse)
- Server: `Events.Source` BaseEvent emission (~2s)
- Server: gate-compliant `History.Temperature` fixed raw samples + HistoryRead
- Milo `serverServices` includes `HistoryRead`
- Capabilities `adapter.version` = `0.5.0`

## Fix-forward republication

```bash
git status
git add -A
git commit -m "$(cat <<'EOF'
Align adapter.version with v0.5.0 release tag.

EOF
)"

# Move the existing tag onto HEAD (fix-forward)
git tag -f v0.5.0
git push origin HEAD
git push -f origin v0.5.0
```

The `Release` workflow rebuilds multi-arch images and refreshes the GitHub release.

## After publish — re-pin digests in go-opcua

```bash
docker pull ghcr.io/otfabric/opcua-interop-open62541:v0.5.0
docker pull ghcr.io/otfabric/opcua-interop-milo:v0.5.0
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-open62541:v0.5.0
docker buildx imagetools inspect ghcr.io/otfabric/opcua-interop-milo:v0.5.0
```

Update `defaultOpen62541Image` / `defaultMiloImage` in
`go-opcua/interop/harness_test.go` and `.github/workflows/interop.yml` (and
`INTEROP.md` / `BUCKET_B.md`) to the new multi-arch `@sha256:…` digests.

```bash
cd go-opcua
unset OPEN62541_IMAGE MILO_IMAGE
OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 go test -count=1 -tags=interop ./interop/...
```

Also delete any stray remote `v0.5.1` tag if present:

```bash
git push origin :refs/tags/v0.5.1
```
