#!/usr/bin/env bash
# Fails when versions.yaml disagrees with what the builds actually pin.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
status=0

bad() { echo "FAIL $*"; status=1; }

# A top-level "key: "value"" of versions.yaml.
field() { sed -nE "s/^$1: \"([^\"]+)\".*/\1/p" versions.yaml; }

# ---- interop_version, contract_version, fixture_schema ----
newest=$(sed -nE 's/^## v([0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*$/\1/p' RELEASE.md | head -1)
if [[ "$(field interop_version)" == "${newest}" ]]; then echo "ok   interop_version: ${newest}"
else bad "interop_version $(field interop_version) is not the newest RELEASE.md section ${newest}"; fi

contract=$(sed -nE 's/^Version: \*\*([0-9.]+)\*\*.*/\1/p' docs/CONTAINER_CONTRACT.md | head -1)
if [[ "$(field contract_version)" == "${contract}" ]]; then echo "ok   contract_version: ${contract}"
else bad "contract_version $(field contract_version) is not the version of docs/CONTAINER_CONTRACT.md (${contract})"; fi

for f in fixtures/*/fixture.json; do
    got=$(jq -r .schemaVersion "${f}")
    if [[ "$(field fixture_schema)" == "${got}" ]]; then echo "ok   fixture_schema of ${f}: ${got}"
    else bad "fixture_schema $(field fixture_schema) is not the schemaVersion of ${f} (${got})"; fi
done

# ---- every version of an implementation occurs in its pinned_in files ----
while IFS=$'\t' read -r name value files; do
    # shellcheck disable=SC2086
    if cat ${files} | grep -qF -- "${value}"; then echo "ok   ${name} version: ${value}"
    else bad "${name}: version ${value} is not in ${files}"; fi
done < <(awk '
    /^implementations:/ { on = 1; next }
    /^[a-z_]+:/ { on = 0 }
    !on { next }
    function flush() { if (name != "") printf "%s\t%s\t%s\n", name, version, files; }
    /^  [a-z0-9-]+:$/ { flush(); name = $1; sub(/:$/, "", name); version = ""; files = ""; next }
    /^    version:/ { version = $2; gsub(/"/, "", version); next }
    /^      - / { files = files (files == "" ? "" : " ") $2; next }
    END { flush() }
' versions.yaml)

# ---- every digest a build uses is listed, and every listed digest is used ----
listed=$(sed -n '/^base_images:/,/^[a-z_]*:$/p' versions.yaml | grep -oE 'sha256:[0-9a-f]{64}' | sort -u)
used=$(find adapters own -name Dockerfile -print0 | xargs -0 cat Makefile | grep -oE 'sha256:[0-9a-f]{64}' | sort -u)
while read -r d; do
    [[ -n "${d}" ]] && bad "${d} is used by a build but not listed in versions.yaml"
done < <(comm -23 <(echo "${used}") <(echo "${listed}"))
while read -r d; do
    [[ -n "${d}" ]] && bad "${d} is listed in versions.yaml but no build uses it"
done < <(comm -13 <(echo "${used}") <(echo "${listed}"))
echo "ok   $(echo "${listed}" | wc -l | tr -d ' ') base image digests checked"

# ---- images and platforms ----
images=$(sed -n '/^images:/,/^[a-z_]*:$/p' versions.yaml | sed -nE 's/^  ([a-z0-9-]+): "ghcr.io\/otfabric\/opcua-interop-([a-z0-9-]+)"$/\1 \2/p' | awk '$1 == $2 { print $1 }' | sort | xargs)
adapters=$(sed -nE 's/^ADAPTERS \?= //p' Makefile | tr ' ' '\n' | sort | xargs)
if [[ "${images}" == "${adapters}" ]]; then echo "ok   images: ${images}"
else bad "images of versions.yaml (${images}) are not ADAPTERS of the Makefile (${adapters})"; fi
for a in ${adapters}; do
    [[ -f "adapters/${a}/Dockerfile" ]] || bad "adapters/${a}/Dockerfile does not exist"
done
platforms=$(sed -n '/^platforms:/,$p' versions.yaml | sed -nE 's/^  - "(.*)"$/\1/p' | paste -sd, -)
if [[ "${platforms}" == "$(sed -nE 's/^PLATFORMS \?= //p' Makefile)" ]]; then echo "ok   platforms: ${platforms}"
else bad "platforms of versions.yaml (${platforms}) are not PLATFORMS of the Makefile"; fi

exit "${status}"
