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

# ---- every FROM line is pinned by digest ----
# An image is pinned when it carries @sha256:<digest>, @${X_DIGEST} with
# ARG X_DIGEST=sha256:<digest>, or is ${X} with ARG X=<image>@sha256:<digest>; a
# FROM may also name an earlier stage of the same Dockerfile.
unpinned=0
for dockerfile in adapters/*/Dockerfile own/*/Dockerfile; do
    [[ -f "${dockerfile}" ]] || continue
    stages=" "
    while read -r image stage; do
        arg=""
        case "${image}" in
            *@sha256:*) ok=1 ;;
            *'@${'*'}')
                arg=$(sed -nE 's/.*@\$\{([A-Za-z0-9_]+)\}$/\1/p' <<<"${image}")
                grep -qE "^ARG ${arg}=sha256:[0-9a-f]{64}$" "${dockerfile}" && ok=1 || ok=0 ;;
            '${'*'}')
                arg=$(sed -nE 's/^\$\{([A-Za-z0-9_]+)\}$/\1/p' <<<"${image}")
                grep -qE "^ARG ${arg}=[^[:space:]]+@sha256:[0-9a-f]{64}$" "${dockerfile}" && ok=1 || ok=0 ;;
            *) [[ "${stages}" == *" ${image} "* ]] && ok=1 || ok=0 ;;
        esac
        if [[ "${ok}" != 1 ]]; then
            bad "${dockerfile}: FROM ${image} is not pinned by digest"
            unpinned=1
        fi
        [[ -n "${stage}" ]] && stages+="${stage} "
    done < <(sed -nE 's/^FROM[[:space:]]+(--[^[:space:]]+[[:space:]]+)*([^[:space:]]+)([[:space:]]+[Aa][Ss][[:space:]]+([^[:space:]]+))?[[:space:]]*$/\2 \4/p' "${dockerfile}")
done
[[ "${unpinned}" == 0 ]] && echo "ok   every FROM line is pinned by digest"

# ---- open62541 is built from the commit versions.yaml records for its tag ----
tag_commit=$(sed -n '/^  open62541:$/,/^  [a-z0-9-]*:$/p' versions.yaml | sed -nE 's/^    tag_commit: "([0-9a-f]{40})".*/\1/p')
build_sha=$(sed -nE 's/^ARG OPEN62541_SHA=([0-9a-f]{40})$/\1/p' adapters/open62541/Dockerfile)
if [[ -n "${tag_commit}" && "${build_sha}" == "${tag_commit}" ]]; then echo "ok   open62541 tag_commit: ${tag_commit}"
else bad "open62541: tag_commit ${tag_commit:-missing} of versions.yaml is not ARG OPEN62541_SHA ${build_sha:-missing} of adapters/open62541/Dockerfile"; fi

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
