#!/usr/bin/env bash
# Checks that a release tag is consistent with the repository before anything
# is built: the tag is vMAJOR.MINOR.PATCH, every adapter reports that version
# (print-capabilities adapter.version, Milo BuildInfo), and RELEASE.md has a
# non-empty section for it.
#
#   scripts/check-release.sh v0.8.0
set -euo pipefail

TAG="${1:?usage: $0 vX.Y.Z}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

fail() { echo "error: $*" >&2; exit 1; }

[[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag ${TAG} is not of the form vMAJOR.MINOR.PATCH"
VERSION="${TAG#v}"

# The version string each file reports, extracted by a sed expression.
reported() { sed -nE "$2" "$1" | head -1; }
check() { # file, sed expression printing the version, what
    local got
    got="$(reported "$1" "$2")"
    [[ "${got}" == "${VERSION}" ]] || fail "$1: $3 is '${got:-missing}', not ${VERSION}"
}
check open62541/src/main.c 's/.*"adapter\\": \{\\"name\\": \\"open62541\\", \\"version\\": \\"([0-9.]+)\\".*/\1/p' "open62541 adapter.version"
check milo/src/main/java/io/otfabric/opcuainterop/CapabilitiesCommand.java 's/.*adapter\.put\("version", "([0-9.]+)"\).*/\1/p' "Milo adapter.version"
check milo/src/main/java/io/otfabric/opcuainterop/ServerCommand.java 's/^ +"([0-9]+\.[0-9]+\.[0-9]+)",$/\1/p' "Milo server BuildInfo version"

notes="$("${ROOT}/scripts/release-notes.sh" "${TAG}")" || fail "RELEASE.md has no section \"## ${TAG}\""
[[ -n "${notes//[[:space:]]/}" ]] || fail "RELEASE.md section \"## ${TAG}\" is empty"
if grep -qiE '^\*\*Date:\*\* *(unreleased|tbd)' <<<"${notes}"; then
    fail "RELEASE.md section \"## ${TAG}\" has no release date"
fi

echo "release ${TAG}: versions and RELEASE.md are consistent"
