#!/usr/bin/env bash
# Prints the release notes of one version from RELEASE.md: the lines after
# the heading "## <tag>" up to the next line that is exactly "---". This is
# the format of every otfabric repository, and the rule the shared Go
# release workflow (otfabric/.github, go-package-release.yml) applies.
#
# Usage: release-notes.sh [<tag>]     e.g. release-notes.sh v0.8.0
#        Without a tag: the newest version, the first "## vX.Y.Z" heading
#        in RELEASE.md.
#
# Fails when RELEASE.md has no such section, when the section is empty or
# when it does not end with "---": the Release workflow publishes exactly
# this text as the body of the GitHub release.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILE="${ROOT}/RELEASE.md"
tag="${1:-$(sed -nE 's/^## (v[0-9]+\.[0-9]+\.[0-9]+)$/\1/p' "${FILE}" | head -1)}"
[[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-notes: '${tag}' is not vX.Y.Z" >&2; exit 2; }

notes=$(awk -v target="## ${tag}" '
    $0 == target { found = 1; next }
    found && /^---$/ { closed = 1; exit }
    found { print }
    END { if (found && !closed) exit 3 }
' "${FILE}") || { echo "release-notes: the section ## ${tag} in RELEASE.md does not end with ---" >&2; exit 1; }

if [[ -z "${notes//[[:space:]]/}" ]]; then
    echo "release-notes: RELEASE.md has no notes under ## ${tag}" >&2
    exit 1
fi
printf '%s\n' "${notes}"
