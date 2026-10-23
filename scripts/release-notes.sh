#!/usr/bin/env bash
# Prints the section of RELEASE.md for a tag: everything after the heading
# "## vX.Y.Z" up to the next "---" line. Exits 1 if there is no such section.
#
#   scripts/release-notes.sh v0.8.0
set -euo pipefail

TAG="${1:?usage: $0 vX.Y.Z}"
FILE="$(cd "$(dirname "$0")/.." && pwd)/RELEASE.md"

awk -v target="## ${TAG}" '
    $0 == target { found = 1; next }
    found && /^---$/ { exit }
    found { print }
    END { if (!found) exit 1 }
' "${FILE}"
