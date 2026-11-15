#!/usr/bin/env bash
# Checks the output of `make digests` before a release uses it: one
# "<adapter> <digest>" line for every adapter of ADAPTERS in the Makefile, each
# with a sha256 digest, and no other line. Prints "<adapter>=<digest>" for
# $GITHUB_OUTPUT; prints nothing and fails when a line is missing or wrong.
#
#   scripts/check-digests.sh digests.txt >> "$GITHUB_OUTPUT"
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
file="${1:?usage: $0 <output of make digests>}"

adapters=$(sed -nE 's/^ADAPTERS \?= //p' "${ROOT}/Makefile")
[[ -n "${adapters}" ]] || { echo "::error::no ADAPTERS in the Makefile" >&2; exit 1; }

status=0
out=""
for adapter in ${adapters}; do
    lines=$(awk -v a="${adapter}" '$1 == a' "${file}" | wc -l | tr -d ' ')
    digest=$(awk -v a="${adapter}" '$1 == a { print $2 }' "${file}")
    if [[ "${lines}" != 1 ]]; then
        echo "::error::${adapter}: ${lines} lines in ${file}, want 1" >&2
        status=1
    elif ! [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "::error::no digest for ${adapter}" >&2
        status=1
    else
        out+="${adapter}=${digest}"$'\n'
    fi
done
while read -r adapter _; do
    [[ -z "${adapter}" || " ${adapters} " == *" ${adapter} "* ]] && continue
    echo "::error::${adapter} in ${file} is not in ADAPTERS" >&2
    status=1
done < "${file}"

[[ "${status}" == 0 ]] || exit 1
printf '%s' "${out}"
