#!/usr/bin/env bash
# Reference-stack self-test: every client adapter against every server adapter.
#
# Usage: interop.sh <adapter> [<adapter> ...]      e.g. interop.sh open62541 milo
#
# For each pairing, each case of tests/cases.tsv: the result document must match
# the expectation of the case. OPC UA servers differ in what they may answer
# (browse results, endpoint lists), so the documents of two pairings are not
# compared with each other, as they are in modbus-interop and iec104-interop.
# Then codec documents across stacks (tests/codec-cases.tsv), secured channels
# (tests/secure-cases.tsv) and the scenarios of scripts/features.sh.
#
# When an adapter declares upstream.independentEngine false, only the pairings
# with it run: an own stack against the references, not the references again.
#
# tests/known-bugs.tsv lists deviations of specific upstream versions; a document
# with the signature of one is counted as a known deviation instead of a failure.
#
# Every outcome goes to results.json (interop-result-v1): in REPORT_DIR when it
# is set. A run with no pass, or with a known deviation that no longer reproduces,
# fails.
#
# This tests the reference adapters against each other. It says nothing about
# any library that consumes the images.
#
# Environment: REGISTRY, VERSION (image tag, default dev), VERBOSE=1,
#              REPORT_DIR (keeps every result document when set).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "${SCRIPT_DIR}/lib.sh"
# shellcheck source=scripts/features.sh
source "${SCRIPT_DIR}/features.sh"

[[ $# -ge 1 ]] || { echo "usage: interop.sh <adapter> [<adapter> ...]" >&2; exit 2; }
ADAPTERS=("$@")
SUITE=cross
require_tools
WORK=$(mktemp -d)
trap 'results_abort; rm -rf "${WORK}"; cleanup' EXIT
results_open interop "${REPORT_DIR:-${WORK}}" "VERSION=${VERSION} scripts/interop.sh $*"
network_up
load_caps "${ADAPTERS[@]}" || { finish; exit 1; }
load_known_bugs "${ADAPTERS[@]}"

FOCUS=""
for adapter in "${ADAPTERS[@]}"; do
    if is_own "${adapter}"; then FOCUS="${FOCUS} ${adapter}"; fi
done

# in_scope <client> <server>
in_scope() {
    [[ -z "${FOCUS}" || " ${FOCUS} " == *" $1 "* || " ${FOCUS} " == *" $2 "* ]]
}

# named <adapter>: it is among the adapters of this run.
named() { [[ " ${ADAPTERS[*]} " == *" $1 "* ]]; }

log "adapters: ${ADAPTERS[*]} (${VERSION})"
for server in "${ADAPTERS[@]}"; do
    name="srv-${server}-${RUN_ID}"
    started=""
    for client in "${ADAPTERS[@]}"; do
        in_scope "${client}" "${server}" || continue
        has_role "${server}" server || continue
        if [[ -z "${started}" ]]; then
            server_up "${name}" "${server}" || { finish; exit 1; }
            started=1
        fi
        log "${client} -> ${server}"
        run_cases "${client}" "${server}" "$(url_of "${name}")"
    done
    [[ -z "${started}" ]] || stop_server "${name}"
done

for enc in "${ADAPTERS[@]}"; do
    for dec in "${ADAPTERS[@]}"; do
        in_scope "${enc}" "${dec}" || continue
        has_cap "${enc}" client codec && has_cap "${dec}" client codec || continue
        run_codec "${enc}" "${dec}"
    done
done

run_secure_cases in_scope "${ADAPTERS[@]}"

if [[ -z "${FOCUS}" ]]; then
    if named open62541 && named milo; then run_lds_features open62541 milo; fi
    if named dotnet && named open62541; then run_chain dotnet open62541; fi
    if named asyncua && named open62541; then run_register_with asyncua open62541; fi
fi

finish
status=$?
trap 'rm -rf "${WORK}"; cleanup' EXIT
exit "${status}"
