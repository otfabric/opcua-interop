#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Records the outcome of every scenario of a self-test, one JSON line each, for
# scripts/write-results.py, which writes results.json (interop-result-v1).
# Source, do not execute. Needs jq and python3.
#
#   results_open <name> <directory> <command>     start results-<name>.jsonl
#   at <id> [<client> <server>]                   the scenario of what follows;
#                                                 both default to RESULT_SUBJECT
#   result <outcome> [<reason>] [<waiver id>]     one outcome of that scenario;
#                                                 RESULT_FEATURE names its feature
#   waiver <id> <scope> <evidence url> <true|false: it reproduced>
#   implementation <name> <capability document>   what an image says of itself
#   results_close                                 write results.json and judge
#   results_abort                                 for the EXIT trap of a run
#
# Every results-*.jsonl of the directory goes into one results.json there, so a
# second self-test with the same REPORT_DIR adds to the first.

RESULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULT_FILE="" RESULT_ID="" RESULT_CLIENT="" RESULT_SERVER="" RESULT_FEATURE="" RESULT_T0=0 RESULTS_CLOSED=""

result_now() {
    if [[ -n "${EPOCHREALTIME:-}" ]]; then local t="${EPOCHREALTIME/[.,]/}"; echo $((t / 1000)); else echo $(($(date +%s) * 1000)); fi
}

results_open() {
    mkdir -p "$2"
    RESULT_FILE="$2/results-$1.jsonl"
    jq -cn --arg s "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg r "$3" \
        '{kind: "run", startedAt: $s, reproduce: $r}' > "${RESULT_FILE}"
}

# Ids are lower case and carry the suite of the script: SUITE.<id>.
at() {
    local id
    id=$(LC_ALL=C tr 'A-Z' 'a-z' <<<"$1" | LC_ALL=C tr -cs 'a-z0-9._-' '-' | sed -e 's/^-*//' -e 's/-*$//')
    RESULT_ID="${SUITE:-selftest}.${id}" RESULT_CLIENT="${2:-${RESULT_SUBJECT:-}}" RESULT_SERVER="${3:-${RESULT_SUBJECT:-}}" RESULT_T0=$(result_now)
}

# A check outside any scenario can only be about the harness itself, so a
# failure there is an infra-error and a pass is no evidence of anything.
result() {
    [[ -n "${RESULT_FILE}" ]] || return 0
    local outcome="$1" id="${RESULT_ID}"
    if [[ -z "${id}" ]]; then
        [[ "${outcome}" == pass ]] && return 0
        id=harness.check outcome=infra-error
    fi
    jq -cn --arg id "${id}" --arg c "${RESULT_CLIENT}" --arg s "${RESULT_SERVER}" --arg o "${outcome}" \
        --argjson ms $(($(result_now) - RESULT_T0)) --arg r "${2:-}" --arg w "${3:-}" --arg f "${RESULT_FEATURE}" \
        '{kind: "result", id: $id, client: $c, server: $s, outcome: $o, durationMs: $ms, reason: $r[:500], waiver: $w, feature: $f}' \
        >> "${RESULT_FILE}"
}

waiver() {
    [[ -n "${RESULT_FILE}" ]] || return 0
    jq -cn --arg i "$1" --arg s "$2" --arg e "$3" --argjson r "$4" \
        '{kind: "waiver", id: $i, scope: $s, evidence: $e, reproduced: $r}' >> "${RESULT_FILE}"
}

implementation() {
    [[ -n "${RESULT_FILE}" ]] || return 0
    jq -c --arg n "$1" '{kind: "implementation", name: $n, version: (.upstream.version // .stack.version), upstream: (.upstream.name // .stack.name),
        revision: .upstream.revision, independent: (.upstream.independentEngine // true)}' "$2" \
        >> "${RESULT_FILE}"
}

results_close() {
    [[ -n "${RESULT_FILE}" && -z "${RESULTS_CLOSED}" ]] || return 0
    RESULTS_CLOSED=1
    python3 "${RESULT_ROOT}/scripts/write-results.py" "$(dirname "${RESULT_FILE}")"
}

# A run that exits before results_close still leaves a results.json, which says so.
results_abort() {
    [[ -n "${RESULT_FILE}" && -z "${RESULTS_CLOSED}" ]] || return 0
    RESULT_ID=harness.aborted RESULT_CLIENT="" RESULT_SERVER=""
    result infra-error "the self-test stopped before its end"
    results_close || true
}
