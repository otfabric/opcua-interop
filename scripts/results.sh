#!/usr/bin/env bash
# results.json for scripts/smoke.sh and scripts/pubsub-smoke.sh. Source, do not
# execute. The script sets SUITE and defines ok, fail and the counters.
#
# With REPORT_DIR set, every result is appended to ${REPORT_DIR}/results.log (one
# tab-separated line: stable ID, outcome, roles as "role=name" words,
# milliseconds since the previous result, reason, waiver) and each script ends by
# rewriting ${REPORT_DIR}/results.json from everything logged so far
# (scripts/results-from-log.py). Several scripts with one REPORT_DIR are one run.

RESULTS_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/results-from-log.py"
SCENARIO_ID=""
SCENARIO_ROLES=""
KNOWN=0

results_slug() { LC_ALL=C tr 'A-Z' 'a-z' <<<"$1" | LC_ALL=C tr -cs 'a-z0-9._-' '-' | sed -e 's/^-*//' -e 's/-*$//'; }
results_ms() { if [[ -n "${EPOCHREALTIME:-}" ]]; then local t="${EPOCHREALTIME/[.,]/}"; echo "${t%???}"; else echo "$((SECONDS * 1000))"; fi; }
RESULT_LAST=$(results_ms)

# at <stable id> [label]: what the next result is about. The label names the
# pairing as "<client>→<server>[ (variant)]"; without one the subject is the adapter.
at() {
    local who="${2:-}" client server variant=""
    who="${who%%:*}"
    SCENARIO_ID="${SUITE}.$(results_slug "$1")"
    if [[ "${who}" == *"→"* ]]; then
        client="${who%%→*}"; server="${who#*→}"
        if [[ "${server}" == *" ("* ]]; then variant="${server#* (}"; variant="${variant%)}"; server="${server%% (*}"; fi
        [[ "${client}" == o62541 ]] && client=open62541
        [[ "${server}" == o62541 ]] && server=open62541
        SCENARIO_ROLES="client=$(results_slug "${client}") server=$(results_slug "${server}")"
        if [[ -n "${variant}" ]]; then SCENARIO_ROLES="${SCENARIO_ROLES} variant=$(results_slug "${variant}")"; fi
    else
        SCENARIO_ROLES="adapter=${RESULT_ADAPTER}"
    fi
}

# record <outcome> [reason] [waiver]
record() {
    if [[ -z "${REPORT_DIR:-}" ]]; then return 0; fi
    local now reason="${2:-}"
    now=$(results_ms)
    reason="${reason//[$'\t\n']/ }"
    [[ -n "${SCENARIO_ID}" ]] || at harness
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${SCENARIO_ID}" "$1" "${SCENARIO_ROLES}" "$((now - RESULT_LAST))" "${reason}" "${3:-}" >> "${REPORT_DIR}/results.log"
    RESULT_LAST="${now}"
}

# known <waiver> <what>: an expected deviation of tests/known-differences.tsv. It is
# reported, and it does not count as a pass.
known() { log "KNOWN: $2"; KNOWN=$((KNOWN + 1)); record known-difference "$2" "$1"; }

# stale <waiver> <what>: the deviation is gone. The run fails until the entry is removed.
stale() { log "FAIL: $2"; FAIL=$((FAIL + 1)); record fail "$2" "$1"; }

# infra <what>: the environment failed, not a stack; it fails the run all the same.
infra() { log "FAIL: $*"; FAIL=$((FAIL + 1)); record infra-error "$*"; }

# results_start <image...>: the implementations of this script, for results.json.
# An image that declares upstream.independentEngine false gets its version and
# commit as further columns: results.json records it as not independent.
results_start() {
    if [[ -z "${REPORT_DIR:-}" ]]; then return 0; fi
    mkdir -p "${REPORT_DIR}"
    [[ -f "${REPORT_DIR}/started" ]] || date -u +%Y-%m-%dT%H:%M:%SZ > "${REPORT_DIR}/started"
    printf 'REPORT_DIR=reports %s\n' "$(basename "$0") ${RESULTS_ARGS}" >> "${REPORT_DIR}/commands"
    local image name own
    for image in "$@"; do
        [[ -n "${image}" ]] || continue
        name="${image##*/}"; name="${name%%[:@]*}"; name="${name#opcua-interop-}"
        own=$(docker run --rm "${image}" print-capabilities 2>/dev/null \
            | jq -r 'select(.upstream.independentEngine == false) | "\t\(.upstream.version)\t\(.upstream.revision)"' 2>/dev/null) || true
        printf '%s\t%s%s\n' "${name}" "${image}" "${own}" >> "${REPORT_DIR}/implementations.tsv"
    done
}

# results_finish: rewrites results.json. Its verdict covers the whole REPORT_DIR.
results_finish() {
    if [[ -z "${REPORT_DIR:-}" ]]; then return 0; fi
    python3 "${RESULTS_SCRIPT}" "${REPORT_DIR}" "${REPORT_DIR}/results.json" || FAIL=$((FAIL + 1))
}
