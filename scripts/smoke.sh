#!/usr/bin/env bash
# Smoke test of one adapter image, against itself.
#
# Usage: smoke.sh <adapter>
#
# The image's own tests (its "test" command), its capability document, its client
# against its server with the cases of tests/cases.tsv and tests/codec-cases.tsv,
# what only this adapter has (scripts/features.sh), and a clean exit on SIGTERM.
#
# Environment: REGISTRY, VERSION (image tag, default dev), VERBOSE=1,
#              REPORT_DIR (keeps every result document when set).
#              ADAPTER_IMAGE_<adapter>: an image outside the release set.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib.sh
source "${SCRIPT_DIR}/lib.sh"
# shellcheck source=scripts/features.sh
source "${SCRIPT_DIR}/features.sh"

[[ $# -eq 1 ]] || { echo "usage: smoke.sh <adapter>" >&2; exit 2; }
ADAPTER="$1"
SUITE=single
require_tools
WORK=$(mktemp -d)
trap 'results_abort; rm -rf "${WORK}"; cleanup' EXIT
results_open "smoke-${ADAPTER}" "${REPORT_DIR:-${WORK}}" "VERSION=${VERSION} scripts/smoke.sh ${ADAPTER}"
network_up
load_caps "${ADAPTER}" || { finish; exit 1; }
load_known_bugs "${ADAPTER}"
CAPS="${WORK}/caps-${ADAPTER}.json"
IMAGE="$(image_of "${ADAPTER}")"

# ---- the capability document ----
at capabilities "${ADAPTER}" "${ADAPTER}"
if jq -e --arg a "${ADAPTER}" '.adapter.name == $a and (.adapter.version | length) > 0 and (.stack.version | length) > 0
        and (.roles | index("client") and index("server")) and (.clientOperations | index("endpoints"))' "${CAPS}" >/dev/null 2>&1; then
    ok "${ADAPTER}: capabilities"
else
    fail "${ADAPTER}: capabilities: $(head -c 400 "${CAPS}")"
fi
case "${ADAPTER}" in
    open62541|milo|async-opcua|dotnet|node-opcua|asyncua)
        check history.caps "${ADAPTER}" "${ADAPTER}" \
            '(.clientOperations | index("history-read-events")) and (.clientOperations | index("history-update-events"))' "$(cat "${CAPS}")"
        ;;
esac

# ---- the image's own tests; an own stack's image has its tests in its repository ----
if ! is_own "${ADAPTER}"; then
    at unit-tests "${ADAPTER}" "${ADAPTER}"
    if docker run --rm --label "opcua-interop.run=${RUN_ID}" "${DOCKER_ARGS[@]}" "${IMAGE}" test >"${WORK}/unit.log" 2>&1; then
        ok "${ADAPTER}: test command"
    else
        fail "${ADAPTER}: test command: $(tail -5 "${WORK}/unit.log")"
    fi
fi

# in_scope for the tables: the adapter with itself.
in_scope() { [[ "$1" == "${ADAPTER}" && "$2" == "${ADAPTER}" ]]; }

if [[ "${ADAPTER}" == dotnet-gds ]]; then
    run_gds dotnet-gds
else
    name="srv-${ADAPTER}-${RUN_ID}"
    server_up "${name}" "${ADAPTER}" || { finish; exit 1; }
    run_cases "${ADAPTER}" "${ADAPTER}" "$(url_of "${name}")"
    stop_server "${name}"
    if has_cap "${ADAPTER}" client codec; then run_codec "${ADAPTER}" "${ADAPTER}"; fi
    run_secure_cases in_scope "${ADAPTER}"
    case "${ADAPTER}" in
        open62541) run_lds_features open62541 ;;
        dotnet)    run_chain dotnet ;;
    esac
fi

# ---- SIGTERM ends the server with exit code 0 ----
at shutdown.sigterm "${ADAPTER}" "${ADAPTER}"
name="srv-${ADAPTER}-stop-${RUN_ID}"
SERVER_FIXTURE=/fixtures/baseline/fixture.json
if server_up "${name}" "${ADAPTER}"; then
    at shutdown.sigterm "${ADAPTER}" "${ADAPTER}"
    docker stop --time=10 "${name}" >/dev/null
    code=$(docker inspect --format '{{.State.ExitCode}}' "${name}")
    if [[ "${code}" == 0 ]]; then ok "${ADAPTER}: clean shutdown"
    else fail "${ADAPTER}: exit code ${code} on SIGTERM"; fi
    stop_server "${name}"
fi

finish
status=$?
trap 'rm -rf "${WORK}"; cleanup' EXIT
exit "${status}"
