#!/usr/bin/env bash
# PubSub of an own stack's image: alone, and in each role against each reference that
# has PubSub (open62541 and dotnet; Milo, async-opcua, node-opcua and asyncua do not).
#
# Usage: pubsub-own.sh <adapter>
#
# Every run happens; a failure of one does not stop the next. The counts of all of them
# are printed at the end, and a run's documents are in REPORT_DIR/pubsub/<run>/.
#
# Environment: as scripts/pubsub-smoke.sh.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $# -eq 1 ]] || { echo "usage: pubsub-own.sh <adapter>" >&2; exit 2; }
ADAPTER="$1"
BASE="${REPORT_DIR:-$(mktemp -d)}/pubsub"
mkdir -p "${BASE}"
status=0 passed=0 failed=0

# run <name> <VAR=value or -> <scenario>...
run() {
    local name="$1" pairing="$2"
    shift 2
    local log="${BASE}/${name}.log"
    mkdir -p "${BASE}/${name}"
    echo "=== ${name}: $*"
    if [[ "${pairing}" == - ]]; then
        REPORT_DIR="${BASE}/${name}" "${SCRIPT_DIR}/pubsub-smoke.sh" "${ADAPTER}" "$@" 2>&1 | tee "${log}" || status=1
    else
        env "${pairing}" REPORT_DIR="${BASE}/${name}" "${SCRIPT_DIR}/pubsub-smoke.sh" "${ADAPTER}" "$@" 2>&1 | tee "${log}" || status=1
    fi
    local line
    line=$(grep -E '^\[pubsub-smoke\] [0-9]+ passed' "${log}" | tail -1)
    [[ -n "${line}" ]] || { echo "${name}: no count: the run did not finish"; status=1; return; }
    passed=$((passed + $(sed -E 's/.* ([0-9]+) passed.*/\1/' <<<"${line}")))
    failed=$((failed + $(sed -E 's/.* ([0-9]+) failed.*/\1/' <<<"${line}")))
}

# Alone: everything the capability document declares.
run self - codec udp-unicast udp-multicast mqtt-uadp mqtt-json mqtt-late-broker mqtt-v5 \
    udp-secure sign aes128 chunking delta-frames sks sks-push infomodel discovery

both="udp-unicast udp-multicast mqtt-uadp mqtt-json udp-secure sign aes128"
# An open62541 subscriber discards DeltaFrames, and open62541 has no chunking (§14.10).
# shellcheck disable=SC2086
run from-open62541 PUBLISHER_ADAPTER=open62541 codec-cross ${both} delta-frames sks sks-push
# shellcheck disable=SC2086
run to-open62541 SUBSCRIBER_ADAPTER=open62541 ${both} sks sks-push
# shellcheck disable=SC2086
run from-dotnet PUBLISHER_ADAPTER=dotnet codec-cross ${both} chunking mqtt-v5 discovery
# shellcheck disable=SC2086
run to-dotnet SUBSCRIBER_ADAPTER=dotnet ${both} chunking mqtt-v5
run probe-by-dotnet CLIENT_ADAPTER=dotnet discovery

echo "[pubsub-own] ${passed} passed, ${failed} failed"
[[ "${passed}" -gt 0 ]] || status=1
exit "${status}"
