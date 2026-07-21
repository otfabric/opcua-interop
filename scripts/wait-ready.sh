#!/usr/bin/env bash
# Wait for an OPC UA compat container to write its ready file.
# Usage: wait-ready.sh <container-name-or-id> [timeout-seconds]
#
# The ready file (/run/opcua-interop/ready) is written by the server only after
# the fixture has been loaded and the address space is available. Checking for
# a listening port is insufficient — readiness requires fixture initialization.

set -euo pipefail

CONTAINER="${1:?Usage: wait-ready.sh <container> [timeout-seconds]}"
TIMEOUT="${2:-60}"
READY_FILE="/run/opcua-interop/ready"
INTERVAL=1
elapsed=0

echo "Waiting for container '${CONTAINER}' to be ready (timeout: ${TIMEOUT}s)..." >&2

while true; do
    status=$(docker inspect --format='{{.State.Status}}' "${CONTAINER}" 2>/dev/null || echo "absent")

    if [[ "${status}" == "absent" ]]; then
        echo "Error: container '${CONTAINER}' not found." >&2
        exit 1
    fi

    if [[ "${status}" != "running" ]]; then
        echo "Error: container '${CONTAINER}' is in state '${status}'." >&2
        exit 1
    fi

    if docker exec "${CONTAINER}" test -f "${READY_FILE}" 2>/dev/null; then
        echo "Container '${CONTAINER}' is ready (${elapsed}s)." >&2
        exit 0
    fi

    if [[ "${elapsed}" -ge "${TIMEOUT}" ]]; then
        echo "Error: container '${CONTAINER}' not ready after ${TIMEOUT}s." >&2
        docker logs --tail=50 "${CONTAINER}" >&2 || true
        exit 1
    fi

    sleep "${INTERVAL}"
    elapsed=$((elapsed + INTERVAL))
done
