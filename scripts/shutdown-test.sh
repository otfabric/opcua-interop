#!/usr/bin/env bash
# Test graceful shutdown (SIGTERM → exit 0) for a single adapter.
#
# Usage:
#   shutdown-test.sh <open62541|milo> <image>
#
# Exit codes:
#   0  — container exited with code 0 after SIGTERM
#   1  — container exited with non-zero code, or timed out before ready

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ADAPTER="${1:?Usage: shutdown-test.sh <open62541|milo> <image>}"
IMAGE="${2:?Usage: shutdown-test.sh <open62541|milo> <image>}"

echo "[shutdown] Testing ${ADAPTER} graceful shutdown (SIGTERM → exit 0)..."

cname=$(docker run -d \
    -v "${REPO_ROOT}/fixtures:/fixtures:ro" \
    "${IMAGE}" \
    server \
    --fixture /fixtures/baseline/fixture.json \
    --bind-address 0.0.0.0 \
    --bind-port 4840 \
    --advertised-host localhost \
    --endpoint-path /opcua-interop \
    --ready-file /run/opcua-interop/ready)

cleanup() { docker rm -f "${cname}" 2>/dev/null || true; }
trap cleanup EXIT

"${SCRIPT_DIR}/wait-ready.sh" "${cname}" 60

docker stop --time=10 "${cname}"
exit_code=$(docker inspect --format='{{.State.ExitCode}}' "${cname}")
docker rm "${cname}"
trap - EXIT

if [[ "${exit_code}" -ne 0 ]]; then
    echo "[shutdown] ERROR: ${ADAPTER} exited with code ${exit_code} on SIGTERM" >&2
    exit 1
fi
echo "[shutdown] ${ADAPTER}: clean shutdown OK (exit code 0)"
