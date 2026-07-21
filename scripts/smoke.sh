#!/usr/bin/env bash
# Cross-stack smoke test for opcua-interop.
#
# Usage:
#   smoke.sh open62541 <image>           # single-adapter smoke
#   smoke.sh milo <image>                # single-adapter smoke
#   smoke.sh cross <image-open62541> <image-milo>  # cross-stack self-check
#
# This script proves both adapters realize the same baseline contract. It is a
# repository self-check, not a product compatibility matrix. Test assertions
# belong in consumer repositories.
#
# Exit codes:
#   0  — all checks passed
#   1  — one or more checks failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${REPO_ROOT}/fixtures/baseline/fixture.json"
ENDPOINT_PATH="/opcua-interop"
WAIT_TIMEOUT=60

MODE="${1:?Usage: smoke.sh <open62541|milo|cross> <image> [image-milo]}"
shift

PASS=0
FAIL=0

log()  { echo "[smoke] $*" >&2; }
ok()   { log "OK: $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); }

# ── Container lifecycle helpers ───────────────────────────────────────────────

start_server() {
    local name="$1"
    local image="$2"
    local port="$3"

    log "Starting ${name} (${image}) on port ${port}..."

    docker run -d \
        --name "smoke-${name}-$$" \
        -p "${port}:4840" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" \
        "${image}" \
        server \
        --fixture /fixtures/baseline/fixture.json \
        --endpoint "opc.tcp://0.0.0.0:4840${ENDPOINT_PATH}" \
        --ready-file /run/opcua-interop/ready

    echo "smoke-${name}-$$"
}

stop_server() {
    local cname="$1"
    docker rm -f "${cname}" &>/dev/null || true
}

wait_ready() {
    local cname="$1"
    "${SCRIPT_DIR}/wait-ready.sh" "${cname}" "${WAIT_TIMEOUT}"
}

run_client_op() {
    local client_image="$1"
    local subcommand="$2"
    shift 2

    docker run --rm \
        --network host \
        "${client_image}" \
        client "${subcommand}" "$@"
}

# ── Smoke checks ─────────────────────────────────────────────────────────────

check_endpoints() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local output
    if output=$(run_client_op "${client_image}" endpoints --endpoint "${endpoint}" 2>/dev/null); then
        if echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d.get('results',[])) > 0" 2>/dev/null; then
            ok "${label}: endpoints returned at least one endpoint"
        else
            fail "${label}: endpoints returned empty results"
        fi
    else
        fail "${label}: endpoints command failed"
    fi
}

check_read_scalar() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32"
    local output
    if output=$(run_client_op "${client_image}" read --endpoint "${endpoint}" --node "${node}" 2>/dev/null); then
        if echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('success') is True" 2>/dev/null; then
            ok "${label}: read Scalar.Int32"
        else
            fail "${label}: read Scalar.Int32 returned success=false"
        fi
    else
        fail "${label}: read command failed"
    fi
}

check_write() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Access.ReadWrite"
    local output
    if output=$(run_client_op "${client_image}" write \
            --endpoint "${endpoint}" \
            --node "${node}" \
            --type Int32 \
            --value 999 2>/dev/null); then
        if echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('success') is True" 2>/dev/null; then
            ok "${label}: write Access.ReadWrite"
        else
            fail "${label}: write returned success=false"
        fi
    else
        fail "${label}: write command failed"
    fi
}

check_browse() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local output
    if output=$(run_client_op "${client_image}" browse --endpoint "${endpoint}" --node "i=85" 2>/dev/null); then
        if echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert any('Compatibility' in str(r) for r in d.get('results',[]))" 2>/dev/null; then
            ok "${label}: browse Objects found Compatibility node"
        else
            fail "${label}: browse did not find Compatibility node"
        fi
    else
        fail "${label}: browse command failed"
    fi
}

check_call_add() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local object="nsu=urn:otfabric:opcua-interop:model;s=Methods"
    local method="nsu=urn:otfabric:opcua-interop:model;s=Methods.Add"
    local output
    if output=$(run_client_op "${client_image}" call \
            --endpoint "${endpoint}" \
            --object "${object}" \
            --method "${method}" \
            --input "Int32:10" \
            --input "Int32:20" 2>/dev/null); then
        if echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('success') is True and any(r.get('value')==30 for r in d.get('results',[]))" 2>/dev/null; then
            ok "${label}: call Add(10,20)=30"
        else
            fail "${label}: call Add returned unexpected result"
        fi
    else
        fail "${label}: call command failed"
    fi
}

check_subscribe() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Dynamic.Counter"
    local output
    if output=$(run_client_op "${client_image}" subscribe \
            --endpoint "${endpoint}" \
            --node "${node}" \
            --publishing-interval 250 \
            --notifications 2 \
            --timeout 10s 2>/dev/null); then
        if echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('success') is True and len(d.get('notifications',[])) >= 2" 2>/dev/null; then
            ok "${label}: subscribe received ≥2 counter notifications"
        else
            fail "${label}: subscribe returned insufficient notifications"
        fi
    else
        fail "${label}: subscribe command failed"
    fi
}

# ── Mode: single adapter ──────────────────────────────────────────────────────

run_single_smoke() {
    local adapter="$1"
    local image="$2"
    local port=14840

    local cname
    cname=$(start_server "${adapter}" "${image}" "${port}")
    trap "stop_server ${cname}" EXIT

    wait_ready "${cname}"

    local endpoint="opc.tcp://localhost:${port}${ENDPOINT_PATH}"

    log "Running ${adapter} self-smoke: client=${adapter} server=${adapter}"
    check_endpoints  "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_browse     "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_read_scalar "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_write      "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_call_add   "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_subscribe  "${image}" "${endpoint}" "${adapter}→${adapter}"

    stop_server "${cname}"
    trap - EXIT
}

# ── Mode: cross-stack ─────────────────────────────────────────────────────────

run_cross_smoke() {
    local img_open62541="$1"
    local img_milo="$2"
    local port_open62541=14840
    local port_milo=14841

    local cname_open62541 cname_milo
    cname_open62541=$(start_server "open62541" "${img_open62541}" "${port_open62541}")
    cname_milo=$(start_server "milo" "${img_milo}" "${port_milo}")
    trap "stop_server ${cname_open62541}; stop_server ${cname_milo}" EXIT

    wait_ready "${cname_open62541}"
    wait_ready "${cname_milo}"

    local ep_open62541="opc.tcp://localhost:${port_open62541}${ENDPOINT_PATH}"
    local ep_milo="opc.tcp://localhost:${port_milo}${ENDPOINT_PATH}"

    log "Cross-stack: open62541-client → open62541-server"
    check_endpoints  "${img_open62541}" "${ep_open62541}" "o62541-client→o62541-server"
    check_browse     "${img_open62541}" "${ep_open62541}" "o62541-client→o62541-server"
    check_read_scalar "${img_open62541}" "${ep_open62541}" "o62541-client→o62541-server"
    check_call_add   "${img_open62541}" "${ep_open62541}" "o62541-client→o62541-server"
    check_subscribe  "${img_open62541}" "${ep_open62541}" "o62541-client→o62541-server"

    log "Cross-stack: open62541-client → milo-server"
    check_endpoints  "${img_open62541}" "${ep_milo}" "o62541-client→milo-server"
    check_browse     "${img_open62541}" "${ep_milo}" "o62541-client→milo-server"
    check_read_scalar "${img_open62541}" "${ep_milo}" "o62541-client→milo-server"
    check_call_add   "${img_open62541}" "${ep_milo}" "o62541-client→milo-server"
    check_subscribe  "${img_open62541}" "${ep_milo}" "o62541-client→milo-server"

    log "Cross-stack: milo-client → open62541-server"
    check_endpoints  "${img_milo}" "${ep_open62541}" "milo-client→o62541-server"
    check_browse     "${img_milo}" "${ep_open62541}" "milo-client→o62541-server"
    check_read_scalar "${img_milo}" "${ep_open62541}" "milo-client→o62541-server"
    check_call_add   "${img_milo}" "${ep_open62541}" "milo-client→o62541-server"
    check_subscribe  "${img_milo}" "${ep_open62541}" "milo-client→o62541-server"

    log "Cross-stack: milo-client → milo-server"
    check_endpoints  "${img_milo}" "${ep_milo}" "milo-client→milo-server"
    check_browse     "${img_milo}" "${ep_milo}" "milo-client→milo-server"
    check_read_scalar "${img_milo}" "${ep_milo}" "milo-client→milo-server"
    check_call_add   "${img_milo}" "${ep_milo}" "milo-client→milo-server"
    check_subscribe  "${img_milo}" "${ep_milo}" "milo-client→milo-server"

    stop_server "${cname_open62541}"
    stop_server "${cname_milo}"
    trap - EXIT
}

# ── Entry point ───────────────────────────────────────────────────────────────

case "${MODE}" in
    open62541)
        run_single_smoke "open62541" "${1:?image required}"
        ;;
    milo)
        run_single_smoke "milo" "${1:?image required}"
        ;;
    cross)
        run_cross_smoke "${1:?open62541 image required}" "${2:?milo image required}"
        ;;
    *)
        echo "Unknown mode: ${MODE}. Use open62541, milo, or cross." >&2
        exit 1
        ;;
esac

echo ""
log "Results: ${PASS} passed, ${FAIL} failed"

if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
