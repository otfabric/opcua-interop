#!/usr/bin/env bash
# Cross-stack smoke test for opcua-interop.
#
# Usage:
#   smoke.sh open62541 <image>                        # single-adapter smoke
#   smoke.sh milo <image>                             # single-adapter smoke
#   smoke.sh cross <image-open62541> <image-milo>     # cross-stack self-check
#
# Exit codes:
#   0  — all checks passed
#   1  — one or more checks failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
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
        --bind-address 0.0.0.0 \
        --bind-port 4840 \
        --advertised-host localhost \
        --endpoint-path "${ENDPOINT_PATH}" \
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

    # Replace localhost with host.docker.internal so the client container can
    # reach the host-published server port on both Linux and macOS Docker Desktop.
    local fixed_args=()
    for arg in "$@"; do
        fixed_args+=("${arg/localhost/host.docker.internal}")
    done

    docker run --rm \
        --add-host=host.docker.internal:host-gateway \
        "${client_image}" \
        client "${subcommand}" "${fixed_args[@]}"
}

# ── Envelope validation (requires jq) ────────────────────────────────────────

validate_envelope() {
    local output="$1"
    local label="$2"
    if ! echo "${output}" | jq -e '.schemaVersion and .adapter and (.success != null)' >/dev/null 2>&1; then
        fail "${label}: output is not a valid result envelope"
        return 1
    fi
    return 0
}

# ── Smoke checks ──────────────────────────────────────────────────────────────

check_endpoints() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local output
    if output=$(run_client_op "${client_image}" endpoints --endpoint "${endpoint}" 2>/dev/null); then
        validate_envelope "${output}" "${label}:endpoints" || return
        if echo "${output}" | jq -e '.success == true and (.results | length) > 0' >/dev/null 2>&1; then
            ok "${label}: endpoints"
        else
            fail "${label}: endpoints — success=false or empty results: ${output}"
        fi
    else
        fail "${label}: endpoints command exited non-zero"
    fi
}

check_browse() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local output
    if output=$(run_client_op "${client_image}" browse --endpoint "${endpoint}" --node "i=85" 2>/dev/null); then
        validate_envelope "${output}" "${label}:browse" || return
        if echo "${output}" | jq -e '.success == true and ([.results[].browseName.name? // .results[].nodeId?] | map(test("Compatibility")) | any)' >/dev/null 2>&1; then
            ok "${label}: browse found Compatibility node"
        else
            fail "${label}: browse — Compatibility not found in results: ${output}"
        fi
    else
        fail "${label}: browse command exited non-zero"
    fi
}

check_read_scalar() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32"
    local output
    if output=$(run_client_op "${client_image}" read --endpoint "${endpoint}" --node "${node}" 2>/dev/null); then
        validate_envelope "${output}" "${label}:read" || return
        if echo "${output}" | jq -e '.success == true and .results[0].statusCode.name == "Good"' >/dev/null 2>&1; then
            ok "${label}: read Scalar.Int32"
        else
            fail "${label}: read — unexpected result: ${output}"
        fi
    else
        fail "${label}: read command exited non-zero"
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
        validate_envelope "${output}" "${label}:write" || return
        if echo "${output}" | jq -e '.success == true and .results[0].statusCode.name == "Good"' >/dev/null 2>&1; then
            ok "${label}: write Access.ReadWrite"
        else
            fail "${label}: write — unexpected result: ${output}"
        fi
    else
        fail "${label}: write command exited non-zero"
    fi
}

check_call() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local obj="nsu=urn:otfabric:opcua-interop:model;s=Methods"
    local meth="nsu=urn:otfabric:opcua-interop:model;s=Methods.Add"
    local output
    if output=$(run_client_op "${client_image}" call \
            --endpoint "${endpoint}" \
            --object "${obj}" \
            --method "${meth}" \
            --input "Int32:10" \
            --input "Int32:20" 2>/dev/null); then
        validate_envelope "${output}" "${label}:call" || return
        if echo "${output}" | jq -e '.success == true and .results[0].statusCode.name == "Good" and (.results[0].outputArguments[0] == 30)' >/dev/null 2>&1; then
            ok "${label}: call Methods.Add(10,20)=30"
        else
            fail "${label}: call — unexpected result: ${output}"
        fi
    else
        fail "${label}: call command exited non-zero"
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
            --publishing-interval-ms 500 \
            --notifications 3 \
            --timeout-ms 15000 2>/dev/null); then
        validate_envelope "${output}" "${label}:subscribe" || return
        if echo "${output}" | jq -e '.success == true and (.results[0].notifications | length) == 3' >/dev/null 2>&1; then
            ok "${label}: subscribe Dynamic.Counter (3 notifications)"
        else
            fail "${label}: subscribe — unexpected result: ${output}"
        fi
    else
        fail "${label}: subscribe command exited non-zero"
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

    log "Running ${adapter} self-smoke"
    check_endpoints   "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_browse      "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_read_scalar "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_write       "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_call        "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_subscribe   "${image}" "${endpoint}" "${adapter}→${adapter}"

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
    check_endpoints   "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_browse      "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_read_scalar "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_write       "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_call        "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_subscribe   "${img_open62541}" "${ep_open62541}" "o62541→o62541"

    log "Cross-stack: open62541-client → milo-server"
    check_endpoints   "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_browse      "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_read_scalar "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_write       "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_call        "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_subscribe   "${img_open62541}" "${ep_milo}" "o62541→milo"

    log "Cross-stack: milo-client → open62541-server"
    check_endpoints   "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_browse      "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_read_scalar "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_write       "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_call        "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_subscribe   "${img_milo}" "${ep_open62541}" "milo→o62541"

    log "Cross-stack: milo-client → milo-server"
    check_endpoints   "${img_milo}" "${ep_milo}" "milo→milo"
    check_browse      "${img_milo}" "${ep_milo}" "milo→milo"
    check_read_scalar "${img_milo}" "${ep_milo}" "milo→milo"
    check_write       "${img_milo}" "${ep_milo}" "milo→milo"
    check_call        "${img_milo}" "${ep_milo}" "milo→milo"
    check_subscribe   "${img_milo}" "${ep_milo}" "milo→milo"

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

[[ "${FAIL}" -eq 0 ]]
