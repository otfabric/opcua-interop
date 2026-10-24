#!/usr/bin/env bash
# Cross-stack smoke test for opcua-interop.
#
# Usage:
#   smoke.sh open62541 <image>                        # single-adapter smoke
#   smoke.sh milo <image>                             # single-adapter smoke
#   smoke.sh async-opcua <image>                      # single-adapter smoke
#   smoke.sh cross <image-open62541> <image-milo> [image-async-opcua]
#                                                     # cross-stack self-check
#
# Exit codes:
#   0  — all checks passed
#   1  — one or more checks failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENDPOINT_PATH="/opcua-interop"
WAIT_TIMEOUT=60

MODE="${1:?Usage: smoke.sh <open62541|milo|async-opcua|cross> <image> [image-milo] [image-async-opcua]}"
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
        --ready-file /run/opcua-interop/ready \
        >/dev/null

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

    # Capture stdout; preserve docker exit code separately.
    # Strip any non-JSON prefix lines (e.g. the open62541 ANSI error/channel log
    # that is emitted during a BadSecureChannelClosed retry before the JSON envelope).
    local raw
    raw=$(docker run --rm \
        --add-host=host.docker.internal:host-gateway \
        "${client_image}" \
        client "${subcommand}" "${fixed_args[@]}" 2>/dev/null)
    local rc=$?
    # Output the first JSON line if present, otherwise pass raw output through
    # so callers still see something meaningful when JSON is absent.
    printf '%s\n' "${raw}" | grep -m1 '^{' || printf '%s\n' "${raw}"
    return ${rc}
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
    if output=$(run_client_op "${client_image}" endpoints --endpoint "${endpoint}"); then
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
    if output=$(run_client_op "${client_image}" browse --endpoint "${endpoint}" --node "i=85"); then
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
    if output=$(run_client_op "${client_image}" read --endpoint "${endpoint}" --node "${node}"); then
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
            --value 999); then
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
            --input "Int32:20"); then
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
            --timeout-ms 15000); then
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

check_register_nodes() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32"
    local output
    if output=$(run_client_op "${client_image}" register-nodes \
            --endpoint "${endpoint}" \
            --node "${node}"); then
        validate_envelope "${output}" "${label}:register-nodes" || return
        if echo "${output}" | jq -e '.success == true and .results[0].statusCode.name == "Good" and .results[0].unregisterStatusCode.name == "Good" and .results[0].value == -123456789' >/dev/null 2>&1; then
            ok "${label}: register-nodes Scalar.Int32"
        else
            fail "${label}: register-nodes — unexpected result: ${output}"
        fi
    else
        fail "${label}: register-nodes command exited non-zero"
    fi
}

# Subscribes across two SecureChannel lifetimes (~12 s at 2 notifications/s):
# the command only succeeds when every SecurityToken renewal is accepted and
# data keeps flowing. Lifetimes below ~5 s are not usable: the open62541 client
# schedules renewal coarsely and its old token can expire inside the 25% window.
check_channel_renewal() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Dynamic.Counter"
    local output
    if output=$(run_client_op "${client_image}" subscribe \
            --endpoint "${endpoint}" \
            --node "${node}" \
            --publishing-interval-ms 500 \
            --notifications 24 \
            --timeout-ms 40000 \
            --channel-lifetime-ms 6000); then
        validate_envelope "${output}" "${label}:channel-renewal" || return
        if echo "${output}" | jq -e '.success == true and (.results[0].notifications | length) == 24' >/dev/null 2>&1; then
            ok "${label}: subscribe across SecureChannel renewals (lifetime 6s)"
        else
            fail "${label}: channel renewal — unexpected result: ${output}"
        fi
    else
        fail "${label}: channel renewal subscribe exited non-zero"
    fi
}

# DataChangeFilter: an absolute deadband of 10 on the Analog.Level ramp (step 2)
# must be accepted and thin the notifications out; a percent deadband on a
# node without EURange must be rejected (exit 4, visible in the result).
check_deadband() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Analog.Level"
    local output
    if output=$(run_client_op "${client_image}" subscribe \
            --endpoint "${endpoint}" --node "${node}" \
            --publishing-interval-ms 200 --notifications 3 --timeout-ms 15000 \
            --deadband-absolute 10); then
        if echo "${output}" | jq -e '
              .success == true
              and .results[0].monitoredItemStatusCode.code == 0
              and .results[0].filter.deadbandType == "Absolute"
              and ([.results[0].notifications[].value] as $v
                   | [range(1; $v|length) | (($v[.] - $v[.-1]) | if . < 0 then 11 else . end)]
                   | all(. > 10))' >/dev/null 2>&1; then
            ok "${label}: subscribe with absolute deadband"
        else
            fail "${label}: deadband — unexpected result: ${output}"
        fi
    else
        fail "${label}: deadband subscribe exited non-zero"
    fi

    local ramp="nsu=urn:otfabric:opcua-interop:model;s=Dynamic.Ramp"
    output=$(run_client_op "${client_image}" subscribe \
            --endpoint "${endpoint}" --node "${ramp}" --notifications 1 \
            --deadband-percent 10) || true
    if echo "${output}" | jq -e '
          .success == false
          and .results[0].monitoredItemStatusCode.severity == "Bad"
          and .results[0].filter.deadbandType == "Percent"' >/dev/null 2>&1; then
        ok "${label}: percent deadband without EURange is rejected"
    else
        fail "${label}: percent deadband rejection — unexpected result: ${output}"
    fi
}

# codec short form: read a node and encode its Variant as JSON and XML.
check_codec_node() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"

    local node="nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32"
    local output
    if output=$(run_client_op "${client_image}" codec --endpoint "${endpoint}" --node "${node}"); then
        if echo "${output}" | jq -e '
              .success == true and .results[0].value == -123456789
              and (.results[0].json | fromjson | .UaType == 6 and .Value == -123456789)
              and (.results[0].xml | test("<([a-z]+:)?Int32>-123456789</"))
              and .results[0].binary == "BusypPg="' >/dev/null 2>&1; then
            ok "${label}: codec node (JSON + XML Variant)"
        else
            fail "${label}: codec node — unexpected result: ${output}"
        fi
    else
        fail "${label}: codec node exited non-zero"
    fi
}

# codec without a server: the encoder's document is decoded by the decoder
# (possibly the other stack) and must yield the same OPC UA Binary encoding.
check_codec_roundtrip() {
    local enc_image="$1"
    local dec_image="$2"
    local label="$3"

    local fmt type value
    for spec in "json|Int64|-1234567890123456789" "json|LocalizedText[]|[\"en:Hello\",\"de:Hallo\"]" \
                "xml|Double[]|1.5,2.5" "xml|String|interop"; do
        fmt="${spec%%|*}"; value="${spec#*|}"; type="${value%%|*}"; value="${value#*|}"
        local enc dec doc bin
        enc=$(docker run --rm "${enc_image}" client codec encode --format "${fmt}" \
                --type "${type}" --value "${value}" 2>/dev/null | grep -m1 '^{') || true
        doc=$(echo "${enc}" | jq -r '.results[0].encoded.variant // empty')
        bin=$(echo "${enc}" | jq -r '.results[0].binary.variant // empty')
        if [[ -z "${doc}" || -z "${bin}" ]]; then
            fail "${label}: codec encode ${fmt} ${type}: ${enc}"
            continue
        fi
        dec=$(printf '%s' "${doc}" | docker run --rm -i "${dec_image}" client codec decode \
                --format "${fmt}" --type Variant 2>/dev/null | grep -m1 '^{') || true
        if echo "${dec}" | jq -e --arg bin "${bin}" \
              '.success == true and .results[0].binary == $bin' >/dev/null 2>&1; then
            ok "${label}: codec ${fmt} ${type} round trip (binary identical)"
        else
            fail "${label}: codec decode ${fmt} ${type}: ${dec}"
        fi
    done
}

# ── open62541 feature smoke: ECC, reverse connect, LDS / mDNS ─────────────────
#
# These need container-to-container addressing (the server dials the client,
# servers register with an LDS, mDNS), so they run on a dedicated Docker
# network with the test PKI mounted.

FEAT_NET=""
FEAT_TMP=""
FEAT_CONTAINERS=()

feature_cleanup() {
    local c
    for c in ${FEAT_CONTAINERS[@]+"${FEAT_CONTAINERS[@]}"}; do
        docker rm -f "${c}" &>/dev/null || true
    done
    FEAT_CONTAINERS=()
    if [[ -n "${FEAT_NET}" ]]; then docker network rm "${FEAT_NET}" &>/dev/null || true; FEAT_NET=""; fi
    if [[ -n "${FEAT_TMP}" ]]; then rm -rf "${FEAT_TMP}"; FEAT_TMP=""; fi
}

# A world-readable copy of the test PKI (generated on demand; an existing CA
# and its RSA identities are kept and only the ECC certificates are added).
prepare_pki() {
    local pki="${OPCUA_INTEROP_PKI_DIR:-${REPO_ROOT}/certs/test-pki}"
    if [[ ! -f "${pki}/ca/ca.crt" ]]; then
        log "Generating test PKI..."
        "${REPO_ROOT}/certs/generate.sh" >/dev/null 2>&1
    elif [[ ! -f "${pki}/open62541-server/ecc-nistp256/cert.crt" ]]; then
        log "Adding ECC certificates to the test PKI..."
        "${REPO_ROOT}/certs/generate.sh" --add-ecc >/dev/null 2>&1
    fi
    FEAT_TMP=$(mktemp -d "${TMPDIR:-/tmp}/opcua-interop-smoke.XXXXXX")
    cp -R "${pki}" "${FEAT_TMP}/pki"
    chmod -R a+rwX "${FEAT_TMP}"
}

# feat_client <image> <container-name|-> <args...>: client on the feature network.
feat_client() {
    local image="$1" name="$2"
    shift 2
    local name_args=()
    if [[ "${name}" != "-" ]]; then
        docker rm -f "${name}" &>/dev/null || true
        name_args=(--name "${name}")
    fi
    local raw rc=0
    raw=$(docker run --rm ${name_args[@]+"${name_args[@]}"} --network "${FEAT_NET}" \
            -v "${FEAT_TMP}/pki:/pki" "${image}" client "$@" 2>/dev/null) || rc=$?
    printf '%s\n' "${raw}" | grep -m1 '^{' || printf '%s\n' "${raw}"
    return ${rc}
}

feat_expect() {
    local label="$1" filter="$2" output="$3"
    if echo "${output}" | jq -e "${filter}" >/dev/null 2>&1; then
        ok "${label}"
    else
        fail "${label}: ${output}"
    fi
}

# run_open62541_features <open62541-image> [milo-image]
run_open62541_features() {
    local img="$1"
    local img_milo="${2:-}"
    local model="nsu=urn:otfabric:opcua-interop:model;s="

    prepare_pki
    FEAT_NET="smoke-net-$$"
    docker network create "${FEAT_NET}" >/dev/null

    local lds="smoke-lds-$$" member="smoke-member-$$" rclient="smoke-rclient-$$"
    local lds_url="opc.tcp://${lds}:4840${ENDPOINT_PATH}"
    FEAT_CONTAINERS+=("${lds}" "${member}" "${rclient}")

    # One open62541 server: RSA + ECC endpoints, Local Discovery Server with
    # mDNS, and a reverse connection towards the (not yet running) client.
    log "Starting open62541 feature server (ECC, LDS, reverse connect)..."
    docker run -d --name "${lds}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${lds}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
        --pki-dir /pki/open62541-server/pki --ecc-dir /pki/open62541-server \
        --lds --reverse-connect "opc.tcp://${rclient}:4855" >/dev/null
    wait_ready "${lds}"

    # A second server registers with the LDS (Milo in cross mode).
    local member_img="${img}" member_extra=(--mdns-name smoke-member)
    local member_name="open62541"
    if [[ -n "${img_milo}" ]]; then member_img="${img_milo}"; member_extra=(); member_name="milo"; fi
    log "Starting ${member_name} server registering with the LDS..."
    docker run -d --name "${member}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" \
        "${member_img}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${member}" --endpoint-path "${ENDPOINT_PATH}" \
        --register-with "${lds_url}" --register-interval-ms 2000 \
        ${member_extra[@]+"${member_extra[@]}"} >/dev/null
    wait_ready "${member}"

    local rsa=(--certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key
               --trust-list /pki/ca/ca.crt)
    local out curve policy mode

    # RSA over the OpenSSL backend (the pre-0.7.0 policies).
    out=$(feat_client "${img}" - read --endpoint "${lds_url}" --node "${model}Scalar.Int32" \
            --security-policy Basic256Sha256 --security-mode SignAndEncrypt "${rsa[@]}" \
            --username test-user --password test-password) || true
    feat_expect "o62541→o62541: Basic256Sha256/SignAndEncrypt + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    if [[ -n "${img_milo}" ]]; then
        out=$(feat_client "${img_milo}" - read --endpoint "${lds_url}" --node "${model}Scalar.Int32" \
                --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt \
                --certificate /pki/milo-client/cert.crt --private-key /pki/milo-client/cert.key \
                --trust-list /pki/ca/ca.crt) || true
        feat_expect "milo→o62541: Aes256_Sha256_RsaPss/SignAndEncrypt" \
            '.success == true and .results[0].value == -123456789' "${out}"
    fi

    # ECC policies, each with the certificate of its curve; username/password
    # travels as an EccEncryptedSecret.
    for spec in "ECC_nistP256 nistp256 SignAndEncrypt" "ECC_nistP384 nistp384 Sign" \
                "ECC_brainpoolP256r1 brainpoolp256r1 SignAndEncrypt" \
                "ECC_curve25519 curve25519 SignAndEncrypt" \
                "ECC_nistP256_AesGcm nistp256 SignAndEncrypt"; do
        read -r policy curve mode <<<"${spec}"
        out=$(feat_client "${img}" - read --endpoint "${lds_url}" --node "${model}Scalar.Int32" \
                --security-policy "${policy}" --security-mode "${mode}" \
                --certificate "/pki/open62541-client/ecc-${curve}/cert.crt" \
                --private-key "/pki/open62541-client/ecc-${curve}/cert.key" \
                --trust-list /pki/ca/ca.crt \
                --username test-user --password test-password) || true
        feat_expect "o62541→o62541: ${policy}/${mode} + username" \
            '.success == true and .results[0].value == -123456789' "${out}"
    done
    out=$(feat_client "${img}" - read --endpoint "${lds_url}" --node "${model}Scalar.Int32" \
            --security-policy ECC_nistP256 --security-mode SignAndEncrypt \
            --certificate /pki/untrusted/ecc-nistp256/cert.crt \
            --private-key /pki/untrusted/ecc-nistp256/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    feat_expect "o62541→o62541: untrusted ECC certificate is rejected" \
        '.success == false and .serviceResult.severity == "Bad"' "${out}"

    # Reverse connect: the client listens, the server dials in (ReverseHello).
    out=$(feat_client "${img}" "${rclient}" read --endpoint "${lds_url}" \
            --node "${model}Scalar.Int32" --reverse-listen 4855 --reverse-timeout-ms 30000 \
            --reverse-server-uri urn:otfabric:opcua-interop:server) || true
    feat_expect "o62541 reverse connect: None/None" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img}" "${rclient}" subscribe --endpoint "${lds_url}" \
            --node "${model}Dynamic.Counter" --notifications 2 \
            --reverse-listen 4855 --reverse-timeout-ms 30000 \
            --security-policy ECC_nistP256 --security-mode SignAndEncrypt \
            --certificate /pki/open62541-client/ecc-nistp256/cert.crt \
            --private-key /pki/open62541-client/ecc-nistp256/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    feat_expect "o62541 reverse connect: ECC_nistP256/SignAndEncrypt subscription" \
        '.success == true and (.results[0].notifications | length) == 2' "${out}"
    out=$(feat_client "${img}" "${rclient}" endpoints --endpoint "${lds_url}" \
            --reverse-listen 4855 --reverse-timeout-ms 30000) || true
    feat_expect "o62541 reverse connect: GetEndpoints" \
        '.success == true and (.results | length) > 1' "${out}"

    # Discovery: the member registered itself (RegisterServer2), a client
    # registers / unregisters a made-up server, mDNS records are served.
    local clients=("${img}")
    local names=("o62541")
    if [[ -n "${img_milo}" ]]; then clients+=("${img_milo}"); names+=("milo"); fi
    out=$(feat_client "${img}" - find-servers --endpoint "${lds_url}") || true
    feat_expect "LDS FindServers lists the registered ${member_name} server" \
        "[.results[].discoveryUrls[]] | index(\"opc.tcp://${member}:4840${ENDPOINT_PATH}\") != null" "${out}"
    local i
    for i in "${!clients[@]}"; do
        local c="${clients[$i]}" n="${names[$i]}"
        out=$(feat_client "${c}" - find-servers-on-network --endpoint "${lds_url}") || true
        feat_expect "${n}→LDS: FindServersOnNetwork (LDS record + registered server)" \
            ".success == true
             and ([.results[] | select(.serverCapabilities | index(\"LDS\"))] | length) >= 1
             and ([.results[] | select(.discoveryUrl | test(\"${member}\"))] | length) >= 1" "${out}"
        out=$(feat_client "${c}" - register-server --endpoint "${lds_url}" \
                --server-uri "urn:smoke:${n}" --server-name "smoke ${n}" \
                --discovery-url "opc.tcp://smoke-${n}:4999" --mdns-name "smoke-${n}") || true
        feat_expect "${n}→LDS: register-server (RegisterServer2)" \
            '.success == true and .results[0].service == "RegisterServer2"' "${out}"
        out=$(feat_client "${img}" - find-servers --endpoint "${lds_url}") || true
        feat_expect "${n}→LDS: registration visible in FindServers" \
            "[.results[].applicationUri] | index(\"urn:smoke:${n}\") != null" "${out}"
        out=$(feat_client "${c}" - register-server --endpoint "${lds_url}" \
                --server-uri "urn:smoke:${n}" --discovery-url "opc.tcp://smoke-${n}:4999" \
                --mdns-name "smoke-${n}" --online false) || true
        out=$(feat_client "${img}" - find-servers --endpoint "${lds_url}") || true
        feat_expect "${n}→LDS: unregistered server is gone" \
            "[.results[].applicationUri] | index(\"urn:smoke:${n}\") == null" "${out}"
    done
    out=$(feat_client "${img}" - register-server --endpoint "opc.tcp://${member}:4840${ENDPOINT_PATH}" \
            --server-uri urn:smoke:x --discovery-url opc.tcp://x:1) || true
    feat_expect "register-server against a non-LDS (${member_name}) reports the service fault" \
        '.success == false and .results[0].fallback == true' "${out}"

    feature_cleanup
}

# ── async-opcua cross-stack checks ────────────────────────────────────────────

# async-opcua 0.19 answers ActivateSession over SecurityPolicy None with a null
# ServerNonce (SecurityPolicy::random_nonce, Part 4 §5.6.3.2 asks for at least
# 32 bytes); the open62541 1.5.9 client rejects that with
# BadSecurityChecksFailed. Over a secured channel the nonce is 32 bytes and
# open62541 interoperates (run_async_opcua_secure_cross). The check fails when
# the deviation is gone, so the full None/None set gets enabled again.
check_o62541_none_deviation() {
    local client_image="$1" endpoint="$2"
    local node="nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32"
    local output
    output=$(run_client_op "${client_image}" read --endpoint "${endpoint}" --node "${node}") || true
    validate_envelope "${output}" "o62541→async-opcua:read" || return
    if echo "${output}" | jq -e '.success == false and .serviceResult.name == "BadSecurityChecksFailed"' >/dev/null 2>&1; then
        ok "o62541→async-opcua: None/None session refused (known async-opcua 0.19 deviation: null ActivateSession nonce)"
    elif echo "${output}" | jq -e '.success == true' >/dev/null 2>&1; then
        fail "o62541→async-opcua: None/None read succeeded — the ActivateSession nonce deviation is gone; run check_interop_set for this pair"
    else
        fail "o62541→async-opcua: None/None read — unexpected result: ${output}"
    fi
}

# Secured channels to an async-opcua server on the feature network, with the
# test PKI identities: open62541 (whose None/None sessions fail, see above)
# and Milo clients, Basic256Sha256 and the Aes policies, a UserName token, and
# the rejection of an untrusted client certificate.
run_async_opcua_secure_cross() {
    local img_open62541="$1" img_milo="$2" img_async_opcua="$3"
    local model="nsu=urn:otfabric:opcua-interop:model;s="

    prepare_pki
    if [[ ! -f "${FEAT_TMP}/pki/async-opcua-server/cert.crt" ]]; then
        fail "async-opcua secure cross-stack: the test PKI has no async-opcua-server identity (certs/generate.sh --add-async-opcua)"
        feature_cleanup
        return
    fi
    FEAT_NET="smoke-net-$$"
    docker network create "${FEAT_NET}" >/dev/null

    local srv="smoke-async-opcua-sec-$$"
    local url="opc.tcp://${srv}:4840${ENDPOINT_PATH}"
    FEAT_CONTAINERS+=("${srv}")
    log "Starting async-opcua server with certificate (secure endpoints)..."
    docker run -d --name "${srv}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img_async_opcua}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${srv}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/async-opcua-server/cert.crt --private-key /pki/async-opcua-server/cert.key \
        --pki-dir /pki/async-opcua-server/pki >/dev/null
    wait_ready "${srv}"

    local o62541=(--certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key
                  --trust-list /pki/ca/ca.crt)
    local b256=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt)
    local out
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - write --endpoint "${url}" --node "${model}Access.ReadWrite" \
            --type Int32 --value 4242 "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt write" \
        '.success == true and .results[0].statusCode.name == "Good"' "${out}"
    out=$(feat_client "${img_open62541}" - call --endpoint "${url}" --object "${model}Methods" \
            --method "${model}Methods.Add" --input Int32:10 --input Int32:20 "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt call Methods.Add(10,20)=30" \
        '.success == true and .results[0].outputArguments[0] == 30' "${out}"
    out=$(feat_client "${img_open62541}" - subscribe --endpoint "${url}" --node "${model}Dynamic.Counter" \
            --publishing-interval-ms 500 --notifications 3 --timeout-ms 15000 \
            "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt subscribe Dynamic.Counter" \
        '.success == true and (.results[0].notifications | length) >= 3' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Basic256Sha256 --security-mode Sign "${o62541[@]}" \
            --username test-user --password test-password) || true
    feat_expect "o62541→async-opcua: Basic256Sha256/Sign + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes128_Sha256_RsaOaep --security-mode SignAndEncrypt "${o62541[@]}") || true
    feat_expect "o62541→async-opcua: Aes128_Sha256_RsaOaep/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt \
            --certificate /pki/milo-client/cert.crt --private-key /pki/milo-client/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    feat_expect "milo→async-opcua: Aes256_Sha256_RsaPss/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" --certificate /pki/untrusted/cert.crt --private-key /pki/untrusted/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    feat_expect "o62541→async-opcua: untrusted client certificate is rejected" \
        '.success == false' "${out}"

    feature_cleanup
}

# ── Mode: single adapter ──────────────────────────────────────────────────────

# The client/server checks every adapter pair runs (no codec: the async-opcua
# adapter has no codec operation, see async-opcua/README.md).
check_interop_set() {
    local image="$1" endpoint="$2" label="$3"
    check_endpoints   "${image}" "${endpoint}" "${label}"
    check_browse      "${image}" "${endpoint}" "${label}"
    check_read_scalar "${image}" "${endpoint}" "${label}"
    check_write       "${image}" "${endpoint}" "${label}"
    check_call        "${image}" "${endpoint}" "${label}"
    check_subscribe   "${image}" "${endpoint}" "${label}"
    check_register_nodes "${image}" "${endpoint}" "${label}"
    check_channel_renewal "${image}" "${endpoint}" "${label}"
    check_deadband "${image}" "${endpoint}" "${label}"
}

run_single_smoke() {
    local adapter="$1"
    local image="$2"
    local port=14840

    local cname
    cname=$(start_server "${adapter}" "${image}" "${port}")
    trap "stop_server ${cname}; feature_cleanup" EXIT

    wait_ready "${cname}"

    local endpoint="opc.tcp://localhost:${port}${ENDPOINT_PATH}"

    log "Running ${adapter} self-smoke"
    check_endpoints   "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_browse      "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_read_scalar "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_write       "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_call        "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_subscribe   "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_register_nodes "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_channel_renewal "${image}" "${endpoint}" "${adapter}→${adapter}"
    check_deadband "${image}" "${endpoint}" "${adapter}→${adapter}"
    if [[ "${adapter}" != "async-opcua" ]]; then
        check_codec_node "${image}" "${endpoint}" "${adapter}→${adapter}"
        check_codec_roundtrip "${image}" "${image}" "${adapter}→${adapter}"
    fi

    stop_server "${cname}"
    if [[ "${adapter}" == "open62541" ]]; then
        run_open62541_features "${image}"
    fi
    trap - EXIT
}

# ── Mode: cross-stack ─────────────────────────────────────────────────────────

run_cross_smoke() {
    local img_open62541="$1"
    local img_milo="$2"
    local img_async_opcua="${3:-}"
    local port_open62541=14840
    local port_milo=14841
    local port_async_opcua=14842

    local cname_open62541 cname_milo
    cname_open62541=$(start_server "open62541" "${img_open62541}" "${port_open62541}")
    cname_milo=$(start_server "milo" "${img_milo}" "${port_milo}")
    trap "stop_server ${cname_open62541}; stop_server ${cname_milo}; feature_cleanup" EXIT

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
    check_register_nodes "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_channel_renewal "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_deadband "${img_open62541}" "${ep_open62541}" "o62541→o62541"
    check_codec_node "${img_open62541}" "${ep_open62541}" "o62541→o62541"

    log "Cross-stack: open62541-client → milo-server"
    check_endpoints   "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_browse      "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_read_scalar "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_write       "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_call        "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_subscribe   "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_register_nodes "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_channel_renewal "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_deadband "${img_open62541}" "${ep_milo}" "o62541→milo"
    check_codec_node "${img_open62541}" "${ep_milo}" "o62541→milo"

    log "Cross-stack: milo-client → open62541-server"
    check_endpoints   "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_browse      "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_read_scalar "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_write       "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_call        "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_subscribe   "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_register_nodes "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_channel_renewal "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_deadband "${img_milo}" "${ep_open62541}" "milo→o62541"
    check_codec_node "${img_milo}" "${ep_open62541}" "milo→o62541"

    log "Cross-stack: milo-client → milo-server"
    check_endpoints   "${img_milo}" "${ep_milo}" "milo→milo"
    check_browse      "${img_milo}" "${ep_milo}" "milo→milo"
    check_read_scalar "${img_milo}" "${ep_milo}" "milo→milo"
    check_write       "${img_milo}" "${ep_milo}" "milo→milo"
    check_call        "${img_milo}" "${ep_milo}" "milo→milo"
    check_subscribe   "${img_milo}" "${ep_milo}" "milo→milo"
    check_register_nodes "${img_milo}" "${ep_milo}" "milo→milo"
    check_channel_renewal "${img_milo}" "${ep_milo}" "milo→milo"
    check_deadband "${img_milo}" "${ep_milo}" "milo→milo"
    check_codec_node "${img_milo}" "${ep_milo}" "milo→milo"

    if [[ -n "${img_async_opcua}" ]]; then
        local cname_async_opcua
        cname_async_opcua=$(start_server "async-opcua" "${img_async_opcua}" "${port_async_opcua}")
        trap "stop_server ${cname_open62541}; stop_server ${cname_milo}; stop_server ${cname_async_opcua}; feature_cleanup" EXIT
        wait_ready "${cname_async_opcua}"
        local ep_async_opcua="opc.tcp://localhost:${port_async_opcua}${ENDPOINT_PATH}"

        log "Cross-stack: milo-client → async-opcua-server"
        check_interop_set "${img_milo}" "${ep_async_opcua}" "milo→async-opcua"
        log "Cross-stack: open62541-client → async-opcua-server (SecurityPolicy None)"
        check_o62541_none_deviation "${img_open62541}" "${ep_async_opcua}"
        log "Cross-stack: async-opcua-client → open62541 / milo / async-opcua servers"
        check_interop_set "${img_async_opcua}" "${ep_open62541}" "async-opcua→o62541"
        check_interop_set "${img_async_opcua}" "${ep_milo}" "async-opcua→milo"
        check_interop_set "${img_async_opcua}" "${ep_async_opcua}" "async-opcua→async-opcua"
        stop_server "${cname_async_opcua}"
        trap "stop_server ${cname_open62541}; stop_server ${cname_milo}; feature_cleanup" EXIT
        run_async_opcua_secure_cross "${img_open62541}" "${img_milo}" "${img_async_opcua}"
    fi

    log "Cross-stack: codec documents of one stack decoded by the other"
    check_codec_roundtrip "${img_open62541}" "${img_milo}" "o62541→milo"
    check_codec_roundtrip "${img_milo}" "${img_open62541}" "milo→o62541"

    stop_server "${cname_open62541}"
    stop_server "${cname_milo}"

    log "Cross-stack: open62541 features with a Milo peer (registration, RSA client)"
    run_open62541_features "${img_open62541}" "${img_milo}"
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
    async-opcua)
        run_single_smoke "async-opcua" "${1:?image required}"
        ;;
    cross)
        run_cross_smoke "${1:?open62541 image required}" "${2:?milo image required}" "${3:-}"
        ;;
    *)
        echo "Unknown mode: ${MODE}. Use open62541, milo, async-opcua, or cross." >&2
        exit 1
        ;;
esac

echo ""
log "Results: ${PASS} passed, ${FAIL} failed"

[[ "${FAIL}" -eq 0 ]]
