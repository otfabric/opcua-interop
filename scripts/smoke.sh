#!/usr/bin/env bash
# Cross-stack smoke test for opcua-interop.
#
# Usage:
#   smoke.sh open62541 <image>                        # single-adapter smoke
#   smoke.sh milo <image>                             # single-adapter smoke
#   smoke.sh async-opcua <image>                      # single-adapter smoke
#   smoke.sh dotnet <image>                           # single-adapter smoke
#   smoke.sh node-opcua <image>                       # single-adapter smoke
#   smoke.sh cross <image-open62541> <image-milo> [image-async-opcua] [image-node-opcua]
#                                                     # cross-stack self-check
#   smoke.sh cross-dotnet <image-dotnet> <image-open62541> <image-milo>
#                                                     # dotnet against both reference stacks
#   smoke.sh asyncua <image>                          # single-adapter smoke
#   smoke.sh cross-asyncua <image-asyncua> <image-open62541> <image-milo> [image-async-opcua] [image-dotnet]
#                                                     # asyncua against the reference stacks
#
# Exit codes:
#   0  — all checks passed
#   1  — one or more checks failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENDPOINT_PATH="/opcua-interop"
WAIT_TIMEOUT=60

MODE="${1:?Usage: smoke.sh <open62541|milo|async-opcua|dotnet|node-opcua|asyncua|cross|cross-dotnet|cross-asyncua> <image> [images...]}"
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
# The optional fourth argument limits the formats (default "json xml").
check_codec_roundtrip() {
    local enc_image="$1"
    local dec_image="$2"
    local label="$3"
    local formats="${4:-json xml}"

    local fmt type value
    for spec in "json|Int64|-1234567890123456789" "json|LocalizedText[]|[\"en:Hello\",\"de:Hallo\"]" \
                "xml|Double[]|1.5,2.5" "xml|String|interop"; do
        fmt="${spec%%|*}"; value="${spec#*|}"; type="${value%%|*}"; value="${value#*|}"
        [[ " ${formats} " == *" ${fmt} "* ]] || continue
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

# open62541 writes XML documents without the UA Types namespace
# (<Variant><Value><String>); the UA-.NETStandard XmlDecoder only reads
# namespace-qualified elements and must refuse them (a stack limit,
# docs/CLIENT_CONTRACT.md §4, reported, not worked around).
check_codec_xml_unqualified_rejected() {
    local enc_image="$1"
    local dec_image="$2"
    local label="$3"

    local enc doc dec
    enc=$(docker run --rm "${enc_image}" client codec encode --format xml \
            --type String --value interop 2>/dev/null | grep -m1 '^{') || true
    doc=$(echo "${enc}" | jq -r '.results[0].encoded.variant // empty')
    if [[ -z "${doc}" || "${doc}" == *"xmlns="* || "${doc}" == *"xmlns:"* ]]; then
        fail "${label}: expected an XML document without namespace: ${enc}"
        return
    fi
    dec=$(printf '%s' "${doc}" | docker run --rm -i "${dec_image}" client codec decode \
            --format xml --type Variant 2>/dev/null | grep -m1 '^{') || true
    if echo "${dec}" | jq -e '.success == false and .results[0].statusCode.name == "BadDecodingError"' >/dev/null 2>&1; then
        ok "${label}: codec xml without the UA Types namespace is refused (BadDecodingError)"
    else
        fail "${label}: codec decode of an unqualified xml document: ${dec}"
    fi
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

# open62541 client → node-opcua server across SecureChannel renewals. node-opcua
# 2.187 secures every response with the token of its request
# (ServerSecureChannelLayer.send_response), so a Publish request sent before a
# renewal is answered under the old token after the client has switched to
# the new one (Part 6 §6.7.4: the server switches once it receives a message
# with the new token). Once the old token's lifetime has passed, the open62541
# 1.5.9 client drops such a response ("SecurityToken timed out") and the
# subscription stalls. Whether a late response lands after the expiry depends
# on publish timing, so both outcomes are reported; anything else fails.
check_o62541_node_renewal_deviation() {
    local client_image="$1" endpoint="$2"
    local node="nsu=urn:otfabric:opcua-interop:model;s=Dynamic.Counter"
    local output
    output=$(run_client_op "${client_image}" subscribe \
            --endpoint "${endpoint}" \
            --node "${node}" \
            --publishing-interval-ms 500 \
            --notifications 24 \
            --timeout-ms 40000 \
            --channel-lifetime-ms 6000) || true
    validate_envelope "${output}" "o62541→node-opcua:channel-renewal" || return
    if echo "${output}" | jq -e '.success == true and (.results[0].notifications | length) == 24' >/dev/null 2>&1; then
        ok "o62541→node-opcua: subscribe across SecureChannel renewals (lifetime 6s)"
    elif echo "${output}" | jq -e '.success == false and .error.category == "timeout" and (.results[0].notifications | length) > 0' >/dev/null 2>&1; then
        ok "o62541→node-opcua: subscription stalled after a SecureChannel renewal (known node-opcua 2.187 deviation: responses keep the request's old token)"
    else
        fail "o62541→node-opcua: channel renewal — unexpected result: ${output}"
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

# ── node-opcua cross-stack checks ─────────────────────────────────────────────

# Secured channels with a node-opcua server and a node-opcua client on the
# feature network, with the test PKI identities: open62541 and Milo clients
# against the node-opcua server (Basic256Sha256 Sign / SignAndEncrypt, the
# Aes policies, a UserName token, an untrusted client certificate), and the
# node-opcua client against the open62541 and Milo servers.
run_node_opcua_secure_cross() {
    local img_open62541="$1" img_milo="$2" img_node_opcua="$3"
    local model="nsu=urn:otfabric:opcua-interop:model;s="

    prepare_pki
    if [[ ! -f "${FEAT_TMP}/pki/node-opcua-server/cert.crt" ]]; then
        fail "node-opcua secure cross-stack: the test PKI has no node-opcua-server identity (certs/generate.sh --add-node-opcua)"
        feature_cleanup
        return
    fi
    FEAT_NET="smoke-net-$$"
    docker network create "${FEAT_NET}" >/dev/null

    local srv="smoke-node-opcua-sec-$$"
    local url="opc.tcp://${srv}:4840${ENDPOINT_PATH}"
    FEAT_CONTAINERS+=("${srv}")
    log "Starting node-opcua server with certificate (secure endpoints)..."
    docker run -d --name "${srv}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img_node_opcua}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${srv}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/node-opcua-server/cert.crt --private-key /pki/node-opcua-server/cert.key \
        --pki-dir /pki/node-opcua-server/pki >/dev/null
    wait_ready "${srv}"

    local o62541=(--certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key
                  --trust-list /pki/ca/ca.crt)
    local milo=(--certificate /pki/milo-client/cert.crt --private-key /pki/milo-client/cert.key
                --trust-list /pki/ca/ca.crt)
    local b256=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt)
    local out
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→node-opcua: Basic256Sha256/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - call --endpoint "${url}" --object "${model}Methods" \
            --method "${model}Methods.Add" --input Int32:10 --input Int32:20 "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→node-opcua: Basic256Sha256/SignAndEncrypt call Methods.Add(10,20)=30" \
        '.success == true and .results[0].outputArguments[0] == 30' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Basic256Sha256 --security-mode Sign "${o62541[@]}" \
            --username test-user --password test-password) || true
    feat_expect "o62541→node-opcua: Basic256Sha256/Sign + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes128_Sha256_RsaOaep --security-mode SignAndEncrypt "${milo[@]}") || true
    feat_expect "milo→node-opcua: Aes128_Sha256_RsaOaep/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - subscribe --endpoint "${url}" --node "${model}Dynamic.Counter" \
            --publishing-interval-ms 500 --notifications 3 --timeout-ms 15000 \
            --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt "${milo[@]}") || true
    feat_expect "milo→node-opcua: Aes256_Sha256_RsaPss/SignAndEncrypt subscribe Dynamic.Counter" \
        '.success == true and (.results[0].notifications | length) >= 3' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" --certificate /pki/untrusted/cert.crt --private-key /pki/untrusted/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    feat_expect "o62541→node-opcua: untrusted client certificate is rejected" \
        '.success == false' "${out}"

    # The node-opcua client over secured channels to the open62541 and Milo servers.
    local node=(--certificate /pki/node-opcua-client/cert.crt --private-key /pki/node-opcua-client/cert.key
                --trust-list /pki/ca/ca.crt)
    local peer
    for peer in open62541 milo; do
        local psrv="smoke-${peer}-sec-node-$$" pimg
        [[ "${peer}" == "open62541" ]] && pimg="${img_open62541}" || pimg="${img_milo}"
        FEAT_CONTAINERS+=("${psrv}")
        docker run -d --name "${psrv}" --network "${FEAT_NET}" \
            -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
            "${pimg}" server --fixture /fixtures/baseline/fixture.json \
            --advertised-host "${psrv}" --endpoint-path "${ENDPOINT_PATH}" \
            --certificate "/pki/${peer}-server/cert.crt" --private-key "/pki/${peer}-server/cert.key" \
            --pki-dir "/pki/${peer}-server/pki" >/dev/null
        wait_ready "${psrv}"
        out=$(feat_client "${img_node_opcua}" - read --endpoint "opc.tcp://${psrv}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" "${b256[@]}" "${node[@]}") || true
        feat_expect "node-opcua→${peer}: Basic256Sha256/SignAndEncrypt read" \
            '.success == true and .results[0].value == -123456789' "${out}"
        out=$(feat_client "${img_node_opcua}" - read --endpoint "opc.tcp://${psrv}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt \
                "${node[@]}" --username test-user --password test-password) || true
        feat_expect "node-opcua→${peer}: Aes256_Sha256_RsaPss/SignAndEncrypt + username" \
            '.success == true and .results[0].value == -123456789' "${out}"
    done

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
    if [[ "${adapter}" == "asyncua" ]]; then
        # No codec, and the asyncua server's deadband deviation instead of check_deadband.
        check_asyncua_deadband_deviation "${image}" "${endpoint}" "${adapter}→${adapter}"
    else
        check_deadband "${image}" "${endpoint}" "${adapter}→${adapter}"
    fi
    if [[ "${adapter}" != "async-opcua" && "${adapter}" != "node-opcua" && "${adapter}" != "asyncua" ]]; then
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
    local img_node_opcua="${4:-}"
    local port_open62541=14840
    local port_milo=14841
    local port_async_opcua=14842
    local port_node_opcua=14844

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

    if [[ -n "${img_node_opcua}" ]]; then
        local cname_node_opcua
        cname_node_opcua=$(start_server "node-opcua" "${img_node_opcua}" "${port_node_opcua}")
        trap "stop_server ${cname_open62541}; stop_server ${cname_milo}; stop_server ${cname_node_opcua}; feature_cleanup" EXIT
        wait_ready "${cname_node_opcua}"
        local ep_node_opcua="opc.tcp://localhost:${port_node_opcua}${ENDPOINT_PATH}"

        log "Cross-stack: open62541 / milo clients → node-opcua-server"
        local check
        for check in check_endpoints check_browse check_read_scalar check_write check_call \
                     check_subscribe check_register_nodes check_deadband; do
            "${check}" "${img_open62541}" "${ep_node_opcua}" "o62541→node-opcua"
        done
        check_o62541_node_renewal_deviation "${img_open62541}" "${ep_node_opcua}"
        check_interop_set "${img_milo}" "${ep_node_opcua}" "milo→node-opcua"
        log "Cross-stack: node-opcua-client → open62541 / milo / node-opcua servers"
        check_interop_set "${img_node_opcua}" "${ep_open62541}" "node-opcua→o62541"
        check_interop_set "${img_node_opcua}" "${ep_milo}" "node-opcua→milo"
        check_interop_set "${img_node_opcua}" "${ep_node_opcua}" "node-opcua→node-opcua"
        if [[ -n "${img_async_opcua}" ]]; then
            local cname_async_opcua2
            cname_async_opcua2=$(start_server "async-opcua" "${img_async_opcua}" "${port_async_opcua}")
            trap "stop_server ${cname_open62541}; stop_server ${cname_milo}; stop_server ${cname_node_opcua}; stop_server ${cname_async_opcua2}; feature_cleanup" EXIT
            wait_ready "${cname_async_opcua2}"
            log "Cross-stack: async-opcua ↔ node-opcua"
            check_interop_set "${img_async_opcua}" "${ep_node_opcua}" "async-opcua→node-opcua"
            check_interop_set "${img_node_opcua}" "opc.tcp://localhost:${port_async_opcua}${ENDPOINT_PATH}" "node-opcua→async-opcua"
            stop_server "${cname_async_opcua2}"
        fi
        stop_server "${cname_node_opcua}"
        trap "stop_server ${cname_open62541}; stop_server ${cname_milo}; feature_cleanup" EXIT
        run_node_opcua_secure_cross "${img_open62541}" "${img_milo}" "${img_node_opcua}"
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

# ── Mode: dotnet against the reference stacks ──────────────────────────────────

# run_client_checks <client-image> <endpoint> <label>: the client-contract checks
# of a cross-stack direction.
run_client_checks() {
    local check
    for check in check_endpoints check_browse check_read_scalar check_write check_call \
                 check_subscribe check_register_nodes check_channel_renewal check_deadband \
                 check_codec_node; do
        "${check}" "$@"
    done
}

run_cross_dotnet_smoke() {
    local img_dotnet="$1"
    local img_open62541="$2"
    local img_milo="$3"
    local port_open62541=14840
    local port_milo=14841
    local port_dotnet=14842

    local cname_open62541 cname_milo cname_dotnet
    cname_open62541=$(start_server "open62541" "${img_open62541}" "${port_open62541}")
    cname_milo=$(start_server "milo" "${img_milo}" "${port_milo}")
    cname_dotnet=$(start_server "dotnet" "${img_dotnet}" "${port_dotnet}")
    trap "stop_server ${cname_open62541}; stop_server ${cname_milo}; stop_server ${cname_dotnet}" EXIT

    wait_ready "${cname_open62541}"
    wait_ready "${cname_milo}"
    wait_ready "${cname_dotnet}"

    local ep_open62541="opc.tcp://localhost:${port_open62541}${ENDPOINT_PATH}"
    local ep_milo="opc.tcp://localhost:${port_milo}${ENDPOINT_PATH}"
    local ep_dotnet="opc.tcp://localhost:${port_dotnet}${ENDPOINT_PATH}"

    log "Cross-stack: dotnet-client → open62541-server"
    run_client_checks "${img_dotnet}" "${ep_open62541}" "dotnet→o62541"
    log "Cross-stack: dotnet-client → milo-server"
    run_client_checks "${img_dotnet}" "${ep_milo}" "dotnet→milo"
    log "Cross-stack: open62541-client → dotnet-server"
    run_client_checks "${img_open62541}" "${ep_dotnet}" "o62541→dotnet"
    log "Cross-stack: milo-client → dotnet-server"
    run_client_checks "${img_milo}" "${ep_dotnet}" "milo→dotnet"

    log "Cross-stack: codec documents of dotnet decoded by the reference stacks and back"
    check_codec_roundtrip "${img_dotnet}" "${img_open62541}" "dotnet→o62541"
    check_codec_roundtrip "${img_open62541}" "${img_dotnet}" "o62541→dotnet" json
    check_codec_xml_unqualified_rejected "${img_open62541}" "${img_dotnet}" "o62541→dotnet"
    check_codec_roundtrip "${img_dotnet}" "${img_milo}" "dotnet→milo"
    check_codec_roundtrip "${img_milo}" "${img_dotnet}" "milo→dotnet"

    stop_server "${cname_open62541}"
    stop_server "${cname_milo}"
    stop_server "${cname_dotnet}"
    trap - EXIT
}

# ── Mode: asyncua (opcua-asyncio) against the reference stacks ─────────────────

# The client-contract checks of a direction that involves the asyncua adapter:
# no codec (the adapter has none, asyncua/README.md). The absolute / percent
# deadband check only runs against servers other than asyncua (its own
# deadband handling does not conform: check_asyncua_deadband_deviation).
run_asyncua_pair_checks() {
    local image="$1" endpoint="$2" label="$3" deadband="${4:-yes}"
    local check
    for check in check_endpoints check_browse check_read_scalar check_write check_call \
                 check_subscribe check_register_nodes check_channel_renewal; do
        "${check}" "${image}" "${endpoint}" "${label}"
    done
    if [[ "${deadband}" == "yes" ]]; then
        check_deadband "${image}" "${endpoint}" "${label}"
    fi
}

# asyncua 2.1.0 accepts a percent deadband on a node without EURange
# (MonitoredItemService logs "not implemented" and reports every change)
# instead of BadMonitoredItemFilterUnsupported / BadFilterNotAllowed. The check
# fails when the deviation is gone, so check_deadband gets enabled again.
check_asyncua_deadband_deviation() {
    local client_image="$1" endpoint="$2" label="$3"
    local ramp="nsu=urn:otfabric:opcua-interop:model;s=Dynamic.Ramp"
    local output
    output=$(run_client_op "${client_image}" subscribe --endpoint "${endpoint}" --node "${ramp}" \
            --notifications 1 --timeout-ms 15000 --deadband-percent 10) || true
    validate_envelope "${output}" "${label}:percent-deadband" || return
    if echo "${output}" | jq -e '.success == true and .results[0].monitoredItemStatusCode.code == 0' >/dev/null 2>&1; then
        ok "${label}: percent deadband without EURange accepted (known asyncua 2.1.0 deviation, asyncua/README.md)"
    elif echo "${output}" | jq -e '.results[0].monitoredItemStatusCode.severity == "Bad"' >/dev/null 2>&1; then
        fail "${label}: percent deadband without EURange is rejected now — the asyncua deviation is gone; run check_deadband for this server"
    else
        fail "${label}: percent deadband — unexpected result: ${output}"
    fi
}

# Secured channels with the asyncua-server / asyncua-client identities of the
# test PKI on a feature network: the open62541 and Milo clients against the
# asyncua server (Basic256Sha256, the Aes policies, UserName, untrusted client
# certificate) and the asyncua client against the open62541 and Milo servers.
# Then discovery: the asyncua server registers with an open62541 LDS, the
# asyncua client calls FindServersOnNetwork and RegisterServer2 there.
run_asyncua_secure_cross() {
    local img_asyncua="$1" img_open62541="$2" img_milo="$3"
    local model="nsu=urn:otfabric:opcua-interop:model;s="

    prepare_pki
    if [[ ! -f "${FEAT_TMP}/pki/asyncua-server/cert.crt" ]]; then
        fail "asyncua secure cross-stack: the test PKI has no asyncua-server identity (certs/generate.sh --add-asyncua)"
        feature_cleanup
        return
    fi
    FEAT_NET="smoke-net-$$"
    docker network create "${FEAT_NET}" >/dev/null

    local srv="smoke-asyncua-sec-$$" o_srv="smoke-o62541-sec-$$" m_srv="smoke-milo-sec-$$"
    FEAT_CONTAINERS+=("${srv}" "${o_srv}" "${m_srv}")
    local url="opc.tcp://${srv}:4840${ENDPOINT_PATH}"
    log "Starting asyncua, open62541 (LDS) and Milo servers with certificates..."
    docker run -d --name "${o_srv}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img_open62541}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${o_srv}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
        --pki-dir /pki/open62541-server/pki --lds >/dev/null
    docker run -d --name "${m_srv}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img_milo}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${m_srv}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/milo-server/cert.crt --private-key /pki/milo-server/cert.key \
        --pki-dir /pki/milo-server/pki >/dev/null
    wait_ready "${o_srv}"
    local lds_url="opc.tcp://${o_srv}:4840${ENDPOINT_PATH}"
    docker run -d --name "${srv}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img_asyncua}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${srv}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/asyncua-server/cert.crt --private-key /pki/asyncua-server/cert.key \
        --pki-dir /pki/asyncua-server/pki \
        --register-with "${lds_url}" --register-interval-ms 2000 >/dev/null
    wait_ready "${m_srv}"
    wait_ready "${srv}"

    local o62541=(--certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key
                  --trust-list /pki/ca/ca.crt)
    local milo=(--certificate /pki/milo-client/cert.crt --private-key /pki/milo-client/cert.key
                --trust-list /pki/ca/ca.crt)
    local aua=(--certificate /pki/asyncua-client/cert.crt --private-key /pki/asyncua-client/cert.key
               --trust-list /pki/ca/ca.crt)
    local b256=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt)
    local out

    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→asyncua: Basic256Sha256/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - call --endpoint "${url}" --object "${model}Methods" \
            --method "${model}Methods.Add" --input Int32:10 --input Int32:20 "${b256[@]}" "${o62541[@]}") || true
    feat_expect "o62541→asyncua: Basic256Sha256/SignAndEncrypt call Methods.Add(10,20)=30" \
        '.success == true and .results[0].outputArguments[0] == 30' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Basic256Sha256 --security-mode Sign "${o62541[@]}" \
            --username test-user --password test-password) || true
    feat_expect "o62541→asyncua: Basic256Sha256/Sign + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes128_Sha256_RsaOaep --security-mode SignAndEncrypt "${o62541[@]}") || true
    feat_expect "o62541→asyncua: Aes128_Sha256_RsaOaep/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - subscribe --endpoint "${url}" --node "${model}Dynamic.Counter" \
            --publishing-interval-ms 500 --notifications 3 --timeout-ms 15000 \
            --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt "${milo[@]}") || true
    feat_expect "milo→asyncua: Aes256_Sha256_RsaPss/SignAndEncrypt subscribe Dynamic.Counter" \
        '.success == true and (.results[0].notifications | length) >= 3' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" --certificate /pki/untrusted/cert.crt --private-key /pki/untrusted/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    feat_expect "o62541→asyncua: untrusted client certificate is rejected" \
        '.success == false' "${out}"

    local target name
    for target in "${o_srv}:o62541" "${m_srv}:milo"; do
        name="${target#*:}"; target="${target%%:*}"
        out=$(feat_client "${img_asyncua}" - read --endpoint "opc.tcp://${target}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" "${b256[@]}" "${aua[@]}" \
                --username test-user --password test-password) || true
        feat_expect "asyncua→${name}: Basic256Sha256/SignAndEncrypt + username" \
            '.success == true and .results[0].value == -123456789' "${out}"
        out=$(feat_client "${img_asyncua}" - write --endpoint "opc.tcp://${target}:4840${ENDPOINT_PATH}" \
                --node "${model}Access.ReadWrite" --type Int32 --value 4242 \
                --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt "${aua[@]}") || true
        feat_expect "asyncua→${name}: Aes256_Sha256_RsaPss/SignAndEncrypt write" \
            '.success == true and .results[0].statusCode.name == "Good"' "${out}"
    done
    # The client checks the server certificate against --trust-list.
    out=$(feat_client "${img_asyncua}" - read --endpoint "opc.tcp://${m_srv}:4840${ENDPOINT_PATH}" \
            --node "${model}Scalar.Int32" "${b256[@]}" \
            --certificate /pki/asyncua-client/cert.crt --private-key /pki/asyncua-client/cert.key \
            --trust-list /pki/untrusted/cert.crt) || true
    feat_expect "asyncua→milo: server certificate not issued by a --trust-list entry is rejected" \
        '.success == false' "${out}"

    # Discovery against the open62541 LDS.
    local registered=0 i
    for i in $(seq 1 30); do
        out=$(feat_client "${img_open62541}" - find-servers --endpoint "${lds_url}") || true
        if echo "${out}" | jq -e "[.results[].discoveryUrls[]] | index(\"${url}\") != null" >/dev/null 2>&1; then
            registered=1; break
        fi
        sleep 1
    done
    if [[ "${registered}" == 1 ]]; then
        ok "asyncua server registered with the open62541 LDS (--register-with, RegisterServer)"
    else
        fail "asyncua server is not listed by the open62541 LDS after 30 polls: ${out}"
    fi
    out=$(feat_client "${img_asyncua}" - find-servers-on-network --endpoint "${lds_url}") || true
    feat_expect "asyncua→LDS: FindServersOnNetwork (LDS record)" \
        '.success == true and ([.results[] | select(.serverCapabilities | index("LDS"))] | length) >= 1' "${out}"
    out=$(feat_client "${img_asyncua}" - register-server --endpoint "${lds_url}" \
            --server-uri urn:smoke:asyncua --server-name "smoke asyncua" \
            --discovery-url opc.tcp://smoke-asyncua:4999 --mdns-name smoke-asyncua) || true
    feat_expect "asyncua→LDS: register-server (RegisterServer2)" \
        '.success == true and .results[0].service == "RegisterServer2"' "${out}"
    out=$(feat_client "${img_open62541}" - find-servers --endpoint "${lds_url}") || true
    feat_expect "asyncua→LDS: registration visible in FindServers" \
        '[.results[].applicationUri] | index("urn:smoke:asyncua") != null' "${out}"

    feature_cleanup
}

# cross-asyncua <asyncua> <open62541> <milo> [async-opcua] [dotnet]: the
# asyncua client against the open62541 and Milo servers (and, when given, the
# async-opcua and dotnet servers), those clients against the asyncua server,
# then secured channels and discovery (run_asyncua_secure_cross).
run_cross_asyncua_smoke() {
    local img_asyncua="$1" img_open62541="$2" img_milo="$3" img_async_opcua="${4:-}" img_dotnet="${5:-}"
    local port_asyncua=14845 port_open62541=14840 port_milo=14841 port_async_opcua=14842 port_dotnet=14843

    local servers=() cname
    cname=$(start_server "asyncua" "${img_asyncua}" "${port_asyncua}"); servers+=("${cname}")
    cname=$(start_server "open62541" "${img_open62541}" "${port_open62541}"); servers+=("${cname}")
    cname=$(start_server "milo" "${img_milo}" "${port_milo}"); servers+=("${cname}")
    if [[ -n "${img_async_opcua}" ]]; then
        cname=$(start_server "async-opcua" "${img_async_opcua}" "${port_async_opcua}"); servers+=("${cname}")
    fi
    if [[ -n "${img_dotnet}" ]]; then
        cname=$(start_server "dotnet" "${img_dotnet}" "${port_dotnet}"); servers+=("${cname}")
    fi
    trap "for c in ${servers[*]}; do stop_server \${c}; done; feature_cleanup" EXIT
    for cname in "${servers[@]}"; do wait_ready "${cname}"; done

    local ep_asyncua="opc.tcp://localhost:${port_asyncua}${ENDPOINT_PATH}"
    local ep_open62541="opc.tcp://localhost:${port_open62541}${ENDPOINT_PATH}"
    local ep_milo="opc.tcp://localhost:${port_milo}${ENDPOINT_PATH}"

    log "Cross-stack: asyncua-client → open62541 / milo servers"
    run_asyncua_pair_checks "${img_asyncua}" "${ep_open62541}" "asyncua→o62541"
    run_asyncua_pair_checks "${img_asyncua}" "${ep_milo}" "asyncua→milo"
    log "Cross-stack: open62541 / milo clients → asyncua-server"
    run_asyncua_pair_checks "${img_open62541}" "${ep_asyncua}" "o62541→asyncua" no
    check_asyncua_deadband_deviation "${img_open62541}" "${ep_asyncua}" "o62541→asyncua"
    run_asyncua_pair_checks "${img_milo}" "${ep_asyncua}" "milo→asyncua" no
    if [[ -n "${img_async_opcua}" ]]; then
        local ep_async_opcua="opc.tcp://localhost:${port_async_opcua}${ENDPOINT_PATH}"
        log "Cross-stack: asyncua ↔ async-opcua"
        run_asyncua_pair_checks "${img_asyncua}" "${ep_async_opcua}" "asyncua→async-opcua"
        run_asyncua_pair_checks "${img_async_opcua}" "${ep_asyncua}" "async-opcua→asyncua" no
    fi
    if [[ -n "${img_dotnet}" ]]; then
        local ep_dotnet="opc.tcp://localhost:${port_dotnet}${ENDPOINT_PATH}"
        log "Cross-stack: asyncua ↔ dotnet"
        run_asyncua_pair_checks "${img_asyncua}" "${ep_dotnet}" "asyncua→dotnet"
        run_asyncua_pair_checks "${img_dotnet}" "${ep_asyncua}" "dotnet→asyncua" no
    fi

    for cname in "${servers[@]}"; do stop_server "${cname}"; done
    trap "feature_cleanup" EXIT
    run_asyncua_secure_cross "${img_asyncua}" "${img_open62541}" "${img_milo}"
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
    dotnet)
        run_single_smoke "dotnet" "${1:?image required}"
        ;;
    node-opcua)
        run_single_smoke "node-opcua" "${1:?image required}"
        ;;
    cross)
        run_cross_smoke "${1:?open62541 image required}" "${2:?milo image required}" "${3:-}" "${4:-}"
        ;;
    cross-dotnet)
        run_cross_dotnet_smoke "${1:?dotnet image required}" "${2:?open62541 image required}" "${3:?milo image required}"
        ;;
    asyncua)
        run_single_smoke "asyncua" "${1:?image required}"
        ;;
    cross-asyncua)
        run_cross_asyncua_smoke "${1:?asyncua image required}" "${2:?open62541 image required}" "${3:?milo image required}" "${4:-}" "${5:-}"
        ;;
    *)
        echo "Unknown mode: ${MODE}. Use open62541, milo, async-opcua, dotnet, node-opcua, asyncua, cross, cross-dotnet or cross-asyncua." >&2
        exit 1
        ;;
esac

echo ""
log "Results: ${PASS} passed, ${FAIL} failed"

[[ "${FAIL}" -eq 0 ]]
