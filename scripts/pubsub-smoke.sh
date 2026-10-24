#!/usr/bin/env bash
# PubSub (OPC UA Part 14) smoke test of an adapter image.
#
# Usage:
#   pubsub-smoke.sh <adapter-image> [scenario ...]
#
# Scenarios (default: all but discovery, the open62541 set; `make
# smoke-pubsub-dotnet` runs the UA-.NETStandard set):
#   codec          UADP / JSON NetworkMessage encode → decode round trips (no transport)
#   udp-unicast    UADP over opc.udp:// unicast, container → container
#   udp-multicast  UADP over opc.udp:// multicast (224.0.0.22), container → container
#   mqtt-uadp      UADP over MQTT through Eclipse Mosquitto
#   mqtt-json      JSON over MQTT through Eclipse Mosquitto
#   mqtt-late-broker  the publisher starts before the broker answers and must
#                  recover from Error
#   udp-secure     UADP unicast, SignAndEncrypt (PubSub-Aes256-CTR), static keys
#   sks            the publisher is the Security Key Service, the subscriber pulls
#                  its keys with GetSecurityKeys (SignAndEncrypt), UADP SignAndEncrypt
#   sks-push       the subscriber starts without keys; SetSecurityKeys pushes them
#   infomodel      PubSub information model methods: GetSecurityKeys,
#                  AddSecurityGroup, AddConnection / RemoveConnection, Disable / Enable
#   discovery      UADP discovery: `client pubsub-discover` probes the multicast
#                  publisher for DataSetMetaData and DataSetWriterConfiguration
#                  (adapters whose capabilities declare pubsub.discovery)
#
# Every transport scenario starts a subscriber and a publisher container (the
# configurations in pubsub/examples/) on a dedicated Docker network, writes
# fresh values into the publisher's PubSub.* variables with `client write` and
# checks with `client read` that the subscriber's TargetVariables follow
# (Dynamic.Counter is published into the subscriber's PubSub.Int64).
#
# Exit codes: 0 all checks passed, 1 one or more failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
EXAMPLES="${REPO_ROOT}/pubsub/examples"
IMG="${1:?Usage: pubsub-smoke.sh <adapter-image> [scenario ...]}"
shift
SCENARIOS=("$@")
if [[ ${#SCENARIOS[@]} -eq 0 ]]; then
    SCENARIOS=(codec udp-unicast udp-multicast mqtt-uadp mqtt-json mqtt-late-broker udp-secure sks sks-push infomodel)
fi

# Eclipse Mosquitto 2.0.22 (multi-arch index digest), see README "MQTT broker"
MOSQUITTO_IMAGE="${MOSQUITTO_IMAGE:-eclipse-mosquitto:2.0.22@sha256:09b62ff32c2e7b64d4b431b9a89236073289b68db273de2b089edeb9b0d92b5c}"

ENDPOINT_PATH="/opcua-interop"
MODEL="nsu=urn:otfabric:opcua-interop:model;s="
FOLLOW_TIMEOUT=20

PASS=0
FAIL=0
log()  { echo "[pubsub-smoke] $*" >&2; }
ok()   { log "OK: $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

NET="pubsub-smoke-$$"
TMP=""
CONTAINERS=()

cleanup() {
    local c
    for c in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do docker rm -f "${c}" &>/dev/null || true; done
    docker network rm "${NET}" &>/dev/null || true
    if [[ -n "${TMP}" ]]; then rm -rf "${TMP}"; fi
}
trap cleanup EXIT

docker network create "${NET}" >/dev/null

# client <args...>: adapter client on the smoke network (stdout: the JSON envelope)
client() {
    local raw rc=0
    raw=$(docker run --rm --network "${NET}" ${TMP:+-v "${TMP}/pki:/pki"} "${IMG}" client "$@" 2>/dev/null) || rc=$?
    printf '%s\n' "${raw}" | grep -m1 '^{' || printf '%s\n' "${raw}"
    return ${rc}
}

expect() {
    local label="$1" filter="$2" output="$3"
    if echo "${output}" | jq -e "${filter}" >/dev/null 2>&1; then
        ok "${label}"
    else
        fail "${label}: ${output}"
    fi
}

prepare_pki() {
    [[ -n "${TMP}" ]] && return
    local pki="${OPCUA_INTEROP_PKI_DIR:-${REPO_ROOT}/certs/test-pki}"
    if [[ ! -f "${pki}/ca/ca.crt" ]]; then
        log "Generating test PKI..."
        "${REPO_ROOT}/certs/generate.sh" >/dev/null 2>&1
    fi
    TMP=$(mktemp -d "${TMPDIR:-/tmp}/opcua-interop-pubsub.XXXXXX")
    cp -R "${pki}" "${TMP}/pki"
    chmod -R a+rwX "${TMP}"
}

# start_server <container> <network-alias> <config> [extra server args...]
start_server() {
    local name="$1" alias="$2" config="$3"
    shift 3
    docker rm -f "${name}" &>/dev/null || true
    CONTAINERS+=("${name}")
    docker run -d --name "${name}" --network "${NET}" --network-alias "${alias}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${EXAMPLES}:/pubsub:ro" \
        ${TMP:+-v "${TMP}/pki:/pki"} \
        "${IMG}" server --fixture /fixtures/baseline/fixture.json \
        --advertised-host "${alias}" --endpoint-path "${ENDPOINT_PATH}" \
        --pubsub-config "/pubsub/${config}" "$@" >/dev/null
    if ! "${SCRIPT_DIR}/wait-ready.sh" "${name}" 60; then
        fail "${name}: server with ${config} did not become ready"
        return 1
    fi
}

stop_servers() {
    local c
    for c in "$@"; do docker rm -f "${c}" &>/dev/null || true; done
}

ensure_mosquitto() {
    local name="pubsub-smoke-mosquitto-$$"
    if docker ps --format '{{.Names}}' | grep -qx "${name}"; then return; fi
    CONTAINERS+=("${name}")
    docker run -d --name "${name}" --network "${NET}" --network-alias mosquitto \
        -v "${REPO_ROOT}/mqtt/mosquitto.conf:/mosquitto-interop.conf:ro" \
        "${MOSQUITTO_IMAGE}" mosquitto -c /mosquitto-interop.conf >/dev/null
    sleep 1
}

# check_follow <label> [extra client args for the publisher...]
# Writes fresh values on the publisher and waits until the subscriber's
# TargetVariables carry them; Dynamic.Counter (→ PubSub.Int64) must advance.
check_follow() {
    local label="$1"
    shift
    local pub="opc.tcp://pubsub-publisher:4840${ENDPOINT_PATH}"
    local sub="opc.tcp://pubsub-subscriber:4840${ENDPOINT_PATH}"
    local n=$(( (RANDOM << 8) + RANDOM + 1 ))
    local s="pubsub-${label}-${n}"
    local u64
    u64="9$(printf '%018d' "${n}")"   # > 2^63, < 2^64
    local w out
    for w in "PubSub.Int32 Int32 ${n}" "PubSub.String String ${s}" \
             "PubSub.UInt64 UInt64 ${u64}" "PubSub.Int32Array Int32[] ${n},-1,7"; do
        read -r node type value <<<"${w}"
        out=$(client write --endpoint "${pub}" --node "${MODEL}${node}" --type "${type}" --value "${value}") || true
        if ! echo "${out}" | jq -e '.success == true' >/dev/null 2>&1; then
            fail "${label}: write ${node} on the publisher: ${out}"
            return
        fi
    done

    local deadline=$((SECONDS + FOLLOW_TIMEOUT)) first="" counter=""
    while (( SECONDS < deadline )); do
        out=$(client read --endpoint "${sub}" --node "${MODEL}PubSub.Int32" --node "${MODEL}PubSub.String" \
                --node "${MODEL}PubSub.UInt64" --node "${MODEL}PubSub.Int32Array" \
                --node "${MODEL}PubSub.Int64") || true
        counter=$(echo "${out}" | jq -r '.results[4].value // empty' 2>/dev/null || true)
        [[ -z "${first}" && -n "${counter}" ]] && first="${counter}"
        if echo "${out}" | jq -e --argjson n "${n}" --arg s "${s}" --arg u "${u64}" \
              '.results[0].value == $n and .results[1].value == $s and .results[2].value == $u
               and .results[3].value == [$n, -1, 7]' >/dev/null 2>&1 \
           && [[ -n "${counter}" && "${counter}" != "${first}" ]]; then
            ok "${label}: subscriber TargetVariables follow the publisher (Int32=${n}, Counter ${first}→${counter})"
            return
        fi
        sleep 1
    done
    fail "${label}: subscriber did not follow within ${FOLLOW_TIMEOUT}s (expected Int32=${n}): ${out}"
}

# mqtt-late-broker: the publisher starts while the broker refuses connections
# (the name "mosquitto" resolves, nothing listens on 1883), as a broker that is
# still starting up: the first sends fail and the WriterGroup and connection
# enter Error. They must recover (the adapter re-enables them) and data must
# reach a subscriber once the real broker is up. (open62541 cannot configure
# MQTT components while the broker's name does not resolve.)
scenario_mqtt_late_broker() {
    local broker="pubsub-smoke-mosquitto-$$" refuser="pubsub-smoke-refuser-$$"
    local pubc="pubsub-smoke-pub-$$" subc="pubsub-smoke-sub-$$" i
    # grep a captured log: grep -q on a pipe can SIGPIPE docker logs (pipefail)
    local plog; plog=$(mktemp "${TMPDIR:-/tmp}/opcua-interop-late-broker.XXXXXX")
    publog() { docker logs "${pubc}" > "${plog}" 2>&1 || true; }
    log "Scenario mqtt-late-broker: mqtt-json with the publisher started before the broker is up"
    docker rm -f "${broker}" &>/dev/null || true
    CONTAINERS+=("${refuser}")
    docker run -d --name "${refuser}" --network "${NET}" --network-alias mosquitto \
        --entrypoint sleep "${MOSQUITTO_IMAGE}" 600 >/dev/null
    start_server "${pubc}" pubsub-publisher "mqtt-json-publisher.json" || { stop_servers "${refuser}"; return; }
    for i in $(seq 1 20); do
        publog; grep -q "is in Error" "${plog}" && break
        sleep 0.5
    done
    if grep -q "is in Error" "${plog}"; then
        ok "mqtt-late-broker: the publisher went to Error while the broker refused connections"
    else
        fail "mqtt-late-broker: the publisher did not report Error while the broker refused connections"
    fi
    stop_servers "${refuser}"
    ensure_mosquitto
    if [[ "$(docker inspect -f '{{.State.Running}}' "${pubc}" 2>/dev/null)" != true ]]; then
        fail "mqtt-late-broker: the publisher exited ($(docker inspect -f '{{.State.ExitCode}}' "${pubc}" 2>/dev/null))"
        stop_servers "${pubc}"
        return
    fi
    start_server "${subc}" pubsub-subscriber "mqtt-json-subscriber.json" || { stop_servers "${pubc}"; return; }
    local before=${FAIL}
    check_follow "mqtt-late-broker"
    publog
    if grep -q "re-enabled" "${plog}"; then
        ok "mqtt-late-broker: the publisher re-enabled its components"
    else
        fail "mqtt-late-broker: no recovery reported by the publisher"
    fi
    if (( FAIL > before )); then
        log "publisher PubSub log (tail):"; grep "pubsub\|open62541\]" "${plog}" | tail -12 >&2
        log "subscriber PubSub log (tail):"
        docker logs "${subc}" 2>&1 | grep "pubsub\|MQTT\|open62541\]" | tail -12 >&2 || true
    fi
    rm -f "${plog}"
    stop_servers "${pubc}" "${subc}"
}

# run_pair <label> <config-prefix> [-- publisher-args -- subscriber-args]
run_pair() {
    local label="$1" prefix="$2"
    local pubc="pubsub-smoke-pub-$$" subc="pubsub-smoke-sub-$$"
    local pub_args=() sub_args=()
    if [[ "${3:-}" == "--pub" ]]; then
        shift 3
        while [[ $# -gt 0 && "$1" != "--sub" ]]; do pub_args+=("$1"); shift; done
        [[ "${1:-}" == "--sub" ]] && shift
        sub_args=("$@")
    fi
    log "Scenario ${label}: ${prefix}-subscriber.json ← ${prefix}-publisher.json"
    # The subscriber first: a unicast publisher resolves its destination at start.
    start_server "${subc}" pubsub-subscriber "${prefix}-subscriber.json" ${sub_args[@]+"${sub_args[@]}"} || return
    start_server "${pubc}" pubsub-publisher "${prefix}-publisher.json" ${pub_args[@]+"${pub_args[@]}"} || { stop_servers "${subc}"; return; }
    check_follow "${label}"
    stop_servers "${pubc}" "${subc}"
}

scenario_codec() {
    local desc out b64 json
    desc='{"publisherId":{"type":"UInt16","value":2234},"groupHeader":{"writerGroupId":100,"sequenceNumber":7},
           "payloadHeader":true,"timestamp":"2026-10-23T10:00:00.1234567Z",
           "messages":[{"dataSetWriterId":1,"messageType":"KeyFrame","fieldEncoding":"Variant","sequenceNumber":3,
             "fields":[{"name":"Int32","dataType":"Int32","value":-5},{"name":"String","dataType":"String","value":"hi"},
                       {"name":"UInt64","dataType":"UInt64","value":"18446744073709551615"},
                       {"name":"Arr","dataType":"Int32","value":[1,2,3]}]}]}'
    out=$(client codec pubsub-uadp-encode --document "${desc}") || true
    b64=$(echo "${out}" | jq -r '.results[0].encoded // empty')
    expect "codec: pubsub-uadp-encode" '.success == true and (.results[0].encoded | length) > 0' "${out}"
    out=$(client codec pubsub-uadp-decode --document "${b64}") || true
    expect "codec: pubsub-uadp-decode round trip" \
        ".success == true and .results[0].reencoded == \"${b64}\"
         and .results[0].networkMessage.publisherId == {\"type\":\"UInt16\",\"value\":2234}
         and .results[0].networkMessage.messages[0].fields[2].value == \"18446744073709551615\"" "${out}"

    # RawData needs the DataSetMetaData to decode
    desc='{"publisherId":{"type":"Byte","value":5},"payloadHeader":true,
           "messages":[{"dataSetWriterId":1,"messageType":"KeyFrame","fieldEncoding":"RawData",
             "fields":[{"name":"a","dataType":"Int32","value":7},{"name":"b","dataType":"Double","value":1.5}]}]}'
    b64=$(client codec pubsub-uadp-encode --document "${desc}" | jq -r '.results[0].encoded // empty') || true
    out=$(client codec pubsub-uadp-decode --document "${b64}" \
            --metadata '{"Name":"ds","Fields":[{"Name":"a","BuiltInType":6,"DataType":"i=6","ValueRank":-1},{"Name":"b","BuiltInType":11,"DataType":"i=11","ValueRank":-1}]}') || true
    expect "codec: RawData decode with --metadata" \
        '.success == true and .results[0].networkMessage.messages[0].fields[1].value == 1.5' "${out}"

    desc='{"messageId":"m-1","publisherId":{"type":"String","value":"pub-a"},
           "messages":[{"dataSetWriterId":7,"messageType":"KeyFrame","fieldEncoding":"DataValue","sequenceNumber":9,
             "fields":[{"name":"Temp","dataType":"Double","value":21.5,"sourceTimestamp":"2026-10-23T09:59:59.5Z"}]}]}'
    out=$(client codec pubsub-json-encode --document "${desc}") || true
    expect "codec: pubsub-json-encode" '.success == true and (.results[0].encoded | fromjson | .Messages[0].Payload.Temp.Value) == 21.5' "${out}"
    json=$(echo "${out}" | jq -r '.results[0].encoded // empty')
    out=$(client codec pubsub-json-decode --document "${json}") || true
    expect "codec: pubsub-json-decode round trip" \
        ".success == true and .results[0].reencoded == $(jq -Rn --arg j "${json}" '$j')
         and .results[0].networkMessage.messages[0].fields[0].name == \"Temp\"" "${out}"
}

# SKS push: subscriber without keys, the static-key publisher of udp-secure,
# then SetSecurityKeys (PublishSubscribe i=17364) on the subscriber.
scenario_sks_push() {
    prepare_pki
    local pubc="pubsub-smoke-pub-$$" subc="pubsub-smoke-sub-$$" out key
    local sub_ep="opc.tcp://pubsub-subscriber:4840${ENDPOINT_PATH}"
    log "Scenario sks-push: sks-push-subscriber.json ← udp-secure-publisher.json + SetSecurityKeys"
    start_server "${subc}" pubsub-subscriber sks-push-subscriber.json \
        --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
        --pki-dir /pki/open62541-server/pki || return
    start_server "${pubc}" pubsub-publisher udp-secure-publisher.json || { stop_servers "${subc}"; return; }
    key=$(jq -r '.securityGroups[0].keys[0].key' "${EXAMPLES}/udp-secure-publisher.json")
    out=$(client call --endpoint "${sub_ep}" --security-policy Basic256Sha256 --security-mode SignAndEncrypt \
            --certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key \
            --trust-list /pki/ca/ca.crt --object i=14443 --method i=17364 \
            --input String:InteropGroup \
            --input 'String:http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR' \
            --input UInt32:1 --input "ByteString:${key}" --input 'ByteString[]:' \
            --input Double:0 --input Double:60000) || true
    expect "sks-push: SetSecurityKeys (SignAndEncrypt)" '.success == true' "${out}"
    check_follow "sks-push"
    stop_servers "${pubc}" "${subc}"
}

scenario_infomodel() {
    prepare_pki
    local pubc="pubsub-smoke-im-$$" ep="opc.tcp://pubsub-publisher:4840${ENDPOINT_PATH}" out
    local sec=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt
               --certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key
               --trust-list /pki/ca/ca.crt --username test-user --password test-password)
    local subc="pubsub-smoke-im-sub-$$"
    log "Scenario infomodel: SKS publisher, PublishSubscribe methods"
    # (the publisher's unicast destination must resolve when it starts)
    start_server "${subc}" pubsub-subscriber udp-unicast-subscriber.json || return
    start_server "${pubc}" pubsub-publisher sks-publisher.json \
        --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
        --pki-dir /pki/open62541-server/pki || return

    out=$(client call --endpoint "${ep}" "${sec[@]}" --object i=14443 --method i=15215 \
            --input String:InteropGroup --input UInt32:0 --input UInt32:1) || true
    # 68-byte (PubSub-Aes256-CTR) / 52-byte (PubSub-Aes128-CTR) keys = 92 / 72 Base64 characters
    expect "infomodel: GetSecurityKeys (SignAndEncrypt) returns PubSub-Aes256-CTR keys of 68 bytes" \
        '.success == true and (.results[0].outputArguments[0] | endswith("PubSub-Aes256-CTR"))
         and (.results[0].outputArguments[2] | length) >= 1
         and (.results[0].outputArguments[2][0] | length) == 92' "${out}"
    out=$(client call --endpoint "${ep}" --object i=14443 --method i=15215 \
            --input String:InteropGroup --input UInt32:0 --input UInt32:1) || true
    expect "infomodel: GetSecurityKeys over None is refused" \
        '.results[0].statusCode.name == "BadSecurityModeInsufficient"' "${out}"
    out=$(client call --endpoint "${ep}" --object i=15443 --method i=15444 --input String:SmokeGroup \
            --input Double:30000 --input 'String:http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR' \
            --input UInt32:2 --input UInt32:1) || true
    expect "infomodel: AddSecurityGroup" '.success == true and .results[0].outputArguments[0] == "SmokeGroup"' "${out}"
    out=$(client call --endpoint "${ep}" "${sec[@]}" --object i=14443 --method i=15215 \
            --input String:SmokeGroup --input UInt32:0 --input UInt32:2) || true
    expect "infomodel: GetSecurityKeys of the added group (PubSub-Aes128-CTR, 52-byte keys)" \
        '.success == true and (.results[0].outputArguments[2][0] | length) == 72' "${out}"

    # AddConnection with a binary PubSubConnectionDataType (built by the codec)
    local doc body cid
    doc='{"UaTypeId":"i=15617","UaBody":{"Name":"ViaMethod","Enabled":true,"PublisherId":{"UaType":5,"Value":77},
          "TransportProfileUri":"http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp",
          "Address":{"UaTypeId":"i=15510","UaBody":{"Url":"opc.udp://224.0.0.23:4840"}}}}'
    body=$(client codec decode --format json --type ExtensionObject --document "${doc}" \
            | jq -r '.results[0].binary' | base64 -d | tail -c +10 | base64 | tr -d '\n') || true
    out=$(client call --endpoint "${ep}" --object i=14443 --method i=17366 \
            --input "ExtensionObject:i=15694|${body}") || true
    expect "infomodel: AddConnection (PubSubConnectionDataType)" '.success == true' "${out}"
    cid=$(echo "${out}" | jq -r '.results[0].outputArguments[0] // empty')
    out=$(client call --endpoint "${ep}" --object i=14443 --method i=17369 --input "NodeId:${cid}") || true
    expect "infomodel: RemoveConnection" '.success == true' "${out}"

    # Disable / Enable the WriterGroup through its Status object
    local conn wg status state
    conn=$(client browse --endpoint "${ep}" --node i=14443 | jq -r '.results[] | select(.browseName.name=="InteropPublisher") | .nodeId')
    wg=$(client browse --endpoint "${ep}" --node "${conn}" | jq -r '.results[] | select(.browseName.name=="InteropWriterGroup") | .nodeId')
    status=$(client browse --endpoint "${ep}" --node "${wg}" | jq -r '.results[] | select(.browseName.name=="Status") | .nodeId')
    state=$(client browse --endpoint "${ep}" --node "${status}" | jq -r '.results[] | select(.browseName.name=="State") | .nodeId')
    out=$(client call --endpoint "${ep}" --object "${status}" --method i=14646) || true
    expect "infomodel: WriterGroup Status.Disable" '.success == true' "${out}"
    out=$(client read --endpoint "${ep}" --node "${state}") || true
    expect "infomodel: WriterGroup State = Disabled (0)" '.results[0].value == 0' "${out}"
    out=$(client call --endpoint "${ep}" --object "${status}" --method i=14645) || true
    expect "infomodel: WriterGroup Status.Enable" '.success == true' "${out}"
    out=$(client read --endpoint "${ep}" --node "${state}") || true
    expect "infomodel: WriterGroup State = Operational (2)" '.results[0].value == 2' "${out}"
    stop_servers "${pubc}" "${subc}"
}

# discovery: probe the multicast publisher (its connection address is the
# group 224.0.0.22:4840) and check the announcements describe its DataSet.
scenario_discovery() {
    local pubc="pubsub-smoke-pub-$$" out
    log "Scenario discovery: pubsub-discover <- udp-multicast-publisher.json"
    start_server "${pubc}" pubsub-publisher udp-multicast-publisher.json || return
    out=$(client pubsub-discover --url opc.udp://224.0.0.22:4840 --type DataSetMetaData --timeout-ms 5000) || true
    expect "discovery: DataSetMetaData announcement" \
        '.success == true and .results[0].dataSetMetaData[0].publisherId == {"type":"UInt16","value":2234}
         and .results[0].dataSetMetaData[0].dataSetWriterId == 1
         and .results[0].dataSetMetaData[0].metaData.name == "InteropDataSet"
         and (.results[0].dataSetMetaData[0].metaData.fields | map(.name) | index("Counter")) != null' "${out}"
    out=$(client pubsub-discover --url opc.udp://224.0.0.22:4840 --type DataSetWriterConfiguration --writer-ids 1 --timeout-ms 5000) || true
    expect "discovery: DataSetWriterConfiguration announcement" \
        '.success == true and .results[0].writerConfigurations[0].writerGroup.writerGroupId == 100
         and .results[0].writerConfigurations[0].writerGroup.dataSetWriters[0].dataSetWriterId == 1' "${out}"
    stop_servers "${pubc}"
}

for sc in "${SCENARIOS[@]}"; do
    case "${sc}" in
        codec)         scenario_codec ;;
        udp-unicast)   run_pair udp-unicast udp-unicast ;;
        udp-multicast) run_pair udp-multicast udp-multicast ;;
        mqtt-uadp)     ensure_mosquitto; run_pair mqtt-uadp mqtt-uadp ;;
        mqtt-json)     ensure_mosquitto; run_pair mqtt-json mqtt-json ;;
        mqtt-late-broker) scenario_mqtt_late_broker ;;
        udp-secure)    run_pair udp-secure udp-secure ;;
        sks)
            prepare_pki
            run_pair sks sks \
                --pub --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
                      --pki-dir /pki/open62541-server/pki \
                --sub --certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key \
                      --pki-dir /pki/open62541-client/pki
            ;;
        sks-push)      scenario_sks_push ;;
        infomodel)     scenario_infomodel ;;
        discovery)     scenario_discovery ;;
        *) echo "unknown scenario: ${sc}" >&2; exit 1 ;;
    esac
done

echo ""
log "Results: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
