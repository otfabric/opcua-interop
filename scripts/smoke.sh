#!/usr/bin/env bash
# Cross-stack smoke test for opcua-interop.
#
# Usage:
#   smoke.sh open62541 <image>                        # single-adapter smoke
#   smoke.sh milo <image>                             # single-adapter smoke
#   smoke.sh async-opcua <image>                      # single-adapter smoke
#   smoke.sh dotnet <image>                           # single-adapter smoke
#   smoke.sh dotnet-gds <image>                       # GDS pull model: server + client gds-pull (§16)
#   smoke.sh node-opcua <image>                       # single-adapter smoke
#   smoke.sh cross <image-open62541> <image-milo> [image-async-opcua] [image-node-opcua]
#                                                     # cross-stack self-check
#   smoke.sh cross-dotnet <image-dotnet> <image-open62541> <image-milo> [image-node-opcua]
#                                                     # dotnet against both reference stacks (and the
#                                                     # node-opcua client against the dotnet history events)
#   smoke.sh asyncua <image>                          # single-adapter smoke
#   smoke.sh cross-asyncua <image-asyncua> <image-open62541> <image-milo> [image-async-opcua] [image-dotnet]
#                                                     # asyncua against the reference stacks
#
# Exit codes:
#   0  — all checks passed
#   1  — one or more checks failed, or none passed
#
# With REPORT_DIR set, writes ${REPORT_DIR}/results.json (interop-result-v1,
# scripts/results.sh): only a pass counts as passing, and a known deviation of
# tests/known-differences.tsv is reported as such.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENDPOINT_PATH="/opcua-interop"
WAIT_TIMEOUT=60

MODE="${1:?Usage: smoke.sh <open62541|milo|async-opcua|dotnet|dotnet-gds|node-opcua|asyncua|cross|cross-dotnet|cross-asyncua> <image> [images...]}"
shift

PASS=0
FAIL=0

log()  { echo "[smoke] $*" >&2; }
ok()   { log "OK: $*"; PASS=$((PASS + 1)); record pass; }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); record fail "$*"; }

# shellcheck source=scripts/results.sh
source "${SCRIPT_DIR}/results.sh"
case "${MODE}" in cross*) SUITE="${MODE}" ;; *) SUITE=single ;; esac
RESULT_ADAPTER="${MODE}"
RESULTS_ARGS="${MODE} $*"
results_start "$@"

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
    "${SCRIPT_DIR}/wait-ready.sh" "${cname}" "${WAIT_TIMEOUT}" && return 0
    at harness.server-ready
    infra "${cname} did not become ready"
    results_finish
    exit 1
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

# ── Historical events (CLIENT_CONTRACT.md `history-read-events`, `history-update-events`) ──

HEV_NODE="nsu=urn:otfabric:opcua-interop:model;s=History.Events"

# check_history_events_caps <image> <label>: print-capabilities lists both operations.
check_history_events_caps() {
    local image="$1" label="$2" out
    at history.caps "${label}"
    out=$(docker run --rm "${image}" print-capabilities 2>/dev/null) || true
    if echo "${out}" | jq -e '(.clientOperations | index("history-read-events")) and (.clientOperations | index("history-update-events"))' >/dev/null 2>&1; then
        ok "${label}: print-capabilities lists history-read-events / history-update-events"
    else
        fail "${label}: print-capabilities lacks the history-events client operations"
    fi
}

# check_history_events_envelope <image> <endpoint> <label>: a node of the
# baseline fixture without event history; the command completes the protocol
# and prints a history-read-events envelope (servers answer a Bad item status
# or no events, the check takes either).
check_history_events_envelope() {
    local image="$1" endpoint="$2" label="$3" out
    at history.envelope "${label}"
    out=$(run_client_op "${image}" history-read-events --endpoint "${endpoint}" \
            --node "nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32" \
            --start 2026-07-24T10:00:00Z --end 2026-07-24T10:01:00Z) || true
    validate_envelope "${out}" "${label}:history-read-events" || return
    if echo "${out}" | jq -e '.operation == "history-read-events" and ((.success == false) or ((.results[0].events | length) == 0))' >/dev/null 2>&1; then
        ok "${label}: history-read-events on a node without event history"
    else
        fail "${label}: history-read-events on a node without event history — unexpected: ${out}"
    fi
}

# check_history_events_read <image> <endpoint> <label>: the five seeded events
# of History.Events, oldest first, and the newest first with start > end.
check_history_events_read() {
    local image="$1" endpoint="$2" label="$3" out
    at history.read "${label}"
    out=$(run_client_op "${image}" history-read-events --endpoint "${endpoint}" --node "${HEV_NODE}" \
            --start 2026-07-24T10:00:00Z --end 2026-07-24T10:01:00Z) || true
    validate_envelope "${out}" "${label}:history-read-events" || return
    if echo "${out}" | jq -e '.success == true and (.results[0].events | length) == 5
            and .results[0].events[0].fields[0].name == "EventId"
            and .results[0].events[0].fields[0].value == "aGlzdC1ldnQtMA=="
            and .results[0].events[4].fields[0].value == "aGlzdC1ldnQtNA=="' >/dev/null 2>&1; then
        ok "${label}: history-read-events forward → 5 events"
    else
        fail "${label}: history-read-events forward — unexpected: ${out}"
    fi
}

# ── Smoke checks ──────────────────────────────────────────────────────────────

check_endpoints() {
    local client_image="$1"
    local endpoint="$2"
    local label="$3"
    at endpoints "${label}"

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
    at browse "${label}"

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
    at read-scalar "${label}"

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
    at write "${label}"

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
    at call "${label}"

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
    at subscribe "${label}"

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
    at register-nodes "${label}"

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
    at channel-renewal "${label}"

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
    at deadband.absolute "${label}"

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
    at deadband.percent-no-eurange "${label}"
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
    at codec.node "${label}"

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
        at "codec.roundtrip-${fmt}-${type}" "${label}"
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
    at codec.xml-unqualified "${label}"

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

# ── Historical events (CLIENT_CONTRACT.md §17) ─────────────────────────────────

# client_has_op <image> <operation>: the image's print-capabilities lists the client operation.
client_has_op() {
    docker run --rm "$1" print-capabilities 2>/dev/null | jq -e --arg op "$2" '.clientOperations | index($op) != null' >/dev/null 2>&1
}

# hev_expect <label> <jq-filter> <output>: ok when the filter holds on the output.
hev_expect() {
    if echo "$3" | jq -e "$2" >/dev/null 2>&1; then
        ok "$1"
    else
        fail "$1 — unexpected result: $3"
    fi
}

# check_history_events <client-image> <endpoint> <label>: history-read-events and
# history-update-events against a server with history-events and
# history-events-update (s=History.Events, the reference results of §17.1).
check_history_events() {
    local img="$1" ep="$2" label="$3"
    local m="nsu=urn:otfabric:opcua-interop:model;s="
    local n="${m}History.Events"
    local fwd=(--start 2026-07-24T10:00:00Z --end 2026-07-24T10:01:00Z)
    local ids='[.results[0].events[] | .fields[0].value | @base64d]'
    local out
    b64() { printf %s "$1" | base64 | tr -d '\n'; }

    out=$(run_client_op "${img}" call --endpoint "${ep}" --object "${n}" --method "${m}History.ResetEvents") || true
    at "history.history.resetevents" "${label}"
    hev_expect "${label}: History.ResetEvents" '.success == true' "${out}"
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" "${fwd[@]}") || true
    at "history.history-read-events-forward-hist-evt-0-4-with-the-default" "${label}"
    hev_expect "${label}: history-read-events forward → hist-evt-0…4 with the default SelectClauses" \
        ".success == true and ${ids} == [\"hist-evt-0\",\"hist-evt-1\",\"hist-evt-2\",\"hist-evt-3\",\"hist-evt-4\"]
         and (.results[0].selectClauses | length) == 8
         and ([.results[0].events[0].fields[] | .dataType] == [\"ByteString\",\"NodeId\",\"NodeId\",\"String\",\"DateTime\",\"DateTime\",\"LocalizedText\",\"UInt16\"])
         and .results[0].events[0].fields[6].value.text == \"history-event-0\" and .results[0].events[4].fields[7].value == 500" "${out}"
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" \
            --start 2026-07-24T10:01:00Z --end 2026-07-24T09:59:00Z) || true
    at "history.history-read-events-reverse-hist-evt-4-0" "${label}"
    hev_expect "${label}: history-read-events reverse → hist-evt-4…0" \
        ".success == true and ${ids} == [\"hist-evt-4\",\"hist-evt-3\",\"hist-evt-2\",\"hist-evt-1\",\"hist-evt-0\"]" "${out}"
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" "${fwd[@]}" \
            --num-values 2 --scenario continue) || true
    at "history.history-read-events-num-values-2-scenario-continue-pages-2-2-1" "${label}"
    hev_expect "${label}: history-read-events --num-values 2 --scenario continue → pages 2,2,1" \
        '.success == true and [.results[0].pages[] | (.events | length)] == [2,2,1] and (.results[0].events | length) == 5
         and .results[0].continuationPoint == null and .results[0].releaseStatusCode != null' "${out}"
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" "${fwd[@]}" --of-type i=2130) || true
    at "history.history-read-events-of-type-i-2130-hist-evt-3" "${label}"
    hev_expect "${label}: history-read-events --of-type i=2130 → hist-evt-3" \
        ".success == true and ${ids} == [\"hist-evt-3\"]" "${out}"
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" "${fwd[@]}" --min-severity 300) || true
    at "history.history-read-events-min-severity-300-hist-evt-2-4" "${label}"
    hev_expect "${label}: history-read-events --min-severity 300 → hist-evt-2…4" \
        ".success == true and ${ids} == [\"hist-evt-2\",\"hist-evt-3\",\"hist-evt-4\"]" "${out}"
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" "${fwd[@]}" \
            --of-type i=2041 --min-severity 300 --select EventId --select Severity) || true
    at "history.history-read-events-of-type-i-2041-min-severity-300-and-hist" "${label}"
    hev_expect "${label}: history-read-events --of-type i=2041 --min-severity 300 (And) → hist-evt-2…4" \
        ".success == true and ${ids} == [\"hist-evt-2\",\"hist-evt-3\",\"hist-evt-4\"] and .results[0].selectClauses == [\"EventId\",\"Severity\"]" "${out}"

    local sel=(--select EventId --select EventType --select Time --select Severity --select Message)

    ev() { # ev <event-id> <time> <severity> <text>
        printf '{"EventId":{"type":"ByteString","value":"%s"},"EventType":{"type":"NodeId","value":"i=2041"},"Time":{"type":"DateTime","value":"%s"},"Severity":{"type":"UInt16","value":%s},"Message":{"type":"LocalizedText","value":{"locale":"en","text":"%s"}}}' \
            "$(b64 "$1")" "$2" "$3" "$4"
    }
    local ops='[.results[0].operationResults[].code]'
    # GoodEntryInserted 0x00A20000, GoodEntryReplaced 0x00A30000, BadEntryExists 0x809F0000, BadNoEntryExists 0x80A00000
    out=$(run_client_op "${img}" history-update-events --endpoint "${ep}" --node "${n}" --perform insert "${sel[@]}" \
            --event "$(ev hist-evt-5 2026-07-24T10:00:25Z 600 inserted)" --event "$(ev hist-evt-0 2026-07-24T10:00:00Z 700 dup)") || true
    at "history.history-update-events-insert-goodentryinserted-badentryexists" "${label}"
    hev_expect "${label}: history-update-events insert → GoodEntryInserted, BadEntryExists" \
        ".success == true and .results[0].performUpdateType == \"Insert\" and ${ops} == [10616832, 2157903872]" "${out}"
    out=$(run_client_op "${img}" history-update-events --endpoint "${ep}" --node "${n}" --perform replace "${sel[@]}" \
            --event "$(ev hist-evt-0 2026-07-24T10:00:00Z 700 replaced)" --event "$(ev hist-evt-9 2026-07-24T10:00:30Z 900 nope)") || true
    at "history.history-update-events-replace-goodentryreplaced-badnoentryexists" "${label}"
    hev_expect "${label}: history-update-events replace → GoodEntryReplaced, BadNoEntryExists" \
        ".success == true and ${ops} == [10682368, 2157969408]" "${out}"
    out=$(run_client_op "${img}" history-update-events --endpoint "${ep}" --node "${n}" --perform update "${sel[@]}" \
            --event "$(ev hist-evt-9 2026-07-24T10:00:30Z 900 upserted)" --event "$(ev hist-evt-0 2026-07-24T10:00:00Z 800 updated)") || true
    at "history.history-update-events-update-goodentryinserted-goodentryreplaced" "${label}"
    hev_expect "${label}: history-update-events update → GoodEntryInserted, GoodEntryReplaced" \
        ".success == true and ${ops} == [10616832, 10682368]" "${out}"
    out=$(run_client_op "${img}" history-update-events --endpoint "${ep}" --node "${n}" --perform delete \
            --event-id "$(b64 hist-evt-1)" --event-id "$(b64 no-such-event)") || true
    at "history.history-update-events-delete-good-badnoentryexists" "${label}"
    hev_expect "${label}: history-update-events delete → Good, BadNoEntryExists" \
        ".success == true and .results[0].performUpdateType == \"Delete\" and ${ops} == [0, 2157969408]" "${out}"
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" "${fwd[@]}" \
            --select EventId --select Severity --select Message) || true
    at "history.history-read-events-after-the-updates" "${label}"
    hev_expect "${label}: history-read-events after the updates" \
        ".success == true and ${ids} == [\"hist-evt-0\",\"hist-evt-2\",\"hist-evt-3\",\"hist-evt-4\",\"hist-evt-5\",\"hist-evt-9\"]
         and .results[0].events[0].fields[1].value == 800 and .results[0].events[0].fields[2].value.text == \"updated\"" "${out}"
    out=$(run_client_op "${img}" call --endpoint "${ep}" --object "${n}" --method "${m}History.ResetEvents") || true
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node "${n}" "${fwd[@]}") || true
    at "history.history-read-events-after-history.resetevents-the-seed" "${label}"
    hev_expect "${label}: history-read-events after History.ResetEvents → the seed" \
        ".success == true and ${ids} == [\"hist-evt-0\",\"hist-evt-1\",\"hist-evt-2\",\"hist-evt-3\",\"hist-evt-4\"]" "${out}"
}

# check_history_events_unsupported <client-image> <endpoint> <label>: the node-opcua
# server has no event history (§17.3): HistoryRead with ReadEventDetails is the
# service fault BadHistoryOperationInvalid, HistoryUpdate BadServiceUnsupported.
check_history_events_unsupported() {
    local img="$1" ep="$2" label="$3" out
    out=$(run_client_op "${img}" history-read-events --endpoint "${ep}" --node i=2253 \
            --start 2026-07-24T10:00:00Z --end 2026-07-24T10:01:00Z) || true
    at "history.history-read-events-badhistoryoperationinvalid-no-event-history" "${label}"
    hev_expect "${label}: history-read-events → BadHistoryOperationInvalid (no event history, §17.3)" \
        '.success == false and .serviceResult.name == "BadHistoryOperationInvalid"' "${out}"
    out=$(run_client_op "${img}" history-update-events --endpoint "${ep}" --node i=2253 --perform delete --event-id AAAA) || true
    at "history.history-update-events-badserviceunsupported-17.3" "${label}"
    hev_expect "${label}: history-update-events → BadServiceUnsupported (§17.3)" \
        '.success == false and .serviceResult.name == "BadServiceUnsupported" and .results == []' "${out}"
}

feature_cleanup() {
    local c img=""
    for c in ${FEAT_CONTAINERS[@]+"${FEAT_CONTAINERS[@]}"}; do
        [[ -n "${img}" ]] || img=$(docker inspect -f '{{.Config.Image}}' "${c}" 2>/dev/null || true)
        docker rm -f "${c}" &>/dev/null || true
    done
    FEAT_CONTAINERS=()
    if [[ -n "${FEAT_NET}" ]]; then docker network rm "${FEAT_NET}" &>/dev/null || true; FEAT_NET=""; fi
    if [[ -n "${FEAT_TMP}" ]]; then
        # The adapters write into their mounted PKI directories (Milo's issuer
        # store, node-opcua's own/), and on Linux those files belong to the
        # container's user: remove them as root through one of the images.
        if ! rm -rf "${FEAT_TMP}" 2>/dev/null && [[ -n "${img}" ]]; then
            docker run --rm --user 0 --entrypoint sh -v "${FEAT_TMP}:/scratch" "${img}" \
                -c 'rm -rf /scratch/* /scratch/.[!.]*' >/dev/null 2>&1 || true
            rm -rf "${FEAT_TMP}"
        fi
        FEAT_TMP=""
    fi
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
    at "features.basic256sha256-signandencrypt-username" "o62541→o62541"
    feat_expect "o62541→o62541: Basic256Sha256/SignAndEncrypt + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    if [[ -n "${img_milo}" ]]; then
        out=$(feat_client "${img_milo}" - read --endpoint "${lds_url}" --node "${model}Scalar.Int32" \
                --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt \
                --certificate /pki/milo-client/cert.crt --private-key /pki/milo-client/cert.key \
                --trust-list /pki/ca/ca.crt) || true
        at "features.aes256_sha256_rsapss-signandencrypt" "milo→o62541"
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
        at "features.${policy}-${mode}-username" "o62541→o62541"
        feat_expect "o62541→o62541: ${policy}/${mode} + username" \
            '.success == true and .results[0].value == -123456789' "${out}"
    done
    out=$(feat_client "${img}" - read --endpoint "${lds_url}" --node "${model}Scalar.Int32" \
            --security-policy ECC_nistP256 --security-mode SignAndEncrypt \
            --certificate /pki/untrusted/ecc-nistp256/cert.crt \
            --private-key /pki/untrusted/ecc-nistp256/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    at "features.untrusted-ecc-certificate-is-rejected" "o62541→o62541"
    feat_expect "o62541→o62541: untrusted ECC certificate is rejected" \
        '.success == false and .serviceResult.severity == "Bad"' "${out}"

    # Reverse connect: the client listens, the server dials in (ReverseHello).
    out=$(feat_client "${img}" "${rclient}" read --endpoint "${lds_url}" \
            --node "${model}Scalar.Int32" --reverse-listen 4855 --reverse-timeout-ms 30000 \
            --reverse-server-uri urn:otfabric:opcua-interop:server) || true
    at "features.o62541-reverse-connect-none-none"
    feat_expect "o62541 reverse connect: None/None" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img}" "${rclient}" subscribe --endpoint "${lds_url}" \
            --node "${model}Dynamic.Counter" --notifications 2 \
            --reverse-listen 4855 --reverse-timeout-ms 30000 \
            --security-policy ECC_nistP256 --security-mode SignAndEncrypt \
            --certificate /pki/open62541-client/ecc-nistp256/cert.crt \
            --private-key /pki/open62541-client/ecc-nistp256/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    at "features.o62541-reverse-connect-ecc_nistp256-signandencrypt-subscription"
    feat_expect "o62541 reverse connect: ECC_nistP256/SignAndEncrypt subscription" \
        '.success == true and (.results[0].notifications | length) == 2' "${out}"
    out=$(feat_client "${img}" "${rclient}" endpoints --endpoint "${lds_url}" \
            --reverse-listen 4855 --reverse-timeout-ms 30000) || true
    at "features.o62541-reverse-connect-getendpoints"
    feat_expect "o62541 reverse connect: GetEndpoints" \
        '.success == true and (.results | length) > 1' "${out}"

    # Discovery: the member registered itself (RegisterServer2), a client
    # registers / unregisters a made-up server, mDNS records are served.
    local clients=("${img}")
    local names=("o62541")
    if [[ -n "${img_milo}" ]]; then clients+=("${img_milo}"); names+=("milo"); fi
    out=$(feat_client "${img}" - find-servers --endpoint "${lds_url}") || true
    at "features.lds-findservers-lists-the-registered-${member_name}-server"
    feat_expect "LDS FindServers lists the registered ${member_name} server" \
        "[.results[].discoveryUrls[]] | index(\"opc.tcp://${member}:4840${ENDPOINT_PATH}\") != null" "${out}"
    local i
    for i in "${!clients[@]}"; do
        local c="${clients[$i]}" n="${names[$i]}"
        out=$(feat_client "${c}" - find-servers-on-network --endpoint "${lds_url}") || true
        at "features.findserversonnetwork-lds-record-registered-server" "${n}→LDS"
        feat_expect "${n}→LDS: FindServersOnNetwork (LDS record + registered server)" \
            ".success == true
             and ([.results[] | select(.serverCapabilities | index(\"LDS\"))] | length) >= 1
             and ([.results[] | select(.discoveryUrl | test(\"${member}\"))] | length) >= 1" "${out}"
        out=$(feat_client "${c}" - register-server --endpoint "${lds_url}" \
                --server-uri "urn:smoke:${n}" --server-name "smoke ${n}" \
                --discovery-url "opc.tcp://smoke-${n}:4999" --mdns-name "smoke-${n}") || true
        at "features.register-server-registerserver2" "${n}→LDS"
        feat_expect "${n}→LDS: register-server (RegisterServer2)" \
            '.success == true and .results[0].service == "RegisterServer2"' "${out}"
        out=$(feat_client "${img}" - find-servers --endpoint "${lds_url}") || true
        at "features.registration-visible-in-findservers" "${n}→LDS"
        feat_expect "${n}→LDS: registration visible in FindServers" \
            "[.results[].applicationUri] | index(\"urn:smoke:${n}\") != null" "${out}"
        out=$(feat_client "${c}" - register-server --endpoint "${lds_url}" \
                --server-uri "urn:smoke:${n}" --discovery-url "opc.tcp://smoke-${n}:4999" \
                --mdns-name "smoke-${n}" --online false) || true
        out=$(feat_client "${img}" - find-servers --endpoint "${lds_url}") || true
        at "features.unregistered-server-is-gone" "${n}→LDS"
        feat_expect "${n}→LDS: unregistered server is gone" \
            "[.results[].applicationUri] | index(\"urn:smoke:${n}\") == null" "${out}"
    done
    out=$(feat_client "${img}" - register-server --endpoint "opc.tcp://${member}:4840${ENDPOINT_PATH}" \
            --server-uri urn:smoke:x --discovery-url opc.tcp://x:1) || true
    at "features.register-server-against-a-non-lds-${member_name}-reports-the"
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
    at none-none-session "o62541→async-opcua"
    output=$(run_client_op "${client_image}" read --endpoint "${endpoint}" --node "${node}") || true
    validate_envelope "${output}" "o62541→async-opcua:read" || return
    if echo "${output}" | jq -e '.success == false and .serviceResult.name == "BadSecurityChecksFailed"' >/dev/null 2>&1; then
        known async-opcua-null-session-nonce "o62541→async-opcua: None/None session refused (known async-opcua 0.19 deviation: null ActivateSession nonce)"
    elif echo "${output}" | jq -e '.success == true' >/dev/null 2>&1; then
        stale async-opcua-null-session-nonce "o62541→async-opcua: None/None read succeeded — the ActivateSession nonce deviation is gone; run check_interop_set for this pair"
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
    at channel-renewal "o62541→node-opcua"
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
        known node-opcua-renewal-old-token "o62541→node-opcua: subscription stalled after a SecureChannel renewal (known node-opcua 2.187 deviation: responses keep the request's old token)"
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
        at secure.pki
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
    at "secure.basic256sha256-signandencrypt-read" "o62541→async-opcua"
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - write --endpoint "${url}" --node "${model}Access.ReadWrite" \
            --type Int32 --value 4242 "${b256[@]}" "${o62541[@]}") || true
    at "secure.basic256sha256-signandencrypt-write" "o62541→async-opcua"
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt write" \
        '.success == true and .results[0].statusCode.name == "Good"' "${out}"
    out=$(feat_client "${img_open62541}" - call --endpoint "${url}" --object "${model}Methods" \
            --method "${model}Methods.Add" --input Int32:10 --input Int32:20 "${b256[@]}" "${o62541[@]}") || true
    at "secure.basic256sha256-signandencrypt-call-methods.add-10-20-30" "o62541→async-opcua"
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt call Methods.Add(10,20)=30" \
        '.success == true and .results[0].outputArguments[0] == 30' "${out}"
    out=$(feat_client "${img_open62541}" - subscribe --endpoint "${url}" --node "${model}Dynamic.Counter" \
            --publishing-interval-ms 500 --notifications 3 --timeout-ms 15000 \
            "${b256[@]}" "${o62541[@]}") || true
    at "secure.basic256sha256-signandencrypt-subscribe-dynamic.counter" "o62541→async-opcua"
    feat_expect "o62541→async-opcua: Basic256Sha256/SignAndEncrypt subscribe Dynamic.Counter" \
        '.success == true and (.results[0].notifications | length) >= 3' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Basic256Sha256 --security-mode Sign "${o62541[@]}" \
            --username test-user --password test-password) || true
    at "secure.basic256sha256-sign-username" "o62541→async-opcua"
    feat_expect "o62541→async-opcua: Basic256Sha256/Sign + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes128_Sha256_RsaOaep --security-mode SignAndEncrypt "${o62541[@]}") || true
    at "secure.aes128_sha256_rsaoaep-signandencrypt-read" "o62541→async-opcua"
    feat_expect "o62541→async-opcua: Aes128_Sha256_RsaOaep/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt \
            --certificate /pki/milo-client/cert.crt --private-key /pki/milo-client/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    at "secure.aes256_sha256_rsapss-signandencrypt-read" "milo→async-opcua"
    feat_expect "milo→async-opcua: Aes256_Sha256_RsaPss/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" --certificate /pki/untrusted/cert.crt --private-key /pki/untrusted/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    at "secure.untrusted-client-certificate-is-rejected" "o62541→async-opcua"
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
        at secure.pki
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
    at "secure.basic256sha256-signandencrypt-read" "o62541→node-opcua"
    feat_expect "o62541→node-opcua: Basic256Sha256/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - call --endpoint "${url}" --object "${model}Methods" \
            --method "${model}Methods.Add" --input Int32:10 --input Int32:20 "${b256[@]}" "${o62541[@]}") || true
    at "secure.basic256sha256-signandencrypt-call-methods.add-10-20-30" "o62541→node-opcua"
    feat_expect "o62541→node-opcua: Basic256Sha256/SignAndEncrypt call Methods.Add(10,20)=30" \
        '.success == true and .results[0].outputArguments[0] == 30' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Basic256Sha256 --security-mode Sign "${o62541[@]}" \
            --username test-user --password test-password) || true
    at "secure.basic256sha256-sign-username" "o62541→node-opcua"
    feat_expect "o62541→node-opcua: Basic256Sha256/Sign + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes128_Sha256_RsaOaep --security-mode SignAndEncrypt "${milo[@]}") || true
    at "secure.aes128_sha256_rsaoaep-signandencrypt-read" "milo→node-opcua"
    feat_expect "milo→node-opcua: Aes128_Sha256_RsaOaep/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - subscribe --endpoint "${url}" --node "${model}Dynamic.Counter" \
            --publishing-interval-ms 500 --notifications 3 --timeout-ms 15000 \
            --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt "${milo[@]}") || true
    at "secure.aes256_sha256_rsapss-signandencrypt-subscribe-dynamic.counter" "milo→node-opcua"
    feat_expect "milo→node-opcua: Aes256_Sha256_RsaPss/SignAndEncrypt subscribe Dynamic.Counter" \
        '.success == true and (.results[0].notifications | length) >= 3' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" --certificate /pki/untrusted/cert.crt --private-key /pki/untrusted/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    at "secure.untrusted-client-certificate-is-rejected" "o62541→node-opcua"
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
        at "secure.basic256sha256-signandencrypt-read" "node-opcua→${peer}"
        feat_expect "node-opcua→${peer}: Basic256Sha256/SignAndEncrypt read" \
            '.success == true and .results[0].value == -123456789' "${out}"
        out=$(feat_client "${img_node_opcua}" - read --endpoint "opc.tcp://${psrv}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt \
                "${node[@]}" --username test-user --password test-password) || true
        at "secure.aes256_sha256_rsapss-signandencrypt-username" "node-opcua→${peer}"
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
    case "${adapter}" in
        dotnet)
            check_history_events "${image}" "${endpoint}" "${adapter}→${adapter}"
            ;;
        node-opcua)
            check_history_events_unsupported "${image}" "${endpoint}" "${adapter}→${adapter}"
            ;;
        asyncua)
            check_history_events_caps "${image}" "${adapter}"
            check_history_events_read "${image}" "${endpoint}" "${adapter}→${adapter}"
            check_asyncua_history_update_deviation "${image}" "${endpoint}" "${adapter}→${adapter}"
            ;;
        async-opcua|open62541|milo)
            check_history_events_caps "${image}" "${adapter}"
            check_history_events_envelope "${image}" "${endpoint}" "${adapter}→${adapter}"
            ;;
    esac

    stop_server "${cname}"
    if [[ "${adapter}" == "open62541" ]]; then
        run_open62541_features "${image}"
    elif [[ "${adapter}" == "dotnet" ]]; then
        run_dotnet_chain_checks "${image}"
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

# run_dotnet_chain_checks <dotnet-image> [open62541-image]: the dotnet server
# with the dotnet-server identity of the test PKI, once with the default
# certificate chain and once with --no-certificate-chain (CLIENT_CONTRACT.md
# §11, §16.3). The dotnet client takes both. open62541 v1.5.9 compares the
# CreateSession ServerCertificate with the leaf byte for byte, so it connects
# only to the --no-certificate-chain server; the chained server is checked as a
# known limitation and fails when open62541 takes chains.
run_dotnet_chain_checks() {
    local img_dotnet="$1" img_open62541="${2:-}"
    local model="nsu=urn:otfabric:opcua-interop:model;s="

    prepare_pki
    FEAT_NET="smoke-net-$$"
    docker network create "${FEAT_NET}" >/dev/null
    local chain="smoke-dotnet-chain-$$" leaf="smoke-dotnet-leaf-$$" c
    FEAT_CONTAINERS+=("${chain}" "${leaf}")
    log "Starting dotnet servers with a CA-signed certificate (chain, --no-certificate-chain)..."
    for c in "${chain}" "${leaf}"; do
        local extra=()
        [[ "${c}" == "${leaf}" ]] && extra=(--no-certificate-chain)
        docker run -d --name "${c}" --network "${FEAT_NET}" \
            -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
            "${img_dotnet}" server --fixture /fixtures/baseline/fixture.json \
            --advertised-host "${c}" --endpoint-path "${ENDPOINT_PATH}" \
            --certificate /pki/dotnet-server/cert.crt --private-key /pki/dotnet-server/cert.key \
            --pki-dir /pki/dotnet-server/pki ${extra[@]+"${extra[@]}"} >/dev/null
    done
    wait_ready "${chain}"
    wait_ready "${leaf}"
    at chain.no-certificate-chain
    if docker logs "${leaf}" 2>&1 | grep "sent without its issuer chain" >/dev/null; then
        ok "dotnet: --no-certificate-chain"
    else
        fail "dotnet: --no-certificate-chain not applied"
    fi

    local b256=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt)
    local dn=(--certificate /pki/dotnet-client/cert.crt --private-key /pki/dotnet-client/cert.key
              --trust-list /pki/ca/ca.crt)
    local o62541=(--certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key
                  --trust-list /pki/ca/ca.crt)
    local out
    for c in "${chain}:chain" "${leaf}:--no-certificate-chain"; do
        out=$(feat_client "${img_dotnet}" - read --endpoint "opc.tcp://${c%%:*}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" "${b256[@]}" "${dn[@]}") || true
        at "chain.basic256sha256-signandencrypt-read" "dotnet→dotnet (${c#*:})"
        feat_expect "dotnet→dotnet (${c#*:}): Basic256Sha256/SignAndEncrypt read" \
            '.success == true and .results[0].value == -123456789' "${out}"
    done
    if [[ -n "${img_open62541}" ]]; then
        out=$(feat_client "${img_open62541}" - read --endpoint "opc.tcp://${leaf}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" "${b256[@]}" "${o62541[@]}") || true
        at "chain.basic256sha256-signandencrypt-read" "o62541→dotnet (--no-certificate-chain)"
        feat_expect "o62541→dotnet (--no-certificate-chain): Basic256Sha256/SignAndEncrypt read" \
            '.success == true and .results[0].value == -123456789' "${out}"
        out=$(feat_client "${img_open62541}" - read --endpoint "opc.tcp://${chain}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" "${b256[@]}" "${o62541[@]}") || true
        at chain.basic256sha256-read "o62541→dotnet (chain)"
        if echo "${out}" | jq -e '.success == false and .serviceResult.name == "BadCertificateInvalid"' >/dev/null 2>&1; then
            known open62541-chain-leaf-compare "o62541→dotnet (chain): BadCertificateInvalid (known open62541 v1.5.9 limitation: CreateSession certificate compared with the leaf, CLIENT_CONTRACT.md §16.3)"
        elif echo "${out}" | jq -e '.success == true' >/dev/null 2>&1; then
            stale open62541-chain-leaf-compare "o62541→dotnet (chain): secure read succeeded — open62541 takes the chain now; update CLIENT_CONTRACT.md §16.3"
        else
            fail "o62541→dotnet (chain): unexpected result: ${out}"
        fi
    fi
    feature_cleanup
}

run_cross_dotnet_smoke() {
    local img_dotnet="$1"
    local img_open62541="$2"
    local img_milo="$3"
    local img_node_opcua="${4:-}"
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

    # The dotnet event history fixture (§17) from every client that has the
    # operations (node-opcua since adapter 0.17.0, the others when they declare them).
    local img
    for img in "${img_open62541}" "${img_milo}" ${img_node_opcua:+"${img_node_opcua}"}; do
        if client_has_op "${img}" history-read-events; then
            log "Cross-stack: ${img} client → dotnet-server, historical events"
            check_history_events "${img}" "${ep_dotnet}" "${img##*/}→dotnet"
        fi
    done

    log "Cross-stack: codec documents of dotnet decoded by the reference stacks and back"
    check_codec_roundtrip "${img_dotnet}" "${img_open62541}" "dotnet→o62541"
    check_codec_roundtrip "${img_open62541}" "${img_dotnet}" "o62541→dotnet" json
    check_codec_xml_unqualified_rejected "${img_open62541}" "${img_dotnet}" "o62541→dotnet"
    check_codec_roundtrip "${img_dotnet}" "${img_milo}" "dotnet→milo"
    check_codec_roundtrip "${img_milo}" "${img_dotnet}" "milo→dotnet"

    stop_server "${cname_open62541}"
    stop_server "${cname_milo}"
    stop_server "${cname_dotnet}"
    trap feature_cleanup EXIT
    log "Cross-stack: open62541-client → dotnet-server, certificate chain"
    run_dotnet_chain_checks "${img_dotnet}" "${img_open62541}"
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
    at deadband.percent-no-eurange "${label}"
    validate_envelope "${output}" "${label}:percent-deadband" || return
    if echo "${output}" | jq -e '.success == true and .results[0].monitoredItemStatusCode.code == 0' >/dev/null 2>&1; then
        known asyncua-percent-deadband "${label}: percent deadband without EURange accepted (known asyncua 2.1.0 deviation, asyncua/README.md)"
    elif echo "${output}" | jq -e '.results[0].monitoredItemStatusCode.severity == "Bad"' >/dev/null 2>&1; then
        stale asyncua-percent-deadband "${label}: percent deadband without EURange is rejected now — the asyncua deviation is gone; run check_deadband for this server"
    else
        fail "${label}: percent deadband — unexpected result: ${output}"
    fi
}

# asyncua 2.1.0 has no HistoryUpdate: its permission ruleset refuses the
# request for the User role the adapter gives every session
# (BadUserAccessDenied), and the dispatcher has no handler behind it
# (BadServiceUnsupported for Admin) — asyncua/README.md. The check fails when
# that changes.
check_asyncua_history_update_deviation() {
    local image="$1" endpoint="$2" label="$3" out
    out=$(run_client_op "${image}" history-update-events --endpoint "${endpoint}" --node "${HEV_NODE}" \
            --perform delete --event-id aGlzdC1ldnQtMA==) || true
    at history.update-refused "${label}"
    validate_envelope "${out}" "${label}:history-update-events" || return
    if echo "${out}" | jq -e '.success == false and (.serviceResult.name == "BadUserAccessDenied" or .serviceResult.name == "BadServiceUnsupported")' >/dev/null 2>&1; then
        known asyncua-no-history-update "${label}: history-update-events refused (known asyncua 2.1.0 deviation, asyncua/README.md)"
    else
        stale asyncua-no-history-update "${label}: history-update-events — unexpected (did asyncua gain HistoryUpdate?): ${out}"
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
        at secure.pki
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
    at "secure.basic256sha256-signandencrypt-read" "o62541→asyncua"
    feat_expect "o62541→asyncua: Basic256Sha256/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - call --endpoint "${url}" --object "${model}Methods" \
            --method "${model}Methods.Add" --input Int32:10 --input Int32:20 "${b256[@]}" "${o62541[@]}") || true
    at "secure.basic256sha256-signandencrypt-call-methods.add-10-20-30" "o62541→asyncua"
    feat_expect "o62541→asyncua: Basic256Sha256/SignAndEncrypt call Methods.Add(10,20)=30" \
        '.success == true and .results[0].outputArguments[0] == 30' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Basic256Sha256 --security-mode Sign "${o62541[@]}" \
            --username test-user --password test-password) || true
    at "secure.basic256sha256-sign-username" "o62541→asyncua"
    feat_expect "o62541→asyncua: Basic256Sha256/Sign + username" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            --security-policy Aes128_Sha256_RsaOaep --security-mode SignAndEncrypt "${o62541[@]}") || true
    at "secure.aes128_sha256_rsaoaep-signandencrypt-read" "o62541→asyncua"
    feat_expect "o62541→asyncua: Aes128_Sha256_RsaOaep/SignAndEncrypt read" \
        '.success == true and .results[0].value == -123456789' "${out}"
    out=$(feat_client "${img_milo}" - subscribe --endpoint "${url}" --node "${model}Dynamic.Counter" \
            --publishing-interval-ms 500 --notifications 3 --timeout-ms 15000 \
            --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt "${milo[@]}") || true
    at "secure.aes256_sha256_rsapss-signandencrypt-subscribe-dynamic.counter" "milo→asyncua"
    feat_expect "milo→asyncua: Aes256_Sha256_RsaPss/SignAndEncrypt subscribe Dynamic.Counter" \
        '.success == true and (.results[0].notifications | length) >= 3' "${out}"
    out=$(feat_client "${img_open62541}" - read --endpoint "${url}" --node "${model}Scalar.Int32" \
            "${b256[@]}" --certificate /pki/untrusted/cert.crt --private-key /pki/untrusted/cert.key \
            --trust-list /pki/ca/ca.crt) || true
    at "secure.untrusted-client-certificate-is-rejected" "o62541→asyncua"
    feat_expect "o62541→asyncua: untrusted client certificate is rejected" \
        '.success == false' "${out}"

    local target name
    for target in "${o_srv}:o62541" "${m_srv}:milo"; do
        name="${target#*:}"; target="${target%%:*}"
        out=$(feat_client "${img_asyncua}" - read --endpoint "opc.tcp://${target}:4840${ENDPOINT_PATH}" \
                --node "${model}Scalar.Int32" "${b256[@]}" "${aua[@]}" \
                --username test-user --password test-password) || true
        at "secure.basic256sha256-signandencrypt-username" "asyncua→${name}"
        feat_expect "asyncua→${name}: Basic256Sha256/SignAndEncrypt + username" \
            '.success == true and .results[0].value == -123456789' "${out}"
        out=$(feat_client "${img_asyncua}" - write --endpoint "opc.tcp://${target}:4840${ENDPOINT_PATH}" \
                --node "${model}Access.ReadWrite" --type Int32 --value 4242 \
                --security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt "${aua[@]}") || true
        at "secure.aes256_sha256_rsapss-signandencrypt-write" "asyncua→${name}"
        feat_expect "asyncua→${name}: Aes256_Sha256_RsaPss/SignAndEncrypt write" \
            '.success == true and .results[0].statusCode.name == "Good"' "${out}"
    done
    # The client checks the server certificate against --trust-list.
    out=$(feat_client "${img_asyncua}" - read --endpoint "opc.tcp://${m_srv}:4840${ENDPOINT_PATH}" \
            --node "${model}Scalar.Int32" "${b256[@]}" \
            --certificate /pki/asyncua-client/cert.crt --private-key /pki/asyncua-client/cert.key \
            --trust-list /pki/untrusted/cert.crt) || true
    at "secure.server-certificate-not-issued-by-a-trust-list-entry-is-rejected" "asyncua→milo"
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
    at lds.asyncua-registered
    if [[ "${registered}" == 1 ]]; then
        ok "asyncua server registered with the open62541 LDS (--register-with, RegisterServer)"
    else
        fail "asyncua server is not listed by the open62541 LDS after 30 polls: ${out}"
    fi
    out=$(feat_client "${img_asyncua}" - find-servers-on-network --endpoint "${lds_url}") || true
    at "secure.findserversonnetwork-lds-record" "asyncua→LDS"
    feat_expect "asyncua→LDS: FindServersOnNetwork (LDS record)" \
        '.success == true and ([.results[] | select(.serverCapabilities | index("LDS"))] | length) >= 1' "${out}"
    out=$(feat_client "${img_asyncua}" - register-server --endpoint "${lds_url}" \
            --server-uri urn:smoke:asyncua --server-name "smoke asyncua" \
            --discovery-url opc.tcp://smoke-asyncua:4999 --mdns-name smoke-asyncua) || true
    at "secure.register-server-registerserver2" "asyncua→LDS"
    feat_expect "asyncua→LDS: register-server (RegisterServer2)" \
        '.success == true and .results[0].service == "RegisterServer2"' "${out}"
    out=$(feat_client "${img_open62541}" - find-servers --endpoint "${lds_url}") || true
    at "secure.registration-visible-in-findservers" "asyncua→LDS"
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
    check_history_events_read "${img_open62541}" "${ep_asyncua}" "o62541→asyncua"
    check_history_events_read "${img_milo}" "${ep_asyncua}" "milo→asyncua"
    if [[ -n "${img_async_opcua}" ]]; then
        local ep_async_opcua="opc.tcp://localhost:${port_async_opcua}${ENDPOINT_PATH}"
        log "Cross-stack: asyncua ↔ async-opcua"
        run_asyncua_pair_checks "${img_asyncua}" "${ep_async_opcua}" "asyncua→async-opcua"
        run_asyncua_pair_checks "${img_async_opcua}" "${ep_asyncua}" "async-opcua→asyncua" no
        check_history_events_read "${img_async_opcua}" "${ep_asyncua}" "async-opcua→asyncua"
    fi
    if [[ -n "${img_dotnet}" ]]; then
        local ep_dotnet="opc.tcp://localhost:${port_dotnet}${ENDPOINT_PATH}"
        log "Cross-stack: asyncua ↔ dotnet"
        run_asyncua_pair_checks "${img_asyncua}" "${ep_dotnet}" "asyncua→dotnet"
        run_asyncua_pair_checks "${img_dotnet}" "${ep_asyncua}" "dotnet→asyncua" no
        check_history_events_read "${img_dotnet}" "${ep_asyncua}" "dotnet→asyncua"
    fi

    for cname in "${servers[@]}"; do stop_server "${cname}"; done
    trap "feature_cleanup" EXIT
    run_asyncua_secure_cross "${img_asyncua}" "${img_open62541}" "${img_milo}"
    trap - EXIT
}

# ── Mode: dotnet-gds (GDS pull model, docs/CLIENT_CONTRACT.md §16) ─────────────

# The GDS server of the dotnet-gds image on a feature network (fixtures/gds,
# the dotnet-server identity of the test PKI) and its own client gds-pull
# against it: CSR and new key pair over Basic256Sha256/SignAndEncrypt with the
# gds-admin user, revoke and unregister; anonymous RegisterApplication is denied
# (UA-.NETStandard 2.0.1 lets anyone call FindApplications, Part 12 §6.5.3).
run_dotnet_gds_smoke() {
    local img="$1"

    prepare_pki
    FEAT_NET="smoke-net-$$"
    docker network create "${FEAT_NET}" >/dev/null
    local gds="smoke-gds-$$"
    FEAT_CONTAINERS+=("${gds}")
    trap feature_cleanup EXIT

    log "Starting dotnet-gds Global Discovery Server..."
    docker run -d --name "${gds}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img}" server --fixture /fixtures/gds/fixture.json \
        --advertised-host "${gds}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/dotnet-server/cert.crt --private-key /pki/dotnet-server/cert.key \
        --pki-dir /pki/dotnet-server/pki >/dev/null
    wait_ready "${gds}"

    local ep="opc.tcp://${gds}:4840${ENDPOINT_PATH}"
    local sec=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt
               --certificate /pki/dotnet-client/cert.crt --private-key /pki/dotnet-client/cert.key
               --trust-list /pki/ca/ca.crt)
    local admin=(--username gds-admin --password gds-admin-password)
    local out kind

    out=$(docker run --rm "${img}" print-capabilities) || true
    at "gds.dotnet-gds-print-capabilities"
    feat_expect "dotnet-gds: print-capabilities" \
        '.adapter.name == "dotnet-gds" and (.clientOperations | index("gds-pull")) and (.serverFeatures | index("gds-pull"))' "${out}"

    out=$(feat_client "${img}" - endpoints --endpoint "${ep}") || true
    at "gds.endpoints" "dotnet-gds→dotnet-gds"
    feat_expect "dotnet-gds→dotnet-gds: endpoints" \
        '.success == true and ([.results[] | select(.securityMode == "SignAndEncrypt")] | length) > 0' "${out}"

    for kind in csr new-key-pair; do
        out=$(feat_client "${img}" - gds-pull --endpoint "${ep}" "${sec[@]}" "${admin[@]}" \
                --app-uri "urn:opcua-interop:gds-pull:smoke-${kind}" --request "${kind}" --revoke --unregister) || true
        at "gds.gds-pull-request-${kind}-revoke-unregister" "dotnet-gds→dotnet-gds"
        feat_expect "dotnet-gds→dotnet-gds: gds-pull --request ${kind} --revoke --unregister" \
            '.success == true and .results[0].registered == true and (.results[0].certificate | length) > 0
             and (.results[0].issuerCertificates | length) > 0 and .results[0].trustList.specifiedLists == 15
             and .results[0].revokeStatus.code == 0 and .results[0].unregisterStatus.code == 0' "${out}"
    done

    out=$(feat_client "${img}" - gds-pull --endpoint "${ep}" "${sec[@]}") || true
    at "gds.anonymous-registerapplication-denied" "dotnet-gds→dotnet-gds"
    feat_expect "dotnet-gds→dotnet-gds: anonymous RegisterApplication denied" \
        '.success == false and .serviceResult.name == "BadUserAccessDenied" and .results[0].findApplications == []
         and .results[0].registerStatus.name == "BadUserAccessDenied"' "${out}"

    # --no-certificate-chain (§16.1): the leaf alone as ServerCertificate; the
    # pull model still works.
    local gds_leaf="smoke-gds-leaf-$$"
    FEAT_CONTAINERS+=("${gds_leaf}")
    docker run -d --name "${gds_leaf}" --network "${FEAT_NET}" \
        -v "${REPO_ROOT}/fixtures:/fixtures:ro" -v "${FEAT_TMP}/pki:/pki" \
        "${img}" server --fixture /fixtures/gds/fixture.json \
        --advertised-host "${gds_leaf}" --endpoint-path "${ENDPOINT_PATH}" \
        --certificate /pki/dotnet-server/cert.crt --private-key /pki/dotnet-server/cert.key \
        --pki-dir /pki/dotnet-server/pki --no-certificate-chain >/dev/null
    wait_ready "${gds_leaf}"
    at gds.no-certificate-chain
    if docker logs "${gds_leaf}" 2>&1 | grep "sent without its issuer chain" >/dev/null; then
        ok "dotnet-gds: --no-certificate-chain"
    else
        fail "dotnet-gds: --no-certificate-chain not applied"
    fi
    out=$(feat_client "${img}" - gds-pull --endpoint "opc.tcp://${gds_leaf}:4840${ENDPOINT_PATH}" "${sec[@]}" "${admin[@]}" \
            --app-uri "urn:opcua-interop:gds-pull:smoke-leaf" --unregister) || true
    at "gds.gds-pull" "dotnet-gds→dotnet-gds (--no-certificate-chain)"
    feat_expect "dotnet-gds→dotnet-gds (--no-certificate-chain): gds-pull" \
        '.success == true and (.results[0].certificate | length) > 0 and .results[0].unregisterStatus.code == 0' "${out}"

    feature_cleanup
    trap - EXIT
}

# ── Entry point ───────────────────────────────────────────────────────────────

case "${MODE}" in
    dotnet-gds)
        run_dotnet_gds_smoke "${1:?image required}"
        ;;
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
        run_cross_dotnet_smoke "${1:?dotnet image required}" "${2:?open62541 image required}" "${3:?milo image required}" "${4:-}"
        ;;
    asyncua)
        run_single_smoke "asyncua" "${1:?image required}"
        ;;
    cross-asyncua)
        run_cross_asyncua_smoke "${1:?asyncua image required}" "${2:?open62541 image required}" "${3:?milo image required}" "${4:-}" "${5:-}"
        ;;
    *)
        echo "Unknown mode: ${MODE}. Use open62541, milo, async-opcua, dotnet, dotnet-gds, node-opcua, asyncua, cross, cross-dotnet or cross-asyncua." >&2
        exit 1
        ;;
esac

echo ""
log "Results: ${PASS} passed, ${FAIL} failed"

results_finish
if [[ "${PASS}" -eq 0 ]]; then log "no check passed: this run proves nothing"; exit 1; fi
[[ "${FAIL}" -eq 0 ]]
