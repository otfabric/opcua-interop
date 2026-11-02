#!/usr/bin/env bash
# Shared helpers for the self-test scripts. Source, do not execute.
#
# Servers and clients run as containers on a private Docker network and reach
# each other by container name, so no host port is published and parallel runs
# do not collide.

REGISTRY="${REGISTRY:-ghcr.io/otfabric}"
VERSION="${VERSION:-dev}"
RUN_ID="${RUN_ID:-$$}"
NETWORK="opcua-interop-${RUN_ID}"
READY_FILE="/run/opcua-interop/ready"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-60}"
ENDPOINT_PATH="/opcua-interop"
MODEL="nsu=urn:otfabric:opcua-interop:model;s="
LIB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0
FAIL=0
KNOWN=0
SKIPPED=0
# shellcheck source=scripts/results.sh
source "$(dirname "${BASH_SOURCE[0]}")/results.sh"

# DOCKER_ARGS: extra "docker run" arguments of the servers and clients.
DOCKER_ARGS=(-v "${LIB_ROOT}/fixtures:/fixtures:ro")
PKI_TMP="" PKI_IMAGE=""

log()   { echo "[$(basename "$0" .sh)] $*" >&2; }
ok()    { PASS=$((PASS + 1)); result pass; [[ -n "${VERBOSE:-}" ]] && log "ok: $*"; return 0; }
fail()  { FAIL=$((FAIL + 1)); result fail "$*"; log "FAIL: $*"; return 0; }
infra() { FAIL=$((FAIL + 1)); result infra-error "$*"; log "FAIL: $*"; return 0; }
skip()  { SKIPPED=$((SKIPPED + 1)); result unsupported "$*"; [[ -n "${VERBOSE:-}" ]] && log "skip: $*"; return 0; }
known() { KNOWN=$((KNOWN + 1)); result known-difference "$2" "$1"; [[ -n "${VERBOSE:-}" ]] && log "known: $2"; return 0; }

# image_of <adapter>: ADAPTER_IMAGE_<adapter> ("-" as "_") names an image outside
# the release set, which this repository's scripts know nothing about.
image_of() {
    local override="ADAPTER_IMAGE_${1//-/_}"
    if [[ -n "${!override:-}" ]]; then echo "${!override}"; else echo "${REGISTRY}/opcua-interop-$1:${VERSION}"; fi
}

require_tools() {
    local t
    for t in docker jq python3; do
        command -v "$t" >/dev/null || { log "missing required tool: $t"; exit 2; }
    done
}

network_up() { docker network create "${NETWORK}" >/dev/null; }

cleanup() {
    docker ps -aq --filter "label=opcua-interop.run=${RUN_ID}" | xargs -r docker rm -f >/dev/null 2>&1
    docker network rm "${NETWORK}" >/dev/null 2>&1
    if [[ -n "${PKI_TMP}" ]]; then
        # The adapters write into their mounted PKI directories (Milo's issuer
        # store, node-opcua's own/), and on Linux those files belong to the
        # container's user: remove them as root through one of the images.
        if ! rm -rf "${PKI_TMP}" 2>/dev/null && [[ -n "${PKI_IMAGE}" ]]; then
            docker run --rm --user 0 --entrypoint sh -v "${PKI_TMP}:/scratch" "${PKI_IMAGE}" \
                -c 'rm -rf /scratch/* /scratch/.[!.]*' >/dev/null 2>&1
            rm -rf "${PKI_TMP}" 2>/dev/null
        fi
        PKI_TMP=""
    fi
    return 0
}

# prepare_pki: a world-readable copy of the test PKI, mounted at /pki from here on
# (generated on demand; an existing CA and its RSA identities are kept and only
# the ECC certificates are added).
prepare_pki() {
    [[ -z "${PKI_TMP}" ]] || return 0
    local pki="${OPCUA_INTEROP_PKI_DIR:-${LIB_ROOT}/certs/test-pki}"
    if [[ ! -f "${pki}/ca/ca.crt" ]]; then
        log "Generating test PKI..."
        "${LIB_ROOT}/certs/generate.sh" >/dev/null 2>&1
    elif [[ ! -f "${pki}/open62541-server/ecc-nistp256/cert.crt" ]]; then
        log "Adding ECC certificates to the test PKI..."
        "${LIB_ROOT}/certs/generate.sh" --add-ecc >/dev/null 2>&1
    fi
    PKI_TMP=$(mktemp -d "${TMPDIR:-/tmp}/opcua-interop-smoke.XXXXXX")
    cp -R "${pki}" "${PKI_TMP}/pki"
    chmod -R a+rwX "${PKI_TMP}"
    DOCKER_ARGS+=(-v "${PKI_TMP}/pki:/pki")
}

# load_caps <adapter>...: the capability documents, for has_cap and the results.
# Needs WORK, a scratch directory.
load_caps() {
    local a doc
    for a in "$@"; do
        doc=$(docker run --rm "$(image_of "$a")" print-capabilities 2>/dev/null) \
            || { at harness.capabilities "$a" "$a"; infra "$a: print-capabilities failed: $(image_of "$a")"; return 1; }
        printf '%s\n' "${doc}" > "${WORK}/caps-$a.json"
        keep "capabilities-$a" "${doc}"
        implementation "$a" "${WORK}/caps-$a.json"
        log "$a: $(jq -r '"\(.stack.name) \(.stack.version)"' "${WORK}/caps-$a.json")"
    done
}

# has_cap <adapter> <client|server> <name>
has_cap() {
    local field='.serverFeatures'
    [[ "$2" == client ]] && field='(.clientOperations + .clientFeatures)'
    jq -e --arg n "$3" "${field} | index(\$n) != null" "${WORK}/caps-$1.json" >/dev/null 2>&1
}

has_role() { jq -e --arg r "$2" '.roles | index($r) != null' "${WORK}/caps-$1.json" >/dev/null 2>&1; }

# is_own <adapter>: an image of the organisation's own stack, not an independent engine.
is_own() { jq -e '.upstream.independentEngine == false' "${WORK}/caps-$1.json" >/dev/null 2>&1; }

# supported <client> <server> <needs>: the comma-separated list of tests/cases.tsv.
supported() {
    local need
    has_role "$1" client && has_role "$2" server || return 1
    [[ "$3" == "-" ]] && return 0
    for need in ${3//,/ }; do
        case "${need}" in
            client:*)   has_cap "$1" client "${need#client:}" || return 1 ;;
            server:!*)  has_cap "$2" server "${need#server:!}" && return 1 ;;
            server:*)   has_cap "$2" server "${need#server:}" || return 1 ;;
            server=*)   [[ "$2" == "${need#server=}" ]] || return 1 ;;
            *)          log "bad needs in a case: ${need}"; return 1 ;;
        esac
    done
    return 0
}

# ---- identities of the test PKI ----

# identity_of <adapter> <client|server>: the directory under /pki.
identity_of() {
    if is_own "$1"; then
        if [[ "$2" == client ]]; then echo consumer; else echo go-server; fi
    else
        echo "$1-$2"
    fi
}

# server_host <adapter> <container>: the name the server is reached by. The test
# certificate of an own stack's server names host.docker.internal.
server_host() { if is_own "$1"; then echo host.docker.internal; else echo "$2"; fi; }

# ---- servers ----

# SERVER_FIXTURE: the fixture of the servers (default the baseline).
SERVER_FIXTURE=/fixtures/baseline/fixture.json

# server_start <container> <adapter> [--host <advertised>] [server flags...]: starts
# it. server_up also waits for its ready file; an environment failure when it does not come up.
server_start() {
    local name="$1" adapter="$2" host="$1"; shift 2
    if [[ "${1:-}" == --host ]]; then host="$2"; shift 2; fi
    local alias=()
    [[ "${host}" == "${name}" ]] || alias=(--network-alias "${host}")
    docker rm -f "${name}" >/dev/null 2>&1
    PKI_IMAGE="$(image_of "${adapter}")"
    docker run -d --name "${name}" --network "${NETWORK}" ${alias[@]+"${alias[@]}"} \
        --label "opcua-interop.run=${RUN_ID}" "${DOCKER_ARGS[@]}" "$(image_of "${adapter}")" \
        server --fixture "${SERVER_FIXTURE}" --bind-address 0.0.0.0 --bind-port 4840 \
        --advertised-host "${host}" --endpoint-path "${ENDPOINT_PATH}" --ready-file "${READY_FILE}" "$@" >/dev/null
}

server_up() {
    local name="$1"
    server_start "$@" || { at harness.server-ready; infra "${name}: docker run failed"; return 1; }
    wait_ready "${name}" || { at harness.server-ready; infra "${name} did not become ready"; return 1; }
}

# url_of <host>: the endpoint of a server.
url_of() { echo "opc.tcp://$1:4840${ENDPOINT_PATH}"; }

# wait_ready <container>: the ready file exists only once the fixture is loaded
# and the address space is available. No fixed delays.
wait_ready() {
    local name="$1" waited=0 state
    while true; do
        state=$(docker inspect --format '{{.State.Status}}' "${name}" 2>/dev/null || echo absent)
        if [[ "${state}" != "running" ]]; then
            log "server ${name} is ${state}"; docker logs --tail 20 "${name}" >&2 2>/dev/null; return 1
        fi
        docker exec "${name}" test -f "${READY_FILE}" 2>/dev/null && return 0
        if (( waited >= WAIT_TIMEOUT * 5 )); then
            log "server ${name} not ready after ${WAIT_TIMEOUT}s"; docker logs --tail 20 "${name}" >&2; return 1
        fi
        sleep 0.2; waited=$((waited + 1))
    done
}

stop_server() { docker rm -f "$@" >/dev/null 2>&1; return 0; }

# run_client <adapter> <args...>: prints the result document and returns the exit
# code of the adapter. Capture both with
#     doc=$(run_client ...); rc=$?
# Only the first JSON line is the document: open62541 logs to stdout during a
# BadSecureChannelClosed retry. CLIENT_NAME names the container, for a server that
# dials it. CLIENT_STDIN=1 passes stdin on.
run_client() {
    local adapter="$1" raw rc=0; shift
    local extra=()
    [[ -z "${CLIENT_NAME:-}" ]] || { docker rm -f "${CLIENT_NAME}" >/dev/null 2>&1; extra+=(--name "${CLIENT_NAME}"); }
    if [[ -n "${CLIENT_STDIN:-}" ]]; then
        extra+=(-i)
        raw=$(docker run --rm --network "${NETWORK}" --label "opcua-interop.run=${RUN_ID}" "${extra[@]}" \
            "${DOCKER_ARGS[@]}" "$(image_of "${adapter}")" client "$@" 2>/dev/null) || rc=$?
    else
        raw=$(docker run --rm --network "${NETWORK}" --label "opcua-interop.run=${RUN_ID}" ${extra[@]+"${extra[@]}"} \
            "${DOCKER_ARGS[@]}" "$(image_of "${adapter}")" client "$@" 2>/dev/null </dev/null) || rc=$?
    fi
    printf '%s\n' "${raw}" | grep -m1 '^{' || printf '%s\n' "${raw}"
    return ${rc}
}

# keep <label> <document>: with REPORT_DIR, for scripts/validate-documents.py.
keep() {
    [[ -n "${REPORT_DIR:-}" ]] || return 0
    mkdir -p "${REPORT_DIR}"
    printf '%s\n' "$2" > "${REPORT_DIR}/$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_').json"
}

# check <id> <client> <server> <jq filter> <document>
check() {
    at "$1" "$2" "$3"
    if jq -e "$4" <<<"$5" >/dev/null 2>&1; then ok "$2->$3: $1"
    else fail "$2->$3: $1: ${5:0:400}"; fi
}

# ---- known deviations ----

# load_known_bugs <adapter>...: the lines of tests/known-bugs.tsv for the versions
# under test, to ${WORK}/active.
load_known_bugs() {
    local a version bug_adapter bug_version rest
    : > "${WORK}/active"; : > "${WORK}/reproduced"; : > "${WORK}/covered"
    for a in "$@"; do
        version=$(jq -r '.stack.version' "${WORK}/caps-$a.json")
        while IFS=$'\t' read -r bug_adapter bug_version rest; do
            [[ -z "${bug_adapter}" || "${bug_adapter}" == \#* ]] && continue
            if [[ "${bug_adapter}" == "$a" && "${bug_version}" == "${version}" ]]; then
                printf '%s\t%s\n' "${bug_adapter}" "${rest}" >> "${WORK}/active"
            fi
        done < "${LIB_ROOT}/tests/known-bugs.tsv"
    done
}

# judge <case> <client> <server> <exit> <expect> <document> <client exit>: the
# outcome of the scenario "at" named. An entry of known-bugs.tsv only explains a
# document that matches its signature.
judge() {
    local id="$1" client="$2" server="$3" want="$4" expect="$5" doc="$6" rc="$7" good=1
    local a c s re sig pass text wid url matched=""
    jq -e '.schemaVersion and .adapter and (.success != null)' <<<"${doc}" >/dev/null 2>&1 || good=0
    [[ "${want}" == "-" || "${want}" == "${rc}" ]] || good=0
    [[ "${good}" == 1 ]] && { jq -e "${expect}" <<<"${doc}" >/dev/null 2>&1 || good=0; }
    while IFS=$'\t' read -r a c s re sig pass text wid url; do
        # shellcheck disable=SC2053
        if [[ "${client}" == ${c} && "${server}" == ${s} && "${id}" =~ ${re} ]]; then matched=1; break; fi
    done < "${WORK}/active"
    if [[ -n "${matched}" ]]; then echo "${wid}" >> "${WORK}/covered"; fi
    if [[ "${good}" == 1 ]]; then ok "${client}->${server}: ${id}"; return 0; fi
    if [[ -n "${matched}" ]] && jq -e "${sig}" <<<"${doc}" >/dev/null 2>&1; then
        echo "${wid}" >> "${WORK}/reproduced"
        known "${wid}" "${client}->${server}: ${text}"
        return 0
    fi
    fail "${client}->${server}: ${id}: want exit ${want} and ${expect:0:200}; got exit ${rc}: ${doc:0:400}"
}

# finish_known_bugs: a deviation a run covered and did not see is stale.
finish_known_bugs() {
    local a c s re sig pass text wid url
    while IFS=$'\t' read -r a c s re sig pass text wid url; do
        grep -qxF "${wid}" "${WORK}/covered" || continue
        if grep -qxF "${wid}" "${WORK}/reproduced"; then
            waiver "${wid}" "$( [[ "${c}" == "${a}" ]] && echo client || echo server )@${a}" "${url}" true
        elif [[ "${pass}" != may-pass ]]; then
            waiver "${wid}" "$( [[ "${c}" == "${a}" ]] && echo client || echo server )@${a}" "${url}" false
            at waiver.stale
            fail "known deviation of ${a} did not reproduce: ${wid}: remove it from tests/known-bugs.tsv and docs/COMPATIBILITY.md"
        fi
    done < "${WORK}/active"
}

# ---- the tables of tests/ ----

# run_cases <client> <server> <endpoint>: tests/cases.tsv for one pairing.
run_cases() {
    local client="$1" server="$2" url="$3" id state want expect needs op doc rc args
    while IFS=$'\t' read -r id state want expect needs op; do
        [[ -z "${id}" || "${id}" == \#* ]] && continue
        at "${id}" "${client}" "${server}"
        if ! supported "${client}" "${server}" "${needs}"; then
            skip "${client}->${server}: ${id} (needs ${needs})"
            continue
        fi
        read -r -a args <<<"${op//\$M/${MODEL}}"
        doc=$(run_client "${client}" "${args[0]}" --endpoint "${url}" "${args[@]:1}"); rc=$?
        keep "${SUITE}.${id}-${client}-${server}" "${doc}"
        judge "${id}" "${client}" "${server}" "${want}" "${expect}" "${doc}" "${rc}"
    done < "${LIB_ROOT}/tests/cases.tsv"
}

# run_codec <encoder> <decoder>: tests/codec-cases.tsv.
# open62541 writes XML documents without the UA Types namespace
# (<Variant><Value><String>); the UA-.NETStandard XmlDecoder only reads
# namespace-qualified elements and must refuse them (a stack limit,
# docs/CONTAINER_CONTRACT.md 4, reported, not worked around).
run_codec() {
    local enc="$1" dec="$2" fmt type value doc bin out rc
    local unqualified=""
    [[ "${enc}" == open62541 && "${dec}" == dotnet ]] && unqualified=1
    while IFS=$'\t' read -r fmt type value; do
        [[ -z "${fmt}" || "${fmt}" == \#* ]] && continue
        [[ "${fmt}" == xml && -n "${unqualified}" ]] && continue
        at "codec.roundtrip-${fmt}-${type}" "${enc}" "${dec}"
        if ! has_cap "${enc}" client "codec-${fmt}" || ! has_cap "${dec}" client "codec-${fmt}"; then
            skip "${enc}->${dec}: codec ${fmt} ${type}"
            continue
        fi
        out=$(run_client "${enc}" codec encode --format "${fmt}" --type "${type}" --value "${value}") || true
        doc=$(jq -r '.results[0].encoded.variant // empty' <<<"${out}" 2>/dev/null)
        bin=$(jq -r '.results[0].binary.variant // empty' <<<"${out}" 2>/dev/null)
        if [[ -z "${doc}" || -z "${bin}" ]]; then
            fail "${enc}->${dec}: codec encode ${fmt} ${type}: ${out:0:400}"
            continue
        fi
        out=$(printf '%s' "${doc}" | CLIENT_STDIN=1 run_client "${dec}" codec decode --format "${fmt}" --type Variant) || true
        if jq -e --arg bin "${bin}" '.success == true and .results[0].binary == $bin' <<<"${out}" >/dev/null 2>&1; then
            ok "${enc}->${dec}: codec ${fmt} ${type}: binary identical"
        else
            fail "${enc}->${dec}: codec decode ${fmt} ${type}: ${out:0:400}"
        fi
    done < "${LIB_ROOT}/tests/codec-cases.tsv"
    if [[ -n "${unqualified}" ]]; then
        at codec.xml-unqualified "${enc}" "${dec}"
        out=$(run_client "${enc}" codec encode --format xml --type String --value interop) || true
        doc=$(jq -r '.results[0].encoded.variant // empty' <<<"${out}" 2>/dev/null)
        if [[ -z "${doc}" || "${doc}" == *"xmlns="* || "${doc}" == *"xmlns:"* ]]; then
            fail "${enc}->${dec}: expected an XML document without namespace: ${out:0:400}"
        else
            out=$(printf '%s' "${doc}" | CLIENT_STDIN=1 run_client "${dec}" codec decode --format xml --type Variant) || true
            if jq -e '.success == false and .results[0].statusCode.name == "BadDecodingError"' <<<"${out}" >/dev/null 2>&1; then
                ok "${enc}->${dec}: codec xml without the UA Types namespace is refused"
            else
                fail "${enc}->${dec}: codec decode of an unqualified xml document: ${out:0:400}"
            fi
        fi
    fi
}

# secure_name <token> <adapter>: the token of tests/secure-cases.tsv names the adapter.
secure_names() {
    local t
    for t in ${1//,/ }; do
        if [[ "${t}" == "$2" ]]; then return 0; fi
        if [[ "${t}" == @own ]] && is_own "$2"; then return 0; fi
    done
    return 1
}

# run_secure_cases <in-scope function> <adapter>...: tests/secure-cases.tsv among
# the adapters; each server named there runs once, with its identity.
run_secure_cases() {
    local scope="$1" server client name host url id clients servers want expect op doc rc cert started me o args; shift
    for server in "$@"; do
        started=""
        while IFS=$'\t' read -r id clients servers want expect op; do
            [[ -z "${id}" || "${id}" == \#* ]] && continue
            secure_names "${servers}" "${server}" || continue
            for client in "$@"; do
                secure_names "${clients}" "${client}" || continue
                "${scope}" "${client}" "${server}" || continue
                if [[ -z "${started}" ]]; then
                    prepare_pki
                    cert=$(identity_of "${server}" server)
                    name="sec-${server}-${RUN_ID}"
                    host=$(server_host "${server}" "${name}")
                    if [[ ! -f "${PKI_TMP}/pki/${cert}/cert.crt" ]]; then
                        at secure.pki "${client}" "${server}"
                        fail "the test PKI has no ${cert} identity (certs/generate.sh)"
                        break 2
                    fi
                    log "secure: ${server} server with ${cert}"
                    server_up "${name}" "${server}" --host "${host}" \
                        --certificate "/pki/${cert}/cert.crt" --private-key "/pki/${cert}/cert.key" \
                        --pki-dir "/pki/${cert}/pki" || break 2
                    url=$(url_of "${host}")
                    started=1
                fi
                at "${id}" "${client}" "${server}"
                me=$(identity_of "${client}" client)
                o="${op//\$M/${MODEL}}"
                o="${o//@cred/--certificate /pki/${me}/cert.crt --private-key /pki/${me}/cert.key --trust-list /pki/ca/ca.crt}"
                o="${o//@badca/--certificate /pki/${me}/cert.crt --private-key /pki/${me}/cert.key --trust-list /pki/untrusted/cert.crt}"
                o="${o//@bad/--certificate /pki/untrusted/cert.crt --private-key /pki/untrusted/cert.key --trust-list /pki/ca/ca.crt}"
                o="${o//@user/--username test-user --password test-password}"
                o="${o//@b256s/--security-policy Basic256Sha256 --security-mode Sign}"
                o="${o//@b256/--security-policy Basic256Sha256 --security-mode SignAndEncrypt}"
                o="${o//@a128/--security-policy Aes128_Sha256_RsaOaep --security-mode SignAndEncrypt}"
                o="${o//@a256/--security-policy Aes256_Sha256_RsaPss --security-mode SignAndEncrypt}"
                read -r -a args <<<"${o}"
                doc=$(run_client "${client}" "${args[0]}" --endpoint "${url}" "${args[@]:1}"); rc=$?
                judge "${id}" "${client}" "${server}" "${want}" "${expect}" "${doc}" "${rc}"
            done
        done < "${LIB_ROOT}/tests/secure-cases.tsv"
        [[ -z "${started}" ]] || stop_server "${name}"
    done
}

finish() {
    finish_known_bugs
    echo "" >&2
    local summary=""
    [[ "${KNOWN}" -gt 0 ]] && summary="${summary}, ${KNOWN} known deviations"
    [[ "${SKIPPED}" -gt 0 ]] && summary="${summary}, ${SKIPPED} skipped (capability not declared)"
    log "${PASS} passed, ${FAIL} failed${summary}"
    results_close || FAIL=$((FAIL + 1))
    [[ "${PASS}" -gt 0 ]] || log "no check passed: this run proves nothing"
    [[ "${FAIL}" -eq 0 && "${PASS}" -gt 0 ]]
}
