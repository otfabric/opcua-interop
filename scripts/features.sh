#!/usr/bin/env bash
# Scenarios that need more than one client and one server: a server that dials the
# client, servers that register with another, two configurations of one server, the
# GDS fixture. Source after lib.sh, do not execute. Uses check, run_client, server_up.
# shellcheck disable=SC2034  # SERVER_FIXTURE is read by server_up in lib.sh

READ_OK='.success == true and .results[0].value == -123456789'

# run_lds_features <open62541> [<milo>]: one open62541 server with RSA and ECC
# endpoints, Local Discovery Server with mDNS and a reverse connection; a second
# server (Milo when given) registers with it.
run_lds_features() {
    local o="$1" milo="${2:-}" out
    local lds="lds-${RUN_ID}" member="member-${RUN_ID}" rclient="rclient-${RUN_ID}"
    local lds_url member_url node="${MODEL}Scalar.Int32"
    lds_url=$(url_of "${lds}"); member_url=$(url_of "${member}")

    prepare_pki
    log "features: open62541 server with ECC, LDS, reverse connect"
    server_up "${lds}" "${o}" --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
        --pki-dir /pki/open62541-server/pki --ecc-dir /pki/open62541-server \
        --lds --reverse-connect "opc.tcp://${rclient}:4855" || return 0
    local member_img="${o}" member_extra=(--mdns-name smoke-member) member_name=open62541
    if [[ -n "${milo}" ]]; then member_img="${milo}"; member_extra=(); member_name=milo; fi
    server_up "${member}" "${member_img}" --register-with "${lds_url}" --register-interval-ms 2000 \
        ${member_extra[@]+"${member_extra[@]}"} || { stop_server "${lds}"; return 0; }

    local rsa=(--certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key --trust-list /pki/ca/ca.crt)

    # RSA over the OpenSSL backend (the pre-0.7.0 policies).
    out=$(run_client "${o}" read --endpoint "${lds_url}" --node "${node}" --security-policy Basic256Sha256 \
            --security-mode SignAndEncrypt "${rsa[@]}" --username test-user --password test-password)
    check features.basic256sha256-signandencrypt-username "${o}" "${o}" "${READ_OK}" "${out}"
    if [[ -n "${milo}" ]]; then
        out=$(run_client "${milo}" read --endpoint "${lds_url}" --node "${node}" --security-policy Aes256_Sha256_RsaPss \
                --security-mode SignAndEncrypt --certificate /pki/milo-client/cert.crt --private-key /pki/milo-client/cert.key \
                --trust-list /pki/ca/ca.crt)
        check features.aes256_sha256_rsapss-signandencrypt "${milo}" "${o}" "${READ_OK}" "${out}"
    fi

    # ECC policies, each with the certificate of its curve; username/password
    # travels as an EccEncryptedSecret.
    local spec policy curve mode
    for spec in "ECC_nistP256 nistp256 SignAndEncrypt" "ECC_nistP384 nistp384 Sign" \
                "ECC_brainpoolP256r1 brainpoolp256r1 SignAndEncrypt" \
                "ECC_curve25519 curve25519 SignAndEncrypt" \
                "ECC_nistP256_AesGcm nistp256 SignAndEncrypt"; do
        read -r policy curve mode <<<"${spec}"
        out=$(run_client "${o}" read --endpoint "${lds_url}" --node "${node}" --security-policy "${policy}" --security-mode "${mode}" \
                --certificate "/pki/open62541-client/ecc-${curve}/cert.crt" --private-key "/pki/open62541-client/ecc-${curve}/cert.key" \
                --trust-list /pki/ca/ca.crt --username test-user --password test-password)
        check "features.${policy}-${mode}-username" "${o}" "${o}" "${READ_OK}" "${out}"
    done
    out=$(run_client "${o}" read --endpoint "${lds_url}" --node "${node}" --security-policy ECC_nistP256 --security-mode SignAndEncrypt \
            --certificate /pki/untrusted/ecc-nistp256/cert.crt --private-key /pki/untrusted/ecc-nistp256/cert.key --trust-list /pki/ca/ca.crt)
    check features.untrusted-ecc-certificate-is-rejected "${o}" "${o}" '.success == false and .serviceResult.severity == "Bad"' "${out}"

    # Reverse connect: the client listens, the server dials in (ReverseHello).
    out=$(CLIENT_NAME="${rclient}" run_client "${o}" read --endpoint "${lds_url}" --node "${node}" --reverse-listen 4855 \
            --reverse-timeout-ms 30000 --reverse-server-uri urn:otfabric:opcua-interop:server)
    check features.o62541-reverse-connect-none-none "${o}" "${o}" "${READ_OK}" "${out}"
    out=$(CLIENT_NAME="${rclient}" run_client "${o}" subscribe --endpoint "${lds_url}" --node "${MODEL}Dynamic.Counter" --notifications 2 \
            --reverse-listen 4855 --reverse-timeout-ms 30000 --security-policy ECC_nistP256 --security-mode SignAndEncrypt \
            --certificate /pki/open62541-client/ecc-nistp256/cert.crt --private-key /pki/open62541-client/ecc-nistp256/cert.key \
            --trust-list /pki/ca/ca.crt)
    check features.o62541-reverse-connect-ecc_nistp256-signandencrypt-subscription "${o}" "${o}" \
        '.success == true and (.results[0].notifications | length) == 2' "${out}"
    out=$(CLIENT_NAME="${rclient}" run_client "${o}" endpoints --endpoint "${lds_url}" --reverse-listen 4855 --reverse-timeout-ms 30000)
    check features.o62541-reverse-connect-getendpoints "${o}" "${o}" '.success == true and (.results | length) > 1' "${out}"

    # Discovery: the member registered itself (RegisterServer2), a client registers
    # and unregisters a made-up server, mDNS records are served.
    out=$(run_client "${o}" find-servers --endpoint "${lds_url}")
    check "features.lds-findservers-lists-the-registered-${member_name}-server" "${o}" "${member_name}" \
        "[.results[].discoveryUrls[]] | index(\"${member_url}\") != null" "${out}"
    local c
    for c in "${o}" ${milo:+"${milo}"}; do
        out=$(run_client "${c}" find-servers-on-network --endpoint "${lds_url}")
        check features.findserversonnetwork-lds-record-registered-server "${c}" LDS \
            ".success == true and ([.results[] | select(.serverCapabilities | index(\"LDS\"))] | length) >= 1
             and ([.results[] | select(.discoveryUrl | test(\"${member}\"))] | length) >= 1" "${out}"
        out=$(run_client "${c}" register-server --endpoint "${lds_url}" --server-uri "urn:smoke:${c}" --server-name "smoke ${c}" \
                --discovery-url "opc.tcp://smoke-${c}:4999" --mdns-name "smoke-${c}")
        check features.register-server-registerserver2 "${c}" LDS '.success == true and .results[0].service == "RegisterServer2"' "${out}"
        out=$(run_client "${o}" find-servers --endpoint "${lds_url}")
        check features.registration-visible-in-findservers "${c}" LDS "[.results[].applicationUri] | index(\"urn:smoke:${c}\") != null" "${out}"
        run_client "${c}" register-server --endpoint "${lds_url}" --server-uri "urn:smoke:${c}" \
            --discovery-url "opc.tcp://smoke-${c}:4999" --mdns-name "smoke-${c}" --online false >/dev/null
        out=$(run_client "${o}" find-servers --endpoint "${lds_url}")
        check features.unregistered-server-is-gone "${c}" LDS "[.results[].applicationUri] | index(\"urn:smoke:${c}\") == null" "${out}"
    done
    out=$(run_client "${o}" register-server --endpoint "${member_url}" --server-uri urn:smoke:x --discovery-url opc.tcp://x:1)
    check "features.register-server-against-a-non-lds-${member_name}-reports-the" "${o}" "${member_name}" \
        '.success == false and .results[0].fallback == true' "${out}"
    stop_server "${lds}" "${member}" "${rclient}"
}

# run_chain <dotnet> [<open62541>]: the dotnet server with the dotnet-server identity
# of the test PKI, once with the default certificate chain and once with
# --no-certificate-chain (docs/CONTAINER_CONTRACT.md 11, 16.3). The dotnet client takes
# both. open62541 compares the CreateSession ServerCertificate with the leaf byte for
# byte, so it connects only to the --no-certificate-chain server; tests/known-bugs.tsv.
run_chain() {
    local dn="$1" o="${2:-}" chain="chain-${RUN_ID}" leaf="leaf-${RUN_ID}" out rc
    local node="${MODEL}Scalar.Int32" flags=(--certificate /pki/dotnet-server/cert.crt --private-key /pki/dotnet-server/cert.key --pki-dir /pki/dotnet-server/pki)
    local b256=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt)
    prepare_pki
    log "features: dotnet servers with a CA-signed certificate (chain, --no-certificate-chain)"
    server_up "${chain}" "${dn}" "${flags[@]}" || return 0
    server_up "${leaf}" "${dn}" "${flags[@]}" --no-certificate-chain || { stop_server "${chain}"; return 0; }
    at chain.no-certificate-chain "${dn}" "${dn}"
    if docker logs "${leaf}" 2>&1 | grep "sent without its issuer chain" >/dev/null; then ok "dotnet: --no-certificate-chain"
    else fail "dotnet: --no-certificate-chain not applied"; fi

    local cred=(--certificate /pki/dotnet-client/cert.crt --private-key /pki/dotnet-client/cert.key --trust-list /pki/ca/ca.crt) c
    for c in "${chain}" "${leaf}"; do
        out=$(run_client "${dn}" read --endpoint "$(url_of "${c}")" --node "${node}" "${b256[@]}" "${cred[@]}")
        check "chain.basic256sha256-signandencrypt-read$([[ "${c}" == "${leaf}" ]] && echo -leaf)" "${dn}" "${dn}" "${READ_OK}" "${out}"
    done
    if [[ -n "${o}" ]]; then
        cred=(--certificate /pki/open62541-client/cert.crt --private-key /pki/open62541-client/cert.key --trust-list /pki/ca/ca.crt)
        out=$(run_client "${o}" read --endpoint "$(url_of "${leaf}")" --node "${node}" "${b256[@]}" "${cred[@]}")
        check chain.basic256sha256-signandencrypt-read-leaf "${o}" "${dn}" "${READ_OK}" "${out}"
        out=$(run_client "${o}" read --endpoint "$(url_of "${chain}")" --node "${node}" "${b256[@]}" "${cred[@]}"); rc=$?
        at chain.basic256sha256-read "${o}" "${dn}"
        judge chain.basic256sha256-read "${o}" "${dn}" - "${READ_OK}" "${out}" "${rc}"
    fi
    stop_server "${chain}" "${leaf}"
}

# run_register_with <asyncua> <open62541>: the asyncua server registers with an
# open62541 LDS, the asyncua client calls FindServersOnNetwork and RegisterServer2 there.
run_register_with() {
    local a="$1" o="$2" lds="lds-${RUN_ID}" srv="reg-${RUN_ID}" out i registered=0 lds_url url
    lds_url=$(url_of "${lds}"); url=$(url_of "${srv}")
    prepare_pki
    log "features: ${a} server registers with an ${o} LDS"
    server_up "${lds}" "${o}" --certificate /pki/open62541-server/cert.crt --private-key /pki/open62541-server/cert.key \
        --pki-dir /pki/open62541-server/pki --lds || return 0
    server_up "${srv}" "${a}" --certificate /pki/asyncua-server/cert.crt --private-key /pki/asyncua-server/cert.key \
        --pki-dir /pki/asyncua-server/pki --register-with "${lds_url}" --register-interval-ms 2000 || { stop_server "${lds}"; return 0; }
    for _ in $(seq 1 30); do
        out=$(run_client "${o}" find-servers --endpoint "${lds_url}")
        if jq -e "[.results[].discoveryUrls[]] | index(\"${url}\") != null" <<<"${out}" >/dev/null 2>&1; then registered=1; break; fi
        sleep 1
    done
    at lds.asyncua-registered "${a}" "${o}"
    if [[ "${registered}" == 1 ]]; then ok "${a} server registered with the ${o} LDS"
    else fail "${a} server is not listed by the ${o} LDS after 30 polls: ${out:0:400}"; fi
    out=$(run_client "${a}" find-servers-on-network --endpoint "${lds_url}")
    check secure.findserversonnetwork-lds-record "${a}" LDS '.success == true and ([.results[] | select(.serverCapabilities | index("LDS"))] | length) >= 1' "${out}"
    out=$(run_client "${a}" register-server --endpoint "${lds_url}" --server-uri urn:smoke:asyncua --server-name "smoke asyncua" \
            --discovery-url opc.tcp://smoke-asyncua:4999 --mdns-name smoke-asyncua)
    check secure.register-server-registerserver2 "${a}" LDS '.success == true and .results[0].service == "RegisterServer2"' "${out}"
    out=$(run_client "${o}" find-servers --endpoint "${lds_url}")
    check secure.registration-visible-in-findservers "${a}" LDS '[.results[].applicationUri] | index("urn:smoke:asyncua") != null' "${out}"
    stop_server "${lds}" "${srv}"
}

# run_gds <dotnet-gds>: the GDS server (fixtures/gds, the dotnet-server identity of the
# test PKI) and its own client gds-pull: CSR and new key pair over
# Basic256Sha256/SignAndEncrypt with the gds-admin user, revoke and unregister;
# anonymous RegisterApplication is denied (UA-.NETStandard lets anyone call
# FindApplications, Part 12 6.5.3). Contract section 16.
run_gds() {
    local g="$1" gds="gds-${RUN_ID}" leaf="gds-leaf-${RUN_ID}" out kind ep
    local flags=(--certificate /pki/dotnet-server/cert.crt --private-key /pki/dotnet-server/cert.key --pki-dir /pki/dotnet-server/pki)
    local sec=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt --certificate /pki/dotnet-client/cert.crt
               --private-key /pki/dotnet-client/cert.key --trust-list /pki/ca/ca.crt)
    local admin=(--username gds-admin --password gds-admin-password)
    prepare_pki
    SERVER_FIXTURE=/fixtures/gds/fixture.json
    server_up "${gds}" "${g}" "${flags[@]}" || return 0
    ep=$(url_of "${gds}")
    check gds.dotnet-gds-print-capabilities "${g}" "${g}" \
        '.adapter.name == "dotnet-gds" and (.clientOperations | index("gds-pull")) and (.serverFeatures | index("gds-pull"))' "$(cat "${WORK}/caps-${g}.json")"
    out=$(run_client "${g}" endpoints --endpoint "${ep}")
    check gds.endpoints "${g}" "${g}" '.success == true and ([.results[] | select(.securityMode == "SignAndEncrypt")] | length) > 0' "${out}"
    for kind in csr new-key-pair; do
        out=$(run_client "${g}" gds-pull --endpoint "${ep}" "${sec[@]}" "${admin[@]}" \
                --app-uri "urn:opcua-interop:gds-pull:smoke-${kind}" --request "${kind}" --revoke --unregister)
        check "gds.gds-pull-request-${kind}-revoke-unregister" "${g}" "${g}" \
            '.success == true and .results[0].registered == true and (.results[0].certificate | length) > 0
             and (.results[0].issuerCertificates | length) > 0 and .results[0].trustList.specifiedLists == 15
             and .results[0].revokeStatus.code == 0 and .results[0].unregisterStatus.code == 0' "${out}"
    done
    out=$(run_client "${g}" gds-pull --endpoint "${ep}" "${sec[@]}")
    check gds.anonymous-registerapplication-denied "${g}" "${g}" \
        '.success == false and .serviceResult.name == "BadUserAccessDenied" and .results[0].findApplications == []
         and .results[0].registerStatus.name == "BadUserAccessDenied"' "${out}"
    # --no-certificate-chain: the leaf alone as ServerCertificate; the pull model still works.
    server_up "${leaf}" "${g}" "${flags[@]}" --no-certificate-chain || { stop_server "${gds}"; SERVER_FIXTURE=/fixtures/baseline/fixture.json; return 0; }
    at gds.no-certificate-chain "${g}" "${g}"
    if docker logs "${leaf}" 2>&1 | grep "sent without its issuer chain" >/dev/null; then ok "dotnet-gds: --no-certificate-chain"
    else fail "dotnet-gds: --no-certificate-chain not applied"; fi
    out=$(run_client "${g}" gds-pull --endpoint "$(url_of "${leaf}")" "${sec[@]}" "${admin[@]}" --app-uri urn:opcua-interop:gds-pull:smoke-leaf --unregister)
    check gds.gds-pull "${g}" "${g}" '.success == true and (.results[0].certificate | length) > 0 and .results[0].unregisterStatus.code == 0' "${out}"
    stop_server "${gds}" "${leaf}"
    SERVER_FIXTURE=/fixtures/baseline/fixture.json
}

# run_reverse <client> <server>: the server dials the client (ReverseHello). --endpoint
# names a host that does not exist, so a pass cannot have come from dialling it. A server
# that does not dial this client leaves the client waiting (exit 7), and a client told to
# insist on another ServerUri refuses the connection (exit 3).
run_reverse() {
    local c="$1" s="$2" name="rev-${RUN_ID}" rclient="rclient-${RUN_ID}" out rc nowhere="opc.tcp://nowhere.invalid:4840${ENDPOINT_PATH}"
    local cert me host listen=(--reverse-listen 4855 --reverse-timeout-ms 30000) node="${MODEL}Scalar.Int32"
    prepare_pki
    cert=$(identity_of "${s}" server); me=$(identity_of "${c}" client); host=$(server_host "${s}" "${name}")
    log "features: ${c} listens, the ${s} server dials it"
    # async-opcua resolves the client's name once, when it starts, and exits if that fails:
    # the client has to be there first, so only one command runs.
    if [[ "${s}" == async-opcua ]]; then
        CLIENT_NAME="${rclient}" run_client "${c}" read --endpoint "${nowhere}" --node "${node}" "${listen[@]}" >"${WORK}/reverse-read" &
        local waiting=$!
        sleep 2
        server_up "${name}" "${s}" --host "${host}" --certificate "/pki/${cert}/cert.crt" --private-key "/pki/${cert}/cert.key" \
            --pki-dir "/pki/${cert}/pki" --reverse-connect "opc.tcp://${rclient}:4855" --reverse-connect-interval-ms 500 || { wait "${waiting}"; return 0; }
        wait "${waiting}"
        check_known reverse.read "${c}" "${s}" "${READ_OK}" "$(cat "${WORK}/reverse-read")"
        stop_server "${name}"
        return 0
    fi
    server_up "${name}" "${s}" --host "${host}" --certificate "/pki/${cert}/cert.crt" --private-key "/pki/${cert}/cert.key" \
        --pki-dir "/pki/${cert}/pki" --reverse-connect "opc.tcp://${rclient}:4855" --reverse-connect-interval-ms 500 || return 0

    out=$(CLIENT_NAME="${rclient}" run_client "${c}" read --endpoint "${nowhere}" --node "${node}" "${listen[@]}")
    check_known reverse.read "${c}" "${s}" "${READ_OK}" "${out}"
    out=$(CLIENT_NAME="${rclient}" run_client "${c}" subscribe --endpoint "${nowhere}" --node "${MODEL}Dynamic.Counter" --notifications 2 --timeout-ms 15000 "${listen[@]}")
    check_known reverse.subscribe "${c}" "${s}" '.success == true and (.results[0].notifications | length) == 2' "${out}"
    out=$(CLIENT_NAME="${rclient}" run_client "${c}" endpoints --endpoint "${nowhere}" "${listen[@]}")
    check_known reverse.endpoints "${c}" "${s}" '.success == true and (.results | length) > 1' "${out}"
    out=$(CLIENT_NAME="${rclient}" run_client "${c}" read --endpoint "${nowhere}" --node "${node}" "${listen[@]}" \
            --security-policy Basic256Sha256 --security-mode SignAndEncrypt \
            --certificate "/pki/${me}/cert.crt" --private-key "/pki/${me}/cert.key" --trust-list /pki/ca/ca.crt)
    check_known reverse.basic256sha256-signandencrypt-read "${c}" "${s}" "${READ_OK}" "${out}"
    if is_own "${c}"; then
        out=$(CLIENT_NAME="${rclient}" run_client "${c}" read --endpoint "${nowhere}" --node "${node}" "${listen[@]}" --reverse-server-uri urn:not:this:server); rc=$?
        at reverse.other-server-uri-is-refused "${c}" "${s}"
        if [[ "${rc}" == 3 ]] && jq -e '.success == false and .serviceResult.severity == "Bad"' <<<"${out}" >/dev/null 2>&1; then ok "${c}->${s}: --reverse-server-uri"
        else fail "${c}->${s}: --reverse-server-uri: exit ${rc}: ${out:0:400}"; fi
    fi
    stop_server "${name}"
    # Nothing dials this client: the wait ends with exit 7.
    out=$(CLIENT_NAME="${rclient}" run_client "${c}" read --endpoint "${nowhere}" --node "${node}" --reverse-listen 4855 --reverse-timeout-ms 2000); rc=$?
    at reverse.no-server-times-out "${c}" "${s}"
    if [[ "${rc}" == 7 ]] && jq -e '.success == false and .error.category == "timeout"' <<<"${out}" >/dev/null 2>&1; then ok "${c}: reverse timeout"
    else fail "${c}: --reverse-listen without a server: exit ${rc}: ${out:0:400}"; fi
}

# run_transports <client> <server>: opc.https and opc.wss (docs/CONTAINER_CONTRACT.md 9,
# 11). The endpoints list the transports, a read and a subscription work over each, and
# a TLS certificate outside --trust-list ends the connection.
run_transports() {
    local c="$1" s="$2" name="tls-${RUN_ID}" out cert host scheme url
    local node="${MODEL}Scalar.Int32" user=(--username test-user --password test-password)
    prepare_pki
    cert=$(identity_of "${s}" server); host=$(server_host "${s}" "${name}")
    log "features: ${c} client, ${s} server over opc.https and opc.wss"
    server_up "${name}" "${s}" --host "${host}" --certificate "/pki/${cert}/cert.crt" --private-key "/pki/${cert}/cert.key" \
        --pki-dir "/pki/${cert}/pki" --https-port 4843 --wss-port 4844 || return 0
    for scheme in https:4843 wss:4844; do
        url="opc.${scheme%:*}://${host}:${scheme#*:}${ENDPOINT_PATH}"
        out=$(run_client "${c}" endpoints --endpoint "${url}" --trust-list /pki/ca/ca.crt)
        check_known "transport.${scheme%:*}-endpoints" "${c}" "${s}" ".success == true and ([.results[].url] | map(test(\"^opc.${scheme%:*}://\")) | any)" "${out}"
        out=$(run_client "${c}" read --endpoint "${url}" --node "${node}" --trust-list /pki/ca/ca.crt "${user[@]}")
        check_known "transport.${scheme%:*}-read-username" "${c}" "${s}" "${READ_OK}" "${out}"
        out=$(run_client "${c}" write --endpoint "${url}" --node "${MODEL}Access.ReadWrite" --type Int32 --value 77 --trust-list /pki/ca/ca.crt "${user[@]}")
        check_known "transport.${scheme%:*}-write" "${c}" "${s}" '.success == true and .results[0].statusCode.severity == "Good"' "${out}"
        out=$(run_client "${c}" read --endpoint "${url}" --node "${node}" --trust-list /pki/untrusted/cert.crt "${user[@]}")
        check_known "transport.${scheme%:*}-untrusted-tls-certificate-is-rejected" "${c}" "${s}" '.success == false' "${out}"
    done
    out=$(run_client "${c}" subscribe --endpoint "opc.wss://${host}:4844${ENDPOINT_PATH}" --node "${MODEL}Dynamic.Counter" --notifications 3 --timeout-ms 15000 --trust-list /pki/ca/ca.crt "${user[@]}")
    check_known transport.wss-subscribe "${c}" "${s}" '.success == true and (.results[0].notifications | length) == 3' "${out}"
    stop_server "${name}"
}

# run_codec_literals <adapter>: codec documents the shared table does not reach: the
# verbose JSON form, DataValues, matrices and a document that does not decode.
run_codec_literals() {
    local a="$1" out doc bin
    log "features: ${a} codec literals"
    out=$(run_client "${a}" codec encode --format json --json-mode verbose --type Int32 --value 7)
    check codec.json-verbose "${a}" "${a}" '.success == true and .results[0].jsonMode == "verbose" and (.results[0].encoded.variant | fromjson | .UaType == 6 and .Value == 7)' "${out}"
    out=$(run_client "${a}" codec encode --format json --type Int32[] --value 1,2,3,4,5,6 --dimensions 2,3)
    check codec.json-matrix "${a}" "${a}" '.success == true and .results[0].valueRank == 2 and .results[0].arrayDimensions == [2,3] and .results[0].value == [1,2,3,4,5,6] and .results[0].binary.variant == "xgYAAAABAAAAAgAAAAMAAAAEAAAABQAAAAYAAAACAAAAAgAAAAMAAAA="' "${out}"
    out=$(run_client "${a}" codec encode --format xml --type String --value interop --status 0x40000000 --source-timestamp 2026-07-24T10:00:00Z)
    check codec.xml-datavalue-members "${a}" "${a}" '.success == true and .results[0].dataValue.statusCode.code == 1073741824 and .results[0].dataValue.sourceTimestamp != null and (.results[0].encoded.dataValue | test("SourceTimestamp"))' "${out}"
    doc=$(jq -r '.results[0].encoded.dataValue // empty' <<<"${out}"); bin=$(jq -r '.results[0].binary.dataValue // empty' <<<"${out}")
    out=$(printf '%s' "${doc}" | CLIENT_STDIN=1 run_client "${a}" codec decode --format xml --type DataValue)
    check codec.xml-datavalue-roundtrip "${a}" "${a}" ".success == true and .results[0].binary == \"${bin}\"" "${out}"
    out=$(run_client "${a}" codec decode --format json --type Variant --document 'not json')
    check codec.undecodable-document-is-bad "${a}" "${a}" '.success == false and .results[0].statusCode.name == "BadDecodingError"' "${out}"
}

# gds_identity <adapter> <client|server>: dotnet-gds has the identities of dotnet.
gds_identity() { if [[ "$1" == dotnet-gds ]]; then echo "dotnet-$2"; else identity_of "$1" "$2"; fi; }

# der_b64 <pem file>: the certificate as §4 reports it. sha1_of: its thumbprint.
der_b64() { openssl x509 -in "$1" -outform DER | base64 | tr -d '\n'; }
sha1_of() { openssl x509 -in "$1" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'; }

# check_exit <id> <client> <server> <exit> <expect> <document> <rc>: also the exit code.
check_exit() {
    at "$1" "$2" "$3"
    judge "$1" "$2" "$3" "$4" "$5" "$6" "$7"
}

# run_push <client> <server>: push certificate management (contract 15). gds-admin of
# fixtures/gds has SecurityAdmin. The trust list changes first, and on an own server what
# they do to new channels, seen by the server's own client (the dotnet client cannot load
# the key of the untrusted identity). Then the methods of Part 12 1.05 where the server has them:
# an own server and dotnet (docs/CONTAINER_CONTRACT.md 15, go-opcua's INTEROP.md). On an
# own server also who may call them.
run_push() {
    local c="$1" s="$2" name="push-${RUN_ID}" out rc cert me host url node="${MODEL}Scalar.Int32"
    prepare_pki
    cert=$(identity_of "${s}" server); me=$(identity_of "${c}" client); host=$(server_host "${s}" "${name}")
    local untrusted="${PKI_TMP}/pki/untrusted/cert.crt" extra thumb
    extra=$(der_b64 "${untrusted}"); thumb=$(sha1_of "${untrusted}")
    local sec=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt --certificate "/pki/${me}/cert.crt"
               --private-key "/pki/${me}/cert.key" --trust-list /pki/ca/ca.crt)
    local admin=(--username gds-admin --password gds-admin-password)
    local bad=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt --certificate /pki/untrusted/cert.crt
               --private-key /pki/untrusted/cert.key --trust-list /pki/ca/ca.crt)
    log "features: ${c} client push -> ${s} server"
    SERVER_FIXTURE=/fixtures/gds/fixture.json
    if ! server_up "${name}" "${s}" --host "${host}" --certificate "/pki/${cert}/cert.crt" --private-key "/pki/${cert}/cert.key" --pki-dir "/pki/${cert}/pki"; then
        SERVER_FIXTURE=/fixtures/baseline/fixture.json
        return 0
    fi
    SERVER_FIXTURE=/fixtures/baseline/fixture.json
    url=$(url_of "${host}")

    # AddCertificate and RemoveCertificate take effect at once on open62541 and node-opcua,
    # whose ApplyChanges then answers BadNothingToDo (contract 15).
    local apply=()
    if is_own "${s}" || [[ "${s}" == dotnet ]]; then apply=(--apply); fi
    out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}")
    check_known push.read-trust-list "${c}" "${s}" '.success == true and .results[0].certificateGroupId == "i=14156" and (.results[0].trustList | has("trustedCertificates"))' "${out}"
    if is_own "${s}"; then check_known push.trust-list-is-the-pki-dir "${c}" "${s}" '.results[0].trustList.specifiedLists == 15 and (.results[0].trustList.trustedCertificates | length) > 0' "${out}"; fi

    if is_own "${s}"; then
        out=$(run_client "${s}" read --endpoint "${url}" --node "${node}" "${bad[@]}")
        check_known push.untrusted-client-is-refused "${c}" "${s}" '.success == false' "${out}"
        out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}")
        check_known push.rejected-list-names-it "${c}" "${s}" ".success == true and (.results[0].rejectedCertificates | index(\"${extra}\")) != null" "${out}"
    fi
    out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --add-certificate /pki/untrusted/cert.crt ${apply[@]+"${apply[@]}"})
    check_known push.add-certificate "${c}" "${s}" ".success == true and .results[0].addCertificateStatus.code == 0 and (.results[0].trustListAfter.trustedCertificates | index(\"${extra}\")) != null" "${out}"
    if is_own "${s}"; then
        out=$(run_client "${s}" read --endpoint "${url}" --node "${node}" "${bad[@]}")
        check_known push.added-certificate-opens-a-channel "${c}" "${s}" "${READ_OK}" "${out}"
    fi
    out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --remove-certificate "${thumb}" ${apply[@]+"${apply[@]}"})
    check_known push.remove-certificate "${c}" "${s}" ".success == true and .results[0].removeCertificateStatus.code == 0 and (.results[0].trustListAfter.trustedCertificates | index(\"${extra}\")) == null" "${out}"
    if is_own "${s}"; then
        out=$(run_client "${s}" read --endpoint "${url}" --node "${node}" "${bad[@]}")
        check_known push.removed-certificate-is-refused-again "${c}" "${s}" '.success == false' "${out}"
    fi
    out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --csr)
    check_known push.create-signing-request "${c}" "${s}" '.success == true and (.results[0].certificateSigningRequest | startswith("MI"))' "${out}"

    if is_own "${s}" || [[ "${s}" == dotnet ]]; then
        if has_cap "${c}" client push-certificates; then
            out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --get-certificates)
            check_known push.get-certificates "${c}" "${s}" '.success == true and (.results[0].certificates | length) > 0 and (.results[0].certificateTypeIds | length) == (.results[0].certificates | length)' "${out}"
        fi
        if has_cap "${c}" client push-groups; then
            local group
            for group in Https UserToken; do
                out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --group "${group}")
                check_known "push.group-${group}" "${c}" "${s}" '.success == true and (.results[0].certificateGroupId | IN("i=14088", "i=14122"))' "${out}"
            done
        fi
        if has_cap "${c}" client push-transaction-diagnostics; then
            out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --add-certificate /pki/untrusted/cert.crt --cancel --transaction-diagnostics)
            check_known push.cancel-transaction-diagnostics "${c}" "${s}" ".success == true and .results[0].cancelChangesStatus.code == 0 and .results[0].transactionDiagnosticsStatus.code == 0 and (.results[0].trustListAfter.trustedCertificates | index(\"${extra}\")) == null" "${out}"
        fi
    fi

    if is_own "${s}"; then
        if has_cap "${c}" client push-certificates; then
            out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --create-self-signed --subject "CN=opcua-interop push" --dns localhost)
            check_known push.create-self-signed "${c}" "${s}" '.success == true and (.results[0].selfSignedCertificate | startswith("MI")) and .results[0].cancelChangesStatus.code == 0' "${out}"
            out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --delete-certificate i=12560)
            check_known push.delete-certificate-cancel "${c}" "${s}" '.success == true and .results[0].deleteCertificateStatus.code == 0 and .results[0].cancelChangesStatus.code == 0' "${out}"
            out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --update-certificate "/pki/${cert}/cert.crt" --update-private-key "/pki/${cert}/cert.key" --issuer-certificate /pki/ca/ca.crt --apply)
            check_known push.update-certificate-pem "${c}" "${s}" '.success == true and .results[0].updateCertificateStatus.code == 0 and .results[0].applyChangesStatus.code == 0' "${out}"
            out=$(run_client "${c}" read --endpoint "${url}" --node "${node}" "${sec[@]}")
            check_known push.channel-after-update-certificate "${c}" "${s}" "${READ_OK}" "${out}"
            # A change, then back to the configured lists.
            run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --add-certificate /pki/untrusted/cert.crt --apply >/dev/null
            out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --reset-to-defaults --apply)
            check_known push.reset-to-defaults "${c}" "${s}" ".success == true and .results[0].resetToServerDefaultsStatus.code == 0 and (.results[0].trustListAfter.trustedCertificates | index(\"${extra}\")) == null" "${out}"
        fi
        out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}"); rc=$?
        check_exit push.anonymous-is-denied "${c}" "${s}" 4 '.success == false and (.serviceResult.name | sub("_"; "")) == "BadUserAccessDenied"' "${out}" "${rc}"
        out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" --username test-user --password test-password); rc=$?
        check_exit push.without-securityadmin-is-denied "${c}" "${s}" 4 '.success == false and (.serviceResult.name | sub("_"; "")) == "BadUserAccessDenied"' "${out}" "${rc}"
        out=$(run_client "${c}" push --endpoint "${url}" --security-policy Basic256Sha256 --security-mode Sign --certificate "/pki/${me}/cert.crt" \
                --private-key "/pki/${me}/cert.key" --trust-list /pki/ca/ca.crt "${admin[@]}"); rc=$?
        check_exit push.sign-only-channel-is-refused "${c}" "${s}" 4 '.success == false and (.serviceResult.name | sub("_"; "")) == "BadSecurityModeInsufficient"' "${out}" "${rc}"
    fi
    if is_own "${c}"; then
        out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --group Nothing); rc=$?
        check_exit push.unknown-group-is-input "${c}" "${s}" 2 '.success == false and .error.category == "input"' "${out}" "${rc}"
        out=$(run_client "${c}" push --endpoint "${url}" "${sec[@]}" "${admin[@]}" --remove-certificate 00); rc=$?
        check_exit push.remove-unknown-is-service "${c}" "${s}" 4 '.success == false and .results[0].removeCertificateStatus.severity == "Bad"' "${out}" "${rc}"
    fi
    stop_server "${name}"
}

# run_gds_pull <client> <server>: the pull model of contract 16 against a GDS. Both kinds of
# request, revocation and unregistering; on what it issued, an X.509 check.
run_gds_pull() {
    local c="$1" s="$2" name="gds-pull-${RUN_ID}" kind out rc cert me host url
    prepare_pki
    cert=$(gds_identity "${s}" server); me=$(gds_identity "${c}" client); host=$(server_host "${s}" "${name}")
    local sec=(--security-policy Basic256Sha256 --security-mode SignAndEncrypt --certificate "/pki/${me}/cert.crt"
               --private-key "/pki/${me}/cert.key" --trust-list /pki/ca/ca.crt)
    local admin=(--username gds-admin --password gds-admin-password) uri="urn:opcua-interop:gds-pull:${c}"
    log "features: ${c} client gds-pull -> ${s} server"
    SERVER_FIXTURE=/fixtures/gds/fixture.json
    if ! server_up "${name}" "${s}" --host "${host}" --certificate "/pki/${cert}/cert.crt" --private-key "/pki/${cert}/cert.key" --pki-dir "/pki/${cert}/pki"; then
        SERVER_FIXTURE=/fixtures/baseline/fixture.json
        return 0
    fi
    SERVER_FIXTURE=/fixtures/baseline/fixture.json
    url=$(url_of "${host}")
    for kind in csr new-key-pair; do
        out=$(run_client "${c}" gds-pull --endpoint "${url}" "${sec[@]}" "${admin[@]}" --request-timeout 30 --app-uri "${uri}-${kind}" --request "${kind}" --revoke --unregister)
        check_known "gds-pull.${kind}-revoke-unregister" "${c}" "${s}" \
            '.success == true and .results[0].registered == true and (.results[0].certificate | length) > 0
             and (.results[0].issuerCertificates | length) > 0 and .results[0].trustList.specifiedLists == 15
             and (.results[0].certificateStatus.name | sub("_"; "")) == "BadCertificateRevoked" and .results[0].unregisterStatus.code == 0' "${out}"
    done
    out=$(run_client "${c}" gds-pull --endpoint "${url}" "${sec[@]}" "${admin[@]}" --request-timeout 30 --app-uri "${uri}-ecc" --certificate-type NistP256 --unregister)
    check_known gds-pull.nistp256 "${c}" "${s}" '.success == true and (.results[0].certificate | length) > 0 and .results[0].unregisterStatus.code == 0' "${out}"
    # A record that exists is used. The certificate chains to the issuer it came with.
    run_client "${c}" gds-pull --endpoint "${url}" "${sec[@]}" "${admin[@]}" --request-timeout 30 --app-uri "${uri}-twice" >/dev/null
    out=$(run_client "${c}" gds-pull --endpoint "${url}" "${sec[@]}" "${admin[@]}" --request-timeout 30 --app-uri "${uri}-twice" --unregister)
    check_known gds-pull.existing-record "${c}" "${s}" '.success == true and .results[0].registered == false and (.results[0].findApplications | length) == 1' "${out}"
    at gds-pull.issued-certificate-verifies "${c}" "${s}"
    jq -r '.results[0].issuerCertificates[0] // empty' <<<"${out}" | base64 -d > "${WORK}/gds-ca.der" 2>/dev/null
    jq -r '.results[0].certificate // empty' <<<"${out}" | base64 -d > "${WORK}/gds-leaf.der" 2>/dev/null
    openssl x509 -inform DER -in "${WORK}/gds-ca.der" -out "${WORK}/gds-ca.pem" 2>/dev/null
    openssl x509 -inform DER -in "${WORK}/gds-leaf.der" -out "${WORK}/gds-leaf.pem" 2>/dev/null
    if openssl verify -CAfile "${WORK}/gds-ca.pem" "${WORK}/gds-leaf.pem" >/dev/null 2>&1 \
        && openssl x509 -in "${WORK}/gds-leaf.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "${uri}-twice"; then
        ok "${c}->${s}: the issued certificate chains to the issuer and names the application"
    else
        fail "${c}->${s}: the issued certificate does not verify: ${out:0:300}"
    fi
    if is_own "${c}" || is_own "${s}"; then
        out=$(run_client "${c}" gds-pull --endpoint "${url}" "${sec[@]}" --app-uri "${uri}-anonymous"); rc=$?
        check_exit gds-pull.anonymous-registration-is-denied "${c}" "${s}" 4 '.success == false and (.results[0].registerStatus.name | sub("_"; "")) == "BadUserAccessDenied"' "${out}" "${rc}"
    fi
    stop_server "${name}"
}
