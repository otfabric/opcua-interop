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
