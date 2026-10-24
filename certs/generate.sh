#!/usr/bin/env bash
# Generate the opcua-interop test PKI.
#
# Usage:
#   generate.sh             regenerate everything (CA, RSA identities, ECC certificates)
#   generate.sh --add-ecc   keep the existing CA and RSA identities untouched and
#                           only (re)generate the ecc-<curve>/ certificates
#   generate.sh --add-async-opcua
#                           keep the existing CA and identities untouched and only
#                           (re)generate the async-opcua-server / async-opcua-client
#                           identities (new in v0.9.0) and their trust list entries
#   generate.sh --add-dotnet
#                           keep the existing CA and identities untouched and only
#                           (re)generate the dotnet-server / dotnet-client identities
#                           (new in v0.9.0) and their trust list entries
#   generate.sh --add-node-opcua
#                           keep the existing CA and identities untouched and only
#                           (re)generate the node-opcua-server / node-opcua-client
#                           identities (new in v0.9.0)
#   generate.sh --add-asyncua
#                           keep the existing CA and identities untouched and only
#                           (re)generate the asyncua-server / asyncua-client identities
#                           (opcua-asyncio, new in v0.9.0) and their trust list entries
#
# Requirements: openssl >= 1.1.1 (ECC: brainpool, Ed25519 and Ed448 support)
# Output: certs/test-pki/
#
# Certificates generated here are for ISOLATED TEST ENVIRONMENTS ONLY.
# Never use them in production.

set -euo pipefail

MODE="full"
case "${1:-}" in
    "")        ;;
    --add-ecc) MODE="add-ecc" ;;
    --add-async-opcua) MODE="add-async-opcua" ;;
    --add-dotnet) MODE="add-dotnet" ;;
    --add-node-opcua) MODE="add-node-opcua" ;;
    --add-asyncua) MODE="add-asyncua" ;;
    *) echo "usage: generate.sh [--add-ecc | --add-async-opcua | --add-dotnet | --add-node-opcua | --add-asyncua]" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/test-pki"

CA_DAYS=3650    # 10 years
CERT_DAYS=1825  # 5 years

SERVER_APP_URI="urn:otfabric:opcua-interop:server"
GO_SERVER_URI="urn:otfabric:opcua-interop:server:go-opcua"
OPEN62541_CLIENT_URI="urn:otfabric:opcua-interop:client:open62541"
MILO_CLIENT_URI="urn:otfabric:opcua-interop:client:milo"
ASYNC_OPCUA_CLIENT_URI="urn:otfabric:opcua-interop:client:async-opcua"
DOTNET_CLIENT_URI="urn:otfabric:opcua-interop:client:dotnet"
NODE_OPCUA_CLIENT_URI="urn:otfabric:opcua-interop:client:node-opcua"
ASYNCUA_CLIENT_URI="urn:otfabric:opcua-interop:client:asyncua"
CONSUMER_CLIENT_URI="urn:otfabric:opcua-interop:client:consumer"

log() { echo "[certs] $*" >&2; }

# ── Helpers ───────────────────────────────────────────────────────────────────

gen_ca() {
    local dir="$1"
    local cn="$2"
    mkdir -p "${dir}"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${dir}/ca.key" \
        -out    "${dir}/ca.crt" \
        -days   "${CA_DAYS}" \
        -subj   "/CN=${cn}/O=OTFabric/OU=Test PKI" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" 2>/dev/null
    log "CA: ${cn}"
}

gen_cert() {
    local dir="$1"
    local cn="$2"
    local app_uri="$3"
    local san_extras="${4:-}"  # comma-separated extra SANs (e.g. DNS:open62541,DNS:milo)

    mkdir -p "${dir}"

    local san="URI:${app_uri},DNS:localhost,IP:127.0.0.1"
    if [[ -n "${san_extras}" ]]; then
        san="${san},${san_extras}"
    fi

    openssl req -newkey rsa:2048 -nodes \
        -keyout "${dir}/cert.key" \
        -out    "${dir}/cert.csr" \
        -subj   "/CN=${cn}/O=OTFabric/OU=Test PKI" 2>/dev/null

    openssl x509 -req \
        -in     "${dir}/cert.csr" \
        -CA     "${PKI_DIR}/ca/ca.crt" \
        -CAkey  "${PKI_DIR}/ca/ca.key" \
        -CAcreateserial \
        -out    "${dir}/cert.crt" \
        -days   "${CERT_DAYS}" \
        -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment\nbasicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid" "${san}") \
        2>/dev/null

    rm -f "${dir}/cert.csr"

    # PKCS12 bundle for use with Java keystores (Milo KeyStoreCertificateStore)
    # Fixed password for disposable interoperability-test identities only.
    # Never reuse this password for external or production material.
    # The .pfx file is a debug/inspection artifact; adapters load PEM directly.
    openssl pkcs12 -export \
        -in    "${dir}/cert.crt" \
        -inkey "${dir}/cert.key" \
        -name  "1" \
        -passout pass:password \
        -out   "${dir}/cert.pfx" \
        2>/dev/null

    log "Cert: ${cn} (${app_uri})"
}

gen_crl() {
    local out_file="$1"
    local tmpdir
    tmpdir=$(mktemp -d)

    touch "${tmpdir}/index.txt"
    printf '01\n' > "${tmpdir}/crlnumber"

    # Minimal openssl ca config — only needs a database and crlnumber.
    cat > "${tmpdir}/openssl.cnf" << EOF
[ ca ]
default_ca = myca
[ myca ]
dir = ${tmpdir}
certificate = ${PKI_DIR}/ca/ca.crt
private_key = ${PKI_DIR}/ca/ca.key
database = \$dir/index.txt
crlnumber = \$dir/crlnumber
default_md = sha256
default_crl_days = 3650
[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

    openssl ca -gencrl \
        -config "${tmpdir}/openssl.cnf" \
        -keyfile "${PKI_DIR}/ca/ca.key" \
        -cert    "${PKI_DIR}/ca/ca.crt" \
        -crlexts crl_ext \
        -out     "${out_file}" \
        2>/dev/null

    rm -rf "${tmpdir}"
    log "CRL: ${out_file}"
}

gen_untrusted_cert() {
    local dir="$1"
    local cn="$2"
    mkdir -p "${dir}"

    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${dir}/cert.key" \
        -out    "${dir}/cert.crt" \
        -days   "${CERT_DAYS}" \
        -subj   "/CN=${cn}/O=OTFabric/OU=Untrusted Test" \
        -addext "subjectAltName=URI:urn:otfabric:opcua-interop:client:untrusted,DNS:localhost" \
        2>/dev/null
    log "Untrusted cert: ${cn}"
}

# ── ECC application certificates ─────────────────────────────────────────────
#
# One certificate per identity and curve, in <identity>/ecc-<curve>/:
#   cert.crt  PEM certificate (same subject / SAN URI as the RSA certificate)
#   cert.key  PEM private key (PKCS#8)
# They are issued by the same test CA as the RSA certificates, so every
# existing trust directory (CA in trusted/certs) already accepts them.
#
#   directory             key                 SecurityPolicy
#   ecc-nistp256          EC prime256v1       ECC_nistP256 (+ _AesGcm / _ChaChaPoly)
#   ecc-nistp384          EC secp384r1        ECC_nistP384
#   ecc-brainpoolp256r1   EC brainpoolP256r1  ECC_brainpoolP256r1
#   ecc-brainpoolp384r1   EC brainpoolP384r1  ECC_brainpoolP384r1
#   ecc-curve25519        Ed25519             ECC_curve25519
#   ecc-curve448          Ed448               ECC_curve448

ECC_CURVES="nistp256 nistp384 brainpoolp256r1 brainpoolp384r1 curve25519 curve448"

gen_ecc_key() {
    local curve="$1"
    local out="$2"
    case "${curve}" in
        nistp256)        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1      -pkeyopt ec_param_enc:named_curve -out "${out}" 2>/dev/null ;;
        nistp384)        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1       -pkeyopt ec_param_enc:named_curve -out "${out}" 2>/dev/null ;;
        brainpoolp256r1) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1 -pkeyopt ec_param_enc:named_curve -out "${out}" 2>/dev/null ;;
        brainpoolp384r1) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP384r1 -pkeyopt ec_param_enc:named_curve -out "${out}" 2>/dev/null ;;
        curve25519)      openssl genpkey -algorithm ED25519 -out "${out}" 2>/dev/null ;;
        curve448)        openssl genpkey -algorithm ED448   -out "${out}" 2>/dev/null ;;
        *) return 1 ;;
    esac
}

gen_ecc_certs() {
    local identity_dir="$1"
    local cn="$2"
    local app_uri="$3"
    local san_extras="${4:-}"

    local san="URI:${app_uri},DNS:localhost,IP:127.0.0.1"
    if [[ -n "${san_extras}" ]]; then
        san="${san},${san_extras}"
    fi

    local curve dir
    for curve in ${ECC_CURVES}; do
        dir="${identity_dir}/ecc-${curve}"
        rm -rf "${dir}"
        mkdir -p "${dir}"
        if ! gen_ecc_key "${curve}" "${dir}/cert.key"; then
            log "ECC ${curve}: not supported by this openssl; skipped (${cn})"
            rm -rf "${dir}"
            continue
        fi
        openssl req -new -key "${dir}/cert.key" \
            -out  "${dir}/cert.csr" \
            -subj "/CN=${cn}/O=OTFabric/OU=Test PKI" 2>/dev/null
        openssl x509 -req \
            -in     "${dir}/cert.csr" \
            -CA     "${PKI_DIR}/ca/ca.crt" \
            -CAkey  "${PKI_DIR}/ca/ca.key" \
            -CAcreateserial \
            -sha256 \
            -out    "${dir}/cert.crt" \
            -days   "${CERT_DAYS}" \
            -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature,nonRepudiation,keyAgreement\nbasicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid" "${san}") \
            2>/dev/null
        rm -f "${dir}/cert.csr"
    done
    log "ECC certs: ${cn} (${app_uri})"
}

gen_untrusted_ecc_cert() {
    local dir="$1"
    local cn="$2"
    rm -rf "${dir}"
    mkdir -p "${dir}"
    gen_ecc_key nistp256 "${dir}/cert.key"
    openssl req -x509 -new -key "${dir}/cert.key" \
        -out    "${dir}/cert.crt" \
        -days   "${CERT_DAYS}" \
        -subj   "/CN=${cn}/O=OTFabric/OU=Untrusted Test" \
        -addext "subjectAltName=URI:urn:otfabric:opcua-interop:client:untrusted,DNS:localhost" \
        2>/dev/null
    log "Untrusted ECC cert: ${cn}"
}

gen_all_ecc() {
    gen_ecc_certs "${PKI_DIR}/open62541-server" "open62541 Server" "${SERVER_APP_URI}"       "DNS:open62541"
    gen_ecc_certs "${PKI_DIR}/open62541-client" "open62541 Client" "${OPEN62541_CLIENT_URI}" "DNS:open62541"
    gen_ecc_certs "${PKI_DIR}/consumer"         "Consumer Client"  "${CONSUMER_CLIENT_URI}"  ""
    gen_ecc_certs "${PKI_DIR}/go-server"        "Go OPC UA Server" "${GO_SERVER_URI}"        "DNS:host.docker.internal"
    gen_untrusted_ecc_cert "${PKI_DIR}/untrusted/ecc-nistp256" "Untrusted Client"
}

populate_trust_dir() {
    local adapter_pki_dir="$1"
    local trusted_certs_dir="${adapter_pki_dir}/trusted/certs"
    local trusted_crl_dir="${adapter_pki_dir}/trusted/crl"
    local issuers_dir="${adapter_pki_dir}/issuers/certs"
    local rejected_dir="${adapter_pki_dir}/rejected"

    mkdir -p "${trusted_certs_dir}" "${trusted_crl_dir}" "${issuers_dir}" "${rejected_dir}"

    cp "${PKI_DIR}/ca/ca.crt"       "${trusted_certs_dir}/ca.crt"
    cp "${PKI_DIR}/ca/ca.crl"       "${trusted_crl_dir}/ca.crl"
    log "Trust dir populated: ${adapter_pki_dir}"
}

# The async-opcua identities (v0.9.0) and their trust list entries. async-opcua
# 0.19 trusts a peer certificate only when that exact certificate is trusted
# (no CA chain validation), so the async-opcua server lists every client
# certificate; the other servers trust the async-opcua client certificate.
gen_async_opcua() {
    gen_cert "${PKI_DIR}/async-opcua-server" \
        "async-opcua Server" \
        "${SERVER_APP_URI}" \
        "DNS:async-opcua"

    gen_cert "${PKI_DIR}/async-opcua-client" \
        "async-opcua Client" \
        "${ASYNC_OPCUA_CLIENT_URI}" \
        "DNS:async-opcua"

    populate_trust_dir "${PKI_DIR}/async-opcua-server/pki"
    populate_trust_dir "${PKI_DIR}/async-opcua-client/pki"

    local client
    for client in consumer open62541-client milo-client async-opcua-client; do
        cp "${PKI_DIR}/${client}/cert.crt" "${PKI_DIR}/async-opcua-server/pki/trusted/certs/${client}.crt"
    done
    local server
    for server in open62541-server milo-server go-server; do
        cp "${PKI_DIR}/async-opcua-client/cert.crt" "${PKI_DIR}/${server}/pki/trusted/certs/async-opcua-client.crt"
    done
    link_async_opcua_dotnet
}

# UA-.NETStandard (dotnet adapter) identities, RSA only: the adapter offers no
# ECC SecurityPolicy (UA-.NETStandard 2.0.1 does not accept ECC certificates
# issued by the RSA test CA). Every other identity's trust list gets the
# dotnet client certificate, the dotnet server trusts the other clients.
gen_dotnet() {
    rm -rf "${PKI_DIR}/dotnet-server" "${PKI_DIR}/dotnet-client"
    gen_cert "${PKI_DIR}/dotnet-server" \
        "UA-.NETStandard Server" \
        "${SERVER_APP_URI}" \
        "DNS:dotnet"
    gen_cert "${PKI_DIR}/dotnet-client" \
        "UA-.NETStandard Client" \
        "${DOTNET_CLIENT_URI}" \
        "DNS:dotnet"
    populate_trust_dir "${PKI_DIR}/dotnet-server/pki"
    populate_trust_dir "${PKI_DIR}/dotnet-client/pki"

    local id
    for id in open62541-client milo-client consumer; do
        cp "${PKI_DIR}/${id}/cert.crt" "${PKI_DIR}/dotnet-server/pki/trusted/certs/${id}.crt"
    done
    for id in open62541-server milo-server go-server; do
        cp "${PKI_DIR}/dotnet-client/cert.crt" "${PKI_DIR}/${id}/pki/trusted/certs/dotnet-client.crt"
    done
    link_async_opcua_dotnet
}

# Cross trust of the two v0.9.0 adapters, whichever was generated last: the
# async-opcua server trusts the exact dotnet client certificate, the dotnet
# server the async-opcua client certificate.
link_async_opcua_dotnet() {
    if [[ -d "${PKI_DIR}/async-opcua-server/pki" && -f "${PKI_DIR}/dotnet-client/cert.crt" ]]; then
        cp "${PKI_DIR}/dotnet-client/cert.crt" "${PKI_DIR}/async-opcua-server/pki/trusted/certs/dotnet-client.crt"
    fi
    if [[ -d "${PKI_DIR}/dotnet-server/pki" && -f "${PKI_DIR}/async-opcua-client/cert.crt" ]]; then
        cp "${PKI_DIR}/async-opcua-client/cert.crt" "${PKI_DIR}/dotnet-server/pki/trusted/certs/async-opcua-client.crt"
    fi
    link_node_opcua
}

# The node-opcua identities (v0.9.0). node-opcua validates a peer certificate
# against the trusted CA (and its CRL), so its own trust dirs need nothing
# else; the other servers get the node-opcua client certificate like the
# other adapter clients (async-opcua and dotnet by exact certificate).
gen_node_opcua() {
    gen_cert "${PKI_DIR}/node-opcua-server" \
        "node-opcua Server" \
        "${SERVER_APP_URI}" \
        "DNS:node-opcua"

    gen_cert "${PKI_DIR}/node-opcua-client" \
        "node-opcua Client" \
        "${NODE_OPCUA_CLIENT_URI}" \
        "DNS:node-opcua"

    populate_trust_dir "${PKI_DIR}/node-opcua-server/pki"
    populate_trust_dir "${PKI_DIR}/node-opcua-client/pki"

    local server
    for server in open62541-server milo-server go-server; do
        cp "${PKI_DIR}/node-opcua-client/cert.crt" "${PKI_DIR}/${server}/pki/trusted/certs/node-opcua-client.crt"
    done
    link_node_opcua
}

# The async-opcua and dotnet servers trust the exact node-opcua client
# certificate, whichever of them was generated last.
link_node_opcua() {
    [[ -f "${PKI_DIR}/node-opcua-client/cert.crt" ]] || return 0
    local server
    for server in async-opcua-server dotnet-server; do
        if [[ -d "${PKI_DIR}/${server}/pki/trusted/certs" ]]; then
            cp "${PKI_DIR}/node-opcua-client/cert.crt" "${PKI_DIR}/${server}/pki/trusted/certs/node-opcua-client.crt"
        fi
    done
    link_asyncua
}

# opcua-asyncio (asyncua adapter) identities, RSA only (asyncua has no ECC
# SecurityPolicy). The asyncua server validates client certificates against
# the CA in its trust list and also lists the other client certificates, as
# the other servers do; every other server trusts the asyncua client
# certificate (async-opcua's by exact certificate).
gen_asyncua() {
    rm -rf "${PKI_DIR}/asyncua-server" "${PKI_DIR}/asyncua-client"
    gen_cert "${PKI_DIR}/asyncua-server" \
        "opcua-asyncio Server" \
        "${SERVER_APP_URI}" \
        "DNS:asyncua"
    gen_cert "${PKI_DIR}/asyncua-client" \
        "opcua-asyncio Client" \
        "${ASYNCUA_CLIENT_URI}" \
        "DNS:asyncua"
    populate_trust_dir "${PKI_DIR}/asyncua-server/pki"
    populate_trust_dir "${PKI_DIR}/asyncua-client/pki"
    link_asyncua
}

# Cross trust of the asyncua identities with every other identity present,
# whichever was generated last (link_node_opcua calls it too, so gen_async_opcua,
# gen_dotnet and gen_node_opcua link the asyncua identities).
link_asyncua() {
    [[ -f "${PKI_DIR}/asyncua-client/cert.crt" && -d "${PKI_DIR}/asyncua-server/pki" ]] || return 0
    local id
    for id in consumer open62541-client milo-client async-opcua-client dotnet-client node-opcua-client asyncua-client; do
        if [[ -f "${PKI_DIR}/${id}/cert.crt" ]]; then
            cp "${PKI_DIR}/${id}/cert.crt" "${PKI_DIR}/asyncua-server/pki/trusted/certs/${id}.crt"
        fi
    done
    for id in open62541-server milo-server go-server async-opcua-server dotnet-server node-opcua-server; do
        if [[ -d "${PKI_DIR}/${id}/pki/trusted/certs" ]]; then
            cp "${PKI_DIR}/asyncua-client/cert.crt" "${PKI_DIR}/${id}/pki/trusted/certs/asyncua-client.crt"
        fi
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────

if [[ "${MODE}" == "add-ecc" ]]; then
    if [[ ! -f "${PKI_DIR}/ca/ca.crt" || ! -f "${PKI_DIR}/ca/ca.key" ]]; then
        echo "generate.sh --add-ecc: no existing CA in ${PKI_DIR}/ca (run generate.sh first)" >&2
        exit 1
    fi
    log "Adding ECC certificates to the existing test PKI in ${PKI_DIR}"
    gen_all_ecc
    log ""
    log "ECC certificates generated (CA and RSA identities left untouched)."
    exit 0
fi

if [[ "${MODE}" == "add-node-opcua" ]]; then
    if [[ ! -f "${PKI_DIR}/ca/ca.crt" || ! -f "${PKI_DIR}/ca/ca.key" ]]; then
        echo "generate.sh --add-node-opcua: no existing CA in ${PKI_DIR}/ca (run generate.sh first)" >&2
        exit 1
    fi
    log "Adding the node-opcua identities to the existing test PKI in ${PKI_DIR}"
    gen_node_opcua
    log ""
    log "node-opcua identities generated (CA and other identities left untouched)."
    exit 0
fi

if [[ "${MODE}" == "add-async-opcua" ]]; then
    if [[ ! -f "${PKI_DIR}/ca/ca.crt" || ! -f "${PKI_DIR}/ca/ca.key" ]]; then
        echo "generate.sh --add-async-opcua: no existing CA in ${PKI_DIR}/ca (run generate.sh first)" >&2
        exit 1
    fi
    log "Adding the async-opcua identities to the existing test PKI in ${PKI_DIR}"
    gen_async_opcua
    log ""
    log "async-opcua identities generated (CA and other identities left untouched)."
    exit 0
fi

if [[ "${MODE}" == "add-dotnet" ]]; then
    if [[ ! -f "${PKI_DIR}/ca/ca.crt" || ! -f "${PKI_DIR}/ca/ca.key" || ! -f "${PKI_DIR}/ca/ca.crl" ]]; then
        echo "generate.sh --add-dotnet: no existing CA in ${PKI_DIR}/ca (run generate.sh first)" >&2
        exit 1
    fi
    log "Adding the dotnet identities to the existing test PKI in ${PKI_DIR}"
    gen_dotnet
    log ""
    log "dotnet identities generated (CA and the other certificates unchanged; dotnet-client.crt added to their trust lists)."
    exit 0
fi

if [[ "${MODE}" == "add-asyncua" ]]; then
    if [[ ! -f "${PKI_DIR}/ca/ca.crt" || ! -f "${PKI_DIR}/ca/ca.key" || ! -f "${PKI_DIR}/ca/ca.crl" ]]; then
        echo "generate.sh --add-asyncua: no existing CA in ${PKI_DIR}/ca (run generate.sh first)" >&2
        exit 1
    fi
    log "Adding the asyncua identities to the existing test PKI in ${PKI_DIR}"
    gen_asyncua
    log ""
    log "asyncua identities generated (CA and the other certificates unchanged; asyncua-client.crt added to their trust lists)."
    exit 0
fi

log "Generating test PKI in ${PKI_DIR}"

rm -rf "${PKI_DIR}"
mkdir -p "${PKI_DIR}"

gen_ca "${PKI_DIR}/ca" "OTFabric Test CA"

# Generate an empty CRL so OPC UA PKI managers (e.g. Milo's
# DefaultServerCertificateValidator) find a valid CRL for the CA.
# Without a CRL file, some PKIX validators fall back to online revocation
# checking, which fails for test-only certificates.
gen_crl "${PKI_DIR}/ca/ca.crl"

gen_cert "${PKI_DIR}/open62541-server" \
    "open62541 Server" \
    "${SERVER_APP_URI}" \
    "DNS:open62541"

gen_cert "${PKI_DIR}/open62541-client" \
    "open62541 Client" \
    "${OPEN62541_CLIENT_URI}" \
    "DNS:open62541"

gen_cert "${PKI_DIR}/milo-server" \
    "Milo Server" \
    "${SERVER_APP_URI}" \
    "DNS:milo"

gen_cert "${PKI_DIR}/milo-client" \
    "Milo Client" \
    "${MILO_CLIENT_URI}" \
    "DNS:milo"

gen_cert "${PKI_DIR}/consumer" \
    "Consumer Client" \
    "${CONSUMER_CLIENT_URI}" \
    ""

gen_cert "${PKI_DIR}/go-server" \
    "Go OPC UA Server" \
    "${GO_SERVER_URI}" \
    "DNS:host.docker.internal"

gen_untrusted_cert "${PKI_DIR}/untrusted" "Untrusted Client"

# ECC application certificates (Milo implements no ECC SecurityPolicy, so the
# milo-* identities stay RSA-only).
gen_all_ecc

populate_trust_dir "${PKI_DIR}/open62541-server/pki"
populate_trust_dir "${PKI_DIR}/open62541-client/pki"
populate_trust_dir "${PKI_DIR}/milo-server/pki"
populate_trust_dir "${PKI_DIR}/milo-client/pki"
populate_trust_dir "${PKI_DIR}/consumer/pki"
populate_trust_dir "${PKI_DIR}/go-server/pki"

cp "${PKI_DIR}/open62541-client/cert.crt" "${PKI_DIR}/milo-server/pki/trusted/certs/open62541-client.crt"
cp "${PKI_DIR}/milo-client/cert.crt"      "${PKI_DIR}/open62541-server/pki/trusted/certs/milo-client.crt"
cp "${PKI_DIR}/consumer/cert.crt"         "${PKI_DIR}/open62541-server/pki/trusted/certs/consumer.crt"
cp "${PKI_DIR}/consumer/cert.crt"         "${PKI_DIR}/milo-server/pki/trusted/certs/consumer.crt"
# go-server trusts CA only; adapter clients are CA-signed so the chain resolves.
cp "${PKI_DIR}/open62541-client/cert.crt" "${PKI_DIR}/go-server/pki/trusted/certs/open62541-client.crt"
cp "${PKI_DIR}/milo-client/cert.crt"      "${PKI_DIR}/go-server/pki/trusted/certs/milo-client.crt"
cp "${PKI_DIR}/consumer/cert.crt"         "${PKI_DIR}/go-server/pki/trusted/certs/consumer.crt"
gen_async_opcua
gen_node_opcua

gen_dotnet

gen_asyncua

log ""
log "Test PKI generated:"
find "${PKI_DIR}" -type f | sort | sed 's|^|  |'
log ""
log "Use these directories for testing only. Never use in production."
