#!/usr/bin/env bash
# Generate the opcua-interop test PKI.
#
# Requirements: openssl >= 1.1
# Output: certs/test-pki/
#
# Certificates generated here are for ISOLATED TEST ENVIRONMENTS ONLY.
# Never use them in production.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/test-pki"

CA_DAYS=3650    # 10 years
CERT_DAYS=1825  # 5 years

SERVER_APP_URI="urn:otfabric:opcua-interop:server"
GO_SERVER_URI="urn:otfabric:opcua-interop:server:go-opcua"
OPEN62541_CLIENT_URI="urn:otfabric:opcua-interop:client:open62541"
MILO_CLIENT_URI="urn:otfabric:opcua-interop:client:milo"
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

# ── Main ──────────────────────────────────────────────────────────────────────

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

log ""
log "Test PKI generated:"
find "${PKI_DIR}" -type f | sort | sed 's|^|  |'
log ""
log "Use these directories for testing only. Never use in production."
