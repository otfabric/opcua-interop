#!/usr/bin/env bash
# Generate the opcua-compat test PKI.
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

SERVER_APP_URI="urn:otfabric:opcua-compat:server"
OPEN62541_CLIENT_URI="urn:otfabric:opcua-compat:client:open62541"
MILO_CLIENT_URI="urn:otfabric:opcua-compat:client:milo"
CONSUMER_CLIENT_URI="urn:otfabric:opcua-compat:client:consumer"

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
        -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid" "${san}") \
        2>/dev/null

    rm -f "${dir}/cert.csr"
    log "Cert: ${cn} (${app_uri})"
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
        -addext "subjectAltName=URI:urn:otfabric:opcua-compat:client:untrusted,DNS:localhost" \
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

    cp "${PKI_DIR}/ca/ca.crt" "${trusted_certs_dir}/ca.crt"
    log "Trust dir populated: ${adapter_pki_dir}"
}

# ── Main ──────────────────────────────────────────────────────────────────────

log "Generating test PKI in ${PKI_DIR}"

rm -rf "${PKI_DIR}"
mkdir -p "${PKI_DIR}"

gen_ca "${PKI_DIR}/ca" "OTFabric Test CA"

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

gen_untrusted_cert "${PKI_DIR}/untrusted" "Untrusted Client"

populate_trust_dir "${PKI_DIR}/open62541-server/pki"
populate_trust_dir "${PKI_DIR}/open62541-client/pki"
populate_trust_dir "${PKI_DIR}/milo-server/pki"
populate_trust_dir "${PKI_DIR}/milo-client/pki"
populate_trust_dir "${PKI_DIR}/consumer/pki"

cp "${PKI_DIR}/open62541-client/cert.crt" "${PKI_DIR}/milo-server/pki/trusted/certs/open62541-client.crt"
cp "${PKI_DIR}/milo-client/cert.crt"      "${PKI_DIR}/open62541-server/pki/trusted/certs/milo-client.crt"
cp "${PKI_DIR}/consumer/cert.crt"         "${PKI_DIR}/open62541-server/pki/trusted/certs/consumer.crt"
cp "${PKI_DIR}/consumer/cert.crt"         "${PKI_DIR}/milo-server/pki/trusted/certs/consumer.crt"

log ""
log "Test PKI generated:"
find "${PKI_DIR}" -type f | sort | sed 's|^|  |'
log ""
log "Use these directories for testing only. Never use in production."
