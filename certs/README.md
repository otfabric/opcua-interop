# Test PKI

This directory contains test certificates for OPC UA security testing. Run `generate.sh` or `make certs` to populate `test-pki/`.

**These certificates are for isolated test environments only. Never use them in production.**

## Layout

```
certs/
├── generate.sh          # Generates the full test PKI
└── test-pki/
    ├── ca/               # Test CA certificate and key
    ├── open62541-server/ # open62541 server certificate and key
    ├── open62541-client/ # open62541 client certificate and key
    ├── milo-server/      # Milo server certificate and key
    ├── milo-client/      # Milo client certificate and key
    ├── async-opcua-server/ # async-opcua server certificate and key
    ├── async-opcua-client/ # async-opcua client certificate and key
    ├── node-opcua-server/  # node-opcua server certificate and key
    ├── node-opcua-client/  # node-opcua client certificate and key
    ├── asyncua-server/     # opcua-asyncio (asyncua) server certificate and key
    ├── asyncua-client/     # opcua-asyncio (asyncua) client certificate and key
    ├── go-server/        # Go OPC UA server certificate (consumer secure-server tests)
    ├── consumer/         # Certificate for use by consumer repositories (e.g. go-opcua)
    └── untrusted/        # Intentionally untrusted self-signed client certificate
```

`test-pki/` is git-ignored: generate it with `make certs`.

### ECC certificates

`open62541-server`, `open62541-client`, `consumer` and `go-server` additionally
hold one ECC application certificate per curve (the `milo-*` identities do not:
Eclipse Milo 1.1.8 has no ECC security policy):

```
<identity>/
├── cert.crt, cert.key, cert.pfx     # RSA 2048 (unchanged)
├── ecc-nistp256/cert.crt|cert.key          # EC prime256v1   → ECC_nistP256, ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly
├── ecc-nistp384/cert.crt|cert.key          # EC secp384r1    → ECC_nistP384
├── ecc-brainpoolp256r1/cert.crt|cert.key   # brainpoolP256r1 → ECC_brainpoolP256r1
├── ecc-brainpoolp384r1/cert.crt|cert.key   # brainpoolP384r1 → ECC_brainpoolP384r1
├── ecc-curve25519/cert.crt|cert.key        # Ed25519         → ECC_curve25519
└── ecc-curve448/cert.crt|cert.key          # Ed448           → ECC_curve448
untrusted/ecc-nistp256/cert.crt|cert.key    # self-signed, for rejection tests
```

- Same subject and SAN (ApplicationUri, DNS, IP) as the identity's RSA
  certificate; `cert.key` is PKCS#8 PEM.
- Issued by the **same RSA test CA** (`ca/ca.crt`, signature
  `sha256WithRSAEncryption`). Every trust directory that trusts the CA
  therefore accepts the ECC certificates without change, and open62541 (OpenSSL
  backend) validates the mixed chain; no separate ECC CA is needed.
- KeyUsage: `digitalSignature, nonRepudiation, keyAgreement`.

`certs/generate.sh --add-ecc` (re)generates only these directories in an
existing PKI and leaves the CA and all RSA files byte-identical; a plain
`certs/generate.sh` regenerates everything.

## Generation

```sh
make certs
# or directly:
certs/generate.sh
```

Requirements: `openssl` ≥ 1.1.1 (brainpool, Ed25519 and Ed448 for the ECC certificates).

The script generates:

- A test CA (self-signed, 10-year validity)
- Server certificates (signed by test CA, 5-year validity)
- Client certificates (signed by test CA, 5-year validity)
- An intentionally untrusted certificate (self-signed, not signed by test CA)
- Trust directories populated for each adapter

## Certificate properties

All certificates include:

- Correct `applicationUri` in the Subject Alternative Name (URI SAN)
- DNS SAN entries for Docker service names (`open62541`, `milo`)
- `localhost` and `127.0.0.1` SANs for local testing
- Extended Key Usage: `clientAuth` and/or `serverAuth` as appropriate

## Application URIs

| Component | ApplicationUri |
|---|---|
| Server (both adapters) | `urn:otfabric:opcua-interop:server` |
| Go OPC UA server | `urn:otfabric:opcua-interop:server:go-opcua` |
| open62541 client | `urn:otfabric:opcua-interop:client:open62541` |
| Milo client | `urn:otfabric:opcua-interop:client:milo` |
| async-opcua client | `urn:otfabric:opcua-interop:client:async-opcua` |
| node-opcua client | `urn:otfabric:opcua-interop:client:node-opcua` |
| asyncua (opcua-asyncio) client | `urn:otfabric:opcua-interop:client:asyncua` |
| Consumer client | `urn:otfabric:opcua-interop:client:consumer` |
| Untrusted client | `urn:otfabric:opcua-interop:client:untrusted` |

## Trust model

Each adapter image expects a PKI directory with:

```
/pki/
├── trusted/certs/    # Trusted CA and client certificates
├── trusted/crl/      # CRLs (may be empty)
├── issuers/certs/    # Intermediate CA certificates (may be empty)
└── rejected/         # Auto-populated by the server on rejection
```

The `generate.sh` script populates these directories for all adapters.

async-opcua 0.19 trusts a peer certificate only when that exact certificate
is in its trust store; it does not validate a chain to a trusted CA. The
`async-opcua-server/pki/trusted/certs` directory therefore lists the consumer
and the adapter client certificates next to the CA.

node-opcua validates a peer certificate against the CA in `trusted/certs`
and its CRL in `trusted/crl`, like open62541 and Milo; its identities
(`node-opcua-server`, `node-opcua-client`, new in v0.9.0) are added to an
existing PKI with `generate.sh --add-node-opcua`.

The `asyncua-server` / `asyncua-client` identities (opcua-asyncio, v0.9.0,
RSA only) are trusted by every other server identity (async-opcua's by exact
certificate) and trust the other clients; `certs/generate.sh --add-asyncua`
adds them to an existing PKI without regenerating the CA or the other
certificates.

## Security note

Certificates generated by this script have long validity periods to avoid expiry during CI. They must never be used for anything other than automated interoperability testing in isolated container networks.
