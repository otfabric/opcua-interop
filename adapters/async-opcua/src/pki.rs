//! Certificates, keys and trust.
//!
//! async-opcua 0.19 keeps its own PKI layout (`own/cert.der`,
//! `private/private.pem`, `trusted/<CN> [<thumbprint>].der`, `rejected/`) and
//! trusts a peer certificate only when that exact certificate is in
//! `trusted/` — it does not validate certificate chains
//! (`async-opcua-crypto/src/certificate_store.rs`: "trust checks based on ca
//! could be added here"). The adapter maps the contract's PKI onto that:
//!
//! * server: every certificate in `<pki-dir>/trusted/certs` is copied into the
//!   stack's trusted directory, so explicitly listed client certificates are
//!   trusted; a client certificate that is only *signed* by a listed CA is
//!   rejected by the stack (`BadCertificateUntrusted`) — a stack limit.
//! * client: `--trust-list` certificates are a trust anchor list. Before the
//!   session is created the adapter checks the server certificate from the
//!   endpoint description against them (exact match, or signed by one of them
//!   and within its validity period) and, when it passes, places it in the
//!   stack's trusted directory. A server certificate that does not pass is
//!   left untrusted and the stack rejects it.

use std::path::{Path, PathBuf};

use der::{Decode, Encode, Reader, SliceReader};
use opcua::crypto::{CertificateStore, X509};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;

fn pem_blocks(text: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(b) = rest.find(&begin) {
        let after = &rest[b + begin.len()..];
        let Some(e) = after.find(&end) else { break };
        let body: String = after[..e].chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(d) = crate::nodeid::b64_decode(&body) {
            out.push(d);
        }
        rest = &after[e + end.len()..];
    }
    out
}

/// DER bytes of a certificate file (PEM or DER).
pub fn read_cert_der(path: &Path) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if let Ok(text) = std::str::from_utf8(&raw) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            return pem_blocks(text, "CERTIFICATE")
                .into_iter()
                .next()
                .ok_or_else(|| format!("{}: malformed PEM certificate", path.display()));
        }
    }
    Ok(raw)
}

pub fn read_cert(path: &Path) -> Result<X509, String> {
    let der = read_cert_der(path)?;
    X509::from_der(&der).map_err(|e| format!("{}: not an X.509 certificate: {e:?}", path.display()))
}

/// PEM text of a private key file (PEM PKCS#8 / PKCS#1, or DER PKCS#8).
pub fn read_key_pem(path: &Path) -> Result<String, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if let Ok(text) = std::str::from_utf8(&raw) {
        if text.contains("-----BEGIN") {
            return Ok(text.to_owned());
        }
    }
    // DER PKCS#8: wrap it.
    let b = crate::nodeid::b64(&raw);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    Ok(pem)
}

/// The application URI in the certificate's subjectAltName.
pub fn cert_application_uri(der_bytes: &[u8]) -> Option<String> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;
    let cert = x509_cert::Certificate::from_der(der_bytes).ok()?;
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts {
        if ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME {
            let san = SubjectAltName::from_der(ext.extn_value.as_bytes()).ok()?;
            for n in san.0 {
                if let GeneralName::UniformResourceIdentifier(u) = n {
                    return Some(u.to_string());
                }
            }
        }
    }
    None
}

/// A stack PKI directory with the application certificate and key in place.
pub struct StackPki {
    pub dir: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Create `<dir>/{own,private,trusted,rejected}` and install the application
/// certificate (as DER) and key (as PEM).
pub fn prepare_stack_pki(dir: &Path, cert: &Path, key: &Path) -> Result<StackPki, String> {
    for sub in ["own", "private", "trusted", "rejected"] {
        std::fs::create_dir_all(dir.join(sub))
            .map_err(|e| format!("cannot create {}: {e}", dir.join(sub).display()))?;
    }
    let der = read_cert_der(cert)?;
    X509::from_der(&der).map_err(|e| format!("{}: not an X.509 certificate: {e:?}", cert.display()))?;
    let cert_path = dir.join("own/cert.der");
    std::fs::write(&cert_path, &der).map_err(|e| format!("cannot write {}: {e}", cert_path.display()))?;
    let key_pem = read_key_pem(key)?;
    let key_path = dir.join("private/private.pem");
    std::fs::write(&key_path, key_pem).map_err(|e| format!("cannot write {}: {e}", key_path.display()))?;
    // Make sure the stack can load the key.
    CertificateStore::read_pkey(&key_path)
        .map_err(|e| format!("{}: unusable private key: {e}", key.display()))?;
    Ok(StackPki {
        dir: dir.to_path_buf(),
        cert_path,
        key_path,
    })
}

/// Create an empty stack PKI directory (no application certificate).
pub fn prepare_empty_pki(dir: &Path) -> Result<(), String> {
    for sub in ["trusted", "rejected"] {
        std::fs::create_dir_all(dir.join(sub))
            .map_err(|e| format!("cannot create {}: {e}", dir.join(sub).display()))?;
    }
    Ok(())
}

/// Put a certificate into the stack's trusted directory.
pub fn trust_in_stack(stack_dir: &Path, cert: &X509) -> Result<(), String> {
    let name = CertificateStore::cert_file_name(cert);
    let der = cert.to_der().map_err(|e| format!("cannot encode certificate: {e:?}"))?;
    let path = stack_dir.join("trusted").join(name);
    std::fs::write(&path, der).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Copy every certificate of `<pki-dir>/trusted/certs` into the stack's
/// trusted directory. Returns how many were installed.
pub fn import_trusted_dir(contract_pki: &Path, stack_dir: &Path) -> usize {
    let dir = contract_pki.join("trusted/certs");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut n = 0;
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        match read_cert(&p) {
            Ok(c) => {
                if trust_in_stack(stack_dir, &c).is_ok() {
                    n += 1;
                }
            }
            Err(err) => log::warn!("skipping trusted certificate {}: {err}", p.display()),
        }
    }
    n
}

/// Whether `cert` (DER) is signed by `issuer` (DER) with RSA PKCS#1 v1.5 /
/// SHA-256 and the issuer name matches.
fn signed_by(cert: &x509_cert::Certificate, issuer: &x509_cert::Certificate) -> bool {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return false;
    }
    // sha256WithRSAEncryption
    if cert.signature_algorithm.oid != const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        return false;
    }
    let Ok(spki_der) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
        return false;
    };
    let Ok(spki) = spki::SubjectPublicKeyInfoRef::from_der(&spki_der) else {
        return false;
    };
    let Ok(pk) = RsaPublicKey::try_from(spki) else {
        return false;
    };
    let Ok(tbs) = cert.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig_bytes) = cert.signature.as_bytes() else {
        return false;
    };
    let Ok(sig) = Signature::try_from(sig_bytes) else {
        return false;
    };
    VerifyingKey::<Sha256>::new(pk).verify(&tbs, &sig).is_ok()
}

fn time_valid(cert: &x509_cert::Certificate) -> bool {
    let now = std::time::SystemTime::now();
    let v = &cert.tbs_certificate.validity;
    v.not_before.to_system_time() <= now && now <= v.not_after.to_system_time()
}

/// The first certificate of a DER certificate chain, parsed, and its DER
/// bytes. A ServerCertificate may be the certificate followed by its issuers,
/// DER certificates concatenated (Part 6 §6.2.3; UA-.NETStandard 2.0.1 servers
/// send it so); a single certificate is a chain of one.
fn decode_leaf(chain: &[u8]) -> der::Result<(x509_cert::Certificate, &[u8])> {
    let mut r = SliceReader::new(chain)?;
    let cert = x509_cert::Certificate::decode(&mut r)?;
    let used = u32::from(r.position()) as usize;
    Ok((cert, &chain[..used]))
}

/// The DER bytes of the first certificate of a chain (see `decode_leaf`), or
/// the input unchanged when it does not start with a certificate.
pub fn leaf_der(chain: &[u8]) -> &[u8] {
    decode_leaf(chain).map(|(_, leaf)| leaf).unwrap_or(chain)
}

/// Validate a peer certificate (DER, or a DER chain whose first certificate is
/// the peer's) against trust anchors (DER): exact match, or issued (one level)
/// by one of them, within its validity period. The issuers that follow the
/// leaf in a chain are not used: the anchors decide.
pub fn validate_against(cert_der: &[u8], anchors: &[Vec<u8>]) -> Result<(), String> {
    let (cert, leaf) =
        decode_leaf(cert_der).map_err(|e| format!("peer certificate cannot be parsed: {e}"))?;
    if anchors.iter().any(|a| a.as_slice() == leaf) {
        return Ok(());
    }
    if !time_valid(&cert) {
        return Err("peer certificate is outside its validity period".into());
    }
    for a in anchors {
        if let Ok(ca) = x509_cert::Certificate::from_der(a) {
            if signed_by(&cert, &ca) {
                return Ok(());
            }
        }
    }
    Err("peer certificate is not in the trust list and not issued by a trusted CA".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // testdata/pki: ca.crt (self-signed CA), leaf.crt / leaf.der (issued by
    // the CA, SAN URI urn:otfabric:opcua-interop:test:leaf), other.crt (a
    // self-signed CA with the same subject as ca.crt but another key).
    fn data(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/pki").join(name)
    }

    fn der(name: &str) -> Vec<u8> {
        read_cert_der(&data(name)).unwrap()
    }

    #[test]
    fn pem_and_der_files_give_the_same_certificate() {
        assert_eq!(der("leaf.crt"), der("leaf.der"));
        assert!(read_cert(&data("leaf.crt")).is_ok());
        assert!(read_cert_der(&data("missing.crt")).is_err());
    }

    #[test]
    fn application_uri_comes_from_the_san() {
        assert_eq!(
            cert_application_uri(&der("leaf.crt")).as_deref(),
            Some("urn:otfabric:opcua-interop:test:leaf")
        );
        assert_eq!(cert_application_uri(&der("ca.crt")), None);
    }

    #[test]
    fn trust_by_exact_match_or_issuing_ca() {
        let (ca, leaf, other) = (der("ca.crt"), der("leaf.crt"), der("other.crt"));
        assert!(validate_against(&leaf, &[leaf.clone()]).is_ok(), "exact match");
        assert!(validate_against(&leaf, &[ca.clone()]).is_ok(), "issued by a listed CA");
        assert!(validate_against(&leaf, &[other.clone(), ca.clone()]).is_ok());
        // Same issuer name, different key: the signature does not verify.
        assert!(validate_against(&leaf, &[other.clone()]).is_err());
        assert!(validate_against(&leaf, &[]).is_err());
        assert!(validate_against(&ca, &[other]).is_err());
    }

    #[test]
    fn chain_is_validated_by_its_leaf() {
        // leaf followed by its issuer, as a UA-.NETStandard 2.0.1 server sends
        // its ServerCertificate.
        let (ca, leaf, other) = (der("ca.crt"), der("leaf.crt"), der("other.crt"));
        let chain = [leaf.clone(), ca.clone()].concat();
        assert_eq!(leaf_der(&chain), leaf.as_slice());
        assert_eq!(leaf_der(&leaf), leaf.as_slice());
        assert_eq!(leaf_der(b"not a certificate"), b"not a certificate");
        assert!(validate_against(&chain, &[ca.clone()]).is_ok(), "issued by a listed CA");
        assert!(validate_against(&chain, &[leaf.clone()]).is_ok(), "exact match of the leaf");
        assert!(validate_against(&chain, &[other]).is_err());
        // The CA that follows the leaf is no trust anchor.
        assert!(validate_against(&chain, &[]).is_err());
        assert!(validate_against(&leaf[..leaf.len() - 1], &[ca]).is_err(), "truncated");
    }

    #[test]
    fn tampered_certificate_is_rejected() {
        let mut leaf = der("leaf.crt");
        // Flip a byte in the subject public key, inside the signed part.
        let i = leaf.len() / 2;
        leaf[i] ^= 0x01;
        assert!(validate_against(&leaf, &[der("ca.crt")]).is_err());
    }

    #[test]
    fn trusted_dir_is_imported_into_the_stack_pki() {
        let base = std::env::temp_dir().join(format!("async-opcua-pki-test-{}", std::process::id()));
        let contract = base.join("contract");
        let stack = base.join("stack");
        std::fs::create_dir_all(contract.join("trusted/certs")).unwrap();
        for f in ["ca.crt", "leaf.der"] {
            std::fs::copy(data(f), contract.join("trusted/certs").join(f)).unwrap();
        }
        std::fs::write(contract.join("trusted/certs/garbage.crt"), b"not a certificate").unwrap();
        prepare_empty_pki(&stack).unwrap();
        assert_eq!(import_trusted_dir(&contract, &stack), 2);
        assert_eq!(std::fs::read_dir(stack.join("trusted")).unwrap().count(), 2);
        assert_eq!(import_trusted_dir(&base.join("absent"), &stack), 0);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
