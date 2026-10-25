"""Certificates, keys and trust lists in the layout of the test PKI
(certs/generate.sh): PEM or DER in *.crt / *.der / *.pem files, CRLs in
*.crl files, `<pki-dir>/trusted/{certs,crl}` and `<pki-dir>/issuers/{certs,crl}`.

asyncua decides PEM / DER by the file suffix and its TrustStore only loads
files whose name ends in "der" or "pem", so neither the test PKI's *.crt
certificates nor its *.crl revocation lists would be read. The helpers here
load them by content and hand them to asyncua's own TrustStore /
CertificateValidator, which do the actual validation."""

from __future__ import annotations

from pathlib import Path

from asyncua.crypto import uacrypto
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .common import log

CERT_SUFFIXES = (".crt", ".cer", ".der", ".pem")
CRL_SUFFIXES = (".crl", ".der", ".pem")


def load_certificate(path) -> x509.Certificate:
    data = Path(path).read_bytes()
    if data.lstrip().startswith(b"-----"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def load_crl(path) -> x509.CertificateRevocationList:
    data = Path(path).read_bytes()
    if data.lstrip().startswith(b"-----"):
        return x509.load_pem_x509_crl(data)
    return x509.load_der_x509_crl(data)


def leaf_certificate(der: bytes) -> bytes:
    """The first certificate of a DER blob that may be a certificate chain.

    A ServerCertificate (EndpointDescription, CreateSession) may hold the
    application instance certificate followed by its issuers, DER certificates
    concatenated (Part 6 §6.2.3); UA-.NETStandard 2.0.1 servers send the chain by
    default (SecurityConfiguration.SendCertificateChain). asyncua's own endpoint
    selection peels the leaf off (client._first_cert_from_chain), but
    Client.set_security(server_certificate=...) parses the bytes it is given as
    one certificate, which fails on a chain ("ExtraData"). The length comes
    from the outer SEQUENCE header (short or long form); a blob that is not a
    DER SEQUENCE, or is shorter than its header says, is returned unchanged."""
    if len(der) < 2 or der[0] != 0x30:
        return der
    first = der[1]
    if first < 0x80:
        end = 2 + first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or len(der) < 2 + n:
            return der
        end = 2 + n + int.from_bytes(der[2 : 2 + n], "big")
    return der[:end] if end <= len(der) else der


def application_uri(cert: x509.Certificate) -> str | None:
    """The first URI of the SubjectAlternativeName (the ApplicationUri)."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    return uris[0] if uris else None


def _files(location: Path, suffixes: tuple[str, ...]) -> list[Path]:
    if location.is_file():
        return [location]
    if not location.is_dir():
        return []
    return [f for f in sorted(location.iterdir()) if f.is_file() and f.suffix.lower() in suffixes]


class PkiTrustStore(TrustStore):
    """asyncua's TrustStore over files of the test PKI. A location is a
    directory (every certificate / CRL file in it) or a single file. Files
    that cannot be parsed are skipped with a warning, as a stack's
    directory store does.

    Issuer certificates (`issuers/certs`) only complete a chain, as in the
    OPC UA trust list model: a certificate issued by a CA that is listed
    there but not in a trusted location stays untrusted. asyncua's own
    TrustStore has no issuer list (it verifies without intermediates)."""

    def __init__(self, trust_locations, crl_locations, issuer_locations=()):
        super().__init__(list(trust_locations), list(crl_locations))
        self._issuer_locations = [Path(p) for p in issuer_locations]
        self._intermediates: list[x509.Certificate] = []

    async def load(self) -> None:
        await super().load()
        self._intermediates = []
        for location in self._issuer_locations:
            self._intermediates.extend(await self._load_trust_location(location))

    def is_trusted(self, certificate: x509.Certificate) -> bool:
        if not self._trust_store:
            return False
        verifier = self.policy_builder.store(self._trust_store).build_client_verifier()
        try:
            verifier.verify(certificate, self._intermediates)
            return True
        except x509.verification.VerificationError as e:
            log(f"certificate {certificate.subject.rfc4514_string()} is not trusted: {e}")
            return False

    async def load_trust(self) -> None:
        # cryptography cannot build an empty x509 Store (ValueError), which
        # would stop a server whose trust list is empty. Without a store
        # TrustStore.is_trusted() is False for every certificate.
        certs = []
        for location in self.trust_locations:
            certs.extend(await self._load_trust_location(location))
        self._trust_store = x509.verification.Store(certs) if certs else None

    async def _load_trust_location(self, location):
        certs = []
        for f in _files(Path(location), CERT_SUFFIXES):
            try:
                certs.append(load_certificate(f))
            except ValueError as e:
                log(f"warn: cannot load trusted certificate {f}: {e}")
        return certs

    async def _load_crl_location(self, location):
        revoked = []
        for f in _files(Path(location), CRL_SUFFIXES):
            try:
                revoked.extend(load_crl(f))
            except ValueError as e:
                log(f"warn: cannot load CRL {f}: {e}")
        return revoked


async def server_validator(pki_dir: str):
    """The CreateSession check of client certificates: issued by (or equal
    to) a certificate in trusted/certs (issuers/certs completes the chain),
    within its validity
    period, URI SAN = ApplicationUri, not in a CRL of trusted/crl or
    issuers/crl. A rejected certificate is copied to <pki-dir>/rejected/."""
    base = Path(pki_dir)
    store = PkiTrustStore(
        [base / "trusted" / "certs"],
        [base / "trusted" / "crl", base / "issuers" / "crl"],
        [base / "issuers" / "certs"],
    )
    await store.load()
    validator = CertificateValidator(
        CertificateValidatorOptions.TIME_RANGE
        | CertificateValidatorOptions.URI
        | CertificateValidatorOptions.TRUSTED
        | CertificateValidatorOptions.REVOKED,
        store,
    )
    rejected = base / "rejected"

    async def validate(cert, app_description):
        try:
            await validator.validate(cert, app_description)
        except Exception:
            try:
                rejected.mkdir(parents=True, exist_ok=True)
                name = cert.fingerprint(hashes.SHA1()).hex()  # noqa: S303 - a file name, not a security check
                (rejected / f"{name}.der").write_bytes(uacrypto.der_from_x509(cert))
            except OSError:
                pass  # quarantine is best effort (read-only PKI mount)
            raise

    return validate


async def client_validator(trust_files: list[str]) -> CertificateValidator:
    """The client's check of the server certificate against --trust-list
    (the CA or the server certificate itself): chain to a listed
    certificate, validity period, revocation."""
    store = PkiTrustStore([Path(f) for f in trust_files], [])
    await store.load()
    return CertificateValidator(
        CertificateValidatorOptions.TIME_RANGE | CertificateValidatorOptions.TRUSTED | CertificateValidatorOptions.REVOKED,
        store,
    )
