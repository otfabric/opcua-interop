"""Trust lists of the test PKI layout (pki.py) on asyncua's TrustStore and
CertificateValidator.

testdata/pki (no private keys): ca.crt (self-signed CA), leaf.crt / leaf.der
(issued by the CA, serial 0x1001, SAN URI urn:otfabric:opcua-interop:test:leaf),
leaf2.crt (issued by the CA, serial 0x1002), other.crt (a self-signed CA with
the same subject as ca.crt but another key), ca-revokes-leaf.crl (CRL of the CA
revoking 0x1001), intermediate.crt (a CA issued by ca.crt) and
leaf-via-intermediate.crt (issued by it, SAN URI
urn:otfabric:opcua-interop:test:leaf-via-intermediate), self-signed.crt (a self-signed end-entity certificate, SAN URI
urn:otfabric:opcua-interop:test:self-signed)."""

import asyncio
import logging
import shutil
import tempfile
import unittest
from pathlib import Path

from asyncua import ua
from asyncua.common.utils import ServiceError
from cryptography.hazmat.primitives.serialization import Encoding

from opcua_interop_asyncua import pki
from opcua_interop_asyncua.common import file_format

DATA = Path(__file__).resolve().parent.parent / "testdata" / "pki"

# asyncua logs every untrusted certificate with a traceback.
logging.getLogger("asyncuagds.validate").setLevel(logging.CRITICAL)


def app(uri):
    return ua.ApplicationDescription(ApplicationUri=uri, ApplicationType=ua.ApplicationType.Client)


LEAF_URI = "urn:otfabric:opcua-interop:test:leaf"


def run(coro):
    return asyncio.run(coro)


class FilesTest(unittest.TestCase):
    def test_pem_and_der_give_the_same_certificate(self):
        self.assertEqual(file_format(DATA / "leaf.crt"), "pem")
        self.assertEqual(file_format(DATA / "leaf.der"), "der")
        self.assertEqual(pki.load_certificate(DATA / "leaf.crt"), pki.load_certificate(DATA / "leaf.der"))

    def test_application_uri_from_the_san(self):
        self.assertEqual(pki.application_uri(pki.load_certificate(DATA / "leaf.crt")), LEAF_URI)
        self.assertIsNone(pki.application_uri(pki.load_certificate(DATA / "ca.crt")))

    def test_crl_file(self):
        crl = pki.load_crl(DATA / "ca-revokes-leaf.crl")
        self.assertEqual([r.serial_number for r in crl], [0x1001])

    def test_leaf_of_a_certificate_chain(self):
        # A ServerCertificate holding the leaf followed by its issuers (Part 6
        # §6.2.3), as UA-.NETStandard 2.0.1 sends it: only the leaf is kept.
        leaf = (DATA / "leaf.der").read_bytes()
        ca = pki.load_certificate(DATA / "ca.crt").public_bytes(Encoding.DER)
        self.assertEqual(pki.leaf_certificate(leaf + ca), leaf)
        self.assertEqual(pki.leaf_certificate(leaf), leaf)
        self.assertEqual(pki.leaf_certificate(b""), b"")
        self.assertEqual(pki.leaf_certificate(b"\x30\x05ab"), b"\x30\x05ab")  # truncated: unchanged
        self.assertEqual(pki.leaf_certificate(b"\x30\x02ab" + ca), b"\x30\x02ab")  # short form


class PkiDir:
    """A <pki-dir> with trusted/{certs,crl}, issuers/{certs,crl} in a temp dir."""

    def __init__(self, trusted=(), crls=(), issuers=()):
        self.base = Path(tempfile.mkdtemp(prefix="asyncua-pki-test-"))
        for sub, files in (("trusted/certs", trusted), ("trusted/crl", crls), ("issuers/certs", issuers)):
            d = self.base / sub
            d.mkdir(parents=True)
            for f in files:
                shutil.copy(DATA / f, d / f)
        (self.base / "issuers" / "crl").mkdir(parents=True)

    def close(self):
        shutil.rmtree(self.base, ignore_errors=True)


class ServerValidatorTest(unittest.TestCase):
    def validate(self, pkidir: PkiDir, cert: str, uri=LEAF_URI):
        try:
            v = run(pki.server_validator(str(pkidir.base)))
            run(v(pki.load_certificate(DATA / cert), app(uri)))
            return None
        except ServiceError as e:
            return e.code
        finally:
            pkidir.close()

    def test_issued_by_a_trusted_ca(self):
        self.assertIsNone(self.validate(PkiDir(trusted=["ca.crt"]), "leaf.crt"))

    def test_exact_certificate_in_the_trust_list(self):
        self.assertIsNone(self.validate(PkiDir(trusted=["leaf.crt"]), "leaf.crt"))
        self.assertIsNone(self.validate(PkiDir(trusted=["self-signed.crt"]), "self-signed.crt",
                                        uri="urn:otfabric:opcua-interop:test:self-signed"))

    def test_self_signed_certificate_not_in_the_trust_list(self):
        self.assertEqual(self.validate(PkiDir(trusted=["ca.crt"]), "self-signed.crt",
                                       uri="urn:otfabric:opcua-interop:test:self-signed"),
                         ua.StatusCodes.BadCertificateUntrusted)

    def test_issuer_list_alone_does_not_trust(self):
        # issuers/certs completes chains; it is no trust anchor (OPC UA Part 12 trust lists).
        self.assertEqual(self.validate(PkiDir(issuers=["ca.crt"]), "leaf.crt"), ua.StatusCodes.BadCertificateUntrusted)

    def test_issuer_list_completes_the_chain(self):
        uri = "urn:otfabric:opcua-interop:test:leaf-via-intermediate"
        self.assertIsNone(self.validate(PkiDir(trusted=["ca.crt"], issuers=["intermediate.crt"]), "leaf-via-intermediate.crt", uri=uri))
        self.assertEqual(self.validate(PkiDir(trusted=["ca.crt"]), "leaf-via-intermediate.crt", uri=uri),
                         ua.StatusCodes.BadCertificateUntrusted)

    def test_der_trust_list_entry(self):
        d = PkiDir()
        (d.base / "trusted" / "certs" / "ca.der").write_bytes(pki.load_certificate(DATA / "ca.crt").public_bytes(Encoding.DER))
        self.assertIsNone(self.validate(d, "leaf.crt"))

    def test_same_issuer_name_other_key_is_untrusted(self):
        self.assertEqual(self.validate(PkiDir(trusted=["other.crt"]), "leaf.crt"), ua.StatusCodes.BadCertificateUntrusted)

    def test_empty_trust_list_is_untrusted(self):
        self.assertEqual(self.validate(PkiDir(), "leaf.crt"), ua.StatusCodes.BadCertificateUntrusted)

    def test_uri_must_match_the_application_uri(self):
        self.assertEqual(self.validate(PkiDir(trusted=["ca.crt"]), "leaf.crt", uri="urn:other"),
                         ua.StatusCodes.BadCertificateUriInvalid)

    def test_crl_of_the_test_pki_layout_is_applied(self):
        # The test PKI stores CRLs as *.crl, which asyncua's own TrustStore skips.
        self.assertEqual(self.validate(PkiDir(trusted=["ca.crt"], crls=["ca-revokes-leaf.crl"]), "leaf.crt"),
                         ua.StatusCodes.BadCertificateRevoked)
        self.assertIsNone(self.validate(PkiDir(trusted=["ca.crt"], crls=["ca-revokes-leaf.crl"]), "leaf2.crt",
                                        uri="urn:otfabric:opcua-interop:test:leaf2"))

    def test_rejected_certificate_is_copied_to_rejected(self):
        d = PkiDir()
        try:
            v = run(pki.server_validator(str(d.base)))
            with self.assertRaises(ServiceError):
                run(v(pki.load_certificate(DATA / "leaf.crt"), app(LEAF_URI)))
            files = list((d.base / "rejected").iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(pki.load_certificate(files[0]), pki.load_certificate(DATA / "leaf.crt"))
        finally:
            d.close()

    def test_unparsable_files_are_skipped(self):
        d = PkiDir(trusted=["ca.crt"])
        (d.base / "trusted" / "certs" / "garbage.crt").write_bytes(b"not a certificate")
        (d.base / "trusted" / "crl" / "garbage.crl").write_bytes(b"not a crl")
        self.assertIsNone(self.validate(d, "leaf.crt"))


class ClientValidatorTest(unittest.TestCase):
    def validate(self, trust: list[str], cert: str):
        try:
            v = run(pki.client_validator([str(DATA / t) for t in trust]))
            # The client does not compare the server's ApplicationUri with the SAN.
            run(v(pki.load_certificate(DATA / cert), app("urn:anything")))
            return None
        except ServiceError as e:
            return e.code

    def test_server_issued_by_the_listed_ca(self):
        self.assertIsNone(self.validate(["ca.crt"], "leaf.crt"))
        self.assertIsNone(self.validate(["other.crt", "ca.crt"], "leaf.der"))

    def test_server_not_issued_by_a_listed_certificate(self):
        self.assertEqual(self.validate(["other.crt"], "leaf.crt"), ua.StatusCodes.BadCertificateUntrusted)

    def test_tampered_certificate(self):
        cert = pki.load_certificate(DATA / "leaf.crt")
        der = bytearray(cert.public_bytes(Encoding.DER))
        # Flip a bit of the RSA modulus, inside the signed TBSCertificate.
        modulus = cert.public_key().public_numbers().n.to_bytes(256, "big")
        i = bytes(der).index(modulus) + 128
        der[i] ^= 0x01
        tmp = Path(tempfile.mkdtemp(prefix="asyncua-pki-test-"))
        try:
            (tmp / "tampered.der").write_bytes(bytes(der))
            v = run(pki.client_validator([str(DATA / "ca.crt")]))
            with self.assertRaises(ServiceError) as ctx:
                run(v(pki.load_certificate(tmp / "tampered.der"), app("urn:anything")))
            self.assertEqual(ctx.exception.code, ua.StatusCodes.BadCertificateUntrusted)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
