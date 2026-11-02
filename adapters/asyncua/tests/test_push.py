"""`client push` (§1 "push flags", §15) and `client gds-pull` (§16.2): flag
parsing and input errors (exit 2 before connecting), the hand-made encodings
and the CSR. The commands themselves run against a consumer in its interop
suite (no asyncua server implements push management or a GDS)."""

import base64
import os
import tempfile
import unittest
from pathlib import Path

from asyncua import ua
from asyncua.common.utils import Buffer
from asyncua.ua import ua_binary
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from opcua_interop_asyncua import capabilities, client, push
from opcua_interop_asyncua.common import Args, InputError

from test_capabilities import run_client

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"
# Nothing listens there: an input error must come before connecting.
NOWHERE = "opc.tcp://127.0.0.1:9"


def _cert_file() -> str:
    return str(next(p for p in (TESTDATA / "pki").rglob("*.crt")))


class PushArgsTest(unittest.TestCase):
    def test_defaults(self):
        o = push.parse_push(Args([]))
        self.assertEqual((o.group, o.group_id, o.certificate_type_id), ("Application", "i=14156", "i=12560"))
        self.assertEqual((o.lifetime_days, o.key_size, o.subject), (365, 0, ""))
        self.assertFalse(o.apply or o.cancel or o.diagnostics or o.get_certificates or o.reset)

    def test_groups(self):
        self.assertEqual(push.parse_push(Args(["--group", "Https"])).certificate_type_id, "i=12558")
        o = push.parse_push(Args(["--group", "UserToken"]))
        self.assertEqual((o.group_id, o.certificate_type_id), ("i=14122", "i=15181"))
        self.assertEqual(push.parse_push(Args(["--group", "Https", "--certificate-type-id", "i=12560"])).certificate_type_id, "i=12560")

    def test_cancel_is_implied(self):
        self.assertTrue(push.parse_push(Args(["--create-self-signed"])).cancel)
        self.assertTrue(push.parse_push(Args(["--delete-certificate", "i=12560"])).cancel)
        self.assertTrue(push.parse_push(Args(["--cancel"])).cancel)
        o = push.parse_push(Args(["--delete-certificate", "i=12560", "--apply"]))
        self.assertTrue(o.apply)
        self.assertFalse(o.cancel)

    def test_create_self_signed_flags(self):
        o = push.parse_push(Args(["--create-self-signed", "--subject", "CN=x", "--dns", "a", "--dns", "b",
                                  "--ip", "192.0.2.1", "--lifetime-days", "2", "--key-size", "2048"]))
        self.assertEqual((o.subject, o.dns, o.ip, o.lifetime_days, o.key_size), ("CN=x", ["a", "b"], ["192.0.2.1"], 2, 2048))

    def test_private_key_format(self):
        self.assertEqual(push.private_key_format(Args([]), "/w/new.pfx"), "PFX")
        self.assertEqual(push.private_key_format(Args([]), "/w/NEW.P12"), "PFX")
        self.assertEqual(push.private_key_format(Args([]), "/w/new.key"), "PEM")
        self.assertEqual(push.private_key_format(Args(["--private-key-format", "PFX"]), "/w/new.key"), "PFX")
        with self.assertRaises(InputError):
            push.private_key_format(Args(["--private-key-format", "DER"]), "/w/new.key")

    def test_update_certificate_files(self):
        cert = _cert_file()
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "new.pfx")
            Path(key).write_bytes(b"\x30\x82pfx")
            o = push.parse_push(Args(["--update-certificate", cert, "--update-private-key", key, "--issuer-certificate", cert]))
        self.assertEqual(o.key, b"\x30\x82pfx")
        self.assertEqual(o.key_format, "PFX")
        self.assertEqual(o.update, o.issuers[0])
        x509.load_der_x509_certificate(o.update)

    def test_input_errors(self):
        cert = _cert_file()
        for argv in (
            ["--group", "Default"],
            ["--certificate-type-id", "x=1"],
            ["--delete-certificate", "nonsense"],
            ["--lifetime-days", "70000"],
            ["--key-size", "-1"],
            ["--lifetime-days", "two"],
            ["--add-certificate", "/nonexistent/add.der"],
            ["--update-private-key", cert],
            ["--update-certificate", cert, "--update-private-key", cert, "--private-key-format", "DER"],
            ["--issuer-certificate", "/nonexistent/ca.der"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(InputError):
                    push.parse_push(Args(argv))
                rc, res = run_client("push", "--endpoint", NOWHERE, *argv)
                self.assertEqual(rc, 2)
                self.assertEqual(res["error"]["category"], "input")

    def test_trust_list_codec(self):
        tl = ua.TrustListDataType(SpecifiedLists=15, TrustedCertificates=[b"\x01\x02"], TrustedCrls=[b"\x03"],
                                  IssuerCertificates=[], IssuerCrls=[b"\x04"])
        got = push.trust_list_json(push.decode_trust_list(ua_binary.struct_to_binary(tl)))
        self.assertEqual(got, {
            "specifiedLists": 15,
            "trustedCertificates": [base64.b64encode(b"\x01\x02").decode()],
            "trustedCrls": [base64.b64encode(b"\x03").decode()],
            "issuerCertificates": [],
            "issuerCrls": [base64.b64encode(b"\x04").decode()],
        })


class GdsPullArgsTest(unittest.TestCase):
    def test_defaults(self):
        o = push.parse_gds_pull(Args([]))
        self.assertEqual((o.app_uri, o.app_type, o.discovery_urls, o.request, o.certificate_type, o.finish_timeout_ms),
                         ("urn:opcua-interop:gds-pull:app", "Server", ["opc.tcp://localhost:4850"], "csr", "RsaSha256", 30000))
        self.assertFalse(o.revoke or o.unregister)

    def test_app_name(self):
        self.assertEqual(push.app_name("urn:otfabric:interop:gds-pull:asyncua-client"), "asyncua-client")
        self.assertEqual(push.app_name("http://example.com/apps/x/"), "x")
        self.assertEqual(push.app_name("urn:"), "urn")
        self.assertEqual(push.app_name(":::"), "opcua-interop gds-pull app")

    def test_input_errors(self):
        for argv in (
            ["--app-type", "Gateway"],
            ["--request", "pfx"],
            ["--certificate-type", "NistP384"],
            ["--finish-timeout-ms", "-1"],
            ["--finish-timeout-ms", "soon"],
            ["--app-uri", ""],
        ):
            with self.subTest(argv=argv):
                rc, res = run_client("gds-pull", "--endpoint", NOWHERE, *argv)
                self.assertEqual(rc, 2)
                self.assertEqual(res["error"]["category"], "input")
                self.assertEqual(res["operation"], "gds-pull")

    def test_application_record(self):
        o = push.parse_gds_pull(Args(["--app-uri", "urn:x:app", "--discovery-url", "opc.tcp://h:1", "--discovery-url", "opc.tcp://h:2"]))
        eo = push.encode_application_record(2, o)
        self.assertEqual(eo.TypeId, ua.NodeId(134, 2))
        b = Buffer(eo.Body)
        self.assertEqual(ua_binary.nodeid_from_binary(b), ua.NodeId())
        p = ua_binary.Primitives
        self.assertEqual(p.String.unpack(b), "urn:x:app")
        self.assertEqual(p.Int32.unpack(b), 0)
        names = ua_binary.from_binary(list[ua.LocalizedText], b)
        self.assertEqual((names[0].Text, names[0].Locale), ("app", "en-US"))
        self.assertEqual(p.String.unpack(b), "urn:opcua-interop:asyncua")
        self.assertEqual(ua_binary.unpack_uatype_array(ua.VariantType.String, b), ["opc.tcp://h:1", "opc.tcp://h:2"])
        self.assertEqual(ua_binary.unpack_uatype_array(ua.VariantType.String, b), ["NA"])
        self.assertEqual(len(b), 0)
        # A Client has no DiscoveryUrls / ServerCapabilities.
        c = push.encode_application_record(2, push.parse_gds_pull(Args(["--app-type", "Client"])))
        self.assertTrue(c.Body.endswith(b"\x00\x00\x00\x00\x00\x00\x00\x00"))
        # The ApplicationId of a returned record: its first field.
        rec = ua.ExtensionObject(TypeId=ua.NodeId(134, 2), Body=ua_binary.nodeid_to_binary(ua.NodeId(7, 2)) + eo.Body[1:])
        self.assertEqual(push.application_record_id(rec), ua.NodeId(7, 2))
        # It round-trips through a Variant (the RegisterApplication argument).
        v = ua_binary.variant_from_binary(Buffer(ua_binary.variant_to_binary(ua.Variant(eo, ua.VariantType.ExtensionObject))))
        self.assertEqual(v.Value.Body, eo.Body)

    def test_csr(self):
        for kind, key_type in (("RsaSha256", rsa.RSAPublicKey), ("NistP256", ec.EllipticCurvePublicKey)):
            with self.subTest(kind=kind):
                o = push.parse_gds_pull(Args(["--app-uri", "urn:x:gds-app", "--certificate-type", kind]))
                csr = x509.load_der_x509_csr(push.make_csr(o))
                self.assertTrue(csr.is_signature_valid)
                self.assertIsInstance(csr.public_key(), key_type)
                self.assertEqual(csr.subject.rfc4514_string(), "CN=gds-app")
                san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                self.assertEqual(san.get_values_for_type(x509.UniformResourceIdentifier), ["urn:x:gds-app"])
                self.assertEqual(san.get_values_for_type(x509.DNSName), ["localhost"])


class CapabilitiesTest(unittest.TestCase):
    def test_declared(self):
        caps = capabilities.capabilities()
        for op in ("push", "gds-pull"):
            self.assertIn(op, caps["clientOperations"])
            self.assertIn(op, client.COMMANDS)
        for f in ("push-groups", "push-certificates", "push-transaction-diagnostics"):
            self.assertIn(f, caps["clientFeatures"])
        # The adapter's server has no push management or GDS.
        self.assertNotIn("push-management", caps["serverFeatures"])
        self.assertNotIn("gds-pull", caps["serverFeatures"])


if __name__ == "__main__":
    unittest.main()
