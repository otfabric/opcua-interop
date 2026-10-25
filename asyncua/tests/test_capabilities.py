"""print-capabilities declares what the adapter does, and what it does not do
is refused with exit 2 (docs/CLIENT_CONTRACT.md §5, §13), never faked."""

import asyncio
import contextlib
import io
import json
import logging
import unittest

from opcua_interop_asyncua import capabilities, client, server

logging.disable(logging.WARNING)


def run_client(op, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = asyncio.run(client.run_async(op, list(argv)))
    lines = [line for line in out.getvalue().splitlines() if line.startswith("{")]
    return rc, json.loads(lines[-1]) if lines else None


def run_server(*argv):
    with contextlib.redirect_stderr(io.StringIO()):
        return asyncio.run(server.run(list(argv)))


class CapabilitiesTest(unittest.TestCase):
    caps = capabilities.capabilities()

    def test_document(self):
        c = self.caps
        self.assertEqual(c["schemaVersion"], "1.0")
        self.assertEqual(c["adapter"], {"name": "asyncua", "version": "0.16.0"})
        self.assertEqual(c["stack"]["name"], "opcua-asyncio")
        self.assertRegex(c["stack"]["version"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(c["roles"], ["client", "server"])
        json.dumps(c, allow_nan=False)

    def test_operations_are_the_dispatched_ones(self):
        self.assertEqual(set(self.caps["clientOperations"]), set(client.COMMANDS))
        self.assertNotIn("codec", self.caps["clientOperations"])

    def test_no_unimplemented_features(self):
        for f in ("reverse-listen", "ecc-security", "ecc-user-token", "codec-json", "codec-xml", "codec-pubsub"):
            self.assertNotIn(f, self.caps["clientFeatures"])
        # asyncua's deadband handling does not conform (README): not declared for the server.
        for f in ("deadband", "percent-deadband", "reverse-connect", "lds", "mdns", "node-management", "pubsub",
                  "ecc-security"):
            self.assertNotIn(f, self.caps["serverFeatures"])
        self.assertFalse(self.caps["pubsub"]["supported"])

    def test_security_profiles_are_offered_by_the_server(self):
        offered = {("None", "None")} | set(server._POLICY_TYPES)
        for p in self.caps["securityProfiles"]:
            self.assertIn((p["policy"], p["mode"]), offered)
            self.assertIn(p["policy"], client.POLICIES)
            self.assertFalse(p["policy"].startswith("ECC_"))


class ClientRefusalTest(unittest.TestCase):
    def assertRefused(self, op, *argv):
        rc, out = run_client(op, *argv)
        self.assertEqual(rc, 2, out)
        self.assertFalse(out["success"])
        self.assertEqual(out["error"]["category"], "input")
        self.assertEqual(out["operation"], op)
        return out

    def test_codec(self):
        self.assertRefused("codec", "encode", "--format", "json", "--type", "Int32", "--value", "1")

    def test_reverse_listen(self):
        self.assertRefused("read", "--endpoint", "opc.tcp://localhost:4840", "--node", "i=2258", "--reverse-listen", "4855")

    def test_ecc_policy(self):
        out = self.assertRefused("read", "--endpoint", "opc.tcp://127.0.0.1:1", "--node", "i=2258",
                                 "--security-policy", "ECC_nistP256", "--security-mode", "SignAndEncrypt")
        self.assertIn("ECC", out["error"]["message"])

    def test_missing_endpoint(self):
        self.assertRefused("read", "--node", "i=2258")

    def test_inconsistent_security(self):
        self.assertRefused("read", "--endpoint", "opc.tcp://127.0.0.1:1", "--node", "i=2258",
                           "--security-policy", "Basic256Sha256", "--security-mode", "None")
        self.assertRefused("read", "--endpoint", "opc.tcp://127.0.0.1:1", "--node", "i=2258",
                           "--security-policy", "Basic256Sha256", "--security-mode", "SignAndEncrypt")

    def test_unknown_operation(self):
        rc, _ = run_client("no-such-op", "--endpoint", "opc.tcp://127.0.0.1:1")
        self.assertEqual(rc, 1)


class ServerRefusalTest(unittest.TestCase):
    def test_unsupported_flags(self):
        for flag in ("--reverse-connect", "--lds", "--mdns-name", "--mdns-capability", "--pubsub-config"):
            with self.subTest(flag=flag):
                self.assertEqual(run_server("--fixture", "/nonexistent.json", flag, "x"), 2)

    def test_missing_or_invalid_fixture(self):
        self.assertEqual(run_server(), 1)
        self.assertEqual(run_server("--fixture", "/nonexistent.json"), 5)


if __name__ == "__main__":
    unittest.main()
