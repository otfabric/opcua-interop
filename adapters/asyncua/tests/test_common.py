"""Canonical JSON forms (docs/CONTAINER_CONTRACT.md §6, §7), NodeId input (§8)
and value literals (§12)."""

import math
import struct
import unittest
import uuid
from datetime import datetime, timezone

from asyncua import ua

from opcua_interop_asyncua import common
from opcua_interop_asyncua.common import InputError


class NodeIdTest(unittest.TestCase):
    def test_canonical_form(self):
        cases = [
            (ua.NodeId(85, 0), "i=85"),
            (ua.NodeId(7, 2), "ns=2;i=7"),
            (ua.NodeId("Scalar.Int32", 2, ua.NodeIdType.String), "ns=2;s=Scalar.Int32"),
            (ua.NodeId(uuid.UUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"), 1, ua.NodeIdType.Guid),
             "ns=1;g=72962b91-fa75-4ae6-8d28-b404dc7daf63"),
            (ua.NodeId(b"\x01\x02", 3, ua.NodeIdType.ByteString), "ns=3;b=AQI="),
            (None, "i=0"),
        ]
        for nid, want in cases:
            with self.subTest(want=want):
                self.assertEqual(common.nodeid_str(nid), want)

    def test_parse(self):
        self.assertEqual(common.parse_nodeid_syntax("i=85"), (None, 0, 85, ua.NodeIdType.Numeric))
        self.assertEqual(common.parse_nodeid_syntax("ns=2;s=a;b"), (None, 2, "a;b", ua.NodeIdType.String))
        uri, ns, ident, t = common.parse_nodeid_syntax("nsu=urn:x;s=Scalar.Int32")
        self.assertEqual((uri, ident, t), ("urn:x", "Scalar.Int32", ua.NodeIdType.String))

    def test_malformed_is_an_input_error(self):
        for bad in ("", "nsu=missing", "nsu=;i=1", "ns=x;i=1", "ns=70000;i=1", "i=abc", "i=-1", "i=4294967296",
                    "g=not-a-guid", "b=!!", "q=1"):
            with self.subTest(bad=bad), self.assertRaises(InputError):
                common.parse_nodeid_syntax(bad)

    def test_literal_rejects_namespace_uri(self):
        with self.assertRaises(InputError):
            common.parse_nodeid_literal("nsu=urn:x;i=1")


class StatusCodeTest(unittest.TestCase):
    def test_names_and_severity(self):
        self.assertEqual(common.status_json(0), {"name": "Good", "code": 0, "severity": "Good"})
        self.assertEqual(common.status_json(0x80340000), {"name": "BadNodeIdUnknown", "code": 0x80340000, "severity": "Bad"})
        self.assertEqual(common.status_json(ua.StatusCode(0x40000000))["severity"], "Uncertain")

    def test_info_bits_report_the_base_name(self):
        # Good with the Overflow info bit (0x480) keeps the name of the base code.
        self.assertEqual(common.status_json(0x00000480)["name"], "Good")
        self.assertEqual(common.status_json(0x80340480)["name"], "BadNodeIdUnknown")

    def test_unknown_code_falls_back_on_severity(self):
        self.assertEqual(common.status_json(0x80FF0000)["name"], "Bad")


class ValueTest(unittest.TestCase):
    def test_64_bit_integers_are_strings(self):
        self.assertEqual(common.variant_fields(ua.Variant(-5, ua.VariantType.Int64))["value"], "-5")
        self.assertEqual(common.variant_fields(ua.Variant(2**64 - 1, ua.VariantType.UInt64))["value"], str(2**64 - 1))

    def test_float_is_the_shortest_float32(self):
        self.assertEqual(common.variant_fields(ua.Variant(0.1, ua.VariantType.Float))["value"], 0.1)
        # FLT_MAX: a shorter rounding (3.402824e38) is beyond FLT_MAX and
        # does not pack as a float32 at all; the shortest that does is 3.4028235e38.
        flt_max = 3.4028234663852886e38
        got = common.variant_fields(ua.Variant(flt_max, ua.VariantType.Float))["value"]
        self.assertEqual(struct.pack("<f", got), struct.pack("<f", flt_max))
        self.assertEqual(got, 3.4028235e38)

    def test_non_finite_is_null(self):
        for v in (math.nan, math.inf, -math.inf):
            self.assertIsNone(common.variant_fields(ua.Variant(v, ua.VariantType.Double))["value"])
            self.assertIsNone(common.variant_fields(ua.Variant(v, ua.VariantType.Float))["value"])

    def test_null_variant(self):
        self.assertEqual(common.variant_fields(ua.Variant()), {"dataType": "Null", "builtInType": 0, "value": None})

    def test_structured_built_ins(self):
        self.assertEqual(common.variant_value(ua.Variant(ua.LocalizedText("Hi", "en"))), {"locale": "en", "text": "Hi"})
        self.assertEqual(common.variant_value(ua.Variant(ua.QualifiedName("Name", 2))), {"ns": 2, "name": "Name"})
        self.assertEqual(common.variant_value(ua.Variant(b"\x00\xff", ua.VariantType.ByteString)), "AP8=")

    def test_datetime_is_utc_with_milliseconds(self):
        dt = datetime(2026, 7, 24, 10, 0, 5, 123000, tzinfo=timezone.utc)
        self.assertEqual(common.fmt_datetime(dt), "2026-07-24T10:00:05.123Z")
        self.assertEqual(common.fmt_datetime(dt.replace(microsecond=123456)), "2026-07-24T10:00:05.123456Z")

    def test_matrix_is_nested(self):
        var = ua.Variant([[1, 2], [3, 4]], ua.VariantType.Int32, Dimensions=[2, 2], is_array=True)
        self.assertEqual(common.variant_value(var), [[1, 2], [3, 4]])


class LiteralTest(unittest.TestCase):
    def test_scalars(self):
        self.assertEqual(common.build_variant("Int32", "42").Value, 42)
        self.assertIs(common.build_variant("Boolean", "true").Value, True)
        self.assertEqual(common.build_variant("LocalizedText", "en:Hi").Value, ua.LocalizedText("Hi", "en"))
        self.assertEqual(common.build_variant("QualifiedName", "2:Name").Value, ua.QualifiedName("Name", 2))
        self.assertEqual(common.build_variant("StatusCode", "0x80340000").Value, ua.StatusCode(0x80340000))
        self.assertEqual(common.build_variant("DateTime", "2026-07-24T10:00:00.1234567Z").Value,
                         datetime(2026, 7, 24, 10, 0, 0, 123456, tzinfo=timezone.utc))

    def test_arrays(self):
        var = common.build_variant("Int32[]", "1,2,3")
        self.assertEqual((var.Value, var.VariantType, var.is_array), ([1, 2, 3], ua.VariantType.Int32, True))
        self.assertEqual(common.build_variant("LocalizedText[]", '["en:Hello","de:Hallo"]').Value,
                         [ua.LocalizedText("Hello", "en"), ua.LocalizedText("Hallo", "de")])
        self.assertEqual(common.build_variant("Int32[]", "").Value, [])

    def test_out_of_range_and_unknown_types(self):
        for t, lit in (("Byte", "256"), ("SByte", "-129"), ("UInt32", "-1"), ("Int32", "x"), ("Guid", "nope"),
                       ("Nope", "1"), ("Nope[]", "1")):
            with self.subTest(t=t, lit=lit), self.assertRaises(InputError):
                common.build_variant(t, lit)

    def test_write_and_call_are_lenient(self):
        # §12: an unknown type or malformed literal is sent as a String.
        var = common.lenient_variant("Nope", "abc")
        self.assertEqual((var.Value, var.VariantType), ("abc", ua.VariantType.String))


class ArgsTest(unittest.TestCase):
    def test_flags(self):
        a = common.Args(["--endpoint", "opc.tcp://x", "--trust-list", "a", "--trust-list", "b", "--n", "3", "--flag"])
        self.assertEqual(a.get("--endpoint"), "opc.tcp://x")
        self.assertEqual(a.all("--trust-list"), ["a", "b"])
        self.assertEqual(a.int("--n", 0), 3)
        self.assertTrue(a.has("--flag"))
        self.assertIsNone(a.get("--flag"))
        with self.assertRaises(InputError):
            common.Args(["--n", "x"]).int("--n", 0)
        with self.assertRaises(InputError):
            common.Args(["--b", "maybe"]).bool("--b", False)


class EnvelopeTest(unittest.TestCase):
    def test_failure_envelope(self):
        r = common.Result("read").set_service(0x80340000).fail("service", "boom")
        import json

        out = json.loads(r.to_json())
        self.assertEqual(out["adapter"], "asyncua")
        self.assertEqual(out["schemaVersion"], "1.0")
        self.assertFalse(out["success"])
        self.assertEqual(out["error"], {"category": "service", "message": "boom"})
        self.assertEqual(out["serviceResult"]["name"], "BadNodeIdUnknown")


if __name__ == "__main__":
    unittest.main()
