"""`client history-read-events` / `history-update-events`: select paths,
WhereClause, --event values and flag validation (docs/CONTAINER_CONTRACT.md)."""

import base64
import datetime
import json
import unittest

from asyncua import ua

from opcua_interop_asyncua import history_events as he
from opcua_interop_asyncua.common import InputError


class SelectTest(unittest.TestCase):
    def test_browse_path(self):
        self.assertEqual(he.browse_path("EventId"), [ua.QualifiedName("EventId", 0)])
        self.assertEqual(he.browse_path("AckedState/Id"), [ua.QualifiedName("AckedState", 0), ua.QualifiedName("Id", 0)])
        self.assertEqual(he.browse_path("2:Vendor/Level"), [ua.QualifiedName("Vendor", 2), ua.QualifiedName("Level", 0)])
        for bad in ("", "/x", "x/", "a//b"):
            with self.assertRaises(InputError):
                he.browse_path(bad)

    def test_select_clause(self):
        c = he.select_clause("Severity")
        self.assertEqual(c.TypeDefinitionId, ua.NodeId(2041))
        self.assertEqual(c.AttributeId, ua.AttributeIds.Value)


class WhereTest(unittest.TestCase):
    def test_none(self):
        self.assertEqual(he.where_clause(None, None).Elements, [])

    def test_one(self):
        el = he.where_clause(ua.NodeId(2130), None).Elements
        self.assertEqual([e.FilterOperator for e in el], [ua.FilterOperator.OfType])
        el = he.where_clause(None, 300).Elements
        self.assertEqual([e.FilterOperator for e in el], [ua.FilterOperator.GreaterThanOrEqual])
        self.assertEqual(el[0].FilterOperands[1].Value, ua.Variant(300, ua.VariantType.UInt16))

    def test_both_and_is_the_root(self):
        el = he.where_clause(ua.NodeId(2130), 300).Elements
        self.assertEqual([e.FilterOperator for e in el],
                         [ua.FilterOperator.And, ua.FilterOperator.OfType, ua.FilterOperator.GreaterThanOrEqual])
        self.assertEqual([o.Index for o in el[0].FilterOperands], [1, 2])


class EventValueTest(unittest.TestCase):
    def test_typed(self):
        ev = json.loads('{"EventId":{"type":"ByteString","value":"aGk="},"Time":{"type":"DateTime","value":"2026-07-24T10:00:00Z"},'
                        '"Severity":{"type":"UInt16","value":700},"Message":{"type":"LocalizedText","value":{"text":"x"}},'
                        '"EventType":{"type":"NodeId","value":"i=2041"},"SourceName":{"type":"String","value":"s"}}')
        paths = ["EventId", "EventType", "Time", "Severity", "Message", "SourceName", "SourceNode"]
        f = he.event_field_list(paths, ev).EventFields
        self.assertEqual(f[0], ua.Variant(b"hi", ua.VariantType.ByteString))
        self.assertEqual(f[1], ua.Variant(ua.NodeId(2041), ua.VariantType.NodeId))
        self.assertEqual(f[2].Value, datetime.datetime(2026, 7, 24, 10, tzinfo=datetime.timezone.utc))
        self.assertEqual(f[3], ua.Variant(700, ua.VariantType.UInt16))
        self.assertEqual(f[4].Value.Text, "x")
        self.assertEqual(f[5], ua.Variant("s", ua.VariantType.String))
        self.assertIsNone(f[6].Value)  # selected, not given: null

    def test_untyped_and_errors(self):
        self.assertEqual(he._event_value("a", 3), ua.Variant(3, ua.VariantType.Int32))
        self.assertEqual(he._event_value("a", "s"), ua.Variant("s", ua.VariantType.String))
        self.assertEqual(he._event_value("a", True), ua.Variant(True, ua.VariantType.Boolean))
        self.assertIsNone(he._event_value("a", None).Value)
        with self.assertRaises(InputError):
            he._event_value("a", {"type": "UInt16", "value": 70000})
        with self.assertRaises(InputError):
            he._event_value("a", {"type": "Nope", "value": 1})
        with self.assertRaises(InputError):
            he.event_field_list(["EventId"], {"Severity": 1})
        with self.assertRaises(InputError):
            he.parse_events(["[1]"])

    def test_events_json(self):
        data = ua.HistoryEvent(Events=[ua.HistoryEventFieldList(EventFields=[
            ua.Variant(b"hist-evt-0", ua.VariantType.ByteString),
            ua.Variant(ua.StatusCode(ua.StatusCodes.BadNoData), ua.VariantType.StatusCode),
        ])])
        out = he.events_json(["EventId", "Nope", "Missing"], data)
        f = out[0]["fields"]
        self.assertEqual(f[0], {"name": "EventId", "dataType": "ByteString", "builtInType": 15,
                                "value": base64.b64encode(b"hist-evt-0").decode()})
        self.assertEqual(f[1]["value"]["name"], "BadNoData")
        self.assertEqual(len(f), 2)  # fewer fields from the server: fewer in the output


class FlagTest(unittest.TestCase):
    def run_op(self, *argv):
        import asyncio
        import contextlib
        import io

        from opcua_interop_asyncua import client

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = asyncio.run(client.run_async("history-read-events", ["--endpoint", "opc.tcp://127.0.0.1:1", *argv]))
        return rc, json.loads(out.getvalue().splitlines()[-1])

    def test_release_needs_a_continuation_point(self):
        rc, out = self.run_op("--node", "i=2253", "--release-continuation-point")
        self.assertEqual((rc, out["error"]["category"]), (2, "input"))

    def test_continuation_point_takes_one_node(self):
        rc, out = self.run_op("--node", "i=2253", "--node", "i=85", "--continuation-point", "AAAA")
        self.assertEqual((rc, out["error"]["category"]), (2, "input"))


if __name__ == "__main__":
    unittest.main()
