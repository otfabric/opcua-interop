"""`client alarms` (docs/CLIENT_CONTRACT.md §4 `alarms`): select clauses, ConditionEntry encoding, flags."""

import datetime
import unittest

from asyncua import ua

from opcua_interop_asyncua import client
from opcua_interop_asyncua.common import Args


def _fields(**over):
    v = [
        ua.Variant(b"\x01\x02", ua.VariantType.ByteString),
        ua.Variant(ua.NodeId(2915), ua.VariantType.NodeId),
        ua.Variant(ua.NodeId("Alarms.Source", 1), ua.VariantType.NodeId),
        ua.Variant("Alarms.Source", ua.VariantType.String),
        ua.Variant(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc), ua.VariantType.DateTime),
        ua.Variant(ua.LocalizedText(Text="interop-alarm", Locale="en"), ua.VariantType.LocalizedText),
        ua.Variant(500, ua.VariantType.UInt16),
        ua.Variant("InteropAlarm", ua.VariantType.String),
        ua.Variant(None, ua.VariantType.Null),
        ua.Variant(True, ua.VariantType.Boolean),
        ua.Variant(True, ua.VariantType.Boolean),
        ua.Variant(ua.LocalizedText(Text="", Locale=""), ua.VariantType.LocalizedText),
        ua.Variant(False, ua.VariantType.Boolean),
        ua.Variant(ua.StatusCode(0x80340000), ua.VariantType.StatusCode),
        ua.Variant(True, ua.VariantType.Boolean),
        ua.Variant(ua.NodeId("Alarms.InteropAlarm", 1), ua.VariantType.NodeId),
    ]
    for i, x in over.items():
        v[int(i[1:])] = x
    return v


class AlarmsTest(unittest.TestCase):
    def test_select_clauses(self):
        self.assertEqual(len(client.ALARM_SELECT), 16)
        tid, path, attr = client.ALARM_SELECT[15]
        self.assertEqual((tid, path, attr), (2782, [], ua.AttributeIds.NodeId))
        self.assertEqual(client.ALARM_SELECT[10][1], ["EnabledState", "Id"])
        self.assertEqual(client.ALARM_SELECT[14][0], 2915)

    def test_condition_entry(self):
        e = client._condition_entry(_fields())
        self.assertEqual(list(e), ["conditionId", "eventId", "eventType", "sourceNode", "sourceName",
                                   "conditionName", "time", "message", "severity", "retain", "enabled",
                                   "acked", "confirmed", "active", "comment"])
        self.assertEqual(e["conditionId"], "ns=1;s=Alarms.InteropAlarm")
        self.assertEqual(e["eventId"], "AQI=")
        self.assertEqual(e["eventType"], "i=2915")
        self.assertEqual(e["time"], "2026-01-01T00:00:00.000Z")
        self.assertEqual(e["message"], "interop-alarm")
        self.assertEqual(e["severity"], 500)
        self.assertIs(e["acked"], False)
        self.assertIsNone(e["confirmed"])  # a StatusCode field is null
        self.assertEqual(e["comment"], "")

    def test_base_event_has_no_condition_id(self):
        e = client._condition_entry(_fields(f15=ua.Variant(None, ua.VariantType.Null)))
        self.assertIsNone(e["conditionId"])
        self.assertIsNone(client._condition_entry([])["eventId"])

    def test_null_datetime_is_null(self):
        null_time = ua.Variant(datetime.datetime(1601, 1, 1), ua.VariantType.DateTime)
        self.assertIsNone(client._condition_entry(_fields(f4=null_time))["time"])

    def test_presence_flags(self):
        a = Args(["--acknowledge", "--confirm", "false", "--add-comment"])
        self.assertTrue(client._presence_flag(a, "--acknowledge"))
        self.assertFalse(client._presence_flag(a, "--confirm"))
        self.assertTrue(client._presence_flag(a, "--add-comment"))
        self.assertFalse(client._presence_flag(Args([]), "--acknowledge"))

    def test_registered(self):
        self.assertIn("alarms", client.OPERATIONS)
        self.assertIs(client.COMMANDS["alarms"], client.cmd_alarms)


if __name__ == "__main__":
    unittest.main()
