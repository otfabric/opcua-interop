// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>
    /// The "test" subcommand: in-process unit tests of the adapter's own code (no network).
    ///   - the capability document is well formed and reports AdapterVersion,
    ///   - literal parsing (client write / call / codec encode) produces the expected Variants
    ///     and OPC UA Binary encodings, and rejects malformed input,
    ///   - every Variable of the fixture gets a Variant of its declared type whose binary
    ///     encoding survives a decode / re-encode round trip.
    /// The fixture is --fixture, else /fixtures/baseline/fixture.json (the mount the Makefile
    /// and CI use). Exit 0 when every check passes, 1 otherwise.
    /// </summary>
    internal static class SelfTest
    {
        private const string DefaultFixture = "/fixtures/baseline/fixture.json";

        private static int s_pass;
        private static int s_fail;

        public static int Run(string[] args)
        {
            var a = new Args(args);
            string fixturePath = a.Get("--fixture") ?? DefaultFixture;

            Section("capabilities", CheckCapabilities);
            Section("literals", CheckLiterals);
            Section("pubsub codec", CheckPubSubCodec);
            Section("alarms", CheckAlarms);
            Section("push / gds-pull flags", CheckPushFlags);
            Section("history events", CheckHistoryEvents);
            if (File.Exists(fixturePath))
            {
                Section("fixture " + fixturePath, () => CheckFixture(fixturePath));
            }
            else if (a.Get("--fixture") != null)
            {
                Fail("fixture " + fixturePath + " does not exist");
            }
            else
            {
                Console.Error.WriteLine("[dotnet] test: no fixture at " + DefaultFixture + " (mount fixtures/ on /fixtures); fixture checks skipped");
            }

            Console.Error.WriteLine("[dotnet] test: " + s_pass + " passed, " + s_fail + " failed (stack " + Capabilities.StackVersion + ")");
            return s_fail == 0 ? 0 : 1;
        }

        private static void Section(string name, Action body)
        {
            try
            {
                body();
            }
            catch (Exception e)
            {
                Fail(name + ": unexpected " + e.GetType().Name + ": " + e.Message);
            }
        }

        private static void Check(bool ok, string what)
        {
            if (ok)
            {
                s_pass++;
                Console.Error.WriteLine("PASS: " + what);
            }
            else
            {
                Fail(what);
            }
        }

        private static void Fail(string what)
        {
            s_fail++;
            Console.Error.WriteLine("FAIL: " + what);
        }

        // ── capabilities ────────────────────────────────────────────────────

        private static void CheckAlarms()
        {
            using (JsonDocument doc = JsonDocument.Parse(Capabilities.Document()))
            {
                JsonElement root = doc.RootElement;
                Check(root.GetProperty("clientOperations").EnumerateArray().Any(e => e.GetString() == "alarms"),
                    "capabilities clientOperations has alarms");
                Check(root.GetProperty("serverFeatures").EnumerateArray().Any(e => e.GetString() == "alarms"),
                    "capabilities serverFeatures has alarms");
            }
            Check(ClientCommand.PresenceFlag(new Args(["--acknowledge", "--confirm"]), "--acknowledge"), "bare --acknowledge is true");
            Check(ClientCommand.PresenceFlag(new Args(["--confirm"]), "--confirm"), "trailing bare --confirm is true");
            Check(!ClientCommand.PresenceFlag(new Args(["--confirm", "false"]), "--confirm"), "--confirm false is false");
            Check(!ClientCommand.PresenceFlag(new Args([]), "--add-comment"), "absent --add-comment is false");
            Check(ClientCommand.s_alarmClauses.Length == 16 && ClientCommand.s_alarmClauses[15].Path.Length == 0 &&
                ClientCommand.s_alarmClauses[15].Attribute == Attributes.NodeId, "16 SelectClauses, ConditionId is the NodeId attribute");

            var f = new Variant[16];
            f[0] = new Variant(ByteString.From(new byte[] { 1, 2, 3 }));
            f[1] = new Variant(ObjectTypeIds.AlarmConditionType);
            f[2] = new Variant(new NodeId("Alarms.Source", 2));
            f[3] = new Variant("Alarms.Source");
            f[4] = new Variant(new DateTimeUtc(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
            f[5] = new Variant(new LocalizedText("en", "interop-alarm"));
            f[6] = new Variant((ushort)500);
            f[7] = new Variant("InteropAlarm");
            f[9] = new Variant(true);
            f[10] = new Variant(true);
            f[11] = new Variant(new LocalizedText("en", "c"));
            f[12] = new Variant(false);
            f[13] = new Variant(StatusCodes.BadAttributeIdInvalid);
            f[14] = new Variant(true);
            f[15] = new Variant(new NodeId("Alarms.InteropAlarm", 2));
            string json = ClientCommand.ConditionEntry(f).ToJsonString();
            Check(json == "{\"conditionId\":\"ns=2;s=Alarms.InteropAlarm\",\"eventId\":\"AQID\",\"eventType\":\"i=2915\"," +
                "\"sourceNode\":\"ns=2;s=Alarms.Source\",\"sourceName\":\"Alarms.Source\",\"conditionName\":\"InteropAlarm\"," +
                "\"time\":\"2026-01-01T00:00:00.000Z\",\"message\":\"interop-alarm\",\"severity\":500,\"retain\":true," +
                "\"enabled\":true,\"acked\":false,\"confirmed\":null,\"active\":true,\"comment\":\"c\"}",
                "ConditionEntry encoding (StatusCode field → null): " + json);
        }

        private static void CheckCapabilities()
        {
            using JsonDocument doc = JsonDocument.Parse(Capabilities.Document());
            JsonElement root = doc.RootElement;
            Check(root.GetProperty("schemaVersion").GetString() == "1.0", "capabilities schemaVersion is 1.0");
            Check(root.GetProperty("adapter").GetProperty("name").GetString() == Result.Adapter,
                "capabilities adapter.name is " + Result.Adapter);
            Check(root.GetProperty("adapter").GetProperty("version").GetString() == Capabilities.AdapterVersion,
                "capabilities adapter.version is " + Capabilities.AdapterVersion);
            Check(root.GetProperty("stack").GetProperty("version").GetString() != "unknown",
                "capabilities stack.version is known");
            string[] ops = root.GetProperty("clientOperations").EnumerateArray().Select(e => e.GetString()).ToArray();
            Check(ops.Length > 0 && ops.SequenceEqual(ClientCommand.Operations),
                "capabilities clientOperations are the implemented operations (" + ops.Length + ")");
            JsonElement pubsub = root.GetProperty("pubsub");
            Check(pubsub.GetProperty("supported").GetBoolean(), "capabilities pubsub.supported is true");
            Check(pubsub.GetProperty("codecOps").EnumerateArray().Select(e => e.GetString()).SequenceEqual(PubSubCodec.Operations),
                "capabilities pubsub.codecOps are the implemented codec operations");
        }

        // ── history events ──────────────────────────────────────────────────

        private static void CheckHistoryEvents()
        {
            using (JsonDocument doc = JsonDocument.Parse(Capabilities.Document()))
            {
                JsonElement root = doc.RootElement;
                string[] ops = root.GetProperty("clientOperations").EnumerateArray().Select(e => e.GetString()).ToArray();
                Check(ops.Contains("history-read-events") && ops.Contains("history-update-events"),
                    "capabilities clientOperations has history-read-events and history-update-events");
                string[] features = root.GetProperty("serverFeatures").EnumerateArray().Select(e => e.GetString()).ToArray();
                Check(features.Contains("history-events") && features.Contains("history-events-update"),
                    "capabilities serverFeatures has history-events and history-events-update");
                Check(root.GetProperty("serverServices").EnumerateArray().Any(e => e.GetString() == "HistoryUpdate"),
                    "capabilities serverServices has HistoryUpdate");
            }
            Check(ClientCommand.DefaultHistoryEventSelect.SequenceEqual(
                ["EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"]),
                "history-read-events default SelectClauses");
            SimpleAttributeOperand op = ClientCommand.SelectOperand("2:Foo/Bar");
            Check(op.TypeDefinitionId == ObjectTypeIds.BaseEventType && op.AttributeId == Attributes.Value &&
                op.BrowsePath.Count == 2 && op.BrowsePath[0] == new QualifiedName("Foo", 2) && op.BrowsePath[1] == new QualifiedName("Bar", 0),
                "--select 2:Foo/Bar is BaseEventType / [2:Foo, 0:Bar] / Value");
            ContentFilter none = ClientCommand.EventWhere(NodeId.Null, null);
            Check(none.Elements.Count == 0, "no --of-type / --min-severity: empty WhereClause");
            ContentFilter both = ClientCommand.EventWhere(ObjectTypeIds.SystemEventType, 300);
            Check(both.Elements.Count == 3 && both.Elements[0].FilterOperator == FilterOperator.And &&
                both.Elements[1].FilterOperator == FilterOperator.OfType && both.Elements[2].FilterOperator == FilterOperator.GreaterThanOrEqual,
                "--of-type and --min-severity: And(1, 2) first, then OfType, GreaterThanOrEqual");
            Check(ClientCommand.EventTimestamps("Neither") == TimestampsToReturn.Neither && ClientCommand.EventTimestamps(null) == TimestampsToReturn.Both,
                "--timestamps is case-insensitive, default both");

            var ev = ClientCommand.ParseEventJson(
                "{\"EventId\":{\"type\":\"ByteString\",\"value\":\"aGlzdC1ldnQtOQ==\"},\"EventType\":{\"type\":\"NodeId\",\"value\":\"i=2041\"}," +
                "\"Time\":{\"type\":\"DateTime\",\"value\":\"2026-07-24T10:00:30Z\"},\"Severity\":{\"type\":\"UInt16\",\"value\":700}," +
                "\"Message\":{\"type\":\"LocalizedText\",\"value\":{\"text\":\"x\"}},\"SourceName\":\"src\"}");
            Variant V(string path) => ClientCommand.EventFieldVariant(ev.First(f => f.Path == path), s => NodeIds.Parse(s));
            Check(ev.Count == 6 && ev[0].Path == "EventId", "--event keeps the field order");
            Check(V("EventId").TryGetValue(out ByteString id) && System.Text.Encoding.ASCII.GetString(id.Span.ToArray()) == "hist-evt-9", "--event ByteString is Base64");
            Check(V("EventType").TryGetValue(out NodeId et) && et == ObjectTypeIds.BaseEventType, "--event NodeId");
            Check(V("Time").TryGetValue(out DateTimeUtc t) && t.ToDateTime() == new DateTime(2026, 7, 24, 10, 0, 30, DateTimeKind.Utc), "--event DateTime");
            Check(V("Severity").TryGetValue(out ushort sev) && sev == 700, "--event UInt16");
            Check(V("Message").TryGetValue(out LocalizedText lt) && lt.Text == "x", "--event LocalizedText");
            Check(V("SourceName").TryGetValue(out string sn) && sn == "src", "--event plain string is a String");
            foreach (string bad in new[] { "[]", "{\"Severity\":{\"type\":\"UInt16\",\"value\":70000}}", "{\"EventId\":{\"type\":\"ByteString\",\"value\":\"%%\"}}", "{\"\":1}" })
            {
                bool refused = false;
                try
                {
                    ClientCommand.ParseEventJson(bad);
                }
                catch (InputException)
                {
                    refused = true;
                }
                Check(refused, "--event " + bad + " is an input error");
            }

            var seed = InteropNodeManager.HistoryEventSeed();
            Check(seed.Count == 5 && seed[0].EventId == "hist-evt-0" && seed[0].Severity == 100 &&
                seed[3].EventType == ObjectTypeIds.SystemEventType && seed[4].Time == new DateTime(2026, 7, 24, 10, 0, 20, DateTimeKind.Utc) &&
                seed[4].Message == "history-event-4" && seed.Count(e => e.EventType == ObjectTypeIds.BaseEventType) == 4,
                "History.Events seed: hist-evt-0…4, 5 s apart, Severity 100…500, #3 SystemEventType");
        }

        // ── push / gds-pull flags ───────────────────────────────────────────

        private static void CheckPushFlags()
        {
            PushOptions o = PushOptions.Parse(new Args([]));
            Check(o.GroupId == "i=14156" && o.CertificateTypeId == "i=12560" && !o.Apply && !o.Cancel && o.LifetimeDays == 365 && o.KeySize == 0,
                "push defaults: DefaultApplicationGroup, RsaSha256ApplicationCertificateType, lifetime 365, key size 0");
            o = PushOptions.Parse(new Args(["--group", "Https"]));
            Check(o.GroupId == "i=14088" && o.CertificateTypeId == "i=12558", "push --group Https: DefaultHttpsGroup, HttpsCertificateType");
            o = PushOptions.Parse(new Args(["--group", "UserToken", "--create-self-signed"]));
            Check(o.GroupId == "i=14122" && o.CertificateTypeId == "i=15181" && o.Cancel, "push --group UserToken --create-self-signed: CancelChanges implied");
            o = PushOptions.Parse(new Args(["--delete-certificate", "i=12560", "--apply"]));
            Check(o.DeleteType == "i=12560" && o.Apply && !o.Cancel, "push --delete-certificate --apply: no CancelChanges");
            foreach (string[] bad in new[]
            {
                new[] { "--group", "Nope" },
                new[] { "--lifetime-days", "65536" },
                new[] { "--key-size", "-1" },
                new[] { "--delete-certificate", "x=1" },
                new[] { "--add-certificate", "/nonexistent.der" },
                new[] { "--update-private-key", "/nonexistent.pem" }
            })
            {
                bool refused = false;
                try
                {
                    PushOptions.Parse(new Args(bad));
                }
                catch (InputException)
                {
                    refused = true;
                }
                Check(refused, "push " + string.Join(' ', bad) + " is an input error");
            }
            GdsPullOptions g = GdsPullOptions.Parse(new Args(["--app-uri", "urn:x:y:my-app"]));
            Check(g.AppName == "my-app" && g.Request == "csr" && g.AppType == ApplicationType.Server, "gds-pull defaults and the application name");
            bool badPull = false;
            try
            {
                GdsPullOptions.Parse(new Args(["--request", "nope"]));
            }
            catch (InputException)
            {
                badPull = true;
            }
            Check(badPull, "gds-pull --request nope is an input error");
        }

        // ── PubSub codec ────────────────────────────────────────────────────

        // The UADP example of docs/CONTAINER_CONTRACT.md §14.9 and its description.
        private const string UadpExample = "8SG6CAlkAAcAAU30hyYcRNVi3QEJAwAEAAb7////DAIAAABoaQn//////////4YDAAAAAQAAAAIAAAADAAAA";

        private const string UadpExampleDescription =
            "{\"publisherId\":{\"type\":\"UInt16\",\"value\":2234},\"groupHeader\":{\"writerGroupId\":100,\"sequenceNumber\":7}," +
            "\"payloadHeader\":true,\"timestamp\":\"2026-10-23T10:00:00.1234567Z\"," +
            "\"messages\":[{\"dataSetWriterId\":62541,\"messageType\":\"KeyFrame\",\"fieldEncoding\":\"Variant\",\"sequenceNumber\":3," +
            "\"fields\":[{\"dataType\":\"Int32\",\"value\":-5},{\"dataType\":\"String\",\"value\":\"hi\"}," +
            "{\"dataType\":\"UInt64\",\"value\":\"18446744073709551615\"},{\"dataType\":\"Int32\",\"value\":[1,2,3]}]}]}";

        private static void CheckPubSubCodec()
        {
            Check(PubSubCodec.ReencodeUadpAsync(UadpExample).GetAwaiter().GetResult() == UadpExample,
                "pubsub-uadp-decode re-encodes the §14.9 example byte for byte");
            Check(PubSubCodec.EncodeUadpAsync(UadpExampleDescription).GetAwaiter().GetResult() == UadpExample,
                "pubsub-uadp-encode of the §14.9 description is the §14.9 example");
        }

        // ── literal parsing and binary encoding ─────────────────────────────

        private static void CheckLiterals()
        {
            ExpectBinary("Int32", "-123456789", "BusypPg=");
            ExpectBinary("Boolean", "true", "AQE=");
            ExpectBinary("Byte", "255", "A/8=");
            ExpectBinary("Double[]", "1.5,2.5", "iwIAAAAAAAAAAAD4PwAAAAAAAARA");

            foreach ((string type, string literal) in new[]
            {
                ("Int64", "-1234567890123456789"),
                ("UInt64", "18446744073709551615"),
                ("Float", "3.25"),
                ("String", "interop"),
                ("DateTime", "2024-01-02T03:04:05.123Z"),
                ("Guid", "72962B91-FA75-4AE6-8D28-B404DC7DAF63"),
                ("LocalizedText[]", "[\"en:Hello\",\"de:Hallo\"]"),
                ("String[]", "[\"a\",\"b,c\"]")
            })
            {
                Variant v = ValueParser.Parse(type, literal, null);
                Check(Canonical.DataTypeName(v) + (Canonical.ValueRank(v) >= 1 ? "[]" : "") == type,
                    "parse " + type + " " + literal + " has type " + type);
                Check(RoundTrips(v), "binary round trip of " + type + " " + literal);
            }

            Variant m = ValueParser.Parse("Int32[]", "1,2,3,4,5,6", [2, 3]);
            Check(Canonical.ValueRank(m) == 2 && Canonical.Dimensions(m).SequenceEqual([2, 3]),
                "Int32[] with dimensions 2x3 is a matrix");
            Check(RoundTrips(m), "binary round trip of a 2x3 Int32 matrix");

            ExpectInputError("Int32", "abc", null);
            ExpectInputError("Int32", "2147483648", null);
            ExpectInputError("NoSuchType", "1", null);
            ExpectInputError("Int32[]", "1,2,3", [2, 2]);
            Check(Canonical.DataTypeName(ValueParser.ParseLenient("Int32", "abc")) == "String",
                "lenient parse of a malformed Int32 falls back to String");
        }

        private static void ExpectBinary(string type, string literal, string base64)
        {
            string got = Convert.ToBase64String(Encode(ValueParser.Parse(type, literal, null)));
            Check(got == base64, "binary of " + type + " " + literal + " is " + base64 + " (got " + got + ")");
        }

        private static void ExpectInputError(string type, string literal, int[] dims)
        {
            try
            {
                ValueParser.Parse(type, literal, dims);
                Fail("parse " + type + " " + literal + " is rejected");
            }
            catch (InputException)
            {
                Check(true, "parse " + type + " " + literal + " is rejected");
            }
            catch (Exception e)
            {
                Fail("parse " + type + " " + literal + " is rejected with an InputException, not " + e.GetType().Name);
            }
        }

        // ── fixture ─────────────────────────────────────────────────────────

        private static void CheckFixture(string path)
        {
            Fixture f = Fixture.Load(path);
            Check(f.Nodes.Count > 0, "fixture " + f.Id + " loads (" + f.Nodes.Count + " nodes)");
            int variables = 0;
            int bad = 0;
            foreach (Fixture.NodeDef nd in f.Nodes.Where(n => n.NodeClass == "Variable"))
            {
                variables++;
                try
                {
                    Variant v = InteropNodeManager.FixtureValue(nd);
                    if (v.IsNull)
                    {
                        continue;
                    }
                    string type = Canonical.DataTypeName(v);
                    bool typeOk = nd.DataType == null || type == nd.DataType || nd.DataType is "BaseDataType" or "Number";
                    bool rankOk = nd.ValueRank < 0 ? Canonical.ValueRank(v) < 0 : Canonical.ValueRank(v) == nd.ValueRank;
                    if (!typeOk || !rankOk || !RoundTrips(v))
                    {
                        bad++;
                        Fail("fixture " + nd.NodeId + ": value " + type + " rank " + Canonical.ValueRank(v)
                             + ", declared " + nd.DataType + " rank " + nd.ValueRank + (typeOk && rankOk ? ", binary round trip differs" : ""));
                    }
                }
                catch (Exception e)
                {
                    bad++;
                    Fail("fixture " + nd.NodeId + ": " + e.Message);
                }
            }
            Check(bad == 0, "fixture: " + variables + " variables have values of their declared type and rank that round-trip");

            Fixture.NodeDef int32 = f.Nodes.FirstOrDefault(n => n.NodeId.EndsWith("s=Scalar.Int32", StringComparison.Ordinal));
            Check(int32 != null && Convert.ToBase64String(Encode(InteropNodeManager.FixtureValue(int32))) == "BusypPg=",
                "fixture Scalar.Int32 is -123456789");
        }

        // ── encoding helpers ────────────────────────────────────────────────

        private static byte[] Encode(Variant v)
        {
            using var e = new BinaryEncoder(Codec.Context);
            e.WriteVariant(null, v);
            return e.CloseAndReturnBuffer() ?? [];
        }

        private static bool RoundTrips(Variant v)
        {
            byte[] first = Encode(v);
            using var d = new BinaryDecoder(first, Codec.Context);
            byte[] second = Encode(d.ReadVariant(null));
            return first.AsSpan().SequenceEqual(second);
        }
    }
}
