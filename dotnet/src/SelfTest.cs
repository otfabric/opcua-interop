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
            Check(!root.GetProperty("pubsub").GetProperty("supported").GetBoolean(), "capabilities pubsub.supported is false");
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
