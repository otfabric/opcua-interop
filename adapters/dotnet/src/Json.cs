// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Opc.Ua;

namespace OpcUaInterop
{
    /// <summary>JSON helpers and the result envelope of docs/CONTAINER_CONTRACT.md §3.</summary>
    internal static class Json
    {
        public static readonly JsonSerializerOptions Options = new()
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = false
        };

        public static string Serialize(JsonNode node) =>
            node == null ? "null" : node.ToJsonString(Options);

        public static JsonObject Obj(params (string Key, JsonNode Value)[] members)
        {
            var o = new JsonObject();
            foreach ((string k, JsonNode v) in members)
            {
                o[k] = v;
            }
            return o;
        }

        public static JsonArray Arr(IEnumerable<JsonNode> items)
        {
            var a = new JsonArray();
            foreach (JsonNode n in items)
            {
                a.Add(n);
            }
            return a;
        }

        public static JsonArray Strings(IEnumerable<string> items)
        {
            var a = new JsonArray();
            foreach (string s in items)
            {
                a.Add(JsonValue.Create(s));
            }
            return a;
        }
    }

    /// <summary>Symbolic StatusCode names (from Opc.Ua.StatusCodes constants).</summary>
    internal static class StatusNames
    {
        private static readonly Dictionary<uint, string> s_names = Build();

        // codes of OPC UA 1.04/1.05 that the 2.0 stack's table does not list
        private static readonly Dictionary<uint, string> s_extra = new()
        {
            [0x40920000] = "UncertainInitialValue"
        };

        private static Dictionary<uint, string> Build()
        {
            var d = new Dictionary<uint, string>();
            foreach (FieldInfo f in typeof(StatusCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            {
                object v = null;
                try
                {
                    v = f.IsLiteral ? f.GetRawConstantValue() : f.GetValue(null);
                }
                catch
                {
                    // ignore
                }
                uint code;
                if (v is uint u)
                {
                    code = u;
                }
                else if (v is StatusCode sc)
                {
                    code = sc.Code;
                }
                else
                {
                    continue;
                }
                d.TryAdd(code, f.Name);
            }
            d[0] = "Good";
            return d;
        }

        public static string Severity(uint code) =>
            (code & 0xC0000000) == 0 ? "Good" : (code & 0x80000000) != 0 ? "Bad" : "Uncertain";

        public static string Name(uint code)
        {
            if (s_names.TryGetValue(code, out string n) || s_extra.TryGetValue(code, out n))
            {
                return n;
            }
            // flag bits (e.g. overflow / limit bits) do not change the symbolic name
            if (s_names.TryGetValue(code & 0xFFFF0000, out n))
            {
                return n;
            }
            return Severity(code);
        }

        public static JsonObject Json(uint code) => OpcUaInterop.Json.Obj(
            ("name", JsonValue.Create(Name(code))),
            ("code", JsonValue.Create(code)),
            ("severity", JsonValue.Create(Severity(code))));

        public static JsonObject Json(StatusCode sc) => Json(sc.Code);

        public static JsonObject Good => Json(0u);
    }

    /// <summary>Thrown for invalid command-line input (exit 2).</summary>
    internal sealed class InputException : Exception
    {
        public InputException(string message) : base(message) { }
    }

    /// <summary>Thrown for transport / connect failures (exit 3).</summary>
    internal sealed class TransportException : Exception
    {
        public TransportException(string message, uint code = 0x80050000) : base(message)
        {
            Code = code;
        }

        public uint Code { get; }
    }

    /// <summary>The result envelope.</summary>
    internal sealed class Result
    {
        public const string Adapter = "dotnet";

        private readonly string m_operation;
        private bool m_success = true;
        private uint m_serviceResult;
        private readonly JsonArray m_results = new();
        private JsonObject m_error;

        public Result(string operation)
        {
            m_operation = operation;
        }

        public Result Success(bool s)
        {
            m_success = s;
            return this;
        }

        public Result ServiceResult(uint code)
        {
            m_serviceResult = code;
            return this;
        }

        public Result ServiceResult(StatusCode sc) => ServiceResult(sc.Code);

        public Result Add(JsonNode item)
        {
            m_results.Add(item);
            return this;
        }

        public Result Error(string category, string message)
        {
            m_success = false;
            m_error = Json.Obj(
                ("category", JsonValue.Create(category)),
                ("message", JsonValue.Create(message ?? string.Empty)));
            return this;
        }

        public bool IsSuccess => m_success;

        public string ToJson()
        {
            var o = new JsonObject
            {
                ["schemaVersion"] = "1.0",
                ["adapter"] = Adapter,
                ["operation"] = m_operation,
                ["success"] = m_success,
                ["serviceResult"] = StatusNames.Json(m_serviceResult),
                ["results"] = m_results,
                ["error"] = m_error
            };
            return Json.Serialize(o);
        }

        /// <summary>Writes the envelope to stdout (exactly one line).</summary>
        public void Print()
        {
            Console.Out.WriteLine(ToJson());
            Console.Out.Flush();
        }
    }

    internal static class Inv
    {
        public static readonly CultureInfo C = CultureInfo.InvariantCulture;
    }
}
