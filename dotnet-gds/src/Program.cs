// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;

namespace OpcUaInterop
{
    /// <summary>
    /// opcua-interop GDS adapter for the OPC Foundation UA-.NETStandard stack (1.5.378):
    ///   server             start the Global Discovery Server (Part 12 pull model)
    ///   client &lt;op&gt;        run one client operation (endpoints, gds-pull; docs/CLIENT_CONTRACT.md §16)
    ///   validate-fixture   validate a fixture file
    ///   print-capabilities emit the capability document
    ///   test               in-process checks (capabilities, the baseline fixture)
    /// </summary>
    public static class Program
    {
        public static async Task<int> Main(string[] args)
        {
            Console.OutputEncoding = new System.Text.UTF8Encoding(false);
            if (args.Length == 0)
            {
                Usage();
                return 1;
            }
            string[] rest = args[1..];
            try
            {
                switch (args[0])
                {
                    case "server":
                        return await GdsServerCommand.RunAsync(rest).ConfigureAwait(false);
                    case "client":
                        return await GdsClientCommand.RunAsync(rest).ConfigureAwait(false);
                    case "validate-fixture":
                        return ValidateCommand.Run(rest);
                    case "print-capabilities":
                        Console.Out.WriteLine(Capabilities.Document());
                        return 0;
                    case "test":
                        return SelfTest.Run(rest);
                    default:
                        Console.Error.WriteLine("unknown subcommand: " + args[0]);
                        Usage();
                        return 1;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet-gds] fatal: " + e);
                return 1;
            }
        }

        private static void Usage()
        {
            Console.Error.WriteLine("usage: opcua-interop-dotnet-gds <server|client|validate-fixture|print-capabilities|test> [args...]");
        }
    }

    internal static class ValidateCommand
    {
        public static int Run(string[] args)
        {
            var a = new Args(args);
            string path = a.Get("--fixture") ?? (args.Length > 0 ? args[^1] : null);
            if (path == null)
            {
                Console.Error.WriteLine("usage: validate-fixture --fixture <path>");
                return 2;
            }
            try
            {
                Fixture f = Fixture.Load(path);
                Console.Error.WriteLine("[dotnet-gds] fixture " + f.Id + " valid (" + f.Nodes.Count + " nodes, " + f.Users.Count + " users)");
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet-gds] fixture invalid: " + e.Message);
                return 5;
            }
        }
    }

    /// <summary>The "test" subcommand: offline consistency checks.</summary>
    internal static class SelfTest
    {
        public static int Run(string[] args)
        {
            var a = new Args(args);
            int failures = 0;
            void Check(bool ok, string what)
            {
                Console.Error.WriteLine("[dotnet-gds] test: " + (ok ? "OK   " : "FAIL ") + what);
                if (!ok)
                {
                    failures++;
                }
            }

            try
            {
                var doc = System.Text.Json.Nodes.JsonNode.Parse(Capabilities.Document());
                Check(doc?["adapter"]?["name"]?.GetValue<string>() == Result.Adapter, "capabilities adapter name");
                Check(doc?["stack"]?["version"]?.GetValue<string>() == Capabilities.PinnedStackVersion, "stack version " + Capabilities.StackVersion);
            }
            catch (Exception e)
            {
                Check(false, "capabilities: " + e.Message);
            }
            Check(StatusNames.Name(Opc.Ua.StatusCodes.BadNothingToDo) == "BadNothingToDo", "status code names");
            Check(Canonical.NodeId(new Opc.Ua.NodeId(615u, 2)) == "ns=2;i=615", "canonical NodeId");

            string fixture = a.Get("--fixture") ?? "/fixtures/gds/fixture.json";
            if (System.IO.File.Exists(fixture))
            {
                try
                {
                    Fixture f = Fixture.Load(fixture);
                    Check(true, "fixture " + fixture + " (" + f.Users.Count + " users)");
                }
                catch (Exception e)
                {
                    Check(false, "fixture " + fixture + ": " + e.Message);
                }
            }
            Console.Error.WriteLine(failures == 0 ? "[dotnet-gds] self-test: OK" : "[dotnet-gds] self-test: " + failures + " failure(s)");
            return failures == 0 ? 0 : 1;
        }
    }

    /// <summary>NodeIds in the canonical string form of docs/CLIENT_CONTRACT.md §6.</summary>
    internal static class Canonical
    {
        public static string NodeId(Opc.Ua.NodeId n)
        {
            if (n == null || (Opc.Ua.NodeId.IsNull(n) && n.IdType == Opc.Ua.IdType.Numeric))
            {
                return "i=0";
            }
            string prefix = n.NamespaceIndex == 0 ? string.Empty : "ns=" + n.NamespaceIndex.ToString(Inv.C) + ";";
            return n.IdType switch
            {
                Opc.Ua.IdType.Numeric => prefix + "i=" + ((uint)n.Identifier).ToString(Inv.C),
                Opc.Ua.IdType.String => prefix + "s=" + (string)n.Identifier,
                Opc.Ua.IdType.Guid => prefix + "g=" + n.Identifier.ToString().ToLowerInvariant(),
                Opc.Ua.IdType.Opaque => prefix + "b=" + Convert.ToBase64String((byte[])n.Identifier),
                _ => n.ToString()
            };
        }
    }
}
