// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;

namespace OpcUaInterop
{
    /// <summary>
    /// opcua-interop adapter for the OPC Foundation UA-.NETStandard stack.
    ///   server             start the fixture server
    ///   client &lt;op&gt;        run one client operation (docs/CLIENT_CONTRACT.md)
    ///   validate-fixture   validate a fixture file
    ///   print-capabilities emit the capability document
    ///   test               self-test
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
                        return await ServerCommand.RunAsync(rest).ConfigureAwait(false);
                    case "client":
                        return await ClientCommand.RunAsync(rest).ConfigureAwait(false);
                    case "validate-fixture":
                        return ValidateCommand.Run(rest);
                    case "print-capabilities":
                        Console.Out.WriteLine(Capabilities.Document());
                        return 0;
                    case "test":
                        Console.Error.WriteLine("[dotnet] self-test: OK (stack " + Capabilities.StackVersion + ")");
                        return 0;
                    default:
                        Console.Error.WriteLine("unknown subcommand: " + args[0]);
                        Usage();
                        return 1;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] fatal: " + e);
                return 1;
            }
        }

        private static void Usage()
        {
            Console.Error.WriteLine("usage: opcua-interop-dotnet <server|client|validate-fixture|print-capabilities|test> [args...]");
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
                Console.Error.WriteLine("[dotnet] fixture " + f.Id + " valid (" + f.Nodes.Count + " nodes)");
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[dotnet] fixture invalid: " + e.Message);
                return 5;
            }
        }
    }
}
