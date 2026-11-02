#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// opcua-interop adapter for node-opcua.
//
//   server              start an OPC UA server from a fixture
//   client <op> ...     run one client operation, print one JSON result
//   validate-fixture    validate a fixture file
//   print-capabilities  emit the capability JSON (§13)
//   test                internal self-test

import { capabilitiesCommand } from "./capabilities.js";
import { validateFixtureCommand } from "./fixture.js";

function usage(): void {
    process.stderr.write("usage: opcua-interop-node-opcua <server|client|validate-fixture|print-capabilities|test> [args...]\n");
}

async function main(): Promise<void> {
    // node-opcua logs through console.log as well; stdout carries exactly one
    // JSON object (§2), so everything else goes to stderr.
    console.log = (...args: unknown[]) => process.stderr.write(args.map(String).join(" ") + "\n");
    console.info = console.log;
    console.warn = (...args: unknown[]) => process.stderr.write(args.map(String).join(" ") + "\n");

    const [cmd, ...rest] = process.argv.slice(2);
    switch (cmd) {
        case "server": {
            const { serverCommand } = await import("./server.js");
            await serverCommand(rest);
            return; // keeps running until SIGTERM
        }
        case "client": {
            const { clientCommand } = await import("./client.js");
            const code = await clientCommand(rest);
            process.exitCode = code;
            // node-opcua may leave timers behind; the result is already written.
            setTimeout(() => process.exit(code), 50).unref();
            return;
        }
        case "validate-fixture":
            process.exit(validateFixtureCommand(rest));
            return;
        case "print-capabilities":
            process.exit(capabilitiesCommand());
            return;
        case "test": {
            const { selftestCommand } = await import("./selftest.js");
            process.exit(await selftestCommand(rest));
            return;
        }
        default:
            if (cmd) process.stderr.write(`unknown subcommand: ${cmd}\n`);
            usage();
            process.exit(1);
    }
}

main().catch((e) => {
    process.stderr.write(`[node-opcua] fatal: ${(e as Error)?.stack ?? e}\n`);
    process.exit(1);
});
