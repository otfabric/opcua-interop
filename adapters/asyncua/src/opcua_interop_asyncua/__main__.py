"""opcua-interop asyncua adapter: server | client | validate-fixture | print-capabilities | test."""

from __future__ import annotations

import asyncio
import logging
import os
import sys


def _usage() -> None:
    print("usage: opcua-interop-asyncua <server|client|validate-fixture|print-capabilities|test> [args...]", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    level = os.environ.get("OPCUA_INTEROP_LOG", "WARNING").upper()
    # Diagnostics go to stderr only; stdout carries exactly one JSON object.
    logging.basicConfig(stream=sys.stderr, level=getattr(logging, level, logging.WARNING), format="[asyncua] %(levelname)s %(name)s: %(message)s")
    if not argv:
        _usage()
        return 1
    cmd, rest = argv[0], argv[1:]
    if cmd == "server":
        from . import server

        try:
            return asyncio.run(server.run(rest))
        except Exception as e:  # noqa: BLE001
            import traceback

            traceback.print_exc()
            print(f"[asyncua] fatal: {e}", file=sys.stderr)
            return 1
    if cmd == "client":
        from . import client

        return client.run(rest)
    if cmd == "print-capabilities":
        from . import capabilities

        return capabilities.run()
    if cmd == "validate-fixture":
        from . import fixture

        path = rest[rest.index("--fixture") + 1] if "--fixture" in rest[:-1] else (rest[0] if rest else None)
        if not path:
            print("usage: validate-fixture --fixture <path>", file=sys.stderr)
            return 2
        try:
            fixture.load(path)
        except Exception as e:  # noqa: BLE001
            print(f"[asyncua] fixture {path} invalid: {e}", file=sys.stderr)
            return 5
        print(f"[asyncua] fixture {path} OK", file=sys.stderr)
        return 0
    if cmd == "test":
        from . import selftest

        return selftest.run()
    print(f"unknown subcommand: {cmd}", file=sys.stderr)
    _usage()
    return 1


if __name__ == "__main__":
    sys.exit(main())
