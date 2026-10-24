"""The server built from testdata/fixture.json, in process, and the adapter
client against it: ready file, fixture nodes, write-only node, method
validation, EURange, history, SIGTERM -> exit 0. Readiness is polled (the
ready file, the server's own condition), never waited for by a fixed delay."""

import asyncio
import contextlib
import io
import json
import logging
import os
import signal
import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from asyncua import Client, ua

from opcua_interop_asyncua import client as adapter_client
from opcua_interop_asyncua import fixture, selftest, server

logging.disable(logging.WARNING)

FIXTURE = Path(__file__).resolve().parent.parent / "testdata" / "fixture.json"
MODEL = "nsu=urn:otfabric:opcua-interop:model;s="
READY_TIMEOUT = 30.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def wait_for(cond, what: str, timeout: float = READY_TIMEOUT):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.05)


async def client_op(op, *argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = await adapter_client.run_async(op, list(argv))
    return rc, json.loads([line for line in out.getvalue().splitlines() if line.startswith("{")][-1])


class ServerTest(unittest.IsolatedAsyncioTestCase):
    async def test_server_serves_the_fixture_and_stops_on_sigterm(self):
        port = free_port()
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "ready"
            endpoint = f"opc.tcp://127.0.0.1:{port}/opcua-interop"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                task = asyncio.create_task(server.run([
                    "--fixture", str(FIXTURE), "--bind-address", "127.0.0.1", "--bind-port", str(port),
                    "--advertised-host", "127.0.0.1", "--endpoint-path", "/opcua-interop",
                    "--pki-dir", str(Path(tmp) / "pki"), "--ready-file", str(ready),
                ]))
                await wait_for(lambda: ready.exists() or task.done(), "the ready file")
                self.assertFalse(task.done(), stderr.getvalue())
                info = json.loads(ready.read_text())
                self.assertEqual(info, {"ready": True, "adapter": "asyncua", "fixture": "unit", "endpoint": endpoint})

                await self.check_address_space(endpoint)
                await self.check_adapter_client(endpoint)

                os.kill(os.getpid(), signal.SIGTERM)
                rc = await asyncio.wait_for(task, 30)
            self.assertEqual(rc, 0)
            self.assertFalse(ready.exists(), "the ready file is removed on shutdown")

    async def check_address_space(self, endpoint):
        async with Client(endpoint, timeout=10) as c:
            ns = await c.get_namespace_index("urn:otfabric:opcua-interop:model")

            def node(name):
                return c.get_node(ua.NodeId(name, ns, ua.NodeIdType.String))

            self.assertEqual(await node("Scalar.Int32").read_value(), -123456789)
            self.assertEqual(await node("Array.Int32").read_value(), [1, 2, 3])

            # Access.WriteOnly: written values are accepted, reads are refused.
            await node("Access.WriteOnly").write_value(ua.Variant(7, ua.VariantType.Int32))
            dv = await node("Access.WriteOnly").read_attribute(ua.AttributeIds.Value, raise_on_bad_status=False)
            self.assertEqual(dv.StatusCode.value, ua.StatusCodes.BadNotReadable)

            eu = await node("Analog.Level").get_child([ua.QualifiedName("EURange", 0)])
            rng = await eu.read_value()
            self.assertEqual((rng.Low, rng.High), (0.0, 100.0))

            # The counter behaviour runs: poll for a value change.
            first = await node("Dynamic.Counter").read_value()
            last = first
            loop = asyncio.get_running_loop()
            deadline = loop.time() + READY_TIMEOUT
            while last == first and loop.time() < deadline:
                await asyncio.sleep(0.05)
                last = await node("Dynamic.Counter").read_value()
            self.assertGreater(last, first)

            start = datetime(2026, 7, 24, 10, 0, 0, tzinfo=timezone.utc)
            hist = await node("History.Temperature").read_raw_history(start, start + timedelta(seconds=30))
            self.assertEqual([dv.Value.Value for dv in hist], [20.0, 21.0, 22.0, 23.0, 24.0])

            methods = node("Methods")
            add = node("Methods.Add")
            self.assertEqual(await methods.call_method(add, ua.Variant(10, ua.VariantType.Int32), ua.Variant(20, ua.VariantType.Int32)), 30)
            with self.assertRaises(ua.UaStatusCodeError) as ctx:
                await methods.call_method(add, ua.Variant(10, ua.VariantType.Int32))
            self.assertEqual(ctx.exception.code, ua.StatusCodes.BadArgumentsMissing)

    async def check_adapter_client(self, endpoint):
        rc, out = await client_op("read", "--endpoint", endpoint, "--node", MODEL + "Scalar.Int32")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["results"][0]["value"], -123456789)
        self.assertEqual(out["results"][0]["nodeId"].split(";")[1], "s=Scalar.Int32")

        rc, out = await client_op("read", "--endpoint", endpoint, "--node", MODEL + "Access.WriteOnly")
        self.assertEqual(out["results"][0]["statusCode"]["name"], "BadNotReadable", out)

        rc, out = await client_op("call", "--endpoint", endpoint, "--object", MODEL + "Methods",
                                  "--method", MODEL + "Methods.Add", "--input", "Int32:2", "--input", "Int32:3")
        self.assertEqual((rc, out["results"][0]["outputArguments"]), (0, [5]), out)

        rc, out = await client_op("read", "--endpoint", endpoint, "--node", "nsu=urn:unknown;s=x")
        self.assertEqual(rc, 2, out)
        self.assertEqual(out["error"]["category"], "input")

        rc, out = await client_op("read", "--endpoint", endpoint, "--node", MODEL + "Scalar.Int32",
                                  "--username", "test-user", "--password", "wrong")
        self.assertNotEqual(rc, 0, out)
        self.assertFalse(out["success"])
        rc, out = await client_op("read", "--endpoint", endpoint, "--node", MODEL + "Scalar.Int32",
                                  "--username", "test-user", "--password", "test-password")
        self.assertEqual(rc, 0, out)

    async def test_selftest_builds_the_fixture(self):
        # `test` builds the address space of every mounted fixture.
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(await selftest.check_fixture(str(FIXTURE)), [])

    async def test_invalid_fixture(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"schemaVersion": "1.0", "id": "x", "namespaces": [{"uri": "urn:x"}],
                       "nodes": [{"nodeClass": "Variable", "nodeId": "nsu=urn:x;s=a", "browseName": "1:a", "dataType": "Nope"}]}, f)
        try:
            with self.assertRaises(fixture.FixtureError):
                fixture.load(f.name)
        finally:
            os.unlink(f.name)


class ApplicationUriTest(unittest.TestCase):
    def test_flag_and_certificate(self):
        from opcua_interop_asyncua.common import Args

        conn = adapter_client.Conn(Args(["--endpoint", "opc.tcp://x:4840", "--application-uri", "urn:flag"]))
        self.assertEqual(conn.app_uri_flag, "urn:flag")
        conn = adapter_client.Conn(Args(["--endpoint", "opc.tcp://x:4840",
                                         "--certificate", str(FIXTURE.parent / "pki" / "leaf.crt"), "--private-key", "k"]))
        self.assertEqual(asyncio.run(conn._cert_uri()), "urn:otfabric:opcua-interop:test:leaf")


if __name__ == "__main__":
    unittest.main()
