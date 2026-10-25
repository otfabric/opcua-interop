"""`test` subcommand (`make test-asyncua`, `docker run <image> test`): the
capability document against the dispatched operations, and every fixture
mounted under /fixtures loaded and built into an asyncua address space (the
server is initialised, not started). The adapter's unit tests (tests/) run in
the image build."""

from __future__ import annotations

import asyncio
import glob
import sys

from asyncua import Server, ua

from . import capabilities, client, common, fixture


async def check_fixture(path: str) -> list[str]:
    """Problems of one fixture: invalid, or a node the server cannot build or
    does not serve with the fixture's value."""
    try:
        data = fixture.load(path)
    except Exception as e:  # noqa: BLE001
        return [f"{path}: invalid: {e}"]
    srv = Server()
    await srv.init()
    history = fixture.History(srv)
    srv.iserver.history_manager.set_storage(history)
    space = fixture.AddressSpaceBuilder(srv, data, history)
    try:
        await space.build()
    except Exception as e:  # noqa: BLE001
        return [f"{path}: cannot build the address space: {e}"]
    problems = []
    if space.history_events is not None:
        evs, _ = await history.read_event_history(space.history_events, fixture.history_event(space.history_events, 0).Time,
                                                  fixture.history_event(space.history_events, 4).Time, 0, ua.EventFilter())
        if [bytes(e.EventId) for e in evs] != [f"hist-evt-{i}".encode() for i in range(5)]:
            problems.append(f"{path}: History.Events does not hold the five seed events")
    for nd in data["nodes"]:
        nid = space.nodes.get(nd["nodeId"])
        if nid is None:
            problems.append(f"{path}: {nd['nodeId']} not created")
            continue
        if nd["nodeClass"] != "Variable" or "CurrentRead" not in nd.get("accessLevel", ["CurrentRead"]):
            continue
        if "initialValue" not in nd:
            continue
        want = fixture.build_variant(nd["initialValue"], nd["dataType"], int(nd.get("valueRank", -1)), nd.get("arrayDimensions"))
        got = srv.read_attribute_value(nid).Value
        if common.variant_value(got) != common.variant_value(want) and nd["nodeId"].split(";s=")[-1] not in (
            "Diagnostics.AdapterName",
            "Diagnostics.StackVersion",
        ):
            problems.append(f"{path}: {nd['nodeId']} = {common.variant_value(got)!r}, fixture {common.variant_value(want)!r}")
    return problems


def run() -> int:
    problems = []
    caps = capabilities.capabilities()
    if set(caps["clientOperations"]) != set(client.COMMANDS):
        problems.append(f"clientOperations {caps['clientOperations']} != dispatched {sorted(client.COMMANDS)}")
    if "codec" in caps["clientOperations"]:
        problems.append("codec is declared but not implemented")
    if common.status_json(ua.StatusCodes.BadNodeIdUnknown)["name"] != "BadNodeIdUnknown":
        problems.append("status code names")

    paths = sorted(glob.glob("/fixtures/*/fixture.json") + glob.glob("/fixtures/*.json"))
    for path in paths:
        problems.extend(asyncio.run(check_fixture(path)))
    for p in problems:
        print(f"[asyncua] self-test FAIL {p}", file=sys.stderr)
    if problems:
        print(f"[asyncua] self-test: {len(problems)} failure(s)", file=sys.stderr)
        return 1
    print(f"[asyncua] self-test: OK ({len(paths)} fixture(s))", file=sys.stderr)
    return 0
