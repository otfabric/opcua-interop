#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compares the upstream pin of one adapter with the latest upstream release.

    scripts/latest-upstream.py <adapter>

Prints key=value lines (the format of $GITHUB_OUTPUT):

    pin=<pinned release of the adapter's stack>
    latest=<latest stable upstream release>
    latest_sha=<empty: every stack is pinned by release>
    update=yes|no
    source=<where the latest release was looked up>

Pin locations and lookups:

    open62541    adapters/open62541/Dockerfile ARG OPEN62541_COMMIT   latest GitHub release
    milo         adapters/milo/pom.xml <milo.version>                 latest GitHub release
    async-opcua  adapters/async-opcua/Cargo.toml (=X.Y.Z)             crates.io max_stable_version
    dotnet       adapters/dotnet/Dockerfile ARG OPCUA_VERSION         newest stable NuGet release of Opc.Ua.Server
    dotnet-gds   adapters/dotnet-gds/Dockerfile ARG OPCUA_VERSION     newest stable NuGet release with both
                                                             Gds.Server and Gds.Client
    node-opcua   adapters/node-opcua/package.json (exact)             npm dist-tag latest
    asyncua      adapters/asyncua/requirements.in (asyncua==X.Y.Z)    PyPI (latest non-pre-release)

Nothing is modified. GITHUB_TOKEN, when set, authenticates the GitHub API calls.
"""

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = "opcua-interop latest-upstream (https://github.com/otfabric/opcua-interop)"


def fetch(url, headers=None):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT, "Accept": "application/json, */*",
                                                   **(headers or {})})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def github_latest(repository):
    """tag_name of the latest GitHub release (never a draft or pre-release)."""
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    return fetch(f"https://api.github.com/repos/{repository}/releases/latest", headers)["tag_name"]


def pinned(path, pattern):
    match = re.search(pattern, (ROOT / path).read_text(), re.M)
    if not match:
        raise SystemExit(f"could not read the pin from {path}")
    return match.group(1).strip()


def nuget_stable(package):
    versions = fetch(f"https://api.nuget.org/v3-flatcontainer/{package}/index.json")["versions"]
    return {v for v in versions if re.fullmatch(r"\d+\.\d+\.\d+(\.\d+)?", v)}


def newest(versions, what):
    if not versions:
        raise SystemExit(f"no stable {what} release found")
    return max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))


def open62541():
    pin = pinned("adapters/open62541/Dockerfile", r"^ARG OPEN62541_COMMIT=(.+)$")
    return pin, github_latest("open62541/open62541"), "GitHub release of open62541/open62541"


def milo():
    pin = pinned("adapters/milo/pom.xml", r"<milo\.version>([^<]+)</milo\.version>")
    return pin, github_latest("eclipse/milo").removeprefix("v"), "GitHub release of eclipse/milo"


def async_opcua():
    pin = pinned("adapters/async-opcua/Cargo.toml", r'^async-opcua = \{ version = "=([0-9.]+)"')
    latest = fetch("https://crates.io/api/v1/crates/async-opcua")["crate"]["max_stable_version"]
    return pin, latest, "crates.io"


def dotnet():
    pin = pinned("adapters/dotnet/Dockerfile", r"^ARG OPCUA_VERSION=(.+)$")
    latest = newest(nuget_stable("opcfoundation.netstandard.opc.ua.server"), "OPCFoundation.NetStandard.Opc.Ua.Server")
    return pin, latest, "nuget.org (Opc.Ua.Server)"


def dotnet_gds():
    # The GDS adapter follows the newest UA-.NETStandard release that has both GDS
    # packages (Gds.Server and Gds.Client; 1.5.x named them Gds.*.Common).
    pin = pinned("adapters/dotnet-gds/Dockerfile", r"^ARG OPCUA_VERSION=(.+)$")
    both = nuget_stable("opcfoundation.netstandard.opc.ua.gds.server") & \
        nuget_stable("opcfoundation.netstandard.opc.ua.gds.client")
    return pin, newest(both, "UA-.NETStandard GDS"), "nuget.org (Gds.Server + Gds.Client)"


def node_opcua():
    pin = json.loads((ROOT / "adapters/node-opcua/package.json").read_text())["dependencies"]["node-opcua"]
    return pin, fetch("https://registry.npmjs.org/node-opcua/latest")["version"], "npm"


def asyncua():
    pin = pinned("adapters/asyncua/requirements.in", r"^asyncua==([0-9.]+)$")
    # info.version is the latest release that is not a pre-release.
    return pin, fetch("https://pypi.org/pypi/asyncua/json")["info"]["version"], "PyPI"


RESOLVERS = {
    "open62541": open62541,
    "milo": milo,
    "async-opcua": async_opcua,
    "dotnet": dotnet,
    "dotnet-gds": dotnet_gds,
    "node-opcua": node_opcua,
    "asyncua": asyncua,
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in RESOLVERS:
        raise SystemExit(f"usage: latest-upstream.py {'|'.join(RESOLVERS)}")
    pin, latest, source = RESOLVERS[sys.argv[1]]()
    print(f"pin={pin}")
    print(f"latest={latest}")
    print("latest_sha=")
    print(f"update={'yes' if latest != pin else 'no'}")
    print(f"source={source}")


if __name__ == "__main__":
    main()
