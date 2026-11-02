"""`server` subcommand: an asyncua (opcua-asyncio) server exposing a fixture's
address space (docs/CONTAINER_CONTRACT.md §10, §11)."""

from __future__ import annotations

import asyncio
import json
import os
import signal
from datetime import datetime, timezone
from pathlib import Path

from asyncua import Server, ua
from asyncua.crypto.permission_rules import User, UserRole

from . import fixture as fx
from . import pki
from .common import ADAPTER, ADAPTER_VERSION, Args, file_format, log, stack_version

# Flags of §11 that asyncua cannot provide: refused (exit 2), never ignored.
_REFUSED = {
    "--reverse-connect": "reverse connect (ReverseHello) is not implemented by asyncua",
    "--reverse-connect-interval-ms": "reverse connect (ReverseHello) is not implemented by asyncua",
    "--lds": "asyncua has no mDNS / FindServersOnNetwork (LDS-ME); see README",
    "--lds-cleanup-timeout": "asyncua has no Local Discovery Server mode; see README",
    "--mdns-name": "asyncua has no mDNS support",
    "--mdns-capability": "asyncua has no mDNS support",
    "--pubsub-config": "the adapter does not wire asyncua's experimental PubSub; see README",
}

_POLICY_TYPES = {
    ("Basic128Rsa15", "Sign"): ua.SecurityPolicyType.Basic128Rsa15_Sign,
    ("Basic128Rsa15", "SignAndEncrypt"): ua.SecurityPolicyType.Basic128Rsa15_SignAndEncrypt,
    ("Basic256", "Sign"): ua.SecurityPolicyType.Basic256_Sign,
    ("Basic256", "SignAndEncrypt"): ua.SecurityPolicyType.Basic256_SignAndEncrypt,
    ("Basic256Sha256", "Sign"): ua.SecurityPolicyType.Basic256Sha256_Sign,
    ("Basic256Sha256", "SignAndEncrypt"): ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
    ("Aes128_Sha256_RsaOaep", "Sign"): ua.SecurityPolicyType.Aes128Sha256RsaOaep_Sign,
    ("Aes128_Sha256_RsaOaep", "SignAndEncrypt"): ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
    ("Aes256_Sha256_RsaPss", "Sign"): ua.SecurityPolicyType.Aes256Sha256RsaPss_Sign,
    ("Aes256_Sha256_RsaPss", "SignAndEncrypt"): ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
}


class FixtureUserManager:
    """Anonymous plus the fixture's username/password users. Every accepted
    identity gets asyncua's `User` role: Read/Write/Browse/Call/Subscribe…
    with AccessLevel enforced on Write. (asyncua's Admin role would bypass the
    AccessLevel checks and is the only role allowed to AddNodes/DeleteNodes.)"""

    def __init__(self, users: list[dict]):
        self.users = {u.get("username"): (u.get("password") or "") for u in users}

    def get_user(self, iserver, username=None, password=None, certificate=None):
        # `certificate` is the SecureChannel's client certificate (asyncua passes
        # it for every token type); X509 user tokens are not offered.
        if username is None:
            return User(role=UserRole.User)
        if username is not None and username in self.users and self.users[username] == (password or ""):
            return User(role=UserRole.User, name=username)
        return None


def _write_ready(path: str, fixture_id: str, endpoint: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps({"ready": True, "adapter": ADAPTER, "fixture": fixture_id, "endpoint": endpoint}) + "\n")
    os.replace(tmp, p)
    log(f"ready file written: {path}")


async def run(argv: list[str]) -> int:
    for a in argv:
        if a in _REFUSED:
            log(f"error: {a} is not supported: {_REFUSED[a]}")
            return 2
    args = Args(argv)
    if args.has("--ecc-dir"):
        log("warn: --ecc-dir ignored: asyncua has no ECC security policies")

    fixture_path = args.get("--fixture") or os.environ.get("OPCUA_FIXTURE")
    if not fixture_path:
        log("error: missing --fixture")
        return 1
    ready_file = args.get("--ready-file") or os.environ.get("OPCUA_READY_FILE") or "/run/opcua-interop/ready"
    try:
        Path(ready_file).unlink(missing_ok=True)
    except OSError:
        pass

    try:
        fixture = fx.load(fixture_path)
    except Exception as e:  # noqa: BLE001
        log(f"error: fixture {fixture_path}: {e}")
        return 5

    bind_address = args.get("--bind-address", "0.0.0.0")
    bind_port = args.int("--bind-port", int(fixture.get("endpoint", {}).get("port", 4840)))
    adv_host = args.get("--advertised-host", "localhost")
    adv_port = args.int("--advertised-port", bind_port)
    path = args.get("--endpoint-path") or fixture.get("endpoint", {}).get("path") or "/"
    advertised = f"opc.tcp://{adv_host}:{adv_port}{path}"
    pki_dir = args.get("--pki-dir", "/run/opcua-interop/pki")
    cert_file = args.get("--certificate")
    key_file = args.get("--private-key")
    register_with = args.get("--register-with")
    register_interval_ms = max(1000, args.int("--register-interval-ms", 30000))

    srv_meta = fixture.get("server", {})
    users = fixture.get("users", []) or []

    server = Server(user_manager=FixtureUserManager(users))
    server.name = srv_meta.get("applicationName", "opcua-interop asyncua server")
    server.product_uri = srv_meta.get("productUri", "urn:otfabric:opcua-interop")
    server.manufacturer_name = "OTFabric"
    await server.init()
    # Advertise exactly --advertised-host / --advertised-port (no per-client rewriting).
    server.set_match_discovery_endpoint_url(False)
    server.set_match_discovery_client_ip(False)
    server.set_endpoint(advertised)
    server.socket_address = (bind_address, bind_port)
    server.set_server_name(server.name)

    app_uri = srv_meta.get("applicationUri", "urn:otfabric:opcua-interop:server")
    have_cert = False
    if cert_file and key_file:
        try:
            await server.load_certificate(cert_file, format=file_format(cert_file))
            await server.load_private_key(key_file, format=file_format(key_file))
            app_uri = pki.application_uri(pki.load_certificate(cert_file)) or app_uri
            have_cert = True
            log(f"server certificate loaded from {cert_file}")
        except Exception as e:  # noqa: BLE001
            log(f"FATAL: cannot load server certificate or key: {e}")
            return 6
    await server.set_application_uri(app_uri)
    await server.set_build_info(
        server.product_uri, "OTFabric", "opcua-interop-asyncua", ADAPTER_VERSION, stack_version(), datetime.now(timezone.utc)
    )

    policies = [ua.SecurityPolicyType.NoSecurity]
    if have_cert:
        for sp in fixture.get("securityProfiles", []) or []:
            key = (sp.get("securityPolicy"), sp.get("securityMode"))
            if key == ("None", "None"):
                continue
            pt = _POLICY_TYPES.get(key)
            if pt is None:
                log(f"info: skipping security profile {key[0]}/{key[1]}: not implemented by asyncua")
                continue
            if pt not in policies:
                policies.append(pt)
                log(f"registered secure endpoint: policy={key[0]} mode={key[1]}")
        server.set_certificate_validator(await pki.server_validator(pki_dir))
    server.set_security_policy(policies)

    tokens = [ua.AnonymousIdentityToken]
    if users:
        tokens.append(ua.UserNameIdentityToken)
    server.set_identity_tokens(tokens)

    history = fx.History(server)
    server.iserver.history_manager.set_storage(history)

    space = fx.AddressSpaceBuilder(server, fixture, history)
    await space.build()

    await server.start()
    log(f"server started on {bind_address}:{bind_port}, advertised {advertised}")
    await space.start_behaviors()

    try:
        _write_ready(ready_file, fixture.get("id", ""), advertised)
    except OSError as e:
        log(f"FATAL: cannot write ready file {ready_file}: {e}")
        await server.stop()
        return 6

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    reg_task = None
    if register_with:
        reg_task = asyncio.create_task(_register_loop(server, register_with, register_interval_ms))

    await stop.wait()
    log("shutdown signal received")
    if reg_task:
        reg_task.cancel()
        try:
            await asyncio.wait_for(server.unregister_from_discovery(register_with), 3)
            log(f"unregistered from {register_with}")
        except Exception as e:  # noqa: BLE001
            log(f"warn: unregistration from {register_with} failed: {e}")
    await space.stop_behaviors()
    try:
        await asyncio.wait_for(server.stop(), 5)
    except Exception as e:  # noqa: BLE001
        log(f"warn: error during shutdown: {e}")
    try:
        Path(ready_file).unlink(missing_ok=True)
    except OSError:
        pass
    return 0


async def _register_loop(server: Server, url: str, interval_ms: int) -> None:
    """--register-with: asyncua's own registration (Server.register_to_discovery,
    RegisterServer with IsOnline=true), repeated every interval."""
    while True:
        try:
            await asyncio.wait_for(server.register_to_discovery(url, period=0), 5)
            log(f"registered with {url} via RegisterServer")
        except Exception as e:  # noqa: BLE001
            log(f"warn: registration with {url} failed: {e!r}")
        await asyncio.sleep(interval_ms / 1000.0)
