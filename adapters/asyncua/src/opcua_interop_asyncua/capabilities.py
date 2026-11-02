"""`print-capabilities` (docs/CAPABILITIES.md). Lists only what the
adapter can do on top of asyncua; see README.md for everything left out and why."""

from __future__ import annotations

import json

from .client import OPERATIONS
from .common import ADAPTER, ADAPTER_VERSION, stack_version

# The profiles of the baseline fixture the server offers (with --certificate)
# and the client was run with against a consumer's server. asyncua also
# implements the deprecated Basic128Rsa15 / Basic256 and the Aes policies in
# Sign mode; nothing exercises them, so they are not declared.
SECURITY_PROFILES = [
    ("None", "None"),
    ("Basic256Sha256", "Sign"),
    ("Basic256Sha256", "SignAndEncrypt"),
    ("Aes128_Sha256_RsaOaep", "SignAndEncrypt"),
    ("Aes256_Sha256_RsaPss", "SignAndEncrypt"),
]


def capabilities() -> dict:
    return {
        "schemaVersion": "1.0",
        "adapter": {"name": ADAPTER, "version": ADAPTER_VERSION},
        "stack": {"name": "opcua-asyncio", "version": stack_version()},
        "fixtureSchemaVersions": ["1.0"],
        "roles": ["client", "server"],
        "transports": ["opc.tcp"],
        "encodings": ["binary"],
        "clientOperations": list(OPERATIONS),
        # channel-lifetime: Client.secure_channel_timeout + asyncua's renew loop (75 %).
        # deadband: the client sends DataChangeFilters (absolute / percent / trigger).
        # application-uri: --application-uri, else the URI SAN of --certificate.
        # register-server2: `register-server` calls RegisterServer2 (fallback RegisterServer).
        # push-groups / push-certificates / push-transaction-diagnostics: the
        # `client push` flags of adapter 0.15.0 (§1 "push flags", §15), plain
        # Calls / Reads on the standard ServerConfiguration NodeIds.
        # Not listed: reverse-listen (no ReverseHello), ECC (no ECC policies),
        # codec-* (no JSON / XML DataEncoding).
        "clientFeatures": [
            "channel-lifetime",
            "deadband",
            "application-uri",
            "register-server2",
            "push-groups",
            "push-certificates",
            "push-transaction-diagnostics",
        ],
        # register-with: Server.register_to_discovery (RegisterServer). Not listed:
        # deadband / percent-deadband (asyncua compares the absolute deadband with the
        # previous *sample* instead of the last reported value and ignores percent
        # deadbands), node-management (AddNodes/DeleteNodes need asyncua's Admin role,
        # which also bypasses AccessLevel checks), lds / mdns, reverse-connect, ECC, pubsub.
        # history-events: History.Events with its five seed events (fixture.History:
        # asyncua's HistoryDict with the WhereClause and NumValuesPerNode paging
        # added). Not history-events-update: asyncua has no HistoryUpdate.
        "serverFeatures": ["register-with", "history-events"],
        "pubsub": {
            "supported": False,
            "reason": "asyncua's PubSub (UADP over UDP, experimental) is not wired to the adapter: "
            "no --pubsub-config / codec pubsub-* implementation (see README)",
            "transports": [],
            "encodings": [],
            "roles": [],
            "securityPolicies": [],
            "sks": {"server": False, "pull": False, "push": False},
            "informationModel": False,
            "codecOps": [],
        },
        "serverServices": [
            "GetEndpoints",
            "FindServers",
            "RegisterServer",
            "RegisterServer2",
            "Browse",
            "BrowseNext",
            "TranslateBrowsePathsToNodeIds",
            "RegisterNodes",
            "UnregisterNodes",
            "Read",
            "Write",
            "HistoryRead",
            "Call",
            "CreateSubscription",
            "ModifySubscription",
            "SetPublishingMode",
            "DeleteSubscriptions",
            "TransferSubscriptions",
            "Publish",
            "Republish",
            "CreateMonitoredItems",
            "ModifyMonitoredItems",
            "SetMonitoringMode",
            "DeleteMonitoredItems",
        ],
        "securityProfiles": [{"policy": p, "mode": m} for p, m in SECURITY_PROFILES],
        "userTokenTypes": ["Anonymous", "UserName"],
    }


def run() -> int:
    print(json.dumps(capabilities()))
    return 0
