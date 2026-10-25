// SPDX-License-Identifier: MIT
//
// print-capabilities (docs/CLIENT_CONTRACT.md §13): what this image can do,
// reported honestly. Everything not listed is refused with exit 2.

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { ADAPTER, ADAPTER_VERSION, SCHEMA_VERSION } from "./util.js";

let cachedVersion: string | undefined;

export function stackVersion(): string {
    if (cachedVersion) return cachedVersion;
    try {
        const here = path.dirname(fileURLToPath(import.meta.url));
        const pkg = JSON.parse(fs.readFileSync(path.join(here, "..", "node_modules", "node-opcua", "package.json"), "utf8"));
        cachedVersion = String(pkg.version);
    } catch {
        cachedVersion = "unknown";
    }
    return cachedVersion;
}

export const CLIENT_OPERATIONS = [
    "endpoints",
    "find-servers",
    "read",
    "write",
    "browse",
    "translate",
    "call",
    "subscribe",
    "subscription-lifecycle",
    "event-subscribe",
    "history-read",
    "republish",
    "transfer-subscriptions",
    "register-nodes",
    "node-management",
    "find-servers-on-network",
    "register-server",
    "alarms",
];

export const CLIENT_FEATURES = ["channel-lifetime", "deadband", "register-server2", "reverse-listen", "application-uri"];

export const SERVER_FEATURES = ["deadband", "percent-deadband", "reverse-connect", "register-with", "alarms"];

export const SECURITY_PROFILES: { policy: string; mode: string }[] = [
    { policy: "None", mode: "None" },
    { policy: "Basic256Sha256", mode: "Sign" },
    { policy: "Basic256Sha256", mode: "SignAndEncrypt" },
    { policy: "Aes128_Sha256_RsaOaep", mode: "SignAndEncrypt" },
    { policy: "Aes256_Sha256_RsaPss", mode: "SignAndEncrypt" },
];

export function capabilitiesDocument() {
    return {
        schemaVersion: SCHEMA_VERSION,
        adapter: { name: ADAPTER, version: ADAPTER_VERSION },
        stack: { name: "node-opcua", version: stackVersion() },
        fixtureSchemaVersions: ["1.0"],
        roles: ["client", "server"],
        transports: ["opc.tcp"],
        encodings: ["binary"],
        clientOperations: CLIENT_OPERATIONS,
        clientFeatures: CLIENT_FEATURES,
        serverFeatures: SERVER_FEATURES,
        // No `codec`: the adapter does not implement `client codec` (§13 lists it as optional).
        pubsub: {
            supported: false,
            reason: "node-opcua has no open-source PubSub (Part 14) implementation; PubSub is a commercial Sterfive add-on",
            transports: [],
            encodings: [],
            roles: [],
            securityPolicies: [],
            sks: { server: false, pull: false, push: false },
            informationModel: false,
            codecOps: [],
        },
        serverServices: [
            "FindServers",
            "GetEndpoints",
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
            "Publish",
            "Republish",
            "TransferSubscriptions",
            "DeleteSubscriptions",
            "CreateMonitoredItems",
            "ModifyMonitoredItems",
            "SetMonitoringMode",
            "SetTriggering",
            "DeleteMonitoredItems",
        ],
        securityProfiles: SECURITY_PROFILES,
        userTokenTypes: ["Anonymous", "UserName"],
    };
}

export function capabilitiesCommand(): number {
    process.stdout.write(JSON.stringify(capabilitiesDocument()) + "\n");
    return 0;
}
