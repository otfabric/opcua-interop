//! `print-capabilities` (CLIENT_CONTRACT §13).

use serde_json::json;

use crate::common::{ADAPTER, ADAPTER_VERSION, STACK_VERSION};

/// The print-capabilities document.
pub fn document() -> serde_json::Value {
    // The profiles verified on both sides (the baseline fixture's RSA
    // profiles). The stack also implements Basic128Rsa15 / Basic256 and the
    // Sign mode of the Aes policies; the adapter accepts them, but they are
    // not part of the fixture and not claimed here.
    let profiles = [
        ("None", "None"),
        ("Basic256Sha256", "Sign"),
        ("Basic256Sha256", "SignAndEncrypt"),
        ("Aes128_Sha256_RsaOaep", "SignAndEncrypt"),
        ("Aes256_Sha256_RsaPss", "SignAndEncrypt"),
    ];
    json!({
        "schemaVersion": "1.0",
        "adapter": {"name": ADAPTER, "version": ADAPTER_VERSION},
        "stack": {"name": "async-opcua", "version": STACK_VERSION},
        "fixtureSchemaVersions": ["1.0"],
        "roles": ["client", "server"],
        "transports": ["opc.tcp"],
        "encodings": ["binary"],
        "clientOperations": crate::client::OPERATIONS.iter().chain(["find-servers-on-network"].iter()).collect::<Vec<_>>(),
        "clientFeatures": ["channel-lifetime", "deadband", "reverse-listen", "application-uri", "register-server2"],
        "serverFeatures": ["deadband", "percent-deadband", "reverse-connect", "register-with", "node-management"],
        "pubsub": {
            "supported": false,
            "reason": "async-opcua 0.19 has no PubSub (Part 14) implementation",
            "transports": [], "encodings": [], "roles": [], "securityPolicies": [],
            "sks": {"server": false, "pull": false, "push": false},
            "informationModel": false,
            "codecOps": []
        },
        "serverServices": [
            "GetEndpoints", "FindServers", "Browse", "BrowseNext", "TranslateBrowsePathsToNodeIds",
            "RegisterNodes", "UnregisterNodes", "Read", "Write", "HistoryRead", "Call",
            "CreateSubscription", "ModifySubscription", "SetPublishingMode", "DeleteSubscriptions",
            "TransferSubscriptions", "Publish", "Republish", "CreateMonitoredItems",
            "ModifyMonitoredItems", "SetMonitoringMode", "SetTriggering", "DeleteMonitoredItems",
            "AddNodes", "DeleteNodes"
        ],
        "securityProfiles": profiles.iter().map(|(p, m)| json!({"policy": p, "mode": m})).collect::<Vec<_>>(),
        "userTokenTypes": ["Anonymous", "UserName"],
    })
}

pub fn run() -> i32 {
    println!("{}", document());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_what_is_not_provided() {
        let c = document();
        assert_eq!(c["adapter"]["name"], json!(ADAPTER));
        assert_eq!(c["stack"]["version"], json!(STACK_VERSION));
        let ops = c["clientOperations"].as_array().unwrap();
        assert!(!ops.contains(&json!("codec")), "no codec operation");
        assert!(ops.contains(&json!("find-servers-on-network")));
        assert!(ops.contains(&json!("alarms")), "client alarms operation");
        let server: Vec<&str> = c["serverFeatures"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(!server.contains(&"alarms"), "async-opcua 0.19 has no A&C server");
        assert_eq!(c["pubsub"]["supported"], json!(false));
        assert!(c.get("codec").is_none());
        let features: Vec<&str> = c["clientFeatures"].as_array().unwrap().iter().chain(c["serverFeatures"].as_array().unwrap()).map(|v| v.as_str().unwrap()).collect();
        for f in ["ecc-security", "ecc-user-token", "lds", "mdns", "pubsub", "codec-json", "codec-xml"] {
            assert!(!features.contains(&f), "{f} must not be declared");
        }
        for p in c["securityProfiles"].as_array().unwrap() {
            assert!(!p["policy"].as_str().unwrap().starts_with("ECC_"));
        }
    }
}
