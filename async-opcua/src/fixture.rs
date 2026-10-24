//! The fixture model (fixtures/schema/opcua-fixture.schema.json).

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixture {
    pub schema_version: String,
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    pub server: ServerDef,
    pub endpoint: EndpointDef,
    pub namespaces: Vec<NamespaceDef>,
    #[serde(default)]
    pub nodes: Vec<NodeDef>,
    #[serde(default)]
    pub behaviors: Vec<BehaviorDef>,
    #[serde(default)]
    pub users: Vec<UserDef>,
    #[serde(default)]
    pub security_profiles: Vec<SecurityProfileDef>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerDef {
    pub application_uri: String,
    pub product_uri: String,
    pub application_name: String,
}

#[derive(Debug, Deserialize)]
pub struct EndpointDef {
    pub path: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct NamespaceDef {
    pub alias: String,
    pub uri: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArgumentDef {
    pub name: String,
    pub data_type: String,
    #[serde(default = "minus_one")]
    pub value_rank: i32,
    #[serde(default)]
    pub description: Option<String>,
}

fn minus_one() -> i32 {
    -1
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EuRange {
    pub low: f64,
    pub high: f64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NodeDef {
    pub node_class: String,
    pub node_id: String,
    pub browse_name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub parent_node_id: String,
    pub reference_type: String,
    #[serde(default)]
    pub type_definition: Option<String>,
    #[serde(default)]
    pub data_type: Option<String>,
    #[serde(default)]
    pub value_rank: Option<i32>,
    #[serde(default)]
    pub array_dimensions: Option<Vec<u32>>,
    #[serde(default)]
    pub access_level: Option<Vec<String>>,
    #[serde(default)]
    pub initial_value: Option<Value>,
    #[serde(default)]
    pub method_behavior: Option<String>,
    #[serde(default)]
    pub input_arguments: Option<Vec<ArgumentDef>>,
    #[serde(default)]
    pub output_arguments: Option<Vec<ArgumentDef>>,
    #[serde(default)]
    pub eu_range: Option<EuRange>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorDef {
    pub target: String,
    pub kind: String,
    #[serde(default)]
    pub initial: Option<Value>,
    #[serde(default)]
    pub increment: Option<f64>,
    #[serde(default)]
    pub minimum: Option<f64>,
    #[serde(default)]
    pub maximum: Option<f64>,
    #[serde(default)]
    pub interval_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserDef {
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecurityProfileDef {
    pub security_policy: String,
    pub security_mode: String,
}

pub fn load(path: &str) -> Result<Fixture, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read fixture {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid fixture {path}: {e}"))
}

/// Structural problems of a fixture: missing identity, an unsupported schema
/// version, duplicate NodeIds.
pub fn problems(f: &Fixture) -> Vec<String> {
    let mut errors = Vec::new();
    if f.schema_version.is_empty() {
        errors.push("missing schemaVersion".into());
    } else if f.schema_version != "1.0" {
        errors.push(format!("unsupported schemaVersion {}", f.schema_version));
    }
    if f.id.is_empty() {
        errors.push("missing id".into());
    }
    if f.namespaces.is_empty() {
        errors.push("missing namespaces".into());
    }
    let mut seen = std::collections::HashSet::new();
    for n in &f.nodes {
        if !seen.insert(n.node_id.as_str()) {
            errors.push(format!("duplicate nodeId {}", n.node_id));
        }
    }
    errors
}

/// `validate-fixture --fixture <path>` / `validate-fixture <path>`.
pub fn validate_command(args: &[String]) -> i32 {
    let mut path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--fixture" && i + 1 < args.len() {
            path = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if path.is_none() && !args[i].starts_with("--") {
            path = Some(args[i].clone());
        }
        i += 1;
    }
    let Some(path) = path else {
        eprintln!("usage: validate-fixture --fixture <path>");
        return 1;
    };
    let errors = match load(&path) {
        Ok(f) => problems(&f),
        Err(e) => vec![e],
    };
    if errors.is_empty() {
        println!("{{\"valid\":true}}");
        0
    } else {
        println!(
            "{}",
            serde_json::json!({"valid": false, "errors": errors})
        );
        1
    }
}
