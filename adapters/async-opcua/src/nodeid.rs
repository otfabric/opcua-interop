//! NodeId canonical string form (CONTAINER_CONTRACT §6) and input parsing (§8).

use base64::Engine;
use opcua::types::{ByteString, ExpandedNodeId, Guid, Identifier, NodeId, UAString};
use std::str::FromStr;

pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("invalid base64 '{s}': {e}"))
}

fn identifier_str(id: &Identifier) -> String {
    match id {
        Identifier::Numeric(n) => format!("i={n}"),
        Identifier::String(s) => format!("s={}", s.as_ref()),
        Identifier::Guid(g) => format!("g={}", g.to_string().to_lowercase()),
        Identifier::ByteString(b) => format!("b={}", b64(b.value.as_deref().unwrap_or(&[]))),
    }
}

/// Canonical compact form: `i=85`, `ns=2;i=1`, `ns=1;s=x`, `ns=1;g=…`, `ns=1;b=…`.
pub fn fmt_node_id(id: &NodeId) -> String {
    if id.namespace == 0 {
        identifier_str(&id.identifier)
    } else {
        format!("ns={};{}", id.namespace, identifier_str(&id.identifier))
    }
}

/// `[svr=<n>;][nsu=<uri>;|ns=<n>;]<i|s|g|b>=<id>`
pub fn fmt_expanded_node_id(id: &ExpandedNodeId) -> String {
    let mut out = String::new();
    if id.server_index != 0 {
        out.push_str(&format!("svr={};", id.server_index));
    }
    if !id.namespace_uri.is_null() && !id.namespace_uri.as_ref().is_empty() {
        out.push_str(&format!("nsu={};", id.namespace_uri.as_ref()));
        out.push_str(&identifier_str(&id.node_id.identifier));
    } else {
        out.push_str(&fmt_node_id(&id.node_id));
    }
    out
}

/// Namespace part of a parsed NodeId.
#[derive(Debug, Clone)]
pub enum Ns {
    Index(u16),
    Uri(String),
}

/// A NodeId as given on the command line, before namespace URIs are resolved.
#[derive(Debug, Clone)]
pub struct NodeRef {
    pub ns: Ns,
    pub identifier: Identifier,
    pub text: String,
}

fn parse_identifier(s: &str) -> Result<Identifier, String> {
    if let Some(v) = s.strip_prefix("i=") {
        v.parse::<u32>()
            .map(Identifier::Numeric)
            .map_err(|_| format!("malformed numeric identifier '{v}'"))
    } else if let Some(v) = s.strip_prefix("s=") {
        Ok(Identifier::String(UAString::from(v)))
    } else if let Some(v) = s.strip_prefix("g=") {
        Guid::from_str(v)
            .map(Identifier::Guid)
            .map_err(|_| format!("malformed GUID identifier '{v}'"))
    } else if let Some(v) = s.strip_prefix("b=") {
        Ok(Identifier::ByteString(ByteString::from(b64_decode(v)?)))
    } else {
        Err(format!("malformed identifier '{s}'"))
    }
}

/// Parse `i=N`, `s=x`, `ns=N;<id>`, `nsu=URI;<id>`.
pub fn parse_node_ref(s: &str) -> Result<NodeRef, String> {
    let text = s.to_owned();
    let bad = |why: String| format!("malformed NodeId: '{s}' ({why})");
    if let Some(rest) = s.strip_prefix("nsu=") {
        // The URI itself may contain ';' only in theory; split at the last ";x=" marker.
        let pos = find_identifier_sep(rest).ok_or_else(|| bad("missing identifier".into()))?;
        let uri = &rest[..pos];
        if uri.is_empty() {
            return Err(bad("empty namespace URI".into()));
        }
        let identifier = parse_identifier(&rest[pos + 1..]).map_err(bad)?;
        return Ok(NodeRef {
            ns: Ns::Uri(uri.to_owned()),
            identifier,
            text,
        });
    }
    if let Some(rest) = s.strip_prefix("ns=") {
        let (idx, id) = rest
            .split_once(';')
            .ok_or_else(|| bad("missing identifier".into()))?;
        let idx: u16 = idx
            .parse()
            .map_err(|_| bad(format!("bad namespace index '{idx}'")))?;
        let identifier = parse_identifier(id).map_err(bad)?;
        return Ok(NodeRef {
            ns: Ns::Index(idx),
            identifier,
            text,
        });
    }
    let identifier = parse_identifier(s).map_err(bad)?;
    Ok(NodeRef {
        ns: Ns::Index(0),
        identifier,
        text,
    })
}

fn find_identifier_sep(rest: &str) -> Option<usize> {
    for marker in [";i=", ";s=", ";g=", ";b="] {
        if let Some(p) = rest.find(marker) {
            return Some(p);
        }
    }
    None
}

/// Parse a NodeId that must not use `nsu=` (value literals).
pub fn parse_node_id_literal(s: &str) -> Result<NodeId, String> {
    let r = parse_node_ref(s)?;
    match r.ns {
        Ns::Index(i) => Ok(NodeId {
            namespace: i,
            identifier: r.identifier,
        }),
        Ns::Uri(_) => Err(format!("nsu= is not allowed in a NodeId literal: '{s}'")),
    }
}

/// Parse an ExpandedNodeId literal `[svr=<n>;][nsu=<uri>;|ns=<n>;]<id>`.
pub fn parse_expanded_node_id(s: &str) -> Result<ExpandedNodeId, String> {
    let mut rest = s;
    let mut server_index = 0u32;
    if let Some(r) = rest.strip_prefix("svr=") {
        let (n, tail) = r
            .split_once(';')
            .ok_or_else(|| format!("malformed ExpandedNodeId '{s}'"))?;
        server_index = n
            .parse()
            .map_err(|_| format!("malformed server index in '{s}'"))?;
        rest = tail;
    }
    let r = parse_node_ref(rest)?;
    let (namespace, namespace_uri) = match r.ns {
        Ns::Index(i) => (i, UAString::null()),
        Ns::Uri(u) => (0, UAString::from(u)),
    };
    Ok(ExpandedNodeId {
        node_id: NodeId {
            namespace,
            identifier: r.identifier,
        },
        namespace_uri,
        server_index,
    })
}

/// Resolve a parsed NodeId against the server's NamespaceArray.
pub fn resolve(r: &NodeRef, namespaces: &[String]) -> Result<NodeId, String> {
    let namespace = match &r.ns {
        Ns::Index(i) => *i,
        Ns::Uri(u) => namespaces
            .iter()
            .position(|n| n == u)
            .map(|p| p as u16)
            .ok_or_else(|| format!("unknown namespace URI '{u}' in '{}'", r.text))?,
    };
    Ok(NodeId {
        namespace,
        identifier: r.identifier.clone(),
    })
}

pub fn needs_namespaces(refs: &[&NodeRef]) -> bool {
    refs.iter().any(|r| matches!(r.ns, Ns::Uri(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_canonical_node_ids() {
        assert_eq!(fmt_node_id(&NodeId::new(0, 85u32)), "i=85");
        assert_eq!(fmt_node_id(&NodeId::new(2, 1u32)), "ns=2;i=1");
        assert_eq!(fmt_node_id(&NodeId::new(1, "Scalar.Int32")), "ns=1;s=Scalar.Int32");
        let g = Guid::from_str("72962B91-FA75-4AE6-8D28-B404DC7DAF63").unwrap();
        assert_eq!(fmt_node_id(&NodeId::new(3, g)), "ns=3;g=72962b91-fa75-4ae6-8d28-b404dc7daf63");
        let b = NodeId::new(1, ByteString::from(vec![1u8, 2, 3]));
        assert_eq!(fmt_node_id(&b), "ns=1;b=AQID");
    }

    #[test]
    fn parses_every_identifier_form() {
        for s in [
            "i=85",
            "ns=2;i=1",
            "ns=1;s=Scalar.Int32",
            "ns=3;g=72962b91-fa75-4ae6-8d28-b404dc7daf63",
            "ns=1;b=AQID",
        ] {
            let id = parse_node_id_literal(s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(fmt_node_id(&id), s, "round trip of {s}");
        }
    }

    #[test]
    fn string_identifier_may_contain_separators() {
        let r = parse_node_ref("ns=1;s=a;b=c").unwrap();
        assert_eq!(r.identifier, Identifier::String(UAString::from("a;b=c")));
    }

    #[test]
    fn namespace_uri_is_resolved_against_the_namespace_array() {
        let r = parse_node_ref("nsu=urn:otfabric:opcua-interop:model;s=Scalar.Int32").unwrap();
        assert!(matches!(&r.ns, Ns::Uri(u) if u == "urn:otfabric:opcua-interop:model"));
        assert!(needs_namespaces(&[&r]));
        let ns = vec![
            "http://opcfoundation.org/UA/".to_owned(),
            "urn:server".to_owned(),
            "urn:otfabric:opcua-interop:model".to_owned(),
        ];
        assert_eq!(fmt_node_id(&resolve(&r, &ns).unwrap()), "ns=2;s=Scalar.Int32");
        assert!(resolve(&r, &ns[..2]).is_err(), "unknown URI must not resolve");
        assert!(parse_node_id_literal("nsu=urn:x;i=1").is_err(), "nsu= is not a NodeId literal");
    }

    #[test]
    fn rejects_malformed_node_ids() {
        for s in ["", "x=1", "i=abc", "ns=;i=1", "ns=70000;i=1", "ns=1", "g=not-a-guid", "nsu=;i=1", "b=%%%"] {
            assert!(parse_node_ref(s).is_err(), "{s:?} must be rejected");
        }
    }

    #[test]
    fn expanded_node_ids_round_trip() {
        for s in ["svr=1;nsu=urn:x;s=y", "nsu=urn:x;i=5", "ns=2;s=z", "i=85"] {
            let id = parse_expanded_node_id(s).unwrap_or_else(|e| panic!("{s}: {e}"));
            assert_eq!(fmt_expanded_node_id(&id), s);
        }
    }

    #[test]
    fn base64_round_trip() {
        assert_eq!(b64_decode(&b64(&[0, 255, 7])).unwrap(), vec![0, 255, 7]);
        assert!(b64_decode("@@").is_err());
    }
}
