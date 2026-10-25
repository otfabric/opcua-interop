//! Helpers shared by `client push` (Part 12 §7) and `client gds-pull`
//! (Part 12 §6, §7.9): plain method calls, the TrustList file of a
//! certificate group (FileType / TrustListType methods) and variant helpers.

use std::io::Cursor;

use opcua::types::{
    Array, BinaryDecodable, BrowsePath, ByteString, CallMethodRequest, ContextOwned,
    DecodingOptions, NamespaceMap, NodeId, QualifiedName, ReferenceTypeId, RelativePath,
    RelativePathElement, StatusCode, TrustListDataType, UAString, Variant, VariantScalarTypeId,
};
use serde_json::{json, Value};

use super::Conn;
use crate::common::{is_timeout, is_transport, Failure};
use crate::nodeid::b64;

/// TrustListMasks All (Part 12 §7.8.2.7).
pub const TRUST_LIST_MASKS_ALL: u32 = 15;
/// FileType Open mode Read (Part 5 §C.2.1).
pub const FILE_MODE_READ: u8 = 1;
/// Bytes per FileType Read.
const READ_CHUNK: i32 = 4096;

/// The result of one CallMethodRequest: the status of the call (the service
/// result when the Call service failed) and the output arguments.
pub struct CallResult {
    pub status: StatusCode,
    pub outputs: Vec<Variant>,
}

/// Call one method. A transport or timeout failure of the Call service is
/// returned as Err (the command fails as a whole); any other status is the
/// status of the step.
pub async fn call(
    conn: &Conn,
    object: &NodeId,
    method: &NodeId,
    inputs: Vec<Variant>,
) -> Result<CallResult, Failure> {
    let req = CallMethodRequest {
        object_id: object.clone(),
        method_id: method.clone(),
        input_arguments: Some(inputs),
    };
    match conn.session.call(vec![req]).await {
        Ok(res) => Ok(match res.into_iter().next() {
            Some(r) => CallResult {
                status: r.status_code,
                outputs: r.output_arguments.unwrap_or_default(),
            },
            None => CallResult {
                status: StatusCode::BadUnexpectedError,
                outputs: Vec::new(),
            },
        }),
        Err(e) => {
            let sc = e.status();
            if is_transport(sc) || is_timeout(sc) {
                Err(Failure::from_status(sc, format!("Call {method}: {e}")))
            } else {
                Ok(CallResult {
                    status: sc,
                    outputs: Vec::new(),
                })
            }
        }
    }
}

/// Resolve the ns=0 browse paths `paths` (each a list of browse names) from
/// `start`. The first target of each path, or the status of the first path
/// that does not resolve.
pub async fn translate(
    conn: &Conn,
    start: &NodeId,
    paths: &[&[&str]],
) -> Result<Result<Vec<NodeId>, StatusCode>, Failure> {
    let bps: Vec<BrowsePath> = paths
        .iter()
        .map(|names| BrowsePath {
            starting_node: start.clone(),
            relative_path: RelativePath {
                elements: Some(
                    names
                        .iter()
                        .map(|n| RelativePathElement {
                            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                            is_inverse: false,
                            include_subtypes: true,
                            target_name: QualifiedName::new(0, *n),
                        })
                        .collect(),
                ),
            },
        })
        .collect();
    let res = match conn.session.translate_browse_paths_to_node_ids(&bps).await {
        Ok(r) => r,
        Err(e) => {
            let sc = e.status();
            if is_transport(sc) || is_timeout(sc) {
                return Err(Failure::from_status(sc, format!("TranslateBrowsePathsToNodeIds: {e}")));
            }
            return Ok(Err(sc));
        }
    };
    let mut out = Vec::new();
    for (i, r) in res.iter().enumerate() {
        let target = r.targets.iter().flatten().next();
        match target {
            Some(t) if r.status_code.is_good() => out.push(t.target_id.node_id.clone()),
            _ => {
                let sc = if r.status_code.is_good() {
                    StatusCode::BadNoMatch
                } else {
                    r.status_code
                };
                log::warn!("browse path {:?} from {start}: {sc}", paths.get(i));
                return Ok(Err(sc));
            }
        }
    }
    if out.len() != paths.len() {
        return Ok(Err(StatusCode::BadUnexpectedError));
    }
    Ok(Ok(out))
}

/// Read a TrustList file object: `Open` (or `OpenWithMasks` when `masks` is
/// set), `Read` until the server returns less than a chunk, `Close`; the
/// decoded TrustListDataType, or the status of the failing step.
pub async fn read_trust_list(
    conn: &Conn,
    trust_list: &NodeId,
    masks: Option<u32>,
) -> Result<Result<TrustListDataType, StatusCode>, Failure> {
    let open_name = if masks.is_some() { "OpenWithMasks" } else { "Open" };
    let ids = match translate(conn, trust_list, &[&[open_name], &["Read"], &["Close"]]).await? {
        Ok(ids) => ids,
        Err(sc) => return Ok(Err(sc)),
    };
    let open_in = match masks {
        Some(m) => vec![Variant::UInt32(m)],
        None => vec![Variant::Byte(FILE_MODE_READ)],
    };
    let r = call(conn, trust_list, &ids[0], open_in).await?;
    if !r.status.is_good() {
        return Ok(Err(r.status));
    }
    let Some(Variant::UInt32(handle)) = r.outputs.first().cloned() else {
        return Ok(Err(StatusCode::BadUnexpectedError));
    };
    let mut data: Vec<u8> = Vec::new();
    let mut failed = None;
    loop {
        let r = call(
            conn,
            trust_list,
            &ids[1],
            vec![Variant::UInt32(handle), Variant::Int32(READ_CHUNK)],
        )
        .await?;
        if !r.status.is_good() {
            failed = Some(r.status);
            break;
        }
        let chunk = match r.outputs.first() {
            Some(Variant::ByteString(b)) => b.value.clone().unwrap_or_default(),
            _ => Vec::new(),
        };
        let n = chunk.len();
        data.extend_from_slice(&chunk);
        if n < READ_CHUNK as usize {
            break;
        }
    }
    let close = call(conn, trust_list, &ids[2], vec![Variant::UInt32(handle)]).await?;
    if let Some(sc) = failed {
        return Ok(Err(sc));
    }
    if !close.status.is_good() {
        return Ok(Err(close.status));
    }
    Ok(decode_trust_list(&data).map_err(|e| {
        log::warn!("TrustList of {trust_list} does not decode: {e}");
        StatusCode::BadDecodingError
    }))
}

/// Decode the binary TrustListDataType of a TrustList file.
pub fn decode_trust_list(data: &[u8]) -> Result<TrustListDataType, String> {
    let ctx = ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::default());
    let mut c = Cursor::new(data);
    TrustListDataType::decode(&mut c, &ctx.context()).map_err(|e| e.to_string())
}

fn b64_list(l: &Option<Vec<ByteString>>) -> Value {
    Value::Array(
        l.iter()
            .flatten()
            .map(|b| json!(b64(b.value.as_deref().unwrap_or_default())))
            .collect(),
    )
}

/// The JSON of a TrustListDataType (CLIENT_CONTRACT §4 `push`, §16.2).
pub fn trust_list_json(tl: &TrustListDataType) -> Value {
    json!({
        "specifiedLists": tl.specified_lists,
        "trustedCertificates": b64_list(&tl.trusted_certificates),
        "trustedCrls": b64_list(&tl.trusted_crls),
        "issuerCertificates": b64_list(&tl.issuer_certificates),
        "issuerCrls": b64_list(&tl.issuer_crls),
    })
}

/// An array variant of `ty` (also when empty).
pub fn array(ty: VariantScalarTypeId, values: Vec<Variant>) -> Variant {
    match Array::new(ty, values) {
        Ok(a) => Variant::Array(Box::new(a)),
        Err(_) => Variant::Empty,
    }
}

pub fn string_array(values: &[String]) -> Variant {
    array(
        VariantScalarTypeId::String,
        values.iter().map(|s| Variant::String(UAString::from(s.as_str()))).collect(),
    )
}

pub fn byte_string_array(values: &[Vec<u8>]) -> Variant {
    array(
        VariantScalarTypeId::ByteString,
        values.iter().map(|b| Variant::ByteString(ByteString::from(b.clone()))).collect(),
    )
}

pub fn byte_string(b: &[u8]) -> Variant {
    Variant::ByteString(ByteString::from(b.to_vec()))
}

/// The elements of an array variant (empty for Empty / null).
pub fn elements(v: Option<&Variant>) -> Vec<Variant> {
    match v {
        Some(Variant::Array(a)) => a.values.clone(),
        _ => Vec::new(),
    }
}

/// The bytes of a ByteString variant (empty for null / not a ByteString).
pub fn bytes(v: Option<&Variant>) -> Vec<u8> {
    match v {
        Some(Variant::ByteString(b)) => b.value.clone().unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// A NodeId variant (also ExpandedNodeId).
pub fn node_id(v: Option<&Variant>) -> Option<NodeId> {
    match v {
        Some(Variant::NodeId(n)) => Some((**n).clone()),
        Some(Variant::ExpandedNodeId(n)) => Some(n.node_id.clone()),
        _ => None,
    }
}

/// Base64 of each ByteString element of an array variant.
pub fn b64_elements(v: Option<&Variant>) -> Value {
    Value::Array(
        elements(v)
            .iter()
            .map(|e| json!(b64(&bytes(Some(e)))))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua::types::BinaryEncodable;

    #[test]
    fn trust_list_round_trip() {
        let tl = TrustListDataType {
            specified_lists: 15,
            trusted_certificates: Some(vec![ByteString::from(vec![1u8, 2, 3])]),
            trusted_crls: Some(vec![]),
            issuer_certificates: None,
            issuer_crls: Some(vec![ByteString::from(vec![9u8])]),
        };
        let ctx = ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::default());
        let mut buf = Vec::new();
        tl.encode(&mut buf, &ctx.context()).unwrap();
        let got = decode_trust_list(&buf).unwrap();
        let j = trust_list_json(&got);
        assert_eq!(j["specifiedLists"], json!(15));
        assert_eq!(j["trustedCertificates"], json!(["AQID"]));
        assert_eq!(j["issuerCertificates"], json!([]));
        assert_eq!(j["issuerCrls"], json!(["CQ=="]));
        assert!(decode_trust_list(&[1, 2]).is_err());
    }

    #[test]
    fn variant_helpers() {
        let v = string_array(&[]);
        assert!(matches!(&v, Variant::Array(a) if a.values.is_empty() && a.value_type == VariantScalarTypeId::String));
        let v = byte_string_array(&[vec![1], vec![2]]);
        assert_eq!(b64_elements(Some(&v)), json!(["AQ==", "Ag=="]));
        assert_eq!(bytes(Some(&byte_string(&[7]))), vec![7]);
        assert!(elements(Some(&Variant::Empty)).is_empty());
        assert_eq!(node_id(Some(&Variant::from(NodeId::new(2, 5u32)))), Some(NodeId::new(2, 5u32)));
    }
}
