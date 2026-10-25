//! `client query` (CLIENT_CONTRACT §1 "query flags", §4 `query`): the Query
//! service set (Part 4 §5.9). async-opcua 0.19's Session has no QueryFirst /
//! QueryNext, but both requests are in the core RequestMessage and the
//! session's secure channel is public: the requests are sent on it with the
//! header of the session (the authentication token of a session builder's
//! request header).

use opcua::client::services::Read;
use opcua::core::ResponseMessage;
use opcua::types::{
    ByteString, ContentFilter, ExpandedNodeId, NodeTypeDescription,
    QueryDataDescription, QueryDataSet, QueryFirstRequest, QueryNextRequest, RelativePath,
    RequestHeader, StatusCode, ViewDescription,
};
use serde_json::{json, Value};

use super::{connect, parse_ref, ConnectSpec, Conn, Opts};
use crate::common::{status_json, Category, Envelope, Failure};
use crate::nodeid::{b64, fmt_expanded_node_id, fmt_node_id, NodeRef};
use crate::values::variant_json;

/// AttributeIds by name (Part 3 §5.9 / Part 6 Annex A).
const ATTRIBUTES: [(&str, u32); 27] = [
    ("NodeId", 1),
    ("NodeClass", 2),
    ("BrowseName", 3),
    ("DisplayName", 4),
    ("Description", 5),
    ("WriteMask", 6),
    ("UserWriteMask", 7),
    ("IsAbstract", 8),
    ("Symmetric", 9),
    ("InverseName", 10),
    ("ContainsNoLoops", 11),
    ("EventNotifier", 12),
    ("Value", 13),
    ("DataType", 14),
    ("ValueRank", 15),
    ("ArrayDimensions", 16),
    ("AccessLevel", 17),
    ("UserAccessLevel", 18),
    ("MinimumSamplingInterval", 19),
    ("Historizing", 20),
    ("Executable", 21),
    ("UserExecutable", 22),
    ("DataTypeDefinition", 23),
    ("RolePermissions", 24),
    ("UserRolePermissions", 25),
    ("AccessRestrictions", 26),
    ("AccessLevelEx", 27),
];

/// `--data-to-return <relativePath>[#<attribute>]`: a RelativePath in the
/// text form of Part 4 Annex A.2 (empty: the node itself) and an AttributeId
/// by name or number (default Value). `#` is reserved in the path syntax
/// (`&#` escapes it), so the last unescaped `#` separates the attribute.
pub fn parse_data_to_return(spec: &str) -> Result<QueryDataDescription, Failure> {
    let chars: Vec<char> = spec.chars().collect();
    let mut cut = None;
    for i in (0..chars.len()).rev() {
        if chars[i] == '#' && (i == 0 || chars[i - 1] != '&') {
            cut = Some(i);
            break;
        }
    }
    let (path, attr): (String, String) = match cut {
        Some(i) => (chars[..i].iter().collect(), chars[i + 1..].iter().collect()),
        None => (spec.to_owned(), "Value".to_owned()),
    };
    let attribute_id = match attr.parse::<u32>() {
        Ok(n) => n,
        Err(_) => ATTRIBUTES
            .iter()
            .find(|(n, _)| *n == attr)
            .map(|(_, id)| *id)
            .ok_or_else(|| Failure::input(format!("--data-to-return {spec}: unknown attribute {attr}")))?,
    };
    let relative_path = if path.is_empty() {
        RelativePath { elements: Some(Vec::new()) }
    } else {
        RelativePath::try_from(path.as_str())
            .map_err(|e| Failure::input(format!("--data-to-return {spec}: invalid relative path: {e:?}")))?
    };
    Ok(QueryDataDescription {
        relative_path,
        attribute_id,
        index_range: Default::default(),
    })
}

struct QueryArgs {
    type_definition: NodeRef,
    include_subtypes: bool,
    data_to_return: Vec<QueryDataDescription>,
    max_data_sets: u32,
    max_references: u32,
    release: bool,
    max_next: u32,
}

impl QueryArgs {
    fn parse(opts: &Opts) -> Result<Self, Failure> {
        opts.required("--endpoint")?;
        Ok(Self {
            type_definition: parse_ref(opts.required("--type-definition")?)?,
            include_subtypes: opts.flag("--include-subtypes")?,
            data_to_return: opts
                .all("--data-to-return")
                .iter()
                .map(|s| parse_data_to_return(s))
                .collect::<Result<_, _>>()?,
            max_data_sets: opts.num::<u32>("--max-data-sets", 0)?,
            max_references: opts.num::<u32>("--max-references", 0)?,
            release: opts.flag("--release-continuation-point")?,
            max_next: opts.num::<u32>("--max-query-next", 100)?,
        })
    }
}

fn data_sets_json(sets: &Option<Vec<QueryDataSet>>) -> Vec<Value> {
    sets.iter()
        .flatten()
        .map(|ds| {
            let values: Vec<Value> = ds
                .values
                .iter()
                .flatten()
                .map(|v| {
                    let (dt, bit, val) = variant_json(v);
                    json!({"dataType": dt, "builtInType": bit, "value": val})
                })
                .collect();
            json!({
                "nodeId": fmt_expanded_node_id(&ds.node_id),
                "typeDefinitionNode": fmt_expanded_node_id(&ds.type_definition_node),
                "values": values,
            })
        })
        .collect()
}

fn cp_json(cp: &ByteString) -> Value {
    match &cp.value {
        Some(b) if !b.is_empty() => json!(b64(b)),
        _ => Value::Null,
    }
}

/// A request header of the session: its authentication token and a fresh
/// request handle.
fn session_header(conn: &Conn) -> RequestHeader {
    Read::new(&conn.session).header().clone()
}

/// The service result of a response (a ServiceFault or a failed send is the
/// status of the request).
fn service_result(r: &Result<ResponseMessage, opcua::types::Error>) -> StatusCode {
    match r {
        Ok(ResponseMessage::QueryFirst(q)) => q.response_header.service_result,
        Ok(ResponseMessage::QueryNext(q)) => q.response_header.service_result,
        Ok(ResponseMessage::ServiceFault(f)) => f.response_header.service_result,
        Ok(_) => StatusCode::BadUnknownResponse,
        Err(e) => e.status(),
    }
}

fn transport_failure(sc: StatusCode, what: &str) -> Option<Failure> {
    (crate::common::is_transport(sc) || crate::common::is_timeout(sc))
        .then(|| Failure::from_status(sc, format!("{what}: {sc}")))
}

pub async fn op_query(opts: &Opts) -> Envelope {
    let op = "query";
    let args = match QueryArgs::parse(opts) {
        Ok(a) => a,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let spec = match ConnectSpec::from_opts(opts) {
        Ok(s) => s,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let mut conn = match connect(&spec).await {
        Ok(c) => c,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let env = run(&mut conn, &args).await;
    conn.close().await;
    env
}

async fn run(conn: &mut Conn, a: &QueryArgs) -> Envelope {
    let op = "query";
    let type_id = match conn.resolve(&a.type_definition).await {
        Ok(t) => t,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let timeout = conn.request_timeout;
    let req = QueryFirstRequest {
        request_header: session_header(conn),
        view: ViewDescription::default(),
        node_types: Some(vec![NodeTypeDescription {
            type_definition_node: ExpandedNodeId::from(type_id.clone()),
            include_sub_types: a.include_subtypes,
            data_to_return: Some(a.data_to_return.clone()),
        }]),
        filter: ContentFilter { elements: Some(Vec::new()) },
        max_data_sets_to_return: a.max_data_sets,
        max_references_to_return: a.max_references,
    };
    let resp = conn.session.channel().send(req, timeout).await;
    let status = service_result(&resp);
    if let Some(f) = transport_failure(status, "QueryFirst") {
        return Envelope::new(op).fail(&f);
    }
    let first = match &resp {
        Ok(ResponseMessage::QueryFirst(q)) if status.is_good() => Some(q),
        _ => None,
    };
    let first_sets = first.map(|q| data_sets_json(&q.query_data_sets)).unwrap_or_default();
    let parsing: Vec<Value> = first
        .iter()
        .flat_map(|q| q.parsing_results.iter().flatten())
        .map(|p| {
            json!({
                "statusCode": status_json(p.status_code),
                "dataStatusCodes": p.data_status_codes.iter().flatten().map(|s| status_json(*s)).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut all = first_sets.clone();
    let mut next: Vec<Value> = Vec::new();
    let mut env = Envelope::new(op);
    let mut cp = first.map(|q| q.continuation_point.clone()).unwrap_or_default();
    let query_first = json!({
        "statusCode": status_json(status),
        "continuationPoint": cp_json(&cp),
        "parsingResults": parsing,
        "queryDataSets": first_sets,
    });
    let mut failure: Option<(StatusCode, &str)> = None;
    if first.is_none() {
        failure = Some((if status.is_good() { StatusCode::BadUnknownResponse } else { status }, "QueryFirst failed"));
    }
    while failure.is_none() && cp.value.as_ref().is_some_and(|b| !b.is_empty()) && (next.len() as u32) < a.max_next {
        let req = QueryNextRequest {
            request_header: session_header(conn),
            release_continuation_point: a.release,
            continuation_point: cp.clone(),
        };
        let resp = conn.session.channel().send(req, timeout).await;
        let status = service_result(&resp);
        if let Some(f) = transport_failure(status, "QueryNext") {
            return env.fail(&f);
        }
        let (sets, revised) = match &resp {
            Ok(ResponseMessage::QueryNext(q)) => (data_sets_json(&q.query_data_sets), q.revised_continuation_point.clone()),
            _ => (Vec::new(), ByteString::null()),
        };
        all.extend(sets.iter().cloned());
        next.push(json!({
            "statusCode": status_json(status),
            "releaseContinuationPoint": a.release,
            "revisedContinuationPoint": cp_json(&revised),
            "queryDataSets": sets,
        }));
        if !status.is_good() || !matches!(resp, Ok(ResponseMessage::QueryNext(_))) {
            failure = Some((if status.is_good() { StatusCode::BadUnknownResponse } else { status }, "QueryNext failed"));
            break;
        }
        if a.release {
            break;
        }
        cp = revised;
    }
    env.results.push(json!({
        "typeDefinitionNode": fmt_node_id(&type_id),
        "queryFirst": query_first,
        "queryNext": next,
        "queryDataSets": all,
    }));
    if let Some((sc, msg)) = failure {
        env.success = false;
        env.service_result = sc;
        env.error = Some((Category::Service, msg.to_owned()));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua::types::{NodeId, ReferenceTypeId};

    #[test]
    fn data_to_return() {
        let d = parse_data_to_return(".Serial").unwrap();
        assert_eq!(d.attribute_id, 13);
        let e = d.relative_path.elements.as_ref().unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].reference_type_id, NodeId::from(ReferenceTypeId::Aggregates));
        assert_eq!(e[0].target_name.name.as_ref(), "Serial");

        let d = parse_data_to_return("#BrowseName").unwrap();
        assert_eq!(d.attribute_id, 3);
        assert!(d.relative_path.elements.as_ref().unwrap().is_empty());

        let d = parse_data_to_return("/2:Name#4").unwrap();
        assert_eq!(d.attribute_id, 4);
        let e = d.relative_path.elements.as_ref().unwrap();
        assert_eq!(e[0].target_name.namespace_index, 2);
        assert_eq!(e[0].reference_type_id, NodeId::from(ReferenceTypeId::HierarchicalReferences));

        let d = parse_data_to_return("<HasProperty>1:A&#B#NodeId").unwrap();
        assert_eq!(d.attribute_id, 1);
        let e = d.relative_path.elements.as_ref().unwrap();
        assert_eq!(e[0].reference_type_id, NodeId::from(ReferenceTypeId::HasProperty));
        assert_eq!(e[0].target_name.name.as_ref(), "A#B");

        assert!(parse_data_to_return(".X#Nope").is_err());
    }

    #[test]
    fn flags() {
        let o = |a: &[&str]| Opts::parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let q = QueryArgs::parse(&o(&["--endpoint", "e", "--type-definition", "ns=2;s=T", "--include-subtypes", "--max-data-sets", "2", "--release-continuation-point"])).unwrap();
        assert!(q.include_subtypes && q.release);
        assert_eq!(q.max_data_sets, 2);
        assert_eq!(q.max_next, 100);
        for bad in [
            vec!["--endpoint", "e"],
            vec!["--endpoint", "e", "--type-definition", "bad"],
            vec!["--endpoint", "e", "--type-definition", "i=1", "--max-data-sets", "-1"],
            vec!["--endpoint", "e", "--type-definition", "i=1", "--data-to-return", "#Bogus"],
        ] {
            assert_eq!(QueryArgs::parse(&o(&bad)).err().unwrap().category, Category::Input, "{bad:?}");
        }
        assert!(cp_json(&ByteString::null()).is_null());
        assert_eq!(cp_json(&ByteString::from(vec![1u8])), json!("AQ=="));
    }
}
