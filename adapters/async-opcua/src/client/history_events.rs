//! `client history-read-events` / `client history-update-events`
//! (CONTAINER_CONTRACT §1, §4): HistoryRead with ReadEventDetails (Part 11
//! §6.5.2) and HistoryUpdate with UpdateEventDetails / DeleteEventDetails
//! (§6.9.4, §6.9.7), through the generic HistoryRead / HistoryUpdate builders
//! of async-opcua 0.19.

use opcua::client::services::{HistoryRead, HistoryUpdate};
use opcua::client::{HistoryReadAction, HistoryUpdateAction, UARequest};
use opcua::types::{
    AttributeId, ByteString, ContentFilter, ContentFilterElement, DateTime, DeleteEventDetails,
    ElementOperand, EventFilter, ExtensionObject, FilterOperator, HistoryEvent,
    HistoryEventFieldList, HistoryReadValueId, LiteralOperand, LocalizedText, NodeId,
    NumericRange, ObjectTypeId, PerformUpdateType, QualifiedName, ReadEventDetails,
    SimpleAttributeOperand, StatusCode, TimestampsToReturn, UpdateEventDetails, Variant,
};
use serde_json::{json, Value};

use super::{connect, parse_ref, svc_err, ConnectSpec, Conn, Opts};
use crate::common::{obj, status_json, Category, Envelope, Failure};
use crate::nodeid::{b64, b64_decode, fmt_node_id, NodeRef};
use crate::values::{parse_datetime, parse_scalar, scalar_type_from_name, variant_json};

/// The default SelectClauses (BaseEventType fields).
pub const DEFAULT_SELECT: [&str; 8] = [
    "EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity",
];

/// One `--select` path: `/`-separated browse names, `ns:Name` for namespace
/// `ns`, from BaseEventType.
pub fn select_operand(path: &str) -> Result<SimpleAttributeOperand, Failure> {
    let mut qns = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() {
            return Err(Failure::input(format!("invalid --select path '{path}'")));
        }
        let qn = match seg.split_once(':') {
            Some((ns, name)) if !name.is_empty() && ns.chars().all(|c| c.is_ascii_digit()) && !ns.is_empty() => {
                let ns: u16 = ns
                    .parse()
                    .map_err(|_| Failure::input(format!("invalid namespace in --select path '{path}'")))?;
                QualifiedName::new(ns, name)
            }
            _ => QualifiedName::new(0, seg),
        };
        qns.push(qn);
    }
    Ok(SimpleAttributeOperand {
        type_definition_id: ObjectTypeId::BaseEventType.into(),
        browse_path: Some(qns),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
    })
}

/// The WhereClause of `--of-type` / `--min-severity`: element 0 is the root
/// (Part 4 §7.7.1), so with both it is `And(1, 2)`.
pub fn where_clause(of_type: Option<NodeId>, min_sev: Option<u16>) -> ContentFilter {
    let mut elements = Vec::new();
    if let Some(t) = of_type {
        elements.push(ContentFilterElement {
            filter_operator: FilterOperator::OfType,
            filter_operands: Some(vec![ExtensionObject::from_message(LiteralOperand::from(t))]),
        });
    }
    if let Some(s) = min_sev {
        elements.push(ContentFilterElement {
            filter_operator: FilterOperator::GreaterThanOrEqual,
            filter_operands: Some(vec![
                ExtensionObject::from_message(select_operand("Severity").expect("static path")),
                ExtensionObject::from_message(LiteralOperand::from(Variant::UInt16(s))),
            ]),
        });
    }
    if elements.len() == 2 {
        elements.insert(
            0,
            ContentFilterElement {
                filter_operator: FilterOperator::And,
                filter_operands: Some(vec![
                    ExtensionObject::from_message(ElementOperand { index: 1 }),
                    ExtensionObject::from_message(ElementOperand { index: 2 }),
                ]),
            },
        );
    }
    ContentFilter {
        elements: if elements.is_empty() { None } else { Some(elements) },
    }
}

/// `--timestamps`: any case, default `both`.
fn timestamps_ci(opts: &Opts) -> Result<TimestampsToReturn, Failure> {
    let v = opts.get("--timestamps").unwrap_or("both");
    Ok(match v.to_ascii_lowercase().as_str() {
        "source" => TimestampsToReturn::Source,
        "server" => TimestampsToReturn::Server,
        "both" => TimestampsToReturn::Both,
        "neither" => TimestampsToReturn::Neither,
        _ => {
            return Err(Failure::input(format!(
                "invalid --timestamps '{v}' (source|server|both|neither)"
            )))
        }
    })
}

/// One field value of `--event`: `{"type":T,"value":V}` (§7 encodings), or a
/// bare JSON string / boolean / number (String, Boolean, Int32 / Double).
pub fn event_field_variant(path: &str, v: &Value) -> Result<Variant, Failure> {
    let bad = |m: String| Failure::input(format!("--event field {path}: {m}"));
    let (ty, val) = match v {
        Value::Object(m) if m.contains_key("type") => {
            let ty = m["type"].as_str().ok_or_else(|| bad("type is not a string".into()))?;
            (ty.to_owned(), m.get("value").cloned().unwrap_or(Value::Null))
        }
        Value::Null => return Ok(Variant::Empty),
        Value::Bool(b) => return Ok(Variant::Boolean(*b)),
        Value::String(s) => return Ok(Variant::from(s.as_str())),
        Value::Number(n) => {
            return Ok(match n.as_i64() {
                Some(i) if i32::try_from(i).is_ok() => Variant::Int32(i as i32),
                _ => Variant::Double(n.as_f64().unwrap_or_default()),
            })
        }
        other => return Err(bad(format!("unsupported value {other} (want {{\"type\",\"value\"}})"))),
    };
    if val.is_null() {
        return Ok(Variant::Empty);
    }
    match ty.as_str() {
        "LocalizedText" => {
            let (locale, text) = match &val {
                Value::Object(m) => (
                    m.get("locale").and_then(Value::as_str).unwrap_or(""),
                    m.get("text").and_then(Value::as_str).unwrap_or(""),
                ),
                Value::String(s) => ("", s.as_str()),
                _ => return Err(bad("LocalizedText wants {\"locale\",\"text\"}".into())),
            };
            Ok(Variant::from(LocalizedText::new(locale, text)))
        }
        "QualifiedName" => match &val {
            Value::Object(m) => Ok(Variant::from(QualifiedName::new(
                m.get("ns").and_then(Value::as_u64).unwrap_or(0) as u16,
                m.get("name").and_then(Value::as_str).unwrap_or(""),
            ))),
            _ => Err(bad("QualifiedName wants {\"ns\",\"name\"}".into())),
        },
        "StatusCode" => match &val {
            Value::Object(m) => Ok(Variant::StatusCode(StatusCode::from(
                m.get("code").and_then(Value::as_u64).unwrap_or(0) as u32,
            ))),
            Value::Number(n) => Ok(Variant::StatusCode(StatusCode::from(n.as_u64().unwrap_or(0) as u32))),
            _ => Err(bad("StatusCode wants {\"code\"} or a number".into())),
        },
        t => {
            let st = scalar_type_from_name(t).ok_or_else(|| bad(format!("unknown type '{t}'")))?;
            let lit = match &val {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            parse_scalar(st, &lit).map_err(bad)
        }
    }
}

/// Parse the `--event` objects into field lists in `select` order (a missing
/// path is a null Variant). Without `--select` the paths are the keys of the
/// events in first-seen order.
pub fn event_field_lists(
    select: &[String],
    events: &[String],
) -> Result<(Vec<String>, Vec<HistoryEventFieldList>), Failure> {
    let mut parsed = Vec::new();
    for e in events {
        let v: serde_json::Map<String, Value> = serde_json::from_str(e)
            .map_err(|err| Failure::input(format!("--event is not a JSON object: {err}")))?;
        parsed.push(v);
    }
    let mut paths: Vec<String> = select.to_vec();
    if paths.is_empty() {
        for m in &parsed {
            for k in m.keys() {
                if !paths.contains(k) {
                    paths.push(k.clone());
                }
            }
        }
    }
    let mut lists = Vec::new();
    for m in &parsed {
        if let Some(k) = m.keys().find(|k| !paths.contains(k)) {
            return Err(Failure::input(format!("--event field {k} is not in --select")));
        }
        let mut fields = Vec::new();
        for p in &paths {
            fields.push(match m.get(p) {
                Some(v) => event_field_variant(p, v)?,
                None => Variant::Empty,
            });
        }
        lists.push(HistoryEventFieldList { event_fields: Some(fields) });
    }
    Ok((paths, lists))
}

fn fields_json(paths: &[String], fields: &[Variant]) -> Value {
    // Only the fields the server returned (by index), not padded to the
    // SelectClauses.
    let fs: Vec<Value> = fields
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let name = paths.get(i).map(String::as_str).unwrap_or("");
            let (dt, bit, val) = variant_json(v);
            obj(vec![
                ("name", json!(name)),
                ("dataType", json!(dt)),
                ("builtInType", json!(bit)),
                ("value", val),
            ])
        })
        .collect();
    obj(vec![("fields", Value::Array(fs))])
}

struct EventPage {
    svc: StatusCode,
    item: StatusCode,
    cp: Option<String>,
    events: Vec<Value>,
}

struct ReadSpec {
    start: DateTime,
    end: DateTime,
    num: u32,
    filter: EventFilter,
    paths: Vec<String>,
    ts: TimestampsToReturn,
}

async fn read_page(
    conn: &Conn,
    id: &NodeId,
    rs: &ReadSpec,
    num: u32,
    cp: Option<&str>,
    release: bool,
) -> Result<EventPage, Failure> {
    let details = ReadEventDetails {
        num_values_per_node: num,
        start_time: rs.start,
        end_time: rs.end,
        filter: rs.filter.clone(),
    };
    let cpb = match cp {
        Some(s) if !s.is_empty() => ByteString::from(b64_decode(s).map_err(Failure::input)?),
        _ => ByteString::null(),
    };
    let r = HistoryRead::new(HistoryReadAction::ReadEventDetails(details), &conn.session)
        .timestamps_to_return(rs.ts)
        .release_continuation_points(release)
        .node(HistoryReadValueId {
            node_id: id.clone(),
            index_range: NumericRange::None,
            data_encoding: QualifiedName::null(),
            continuation_point: cpb,
        })
        .send(conn.session.channel())
        .await;
    match r {
        Err(e) => {
            if crate::common::is_transport(e.status()) || crate::common::is_timeout(e.status()) {
                return Err(svc_err(e, "HistoryRead"));
            }
            Ok(EventPage { svc: e.status(), item: e.status(), cp: None, events: Vec::new() })
        }
        Ok(resp) => {
            let svc = resp.response_header.service_result;
            let Some(hr) = resp.results.and_then(|v| v.into_iter().next()) else {
                return Ok(EventPage { svc, item: svc, cp: None, events: Vec::new() });
            };
            let cp = if hr.continuation_point.is_null_or_empty() {
                None
            } else {
                Some(b64(hr.continuation_point.value.as_deref().unwrap_or(&[])))
            };
            let mut events = Vec::new();
            if let Some(he) = hr.history_data.inner_as::<HistoryEvent>() {
                for fl in he.events.iter().flatten() {
                    events.push(fields_json(&rs.paths, fl.event_fields.as_deref().unwrap_or(&[])));
                }
            }
            Ok(EventPage { svc, item: hr.status_code, cp, events })
        }
    }
}

fn opt_time(opts: &Opts, k: &str) -> Result<DateTime, Failure> {
    match opts.get(k) {
        None => Ok(DateTime::null()),
        Some(s) => parse_datetime(s).map_err(Failure::input),
    }
}

pub async fn op_history_read_events(opts: &Opts) -> Envelope {
    let op = "history-read-events";
    let parsed = (|| -> Result<_, Failure> {
        let nodes: Vec<NodeRef> = opts.all("--node").iter().map(|s| parse_ref(s)).collect::<Result<_, _>>()?;
        if nodes.is_empty() {
            return Err(Failure::input("missing required flag --node"));
        }
        let start = opt_time(opts, "--start")?;
        let end = opt_time(opts, "--end")?;
        let num: u32 = opts.num("--num-values", 0)?;
        let mut paths = opts.all("--select");
        if paths.is_empty() {
            paths = DEFAULT_SELECT.iter().map(|s| s.to_string()).collect();
        }
        let select = paths.iter().map(|p| select_operand(p)).collect::<Result<Vec<_>, _>>()?;
        let of_type = opts.get("--of-type").map(parse_ref).transpose()?;
        let min_sev: Option<u16> = match opts.get("--min-severity") {
            Some(_) => Some(opts.num("--min-severity", 0)?),
            None => None,
        };
        let cp = opts.get("--continuation-point").map(str::to_owned);
        if let Some(c) = &cp {
            b64_decode(c).map_err(|_| Failure::input("--continuation-point is not Base64"))?;
        }
        let release = opts.flag("--release-continuation-point")?;
        if release && cp.is_none() {
            return Err(Failure::input("--release-continuation-point needs --continuation-point"));
        }
        if cp.is_some() && nodes.len() > 1 {
            return Err(Failure::input("--continuation-point takes exactly one --node"));
        }
        let ts = timestamps_ci(opts)?;
        let scenario = opts.get("--scenario").map(str::to_owned);
        if let Some(s) = &scenario {
            if s != "continue" {
                return Err(Failure::input(format!("unknown --scenario '{s}' (continue)")));
            }
        }
        let max_pages: u32 = opts.num("--max-pages", 8)?;
        Ok((nodes, start, end, num, paths, select, of_type, min_sev, cp, release, ts, scenario, max_pages))
    })();
    let (nodes, start, end, num, paths, select, of_type, min_sev, cp, release, ts, scenario, max_pages) =
        match parsed {
            Ok(v) => v,
            Err(f) => return Envelope::new(op).fail(&f),
        };
    with_conn!(op, opts, |conn| {
        let of_type = match &of_type {
            Some(t) => Some(conn.resolve(t).await?),
            None => None,
        };
        let rs = ReadSpec {
            start,
            end,
            num,
            filter: EventFilter { select_clauses: Some(select.clone()), where_clause: where_clause(of_type, min_sev) },
            paths: paths.clone(),
            ts,
        };
        let mut env = Envelope::new(op);
        let mut ok = true;
        let mut first_bad: Option<StatusCode> = None;
        for r in &nodes {
            let id = conn.resolve(r).await?;
            if scenario.is_some() {
                let num = if num == 0 { 2 } else { num };
                let mut pages = Vec::new();
                let mut all_events = Vec::new();
                let mut cur: Option<String> = None;
                let mut last_cp: Option<String> = None;
                let (mut last_svc, mut last_item) = (StatusCode::Good, StatusCode::Good);
                for _ in 0..max_pages.max(1) {
                    let p = read_page(&conn, &id, &rs, num, cur.as_deref(), false).await?;
                    last_svc = p.svc;
                    last_item = p.item;
                    all_events.extend(p.events.iter().cloned());
                    pages.push(obj(vec![
                        ("statusCode", status_json(p.item)),
                        ("continuationPoint", json!(p.cp)),
                        ("events", Value::Array(p.events)),
                    ]));
                    if !p.svc.is_good() || !p.item.is_good() {
                        cur = None;
                        break;
                    }
                    if let Some(c) = &p.cp {
                        last_cp = Some(c.clone());
                    }
                    cur = p.cp;
                    if cur.is_none() {
                        break;
                    }
                }
                // Release / reuse only when the server returned a continuation
                // point: the live one (--max-pages reached) or the last one seen.
                let (mut release_sc, mut reuse_sc) = (Value::Null, Value::Null);
                if let Some(c) = cur.as_ref().or(last_cp.as_ref()) {
                    let rel = read_page(&conn, &id, &rs, num, Some(c), true).await?;
                    release_sc = status_json(if rel.svc.is_good() { rel.item } else { rel.svc });
                    let re = read_page(&conn, &id, &rs, num, Some(c), false).await?;
                    reuse_sc = status_json(if re.svc.is_good() { re.item } else { re.svc });
                }
                let st = if last_svc.is_good() { last_item } else { last_svc };
                if !st.is_good() {
                    ok = false;
                    first_bad.get_or_insert(st);
                }
                env.results.push(obj(vec![
                    ("scenario", json!("continue")),
                    ("nodeId", json!(fmt_node_id(&id))),
                    ("statusCode", status_json(st)),
                    ("continuationPoint", json!(cur)),
                    ("selectClauses", json!(paths)),
                    ("events", Value::Array(all_events)),
                    ("pages", Value::Array(pages)),
                    ("releaseStatusCode", release_sc),
                    ("reuseAfterReleaseStatusCode", reuse_sc),
                ]));
                continue;
            }
            let p = read_page(&conn, &id, &rs, rs.num, cp.as_deref(), release).await?;
            let st = if p.svc.is_good() { p.item } else { p.svc };
            if !st.is_good() {
                ok = false;
                first_bad.get_or_insert(st);
            }
            env.results.push(obj(vec![
                ("nodeId", json!(fmt_node_id(&id))),
                ("statusCode", status_json(p.item)),
                ("continuationPoint", json!(p.cp)),
                ("selectClauses", json!(paths)),
                ("events", Value::Array(p.events)),
            ]));
        }
        if !ok {
            env.success = false;
            env.service_result = first_bad.unwrap_or(StatusCode::BadUnexpectedError);
            env.error = Some((Category::Service, "HistoryRead failed".into()));
        }
        Ok(env)
    })
}

pub fn perform_type(s: &str) -> Result<Option<PerformUpdateType>, Failure> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "insert" => Some(PerformUpdateType::Insert),
        "replace" => Some(PerformUpdateType::Replace),
        "update" => Some(PerformUpdateType::Update),
        "delete" => None,
        _ => return Err(Failure::input(format!("invalid --perform '{s}' (insert|replace|update|delete)"))),
    })
}

pub async fn op_history_update_events(opts: &Opts) -> Envelope {
    let op = "history-update-events";
    let parsed = (|| -> Result<_, Failure> {
        let node = parse_ref(opts.required("--node")?)?;
        let perform = perform_type(opts.required("--perform")?)?;
        let (paths, lists, ids) = match perform {
            Some(_) => {
                let events = opts.all("--event");
                if events.is_empty() {
                    return Err(Failure::input("--perform insert|replace|update needs --event"));
                }
                let (p, l) = event_field_lists(&opts.all("--select"), &events)?;
                (p, l, Vec::new())
            }
            None => {
                let ids = opts
                    .all("--event-id")
                    .iter()
                    .map(|s| b64_decode(s).map(ByteString::from).map_err(|_| Failure::input("--event-id is not Base64")))
                    .collect::<Result<Vec<_>, _>>()?;
                if ids.is_empty() {
                    return Err(Failure::input("--perform delete needs --event-id"));
                }
                (Vec::new(), Vec::new(), ids)
            }
        };
        let select = paths.iter().map(|p| select_operand(p)).collect::<Result<Vec<_>, _>>()?;
        Ok((node, perform, select, lists, ids))
    })();
    let (node, perform, select, lists, ids) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let id = conn.resolve(&node).await?;
        let (action, name) = match perform {
            Some(p) => (
                HistoryUpdateAction::UpdateEventDetails(UpdateEventDetails {
                    node_id: id.clone(),
                    perform_insert_replace: p,
                    filter: EventFilter { select_clauses: Some(select), where_clause: ContentFilter { elements: None } },
                    event_data: Some(lists),
                }),
                match p {
                    PerformUpdateType::Insert => "Insert",
                    PerformUpdateType::Replace => "Replace",
                    _ => "Update",
                },
            ),
            None => (
                HistoryUpdateAction::DeleteEventDetails(DeleteEventDetails { node_id: id.clone(), event_ids: Some(ids) }),
                "Delete",
            ),
        };
        let r = HistoryUpdate::new(&conn.session).action(action).send(conn.session.channel()).await;
        let mut env = Envelope::new(op);
        let (item, op_results) = match r {
            Err(e) => {
                if crate::common::is_transport(e.status()) || crate::common::is_timeout(e.status()) {
                    return Err(svc_err(e, "HistoryUpdate"));
                }
                // A service fault: no result items.
                env.service_result = e.status();
                env.success = false;
                env.error = Some((Category::Service, format!("HistoryUpdate: {e}")));
                return Ok(env);
            }
            Ok(resp) => {
                env.service_result = resp.response_header.service_result;
                match resp.results.and_then(|v| v.into_iter().next()) {
                    Some(hr) => (hr.status_code, hr.operation_results.unwrap_or_default()),
                    None => (StatusCode::BadUnexpectedError, Vec::new()),
                }
            }
        };
        env.results.push(obj(vec![
            ("nodeId", json!(fmt_node_id(&id))),
            ("performUpdateType", json!(name)),
            ("statusCode", status_json(item)),
            ("operationResults", Value::Array(op_results.into_iter().map(status_json).collect())),
        ]));
        if !env.service_result.is_good() || !item.is_good() {
            env.success = false;
            if env.service_result.is_good() {
                env.service_result = item;
            }
            env.error = Some((Category::Service, "HistoryUpdate failed".into()));
        }
        Ok(env)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qn(o: &SimpleAttributeOperand) -> Vec<(u16, String)> {
        o.browse_path
            .iter()
            .flatten()
            .map(|q| (q.namespace_index, q.name.value().clone().unwrap_or_default()))
            .collect()
    }

    #[test]
    fn select_paths() {
        assert_eq!(qn(&select_operand("EventId").unwrap()), [(0, "EventId".to_string())]);
        assert_eq!(
            qn(&select_operand("AckedState/Id").unwrap()),
            [(0, "AckedState".to_string()), (0, "Id".to_string())]
        );
        assert_eq!(
            qn(&select_operand("2:Pump/3:Speed").unwrap()),
            [(2, "Pump".to_string()), (3, "Speed".to_string())]
        );
        assert!(select_operand("a//b").is_err());
        assert!(select_operand("").is_err());
    }

    #[test]
    fn where_clauses() {
        assert!(where_clause(None, None).elements.is_none());
        let one = where_clause(None, Some(300)).elements.unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].filter_operator, FilterOperator::GreaterThanOrEqual);
        let both = where_clause(Some(NodeId::new(0, 2130)), Some(300)).elements.unwrap();
        assert_eq!(
            both.iter().map(|e| e.filter_operator).collect::<Vec<_>>(),
            [FilterOperator::And, FilterOperator::OfType, FilterOperator::GreaterThanOrEqual]
        );
        let and = both[0].filter_operands.as_ref().unwrap();
        assert_eq!(and[0].inner_as::<ElementOperand>().unwrap().index, 1);
        assert_eq!(and[1].inner_as::<ElementOperand>().unwrap().index, 2);
    }

    #[test]
    fn event_json() {
        let ev = r#"{"EventId":{"type":"ByteString","value":"aGlzdC1ldnQtNQ=="},
            "Time":{"type":"DateTime","value":"2026-07-24T10:00:25Z"},
            "Severity":{"type":"UInt16","value":700},
            "Message":{"type":"LocalizedText","value":{"text":"x"}},
            "EventType":{"type":"NodeId","value":"i=2041"},
            "SourceName":{"type":"String","value":"History.Events"}}"#;
        let (paths, lists) = event_field_lists(&[], &[ev.to_string()]).unwrap();
        assert_eq!(paths, ["EventId", "Time", "Severity", "Message", "EventType", "SourceName"]);
        let f = lists[0].event_fields.as_ref().unwrap();
        assert_eq!(f[0], Variant::ByteString(ByteString::from(b"hist-evt-5".to_vec())));
        assert_eq!(f[2], Variant::UInt16(700));
        assert_eq!(f[3], Variant::from(LocalizedText::new("", "x")));
        assert_eq!(f[4], Variant::from(NodeId::new(0, 2041)));
        // With --select: order follows it, a missing path is null.
        let sel = vec!["Severity".to_string(), "Comment".to_string(), "EventId".to_string()];
        let ev2 = r#"{"EventId":{"type":"ByteString","value":"YQ=="},"Severity":{"type":"UInt16","value":1}}"#;
        let (paths, lists) = event_field_lists(&sel, &[ev2.to_string()]).unwrap();
        assert_eq!(paths, sel);
        let f = lists[0].event_fields.as_ref().unwrap();
        assert_eq!(f[0], Variant::UInt16(1));
        assert_eq!(f[1], Variant::Empty);
        // A key outside --select, a bad type, bad JSON.
        assert!(event_field_lists(&["Severity".to_string()], &[ev2.to_string()]).is_err());
        assert!(event_field_lists(&[], &[r#"{"A":{"type":"Nope","value":1}}"#.to_string()]).is_err());
        assert!(event_field_lists(&[], &["[1]".to_string()]).is_err());
        // Bare values.
        assert_eq!(event_field_variant("x", &json!("s")).unwrap(), Variant::from("s"));
        assert_eq!(event_field_variant("x", &json!(5)).unwrap(), Variant::Int32(5));
        assert_eq!(event_field_variant("x", &json!(true)).unwrap(), Variant::Boolean(true));
    }

    #[test]
    fn perform() {
        assert_eq!(perform_type("Insert").unwrap(), Some(PerformUpdateType::Insert));
        assert_eq!(perform_type("delete").unwrap(), None);
        assert!(perform_type("remove").is_err());
    }
}
