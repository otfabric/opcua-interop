//! `server` mode: an async-opcua server exposing the fixture address space
//! (CONTAINER_CONTRACT §10, §11).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opcua::crypto::SecurityPolicy;
use opcua::nodes::{BaseEventType, Event};
use opcua::server::address_space::{
    new_node_from_attributes, AccessLevel, AddressSpace, EventNotifier, MethodBuilder, NodeType,
    ObjectBuilder, VariableBuilder,
};
use opcua::server::node_manager::memory::{
    InMemoryNodeManager, InMemoryNodeManagerBuilder, InMemoryNodeManagerImpl,
    InMemoryNodeManagerImplBuilder,
};
use opcua::server::diagnostics::NamespaceMetadata;
use opcua::nodes::HasNodeId;
use opcua::server::node_manager::{
    AddNodeItem, DeleteNodeItem, HistoryNode, MethodCall, NodeManagersRef, ParsedReadValueId,
    RequestContext, ServerContext, WriteNode,
};
use opcua::server::{
    ContinuationPoint, ReverseConnectTargetConfig, ServerBuilder, ServerEndpoint, ServerUserToken,
    ANONYMOUS_USER_TOKEN_ID,
};
use opcua::sync::RwLock;
use opcua::types::{
    Argument, Array, BuildInfo, ByteString, DataTypeId, DataValue, DateTime, ExpandedNodeId,
    ExtensionObject, HistoryData, LocalizedText, MessageSecurityMode, NodeClass, NodeId,
    NumericRange, ObjectId, ObjectTypeId, QualifiedName, Range, ReadRawModifiedDetails,
    ReferenceTypeId, StatusCode, TimestampsToReturn, UAString, Variant, VariableTypeId,
};
use opcua::nodes::ReferenceDirection;
use serde_json::Value;

use crate::common::{ADAPTER, ADAPTER_VERSION, STACK_VERSION};
use crate::fixture::{self, ArgumentDef, BehaviorDef, Fixture, NodeDef};
use crate::nodeid::{parse_node_ref, Ns};
use crate::values::{parse_scalar, scalar_type_from_name};

pub const INTEROP_NS: &str = "urn:otfabric:opcua-interop:model";
const EVENTS_SOURCE: &str = "Events.Source";
const HISTORY_TEMPERATURE: &str = "History.Temperature";

// ── Command line ────────────────────────────────────────────────────────────

struct ServerArgs {
    fixture: String,
    bind_address: String,
    bind_port: Option<u16>,
    advertised_host: String,
    advertised_port: Option<u16>,
    endpoint_path: Option<String>,
    ready_file: String,
    ready_file_explicit: bool,
    pki_dir: String,
    certificate: Option<String>,
    private_key: Option<String>,
    reverse_connect: Vec<String>,
    reverse_connect_interval_ms: u64,
    register_with: Option<String>,
    register_interval_ms: u64,
}

fn usage_error(msg: &str) -> i32 {
    eprintln!("[{ADAPTER}] error: {msg}");
    2
}

fn parse_args(args: &[String]) -> Result<ServerArgs, i32> {
    let mut a = ServerArgs {
        fixture: String::new(),
        bind_address: "0.0.0.0".into(),
        bind_port: None,
        advertised_host: "localhost".into(),
        advertised_port: None,
        endpoint_path: None,
        ready_file: "/run/opcua-interop/ready".into(),
        ready_file_explicit: false,
        pki_dir: "/run/opcua-interop/pki".into(),
        certificate: None,
        private_key: None,
        reverse_connect: Vec::new(),
        reverse_connect_interval_ms: 1000,
        register_with: None,
        register_interval_ms: 30_000,
    };
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        // Features async-opcua 0.19 does not implement are refused, not ignored.
        let refused = match flag {
            "--lds" | "--lds-cleanup-timeout" => Some(
                "async-opcua 0.19 has no Local Discovery Server: its server answers RegisterServer, \
                 RegisterServer2 and FindServersOnNetwork with BadServiceUnsupported",
            ),
            "--mdns-name" | "--mdns-capability" => {
                Some("async-opcua 0.19 has no mDNS / LDS-ME support")
            }
            "--pubsub-config" => Some("async-opcua 0.19 has no PubSub (Part 14) implementation"),
            _ => None,
        };
        if let Some(why) = refused {
            return Err(usage_error(&format!("{flag} is not supported: {why}")));
        }
        let needs_value = !matches!(flag, "--help");
        let val = if needs_value {
            match args.get(i + 1) {
                Some(v) => v.clone(),
                None => return Err(usage_error(&format!("missing value for {flag}"))),
            }
        } else {
            String::new()
        };
        let num = |v: &str| -> Result<u64, i32> {
            v.parse::<u64>()
                .map_err(|_| usage_error(&format!("invalid number for {flag}: {v}")))
        };
        match flag {
            "--fixture" => a.fixture = val,
            "--bind-address" => a.bind_address = val,
            "--bind-port" => a.bind_port = Some(num(&val)? as u16),
            "--advertised-host" => a.advertised_host = val,
            "--advertised-port" => a.advertised_port = Some(num(&val)? as u16),
            "--endpoint-path" => a.endpoint_path = Some(val),
            "--ready-file" => {
                a.ready_file = val;
                a.ready_file_explicit = true
            }
            "--pki-dir" => a.pki_dir = val,
            "--certificate" => a.certificate = Some(val),
            "--private-key" => a.private_key = Some(val),
            "--ecc-dir" => eprintln!(
                "[{ADAPTER}] warn: --ecc-dir ignored: async-opcua 0.19 has no ECC security policies"
            ),
            "--reverse-connect" => a.reverse_connect.push(val),
            "--reverse-connect-interval-ms" => a.reverse_connect_interval_ms = num(&val)?,
            "--register-with" => a.register_with = Some(val),
            "--register-interval-ms" => a.register_interval_ms = num(&val)?.max(500),
            other => return Err(usage_error(&format!("unknown server flag {other}"))),
        }
        i += 2;
    }
    if a.fixture.is_empty() {
        if let Ok(f) = std::env::var("OPCUA_FIXTURE") {
            a.fixture = f;
        } else {
            return Err(usage_error("missing --fixture"));
        }
    }
    Ok(a)
}

// ── Fixture helpers ─────────────────────────────────────────────────────────

/// Resolve a fixture NodeId (`nsu=<interop>;s=x`, `i=85`) to a runtime NodeId.
fn fixture_node_id(s: &str, ns_idx: u16) -> NodeId {
    match parse_node_ref(s) {
        Ok(r) => {
            let namespace = match r.ns {
                Ns::Index(i) => i,
                Ns::Uri(u) if u == INTEROP_NS => ns_idx,
                Ns::Uri(_) => ns_idx,
            };
            NodeId {
                namespace,
                identifier: r.identifier,
            }
        }
        Err(_) => NodeId::new(ns_idx, s),
    }
}

/// Fixture browse names are `<fixture-ns>:<name>`, fixture ns 1 = interop.
fn fixture_browse_name(s: &str, ns_idx: u16) -> QualifiedName {
    match s.split_once(':') {
        Some((n, name)) if n.chars().all(|c| c.is_ascii_digit()) => {
            let ns = if n == "0" { 0 } else { ns_idx };
            QualifiedName::new(ns, name)
        }
        _ => QualifiedName::new(ns_idx, s),
    }
}

fn reference_type(name: &str) -> ReferenceTypeId {
    match name {
        "HasComponent" => ReferenceTypeId::HasComponent,
        "HasProperty" => ReferenceTypeId::HasProperty,
        "HasNotifier" => ReferenceTypeId::HasNotifier,
        "HasEventSource" => ReferenceTypeId::HasEventSource,
        _ => ReferenceTypeId::Organizes,
    }
}

fn data_type_id(name: &str) -> NodeId {
    match scalar_type_from_name(name) {
        Some(t) => NodeId::new(0, t as u32),
        None => DataTypeId::BaseDataType.into(),
    }
}

fn access_level(levels: &Option<Vec<String>>) -> AccessLevel {
    let mut al = AccessLevel::empty();
    for l in levels.iter().flatten() {
        match l.as_str() {
            "CurrentRead" => al |= AccessLevel::CURRENT_READ,
            "CurrentWrite" => al |= AccessLevel::CURRENT_WRITE,
            "HistoryRead" => al |= AccessLevel::HISTORY_READ,
            "HistoryWrite" => al |= AccessLevel::HISTORY_WRITE,
            "SemanticChange" => al |= AccessLevel::SEMANTIC_CHANGE,
            "StatusWrite" => al |= AccessLevel::STATUS_WRITE,
            "TimestampWrite" => al |= AccessLevel::TIMESTAMP_WRITE,
            _ => {}
        }
    }
    if al.is_empty() {
        al = AccessLevel::CURRENT_READ;
    }
    al
}

fn json_literal(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Build the initial value of a fixture variable.
fn initial_value(nd: &NodeDef) -> Result<Variant, String> {
    let dt = nd.data_type.clone().unwrap_or_else(|| "String".into());
    let ty = scalar_type_from_name(&dt).ok_or_else(|| format!("unknown dataType {dt}"))?;
    let rank = nd.value_rank.unwrap_or(-1);
    let Some(iv) = &nd.initial_value else {
        return Ok(Variant::Empty);
    };
    if rank >= 1 {
        let items = match iv {
            Value::Array(a) => a.clone(),
            _ => vec![iv.clone()],
        };
        let mut vals = Vec::with_capacity(items.len());
        for it in &items {
            vals.push(parse_scalar(ty, &json_literal(it))?);
        }
        if rank >= 2 {
            let dims = nd.array_dimensions.clone().unwrap_or_default();
            let arr = Array::new_multi(ty, vals, dims).map_err(|e| format!("{e:?}"))?;
            return Ok(Variant::from(arr));
        }
        let arr = Array::new(ty, vals).map_err(|e| format!("{e:?}"))?;
        return Ok(Variant::from(arr));
    }
    if dt == "ByteString" {
        if let Value::String(s) = iv {
            if s.is_empty() {
                return Ok(Variant::ByteString(ByteString::from(Vec::<u8>::new())));
            }
        }
    }
    parse_scalar(ty, &json_literal(iv))
}

/// What in a fixture the server could not serve as specified: unknown node
/// classes, data types or method behaviours, initial values that do not
/// parse, references to nodes the fixture does not define, unknown behaviour
/// kinds. Empty for a fixture the server builds completely (`test` and the
/// unit tests check the baseline fixture with it).
pub fn fixture_problems(f: &crate::fixture::Fixture) -> Vec<String> {
    let mut p = Vec::new();
    if !f.namespaces.iter().any(|n| n.uri == INTEROP_NS) {
        p.push(format!("namespace {INTEROP_NS} is not declared"));
    }
    let ids: std::collections::HashSet<&str> = f.nodes.iter().map(|n| n.node_id.as_str()).collect();
    let known = |id: &str| ids.contains(id) || matches!(parse_node_ref(id), Ok(r) if matches!(r.ns, Ns::Index(0)));
    for nd in &f.nodes {
        if !known(&nd.parent_node_id) {
            p.push(format!("{}: parent {} is not defined", nd.node_id, nd.parent_node_id));
        }
        if !matches!(nd.reference_type.as_str(), "HasComponent" | "HasProperty" | "HasNotifier" | "HasEventSource" | "Organizes") {
            p.push(format!("{}: reference type {} is not supported", nd.node_id, nd.reference_type));
        }
        match nd.node_class.as_str() {
            "Variable" => {
                if let Some(dt) = &nd.data_type {
                    if scalar_type_from_name(dt).is_none() {
                        p.push(format!("{}: dataType {dt} is not a built-in type", nd.node_id));
                    }
                }
                if let Err(e) = initial_value(nd) {
                    p.push(format!("{}: initial value: {e}", nd.node_id));
                }
            }
            "Method" => {
                if let Some(b) = &nd.method_behavior {
                    if method_behavior(b).is_none() {
                        p.push(format!("{}: method behaviour {b} is not implemented", nd.node_id));
                    }
                }
                for a in nd.input_arguments.iter().flatten().chain(nd.output_arguments.iter().flatten()) {
                    if scalar_type_from_name(&a.data_type).is_none() {
                        p.push(format!("{}: argument {} has dataType {}", nd.node_id, a.name, a.data_type));
                    }
                }
            }
            "Object" => {}
            other => p.push(format!("{}: node class {other} is not supported", nd.node_id)),
        }
    }
    for b in &f.behaviors {
        if !matches!(b.kind.as_str(), "counter" | "toggle" | "ramp" | "fixed-status") {
            p.push(format!("behaviour {} of {}: unknown kind", b.kind, b.target));
        }
        if !ids.contains(b.target.as_str()) {
            p.push(format!("behaviour {} targets {}, which is not defined", b.kind, b.target));
        }
    }
    for sp in &f.security_profiles {
        let ecc = sp.security_policy.starts_with("ECC_");
        if mode_from_name(&sp.security_mode).is_none() || (!ecc && policy_from_name(&sp.security_policy).is_none()) {
            p.push(format!("security profile {}/{} is not known", sp.security_policy, sp.security_mode));
        }
    }
    p
}

fn arguments(defs: &Option<Vec<ArgumentDef>>) -> Vec<Argument> {
    defs.iter()
        .flatten()
        .map(|d| Argument {
            name: UAString::from(d.name.as_str()),
            data_type: data_type_id(&d.data_type),
            value_rank: d.value_rank,
            array_dimensions: None,
            description: LocalizedText::new("en", d.description.as_deref().unwrap_or("")),
        })
        .collect()
}

fn history_samples() -> Vec<DataValue> {
    let base = chrono::DateTime::parse_from_rfc3339("2026-07-24T10:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    (0..5)
        .map(|i| {
            let ts = DateTime::from(base + chrono::Duration::seconds(5 * i));
            DataValue {
                value: Some(Variant::Double(20.0 + i as f64)),
                status: Some(StatusCode::Good),
                source_timestamp: Some(ts),
                source_picoseconds: None,
                server_timestamp: Some(ts),
                server_picoseconds: None,
            }
        })
        .collect()
}

// ── Node manager ────────────────────────────────────────────────────────────

type MethodFn = fn(&[Variant]) -> Result<Vec<Variant>, StatusCode>;

fn method_behavior(name: &str) -> Option<MethodFn> {
    fn i32_arg(args: &[Variant], i: usize) -> Result<i32, StatusCode> {
        match args.get(i) {
            Some(Variant::Int32(v)) => Ok(*v),
            Some(_) => Err(StatusCode::BadTypeMismatch),
            None => Err(StatusCode::BadArgumentsMissing),
        }
    }
    fn f64_arg(args: &[Variant], i: usize) -> Result<f64, StatusCode> {
        match args.get(i) {
            Some(Variant::Double(v)) => Ok(*v),
            Some(_) => Err(StatusCode::BadTypeMismatch),
            None => Err(StatusCode::BadArgumentsMissing),
        }
    }
    Some(match name {
        "Add" => |a| {
            Ok(vec![Variant::Int32(
                i32_arg(a, 0)?.wrapping_add(i32_arg(a, 1)?),
            )])
        },
        "Multiply" => |a| Ok(vec![Variant::Double(f64_arg(a, 0)? * f64_arg(a, 1)?)]),
        "Echo" => |a| match a.first() {
            Some(Variant::String(s)) => Ok(vec![Variant::String(s.clone())]),
            Some(_) => Err(StatusCode::BadTypeMismatch),
            None => Err(StatusCode::BadArgumentsMissing),
        },
        "NoArguments" => |_| Ok(vec![Variant::Boolean(true)]),
        "MultipleOutputs" => |a| {
            let v = i32_arg(a, 0)?;
            Ok(vec![
                Variant::Int32(v.wrapping_mul(2)),
                Variant::String(UAString::from(v.to_string())),
            ])
        },
        "Fail" => |_| Err(StatusCode::BadInternalError),
        _ => return None,
    })
}

pub struct InteropImplBuilder {
    fixture: Arc<Fixture>,
    ready: Arc<tokio::sync::Notify>,
}

impl InMemoryNodeManagerImplBuilder for InteropImplBuilder {
    type Impl = InteropImpl;

    fn build(self, context: ServerContext, address_space: &mut AddressSpace) -> Self::Impl {
        let ns_idx = {
            let mut type_tree = context.type_tree.write();
            type_tree.namespaces_mut().add_namespace(INTEROP_NS)
        };
        address_space.add_namespace(INTEROP_NS, ns_idx);
        InteropImpl {
            fixture: self.fixture,
            ns_idx,
            ready: self.ready,
            methods: RwLock::new(HashMap::new()),
            node_managers: context.node_managers.clone(),
            added_counter: std::sync::atomic::AtomicU32::new(1),
        }
    }
}

pub struct InteropImpl {
    fixture: Arc<Fixture>,
    ns_idx: u16,
    ready: Arc<tokio::sync::Notify>,
    methods: RwLock<HashMap<NodeId, MethodFn>>,
    #[allow(unused)]
    node_managers: NodeManagersRef,
    added_counter: std::sync::atomic::AtomicU32,
}

/// Continuation point payload of a History.Temperature read.
struct HistoryCp {
    offset: usize,
}

impl InteropImpl {
    pub fn ns(&self) -> u16 {
        self.ns_idx
    }

    fn populate(&self, address_space: &mut AddressSpace) {
        let ns = self.ns_idx;
        let mut methods = self.methods.write();
        for nd in &self.fixture.nodes {
            let id = fixture_node_id(&nd.node_id, ns);
            let bn = fixture_browse_name(&nd.browse_name, ns);
            let dn = LocalizedText::new("en", &nd.display_name);
            let parent = fixture_node_id(&nd.parent_node_id, ns);
            let rt = reference_type(&nd.reference_type);
            let desc = LocalizedText::new("en", nd.description.as_deref().unwrap_or(""));
            match nd.node_class.as_str() {
                "Variable" => {
                    let al = access_level(&nd.access_level);
                    let value = match initial_value(nd) {
                        Ok(v) => v,
                        Err(e) => {
                            log::warn!("node {}: initial value not usable: {e}", nd.node_id);
                            Variant::Empty
                        }
                    };
                    let type_def: NodeId = match &nd.type_definition {
                        Some(t) => fixture_node_id(t, ns),
                        None => VariableTypeId::BaseDataVariableType.into(),
                    };
                    let mut b = VariableBuilder::new(&id, bn, dn)
                        .description(desc)
                        .data_type(data_type_id(nd.data_type.as_deref().unwrap_or("BaseDataType")))
                        .value_rank(nd.value_rank.unwrap_or(-1))
                        .access_level(al)
                        .user_access_level(al)
                        .historizing(nd.node_id.ends_with(HISTORY_TEMPERATURE))
                        .value(value)
                        .has_type_definition(type_def)
                        .reference(parent, rt, ReferenceDirection::Inverse);
                    if let Some(d) = &nd.array_dimensions {
                        b = b.array_dimensions(d);
                    }
                    b.insert(address_space);
                    if let Some(r) = &nd.eu_range {
                        let prop_id = NodeId::new(ns, format!("{}.EURange", id_string(&id)));
                        VariableBuilder::new(&prop_id, QualifiedName::new(0, "EURange"), "EURange")
                            .data_type(DataTypeId::Range)
                            .value_rank(-1)
                            .access_level(AccessLevel::CURRENT_READ)
                            .user_access_level(AccessLevel::CURRENT_READ)
                            .value(ExtensionObject::from_message(Range {
                                low: r.low,
                                high: r.high,
                            }))
                            .has_type_definition(VariableTypeId::PropertyType)
                            .reference(id.clone(), ReferenceTypeId::HasProperty, ReferenceDirection::Inverse)
                            .insert(address_space);
                    }
                }
                "Method" => {
                    let in_id = NodeId::new(ns, format!("{}.InputArguments", id_string(&id)));
                    let out_id = NodeId::new(ns, format!("{}.OutputArguments", id_string(&id)));
                    let ins = arguments(&nd.input_arguments);
                    let outs = arguments(&nd.output_arguments);
                    let mut b = MethodBuilder::new(&id, bn, dn)
                        .description(desc)
                        .executable(true)
                        .user_executable(true)
                        .reference(parent, rt, ReferenceDirection::Inverse);
                    if !ins.is_empty() {
                        b = b.input_args(address_space, &in_id, &ins);
                    }
                    if !outs.is_empty() {
                        b = b.output_args(address_space, &out_id, &outs);
                    }
                    b.insert(address_space);
                    if let Some(f) = nd.method_behavior.as_deref().and_then(method_behavior) {
                        methods.insert(id.clone(), f);
                    }
                }
                _ => {
                    let type_def: NodeId = match &nd.type_definition {
                        Some(t) => fixture_node_id(t, ns),
                        None => ObjectTypeId::FolderType.into(),
                    };
                    let mut b = ObjectBuilder::new(&id, bn, dn)
                        .description(desc)
                        .has_type_definition(type_def)
                        .reference(parent, rt, ReferenceDirection::Inverse);
                    if nd.node_id.ends_with(EVENTS_SOURCE) {
                        b = b.event_notifier(EventNotifier::SUBSCRIBE_TO_EVENTS);
                    }
                    b.insert(address_space);
                }
            }
        }

        // Diagnostics values describe this adapter.
        for (name, val) in [
            ("Diagnostics.AdapterName", ADAPTER.to_owned()),
            ("Diagnostics.StackVersion", format!("async-opcua {STACK_VERSION}")),
            ("Diagnostics.FixtureId", self.fixture.id.clone()),
        ] {
            if let Some(NodeType::Variable(v)) = address_space.find_mut(&NodeId::new(ns, name)) {
                v.set_data_value(DataValue::new_now(Variant::String(UAString::from(val))));
            }
        }
        // DataValues.GoodWithTimestamps carries both timestamps.
        if let Some(NodeType::Variable(v)) =
            address_space.find_mut(&NodeId::new(ns, "DataValues.GoodWithTimestamps"))
        {
            let now = DateTime::now();
            let val = v.value(TimestampsToReturn::Neither, &NumericRange::None, &opcua::types::DataEncoding::Binary, 0.0).value;
            v.set_data_value(DataValue {
                value: val,
                status: Some(StatusCode::Good),
                source_timestamp: Some(now),
                source_picoseconds: None,
                server_timestamp: Some(now),
                server_picoseconds: None,
            });
        }
        // Behaviours that only set a status.
        for b in &self.fixture.behaviors {
            if b.kind == "fixed-status" {
                let id = fixture_node_id(&b.target, ns);
                let code = b.initial.as_ref().and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                if let Some(NodeType::Variable(v)) = address_space.find_mut(&id) {
                    let val = v
                        .value(TimestampsToReturn::Neither, &NumericRange::None, &opcua::types::DataEncoding::Binary, 0.0)
                        .value;
                    v.set_data_value(DataValue {
                        value: val,
                        status: Some(StatusCode::from(code)),
                        source_timestamp: Some(DateTime::now()),
                        source_picoseconds: None,
                        server_timestamp: Some(DateTime::now()),
                        server_picoseconds: None,
                    });
                }
            }
        }
    }
}

fn id_string(id: &NodeId) -> String {
    match &id.identifier {
        opcua::types::Identifier::String(s) => s.as_ref().to_owned(),
        other => format!("{other}"),
    }
}

#[async_trait]
impl InMemoryNodeManagerImpl for InteropImpl {
    async fn init(&self, address_space: &mut AddressSpace, _context: ServerContext) {
        self.populate(address_space);
        self.ready.notify_one();
    }

    fn name(&self) -> &str {
        "opcua-interop"
    }

    fn namespaces(&self) -> Vec<NamespaceMetadata> {
        vec![NamespaceMetadata {
            namespace_uri: INTEROP_NS.to_owned(),
            namespace_index: self.ns_idx,
            ..Default::default()
        }]
    }

    fn handle_new_node(&self, parent_id: &ExpandedNodeId) -> bool {
        parent_id.node_id.namespace == self.ns_idx
    }

    async fn read_values(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes: &[&ParsedReadValueId],
        max_age: f64,
        timestamps_to_return: TimestampsToReturn,
    ) -> Vec<DataValue> {
        let address_space = address_space.read();
        nodes
            .iter()
            .map(|n| address_space.read(context, n, max_age, timestamps_to_return))
            .collect()
    }

    async fn write(
        &self,
        context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_write: &mut [&mut WriteNode],
    ) -> Result<(), StatusCode> {
        let mut address_space = address_space.write();
        let type_tree = context.type_tree.read();
        for write in nodes_to_write.iter_mut() {
            let node = match address_space.validate_node_write(context, write.value(), &*type_tree) {
                Ok(v) => v,
                Err(e) => {
                    write.set_status(e);
                    continue;
                }
            };
            if node.node_class() != NodeClass::Variable
                || write.value().attribute_id != opcua::types::AttributeId::Value
            {
                write.set_status(StatusCode::BadNotWritable);
                continue;
            }
            if write.value().value.value.is_none() {
                write.set_status(StatusCode::BadNothingToDo);
                continue;
            }
            match opcua::server::address_space::write_node_value(node, write.value()) {
                Ok(_) => write.set_status(StatusCode::Good),
                Err(e) => write.set_status(e),
            }
            if write.status().is_good() {
                if let Some(val) = node.as_mut_node().get_attribute(
                    TimestampsToReturn::Both,
                    write.value().attribute_id,
                    &NumericRange::None,
                    &opcua::types::DataEncoding::Binary,
                ) {
                    context.subscriptions.notify_data_change(
                        [(val, node.node_id(), write.value().attribute_id)].into_iter(),
                    );
                }
            }
        }
        Ok(())
    }

    async fn call(
        &self,
        _context: &RequestContext,
        _address_space: &RwLock<AddressSpace>,
        methods_to_call: &mut [&mut &mut MethodCall],
    ) -> Result<(), StatusCode> {
        let methods = self.methods.read();
        for m in methods_to_call.iter_mut() {
            match methods.get(m.method_id()) {
                Some(f) => match f(m.arguments()) {
                    Ok(out) => {
                        m.set_outputs(out);
                        m.set_status(StatusCode::Good);
                    }
                    Err(e) => m.set_status(e),
                },
                None => m.set_status(StatusCode::BadMethodInvalid),
            }
        }
        Ok(())
    }

    async fn history_read_raw_modified(
        &self,
        _context: &RequestContext,
        details: &ReadRawModifiedDetails,
        nodes: &mut [&mut &mut HistoryNode],
        _timestamps_to_return: TimestampsToReturn,
    ) -> Result<(), StatusCode> {
        let temp = NodeId::new(self.ns_idx, HISTORY_TEMPERATURE);
        let samples = history_samples();
        for node in nodes.iter_mut() {
            if details.is_read_modified || *node.node_id() != temp {
                node.set_status(StatusCode::BadHistoryOperationUnsupported);
                continue;
            }
            let start = details.start_time.as_chrono();
            let end = details.end_time.as_chrono();
            let in_range: Vec<DataValue> = samples
                .iter()
                .filter(|dv| {
                    let t = dv.source_timestamp.unwrap().as_chrono();
                    (details.start_time.is_null() || t >= start)
                        && (details.end_time.is_null() || t <= end)
                })
                .cloned()
                .collect();
            let offset = match node.continuation_point() {
                Some(cp) => match cp.get::<HistoryCp>() {
                    Some(h) => h.offset,
                    None => {
                        node.set_status(StatusCode::BadContinuationPointInvalid);
                        continue;
                    }
                },
                None => 0,
            };
            if offset > in_range.len() {
                node.set_status(StatusCode::BadContinuationPointInvalid);
                continue;
            }
            let per = if details.num_values_per_node == 0 {
                in_range.len()
            } else {
                details.num_values_per_node as usize
            };
            let end_idx = (offset + per).min(in_range.len());
            let page = in_range[offset..end_idx].to_vec();
            if end_idx < in_range.len() {
                node.set_next_continuation_point(Some(ContinuationPoint::new(Box::new(
                    HistoryCp { offset: end_idx },
                ))));
            }
            node.set_result(HistoryData {
                data_values: Some(page),
            });
            node.set_status(StatusCode::Good);
        }
        Ok(())
    }

    async fn add_nodes(
        &self,
        _context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_add: &mut [&mut AddNodeItem],
    ) -> Result<(), StatusCode> {
        let mut address_space = address_space.write();
        for item in nodes_to_add.iter_mut() {
            let node_id = if item.requested_new_node_id().is_null() {
                let n = self
                    .added_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                NodeId::new(self.ns_idx, format!("Added.{n}"))
            } else {
                item.requested_new_node_id().clone()
            };
            if node_id.namespace != self.ns_idx {
                item.set_result(NodeId::null(), StatusCode::BadNodeIdRejected);
                continue;
            }
            if address_space.node_exists(&node_id) {
                item.set_result(NodeId::null(), StatusCode::BadNodeIdExists);
                continue;
            }
            let parent = item.parent_node_id().node_id.clone();
            if !address_space.node_exists(&parent) {
                item.set_result(NodeId::null(), StatusCode::BadParentNodeIdInvalid);
                continue;
            }
            if !matches!(item.node_class(), NodeClass::Variable | NodeClass::Object) {
                item.set_result(NodeId::null(), StatusCode::BadNodeClassInvalid);
                continue;
            }
            let node = match new_node_from_attributes(
                node_id.clone(),
                item.browse_name().clone(),
                item.node_class(),
                item.node_attributes().clone(),
            ) {
                Ok(n) => n,
                Err(e) => {
                    item.set_result(NodeId::null(), e);
                    continue;
                }
            };
            let ref_type = item.reference_type_id().clone();
            let type_def = item.type_definition_id().node_id.clone();
            address_space.insert(node, None::<&[(_, &NodeId, _)]>);
            address_space.insert_reference(&parent, &node_id, ref_type);
            if !type_def.is_null() {
                address_space.insert_reference(
                    &node_id,
                    &type_def,
                    ReferenceTypeId::HasTypeDefinition,
                );
            }
            item.set_result(node_id, StatusCode::Good);
        }
        Ok(())
    }

    async fn delete_nodes(
        &self,
        _context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        nodes_to_delete: &mut [&mut DeleteNodeItem],
    ) -> Result<(), StatusCode> {
        let mut address_space = address_space.write();
        for item in nodes_to_delete.iter_mut() {
            if address_space
                .delete(item.node_id(), item.delete_target_references())
                .is_none()
            {
                item.set_result(StatusCode::BadNodeIdUnknown);
            } else {
                item.set_result(StatusCode::Good);
            }
        }
        Ok(())
    }

    async fn delete_node_references(
        &self,
        _context: &RequestContext,
        address_space: &RwLock<AddressSpace>,
        to_delete: &[&DeleteNodeItem],
    ) {
        let mut address_space = address_space.write();
        for item in to_delete {
            address_space.delete_node_references(item.node_id(), item.delete_target_references());
        }
    }
}

pub type InteropNodeManager = InMemoryNodeManager<InteropImpl>;

// ── Behaviours and events ───────────────────────────────────────────────────

fn spawn_behavior(
    b: &BehaviorDef,
    nm: Arc<InteropNodeManager>,
    subs: Arc<opcua::server::SubscriptionCache>,
    ns: u16,
    token: tokio_util::sync::CancellationToken,
) {
    let id = fixture_node_id(&b.target, ns);
    let interval = Duration::from_millis(b.interval_ms.unwrap_or(1000).max(10));
    let initial = b.initial.as_ref().and_then(|v| v.as_f64()).unwrap_or(0.0);
    let inc = b.increment.unwrap_or(1.0);
    let min = b.minimum.unwrap_or(0.0);
    let max = b.maximum.unwrap_or(100.0);
    let kind = b.kind.clone();
    if !matches!(kind.as_str(), "counter" | "toggle" | "ramp") {
        if kind != "fixed-status" {
            log::warn!("unknown behaviour kind {kind} for {}", b.target);
        }
        return;
    }
    // The value type follows the node's DataType.
    let is_int64 = {
        let a = nm.address_space().read();
        match a.find(&id) {
            Some(NodeType::Variable(v)) => v.data_type() == NodeId::from(DataTypeId::Int64),
            _ => false,
        }
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut counter: i64 = initial as i64;
        let mut toggle = false;
        let mut ramp = initial;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = token.cancelled() => return,
            }
            let v = match kind.as_str() {
                "counter" => {
                    let v = if is_int64 { Variant::Int64(counter) } else { Variant::Int32(counter as i32) };
                    counter += inc as i64;
                    v
                }
                "toggle" => {
                    let v = Variant::Boolean(toggle);
                    toggle = !toggle;
                    v
                }
                _ => {
                    let v = Variant::Double(ramp);
                    ramp += inc;
                    if ramp > max {
                        ramp = min;
                    }
                    v
                }
            };
            if let Err(e) = nm.set_value(&subs, &id, None, DataValue::new_now(v)) {
                log::warn!("behaviour update of {id} failed: {e}");
            }
        }
    });
}

fn spawn_events(
    subs: Arc<opcua::server::SubscriptionCache>,
    ns: u16,
    token: tokio_util::sync::CancellationToken,
) {
    let source = NodeId::new(ns, EVENTS_SOURCE);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut n: u64 = 0;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = token.cancelled() => return,
            }
            n += 1;
            let mut id = n.to_be_bytes().to_vec();
            id.extend_from_slice(b"interop-event");
            let event = BaseEventType::new(
                ObjectTypeId::BaseEventType,
                ByteString::from(id),
                LocalizedText::new("en", "peer-event"),
                DateTime::now(),
            )
            .set_source_node(source.clone())
            .set_source_name(UAString::from(EVENTS_SOURCE))
            .set_severity(500);
            let server: NodeId = ObjectId::Server.into();
            subs.notify_events(
                [
                    (&event as &dyn Event, &source),
                    (&event as &dyn Event, &server),
                ]
                .into_iter(),
            );
        }
    });
}

// ── Ready file ──────────────────────────────────────────────────────────────

fn write_ready_file(path: &str, fixture_id: &str, endpoint: &str) -> std::io::Result<()> {
    let p = Path::new(path);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let content = serde_json::json!({
        "ready": true,
        "adapter": ADAPTER,
        "fixture": fixture_id,
        "endpoint": endpoint,
    });
    let tmp = PathBuf::from(format!("{path}.tmp"));
    std::fs::write(&tmp, format!("{content}\n"))?;
    std::fs::rename(&tmp, p)
}

fn policy_from_name(name: &str) -> Option<SecurityPolicy> {
    Some(match name {
        "None" => SecurityPolicy::None,
        "Basic128Rsa15" => SecurityPolicy::Basic128Rsa15,
        "Basic256" => SecurityPolicy::Basic256,
        "Basic256Sha256" => SecurityPolicy::Basic256Sha256,
        "Aes128_Sha256_RsaOaep" => SecurityPolicy::Aes128Sha256RsaOaep,
        "Aes256_Sha256_RsaPss" => SecurityPolicy::Aes256Sha256RsaPss,
        _ => return None,
    })
}

fn mode_from_name(name: &str) -> Option<MessageSecurityMode> {
    Some(match name {
        "None" => MessageSecurityMode::None,
        "Sign" => MessageSecurityMode::Sign,
        "SignAndEncrypt" => MessageSecurityMode::SignAndEncrypt,
        _ => return None,
    })
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub async fn run(args: &[String]) -> i32 {
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let fixture = match fixture::load(&a.fixture) {
        Ok(f) => Arc::new(f),
        Err(e) => {
            eprintln!("[{ADAPTER}] error: {e}");
            return 1;
        }
    };
    eprintln!("[{ADAPTER}] info: fixture loaded: id={}", fixture.id);
    let _ = std::fs::remove_file(&a.ready_file);

    let bind_port = a.bind_port.unwrap_or(fixture.endpoint.port);
    let advertised_port = a.advertised_port.unwrap_or(bind_port);
    let path = a
        .endpoint_path
        .clone()
        .unwrap_or_else(|| fixture.endpoint.path.clone());
    let advertised = format!("opc.tcp://{}:{}{}", a.advertised_host, advertised_port, path);
    if advertised_port != bind_port {
        eprintln!(
            "[{ADAPTER}] warn: async-opcua advertises the port it is bound to; endpoint \
             descriptions carry port {bind_port}, not --advertised-port {advertised_port}"
        );
    }

    // Stack PKI.
    let stack_pki = std::env::temp_dir().join(format!("async-opcua-server-pki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stack_pki);
    let mut app_uri = fixture.server.application_uri.clone();
    let mut have_cert = false;
    let mut cert_paths: Option<(PathBuf, PathBuf)> = None;
    match (&a.certificate, &a.private_key) {
        (Some(c), Some(k)) => {
            match crate::pki::prepare_stack_pki(&stack_pki, Path::new(c), Path::new(k)) {
                Ok(p) => {
                    if let Ok(der) = crate::pki::read_cert_der(Path::new(c)) {
                        if let Some(u) = crate::pki::cert_application_uri(&der) {
                            app_uri = u;
                        }
                    }
                    let n = crate::pki::import_trusted_dir(Path::new(&a.pki_dir), &p.dir);
                    eprintln!(
                        "[{ADAPTER}] info: server certificate loaded from {c}; {n} certificate(s) from {}/trusted/certs trusted",
                        a.pki_dir
                    );
                    cert_paths = Some((p.cert_path, p.key_path));
                    have_cert = true;
                }
                Err(e) => {
                    eprintln!("[{ADAPTER}] error: cannot load server certificate or key: {e}");
                    return 6;
                }
            }
        }
        (None, None) => {
            if let Err(e) = crate::pki::prepare_empty_pki(&stack_pki) {
                eprintln!("[{ADAPTER}] error: {e}");
                return 6;
            }
        }
        _ => {
            eprintln!("[{ADAPTER}] error: --certificate and --private-key must be given together");
            return 2;
        }
    }

    let ready = Arc::new(tokio::sync::Notify::new());
    let token = tokio_util::sync::CancellationToken::new();

    let mut builder = ServerBuilder::new()
        .application_name(fixture.server.application_name.clone())
        .application_uri(app_uri.clone())
        .product_uri(fixture.server.product_uri.clone())
        .build_info(BuildInfo {
            product_uri: UAString::from(fixture.server.product_uri.as_str()),
            manufacturer_name: UAString::from("OTFabric"),
            product_name: UAString::from("opcua-interop-async-opcua"),
            software_version: UAString::from(ADAPTER_VERSION),
            build_number: UAString::from(STACK_VERSION),
            build_date: DateTime::now(),
        })
        .host(a.advertised_host.clone())
        .port(bind_port)
        .discovery_urls(vec![advertised.clone()])
        .pki_dir(stack_pki.clone())
        .create_sample_keypair(false)
        .trust_client_certs(false)
        .token(token.clone())
        .with_node_manager(InMemoryNodeManagerBuilder::new(InteropImplBuilder {
            fixture: fixture.clone(),
            ready: ready.clone(),
        }));
    if let Some((c, k)) = &cert_paths {
        builder = builder.certificate_path(c.clone()).private_key_path(k.clone());
    }
    // The contract's lifetimes / sampling expectations.
    builder.config_mut().reverse_connect_failure_delay_ms = a.reverse_connect_interval_ms;
    {
        let limits = builder.limits_mut();
        limits.subscriptions.min_sampling_interval_ms = 0.0;
        limits.subscriptions.min_publishing_interval_ms = 10.0;
    }

    let mut token_ids: Vec<String> = vec![ANONYMOUS_USER_TOKEN_ID.to_owned()];
    for u in &fixture.users {
        builder = builder.add_user_token(
            u.username.clone(),
            ServerUserToken::user_pass(u.username.clone(), u.password.clone().unwrap_or_default()),
        );
        token_ids.push(u.username.clone());
    }
    let ids: Vec<&str> = token_ids.iter().map(|s| s.as_str()).collect();
    builder = builder.add_endpoint(
        "none",
        ServerEndpoint::from((path.as_str(), SecurityPolicy::None, MessageSecurityMode::None, ids.as_slice())),
    );
    if have_cert {
        for sp in &fixture.security_profiles {
            if sp.security_policy == "None" {
                continue;
            }
            let (Some(pol), Some(mode)) = (
                policy_from_name(&sp.security_policy),
                mode_from_name(&sp.security_mode),
            ) else {
                eprintln!(
                    "[{ADAPTER}] info: skipping security profile {}/{}: not implemented by async-opcua 0.19",
                    sp.security_policy, sp.security_mode
                );
                continue;
            };
            let id = format!("{}_{}", sp.security_policy, sp.security_mode);
            builder = builder.add_endpoint(
                id,
                ServerEndpoint::from((path.as_str(), pol, mode, ids.as_slice())),
            );
            eprintln!(
                "[{ADAPTER}] info: secure endpoint {}/{}",
                sp.security_policy, sp.security_mode
            );
        }
    }

    let (server, handle) = match builder.build() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[{ADAPTER}] error: server configuration rejected: {e}");
            return 1;
        }
    };

    let listener = match tokio::net::TcpListener::bind((a.bind_address.as_str(), bind_port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[{ADAPTER}] error: cannot bind {}:{bind_port}: {e}", a.bind_address);
            return 1;
        }
    };

    let ready_wait = ready.notified();
    let server_task = tokio::spawn(server.run_with(listener));
    tokio::select! {
        _ = ready_wait => {}
        r = tokio::time::sleep(Duration::from_secs(60)) => {
            let _ = r;
            eprintln!("[{ADAPTER}] error: address space was not initialised within 60 s");
            return 1;
        }
    }

    let nm = handle
        .node_managers()
        .get_of_type::<InteropNodeManager>()
        .expect("interop node manager");
    let ns = nm.inner().ns();
    let subs = handle.subscriptions().clone();
    for b in &fixture.behaviors {
        spawn_behavior(b, nm.clone(), subs.clone(), ns, token.clone());
    }
    spawn_events(subs.clone(), ns, token.clone());

    for (i, target) in a.reverse_connect.iter().enumerate() {
        let hostport = target
            .trim_start_matches("opc.tcp://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        let addr = match tokio::net::lookup_host(hostport.as_str()).await {
            Ok(mut it) => it.next(),
            Err(e) => {
                eprintln!("[{ADAPTER}] error: --reverse-connect {target}: {e}");
                None
            }
        };
        let Some(addr) = addr else {
            return 2;
        };
        handle.add_reverse_connect_target(ReverseConnectTargetConfig {
            address: addr,
            endpoint_url: advertised.clone(),
            id: format!("reverse-{i}"),
        });
        eprintln!("[{ADAPTER}] info: reverse connect to {target} ({addr})");
    }

    if let Some(lds) = &a.register_with {
        crate::discovery::spawn_registration(
            lds.clone(),
            app_uri.clone(),
            fixture.server.product_uri.clone(),
            fixture.server.application_name.clone(),
            advertised.clone(),
            a.register_interval_ms,
            token.clone(),
        );
    }

    if let Err(e) = write_ready_file(&a.ready_file, &fixture.id, &advertised) {
        eprintln!("[{ADAPTER}] error: cannot write ready file {}: {e}", a.ready_file);
        if a.ready_file_explicit {
            return 6;
        }
    } else {
        eprintln!("[{ADAPTER}] info: ready file written: {}", a.ready_file);
    }
    eprintln!("[{ADAPTER}] info: server started on {}:{bind_port}, advertised {advertised}", a.bind_address);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("SIGINT handler");
    let mut server_task = server_task;
    let code = tokio::select! {
        _ = sigterm.recv() => 0,
        _ = sigint.recv() => 0,
        r = &mut server_task => {
            eprintln!("[{ADAPTER}] error: server stopped: {r:?}");
            1
        }
    };
    eprintln!("[{ADAPTER}] info: shutting down");
    if let Some(lds) = &a.register_with {
        crate::discovery::unregister(
            lds,
            &app_uri,
            &fixture.server.product_uri,
            &fixture.server.application_name,
            &advertised,
        )
        .await;
    }
    token.cancel();
    handle.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    let _ = std::fs::remove_file(&a.ready_file);
    let _ = std::fs::remove_dir_all(&stack_pki);
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(nodes: Value, behaviors: Value) -> crate::fixture::Fixture {
        serde_json::from_value(json!({
            "schemaVersion": "1.0",
            "id": "unit",
            "server": {"applicationUri": "urn:x", "productUri": "urn:x", "applicationName": "x"},
            "endpoint": {"path": "/opcua-interop", "port": 4840},
            "namespaces": [{"alias": "interop", "uri": INTEROP_NS}],
            "nodes": nodes,
            "behaviors": behaviors,
            "securityProfiles": [
                {"securityPolicy": "None", "securityMode": "None"},
                {"securityPolicy": "Basic256Sha256", "securityMode": "SignAndEncrypt"},
                {"securityPolicy": "ECC_nistP256", "securityMode": "Sign"}
            ]
        }))
        .unwrap()
    }

    fn var(id: &str, dt: &str, rank: i32, value: Value) -> Value {
        json!({
            "nodeClass": "Variable", "nodeId": format!("nsu={INTEROP_NS};s={id}"),
            "browseName": format!("1:{id}"), "displayName": id,
            "parentNodeId": format!("nsu={INTEROP_NS};s=Root"), "referenceType": "HasComponent",
            "dataType": dt, "valueRank": rank, "initialValue": value
        })
    }

    fn root() -> Value {
        json!({
            "nodeClass": "Object", "nodeId": format!("nsu={INTEROP_NS};s=Root"),
            "browseName": "1:Root", "displayName": "Root",
            "parentNodeId": "i=85", "referenceType": "Organizes"
        })
    }

    #[test]
    fn a_complete_fixture_has_no_problems() {
        let mut m = var("Matrix", "Int32", 2, json!([1, 2, 3, 4, 5, 6]));
        m["arrayDimensions"] = json!([3, 2]);
        let f = fixture(
            json!([
                root(),
                var("Int64", "Int64", -1, json!("-9223372036854775808")),
                var("Array", "String", 1, json!(["a", "b"])),
                var("Empty", "ByteString", -1, json!("")),
                m,
                {
                    "nodeClass": "Method", "nodeId": format!("nsu={INTEROP_NS};s=Add"),
                    "browseName": "1:Add", "displayName": "Add",
                    "parentNodeId": format!("nsu={INTEROP_NS};s=Root"), "referenceType": "HasComponent",
                    "methodBehavior": "Add",
                    "inputArguments": [{"name": "a", "dataType": "Int32"}, {"name": "b", "dataType": "Int32"}],
                    "outputArguments": [{"name": "sum", "dataType": "Int32"}]
                }
            ]),
            json!([{"target": format!("nsu={INTEROP_NS};s=Int64"), "kind": "counter"}]),
        );
        assert_eq!(fixture_problems(&f), Vec::<String>::new());
        assert_eq!(crate::fixture::problems(&f), Vec::<String>::new());
        let nd = f.nodes.iter().find(|n| n.node_id.ends_with("Matrix")).unwrap();
        let v = initial_value(nd).unwrap();
        assert_eq!(crate::values::matrix_dims(&v), Some(vec![3, 2]));
    }

    #[test]
    fn problems_are_reported() {
        let mut dup = root();
        dup["displayName"] = json!("again");
        let f = fixture(
            json!([
                root(),
                dup,
                var("Bad", "Int32", -1, json!("twelve")),
                var("Type", "Range", -1, json!(1)),
                {
                    "nodeClass": "Method", "nodeId": format!("nsu={INTEROP_NS};s=M"),
                    "browseName": "1:M", "displayName": "M",
                    "parentNodeId": format!("nsu={INTEROP_NS};s=Nowhere"), "referenceType": "HasComponent",
                    "methodBehavior": "Divide"
                },
                {
                    "nodeClass": "View", "nodeId": format!("nsu={INTEROP_NS};s=V"),
                    "browseName": "1:V", "displayName": "V",
                    "parentNodeId": "i=85", "referenceType": "Organizes"
                }
            ]),
            json!([{"target": format!("nsu={INTEROP_NS};s=Missing"), "kind": "sawtooth"}]),
        );
        let p = fixture_problems(&f).join("\n");
        for want in ["s=Bad: initial value", "dataType Range", "parent nsu=", "Divide", "node class View", "unknown kind", "Missing, which is not defined"] {
            assert!(p.contains(want), "{want:?} not in:\n{p}");
        }
        assert!(crate::fixture::problems(&f).iter().any(|e| e.contains("duplicate nodeId")));
    }

    #[test]
    fn method_behaviours() {
        let add = method_behavior("Add").unwrap();
        assert_eq!(add(&[Variant::Int32(10), Variant::Int32(20)]), Ok(vec![Variant::Int32(30)]));
        assert_eq!(add(&[Variant::Int32(i32::MAX), Variant::Int32(1)]), Ok(vec![Variant::Int32(i32::MIN)]));
        assert_eq!(add(&[Variant::Int32(1)]), Err(StatusCode::BadArgumentsMissing));
        assert_eq!(add(&[Variant::Double(1.0), Variant::Int32(1)]), Err(StatusCode::BadTypeMismatch));
        let mul = method_behavior("Multiply").unwrap();
        assert_eq!(mul(&[Variant::Double(1.5), Variant::Double(4.0)]), Ok(vec![Variant::Double(6.0)]));
        let mo = method_behavior("MultipleOutputs").unwrap();
        assert_eq!(mo(&[Variant::Int32(21)]), Ok(vec![Variant::Int32(42), Variant::String(UAString::from("21"))]));
        assert_eq!(method_behavior("Fail").unwrap()(&[]), Err(StatusCode::BadInternalError));
        assert_eq!(method_behavior("NoArguments").unwrap()(&[]), Ok(vec![Variant::Boolean(true)]));
        assert!(method_behavior("Divide").is_none());
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn server_flags() {
        let a = parse_args(&args(&[
            "--fixture", "/f.json", "--bind-port", "4841", "--reverse-connect", "opc.tcp://a:1",
            "--reverse-connect", "opc.tcp://b:2", "--register-interval-ms", "10",
        ]))
        .unwrap_or_else(|_| panic!("valid flags"));
        assert_eq!(a.fixture, "/f.json");
        assert_eq!(a.bind_port, Some(4841));
        assert_eq!(a.reverse_connect.len(), 2);
        assert_eq!(a.register_interval_ms, 500, "the registration interval has a floor");
        // Features async-opcua does not implement are refused (exit 2), not ignored.
        for f in ["--lds", "--mdns-name", "--pubsub-config"] {
            assert_eq!(parse_args(&args(&["--fixture", "/f.json", f, "x"])).err(), Some(2), "{f}");
        }
        assert_eq!(parse_args(&args(&["--fixture", "/f.json", "--bogus", "1"])).err(), Some(2));
        assert_eq!(parse_args(&args(&["--fixture", "/f.json", "--bind-port", "x"])).err(), Some(2));
        assert_eq!(parse_args(&args(&["--fixture"])).err(), Some(2));
    }

    #[test]
    fn fixture_ids_and_browse_names() {
        assert_eq!(fixture_node_id(&format!("nsu={INTEROP_NS};s=Scalar.Int32"), 2), NodeId::new(2, "Scalar.Int32"));
        assert_eq!(fixture_node_id("i=85", 2), NodeId::new(0, 85u32));
        assert_eq!(fixture_browse_name("1:Scalars", 3), QualifiedName::new(3, "Scalars"));
        assert_eq!(fixture_browse_name("0:Objects", 3), QualifiedName::new(0, "Objects"));
        assert_eq!(fixture_browse_name("Plain", 3), QualifiedName::new(3, "Plain"));
        assert_eq!(access_level(&None).bits(), AccessLevel::CURRENT_READ.bits());
        assert_eq!(
            access_level(&Some(vec!["CurrentWrite".into(), "HistoryRead".into()])).bits(),
            (AccessLevel::CURRENT_WRITE | AccessLevel::HISTORY_READ).bits()
        );
    }
}
