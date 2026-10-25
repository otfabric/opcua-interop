//! `client <subcmd>`: the client operations of CLIENT_CONTRACT §1–§9, built on
//! the async-opcua client.

use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use opcua::client::services::{
    CreateSubscription, DeleteMonitoredItems, DeleteSubscriptions, HistoryRead, Republish,
    TransferSubscriptions,
};
use opcua::client::reverse_connect::{ReverseConnectionSource, TcpConnectorReceiver};
use opcua::client::transport::ReverseTcpConnector;
use opcua::client::{
    ClientBuilder, HistoryReadAction, IdentityToken, MonitoredItemMap,
    OnSubscriptionNotificationCore, Session, UARequest,
};
use opcua::crypto::SecurityPolicy;
use opcua::types::{
    AddNodesItem, AttributeId, BrowseDescription, BrowseDescriptionResultMask, BrowseDirection,
    BrowsePath, ByteString, CallMethodRequest, LocalizedText, ContentFilter, ContentFilterElement,
    DataChangeFilter, DataChangeNotification, DataValue, DeadbandType, DeleteNodesItem,
    ElementOperand, EndpointDescription, EventFilter, EventNotificationList, ExpandedNodeId,
    ExtensionObject, FilterOperator, HistoryData, HistoryReadValueId, LiteralOperand,
    MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters,
    NodeClass, NodeId, NotificationMessage, NumericRange, ObjectId, ObjectTypeId, QualifiedName,
    ReadRawModifiedDetails, ReadValueId, ReferenceTypeId, RelativePath, RelativePathElement,
    SimpleAttributeOperand, StatusCode, TimestampsToReturn, UAString, Variant, VariableAttributes,
    VariableId, VariableTypeId, WriteValue, DataTypeId,
};
use serde_json::{json, Value};

use crate::common::{
    obj, status_json, Category, Envelope, Failure, EXIT_INPUT,
};
use crate::nodeid::{b64, b64_decode, fmt_node_id, parse_node_ref, resolve, NodeRef, Ns};
use crate::values::{
    fmt_datetime, localized_text_json, parse_datetime, parse_literal_lenient, variant_json,
};

// ── Flags ───────────────────────────────────────────────────────────────────

/// Flags that may be given without a value (then "true"): `alarms`, `push`,
/// `query` and `gds-pull` presence flags.
const BARE_FLAGS: [&str; 15] = [
    "--acknowledge",
    "--confirm",
    "--add-comment",
    "--issuer",
    "--csr",
    "--apply",
    "--cancel",
    "--get-certificates",
    "--create-self-signed",
    "--reset-to-defaults",
    "--transaction-diagnostics",
    "--include-subtypes",
    "--release-continuation-point",
    "--revoke",
    "--unregister",
];

pub struct Opts {
    pairs: Vec<(String, String)>,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut pairs = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if !a.starts_with("--") {
                return Err(format!("unexpected argument '{a}'"));
            }
            // Presence flags (`alarms --acknowledge`): a bare flag means true.
            if BARE_FLAGS.contains(&a.as_str()) && args.get(i + 1).is_none_or(|v| v.starts_with("--")) {
                pairs.push((a.clone(), "true".into()));
                i += 1;
                continue;
            }
            let Some(v) = args.get(i + 1) else {
                return Err(format!("missing value for {a}"));
            };
            pairs.push((a.clone(), v.clone()));
            i += 2;
        }
        Ok(Self { pairs })
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.pairs
            .iter()
            .rev()
            .find(|(f, _)| f == k)
            .map(|(_, v)| v.as_str())
    }

    pub fn all(&self, k: &str) -> Vec<String> {
        self.pairs
            .iter()
            .filter(|(f, _)| f == k)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> Result<T, Failure> {
        match self.get(k) {
            None => Ok(default),
            Some(v) => v
                .trim()
                .parse::<T>()
                .map_err(|_| Failure::input(format!("invalid value for {k}: '{v}'"))),
        }
    }

    fn bool(&self, k: &str, default: bool) -> Result<bool, Failure> {
        match self.get(k) {
            None => Ok(default),
            Some("true") | Some("1") => Ok(true),
            Some("false") | Some("0") => Ok(false),
            Some(v) => Err(Failure::input(format!("invalid value for {k}: '{v}' (true|false)"))),
        }
    }

    /// A presence flag (`--apply`, or `--apply true|false`).
    fn flag(&self, k: &str) -> Result<bool, Failure> {
        self.bool(k, false)
    }

    fn secs(&self, k: &str, default: f64) -> Result<Duration, Failure> {
        let v: f64 = self.num(k, default)?;
        Ok(Duration::from_millis((v * 1000.0).max(1.0) as u64))
    }

    fn required(&self, k: &str) -> Result<&str, Failure> {
        self.get(k)
            .ok_or_else(|| Failure::input(format!("missing required flag {k}")))
    }
}

fn parse_ref(s: &str) -> Result<NodeRef, Failure> {
    parse_node_ref(s).map_err(Failure::input)
}

fn timestamps(opts: &Opts) -> Result<TimestampsToReturn, Failure> {
    Ok(match opts.get("--timestamps").unwrap_or("Both") {
        "Source" => TimestampsToReturn::Source,
        "Server" => TimestampsToReturn::Server,
        "Both" => TimestampsToReturn::Both,
        "Neither" => TimestampsToReturn::Neither,
        other => {
            return Err(Failure::input(format!(
                "invalid --timestamps '{other}' (Source|Server|Both|Neither)"
            )))
        }
    })
}

// ── Security ────────────────────────────────────────────────────────────────

pub fn policy_from_name(name: &str) -> Result<SecurityPolicy, Failure> {
    Ok(match name {
        "None" => SecurityPolicy::None,
        "Basic128Rsa15" => SecurityPolicy::Basic128Rsa15,
        "Basic256" => SecurityPolicy::Basic256,
        "Basic256Sha256" => SecurityPolicy::Basic256Sha256,
        "Aes128_Sha256_RsaOaep" => SecurityPolicy::Aes128Sha256RsaOaep,
        "Aes256_Sha256_RsaPss" => SecurityPolicy::Aes256Sha256RsaPss,
        n if n.starts_with("ECC_") => {
            return Err(Failure::input(format!(
                "security policy {n} is not supported: async-opcua 0.19 implements no ECC security policies"
            )))
        }
        n => return Err(Failure::input(format!("unknown security policy '{n}'"))),
    })
}

fn mode_from_name(name: &str) -> Result<MessageSecurityMode, Failure> {
    Ok(match name {
        "None" => MessageSecurityMode::None,
        "Sign" => MessageSecurityMode::Sign,
        "SignAndEncrypt" => MessageSecurityMode::SignAndEncrypt,
        n => return Err(Failure::input(format!("unknown security mode '{n}'"))),
    })
}

fn mode_name(m: MessageSecurityMode) -> &'static str {
    match m {
        MessageSecurityMode::None => "None",
        MessageSecurityMode::Sign => "Sign",
        MessageSecurityMode::SignAndEncrypt => "SignAndEncrypt",
        _ => "Invalid",
    }
}

/// Everything needed to open a session, validated before any network I/O.
struct ConnectSpec {
    url: String,
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
    cert: Option<String>,
    key: Option<String>,
    trust: Vec<String>,
    username: Option<String>,
    password: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    disconnect_timeout: Duration,
    channel_lifetime: Option<u32>,
    application_uri: Option<String>,
    reverse_listen: Option<u16>,
    reverse_timeout: Duration,
    reverse_server_uri: Option<String>,
}

impl ConnectSpec {
    fn from_opts(opts: &Opts) -> Result<Self, Failure> {
        let url = opts.required("--endpoint")?.to_owned();
        let policy = policy_from_name(opts.get("--security-policy").unwrap_or("None"))?;
        let mode = mode_from_name(opts.get("--security-mode").unwrap_or("None"))?;
        if (policy == SecurityPolicy::None) != (mode == MessageSecurityMode::None) {
            return Err(Failure::input(
                "--security-policy None requires --security-mode None and vice versa",
            ));
        }
        let cert = opts.get("--certificate").map(str::to_owned);
        let key = opts.get("--private-key").map(str::to_owned);
        if policy != SecurityPolicy::None && (cert.is_none() || key.is_none()) {
            return Err(Failure::input(
                "--certificate and --private-key are required with a security policy other than None",
            ));
        }
        let channel_lifetime = match opts.get("--channel-lifetime-ms") {
            Some(_) => Some(opts.num::<u32>("--channel-lifetime-ms", 0)?),
            None => None,
        };
        let reverse_listen = match opts.get("--reverse-listen") {
            Some(_) => Some(opts.num::<u16>("--reverse-listen", 0)?),
            None => None,
        };
        Ok(Self {
            url,
            policy,
            mode,
            cert,
            key,
            trust: opts.all("--trust-list"),
            username: opts.get("--username").map(str::to_owned),
            password: opts.get("--password").unwrap_or("").to_owned(),
            connect_timeout: opts.secs("--connect-timeout", 5.0)?,
            request_timeout: opts.secs("--request-timeout", 5.0)?,
            disconnect_timeout: opts.secs("--disconnect-timeout", 2.0)?,
            channel_lifetime,
            application_uri: opts.get("--application-uri").map(str::to_owned),
            reverse_listen,
            reverse_timeout: Duration::from_millis(opts.num::<u64>("--reverse-timeout-ms", 30000)?),
            reverse_server_uri: opts.get("--reverse-server-uri").map(str::to_owned),
        })
    }
}

/// A connected session.
pub struct Conn {
    pub session: Arc<Session>,
    handle: tokio::task::JoinHandle<StatusCode>,
    namespaces: Option<Vec<String>>,
    pub request_timeout: Duration,
    disconnect_timeout: Duration,
    _pki: TempDir,
}

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(prefix: &str) -> TempDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    TempDir(std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id())))
}

fn status_of(e: &opcua::types::Error) -> StatusCode {
    e.status()
}

fn connect_failure(e: &opcua::types::Error, what: &str) -> Failure {
    let sc = status_of(e);
    if crate::common::is_timeout(sc) {
        return Failure::timeout(format!("{what}: {e}"));
    }
    // Identity / session level rejections are service results.
    let cat = if matches!(
        sc,
        StatusCode::BadUserAccessDenied
            | StatusCode::BadIdentityTokenInvalid
            | StatusCode::BadIdentityTokenRejected
            | StatusCode::BadSessionIdInvalid
            | StatusCode::BadTooManySessions
            | StatusCode::BadServiceUnsupported
    ) {
        Category::Service
    } else {
        Category::Transport
    };
    Failure::new(cat, sc, format!("{what}: {e}"))
}

fn endpoint_matches(ep: &EndpointDescription, policy: SecurityPolicy, mode: MessageSecurityMode) -> bool {
    ep.security_policy_uri.as_ref() == policy.to_uri() && ep.security_mode == mode
}

fn accept_any(_url: &str, _uri: &str) -> Result<(), StatusCode> {
    Ok(())
}

async fn connect(spec: &ConnectSpec) -> Result<Conn, Failure> {
    let pki = temp_dir("async-opcua-client-pki");
    let mut builder = ClientBuilder::new()
        .application_name("opcua-interop async-opcua client")
        .product_uri("urn:otfabric:opcua-interop")
        .pki_dir(pki.0.clone())
        .create_sample_keypair(false)
        .session_retry_limit(0)
        .session_retry_initial(Duration::from_millis(100))
        .session_timeout(60_000)
        .request_timeout(spec.request_timeout)
        .verify_server_certs(false)
        .trust_server_certs(spec.trust.is_empty());
    let mut app_uri = "urn:otfabric:opcua-interop:client:async-opcua".to_owned();
    if let (Some(c), Some(k)) = (&spec.cert, &spec.key) {
        let p = crate::pki::prepare_stack_pki(&pki.0, Path::new(c), Path::new(k))
            .map_err(|e| Failure::internal(format!("client certificate / key: {e}")))?;
        if let Ok(der) = crate::pki::read_cert_der(Path::new(c)) {
            if let Some(u) = crate::pki::cert_application_uri(&der) {
                app_uri = u;
            }
        }
        builder = builder.certificate_path(p.cert_path).private_key_path(p.key_path);
    } else {
        crate::pki::prepare_empty_pki(&pki.0).map_err(Failure::internal)?;
    }
    if let Some(u) = &spec.application_uri {
        app_uri = u.clone();
    }
    builder = builder.application_uri(app_uri);
    if let Some(l) = spec.channel_lifetime {
        builder = builder.channel_lifetime(l);
    }
    let client = builder
        .client()
        .map_err(|e| Failure::internal(format!("client configuration: {}", e.join("; "))))?;

    // Reverse connect: listen instead of dialling (Part 6 §7.1.3).
    let listener = match spec.reverse_listen {
        Some(port) => Some(Arc::new(
            tokio::net::TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| {
                Failure::transport(
                    StatusCode::BadCommunicationError,
                    format!("cannot listen on {port}: {e}"),
                )
            })?,
        )),
        None => None,
    };
    let get_timeout = if listener.is_some() {
        spec.reverse_timeout
    } else {
        spec.connect_timeout
    };

    // GetEndpoints and endpoint selection (§9).
    let eps = match &listener {
        None => {
            tokio::time::timeout(
                get_timeout,
                client.get_server_endpoints_from_url(spec.url.as_str()),
            )
            .await
        }
        Some(l) => {
            let none_ep = EndpointDescription::from((
                spec.url.as_str(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
            ));
            let connector = ReverseTcpConnector::new(
                TcpConnectorReceiver::Listener(l.clone()),
                Arc::new(accept_any),
                none_ep,
            );
            tokio::time::timeout(get_timeout, client.get_server_endpoints_from_url(connector)).await
        }
    }
    .map_err(|_| Failure::timeout(format!("GetEndpoints on {} timed out", spec.url)))?
    .map_err(|e| connect_failure(&e, "GetEndpoints"))?;
    let Some(mut ep) = eps
        .iter()
        .find(|e| endpoint_matches(e, spec.policy, spec.mode))
        .cloned()
    else {
        return Err(Failure::transport(
            StatusCode::BadSecurityPolicyRejected,
            format!(
                "no endpoint with SecurityPolicy={} and MessageSecurityMode={} at {}",
                spec.policy.to_uri(),
                mode_name(spec.mode),
                spec.url
            ),
        ));
    };
    if listener.is_none() {
        ep.endpoint_url = UAString::from(spec.url.as_str());
    }

    // --trust-list: chain validation done by the adapter (see pki.rs).
    if spec.policy != SecurityPolicy::None && !spec.trust.is_empty() {
        let anchors: Vec<Vec<u8>> = spec
            .trust
            .iter()
            .filter_map(|t| crate::pki::read_cert_der(Path::new(t)).ok())
            .collect();
        let server_der = ep.server_certificate.value.clone().unwrap_or_default();
        match crate::pki::validate_against(&server_der, &anchors) {
            Ok(()) => {
                // The leaf of a chain (X509::from_der takes one certificate).
                if let Ok(x) = opcua::crypto::X509::from_der(crate::pki::leaf_der(&server_der)) {
                    let _ = crate::pki::trust_in_stack(&pki.0, &x);
                }
            }
            Err(e) => log::warn!("server certificate not trusted: {e}"),
        }
    }

    let identity = match &spec.username {
        Some(u) => IdentityToken::new_user_name(u.clone(), spec.password.clone()),
        None => IdentityToken::Anonymous,
    };
    let (session, mut handle) = match &listener {
        None => {
            let (session, event_loop) = client
                .session_builder()
                .connect_to_endpoint_directly(ep)
                .map_err(|e| connect_failure(&e, "session"))?
                .user_identity_token(identity)
                .build(client.certificate_store().clone())
                .map_err(|e| connect_failure(&e, "session"))?;
            (session, event_loop.spawn())
        }
        Some(l) => {
            let (session, event_loop) = client
                .session_builder()
                .with_connector(
                    ReverseConnectionSource::new_listener(l.clone()).with_verifier(accept_any),
                )
                .connect_to_endpoint_directly(ep)
                .map_err(|e| connect_failure(&e, "session"))?
                .user_identity_token(identity)
                .build(client.certificate_store().clone())
                .map_err(|e| connect_failure(&e, "session"))?;
            (session, event_loop.spawn())
        }
    };
    let deadline = if listener.is_some() {
        spec.reverse_timeout
    } else {
        spec.connect_timeout + spec.request_timeout
    };
    tokio::select! {
        ok = session.wait_for_connection() => {
            if !ok {
                let sc = match tokio::time::timeout(Duration::from_secs(2), &mut handle).await {
                    Ok(Ok(sc)) => sc,
                    _ => StatusCode::BadConnectionClosed,
                };
                return Err(connect_failure(&opcua::types::Error::new(sc, "connect failed"), "connect"));
            }
        }
        r = &mut handle => {
            let sc = r.unwrap_or(StatusCode::BadInternalError);
            let sc = if sc.is_good() { StatusCode::BadConnectionClosed } else { sc };
            return Err(connect_failure(&opcua::types::Error::new(sc, "connection failed"), "connect"));
        }
        _ = tokio::time::sleep(deadline) => {
            handle.abort();
            return Err(Failure::timeout(format!("connecting to {} timed out", spec.url)));
        }
    }
    let conn = Conn {
        session,
        handle,
        namespaces: None,
        request_timeout: spec.request_timeout,
        disconnect_timeout: spec.disconnect_timeout,
        _pki: pki,
    };
    if let Some(want) = &spec.reverse_server_uri {
        let rv = ReadValueId {
            node_id: VariableId::Server_ServerArray.into(),
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        };
        let got = conn
            .session
            .read(&[rv], TimestampsToReturn::Neither, 0.0)
            .await
            .ok()
            .and_then(|v| v.into_iter().next())
            .and_then(|dv| dv.value)
            .and_then(|v| match v {
                Variant::Array(a) => a.values.into_iter().next(),
                _ => None,
            })
            .and_then(|v| match v {
                Variant::String(s) => s.value().clone(),
                _ => None,
            })
            .unwrap_or_default();
        if &got != want {
            conn.close().await;
            return Err(Failure::transport(
                StatusCode::BadServerUriInvalid,
                format!("reverse-connected server's ServerArray[0] is '{got}', not '{want}'"),
            ));
        }
    }
    Ok(conn)
}

impl Conn {
    async fn namespaces(&mut self) -> Result<Vec<String>, Failure> {
        if let Some(n) = &self.namespaces {
            return Ok(n.clone());
        }
        let rv = ReadValueId {
            node_id: VariableId::Server_NamespaceArray.into(),
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        };
        let r = self
            .session
            .read(&[rv], TimestampsToReturn::Neither, 0.0)
            .await
            .map_err(|e| Failure::from_status(e.status(), format!("read NamespaceArray: {e}")))?;
        let mut out = Vec::new();
        if let Some(Variant::Array(a)) = r.first().and_then(|d| d.value.clone()) {
            for v in a.values {
                if let Variant::String(s) = v {
                    out.push(s.value().clone().unwrap_or_default());
                }
            }
        }
        self.namespaces = Some(out.clone());
        Ok(out)
    }

    async fn resolve(&mut self, r: &NodeRef) -> Result<NodeId, Failure> {
        let ns = if matches!(r.ns, Ns::Uri(_)) {
            self.namespaces().await?
        } else {
            Vec::new()
        };
        resolve(r, &ns).map_err(Failure::input)
    }

    async fn close(self) {
        let _ = tokio::time::timeout(self.disconnect_timeout, self.session.disconnect()).await;
        self.handle.abort();
    }
}

fn svc_err(e: opcua::types::Error, what: &str) -> Failure {
    Failure::from_status(e.status(), format!("{what}: {e}"))
}

// ── Entry ───────────────────────────────────────────────────────────────────

pub const OPERATIONS: [&str; 20] = [
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
    "alarms",
    "history-read",
    "republish",
    "transfer-subscriptions",
    "register-nodes",
    "node-management",
    "register-server",
    "push",
    "query",
    "gds-pull",
];

pub async fn run(args: &[String]) -> i32 {
    let Some(sub) = args.first() else {
        eprintln!("usage: client <subcmd> --endpoint <url> [flags]");
        return EXIT_INPUT;
    };
    let rest = &args[1..];
    if sub == "codec" {
        return crate::codec::run(rest).await;
    }
    if sub == "find-servers-on-network" {
        return run_op(sub, rest, |o| Box::pin(op_find_servers_on_network(o))).await;
    }
    if sub == "history-read" && rest.is_empty() {
        // Usage text (consumers probe for the continue scenario).
        eprintln!(
            "usage: client history-read --endpoint <url> --node <id> --start <rfc3339> --end <rfc3339> \
             [--num-values n] [--continuation-point b64] [--release-continuation-point true|false] \
             [--return-bounds true|false] [--timestamps ..] [--scenario continue]"
        );
        let env = Envelope::new("history-read").fail(&Failure::input(
            "missing --endpoint, --node, --start, or --end [--scenario continue]",
        ));
        return env.emit();
    }
    match sub.as_str() {
        "endpoints" => run_op(sub, rest, |o| Box::pin(op_endpoints(o))).await,
        "find-servers" => run_op(sub, rest, |o| Box::pin(op_find_servers(o))).await,
        "read" => run_op(sub, rest, |o| Box::pin(op_read(o))).await,
        "write" => run_op(sub, rest, |o| Box::pin(op_write(o))).await,
        "browse" => run_op(sub, rest, |o| Box::pin(op_browse(o))).await,
        "translate" => run_op(sub, rest, |o| Box::pin(op_translate(o))).await,
        "call" => run_op(sub, rest, |o| Box::pin(op_call(o))).await,
        "subscribe" => run_op(sub, rest, |o| Box::pin(op_subscribe(o))).await,
        "subscription-lifecycle" => run_op(sub, rest, |o| Box::pin(op_lifecycle(o))).await,
        "event-subscribe" => run_op(sub, rest, |o| Box::pin(op_events(o))).await,
        "alarms" => run_op(sub, rest, |o| Box::pin(op_alarms(o))).await,
        "history-read" => run_op(sub, rest, |o| Box::pin(op_history(o))).await,
        "republish" => run_op(sub, rest, |o| Box::pin(op_republish(o))).await,
        "transfer-subscriptions" => run_op(sub, rest, |o| Box::pin(op_transfer(o))).await,
        "register-nodes" => run_op(sub, rest, |o| Box::pin(op_register_nodes(o))).await,
        "node-management" => run_op(sub, rest, |o| Box::pin(op_node_management(o))).await,
        "register-server" => run_op(sub, rest, |o| Box::pin(op_register_server(o))).await,
        "push" => run_op(sub, rest, |o| Box::pin(push::op_push(o))).await,
        "query" => run_op(sub, rest, |o| Box::pin(query::op_query(o))).await,
        "gds-pull" => run_op(sub, rest, |o| Box::pin(gds_pull::op_gds_pull(o))).await,
        other => {
            let env = Envelope::new(other).fail(&Failure::input(format!(
                "unknown or unsupported client subcommand '{other}'"
            )));
            env.emit()
        }
    }
}

type OpFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Envelope> + Send + 'a>>;

async fn run_op<F>(name: &str, args: &[String], f: F) -> i32
where
    F: for<'a> FnOnce(&'a Opts) -> OpFuture<'a>,
{
    let opts = match Opts::parse(args) {
        Ok(o) => o,
        Err(e) => return Envelope::new(name).fail(&Failure::input(e)).emit(),
    };
    f(&opts).await.emit()
}

/// Run `body` with a connected session, turning failures into the envelope.
macro_rules! with_conn {
    ($op:expr, $opts:expr, |$conn:ident| $body:block) => {{
        let spec = match ConnectSpec::from_opts($opts) {
            Ok(s) => s,
            Err(f) => return Envelope::new($op).fail(&f),
        };
        #[allow(unused_mut)]
        let mut $conn = match connect(&spec).await {
            Ok(c) => c,
            Err(f) => return Envelope::new($op).fail(&f),
        };
        let res: Result<Envelope, Failure> = async { $body }.await;
        $conn.close().await;
        match res {
            Ok(e) => e,
            Err(f) => Envelope::new($op).fail(&f),
        }
    }};
}

// Part 12 push management, the Query service set and the GDS pull model
// (CLIENT_CONTRACT §15, §1 "query flags", §16.2); after `with_conn!`.
mod gds_pull;
mod part12;
mod push;
mod query;

// ── endpoints / find-servers ────────────────────────────────────────────────

async fn op_endpoints(opts: &Opts) -> Envelope {
    let op = "endpoints";
    let spec = match ConnectSpec::from_opts(opts) {
        Ok(s) => s,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    if let Some(port) = spec.reverse_listen {
        return match endpoints_reverse(&spec, port).await {
            Ok(eps) => endpoints_envelope(eps),
            Err(f) => Envelope::new(op).fail(&f),
        };
    }
    let tmp = temp_dir("async-opcua-ep");
    let client = match ClientBuilder::new()
        .application_name("opcua-interop async-opcua client")
        .application_uri("urn:otfabric:opcua-interop:client:async-opcua")
        .pki_dir(tmp.0.clone())
        .create_sample_keypair(false)
        .session_retry_limit(0)
        .request_timeout(spec.request_timeout)
        .client()
    {
        Ok(c) => c,
        Err(e) => return Envelope::new(op).fail(&Failure::internal(e.join("; "))),
    };
    let r = tokio::time::timeout(
        spec.connect_timeout + spec.request_timeout,
        client.get_server_endpoints_from_url(spec.url.as_str()),
    )
    .await;
    match r {
        Err(_) => Envelope::new(op).fail(&Failure::timeout("GetEndpoints timed out")),
        Ok(Err(e)) => Envelope::new(op).fail(&connect_failure(&e, "GetEndpoints")),
        Ok(Ok(eps)) => endpoints_envelope(eps),
    }
}

async fn endpoints_reverse(spec: &ConnectSpec, port: u16) -> Result<Vec<EndpointDescription>, Failure> {
    let tmp = temp_dir("async-opcua-ep");
    let client = ClientBuilder::new()
        .application_name("opcua-interop async-opcua client")
        .application_uri("urn:otfabric:opcua-interop:client:async-opcua")
        .pki_dir(tmp.0.clone())
        .create_sample_keypair(false)
        .session_retry_limit(0)
        .request_timeout(spec.request_timeout)
        .client()
        .map_err(|e| Failure::internal(e.join("; ")))?;
    let l = Arc::new(tokio::net::TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| {
        Failure::transport(
            StatusCode::BadCommunicationError,
            format!("cannot listen on {port}: {e}"),
        )
    })?);
    let none_ep = EndpointDescription::from((
        spec.url.as_str(),
        SecurityPolicy::None.to_str(),
        MessageSecurityMode::None,
    ));
    let connector =
        ReverseTcpConnector::new(TcpConnectorReceiver::Listener(l), Arc::new(accept_any), none_ep);
    tokio::time::timeout(spec.reverse_timeout, client.get_server_endpoints_from_url(connector))
        .await
        .map_err(|_| Failure::timeout("no reverse connection within --reverse-timeout-ms"))?
        .map_err(|e| connect_failure(&e, "GetEndpoints"))
}

pub fn endpoints_envelope(eps: Vec<EndpointDescription>) -> Envelope {
    let mut env = Envelope::new("endpoints");
    for ep in eps {
        let tokens: Vec<Value> = ep
            .user_identity_tokens
            .iter()
            .flatten()
            .map(|t| {
                json!({
                    "policyId": t.policy_id.as_ref(),
                    "tokenType": format!("{:?}", t.token_type),
                })
            })
            .collect();
        env.results.push(obj(vec![
            ("url", json!(ep.endpoint_url.as_ref())),
            ("securityPolicy", json!(ep.security_policy_uri.as_ref())),
            ("securityMode", json!(mode_name(ep.security_mode))),
            ("securityLevel", json!(ep.security_level)),
            ("userIdentityTokens", Value::Array(tokens)),
        ]));
    }
    env
}

async fn op_find_servers(opts: &Opts) -> Envelope {
    let op = "find-servers";
    let spec = match ConnectSpec::from_opts(opts) {
        Ok(s) => s,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let tmp = temp_dir("async-opcua-fs");
    let client = match ClientBuilder::new()
        .application_name("opcua-interop async-opcua client")
        .application_uri("urn:otfabric:opcua-interop:client:async-opcua")
        .pki_dir(tmp.0.clone())
        .create_sample_keypair(false)
        .session_retry_limit(0)
        .request_timeout(spec.request_timeout)
        .client()
    {
        Ok(c) => c,
        Err(e) => return Envelope::new(op).fail(&Failure::internal(e.join("; "))),
    };
    let r = tokio::time::timeout(
        spec.connect_timeout + spec.request_timeout,
        client.find_servers(spec.url.as_str(), None, None),
    )
    .await;
    match r {
        Err(_) => Envelope::new(op).fail(&Failure::timeout("FindServers timed out")),
        Ok(Err(e)) => Envelope::new(op).fail(&connect_failure(&e, "FindServers")),
        Ok(Ok(apps)) => {
            let mut env = Envelope::new(op);
            for a in apps {
                env.results.push(obj(vec![
                    ("applicationUri", json!(a.application_uri.as_ref())),
                    ("applicationName", localized_text_json(&a.application_name)),
                    ("productUri", json!(a.product_uri.as_ref())),
                    ("applicationType", json!(format!("{:?}", a.application_type))),
                    (
                        "discoveryUrls",
                        json!(a
                            .discovery_urls
                            .iter()
                            .flatten()
                            .map(|u| u.as_ref().to_owned())
                            .collect::<Vec<_>>()),
                    ),
                ]));
            }
            env
        }
    }
}

// ── read / write ────────────────────────────────────────────────────────────

fn read_item_json(node: &NodeId, dv: &DataValue) -> Value {
    let (dt, bit, val) = match &dv.value {
        Some(v) => variant_json(v),
        None => ("Null".to_owned(), 0, Value::Null),
    };
    let mut pairs = vec![
        ("nodeId", json!(fmt_node_id(node))),
        ("statusCode", status_json(dv.status())),
        ("dataType", json!(dt)),
        ("builtInType", json!(bit)),
        ("value", val),
    ];
    if let Some(d) = crate::values::matrix_dims(dv.value.as_ref().unwrap_or(&Variant::Empty)) {
        pairs.push(("arrayDimensions", json!(d)));
    }
    if let Some(t) = &dv.source_timestamp {
        pairs.push(("sourceTimestamp", json!(fmt_datetime(t))));
    }
    if let Some(t) = &dv.server_timestamp {
        pairs.push(("serverTimestamp", json!(fmt_datetime(t))));
    }
    obj(pairs)
}

fn index_range(opts: &Opts) -> Result<NumericRange, Failure> {
    match opts.get("--index-range") {
        None => Ok(NumericRange::None),
        Some(s) => s
            .parse::<NumericRange>()
            .map_err(|_| Failure::input(format!("invalid --index-range '{s}'"))),
    }
}

async fn op_read(opts: &Opts) -> Envelope {
    let op = "read";
    let nodes = opts.all("--node");
    if nodes.is_empty() {
        return Envelope::new(op).fail(&Failure::input("missing --node"));
    }
    let refs: Result<Vec<NodeRef>, Failure> = nodes.iter().map(|n| parse_ref(n)).collect();
    let refs = match refs {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let range = match index_range(opts) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let ts = match timestamps(opts) {
        Ok(t) => t,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let mut ids = Vec::new();
        for r in &refs {
            ids.push(conn.resolve(r).await?);
        }
        let rvs: Vec<ReadValueId> = ids
            .iter()
            .map(|id| ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::Value as u32,
                index_range: range.clone(),
                data_encoding: QualifiedName::null(),
            })
            .collect();
        let dvs = conn
            .session
            .read(&rvs, ts, 0.0)
            .await
            .map_err(|e| svc_err(e, "Read"))?;
        let mut env = Envelope::new(op);
        let mut first_bad = None;
        for (id, dv) in ids.iter().zip(dvs.iter()) {
            env.results.push(read_item_json(id, dv));
            if !dv.status().is_good() && first_bad.is_none() {
                first_bad = Some(dv.status());
            }
        }
        if ids.len() == 1 {
            env.service_result = dvs.first().map(|d| d.status()).unwrap_or(StatusCode::Good);
        }
        if let Some(b) = first_bad {
            env.success = false;
            if ids.len() != 1 {
                env.service_result = b;
            }
            env.error = Some((Category::Service, "one or more reads were not Good".into()));
        }
        Ok(env)
    })
}

async fn op_write(opts: &Opts) -> Envelope {
    let op = "write";
    let nodes = opts.all("--node");
    let types = opts.all("--type");
    let values = opts.all("--value");
    if nodes.is_empty() || nodes.len() != types.len() || nodes.len() != values.len() {
        return Envelope::new(op).fail(&Failure::input(
            "write requires equal counts of --node, --type and --value",
        ));
    }
    let refs: Result<Vec<NodeRef>, Failure> = nodes.iter().map(|n| parse_ref(n)).collect();
    let refs = match refs {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let range = match index_range(opts) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let mut ids = Vec::new();
        for r in &refs {
            ids.push(conn.resolve(r).await?);
        }
        let wvs: Vec<WriteValue> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| WriteValue {
                node_id: id.clone(),
                attribute_id: AttributeId::Value as u32,
                index_range: range.clone(),
                value: DataValue::value_only(parse_literal_lenient(&types[i], &values[i])),
            })
            .collect();
        let scs = conn
            .session
            .write(&wvs)
            .await
            .map_err(|e| svc_err(e, "Write"))?;
        let mut env = Envelope::new(op);
        let mut first_bad = None;
        for (id, sc) in ids.iter().zip(scs.iter()) {
            env.results.push(obj(vec![
                ("nodeId", json!(fmt_node_id(id))),
                ("statusCode", status_json(*sc)),
            ]));
            if !sc.is_good() && first_bad.is_none() {
                first_bad = Some(*sc);
            }
        }
        if ids.len() == 1 {
            env.service_result = scs.first().copied().unwrap_or(StatusCode::Good);
        }
        if let Some(b) = first_bad {
            env.success = false;
            env.service_result = b;
            env.error = Some((Category::Service, "write was not Good".into()));
        }
        Ok(env)
    })
}

// ── browse / translate ──────────────────────────────────────────────────────

fn node_class_name(nc: NodeClass) -> &'static str {
    match nc {
        NodeClass::Object => "Object",
        NodeClass::Variable => "Variable",
        NodeClass::Method => "Method",
        NodeClass::ObjectType => "ObjectType",
        NodeClass::VariableType => "VariableType",
        NodeClass::ReferenceType => "ReferenceType",
        NodeClass::DataType => "DataType",
        NodeClass::View => "View",
        _ => "Unspecified",
    }
}

fn local(id: &ExpandedNodeId) -> NodeId {
    id.node_id.clone()
}

async fn op_browse(opts: &Opts) -> Envelope {
    let op = "browse";
    let r = match parse_ref(opts.get("--node").unwrap_or("i=85")) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let max_refs: u32 = match opts.num("--max-refs", 0) {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let node_class_mask: u32 = match opts.num("--node-class-mask", 0) {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let include_subtypes = match opts.bool("--include-subtypes", true) {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let result_mask: u32 = match opts.num("--result-mask", 63) {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let id = conn.resolve(&r).await?;
        let bd = BrowseDescription {
            node_id: id,
            browse_direction: BrowseDirection::Forward,
            reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
            include_subtypes,
            node_class_mask,
            result_mask: BrowseDescriptionResultMask::from_bits_truncate(result_mask).bits(),
        };
        let results = conn
            .session
            .browse(&[bd], max_refs, None)
            .await
            .map_err(|e| svc_err(e, "Browse"))?;
        let first = results.into_iter().next().ok_or_else(|| {
            Failure::service(StatusCode::BadUnexpectedError, "empty Browse response")
        })?;
        let sc = first.status_code;
        let mut refs = first.references.unwrap_or_default();
        let mut cp = first.continuation_point;
        let mut guard = 0;
        while !cp.is_null_or_empty() && guard < 1000 {
            guard += 1;
            let next = conn
                .session
                .browse_next(false, &[cp.clone()])
                .await
                .map_err(|e| svc_err(e, "BrowseNext"))?;
            let Some(n) = next.into_iter().next() else { break };
            refs.extend(n.references.unwrap_or_default());
            cp = n.continuation_point;
        }
        let mut env = Envelope::new(op);
        env.service_result = sc;
        env.success = sc.is_good();
        if !sc.is_good() {
            env.error = Some((Category::Service, "Browse failed".into()));
        }
        for rd in refs {
            env.results.push(obj(vec![
                ("referenceTypeId", json!(fmt_node_id(&rd.reference_type_id))),
                ("isForward", json!(rd.is_forward)),
                ("nodeId", json!(fmt_node_id(&local(&rd.node_id)))),
                ("browseName", crate::values::qualified_name_json(&rd.browse_name)),
                ("displayName", localized_text_json(&rd.display_name)),
                ("nodeClass", json!(node_class_name(rd.node_class))),
            ]));
        }
        Ok(env)
    })
}

async fn op_translate(opts: &Opts) -> Envelope {
    let op = "translate";
    let start = match parse_ref(opts.get("--starting-node").unwrap_or("i=85")) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let path = match opts.required("--path") {
        Ok(p) => p.to_owned(),
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let segments: Vec<String> = path
        .split('.')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if segments.is_empty() {
        return Envelope::new(op).fail(&Failure::input("empty --path"));
    }
    let ns: u16 = match opts.num("--namespace", 0) {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let start_id = conn.resolve(&start).await?;
        let elements: Vec<RelativePathElement> = segments
            .iter()
            .map(|s| RelativePathElement {
                reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
                is_inverse: false,
                include_subtypes: true,
                target_name: QualifiedName::new(ns, s.as_str()),
            })
            .collect();
        let bp = BrowsePath {
            starting_node: start_id,
            relative_path: RelativePath {
                elements: Some(elements),
            },
        };
        let res = conn
            .session
            .translate_browse_paths_to_node_ids(&[bp])
            .await
            .map_err(|e| svc_err(e, "TranslateBrowsePathsToNodeIds"))?;
        let mut env = Envelope::new(op);
        let Some(r) = res.into_iter().next() else {
            return Err(Failure::service(StatusCode::BadUnexpectedError, "empty response"));
        };
        let targets: Vec<String> = r
            .targets
            .iter()
            .flatten()
            .map(|t| fmt_node_id(&local(&t.target_id)))
            .collect();
        env.results.push(obj(vec![
            ("statusCode", status_json(r.status_code)),
            ("targets", json!(targets)),
        ]));
        if !r.status_code.is_good() {
            env.success = false;
            env.service_result = r.status_code;
            env.error = Some((Category::Service, "browse path not resolved".into()));
        }
        Ok(env)
    })
}

// ── call ────────────────────────────────────────────────────────────────────

async fn op_call(opts: &Opts) -> Envelope {
    let op = "call";
    let (o, m) = match (opts.required("--object"), opts.required("--method")) {
        (Ok(o), Ok(m)) => (o.to_owned(), m.to_owned()),
        (Err(f), _) | (_, Err(f)) => return Envelope::new(op).fail(&f),
    };
    let (or, mr) = match (parse_ref(&o), parse_ref(&m)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(f), _) | (_, Err(f)) => return Envelope::new(op).fail(&f),
    };
    let inputs: Vec<Variant> = opts
        .all("--input")
        .iter()
        .filter_map(|spec| {
            spec.split_once(':')
                .map(|(t, v)| parse_literal_lenient(t, v))
        })
        .collect();
    with_conn!(op, opts, |conn| {
        let object_id = conn.resolve(&or).await?;
        let method_id = conn.resolve(&mr).await?;
        let req = CallMethodRequest {
            object_id: object_id.clone(),
            method_id: method_id.clone(),
            input_arguments: Some(inputs.clone()),
        };
        let res = conn
            .session
            .call(vec![req])
            .await
            .map_err(|e| svc_err(e, "Call"))?;
        let r = res
            .into_iter()
            .next()
            .ok_or_else(|| Failure::service(StatusCode::BadUnexpectedError, "empty Call response"))?;
        let outs: Vec<Value> = r
            .output_arguments
            .iter()
            .flatten()
            .map(crate::values::scalar_json)
            .collect();
        let mut env = Envelope::new(op);
        env.service_result = r.status_code;
        env.success = r.status_code.is_good();
        if !env.success {
            env.error = Some((Category::Service, "method call failed".into()));
        }
        env.results.push(obj(vec![
            ("objectNodeId", json!(fmt_node_id(&object_id))),
            ("methodNodeId", json!(fmt_node_id(&method_id))),
            ("statusCode", status_json(r.status_code)),
            ("outputArguments", Value::Array(outs)),
        ]));
        Ok(env)
    })
}

// ── Subscriptions ───────────────────────────────────────────────────────────

/// Forwards every NotificationMessage of a subscription to a channel.
struct Forward(tokio::sync::mpsc::UnboundedSender<NotificationMessage>);

impl OnSubscriptionNotificationCore for Forward {
    fn on_subscription_notification(
        &mut self,
        notification: NotificationMessage,
        _items: MonitoredItemMap<'_>,
    ) {
        let _ = self.0.send(notification);
    }
}

struct SubInfo {
    id: u32,
    revised_publishing_interval: f64,
    revised_lifetime: u32,
    revised_keep_alive: u32,
}

async fn create_subscription(
    conn: &Conn,
    publishing_interval_ms: f64,
    lifetime: u32,
    keep_alive: u32,
) -> Result<(SubInfo, tokio::sync::mpsc::UnboundedReceiver<NotificationMessage>), Failure> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let id = conn
        .session
        .create_subscription(
            Duration::from_micros((publishing_interval_ms * 1000.0).max(0.0) as u64),
            lifetime,
            keep_alive,
            0,
            0,
            true,
            Forward(tx),
        )
        .await
        .map_err(|e| svc_err(e, "CreateSubscription"))?;
    let (rpi, rlt, rka) = {
        let state = conn.session.subscription_state().lock();
        match state.get(id) {
            Some(s) => (
                s.publishing_interval().as_secs_f64() * 1000.0,
                s.lifetime_count(),
                s.max_keep_alive_count(),
            ),
            None => (publishing_interval_ms, lifetime, keep_alive),
        }
    };
    Ok((
        SubInfo {
            id,
            revised_publishing_interval: rpi,
            revised_lifetime: rlt,
            revised_keep_alive: rka,
        },
        rx,
    ))
}

fn data_changes(n: &NotificationMessage) -> Vec<(u32, DataValue)> {
    let mut out = Vec::new();
    for eo in n.notification_data.iter().flatten() {
        if let Some(dcn) = eo.inner_as::<DataChangeNotification>() {
            for mi in dcn.monitored_items.iter().flatten() {
                out.push((mi.client_handle, mi.value.clone()));
            }
        }
    }
    out
}

fn events_of(n: &NotificationMessage) -> Vec<(u32, Vec<Variant>)> {
    let mut out = Vec::new();
    for eo in n.notification_data.iter().flatten() {
        if let Some(enl) = eo.inner_as::<EventNotificationList>() {
            for ev in enl.events.iter().flatten() {
                out.push((ev.client_handle, ev.event_fields.clone().unwrap_or_default()));
            }
        }
    }
    out
}

fn notification_json(seq: usize, dv: &DataValue) -> Value {
    let (dt, bit, val) = match &dv.value {
        Some(v) => variant_json(v),
        None => ("Null".to_owned(), 0, Value::Null),
    };
    let mut pairs = vec![
        ("sequenceNumber", json!(seq)),
        ("value", val),
        ("dataType", json!(dt)),
        ("builtInType", json!(bit)),
        ("statusCode", status_json(dv.status())),
    ];
    if let Some(t) = &dv.source_timestamp {
        pairs.push(("sourceTimestamp", json!(fmt_datetime(t))));
    }
    if let Some(t) = &dv.server_timestamp {
        pairs.push(("serverTimestamp", json!(fmt_datetime(t))));
    }
    obj(pairs)
}

async fn op_subscribe(opts: &Opts) -> Envelope {
    let op = "subscribe";
    let r = match opts.required("--node").and_then(parse_ref) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let parsed = (|| -> Result<_, Failure> {
        let pi: f64 = opts.num("--publishing-interval-ms", 500.0)?;
        let si: f64 = opts.num("--sampling-interval-ms", 100.0)?;
        let n: usize = opts.num("--notifications", 5)?;
        let to: u64 = opts.num("--timeout-ms", 10000)?;
        let qs: u32 = opts.num("--queue-size", 1)?;
        let discard = opts.bool("--discard-oldest", true)?;
        let ts = timestamps(opts)?;
        let abs = opts.get("--deadband-absolute");
        let pct = opts.get("--deadband-percent");
        let trig = opts.get("--trigger");
        if abs.is_some() && pct.is_some() {
            return Err(Failure::input(
                "--deadband-absolute and --deadband-percent are mutually exclusive",
            ));
        }
        let filter = if abs.is_some() || pct.is_some() || trig.is_some() {
            let trigger_name = trig.unwrap_or("StatusValue").to_owned();
            let trigger = match trigger_name.as_str() {
                "Status" => opcua::types::DataChangeTrigger::Status,
                "StatusValue" => opcua::types::DataChangeTrigger::StatusValue,
                "StatusValueTimestamp" => opcua::types::DataChangeTrigger::StatusValueTimestamp,
                _ => {
                    return Err(Failure::input(
                        "--trigger must be Status, StatusValue or StatusValueTimestamp",
                    ))
                }
            };
            let (dtype, dname, dval) = if let Some(a) = abs {
                (DeadbandType::Absolute, "Absolute", a.parse::<f64>())
            } else if let Some(p) = pct {
                (DeadbandType::Percent, "Percent", p.parse::<f64>())
            } else {
                (DeadbandType::None, "None", Ok(0.0))
            };
            let dval = dval.map_err(|_| Failure::input("invalid deadband value"))?;
            Some((trigger_name, dname, dval, DataChangeFilter {
                trigger,
                deadband_type: dtype as u32,
                deadband_value: dval,
            }))
        } else {
            None
        };
        Ok((pi, si, n, to, qs, discard, ts, filter))
    })();
    let (pi, si, n_wanted, to, qs, discard, ts, filter) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let id = conn.resolve(&r).await?;
        let (sub, mut rx) = create_subscription(&conn, pi, 10_000, 10).await?;
        let handle = 1u32;
        let req = MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            },
            monitoring_mode: MonitoringMode::Reporting,
            requested_parameters: MonitoringParameters {
                client_handle: handle,
                sampling_interval: si,
                filter: match &filter {
                    Some((_, _, _, f)) => ExtensionObject::from_message(f.clone()),
                    None => ExtensionObject::null(),
                },
                queue_size: qs.max(1),
                discard_oldest: discard,
            },
        };
        let created = conn
            .session
            .create_monitored_items(sub.id, ts, vec![req])
            .await
            .map_err(|e| svc_err(e, "CreateMonitoredItems"))?;
        let mi = created.into_iter().next().ok_or_else(|| {
            Failure::service(StatusCode::BadUnexpectedError, "empty CreateMonitoredItems response")
        })?;
        let mon_sc = mi.result.status_code;
        let mut notifications = Vec::new();
        let mut timed_out = false;
        if mon_sc.is_good() {
            let deadline = Instant::now() + Duration::from_millis(to);
            while notifications.len() < n_wanted {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    timed_out = true;
                    break;
                }
                match tokio::time::timeout(left, rx.recv()).await {
                    Ok(Some(msg)) => {
                        for (h, dv) in data_changes(&msg) {
                            if h == handle && notifications.len() < n_wanted {
                                notifications.push(notification_json(notifications.len() + 1, &dv));
                            }
                        }
                    }
                    Ok(None) => {
                        timed_out = true;
                        break;
                    }
                    Err(_) => {
                        timed_out = true;
                        break;
                    }
                }
            }
        }
        let mut pairs = vec![
            ("nodeId", json!(fmt_node_id(&id))),
            ("subscriptionId", json!(sub.id)),
            ("revisedPublishingInterval", json!(sub.revised_publishing_interval)),
            ("revisedLifetimeCount", json!(sub.revised_lifetime)),
            ("revisedMaxKeepAliveCount", json!(sub.revised_keep_alive)),
            ("monitoredItemStatusCode", status_json(mon_sc)),
        ];
        if let Some((tname, dname, dval, _)) = &filter {
            pairs.push(("monitoredItemId", json!(mi.result.monitored_item_id)));
            pairs.push(("revisedSamplingInterval", json!(mi.result.revised_sampling_interval)));
            pairs.push(("revisedQueueSize", json!(mi.result.revised_queue_size)));
            pairs.push((
                "filter",
                obj(vec![
                    ("trigger", json!(tname)),
                    ("deadbandType", json!(dname)),
                    ("deadbandValue", json!(dval)),
                ]),
            ));
            pairs.push((
                "filterResult",
                if mi.result.filter_result.is_null() {
                    Value::Null
                } else {
                    json!({"typeId": crate::nodeid::fmt_expanded_node_id(&mi.result.filter_result.binary_type_id())})
                },
            ));
        }
        pairs.push(("notifications", Value::Array(notifications)));
        let _ = conn.session.delete_subscription(sub.id).await;
        let mut env = Envelope::new(op);
        env.results.push(obj(pairs));
        env.service_result = mon_sc;
        if !mon_sc.is_good() {
            env.success = false;
            env.error = Some((Category::Service, "CreateMonitoredItems rejected the monitored item".into()));
        } else if timed_out {
            env.success = false;
            env.error = Some((Category::Timeout, "timeout waiting for notifications".into()));
        }
        Ok(env)
    })
}

fn int_values(msg: &NotificationMessage, handle: u32) -> Vec<(i64, StatusCode)> {
    data_changes(msg)
        .into_iter()
        .filter(|(h, _)| *h == handle)
        .filter_map(|(_, dv)| {
            let st = dv.status();
            match dv.value {
                Some(Variant::Int32(v)) => Some((v as i64, st)),
                Some(Variant::Int64(v)) => Some((v, st)),
                _ => None,
            }
        })
        .collect()
}

async fn write_i32(conn: &Conn, id: &NodeId, v: i32) -> Result<(), Failure> {
    let wv = WriteValue {
        node_id: id.clone(),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        value: DataValue::value_only(Variant::Int32(v)),
    };
    let r = conn
        .session
        .write(&[wv])
        .await
        .map_err(|e| svc_err(e, "Write"))?;
    match r.first() {
        Some(sc) if sc.is_good() => Ok(()),
        Some(sc) => Err(Failure::service(*sc, format!("write of {v} failed"))),
        None => Err(Failure::service(StatusCode::BadUnexpectedError, "empty Write response")),
    }
}

async fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<NotificationMessage>, wait: Duration) -> Vec<NotificationMessage> {
    let mut out = Vec::new();
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(m)) => out.push(m),
            _ => break,
        }
    }
    out
}

fn monitored(id: &NodeId, handle: u32, sampling: f64, queue: u32) -> MonitoredItemCreateRequest {
    MonitoredItemCreateRequest {
        item_to_monitor: ReadValueId {
            node_id: id.clone(),
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        },
        monitoring_mode: MonitoringMode::Reporting,
        requested_parameters: MonitoringParameters {
            client_handle: handle,
            sampling_interval: sampling,
            filter: ExtensionObject::null(),
            queue_size: queue,
            discard_oldest: true,
        },
    }
}

async fn op_lifecycle(opts: &Opts) -> Envelope {
    let op = "subscription-lifecycle";
    let r = match opts.required("--node").and_then(parse_ref) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let scenario = match opts.required("--scenario") {
        Ok(s) => s.to_owned(),
        Err(f) => return Envelope::new(op).fail(&f),
    };
    if !matches!(scenario.as_str(), "revise" | "publishing-mode" | "monitoring-mode" | "delete") {
        return Envelope::new(op).fail(&Failure::input(format!("unknown scenario: {scenario}")));
    }
    let to: u64 = match opts.num("--timeout-ms", 15000) {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let collect = Duration::from_millis(to.saturating_sub(2000).clamp(2000, 5000));
    with_conn!(op, opts, |conn| {
        let id = conn.resolve(&r).await?;
        let mut env = Envelope::new(op);
        match scenario.as_str() {
            "revise" => {
                // Raw CreateSubscription: the requested values go to the server unchanged.
                let resp = CreateSubscription::new(&conn.session)
                    .publishing_interval(Duration::from_millis(1))
                    .max_lifetime_count(5)
                    .max_keep_alive_count(10)
                    .publishing_enabled(true)
                    .send(conn.session.channel())
                    .await
                    .map_err(|e| svc_err(e, "CreateSubscription"))?;
                let _ = DeleteSubscriptions::new(&conn.session)
                    .subscription(resp.subscription_id)
                    .send(conn.session.channel())
                    .await;
                let ok = resp.revised_lifetime_count as u64 >= 3 * resp.revised_max_keep_alive_count as u64
                    && resp.revised_publishing_interval >= 10.0;
                env.results.push(obj(vec![
                    ("subscriptionId", json!(resp.subscription_id)),
                    ("requestedPublishingInterval", json!(1)),
                    ("requestedLifetimeCount", json!(5)),
                    ("requestedMaxKeepAliveCount", json!(10)),
                    ("revisedPublishingInterval", json!(resp.revised_publishing_interval)),
                    ("revisedLifetimeCount", json!(resp.revised_lifetime_count)),
                    ("revisedMaxKeepAliveCount", json!(resp.revised_max_keep_alive_count)),
                ]));
                if !ok {
                    env.success = false;
                    env.error = Some((Category::Service, "revised values out of range".into()));
                }
            }
            "publishing-mode" => {
                let (sub, mut rx) = create_subscription(&conn, 500.0, 10_000, 10).await?;
                let created = conn
                    .session
                    .create_monitored_items(sub.id, TimestampsToReturn::Source, vec![monitored(&id, 1, 0.0, 3)])
                    .await
                    .map_err(|e| svc_err(e, "CreateMonitoredItems"))?;
                let sc = created.first().map(|c| c.result.status_code).unwrap_or(StatusCode::BadUnexpectedError);
                if !sc.is_good() {
                    let _ = conn.session.delete_subscription(sub.id).await;
                    return Err(Failure::service(sc, "CreateMonitoredItem failed"));
                }
                let _ = drain(&mut rx, Duration::from_millis(800)).await;
                conn.session
                    .set_publishing_mode(&[sub.id], false)
                    .await
                    .map_err(|e| svc_err(e, "SetPublishingMode"))?;
                let _ = drain(&mut rx, Duration::from_millis(100)).await;
                for v in 1..=5 {
                    write_i32(&conn, &id, v).await?;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                conn.session
                    .set_publishing_mode(&[sub.id], true)
                    .await
                    .map_err(|e| svc_err(e, "SetPublishingMode"))?;
                let msgs = drain(&mut rx, collect).await;
                let _ = conn.session.delete_subscription(sub.id).await;
                let mut values = Vec::new();
                let mut overflow = false;
                for m in &msgs {
                    for (v, st) in int_values(m, 1) {
                        values.push(v);
                        if st.bits() & 0x480 != 0 {
                            overflow = true;
                        }
                    }
                }
                if values.len() < 5 {
                    overflow = true;
                }
                let n = values.len();
                let ok = if n >= 3 {
                    values[n - 3] == 3 && values[n - 2] == 4 && values[n - 1] == 5
                } else if n >= 1 {
                    values[n - 1] == 5
                } else {
                    false
                };
                env.results.push(obj(vec![
                    ("subscriptionId", json!(sub.id)),
                    ("revisedPublishingInterval", json!(sub.revised_publishing_interval)),
                    ("revisedLifetimeCount", json!(sub.revised_lifetime)),
                    ("revisedMaxKeepAliveCount", json!(sub.revised_keep_alive)),
                    ("overflow", json!(overflow)),
                    ("values", json!(values)),
                ]));
                if !ok {
                    env.success = false;
                    env.error = Some((Category::Service, "queued values were not [3,4,5]".into()));
                }
            }
            "monitoring-mode" => {
                let (sub, mut rx) = create_subscription(&conn, 100.0, 10_000, 10).await?;
                let created = conn
                    .session
                    .create_monitored_items(sub.id, TimestampsToReturn::Source, vec![monitored(&id, 1, 0.0, 5)])
                    .await
                    .map_err(|e| svc_err(e, "CreateMonitoredItems"))?;
                let Some(c) = created.first() else {
                    return Err(Failure::service(StatusCode::BadUnexpectedError, "empty response"));
                };
                if !c.result.status_code.is_good() {
                    let _ = conn.session.delete_subscription(sub.id).await;
                    return Err(Failure::service(c.result.status_code, "CreateMonitoredItem failed"));
                }
                let mid = c.result.monitored_item_id;
                let _ = drain(&mut rx, Duration::from_millis(500)).await;
                let count = |msgs: &[NotificationMessage]| -> usize {
                    msgs.iter().map(|m| data_changes(m).into_iter().filter(|(h, _)| *h == 1).count()).sum()
                };
                conn.session
                    .set_monitoring_mode(sub.id, MonitoringMode::Disabled, &[mid])
                    .await
                    .map_err(|e| svc_err(e, "SetMonitoringMode"))?;
                write_i32(&conn, &id, 100).await?;
                let disabled = count(&drain(&mut rx, Duration::from_millis(300)).await);
                conn.session
                    .set_monitoring_mode(sub.id, MonitoringMode::Sampling, &[mid])
                    .await
                    .map_err(|e| svc_err(e, "SetMonitoringMode"))?;
                write_i32(&conn, &id, 101).await?;
                write_i32(&conn, &id, 102).await?;
                let sampling = count(&drain(&mut rx, Duration::from_millis(300)).await);
                conn.session
                    .set_monitoring_mode(sub.id, MonitoringMode::Reporting, &[mid])
                    .await
                    .map_err(|e| svc_err(e, "SetMonitoringMode"))?;
                write_i32(&conn, &id, 103).await?;
                let reporting = count(&drain(&mut rx, collect).await);
                let _ = conn.session.delete_subscription(sub.id).await;
                let ok = disabled == 0 && reporting >= 1;
                env.results.push(obj(vec![
                    ("subscriptionId", json!(sub.id)),
                    (
                        "modeSteps",
                        json!([
                            {"mode": "Disabled", "notificationCount": disabled},
                            {"mode": "Sampling", "notificationCount": sampling},
                            {"mode": "Reporting", "notificationCount": reporting},
                        ]),
                    ),
                ]));
                if !ok {
                    env.success = false;
                    env.error = Some((Category::Service, "monitoring mode steps not as expected".into()));
                }
            }
            _ => {
                // delete: raw requests, so the second deletes reach the server.
                let resp = CreateSubscription::new(&conn.session)
                    .publishing_interval(Duration::from_millis(500))
                    .max_lifetime_count(10_000)
                    .max_keep_alive_count(10)
                    .publishing_enabled(true)
                    .send(conn.session.channel())
                    .await
                    .map_err(|e| svc_err(e, "CreateSubscription"))?;
                let sid = resp.subscription_id;
                let cm = opcua::client::services::CreateMonitoredItems::new(sid, &conn.session)
                    .timestamps_to_return(TimestampsToReturn::Source)
                    .item(monitored(&id, 1, 100.0, 1))
                    .send(conn.session.channel())
                    .await
                    .map_err(|e| svc_err(e, "CreateMonitoredItems"))?;
                let Some(c) = cm.results.first().map(|c| c.result.clone()) else {
                    return Err(Failure::service(StatusCode::BadUnexpectedError, "empty response"));
                };
                if !c.status_code.is_good() {
                    return Err(Failure::service(c.status_code, "CreateMonitoredItem failed"));
                }
                let del_mi = |sid: u32, mid: u32| {
                    let s = conn.session.clone();
                    async move {
                        match DeleteMonitoredItems::new(sid, &s).item(mid).send(s.channel()).await {
                            Ok(r) => r.results.and_then(|v| v.first().copied()).unwrap_or(StatusCode::Good),
                            Err(e) => e.status(),
                        }
                    }
                };
                let del_sub = |sid: u32| {
                    let s = conn.session.clone();
                    async move {
                        match DeleteSubscriptions::new(&s).subscription(sid).send(s.channel()).await {
                            Ok(r) => r.results.and_then(|v| v.first().copied()).unwrap_or(StatusCode::Good),
                            Err(e) => e.status(),
                        }
                    }
                };
                let m1 = del_mi(sid, c.monitored_item_id).await;
                let m2 = del_mi(sid, c.monitored_item_id).await;
                let s1 = del_sub(sid).await;
                let s2 = del_sub(sid).await;
                let ok = m2.is_bad() && s2.is_bad();
                env.results.push(obj(vec![
                    ("subscriptionId", json!(sid)),
                    ("deleteMonitoredItem", obj(vec![("first", status_json(m1)), ("second", status_json(m2))])),
                    ("deleteSubscription", obj(vec![("first", status_json(s1)), ("second", status_json(s2))])),
                ]));
                if !ok {
                    env.success = false;
                    env.error = Some((Category::Service, "second deletes were not Bad".into()));
                }
            }
        }
        Ok(env)
    })
}

// ── Events ──────────────────────────────────────────────────────────────────

const EVENT_FIELDS: [&str; 6] = ["EventId", "EventType", "SourceName", "Message", "Severity", "Time"];

fn sao(field: &str) -> SimpleAttributeOperand {
    SimpleAttributeOperand {
        type_definition_id: ObjectTypeId::BaseEventType.into(),
        browse_path: Some(vec![QualifiedName::new(0, field)]),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
    }
}

async fn op_events(opts: &Opts) -> Envelope {
    let op = "event-subscribe";
    let r = match opts.required("--node").and_then(parse_ref) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let parsed = (|| -> Result<_, Failure> {
        let pi: f64 = opts.num("--publishing-interval-ms", 500.0)?;
        let n: usize = opts.num("--events", 1)?;
        let to: u64 = opts.num("--timeout-ms", 10000)?;
        let qs: u32 = opts.num("--queue-size", 10)?;
        let of_type = match opts.get("--of-type") {
            Some(s) => Some(parse_ref(s)?),
            None => None,
        };
        let min_sev: Option<u16> = match opts.get("--min-severity") {
            Some(_) => Some(opts.num("--min-severity", 0)?),
            None => None,
        };
        Ok((pi, n, to, qs, of_type, min_sev))
    })();
    let (pi, n_wanted, to, qs, of_type, min_sev) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let id = conn.resolve(&r).await?;
        let mut elements = Vec::new();
        if let Some(t) = &of_type {
            let tid = conn.resolve(t).await?;
            elements.push(ContentFilterElement {
                filter_operator: FilterOperator::OfType,
                filter_operands: Some(vec![ExtensionObject::from_message(LiteralOperand::from(tid))]),
            });
        }
        if let Some(s) = min_sev {
            elements.push(ContentFilterElement {
                filter_operator: FilterOperator::GreaterThanOrEqual,
                filter_operands: Some(vec![
                    ExtensionObject::from_message(sao("Severity")),
                    ExtensionObject::from_message(LiteralOperand::from(Variant::UInt16(s))),
                ]),
            });
        }
        if elements.len() == 2 {
            elements.push(ContentFilterElement {
                filter_operator: FilterOperator::And,
                filter_operands: Some(vec![
                    ExtensionObject::from_message(ElementOperand { index: 0 }),
                    ExtensionObject::from_message(ElementOperand { index: 1 }),
                ]),
            });
        }
        let filter = EventFilter {
            select_clauses: Some(EVENT_FIELDS.iter().map(|f| sao(f)).collect()),
            where_clause: ContentFilter {
                elements: if elements.is_empty() { None } else { Some(elements) },
            },
        };
        let (sub, mut rx) = create_subscription(&conn, pi, 10_000, 10).await?;
        let req = MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::EventNotifier as u32,
                ..Default::default()
            },
            monitoring_mode: MonitoringMode::Reporting,
            requested_parameters: MonitoringParameters {
                client_handle: 1,
                sampling_interval: 0.0,
                filter: ExtensionObject::from_message(filter),
                queue_size: qs.max(1),
                discard_oldest: true,
            },
        };
        let created = conn
            .session
            .create_monitored_items(sub.id, TimestampsToReturn::Both, vec![req])
            .await
            .map_err(|e| svc_err(e, "CreateMonitoredItems"))?;
        let mon_sc = created.first().map(|c| c.result.status_code).unwrap_or(StatusCode::BadUnexpectedError);
        let mut events = Vec::new();
        let mut timed_out = false;
        if mon_sc.is_good() {
            let deadline = Instant::now() + Duration::from_millis(to);
            while events.len() < n_wanted {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    timed_out = true;
                    break;
                }
                match tokio::time::timeout(left, rx.recv()).await {
                    Ok(Some(msg)) => {
                        for (h, fields) in events_of(&msg) {
                            if h != 1 || events.len() >= n_wanted {
                                continue;
                            }
                            let fs: Vec<Value> = fields
                                .iter()
                                .zip(EVENT_FIELDS.iter())
                                .map(|(v, name)| {
                                    let (dt, bit, val) = variant_json(v);
                                    obj(vec![
                                        ("name", json!(name)),
                                        ("dataType", json!(dt)),
                                        ("builtInType", json!(bit)),
                                        ("value", val),
                                    ])
                                })
                                .collect();
                            events.push(obj(vec![
                                ("sequenceNumber", json!(events.len() + 1)),
                                ("fields", Value::Array(fs)),
                            ]));
                        }
                    }
                    _ => {
                        timed_out = true;
                        break;
                    }
                }
            }
        }
        let _ = conn.session.delete_subscription(sub.id).await;
        let mut env = Envelope::new(op);
        env.service_result = mon_sc;
        env.results.push(obj(vec![
            ("nodeId", json!(fmt_node_id(&id))),
            ("subscriptionId", json!(sub.id)),
            ("revisedPublishingInterval", json!(sub.revised_publishing_interval)),
            ("monitoredItemStatusCode", status_json(mon_sc)),
            ("selectClauses", json!(EVENT_FIELDS)),
            ("events", Value::Array(events)),
        ]));
        if !mon_sc.is_good() {
            env.success = false;
            env.error = Some((Category::Service, "event monitored item rejected".into()));
        } else if timed_out {
            env.success = false;
            env.error = Some((Category::Timeout, "timeout waiting for events".into()));
        }
        Ok(env)
    })
}

// ── Alarms & Conditions (Part 9) ────────────────────────────────────────────

/// SelectClauses of `alarms`: (TypeDefinitionId, BrowsePath). The last one is
/// the ConditionId: ConditionType, empty BrowsePath, AttributeId NodeId
/// (Part 9 §5.5.2).
const ALARM_FIELDS: [(u32, &[&str]); 16] = [
    (2041, &["EventId"]),
    (2041, &["EventType"]),
    (2041, &["SourceNode"]),
    (2041, &["SourceName"]),
    (2041, &["Time"]),
    (2041, &["Message"]),
    (2041, &["Severity"]),
    (2782, &["ConditionName"]),
    (2782, &["BranchId"]),
    (2782, &["Retain"]),
    (2782, &["EnabledState", "Id"]),
    (2782, &["Comment"]),
    (2881, &["AckedState", "Id"]),
    (2881, &["ConfirmedState", "Id"]),
    (2915, &["ActiveState", "Id"]),
    (2782, &[]),
];

const AL_EVENT_ID: usize = 0;
const AL_EVENT_TYPE: usize = 1;
const AL_SOURCE_NODE: usize = 2;
const AL_SOURCE_NAME: usize = 3;
const AL_TIME: usize = 4;
const AL_MESSAGE: usize = 5;
const AL_SEVERITY: usize = 6;
const AL_CONDITION_NAME: usize = 7;
const AL_RETAIN: usize = 9;
const AL_ENABLED: usize = 10;
const AL_COMMENT: usize = 11;
const AL_ACKED: usize = 12;
const AL_CONFIRMED: usize = 13;
const AL_ACTIVE: usize = 14;
const AL_CONDITION_ID: usize = 15;

const REFRESH_START_EVENT_TYPE: u32 = 2787;
const REFRESH_END_EVENT_TYPE: u32 = 2788;
const CONDITION_TYPE: u32 = 2782;
const CONDITION_REFRESH: u32 = 3875;
const ACKNOWLEDGE: u32 = 9111;
const CONFIRM: u32 = 9113;
const ADD_COMMENT: u32 = 9029;

fn alarm_select_clauses() -> Vec<SimpleAttributeOperand> {
    ALARM_FIELDS
        .iter()
        .map(|(ty, path)| SimpleAttributeOperand {
            type_definition_id: NodeId::new(0, *ty),
            browse_path: Some(path.iter().map(|p| QualifiedName::new(0, *p)).collect()),
            attribute_id: if path.is_empty() { AttributeId::NodeId as u32 } else { AttributeId::Value as u32 },
            index_range: NumericRange::None,
        })
        .collect()
}

fn al_node(v: Option<&Variant>) -> Option<&NodeId> {
    match v {
        Some(Variant::NodeId(n)) if !n.is_null() => Some(n),
        _ => None,
    }
}

fn al_bool(v: Option<&Variant>) -> Value {
    match v {
        Some(Variant::Boolean(b)) => json!(b),
        _ => Value::Null,
    }
}

fn al_lt_text(v: Option<&Variant>) -> Option<String> {
    match v {
        Some(Variant::LocalizedText(l)) => Some(crate::values::ua_str(&l.text)),
        _ => None,
    }
}

fn al_string(v: Option<&Variant>) -> Option<String> {
    match v {
        Some(Variant::String(s)) => s.value().clone(),
        _ => None,
    }
}

fn al_is_type(fields: &[Variant], id: u32) -> bool {
    al_node(fields.get(AL_EVENT_TYPE)) == Some(&NodeId::new(0, id))
}

/// The ConditionEntry of the contract.
fn condition_entry(f: &[Variant]) -> Value {
    let node = |i: usize| al_node(f.get(i)).map(|n| json!(fmt_node_id(n))).unwrap_or(Value::Null);
    obj(vec![
        ("conditionId", node(AL_CONDITION_ID)),
        (
            "eventId",
            match f.get(AL_EVENT_ID) {
                Some(Variant::ByteString(b)) => b.value.as_ref().map(|d| json!(b64(d))).unwrap_or(Value::Null),
                _ => Value::Null,
            },
        ),
        ("eventType", node(AL_EVENT_TYPE)),
        ("sourceNode", node(AL_SOURCE_NODE)),
        ("sourceName", al_string(f.get(AL_SOURCE_NAME)).map(Value::from).unwrap_or(Value::Null)),
        ("conditionName", al_string(f.get(AL_CONDITION_NAME)).map(Value::from).unwrap_or(Value::Null)),
        (
            "time",
            match f.get(AL_TIME) {
                // the OPC UA null DateTime (1601-01-01, encoded 0) is null
                Some(Variant::DateTime(d)) if !d.is_null() => json!(fmt_datetime(d)),
                _ => Value::Null,
            },
        ),
        ("message", al_lt_text(f.get(AL_MESSAGE)).map(Value::from).unwrap_or(Value::Null)),
        (
            "severity",
            match f.get(AL_SEVERITY) {
                Some(Variant::UInt16(s)) => json!(s),
                _ => Value::Null,
            },
        ),
        ("retain", al_bool(f.get(AL_RETAIN))),
        ("enabled", al_bool(f.get(AL_ENABLED))),
        ("acked", al_bool(f.get(AL_ACKED))),
        ("confirmed", al_bool(f.get(AL_CONFIRMED))),
        ("active", al_bool(f.get(AL_ACTIVE))),
        ("comment", al_lt_text(f.get(AL_COMMENT)).map(Value::from).unwrap_or(Value::Null)),
    ])
}

/// The events of the `alarms` monitored item.
#[derive(Default)]
struct AlarmStore {
    /// Condition events (non-null ConditionId), in arrival order.
    events: Vec<Vec<Variant>>,
    /// 0 before ConditionRefresh, 1 refreshing, 2 RefreshEnd seen.
    phase: u8,
    start_seen: bool,
    end_seen: bool,
    /// Indices into `events`: the refreshed conditions, last event per id.
    conditions: Vec<usize>,
}

impl AlarmStore {
    fn add(&mut self, fields: Vec<Variant>) {
        if al_is_type(&fields, REFRESH_START_EVENT_TYPE) {
            if self.phase == 1 {
                self.start_seen = true;
            }
            return;
        }
        if al_is_type(&fields, REFRESH_END_EVENT_TYPE) {
            if self.phase == 1 {
                self.end_seen = true;
                self.phase = 2;
            }
            return;
        }
        let Some(cid) = al_node(fields.get(AL_CONDITION_ID)).cloned() else {
            return; // not a condition (e.g. the Events.Source BaseEvents)
        };
        self.events.push(fields);
        let idx = self.events.len() - 1;
        if self.phase == 1 {
            match self
                .conditions
                .iter()
                .position(|&i| al_node(self.events[i].get(AL_CONDITION_ID)) == Some(&cid))
            {
                Some(p) => self.conditions[p] = idx,
                None => self.conditions.push(idx),
            }
        }
    }

    fn take(&mut self, msg: &NotificationMessage) {
        for (h, fields) in events_of(msg) {
            if h == 1 {
                self.add(fields);
            }
        }
    }

    fn latest(&self, cid: &NodeId) -> Option<usize> {
        self.events
            .iter()
            .rposition(|e| al_node(e.get(AL_CONDITION_ID)) == Some(cid))
    }
}

/// Process the notifications already queued.
fn al_drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<NotificationMessage>, st: &mut AlarmStore) {
    while let Ok(msg) = rx.try_recv() {
        st.take(&msg);
    }
}

/// Wait (until `deadline`) for `done(store)`; true when it became true.
async fn al_wait(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<NotificationMessage>,
    st: &mut AlarmStore,
    deadline: Instant,
    done: impl Fn(&AlarmStore) -> bool,
) -> bool {
    loop {
        al_drain(rx, st);
        if done(st) {
            return true;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(msg)) => st.take(&msg),
            Ok(None) | Err(_) => return done(st),
        }
    }
}

async fn al_call(conn: &Conn, object: NodeId, method: u32, inputs: Vec<Variant>) -> StatusCode {
    let req = CallMethodRequest {
        object_id: object,
        method_id: NodeId::new(0, method),
        input_arguments: Some(inputs),
    };
    match conn.session.call(vec![req]).await {
        Ok(res) => res.first().map(|r| r.status_code).unwrap_or(StatusCode::BadUnexpectedError),
        Err(e) => e.status(),
    }
}

async fn op_alarms(opts: &Opts) -> Envelope {
    let op = "alarms";
    let r = match parse_ref(opts.get("--node").unwrap_or("i=2253")) {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let parsed = (|| -> Result<_, Failure> {
        let pi: f64 = opts.num("--publishing-interval-ms", 200.0)?;
        let to: u64 = opts.num("--timeout-ms", 15000)?;
        let ack = opts.bool("--acknowledge", false)?;
        let confirm = opts.bool("--confirm", false)?;
        let add_comment = opts.bool("--add-comment", false)?;
        Ok((pi, to, ack, confirm, add_comment))
    })();
    let (pi, to, want_ack, want_confirm, want_comment) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let condition_name = opts.get("--condition-name").map(str::to_owned);
    let comment = opts.get("--comment").unwrap_or("interop-comment").to_owned();
    with_conn!(op, opts, |conn| {
        let deadline = Instant::now() + Duration::from_millis(to);
        let id = conn.resolve(&r).await?;
        let filter = EventFilter {
            select_clauses: Some(alarm_select_clauses()),
            where_clause: ContentFilter { elements: None },
        };
        let (sub, mut rx) = create_subscription(&conn, pi, 10_000, 10).await?;
        let req = MonitoredItemCreateRequest {
            item_to_monitor: ReadValueId {
                node_id: id.clone(),
                attribute_id: AttributeId::EventNotifier as u32,
                ..Default::default()
            },
            monitoring_mode: MonitoringMode::Reporting,
            requested_parameters: MonitoringParameters {
                client_handle: 1,
                sampling_interval: 0.0,
                filter: ExtensionObject::from_message(filter),
                queue_size: 1000,
                discard_oldest: true,
            },
        };
        let created = conn
            .session
            .create_monitored_items(sub.id, TimestampsToReturn::Both, vec![req])
            .await
            .map_err(|e| svc_err(e, "CreateMonitoredItems"))?;
        let mon_sc = created.first().map(|c| c.result.status_code).unwrap_or(StatusCode::BadUnexpectedError);

        let mut st = AlarmStore::default();
        let mut failure: Option<(StatusCode, Category, String)> = None;
        let mut refresh_sc = mon_sc;
        let mut target: Option<usize> = None;
        // (status, follow-up event index, repeat status)
        let mut actions: [Option<(StatusCode, Option<usize>, Option<StatusCode>)>; 3] = [None, None, None];

        if !mon_sc.is_good() {
            failure = Some((mon_sc, Category::Service, "event monitored item rejected".into()));
        } else {
            al_drain(&mut rx, &mut st);
            st.phase = 1;
            refresh_sc = al_call(
                &conn,
                NodeId::new(0, CONDITION_TYPE),
                CONDITION_REFRESH,
                vec![Variant::UInt32(sub.id)],
            )
            .await;
            if !refresh_sc.is_good() {
                failure = Some((refresh_sc, Category::Service, "ConditionRefresh failed".into()));
            } else if !al_wait(&mut rx, &mut st, deadline, |s| s.end_seen).await {
                failure = Some((StatusCode::BadTimeout, Category::Timeout, "timeout waiting for the RefreshEndEvent".into()));
            }
        }

        if failure.is_none() {
            target = st.conditions.iter().copied().find(|&i| {
                let f = &st.events[i];
                match &condition_name {
                    Some(n) => al_string(f.get(AL_CONDITION_NAME)).as_deref() == Some(n.as_str()),
                    None => matches!(f.get(AL_RETAIN), Some(Variant::Boolean(true))),
                }
            });
            if target.is_none() && (want_ack || want_confirm || want_comment) {
                failure = Some((
                    StatusCode::BadNodeIdUnknown,
                    Category::Service,
                    "no matching condition in the ConditionRefresh".into(),
                ));
            }
        }

        if let (None, Some(t)) = (&failure, target) {
            let cid = al_node(st.events[t].get(AL_CONDITION_ID)).cloned().unwrap_or_default();
            let steps = [
                (want_ack, ACKNOWLEDGE, "Acknowledge"),
                (want_confirm, CONFIRM, "Confirm"),
                (want_comment, ADD_COMMENT, "AddComment"),
            ];
            for (k, (wanted, method, name)) in steps.iter().enumerate() {
                if !*wanted {
                    continue;
                }
                al_drain(&mut rx, &mut st);
                // EventId of the latest event of the condition
                let event_id = st
                    .latest(&cid)
                    .and_then(|i| match st.events[i].get(AL_EVENT_ID) {
                        Some(Variant::ByteString(b)) => Some(b.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(ByteString::null);
                let args = vec![
                    Variant::from(event_id.clone()),
                    Variant::from(LocalizedText::new("en", &comment)),
                ];
                let mark = st.events.len();
                let sc = al_call(&conn, cid.clone(), *method, args.clone()).await;
                if !sc.is_good() {
                    actions[k] = Some((sc, None, None));
                    failure = Some((sc, Category::Service, format!("{name} failed")));
                    break;
                }
                let is_followup = |s: &AlarmStore, i: usize| -> bool {
                    let f = &s.events[i];
                    if al_node(f.get(AL_CONDITION_ID)) != Some(&cid) {
                        return false;
                    }
                    match k {
                        0 => matches!(f.get(AL_ACKED), Some(Variant::Boolean(true))),
                        1 => matches!(f.get(AL_CONFIRMED), Some(Variant::Boolean(true))),
                        _ => al_lt_text(f.get(AL_COMMENT)).as_deref() == Some(comment.as_str()),
                    }
                };
                al_wait(&mut rx, &mut st, deadline, |s| (mark..s.events.len()).any(|i| is_followup(s, i))).await;
                let ev = (mark..st.events.len()).find(|&i| is_followup(&st, i));
                let repeat = if k == 0 {
                    // the same, now stale EventId again
                    Some(al_call(&conn, cid.clone(), *method, args).await)
                } else {
                    None
                };
                actions[k] = Some((sc, ev, repeat));
                if ev.is_none() {
                    failure = Some((StatusCode::BadTimeout, Category::Timeout, format!("timeout waiting for the {name} event")));
                    break;
                }
            }
        }

        let _ = conn.session.delete_subscription(sub.id).await;
        let action_json = |a: &Option<(StatusCode, Option<usize>, Option<StatusCode>)>, with_repeat: bool| -> Value {
            match a {
                None => Value::Null,
                Some((sc, ev, rep)) => {
                    let mut pairs = vec![
                        ("statusCode", status_json(*sc)),
                        ("event", ev.map(|i| condition_entry(&st.events[i])).unwrap_or(Value::Null)),
                    ];
                    if with_repeat {
                        pairs.push(("repeatStatusCode", rep.map(status_json).unwrap_or(Value::Null)));
                    }
                    obj(pairs)
                }
            }
        };
        let mut env = Envelope::new(op);
        env.results.push(obj(vec![
            ("nodeId", json!(fmt_node_id(&id))),
            ("subscriptionId", json!(sub.id)),
            ("monitoredItemStatusCode", status_json(mon_sc)),
            (
                "refresh",
                obj(vec![
                    ("statusCode", status_json(refresh_sc)),
                    ("startSeen", json!(st.start_seen)),
                    ("endSeen", json!(st.end_seen)),
                ]),
            ),
            (
                "conditions",
                Value::Array(st.conditions.iter().map(|&i| condition_entry(&st.events[i])).collect()),
            ),
            ("target", target.map(|i| condition_entry(&st.events[i])).unwrap_or(Value::Null)),
            ("acknowledge", action_json(&actions[0], true)),
            ("confirm", action_json(&actions[1], false)),
            ("addComment", action_json(&actions[2], false)),
        ]));
        if let Some((sc, cat, msg)) = failure {
            env.success = false;
            env.service_result = sc;
            env.error = Some((cat, msg));
        }
        Ok(env)
    })
}

// ── History ─────────────────────────────────────────────────────────────────

struct HistoryPage {
    svc: StatusCode,
    item: StatusCode,
    cp: Option<String>,
    values: Vec<Value>,
}

fn history_value_json(dv: &DataValue) -> Value {
    let (dt, bit, val) = match &dv.value {
        Some(v) => variant_json(v),
        None => ("Null".to_owned(), 0, Value::Null),
    };
    let mut pairs = vec![
        ("value", val),
        ("dataType", json!(dt)),
        ("builtInType", json!(bit)),
        ("statusCode", status_json(dv.status())),
    ];
    if let Some(t) = &dv.source_timestamp {
        pairs.push(("sourceTimestamp", json!(fmt_datetime(t))));
    }
    if let Some(t) = &dv.server_timestamp {
        pairs.push(("serverTimestamp", json!(fmt_datetime(t))));
    }
    obj(pairs)
}

#[allow(clippy::too_many_arguments)]
async fn history_once(
    conn: &Conn,
    id: &NodeId,
    start: opcua::types::DateTime,
    end: opcua::types::DateTime,
    num: u32,
    bounds: bool,
    ts: TimestampsToReturn,
    cp: Option<&str>,
    release: bool,
) -> Result<HistoryPage, Failure> {
    let details = ReadRawModifiedDetails {
        is_read_modified: false,
        start_time: start,
        end_time: end,
        num_values_per_node: num,
        return_bounds: bounds,
    };
    let cpb = match cp {
        Some(s) if !s.is_empty() => ByteString::from(b64_decode(s).map_err(Failure::input)?),
        _ => ByteString::null(),
    };
    let r = HistoryRead::new(HistoryReadAction::ReadRawModifiedDetails(details), &conn.session)
        .timestamps_to_return(ts)
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
            Ok(HistoryPage {
                svc: e.status(),
                item: e.status(),
                cp: None,
                values: Vec::new(),
            })
        }
        Ok(resp) => {
            let svc = resp.response_header.service_result;
            let Some(hr) = resp.results.and_then(|v| v.into_iter().next()) else {
                return Ok(HistoryPage { svc, item: svc, cp: None, values: Vec::new() });
            };
            let cp = if hr.continuation_point.is_null_or_empty() {
                None
            } else {
                Some(b64(hr.continuation_point.value.as_deref().unwrap_or(&[])))
            };
            let mut values = Vec::new();
            if let Some(hd) = hr.history_data.inner_as::<HistoryData>() {
                for dv in hd.data_values.iter().flatten() {
                    values.push(history_value_json(dv));
                }
            }
            Ok(HistoryPage { svc, item: hr.status_code, cp, values })
        }
    }
}

async fn op_history(opts: &Opts) -> Envelope {
    let op = "history-read";
    let parsed = (|| -> Result<_, Failure> {
        let r = parse_ref(opts.required("--node")?)?;
        let start = parse_datetime(opts.required("--start")?).map_err(Failure::input)?;
        let end = parse_datetime(opts.required("--end")?).map_err(Failure::input)?;
        let num: u32 = opts.num("--num-values", 0)?;
        let cp = opts.get("--continuation-point").map(str::to_owned);
        let release = opts.bool("--release-continuation-point", false)?;
        let bounds = opts.bool("--return-bounds", false)?;
        let ts = timestamps(opts)?;
        let scenario = opts.get("--scenario").map(str::to_owned);
        if let Some(s) = &scenario {
            if s != "continue" {
                return Err(Failure::input(format!("unknown --scenario '{s}' (continue)")));
            }
        }
        Ok((r, start, end, num, cp, release, bounds, ts, scenario))
    })();
    let (r, start, end, num, cp, release, bounds, ts, scenario) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let id = conn.resolve(&r).await?;
        let mut env = Envelope::new(op);
        if scenario.is_some() {
            let num = if num == 0 { 2 } else { num };
            let mut pages = Vec::new();
            let mut cp: Option<String> = None;
            let mut last_cp: Option<String> = None;
            let (mut last_svc, mut last_item) = (StatusCode::Good, StatusCode::Good);
            for _ in 0..8 {
                let p = history_once(&conn, &id, start, end, num, bounds, ts, cp.as_deref(), false).await?;
                last_svc = p.svc;
                last_item = p.item;
                pages.push(obj(vec![
                    ("values", Value::Array(p.values.clone())),
                    ("continuationPoint", json!(p.cp)),
                    ("statusCode", status_json(p.item)),
                ]));
                if !p.svc.is_good() || !p.item.is_good() {
                    break;
                }
                if let Some(c) = &p.cp {
                    last_cp = Some(c.clone());
                }
                match p.cp {
                    Some(c) => cp = Some(c),
                    None => {
                        cp = None;
                        break;
                    }
                }
            }
            let mut release_sc = StatusCode::Good;
            let mut reuse_sc = StatusCode::Good;
            if let Some(c) = &cp {
                let rel = history_once(&conn, &id, start, end, num, bounds, ts, Some(c), true).await?;
                release_sc = if rel.svc.is_good() { rel.item } else { rel.svc };
                let re = history_once(&conn, &id, start, end, num, bounds, ts, Some(c), false).await?;
                reuse_sc = if re.svc.is_good() { re.item } else { re.svc };
            } else if !pages.is_empty() {
                let rel = history_once(&conn, &id, start, end, num, bounds, ts, None, true).await?;
                release_sc = if rel.svc.is_good() { rel.item } else { rel.svc };
                if let Some(c) = &last_cp {
                    let re = history_once(&conn, &id, start, end, num, bounds, ts, Some(c), false).await?;
                    reuse_sc = if re.svc.is_good() { re.item } else { re.svc };
                }
            }
            let ok = last_svc.is_good() && last_item.is_good() && !pages.is_empty();
            env.service_result = if last_svc.is_good() { last_item } else { last_svc };
            env.results.push(obj(vec![
                ("scenario", json!("continue")),
                ("nodeId", json!(fmt_node_id(&id))),
                ("pages", Value::Array(pages)),
                ("releaseStatusCode", status_json(release_sc)),
                ("reuseAfterReleaseStatusCode", status_json(reuse_sc)),
            ]));
            if !ok {
                env.success = false;
                env.error = Some((Category::Service, "HistoryRead failed".into()));
            }
            return Ok(env);
        }
        let p = history_once(&conn, &id, start, end, num, bounds, ts, cp.as_deref(), release).await?;
        env.service_result = if p.svc.is_good() { p.item } else { p.svc };
        env.results.push(obj(vec![
            ("nodeId", json!(fmt_node_id(&id))),
            ("statusCode", status_json(p.item)),
            ("continuationPoint", json!(p.cp)),
            ("values", Value::Array(p.values)),
        ]));
        if !(p.svc.is_good() && p.item.is_good()) {
            env.success = false;
            env.error = Some((Category::Service, "HistoryRead failed".into()));
        }
        Ok(env)
    })
}

// ── republish / transfer ────────────────────────────────────────────────────

async fn op_republish(opts: &Opts) -> Envelope {
    let op = "republish";
    let parsed = (|| -> Result<(u32, u32), Failure> {
        opts.required("--subscription-id")?;
        opts.required("--sequence-number")?;
        Ok((opts.num("--subscription-id", 0)?, opts.num("--sequence-number", 0)?))
    })();
    let (sid, seq) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let r = Republish::new(sid, seq, &conn.session)
            .send(conn.session.channel())
            .await;
        let mut env = Envelope::new(op);
        let mut pairs = vec![
            ("subscriptionId", json!(sid)),
            ("retransmitSequenceNumber", json!(seq)),
        ];
        match r {
            Ok(resp) => {
                let nm = resp.notification_message;
                pairs.push(("sequenceNumber", json!(nm.sequence_number)));
                pairs.push(("publishTime", json!(fmt_datetime(&nm.publish_time))));
                pairs.push((
                    "notificationDataCount",
                    json!(nm.notification_data.as_ref().map(|v| v.len()).unwrap_or(0)),
                ));
            }
            Err(e) => {
                if crate::common::is_transport(e.status()) {
                    return Err(svc_err(e, "Republish"));
                }
                env.success = false;
                env.service_result = e.status();
                env.error = Some((Category::Service, format!("Republish: {e}")));
            }
        }
        env.results.push(obj(pairs));
        Ok(env)
    })
}

async fn op_transfer(opts: &Opts) -> Envelope {
    let op = "transfer-subscriptions";
    let ids = opts.all("--subscription-id");
    if ids.is_empty() {
        return Envelope::new(op).fail(&Failure::input("missing --subscription-id"));
    }
    let parsed: Result<Vec<u32>, Failure> = ids
        .iter()
        .map(|s| s.parse::<u32>().map_err(|_| Failure::input(format!("invalid --subscription-id '{s}'"))))
        .collect();
    let ids = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let send_initial = match opts.bool("--send-initial-values", false) {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let r = TransferSubscriptions::new(&conn.session)
            .subscription_ids(ids.clone())
            .send_initial_values(send_initial)
            .send(conn.session.channel())
            .await;
        let mut env = Envelope::new(op);
        match r {
            Ok(resp) => {
                for (i, tr) in resp.results.iter().flatten().enumerate() {
                    if !tr.status_code.is_good() {
                        env.success = false;
                        env.service_result = tr.status_code;
                    }
                    env.results.push(obj(vec![
                        ("subscriptionId", json!(ids.get(i).copied().unwrap_or(0))),
                        ("statusCode", status_json(tr.status_code)),
                        (
                            "availableSequenceNumbers",
                            json!(tr.available_sequence_numbers.clone().unwrap_or_default()),
                        ),
                    ]));
                }
                if !env.success {
                    env.error = Some((Category::Service, "TransferSubscriptions failed".into()));
                }
            }
            Err(e) => {
                if crate::common::is_transport(e.status()) {
                    return Err(svc_err(e, "TransferSubscriptions"));
                }
                env.success = false;
                env.service_result = e.status();
                env.error = Some((Category::Service, format!("TransferSubscriptions: {e}")));
            }
        }
        Ok(env)
    })
}

// ── register-nodes / node-management ────────────────────────────────────────

async fn op_register_nodes(opts: &Opts) -> Envelope {
    let op = "register-nodes";
    let nodes = opts.all("--node");
    if nodes.is_empty() {
        return Envelope::new(op).fail(&Failure::input("missing --node"));
    }
    let refs: Result<Vec<NodeRef>, Failure> = nodes.iter().map(|n| parse_ref(n)).collect();
    let refs = match refs {
        Ok(r) => r,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let mut ids = Vec::new();
        for r in &refs {
            ids.push(conn.resolve(r).await?);
        }
        let aliases = conn
            .session
            .register_nodes(&ids)
            .await
            .map_err(|e| svc_err(e, "RegisterNodes"))?;
        let rvs: Vec<ReadValueId> = aliases
            .iter()
            .map(|a| ReadValueId {
                node_id: a.clone(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            })
            .collect();
        let dvs = conn
            .session
            .read(&rvs, TimestampsToReturn::Neither, 0.0)
            .await
            .map_err(|e| svc_err(e, "Read"))?;
        let unreg = match conn.session.unregister_nodes(&aliases).await {
            Ok(()) => StatusCode::Good,
            Err(e) => e.status(),
        };
        let mut env = Envelope::new(op);
        let mut ok = unreg.is_good();
        for (i, id) in ids.iter().enumerate() {
            let dv = dvs.get(i).cloned().unwrap_or_default();
            let mut pairs = vec![
                ("nodeId", json!(fmt_node_id(id))),
                ("registeredNodeId", json!(aliases.get(i).map(fmt_node_id))),
                ("statusCode", status_json(dv.status())),
            ];
            if dv.status().is_good() {
                let (dt, bit, val) = match &dv.value {
                    Some(v) => variant_json(v),
                    None => ("Null".to_owned(), 0, Value::Null),
                };
                pairs.push(("dataType", json!(dt)));
                pairs.push(("builtInType", json!(bit)));
                pairs.push(("value", val));
            } else {
                ok = false;
            }
            pairs.push(("unregisterStatusCode", status_json(unreg)));
            env.results.push(obj(pairs));
        }
        if !ok {
            env.success = false;
            env.service_result = if unreg.is_good() {
                dvs.iter().map(|d| d.status()).find(|s| !s.is_good()).unwrap_or(StatusCode::Good)
            } else {
                unreg
            };
            env.error = Some((Category::Service, "register-nodes failed".into()));
        }
        Ok(env)
    })
}

async fn op_node_management(opts: &Opts) -> Envelope {
    let op = "node-management";
    let parsed = (|| -> Result<_, Failure> {
        let parent = parse_ref(opts.required("--parent")?)?;
        let node = parse_ref(opts.required("--node")?)?;
        let name = opts.get("--browse-name").unwrap_or("InteropAdded").to_owned();
        let value: i32 = opts.num("--value", 42)?;
        Ok((parent, node, name, value))
    })();
    let (parent, node, name, value) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    with_conn!(op, opts, |conn| {
        let parent_id = conn.resolve(&parent).await?;
        let node_id = conn.resolve(&node).await?;
        // AttributesMask: AccessLevel | DataType | DisplayName | UserAccessLevel | ValueRank | Value
        let attrs = VariableAttributes {
            specified_attributes: 1 | 16 | 64 | 65536 | 524288 | 2097152,
            display_name: opcua::types::LocalizedText::new("", name.as_str()),
            description: opcua::types::LocalizedText::null(),
            write_mask: 0,
            user_write_mask: 0,
            value: Variant::Int32(value),
            data_type: DataTypeId::Int32.into(),
            value_rank: -1,
            array_dimensions: None,
            access_level: 3,
            user_access_level: 3,
            minimum_sampling_interval: 0.0,
            historizing: false,
        };
        let item = AddNodesItem {
            parent_node_id: parent_id.clone().into(),
            reference_type_id: ReferenceTypeId::HasComponent.into(),
            requested_new_node_id: node_id.clone().into(),
            browse_name: QualifiedName::new(node_id.namespace, name.as_str()),
            node_class: NodeClass::Variable,
            node_attributes: ExtensionObject::from_message(attrs),
            type_definition: VariableTypeId::BaseDataVariableType.into(),
        };
        let mut env = Envelope::new(op);
        let res = match conn.session.add_nodes(&[item]).await {
            Ok(r) => r,
            Err(e) => {
                if crate::common::is_transport(e.status()) {
                    return Err(svc_err(e, "AddNodes"));
                }
                env.success = false;
                env.service_result = e.status();
                env.error = Some((Category::Service, format!("AddNodes: {e}")));
                return Ok(env);
            }
        };
        let add = res.first().cloned().unwrap_or_default();
        let mut pairs = vec![
            ("parentNodeId", json!(fmt_node_id(&parent_id))),
            ("requestedNodeId", json!(fmt_node_id(&node_id))),
            ("addStatusCode", status_json(add.status_code)),
        ];
        if !add.status_code.is_good() {
            env.success = false;
            env.service_result = add.status_code;
            env.error = Some((Category::Service, "AddNodes failed".into()));
            env.results.push(obj(pairs));
            return Ok(env);
        }
        let added = if add.added_node_id.is_null() { node_id.clone() } else { add.added_node_id.clone() };
        pairs.push(("addedNodeId", json!(fmt_node_id(&added))));
        let rv = ReadValueId {
            node_id: added.clone(),
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        };
        let dv = conn
            .session
            .read(&[rv.clone()], TimestampsToReturn::Neither, 0.0)
            .await
            .map_err(|e| svc_err(e, "Read"))?
            .into_iter()
            .next()
            .unwrap_or_default();
        pairs.push(("readStatusCode", status_json(dv.status())));
        let (dt, bit, val) = match &dv.value {
            Some(v) => variant_json(v),
            None => ("Null".to_owned(), 0, Value::Null),
        };
        pairs.push(("dataType", json!(dt)));
        pairs.push(("builtInType", json!(bit)));
        pairs.push(("value", val));
        let del = match conn
            .session
            .delete_nodes(&[DeleteNodesItem {
                node_id: added.clone(),
                delete_target_references: true,
            }])
            .await
        {
            Ok(v) => v.first().copied().unwrap_or(StatusCode::Good),
            Err(e) => e.status(),
        };
        pairs.push(("deleteStatusCode", status_json(del)));
        let after = conn
            .session
            .read(&[rv], TimestampsToReturn::Neither, 0.0)
            .await
            .map_err(|e| svc_err(e, "Read"))?
            .into_iter()
            .next()
            .unwrap_or_default();
        pairs.push(("readAfterDeleteStatusCode", status_json(after.status())));
        let value_ok = matches!(dv.value, Some(Variant::Int32(v)) if v == value);
        let ok = dv.status().is_good() && value_ok && del.is_good() && after.status().is_bad();
        env.results.push(obj(pairs));
        if !ok {
            env.success = false;
            env.service_result = if !dv.status().is_good() {
                dv.status()
            } else if !del.is_good() {
                del
            } else {
                StatusCode::BadUnexpectedError
            };
            env.error = Some((Category::Service, "node-management sequence failed".into()));
        }
        Ok(env)
    })
}

// ── Discovery without a session ─────────────────────────────────────────────

async fn op_register_server(opts: &Opts) -> Envelope {
    let op = "register-server";
    let parsed = (|| -> Result<_, Failure> {
        let url = opts.required("--endpoint")?.to_owned();
        let uri = opts.required("--server-uri")?.to_owned();
        let urls = opts.all("--discovery-url");
        if urls.is_empty() {
            return Err(Failure::input("missing --discovery-url"));
        }
        let name = opts.get("--server-name").unwrap_or(&uri).to_owned();
        let locale = opts.get("--server-name-locale").unwrap_or("en").to_owned();
        let product = opts.get("--product-uri").unwrap_or("").to_owned();
        let stype = match opts.get("--server-type").unwrap_or("Server") {
            "Server" => opcua::types::ApplicationType::Server,
            "Client" => opcua::types::ApplicationType::Client,
            "ClientAndServer" => opcua::types::ApplicationType::ClientAndServer,
            "DiscoveryServer" => opcua::types::ApplicationType::DiscoveryServer,
            o => return Err(Failure::input(format!("invalid --server-type '{o}'"))),
        };
        let gateway = opts.get("--gateway-server-uri").map(str::to_owned);
        let semaphore = opts.get("--semaphore-file").map(str::to_owned);
        let online = opts.bool("--online", true)?;
        let service = opts.get("--service").unwrap_or("auto").to_owned();
        if !matches!(service.as_str(), "auto" | "RegisterServer2" | "RegisterServer") {
            return Err(Failure::input(format!("invalid --service '{service}'")));
        }
        let mdns = opts.get("--mdns-name").unwrap_or(&name).to_owned();
        let caps = opts.all("--capability");
        let ct = opts.secs("--connect-timeout", 5.0)?;
        Ok((url, uri, urls, name, locale, product, stype, gateway, semaphore, online, service, mdns, caps, ct))
    })();
    let (url, uri, urls, name, locale, product, stype, gateway, semaphore, online, service, mdns, caps, ct) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let ch = match crate::discovery::RawChannel::open(&url, ct).await {
        Ok(c) => c,
        Err(e) => return Envelope::new(op).fail(&connect_failure(&e, "connect")),
    };
    let server = opcua::types::RegisteredServer {
        server_uri: UAString::from(uri.as_str()),
        product_uri: UAString::from(product.as_str()),
        server_names: Some(vec![opcua::types::LocalizedText::new(locale.as_str(), name.as_str())]),
        server_type: stype,
        gateway_server_uri: gateway.map(UAString::from).unwrap_or_else(UAString::null),
        discovery_urls: Some(urls.iter().map(|u| UAString::from(u.as_str())).collect()),
        semaphore_file_path: semaphore.map(UAString::from).unwrap_or_else(UAString::null),
        is_online: online,
    };
    let r = crate::discovery::register(&ch, server, &mdns, &caps, &service).await;
    ch.close().await;
    match r {
        Err(e) => Envelope::new(op).fail(&connect_failure(&e, "register")),
        Ok(o) => {
            let mut env = Envelope::new(op);
            let mut pairs = vec![
                ("service", json!(o.service)),
                ("serverUri", json!(uri)),
                ("isOnline", json!(online)),
                ("statusCode", status_json(o.status)),
                ("fallback", json!(o.fallback)),
            ];
            if let Some(s) = o.register_server2_status {
                pairs.push(("registerServer2StatusCode", status_json(s)));
            }
            pairs.push((
                "configurationResults",
                Value::Array(o.configuration_results.iter().map(|s| status_json(*s)).collect()),
            ));
            env.results.push(obj(pairs));
            env.service_result = o.status;
            let ok = o.status.is_good() && o.configuration_results.iter().all(|s| s.is_good());
            if !ok {
                env.success = false;
                env.error = Some((Category::Service, format!("{} failed", o.service)));
            }
            env
        }
    }
}

async fn op_find_servers_on_network(opts: &Opts) -> Envelope {
    let op = "find-servers-on-network";
    let parsed = (|| -> Result<_, Failure> {
        let url = opts.required("--endpoint")?.to_owned();
        let start: u32 = opts.num("--starting-record-id", 0)?;
        let max: u32 = opts.num("--max-records", 0)?;
        let caps = opts.all("--capability");
        let ct = opts.secs("--connect-timeout", 5.0)?;
        Ok((url, start, max, caps, ct))
    })();
    let (url, start, max, caps, ct) = match parsed {
        Ok(v) => v,
        Err(f) => return Envelope::new(op).fail(&f),
    };
    let ch = match crate::discovery::RawChannel::open(&url, ct).await {
        Ok(c) => c,
        Err(e) => return Envelope::new(op).fail(&connect_failure(&e, "connect")),
    };
    let r = crate::discovery::find_servers_on_network(&ch, start, max, &caps).await;
    ch.close().await;
    match r {
        Err(e) => Envelope::new(op).fail(&connect_failure(&e, "FindServersOnNetwork")),
        Ok(Err(sc)) => Envelope::new(op).fail(&Failure::service(sc, "FindServersOnNetwork failed")),
        Ok(Ok(resp)) => {
            let mut env = Envelope::new(op);
            for s in resp.servers.iter().flatten() {
                let mut pairs = vec![
                    ("recordId", json!(s.record_id)),
                    ("serverName", json!(s.server_name.as_ref())),
                    ("discoveryUrl", json!(s.discovery_url.as_ref())),
                    (
                        "serverCapabilities",
                        json!(s.server_capabilities.iter().flatten().map(|c| c.as_ref().to_owned()).collect::<Vec<_>>()),
                    ),
                ];
                if !resp.last_counter_reset_time.is_null() {
                    pairs.push(("lastCounterResetTime", json!(fmt_datetime(&resp.last_counter_reset_time))));
                }
                env.results.push(obj(pairs));
            }
            env
        }
    }
}

#[allow(dead_code)]
fn _unused(_: &StdMutex<()>, _: ObjectId) {}


#[cfg(test)]
mod alarm_tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn presence_flags() {
        let o = Opts::parse(&args(&["--endpoint", "opc.tcp://x", "--acknowledge", "--confirm", "--add-comment"])).unwrap();
        assert_eq!(o.get("--acknowledge"), Some("true"));
        assert_eq!(o.get("--confirm"), Some("true"));
        assert_eq!(o.get("--add-comment"), Some("true"));
        let o = Opts::parse(&args(&["--acknowledge", "false", "--node", "i=2253"])).unwrap();
        assert!(!o.bool("--acknowledge", true).unwrap());
        assert!(Opts::parse(&args(&["--node"])).is_err());
    }

    #[test]
    fn select_clauses() {
        let c = alarm_select_clauses();
        assert_eq!(c.len(), 16);
        assert_eq!(c[10].browse_path.as_ref().unwrap().len(), 2);
        assert_eq!(c[15].attribute_id, AttributeId::NodeId as u32);
        assert!(c[15].browse_path.as_ref().unwrap().is_empty());
        assert_eq!(c[15].type_definition_id, NodeId::new(0, 2782u32));
    }

    fn cond_event(id: &str, acked: bool) -> Vec<Variant> {
        let mut f = vec![Variant::Empty; 16];
        f[AL_EVENT_ID] = Variant::from(ByteString::from(vec![1u8, 2, 3]));
        f[AL_EVENT_TYPE] = Variant::from(NodeId::new(0, 2915u32));
        f[AL_CONDITION_NAME] = Variant::from(UAString::from("InteropAlarm"));
        f[AL_RETAIN] = Variant::Boolean(true);
        f[AL_ACKED] = Variant::Boolean(acked);
        f[AL_CONFIRMED] = Variant::StatusCode(StatusCode::BadNoMatch);
        f[AL_CONDITION_ID] = Variant::from(NodeId::new(1, id));
        f
    }

    fn typed(t: u32) -> Vec<Variant> {
        let mut f = vec![Variant::Empty; 16];
        f[AL_EVENT_TYPE] = Variant::from(NodeId::new(0, t));
        f
    }

    #[test]
    fn store_and_entry() {
        let mut st = AlarmStore::default();
        st.add(cond_event("before", false)); // before the refresh: not a refreshed condition
        st.phase = 1;
        st.add(typed(REFRESH_START_EVENT_TYPE));
        st.add(cond_event("a", false));
        st.add(cond_event("a", true));
        st.add(typed(2041)); // no ConditionId: ignored
        st.add(typed(REFRESH_END_EVENT_TYPE));
        assert!(st.start_seen && st.end_seen);
        assert_eq!(st.conditions, vec![2]);
        assert_eq!(st.events.len(), 3);
        let e = condition_entry(&st.events[st.conditions[0]]);
        assert_eq!(e["conditionId"], json!("ns=1;s=a"));
        assert_eq!(e["eventId"], json!("AQID"));
        assert_eq!(e["acked"], json!(true));
        assert_eq!(e["confirmed"], Value::Null);
        assert_eq!(e["comment"], Value::Null);
        assert_eq!(e["conditionName"], json!("InteropAlarm"));
        let keys: Vec<&String> = e.as_object().unwrap().keys().collect();
        assert_eq!(keys[0], "conditionId");
        assert_eq!(keys[14], "comment");
    }
}
