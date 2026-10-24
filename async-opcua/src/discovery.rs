//! Discovery services on a SecureChannel without a Session: RegisterServer2 /
//! RegisterServer (client `register-server`, server `--register-with`) and
//! FindServersOnNetwork. The async-opcua client only wraps RegisterServer
//! (`Client::register_server`), so these requests are sent on a raw
//! `AsyncSecureChannel` (SecurityPolicy None, like the Milo adapter).

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use opcua::client::transport::{TcpConnector, TransportConfiguration, TransportPollResult};
use opcua::client::{AsyncSecureChannel, SessionRetryPolicy};
use opcua::core::ResponseMessage;
use opcua::crypto::{CertificateStore, SecurityPolicy};
use opcua::sync::RwLock;
use opcua::types::{
    ApplicationType, ContextOwned, DateTime, DecodingOptions, EndpointDescription,
    ExtensionObject, FindServersOnNetworkRequest, FindServersOnNetworkResponse, LocalizedText,
    MdnsDiscoveryConfiguration, MessageSecurityMode, NamespaceMap, NodeId,
    RegisterServer2Request, RegisterServerRequest, RegisteredServer, RequestHeader, StatusCode,
    UAString,
};

use crate::common::ADAPTER;

pub struct RawChannel {
    pub channel: Arc<AsyncSecureChannel>,
    poll: tokio::task::JoinHandle<()>,
    timeout: Duration,
}

impl RawChannel {
    pub async fn open(url: &str, timeout: Duration) -> Result<Self, opcua::types::Error> {
        let dir = std::env::temp_dir().join(format!(
            "async-opcua-discovery-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::create_dir_all(dir.join("trusted"));
        let _ = std::fs::create_dir_all(dir.join("rejected"));
        let store = Arc::new(RwLock::new(CertificateStore::new(&dir)));
        let endpoint = EndpointDescription::from((
            url,
            SecurityPolicy::None.to_uri(),
            MessageSecurityMode::None,
        ));
        let channel = Arc::new(AsyncSecureChannel::new(
            store,
            endpoint.into(),
            SessionRetryPolicy::new(Duration::from_millis(500), Some(0), Duration::from_millis(100)),
            true,
            Arc::new(ArcSwap::new(Arc::new(NodeId::null()))),
            TransportConfiguration {
                send_buffer_size: 65535,
                recv_buffer_size: 65535,
                max_message_size: 0,
                max_chunk_count: 0,
            },
            60_000,
            Arc::new(RwLock::new(ContextOwned::new_default(
                NamespaceMap::new(),
                DecodingOptions::default(),
            ))),
        ));
        let connector = TcpConnector::new(url)?;
        let mut evt = tokio::time::timeout(timeout, channel.connect(&connector))
            .await
            .map_err(|_| opcua::types::Error::new(StatusCode::BadTimeout, "connect timed out"))??;
        let poll = tokio::spawn(async move {
            loop {
                if let TransportPollResult::Closed(_) = evt.poll().await {
                    break;
                }
            }
        });
        Ok(Self {
            channel,
            poll,
            timeout,
        })
    }

    pub fn header(&self) -> RequestHeader {
        RequestHeader {
            authentication_token: NodeId::null(),
            timestamp: DateTime::now(),
            request_handle: self.channel.request_handle(),
            timeout_hint: self.timeout.as_millis() as u32,
            ..Default::default()
        }
    }

    pub async fn close(self) {
        self.channel.close_channel().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), self.poll).await;
    }
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub struct RegisterOutcome {
    pub service: &'static str,
    pub status: StatusCode,
    pub fallback: bool,
    pub register_server2_status: Option<StatusCode>,
    pub configuration_results: Vec<StatusCode>,
}

fn unsupported(sc: StatusCode) -> bool {
    matches!(
        sc,
        StatusCode::BadServiceUnsupported | StatusCode::BadNotImplemented | StatusCode::BadNotSupported
    )
}

/// RegisterServer2 and/or RegisterServer. `service` is `auto`,
/// `RegisterServer2` or `RegisterServer`.
pub async fn register(
    ch: &RawChannel,
    server: RegisteredServer,
    mdns_name: &str,
    capabilities: &[String],
    service: &str,
) -> Result<RegisterOutcome, opcua::types::Error> {
    let mut r2_status = None;
    let mut config_results = Vec::new();
    if service == "auto" || service == "RegisterServer2" {
        let mdns = MdnsDiscoveryConfiguration {
            mdns_server_name: UAString::from(mdns_name),
            server_capabilities: Some(capabilities.iter().map(|c| UAString::from(c.as_str())).collect()),
        };
        let req = RegisterServer2Request {
            request_header: ch.header(),
            server: server.clone(),
            discovery_configuration: Some(vec![ExtensionObject::from_message(mdns)]),
        };
        let resp = ch.channel.send(req, ch.timeout).await?;
        let sc = resp.response_header().service_result;
        if let ResponseMessage::RegisterServer2(r) = &resp {
            config_results = r.configuration_results.clone().unwrap_or_default();
        }
        r2_status = Some(sc);
        if service == "RegisterServer2" || !unsupported(sc) {
            return Ok(RegisterOutcome {
                service: "RegisterServer2",
                status: sc,
                fallback: false,
                register_server2_status: r2_status,
                configuration_results: config_results,
            });
        }
    }
    let req = RegisterServerRequest {
        request_header: ch.header(),
        server,
    };
    let resp = ch.channel.send(req, ch.timeout).await?;
    Ok(RegisterOutcome {
        service: "RegisterServer",
        status: resp.response_header().service_result,
        fallback: r2_status.is_some(),
        register_server2_status: r2_status,
        configuration_results: Vec::new(),
    })
}

pub async fn find_servers_on_network(
    ch: &RawChannel,
    starting_record_id: u32,
    max_records: u32,
    capabilities: &[String],
) -> Result<Result<FindServersOnNetworkResponse, StatusCode>, opcua::types::Error> {
    let req = FindServersOnNetworkRequest {
        request_header: ch.header(),
        starting_record_id,
        max_records_to_return: max_records,
        server_capability_filter: if capabilities.is_empty() {
            None
        } else {
            Some(capabilities.iter().map(|c| UAString::from(c.as_str())).collect())
        },
    };
    let resp = ch.channel.send(req, ch.timeout).await?;
    match resp {
        ResponseMessage::FindServersOnNetwork(r) if r.response_header.service_result.is_good() => {
            Ok(Ok(*r))
        }
        other => Ok(Err(other.response_header().service_result)),
    }
}

fn registered_server(
    server_uri: &str,
    product_uri: &str,
    name: &str,
    discovery_url: &str,
    online: bool,
) -> RegisteredServer {
    RegisteredServer {
        server_uri: UAString::from(server_uri),
        product_uri: UAString::from(product_uri),
        server_names: Some(vec![LocalizedText::new("en", name)]),
        server_type: ApplicationType::Server,
        gateway_server_uri: UAString::null(),
        discovery_urls: Some(vec![UAString::from(discovery_url)]),
        semaphore_file_path: UAString::null(),
        is_online: online,
    }
}

async fn register_once(
    lds: &str,
    server_uri: &str,
    product_uri: &str,
    name: &str,
    discovery_url: &str,
    online: bool,
) -> Result<RegisterOutcome, String> {
    let ch = RawChannel::open(lds, Duration::from_secs(5))
        .await
        .map_err(|e| e.to_string())?;
    let r = register(
        &ch,
        registered_server(server_uri, product_uri, name, discovery_url, online),
        name,
        &["NA".to_owned()],
        "auto",
    )
    .await
    .map_err(|e| e.to_string());
    ch.close().await;
    r
}

/// `server --register-with`: register now and every `interval_ms`.
pub fn spawn_registration(
    lds: String,
    server_uri: String,
    product_uri: String,
    name: String,
    discovery_url: String,
    interval_ms: u64,
    token: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            match register_once(&lds, &server_uri, &product_uri, &name, &discovery_url, true).await {
                Ok(r) => eprintln!(
                    "[{ADAPTER}] info: registered with {lds} via {}: {}",
                    r.service, r.status
                ),
                Err(e) => eprintln!("[{ADAPTER}] warn: registration with {lds} failed: {e}"),
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(interval_ms)) => {}
                _ = token.cancelled() => return,
            }
        }
    });
}

/// Unregister (`IsOnline=false`) on shutdown.
pub async fn unregister(lds: &str, server_uri: &str, product_uri: &str, name: &str, url: &str) {
    match tokio::time::timeout(
        Duration::from_secs(3),
        register_once(lds, server_uri, product_uri, name, url, false),
    )
    .await
    {
        Ok(Ok(r)) => eprintln!("[{ADAPTER}] info: unregistered from {lds} via {}: {}", r.service, r.status),
        Ok(Err(e)) => eprintln!("[{ADAPTER}] warn: unregistration from {lds} failed: {e}"),
        Err(_) => eprintln!("[{ADAPTER}] warn: unregistration from {lds} timed out"),
    }
}
