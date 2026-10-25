//! `client gds-pull` (CLIENT_CONTRACT §16.2): the GDS pull model of Part 12
//! §6.6 / §7.9 against the Directory object of a Global Discovery Server.
//! async-opcua 0.19 has no GDS client: the Directory methods are plain Calls
//! on the standard NodeIds of the GDS namespace, ApplicationRecordDataType
//! (a GDS-namespace structure the stack does not know) is encoded and decoded
//! by the adapter, and the certificate request is a PKCS #10 request made
//! with the RustCrypto crates.

use std::io::Cursor;
use std::str::FromStr;
use std::time::{Duration, Instant};

use der::asn1::Ia5String;
use der::Encode;
use opcua::types::{
    BinaryDecodable, BinaryEncodable, ByteString, ContextOwned, DecodingOptions, ExtensionObject,
    LocalizedText, NamespaceMap, NodeId, StatusCode, UAString, Variant,
};
use opcua::types::type_loader::ByteStringBody;
use serde_json::{json, Map, Value};
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;

use super::part12::{self, b64_elements, byte_string, bytes, elements, string_array, trust_list_json};
use super::{connect, ConnectSpec, Conn, Opts};
use crate::common::{status_json, Category, Envelope, Failure};
use crate::nodeid::{b64, fmt_node_id};

/// The GDS namespace (Part 12 Annex A).
pub const GDS_NAMESPACE: &str = "http://opcfoundation.org/UA/GDS/";
/// Directory (ns=GDS) and its methods.
const DIRECTORY: u32 = 141;
const FIND_APPLICATIONS: u32 = 143;
const REGISTER_APPLICATION: u32 = 146;
const UNREGISTER_APPLICATION: u32 = 149;
const START_NEW_KEY_PAIR_REQUEST: u32 = 154;
const START_SIGNING_REQUEST: u32 = 157;
const FINISH_REQUEST: u32 = 163;
const CHECK_REVOCATION_STATUS: u32 = 177;
const GET_TRUST_LIST: u32 = 204;
const GET_CERTIFICATE_STATUS: u32 = 225;
const GET_CERTIFICATE_GROUPS: u32 = 508;
const REVOKE_CERTIFICATE: u32 = 15005;
/// Directory.CertificateGroups.DefaultApplicationGroup (ns=GDS).
const DEFAULT_APPLICATION_GROUP: u32 = 615;
/// ApplicationRecordDataType_Encoding_DefaultBinary (ns=GDS).
const APPLICATION_RECORD_BINARY: u32 = 134;
/// RsaSha256ApplicationCertificateType, EccNistP256ApplicationCertificateType (ns=0).
const RSA_SHA256_TYPE: u32 = 12560;
const NIST_P256_TYPE: u32 = 23538;
/// FinishRequest polling interval while it answers BadNothingToDo.
const FINISH_POLL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKind {
    RsaSha256,
    NistP256,
}

/// The validated flags of `client gds-pull`.
#[derive(Debug)]
pub struct GdsArgs {
    app_uri: String,
    app_name: String,
    /// ApplicationType: Server 0, Client 1, ClientAndServer 2.
    app_type: i32,
    discovery_urls: Vec<String>,
    csr: bool,
    cert: CertKind,
    revoke: bool,
    unregister: bool,
    finish_timeout: Duration,
}

/// The name of the record: the last `:` / `/` segment of the app uri.
pub fn app_name(uri: &str) -> String {
    let last = uri.rsplit([':', '/']).next().unwrap_or("");
    if last.is_empty() {
        "opcua-interop gds-pull app".to_owned()
    } else {
        last.to_owned()
    }
}

impl GdsArgs {
    pub fn parse(opts: &Opts) -> Result<Self, Failure> {
        opts.required("--endpoint")?;
        let app_uri = opts.get("--app-uri").unwrap_or("urn:opcua-interop:gds-pull:app").to_owned();
        let app_type = match opts.get("--app-type").unwrap_or("Server") {
            "Server" => 0,
            "Client" => 1,
            "ClientAndServer" => 2,
            other => return Err(Failure::input(format!("invalid --app-type {other} (Server|Client|ClientAndServer)"))),
        };
        let csr = match opts.get("--request").unwrap_or("csr") {
            "csr" => true,
            "new-key-pair" => false,
            other => return Err(Failure::input(format!("invalid --request {other} (csr|new-key-pair)"))),
        };
        let cert = match opts.get("--certificate-type").unwrap_or("RsaSha256") {
            "RsaSha256" => CertKind::RsaSha256,
            "NistP256" => CertKind::NistP256,
            other => return Err(Failure::input(format!("invalid --certificate-type {other} (RsaSha256|NistP256)"))),
        };
        let mut discovery_urls = opts.all("--discovery-url");
        if discovery_urls.is_empty() {
            discovery_urls.push("opc.tcp://localhost:4850".into());
        }
        Ok(Self {
            app_name: app_name(&app_uri),
            app_uri,
            app_type,
            discovery_urls,
            csr,
            cert,
            revoke: opts.flag("--revoke")?,
            unregister: opts.flag("--unregister")?,
            finish_timeout: Duration::from_millis(opts.num::<u32>("--finish-timeout-ms", 30000)? as u64),
        })
    }

    fn certificate_type(&self) -> NodeId {
        NodeId::new(0, if self.cert == CertKind::RsaSha256 { RSA_SHA256_TYPE } else { NIST_P256_TYPE })
    }

    fn kind(&self) -> &'static str {
        if self.csr {
            "csr"
        } else {
            "new-key-pair"
        }
    }
}

/// Escape an RFC 4514 attribute value.
fn rdn_escape(v: &str) -> String {
    let mut out = String::new();
    for (i, c) in v.chars().enumerate() {
        if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=') || (i == 0 && matches!(c, '#' | ' ')) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A PKCS #10 request (DER) with a fresh key: subject `CN=<name>`, URI SAN =
/// the application uri, DNS SAN `localhost`, SHA-256; RSA 2048 or ECC P-256.
pub fn make_csr(kind: CertKind, name: &str, uri: &str) -> Result<Vec<u8>, String> {
    let subject = Name::from_str(&format!("CN={}", rdn_escape(name))).map_err(|e| format!("subject: {e}"))?;
    let san = SubjectAltName(vec![
        GeneralName::UniformResourceIdentifier(Ia5String::new(uri).map_err(|e| format!("URI SAN: {e}"))?),
        GeneralName::DnsName(Ia5String::new("localhost").map_err(|e| e.to_string())?),
    ]);
    let mut rng = rand::rngs::OsRng;
    let req = match kind {
        CertKind::RsaSha256 => {
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("RSA key: {e}"))?;
            let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key);
            let mut b = RequestBuilder::new(subject, &signer).map_err(|e| e.to_string())?;
            b.add_extension(&san).map_err(|e| e.to_string())?;
            b.build::<rsa::pkcs1v15::Signature>().map_err(|e| e.to_string())?
        }
        CertKind::NistP256 => {
            let signer = p256::ecdsa::SigningKey::random(&mut rng);
            let mut b = RequestBuilder::new(subject, &signer).map_err(|e| e.to_string())?;
            b.add_extension(&san).map_err(|e| e.to_string())?;
            b.build::<p256::ecdsa::DerSignature>().map_err(|e| e.to_string())?
        }
    };
    req.to_der().map_err(|e| e.to_string())
}

fn ctx() -> ContextOwned {
    ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::default())
}

/// The binary body of an ApplicationRecordDataType (Part 12 §6.6.2) with a
/// null ApplicationId.
pub fn encode_application_record(a: &GdsArgs) -> Result<Vec<u8>, String> {
    let ctx = ctx();
    let c = ctx.context();
    let client = a.app_type == 1;
    let mut buf: Vec<u8> = Vec::new();
    let enc = |r: opcua::types::EncodingResult<()>| r.map_err(|e| e.to_string());
    enc(BinaryEncodable::encode(&NodeId::null(), &mut buf, &c))?;
    enc(BinaryEncodable::encode(&UAString::from(a.app_uri.as_str()), &mut buf, &c))?;
    enc(BinaryEncodable::encode(&a.app_type, &mut buf, &c))?;
    enc(BinaryEncodable::encode(&Some(vec![LocalizedText::new("en-US", &a.app_name)]), &mut buf, &c))?;
    enc(BinaryEncodable::encode(&UAString::from("urn:opcua-interop:async-opcua"), &mut buf, &c))?;
    let urls: Vec<UAString> = if client { Vec::new() } else { a.discovery_urls.iter().map(|u| UAString::from(u.as_str())).collect() };
    enc(BinaryEncodable::encode(&Some(urls), &mut buf, &c))?;
    let caps: Vec<UAString> = if client { Vec::new() } else { vec![UAString::from("NA")] };
    enc(BinaryEncodable::encode(&Some(caps), &mut buf, &c))?;
    Ok(buf)
}

/// The ApplicationId (first field) of an ApplicationRecordDataType
/// ExtensionObject the stack decoded as a raw ByteString body.
pub fn application_id(v: &Variant) -> Option<NodeId> {
    let Variant::ExtensionObject(eo) = v else {
        return None;
    };
    let body = eo.inner_as::<ByteStringBody>()?;
    let raw = body.raw_body().value.as_deref()?;
    let ctx = ctx();
    NodeId::decode(&mut Cursor::new(raw), &ctx.context()).ok()
}

struct Steps<'a> {
    conn: &'a Conn,
    item: Map<String, Value>,
    failed: Option<(StatusCode, String)>,
    directory: NodeId,
    ns: u16,
}

impl Steps<'_> {
    fn set(&mut self, k: &str, v: Value) {
        self.item.insert(k.to_owned(), v);
    }

    fn method(&self, id: u32) -> NodeId {
        NodeId::new(self.ns, id)
    }

    /// Call a Directory method; `status_key` gets the status when it is
    /// Good (if `keep_good`) or Bad. None when the step failed.
    async fn call(&mut self, status_key: &str, keep_good: bool, id: u32, inputs: Vec<Variant>) -> Result<Option<Vec<Variant>>, Failure> {
        let r = part12::call(self.conn, &self.directory, &self.method(id), inputs).await?;
        if r.status.is_good() {
            if keep_good {
                self.set(status_key, status_json(r.status));
            }
            return Ok(Some(r.outputs));
        }
        self.set(status_key, status_json(r.status));
        self.failed = Some((r.status, format!("{status_key}: {}", r.status)));
        Ok(None)
    }
}

pub async fn op_gds_pull(opts: &Opts) -> Envelope {
    let op = "gds-pull";
    let args = match GdsArgs::parse(opts) {
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
    let res = run(&mut conn, &args).await;
    conn.close().await;
    match res {
        Err(f) => Envelope::new(op).fail(&f),
        Ok((item, failed)) => {
            let mut env = Envelope::new(op);
            env.results.push(Value::Object(item));
            if let Some((sc, msg)) = failed {
                env.success = false;
                env.service_result = sc;
                env.error = Some((Category::Service, msg));
            }
            env
        }
    }
}

type StepsResult = (Map<String, Value>, Option<(StatusCode, String)>);

async fn run(conn: &mut Conn, a: &GdsArgs) -> Result<StepsResult, Failure> {
    let namespaces = conn.namespaces().await?;
    let ns = namespaces
        .iter()
        .position(|u| u == GDS_NAMESPACE)
        .ok_or_else(|| Failure::service(StatusCode::BadNodeIdUnknown, format!("the server has no namespace {GDS_NAMESPACE}")))?
        as u16;
    let mut s = Steps {
        conn,
        item: Map::new(),
        failed: None,
        directory: NodeId::new(ns, DIRECTORY),
        ns,
    };
    steps(&mut s, a).await?;
    Ok((s.item, s.failed))
}

async fn steps(s: &mut Steps<'_>, a: &GdsArgs) -> Result<(), Failure> {
    let group = NodeId::new(s.ns, DEFAULT_APPLICATION_GROUP);
    let cert_type = a.certificate_type();

    // 1. FindApplications
    let Some(out) = s.call("findApplicationsStatus", false, FIND_APPLICATIONS, vec![Variant::String(UAString::from(a.app_uri.as_str()))]).await? else {
        return Ok(());
    };
    let found: Vec<NodeId> = elements(out.first()).iter().filter_map(application_id).collect();
    s.set("findApplications", json!(found.iter().map(fmt_node_id).collect::<Vec<_>>()));

    // 2. RegisterApplication
    let app_id = match found.first() {
        Some(id) => {
            s.set("registered", json!(false));
            id.clone()
        }
        None => {
            let body = encode_application_record(a).map_err(|e| Failure::internal(format!("ApplicationRecordDataType: {e}")))?;
            let record = ExtensionObject::new(ByteStringBody::new(ByteString::from(body), NodeId::new(s.ns, APPLICATION_RECORD_BINARY)));
            let Some(out) = s.call("registerStatus", true, REGISTER_APPLICATION, vec![Variant::ExtensionObject(record)]).await? else {
                return Ok(());
            };
            s.set("registered", json!(true));
            part12::node_id(out.first()).unwrap_or_else(NodeId::null)
        }
    };
    s.set("applicationId", json!(fmt_node_id(&app_id)));

    // 3. StartSigningRequest / StartNewKeyPairRequest
    s.set("requestKind", json!(a.kind()));
    let out = if a.csr {
        let csr = make_csr(a.cert, &a.app_name, &a.app_uri).map_err(|e| Failure::internal(format!("certificate request: {e}")))?;
        s.call(
            "startRequestStatus",
            true,
            START_SIGNING_REQUEST,
            vec![Variant::from(app_id.clone()), Variant::from(group.clone()), Variant::from(cert_type.clone()), byte_string(&csr)],
        )
        .await?
    } else {
        s.call(
            "startRequestStatus",
            true,
            START_NEW_KEY_PAIR_REQUEST,
            vec![
                Variant::from(app_id.clone()),
                Variant::from(group.clone()),
                Variant::from(cert_type.clone()),
                Variant::String(UAString::from(format!("CN={}", a.app_name))),
                string_array(&["localhost".to_owned()]),
                Variant::String(UAString::from("PEM")),
                Variant::String(UAString::null()),
            ],
        )
        .await?
    };
    let Some(out) = out else {
        return Ok(());
    };
    let request_id = part12::node_id(out.first()).unwrap_or_else(NodeId::null);
    s.set("requestId", json!(fmt_node_id(&request_id)));

    // 4. FinishRequest while it answers BadNothingToDo (pending)
    let deadline = Instant::now() + a.finish_timeout;
    let out = loop {
        let r = part12::call(s.conn, &s.directory, &s.method(FINISH_REQUEST), vec![Variant::from(app_id.clone()), Variant::from(request_id.clone())]).await?;
        if r.status == StatusCode::BadNothingToDo && Instant::now() < deadline {
            tokio::time::sleep(FINISH_POLL).await;
            continue;
        }
        s.set("finishRequestStatus", status_json(r.status));
        if !r.status.is_good() {
            s.failed = Some((r.status, format!("finishRequest: {}", r.status)));
            return Ok(());
        }
        break r.outputs;
    };
    let certificate = bytes(out.first());
    s.set("certificate", json!(b64(&certificate)));
    if !a.csr {
        s.set("privateKeyFormat", json!("PEM"));
        s.set("privateKey", json!(b64(&bytes(out.get(1)))));
    }
    s.set("issuerCertificates", b64_elements(out.get(2)));

    // 5. GetCertificateGroups
    let Some(out) = s.call("getCertificateGroupsStatus", false, GET_CERTIFICATE_GROUPS, vec![Variant::from(app_id.clone())]).await? else {
        return Ok(());
    };
    let groups: Vec<Value> = elements(out.first()).iter().filter_map(|v| part12::node_id(Some(v))).map(|n| json!(fmt_node_id(&n))).collect();
    s.set("certificateGroups", Value::Array(groups));

    // 6. GetTrustList, then read the TrustList (Open, Read, Close)
    let Some(out) = s.call("getTrustListStatus", false, GET_TRUST_LIST, vec![Variant::from(app_id.clone()), Variant::from(group.clone())]).await? else {
        return Ok(());
    };
    let trust_list = part12::node_id(out.first()).unwrap_or_else(NodeId::null);
    s.set("trustListId", json!(fmt_node_id(&trust_list)));
    match part12::read_trust_list(s.conn, &trust_list, None).await? {
        Ok(tl) => s.set("trustList", trust_list_json(&tl)),
        Err(sc) => {
            s.set("readTrustListStatus", status_json(sc));
            s.failed = Some((sc, format!("readTrustList: {sc}")));
            return Ok(());
        }
    }

    // 7. GetCertificateStatus
    let Some(out) = s
        .call(
            "getCertificateStatusStatus",
            true,
            GET_CERTIFICATE_STATUS,
            vec![Variant::from(app_id.clone()), Variant::from(group.clone()), Variant::from(cert_type.clone())],
        )
        .await?
    else {
        return Ok(());
    };
    s.set("updateRequired", json!(matches!(out.first(), Some(Variant::Boolean(true)))));

    // 8. RevokeCertificate, CheckRevocationStatus
    if a.revoke {
        if s.call("revokeStatus", true, REVOKE_CERTIFICATE, vec![Variant::from(app_id.clone()), byte_string(&certificate)]).await?.is_none() {
            return Ok(());
        }
        let Some(out) = s.call("checkRevocationStatus", true, CHECK_REVOCATION_STATUS, vec![byte_string(&certificate)]).await? else {
            return Ok(());
        };
        let status = match out.first() {
            Some(Variant::StatusCode(sc)) => *sc,
            _ => StatusCode::BadUnexpectedError,
        };
        s.set("certificateStatus", status_json(status));
    }

    // 9. UnregisterApplication
    if a.unregister {
        s.call("unregisterStatus", true, UNREGISTER_APPLICATION, vec![Variant::from(app_id.clone())]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(a: &[&str]) -> Opts {
        Opts::parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn names_and_flags() {
        assert_eq!(app_name("urn:otfabric:interop:gds-pull:async-opcua"), "async-opcua");
        assert_eq!(app_name("http://x/y/app"), "app");
        assert_eq!(app_name("urn:x:"), "opcua-interop gds-pull app");
        let a = GdsArgs::parse(&opts(&["--endpoint", "e"])).unwrap();
        assert_eq!(a.app_uri, "urn:opcua-interop:gds-pull:app");
        assert_eq!(a.app_name, "app");
        assert!(a.csr && a.cert == CertKind::RsaSha256 && a.app_type == 0 && !a.revoke && !a.unregister);
        assert_eq!(a.discovery_urls, vec!["opc.tcp://localhost:4850"]);
        assert_eq!(a.certificate_type(), NodeId::new(0, 12560u32));
        let a = GdsArgs::parse(&opts(&["--endpoint", "e", "--request", "new-key-pair", "--certificate-type", "NistP256", "--app-type", "Client", "--revoke", "--unregister"])).unwrap();
        assert!(!a.csr && a.revoke && a.unregister && a.app_type == 1);
        assert_eq!(a.certificate_type(), NodeId::new(0, 23538u32));
        for bad in [
            vec!["--endpoint", "e", "--app-type", "Other"],
            vec!["--endpoint", "e", "--request", "x"],
            vec!["--endpoint", "e", "--certificate-type", "Rsa"],
            vec!["--endpoint", "e", "--finish-timeout-ms", "-5"],
            vec!["--app-uri", "x"],
        ] {
            assert_eq!(GdsArgs::parse(&opts(&bad)).unwrap_err().category, Category::Input, "{bad:?}");
        }
    }

    #[test]
    fn record_round_trip() {
        let a = GdsArgs::parse(&opts(&["--endpoint", "e", "--app-uri", "urn:a:b"])).unwrap();
        let body = encode_application_record(&a).unwrap();
        // A record as a server returns it: the ApplicationId set.
        let ctx = ctx();
        let mut rec = Vec::new();
        BinaryEncodable::encode(&NodeId::new(2, 77u32), &mut rec, &ctx.context()).unwrap();
        rec.extend_from_slice(&body[NodeId::null().byte_len(&ctx.context())..]);
        let eo = ExtensionObject::new(ByteStringBody::new(ByteString::from(rec), NodeId::new(2, 134u32)));
        assert_eq!(application_id(&Variant::ExtensionObject(eo)), Some(NodeId::new(2, 77u32)));
        // Decoding the fields back.
        let mut c = Cursor::new(&body[..]);
        let cx = ctx.context();
        assert!(NodeId::decode(&mut c, &cx).unwrap().is_null());
        assert_eq!(UAString::decode(&mut c, &cx).unwrap().as_ref(), "urn:a:b");
        assert_eq!(i32::decode(&mut c, &cx).unwrap(), 0);
        let names = <Option<Vec<LocalizedText>>>::decode(&mut c, &cx).unwrap().unwrap();
        assert_eq!(names[0].text.as_ref(), "b");
        assert_eq!(UAString::decode(&mut c, &cx).unwrap().as_ref(), "urn:opcua-interop:async-opcua");
        assert_eq!(<Option<Vec<UAString>>>::decode(&mut c, &cx).unwrap().unwrap().len(), 1);
        assert_eq!(<Option<Vec<UAString>>>::decode(&mut c, &cx).unwrap().unwrap()[0].as_ref(), "NA");
        assert_eq!(c.position() as usize, body.len());
    }

    #[test]
    fn csr() {
        use der::Decode;
        for kind in [CertKind::RsaSha256, CertKind::NistP256] {
            let der = make_csr(kind, "my, app", "urn:a:b").unwrap();
            let req = x509_cert::request::CertReq::from_der(&der).unwrap();
            assert_eq!(req.info.subject.to_string(), "CN=my\\, app");
            assert_eq!(req.info.attributes.len(), 1, "extensionRequest");
        }
    }
}
