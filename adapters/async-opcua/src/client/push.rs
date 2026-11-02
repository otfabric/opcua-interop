//! `client push` (CLIENT_CONTRACT §1 "push flags", §4 `push`, §15): push
//! certificate management (Part 12 §7) against the ServerConfiguration
//! object of the server. async-opcua 0.19 has no push client, so every step
//! is a plain Call on the standard NodeIds of ServerConfiguration and of the
//! TrustList of the selected CertificateGroup, on one session (one
//! transaction, Part 12 §7.10.2).

use std::path::Path;

use opcua::types::{
    AttributeId, DataValue, NodeId, ReadValueId, StatusCode, TimestampsToReturn,
    TransactionErrorType, UAString, Variant,
};
use serde_json::{json, Map, Value};

use super::part12::{
    self, b64_elements, byte_string, byte_string_array, bytes, elements, string_array,
    trust_list_json, TRUST_LIST_MASKS_ALL,
};
use super::{connect, parse_ref, ConnectSpec, Conn, Opts};
use crate::common::{status_json, Category, Envelope, Failure};
use crate::nodeid::{b64, fmt_node_id, NodeRef};
use crate::values::fmt_datetime;

/// ServerConfiguration (Part 12 §7.10) and its methods.
const SERVER_CONFIGURATION: u32 = 12637;
const UPDATE_CERTIFICATE: u32 = 13737;
const CREATE_SIGNING_REQUEST: u32 = 12737;
const GET_REJECTED_LIST: u32 = 12777;
const APPLY_CHANGES: u32 = 12740;
const GET_CERTIFICATES: u32 = 32333;
const CREATE_SELF_SIGNED_CERTIFICATE: u32 = 19342;
const DELETE_CERTIFICATE: u32 = 19345;
const CANCEL_CHANGES: u32 = 25708;
const RESET_TO_SERVER_DEFAULTS: u32 = 25709;
/// ServerConfiguration.TransactionDiagnostics: StartTime, EndTime, Result,
/// AffectedTrustLists, AffectedCertificateGroups, Errors (Part 12 §7.10.12).
const TRANSACTION_DIAGNOSTICS: [u32; 6] = [32337, 32338, 32339, 32340, 32341, 32342];

/// `--group`: the well-known CertificateGroup (Part 12 §7.8.4) and the
/// default CertificateType of the group.
pub fn group_ids(name: &str) -> Option<(u32, u32)> {
    match name {
        // DefaultApplicationGroup, RsaSha256ApplicationCertificateType
        "Application" => Some((14156, 12560)),
        // DefaultHttpsGroup, HttpsCertificateType
        "Https" => Some((14088, 12558)),
        // DefaultUserTokenGroup, UserCredentialCertificateType
        "UserToken" => Some((14122, 15181)),
        _ => None,
    }
}

/// The PrivateKeyFormat of `--update-private-key`: `--private-key-format`,
/// else PFX for `.pfx` / `.p12` files, else PEM.
pub fn private_key_format(flag: Option<&str>, file: &str) -> Result<String, Failure> {
    match flag {
        Some(f @ ("PEM" | "PFX")) => Ok(f.to_owned()),
        Some(f) => Err(Failure::input(format!("--private-key-format must be PEM or PFX, got {f}"))),
        None => {
            let lower = file.to_ascii_lowercase();
            Ok(if lower.ends_with(".pfx") || lower.ends_with(".p12") { "PFX" } else { "PEM" }.to_owned())
        }
    }
}

fn read_certificate(file: &str, flag: &str) -> Result<Vec<u8>, Failure> {
    crate::pki::read_cert_der(Path::new(file)).map_err(|e| Failure::input(format!("{flag} {file}: {e}")))
}

/// The validated flags of `client push`.
pub struct PushArgs {
    group: (u32, u32),
    certificate_type: NodeRef,
    add: Option<Vec<u8>>,
    remove: Option<String>,
    issuer: bool,
    csr: bool,
    apply: bool,
    cancel: bool,
    get_certificates: bool,
    self_signed: bool,
    subject: String,
    dns: Vec<String>,
    ip: Vec<String>,
    lifetime_days: u16,
    key_size: u16,
    delete: Option<NodeRef>,
    update: Option<Vec<u8>>,
    update_key: Option<(String, Vec<u8>)>,
    issuers: Vec<Vec<u8>>,
    reset: bool,
    diagnostics: bool,
}

impl PushArgs {
    /// Parse and check the flags; a bad flag or an unreadable file is an
    /// input error before connecting.
    pub fn parse(opts: &Opts) -> Result<Self, Failure> {
        opts.required("--endpoint")?;
        let group_name = opts.get("--group").unwrap_or("Application");
        let group = group_ids(group_name)
            .ok_or_else(|| Failure::input(format!("--group must be Application, Https or UserToken, got {group_name}")))?;
        let certificate_type = match opts.get("--certificate-type-id") {
            Some(s) => parse_ref(s)?,
            None => parse_ref(&format!("i={}", group.1))?,
        };
        let delete = opts.get("--delete-certificate").map(parse_ref).transpose()?;
        let update_file = opts.get("--update-certificate");
        let key_file = opts.get("--update-private-key");
        if key_file.is_some() && update_file.is_none() {
            return Err(Failure::input("--update-private-key needs --update-certificate"));
        }
        let update_key = match key_file {
            Some(f) => {
                let format = private_key_format(opts.get("--private-key-format"), f)?;
                let raw = std::fs::read(f).map_err(|e| Failure::input(format!("--update-private-key {f}: {e}")))?;
                Some((format, raw))
            }
            None => None,
        };
        let apply = opts.flag("--apply")?;
        let self_signed = opts.flag("--create-self-signed")?;
        let cancel = !apply && (opts.flag("--cancel")? || self_signed || delete.is_some());
        Ok(Self {
            group,
            certificate_type,
            add: opts.get("--add-certificate").map(|f| read_certificate(f, "--add-certificate")).transpose()?,
            remove: opts.get("--remove-certificate").map(str::to_owned),
            issuer: opts.flag("--issuer")?,
            csr: opts.flag("--csr")?,
            apply,
            cancel,
            get_certificates: opts.flag("--get-certificates")?,
            self_signed,
            subject: opts.get("--subject").unwrap_or("").to_owned(),
            dns: opts.all("--dns"),
            ip: opts.all("--ip"),
            lifetime_days: opts.num::<u16>("--lifetime-days", 365)?,
            key_size: opts.num::<u16>("--key-size", 0)?,
            delete,
            update: update_file.map(|f| read_certificate(f, "--update-certificate")).transpose()?,
            update_key,
            issuers: opts
                .all("--issuer-certificate")
                .iter()
                .map(|f| read_certificate(f, "--issuer-certificate"))
                .collect::<Result<_, _>>()?,
            reset: opts.flag("--reset-to-defaults")?,
            diagnostics: opts.flag("--transaction-diagnostics")?,
        })
    }
}

/// The result object and the first failing status.
struct Out {
    m: Map<String, Value>,
    failed: Option<(StatusCode, String)>,
}

impl Out {
    fn set(&mut self, k: &str, v: Value) {
        self.m.insert(k.to_owned(), v);
    }

    /// Record the status of a step; false (and the failure) when it is Bad.
    fn step(&mut self, name: &str, sc: StatusCode) -> bool {
        self.set(&format!("{name}Status"), status_json(sc));
        if sc.is_good() {
            return true;
        }
        if self.failed.is_none() {
            self.failed = Some((sc, format!("{name} returned a non-Good status")));
        }
        false
    }

    fn ok(&self) -> bool {
        self.failed.is_none()
    }
}

pub async fn op_push(opts: &Opts) -> Envelope {
    let op = "push";
    let args = match PushArgs::parse(opts) {
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
    let mut out = Out { m: Map::new(), failed: None };
    let res = steps(&mut conn, &args, &mut out).await;
    conn.close().await;
    let mut env = Envelope::new(op);
    if let Err(f) = res {
        // A transport failure, or a step without a status key of its own
        // (the trust list read): the result so far, failed.
        env = env.fail(&f);
        env.results.push(Value::Object(out.m));
        return env;
    }
    env.results.push(Value::Object(out.m));
    if let Some((sc, msg)) = out.failed {
        env.success = false;
        env.service_result = sc;
        env.error = Some((Category::Service, msg));
    }
    env
}

async fn steps(conn: &mut Conn, a: &PushArgs, out: &mut Out) -> Result<(), Failure> {
    let sc_obj = NodeId::new(0, SERVER_CONFIGURATION);
    let method = |id: u32| NodeId::new(0, id);
    let group = NodeId::new(0, a.group.0);
    let cert_type = conn.resolve(&a.certificate_type).await?;
    out.set("certificateGroupId", json!(fmt_node_id(&group)));

    // The TrustList of the group and its TrustListType methods.
    let tl = match part12::translate(conn, &group, &[&["TrustList"], &["TrustList", "AddCertificate"], &["TrustList", "RemoveCertificate"]]).await? {
        Ok(ids) => ids,
        Err(sc) => return Err(Failure::service(sc, format!("the TrustList of {} not found: {sc}", fmt_node_id(&group)))),
    };
    let (trust_list, add_method, remove_method) = (&tl[0], &tl[1], &tl[2]);
    match part12::read_trust_list(conn, trust_list, Some(TRUST_LIST_MASKS_ALL)).await? {
        Ok(l) => out.set("trustList", trust_list_json(&l)),
        Err(sc) => return Err(Failure::service(sc, format!("reading the TrustList {}: {sc}", fmt_node_id(trust_list)))),
    }

    if let Some(cert) = &a.add {
        let r = part12::call(conn, trust_list, add_method, vec![byte_string(cert), Variant::Boolean(!a.issuer)]).await?;
        out.step("addCertificate", r.status);
    }
    if out.ok() {
        if let Some(thumb) = &a.remove {
            let r = part12::call(
                conn,
                trust_list,
                remove_method,
                vec![Variant::String(UAString::from(thumb.as_str())), Variant::Boolean(!a.issuer)],
            )
            .await?;
            out.step("removeCertificate", r.status);
        }
    }
    if out.ok() && a.get_certificates {
        let r = part12::call(conn, &sc_obj, &method(GET_CERTIFICATES), vec![Variant::from(group.clone())]).await?;
        if out.step("getCertificates", r.status) {
            let types: Vec<Value> = elements(r.outputs.first())
                .iter()
                .filter_map(|v| part12::node_id(Some(v)))
                .map(|n| json!(fmt_node_id(&n)))
                .collect();
            out.set("certificateTypeIds", Value::Array(types));
            out.set("certificates", b64_elements(r.outputs.get(1)));
        }
    }
    if out.ok() && a.self_signed {
        let r = part12::call(
            conn,
            &sc_obj,
            &method(CREATE_SELF_SIGNED_CERTIFICATE),
            vec![
                Variant::from(group.clone()),
                Variant::from(cert_type.clone()),
                Variant::String(UAString::from(a.subject.as_str())),
                string_array(&a.dns),
                string_array(&a.ip),
                Variant::UInt16(a.lifetime_days),
                Variant::UInt16(a.key_size),
            ],
        )
        .await?;
        if out.step("createSelfSignedCertificate", r.status) {
            out.set("selfSignedCertificate", json!(b64(&bytes(r.outputs.first()))));
        }
    }
    if out.ok() {
        if let Some(t) = &a.delete {
            let type_id = conn.resolve(t).await?;
            let r = part12::call(conn, &sc_obj, &method(DELETE_CERTIFICATE), vec![Variant::from(group.clone()), Variant::from(type_id)]).await?;
            out.step("deleteCertificate", r.status);
        }
    }
    if out.ok() {
        if let Some(cert) = &a.update {
            let (format, key) = match &a.update_key {
                Some((f, k)) => (f.as_str(), byte_string(k)),
                None => ("", Variant::ByteString(Default::default())),
            };
            let r = part12::call(
                conn,
                &sc_obj,
                &method(UPDATE_CERTIFICATE),
                vec![
                    Variant::from(group.clone()),
                    Variant::from(cert_type.clone()),
                    byte_string(cert),
                    byte_string_array(&a.issuers),
                    Variant::String(UAString::from(format)),
                    key,
                ],
            )
            .await?;
            if out.step("updateCertificate", r.status) {
                let required = matches!(r.outputs.first(), Some(Variant::Boolean(true)));
                out.set("applyChangesRequired", json!(required));
            }
        }
    }
    if out.ok() && a.csr {
        let r = part12::call(
            conn,
            &sc_obj,
            &method(CREATE_SIGNING_REQUEST),
            vec![
                Variant::from(group.clone()),
                Variant::from(cert_type.clone()),
                Variant::String(UAString::null()),
                Variant::Boolean(false),
                Variant::ByteString(Default::default()),
            ],
        )
        .await?;
        if out.step("createSigningRequest", r.status) {
            out.set("certificateSigningRequest", json!(b64(&bytes(r.outputs.first()))));
        }
    }
    if out.ok() {
        let r = part12::call(conn, &sc_obj, &method(GET_REJECTED_LIST), vec![]).await?;
        if out.step("getRejectedList", r.status) {
            out.set("rejectedCertificates", b64_elements(r.outputs.first()));
        }
    }
    if out.ok() && a.reset {
        let r = part12::call(conn, &sc_obj, &method(RESET_TO_SERVER_DEFAULTS), vec![]).await?;
        out.step("resetToServerDefaults", r.status);
    }
    let mut applied = false;
    if out.ok() && a.apply {
        let r = part12::call(conn, &sc_obj, &method(APPLY_CHANGES), vec![]).await?;
        out.step("applyChanges", r.status);
        applied = true;
    }
    if out.ok() && a.cancel {
        let r = part12::call(conn, &sc_obj, &method(CANCEL_CHANGES), vec![]).await?;
        out.step("cancelChanges", r.status);
    }
    // The diagnostics explain a failed ApplyChanges too: read them also then.
    if a.diagnostics && (out.ok() || applied) {
        let (sc, diag) = transaction_diagnostics(conn).await?;
        out.set("transactionDiagnosticsStatus", status_json(sc));
        if let Some(d) = diag {
            out.set("transactionDiagnostics", d);
        }
        if out.ok() && !sc.is_good() {
            out.failed = Some((sc, "reading TransactionDiagnostics returned a non-Good status".into()));
        }
    }
    if out.ok() {
        match part12::read_trust_list(conn, trust_list, Some(TRUST_LIST_MASKS_ALL)).await? {
            Ok(l) => out.set("trustListAfter", trust_list_json(&l)),
            Err(sc) => return Err(Failure::service(sc, format!("reading the TrustList {} again: {sc}", fmt_node_id(trust_list)))),
        }
    }
    Ok(())
}

fn node_ids_json(v: Option<&Variant>) -> Value {
    Value::Array(
        elements(v)
            .iter()
            .filter_map(|e| part12::node_id(Some(e)))
            .map(|n| json!(fmt_node_id(&n)))
            .collect(),
    )
}

fn datetime_json(v: Option<&Variant>) -> Value {
    match v {
        Some(Variant::DateTime(d)) if !d.is_null() => json!(fmt_datetime(d)),
        _ => Value::Null,
    }
}

/// The TransactionDiagnostics JSON of the six values (StartTime … Errors).
pub fn transaction_diagnostics_json(values: &[Option<Variant>]) -> Value {
    let v = |i: usize| values.get(i).and_then(|x| x.as_ref());
    let result = match v(2) {
        Some(Variant::StatusCode(s)) => *s,
        _ => StatusCode::Good,
    };
    let errors: Vec<Value> = elements(v(5))
        .iter()
        .map(|e| match e {
            Variant::ExtensionObject(eo) => match eo.inner_as::<TransactionErrorType>() {
                Some(t) => json!({
                    "targetId": fmt_node_id(&t.target_id),
                    "error": status_json(t.error),
                    "message": t.message.text.value().clone(),
                }),
                None => json!({"targetId": "i=0", "error": status_json(StatusCode::BadDecodingError), "message": null}),
            },
            _ => json!({"targetId": "i=0", "error": status_json(StatusCode::BadDecodingError), "message": null}),
        })
        .collect();
    json!({
        "startTime": datetime_json(v(0)),
        "endTime": datetime_json(v(1)),
        "result": status_json(result),
        "affectedTrustLists": node_ids_json(v(3)),
        "affectedCertificateGroups": node_ids_json(v(4)),
        "errors": errors,
    })
}

/// Read the TransactionDiagnostics variables of ServerConfiguration in one
/// Read: Good and the JSON, or the first Bad status.
async fn transaction_diagnostics(conn: &Conn) -> Result<(StatusCode, Option<Value>), Failure> {
    let nodes: Vec<ReadValueId> = TRANSACTION_DIAGNOSTICS
        .iter()
        .map(|id| ReadValueId {
            node_id: NodeId::new(0, *id),
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        })
        .collect();
    let dvs: Vec<DataValue> = match conn.session.read(&nodes, TimestampsToReturn::Neither, 0.0).await {
        Ok(d) => d,
        Err(e) => {
            let sc = e.status();
            if crate::common::is_transport(sc) || crate::common::is_timeout(sc) {
                return Err(Failure::from_status(sc, format!("read TransactionDiagnostics: {e}")));
            }
            return Ok((sc, None));
        }
    };
    if dvs.len() != nodes.len() {
        return Ok((StatusCode::BadUnexpectedError, None));
    }
    if let Some(bad) = dvs.iter().filter_map(|d| d.status).find(|s| !s.is_good()) {
        return Ok((bad, None));
    }
    let values: Vec<Option<Variant>> = dvs.into_iter().map(|d| d.value).collect();
    Ok((StatusCode::Good, Some(transaction_diagnostics_json(&values))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua::types::{DateTime, ExtensionObject, LocalizedText, VariantScalarTypeId};

    fn opts(a: &[&str]) -> Opts {
        Opts::parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn groups_and_key_format() {
        assert_eq!(group_ids("Application"), Some((14156, 12560)));
        assert_eq!(group_ids("Https"), Some((14088, 12558)));
        assert_eq!(group_ids("UserToken"), Some((14122, 15181)));
        assert_eq!(group_ids("Other"), None);
        assert_eq!(private_key_format(None, "/work/k.PFX").unwrap(), "PFX");
        assert_eq!(private_key_format(None, "k.p12").unwrap(), "PFX");
        assert_eq!(private_key_format(None, "k.pem").unwrap(), "PEM");
        assert_eq!(private_key_format(Some("PEM"), "k.pfx").unwrap(), "PEM");
        assert!(private_key_format(Some("DER"), "k").is_err());
    }

    #[test]
    fn parse_flags() {
        let a = PushArgs::parse(&opts(&["--endpoint", "opc.tcp://x", "--group", "Https", "--create-self-signed", "--dns", "a", "--dns", "b", "--lifetime-days", "2"])).unwrap();
        assert_eq!(a.group, (14088, 12558));
        assert!(a.self_signed && a.cancel && !a.apply);
        assert_eq!(a.dns, vec!["a", "b"]);
        assert_eq!(a.lifetime_days, 2);
        let a = PushArgs::parse(&opts(&["--endpoint", "e", "--delete-certificate", "i=12560", "--apply", "--transaction-diagnostics"])).unwrap();
        assert!(a.apply && !a.cancel && a.diagnostics && a.delete.is_some());
        let a = PushArgs::parse(&opts(&["--endpoint", "e", "--cancel"])).unwrap();
        assert!(a.cancel);
        for bad in [
            vec!["--endpoint", "e", "--group", "Nope"],
            vec!["--endpoint", "e", "--lifetime-days", "70000"],
            vec!["--endpoint", "e", "--key-size", "-1"],
            vec!["--endpoint", "e", "--add-certificate", "/nonexistent/x.der"],
            vec!["--endpoint", "e", "--update-private-key", "k.pem"],
            vec!["--endpoint", "e", "--delete-certificate", "x=bad"],
            vec!["--group", "Https"],
        ] {
            let f = PushArgs::parse(&opts(&bad)).err().unwrap_or_else(|| panic!("{bad:?} accepted"));
            assert_eq!(f.category, Category::Input, "{bad:?}");
        }
    }

    #[test]
    fn diagnostics_json() {
        let err = TransactionErrorType {
            target_id: NodeId::new(0, 14156u32),
            error: StatusCode::BadInvalidState,
            message: LocalizedText::new("en", "in use"),
        };
        let values = vec![
            Some(Variant::DateTime(Box::new(DateTime::now()))),
            Some(Variant::DateTime(Box::new(DateTime::null()))),
            Some(Variant::StatusCode(StatusCode::BadInvalidState)),
            Some(part12::array(VariantScalarTypeId::NodeId, vec![Variant::from(NodeId::new(0, 12642u32))])),
            None,
            Some(part12::array(VariantScalarTypeId::ExtensionObject, vec![Variant::ExtensionObject(ExtensionObject::from_message(err))])),
        ];
        let j = transaction_diagnostics_json(&values);
        assert!(j["startTime"].is_string());
        assert!(j["endTime"].is_null());
        assert_eq!(j["result"]["name"], json!("BadInvalidState"));
        assert_eq!(j["affectedTrustLists"], json!(["i=12642"]));
        assert_eq!(j["affectedCertificateGroups"], json!([]));
        assert_eq!(j["errors"][0]["targetId"], json!("i=14156"));
        assert_eq!(j["errors"][0]["error"]["name"], json!("BadInvalidState"));
        assert_eq!(j["errors"][0]["message"], json!("in use"));
    }
}
