//! Shared pieces of the adapter: identity, the result envelope (CLIENT_CONTRACT
//! §3), status code objects and exit codes (§5).

use opcua::types::StatusCode;
use serde_json::{json, Map, Value};

/// Adapter name as it appears in the envelope, the ready file and
/// print-capabilities.
pub const ADAPTER: &str = "async-opcua";
/// opcua-interop release this adapter belongs to.
pub const ADAPTER_VERSION: &str = "0.15.0";
/// The async-opcua crate version the adapter is built against (Cargo.toml
/// pins it with `=`).
pub const STACK_VERSION: &str = "0.19.0";

pub const EXIT_OK: i32 = 0;
pub const EXIT_INPUT: i32 = 2;
pub const EXIT_TRANSPORT: i32 = 3;
pub const EXIT_SERVICE: i32 = 4;
pub const EXIT_INTERNAL: i32 = 6;
pub const EXIT_TIMEOUT: i32 = 7;

/// Symbolic name of a status code (`Good`, `BadNodeIdUnknown`, …). Info bits
/// are ignored; unknown codes are rendered as hex.
pub fn status_name(sc: StatusCode) -> String {
    let bits = sc.bits();
    if bits & 0xFFFF_0000 == 0 {
        return "Good".to_owned();
    }
    let base = StatusCode::from(bits & 0xFFFF_0000);
    let name = base.sub_code().name();
    if name == "Invalid" {
        format!("0x{:08X}", bits)
    } else {
        name.to_owned()
    }
}

pub fn severity_name(sc: StatusCode) -> &'static str {
    if sc.is_bad() {
        "Bad"
    } else if sc.is_uncertain() {
        "Uncertain"
    } else {
        "Good"
    }
}

/// `{"name": …, "code": …, "severity": …}`
pub fn status_json(sc: StatusCode) -> Value {
    json!({
        "name": status_name(sc),
        "code": sc.bits(),
        "severity": severity_name(sc),
    })
}

/// Error categories of the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Input,
    Transport,
    Service,
    Timeout,
    Internal,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Input => "input",
            Category::Transport => "transport",
            Category::Service => "service",
            Category::Timeout => "timeout",
            Category::Internal => "internal",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Category::Input => EXIT_INPUT,
            Category::Transport => EXIT_TRANSPORT,
            Category::Service => EXIT_SERVICE,
            Category::Timeout => EXIT_TIMEOUT,
            Category::Internal => EXIT_INTERNAL,
        }
    }
}

/// A failed command: category, status and message.
#[derive(Debug, Clone)]
pub struct Failure {
    pub category: Category,
    pub status: StatusCode,
    pub message: String,
}

impl Failure {
    pub fn new(category: Category, status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            category,
            status,
            message: message.into(),
        }
    }

    pub fn input(message: impl Into<String>) -> Self {
        Self::new(Category::Input, StatusCode::BadInvalidArgument, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Category::Internal, StatusCode::BadInternalError, message)
    }

    pub fn service(status: StatusCode, message: impl Into<String>) -> Self {
        Self::new(Category::Service, status, message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(Category::Timeout, StatusCode::BadTimeout, message)
    }

    pub fn transport(status: StatusCode, message: impl Into<String>) -> Self {
        Self::new(Category::Transport, status, message)
    }

    /// Classify an error status returned by the stack for a request: a
    /// connection-level status is a transport failure, a timeout a timeout,
    /// anything else a service failure.
    pub fn from_status(status: StatusCode, message: impl Into<String>) -> Self {
        let cat = if is_timeout(status) {
            Category::Timeout
        } else if is_transport(status) {
            Category::Transport
        } else {
            Category::Service
        };
        Self::new(cat, status, message)
    }
}

pub fn is_timeout(sc: StatusCode) -> bool {
    matches!(
        sc,
        StatusCode::BadTimeout | StatusCode::BadRequestTimeout
    )
}

pub fn is_transport(sc: StatusCode) -> bool {
    matches!(
        sc,
        StatusCode::BadCommunicationError
            | StatusCode::BadConnectionClosed
            | StatusCode::BadConnectionRejected
            | StatusCode::BadNotConnected
            | StatusCode::BadServerNotConnected
            | StatusCode::BadTcpEndpointUrlInvalid
            | StatusCode::BadTcpInternalError
            | StatusCode::BadTcpMessageTooLarge
            | StatusCode::BadTcpMessageTypeInvalid
            | StatusCode::BadTcpNotEnoughResources
            | StatusCode::BadTcpSecureChannelUnknown
            | StatusCode::BadTcpServerTooBusy
            | StatusCode::BadSecureChannelClosed
            | StatusCode::BadSecureChannelIdInvalid
            | StatusCode::BadSecureChannelTokenUnknown
            | StatusCode::BadDisconnect
            | StatusCode::BadShutdown
            | StatusCode::BadServerHalted
            | StatusCode::BadNoCommunication
            | StatusCode::BadResourceUnavailable
            | StatusCode::BadSecurityChecksFailed
            | StatusCode::BadSecurityPolicyRejected
            | StatusCode::BadCertificateUntrusted
            | StatusCode::BadCertificateInvalid
            | StatusCode::BadCertificateTimeInvalid
            | StatusCode::BadCertificateUriInvalid
            | StatusCode::BadCertificateHostNameInvalid
            | StatusCode::BadCertificateUseNotAllowed
            | StatusCode::BadCertificateRevoked
            | StatusCode::BadCertificateIssuerRevocationUnknown
            | StatusCode::BadCertificateRevocationUnknown
            | StatusCode::BadNonceInvalid
            | StatusCode::BadUnexpectedError
    )
}

/// The result envelope of one client command.
pub struct Envelope {
    pub operation: String,
    pub success: bool,
    pub service_result: StatusCode,
    pub results: Vec<Value>,
    pub error: Option<(Category, String)>,
}

impl Envelope {
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_owned(),
            success: true,
            service_result: StatusCode::Good,
            results: Vec::new(),
            error: None,
        }
    }

    pub fn fail(mut self, f: &Failure) -> Self {
        self.success = false;
        self.service_result = f.status;
        self.error = Some((f.category, f.message.clone()));
        self
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("schemaVersion".into(), json!("1.0"));
        m.insert("adapter".into(), json!(ADAPTER));
        m.insert("operation".into(), json!(self.operation));
        m.insert("success".into(), json!(self.success));
        m.insert("serviceResult".into(), status_json(self.service_result));
        m.insert("results".into(), Value::Array(self.results.clone()));
        m.insert(
            "error".into(),
            match &self.error {
                None => Value::Null,
                Some((c, msg)) => json!({"category": c.as_str(), "message": msg}),
            },
        );
        Value::Object(m)
    }

    /// Print the envelope as one line on stdout and return the exit code.
    pub fn emit(&self) -> i32 {
        println!("{}", self.to_json());
        if self.success {
            EXIT_OK
        } else {
            match &self.error {
                Some((c, _)) => c.exit_code(),
                None => EXIT_SERVICE,
            }
        }
    }
}

/// Build an object from (key, value) pairs, keeping the order.
pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_owned(), v);
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_objects() {
        assert_eq!(status_json(StatusCode::Good), json!({"name": "Good", "code": 0, "severity": "Good"}));
        assert_eq!(status_name(StatusCode::BadNodeIdUnknown), "BadNodeIdUnknown");
        assert_eq!(severity_name(StatusCode::UncertainLastUsableValue), "Uncertain");
        // Info bits do not change the name.
        assert_eq!(status_name(StatusCode::from(0x8034_0400)), "BadNodeIdUnknown");
        assert_eq!(status_name(StatusCode::from(0x8FFF_0000)), "0x8FFF0000");
    }

    #[test]
    fn failures_are_classified() {
        assert_eq!(Failure::from_status(StatusCode::BadTimeout, "").category, Category::Timeout);
        assert_eq!(Failure::from_status(StatusCode::BadConnectionClosed, "").category, Category::Transport);
        assert_eq!(Failure::from_status(StatusCode::BadNodeIdUnknown, "").category, Category::Service);
        assert_eq!(Category::Input.exit_code(), EXIT_INPUT);
        assert_eq!(Category::Internal.exit_code(), EXIT_INTERNAL);
    }

    #[test]
    fn envelope() {
        let ok = Envelope::new("read").to_json();
        assert_eq!(ok["adapter"], json!("async-opcua"));
        assert_eq!(ok["success"], json!(true));
        assert_eq!(ok["error"], Value::Null);
        let keys: Vec<&String> = ok.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["schemaVersion", "adapter", "operation", "success", "serviceResult", "results", "error"]);
        let failed = Envelope::new("read").fail(&Failure::input("bad flag"));
        let j = failed.to_json();
        assert_eq!(j["success"], json!(false));
        assert_eq!(j["serviceResult"]["name"], json!("BadInvalidArgument"));
        assert_eq!(j["error"], json!({"category": "input", "message": "bad flag"}));
    }
}
