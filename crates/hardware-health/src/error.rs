//! Errors that refuse a whole smartctl output.

use thiserror::Error;


#[derive(Debug, Error)]
pub enum SmartError {
    #[error("reading the smartctl output failed")]
    Read(#[from] std::io::Error),
    #[error("smartctl output is larger than {limit} bytes")]
    Oversized { limit: u64 },
    #[error("smartctl output is not valid JSON ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("smartctl output is not a JSON object")]
    NotAnObject,
    #[error("upsc output has more than {limit} lines")]
    TooManyLines { limit: usize },
    #[error("upsc output is not valid UTF-8")]
    NotUtf8(#[from] std::str::Utf8Error),
    #[error("upsc output repeats a variable name")]
    DuplicateKey,
    #[error("thresholds file is larger than {limit} bytes")]
    ThresholdsTooLarge { limit: usize },
    #[error("thresholds file is not valid")]
    Thresholds(#[source] Box<serde_saphyr::Error>),
    #[error("document nesting is deeper than {limit} levels")]
    TooDeep { limit: usize },
    #[error("redfish {document} document refused")]
    Document {
        document: &'static str,
        #[source]
        source: Box<SmartError>,
    },
    #[error("settings file is larger than {limit} bytes")]
    SettingsTooLarge { limit: usize },
    #[error("settings file is not valid")]
    Settings(#[source] Box<serde_saphyr::Error>),
    #[error("the output holds more than {limit} JSON values")]
    TooManyNodes { limit: usize },
    #[error("setting {field} is out of range")]
    SettingsField { field: &'static str },
    #[error("min_battery_charge must be between 1 and 100")]
    ChargeThresholdRange,
}


impl From<serde_json::Error> for SmartError {
    fn from(error: serde_json::Error) -> Self {
        Self::Malformed {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        }
    }
}


#[derive(Debug, Error)]
pub enum FetchError {
    #[error("device file is larger than {limit} bytes")]
    DevicesTooLarge { limit: usize },
    #[error("device file is not valid at line {line} column {column}")]
    Devices {
        line: u64,
        column: u64,
        #[source]
        source: Box<serde_saphyr::Error>,
    },
    #[error("device file declares more than {limit} devices")]
    TooManyDevices { limit: usize },
    #[error("device {index}: field {field} is refused")]
    InvalidDevice { index: usize, field: &'static str },
    #[error("tenant is refused")]
    Tenant(#[source] core_pg::error::PgError),
    #[error("password file refused")]
    Password(#[source] core_pg::error::PgError),
    #[error("CA file refused")]
    CaFile(#[source] core_pg::error::PgError),
    #[error("CA certificate refused")]
    CaInvalid(#[source] ureq::Error),
}


#[derive(Debug, Error)]
pub enum GetError {
    #[error("deadline reached")]
    Expired,
    #[error("request failed: {0}")]
    Transport(TransportKind),
    #[error("status {0}")]
    Status(u16),
    #[error("reading the body failed")]
    Body(#[source] std::io::Error),
    #[error("body is larger than the limit")]
    Oversized,
}


#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("document nesting is deeper than the limit")]
    TooDeep,
    #[error("document is not valid JSON ({category:?})")]
    Malformed { category: serde_json::error::Category },
    #[error("no Members array")]
    NoMembers,
    #[error("more than {limit} members")]
    TooMany { limit: usize },
    #[error("a member id is refused")]
    BadId,
}


/// What a failed connection tells: a fixed class, never text the peer chose (a rustls name error lists the certificate names raw).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransportKind {
    #[error("the request timed out")]
    Timeout,
    #[error("the TLS handshake was refused")]
    Tls,
    #[error("the connection could not be made")]
    Connect,
    #[error("an I/O failure ({kind})")]
    Io { kind: std::io::ErrorKind },
    #[error("the HTTP exchange was refused")]
    Protocol,
}


/// A certificate refusal is a ureq `Io` of kind `InvalidData`.
pub fn transport_kind(error: &ureq::Error) -> TransportKind {
    match error {
        ureq::Error::Timeout(_) => TransportKind::Timeout,
        ureq::Error::Tls(_) => TransportKind::Tls,
        ureq::Error::Io(source) if source.kind() == std::io::ErrorKind::InvalidData => TransportKind::Tls,
        ureq::Error::Io(source) => TransportKind::Io { kind: source.kind() },
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => TransportKind::Connect,
        _ => TransportKind::Protocol,
    }
}
