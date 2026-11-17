use crate::types::BoxError;
use std::io;
use thiserror::Error;


pub const USAGE: &str = "usage: webhook|syslog|otlp <config> <count> <first-sequence>";


#[derive(Debug, Error)]
pub enum ExportError {
    #[error("cannot serialise the event: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("cannot format a timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid certificate: {0}")]
    Certificate(#[source] ureq::Error),
    #[error("invalid server name `{name}`: {source}")]
    ServerName {
        name: String,
        #[source]
        source: rustls::pki_types::InvalidDnsNameError,
    },
    #[error("delivery failed after {attempts} attempt(s)")]
    Exhausted {
        attempts: u32,
        #[source]
        source: Option<BoxError>,
    },
    #[error("the receiver rejected the batch permanently with status {status}")]
    Rejected { status: u16 },
    #[error("cannot resolve the secret reference: {0}")]
    Secret(#[source] BoxError),
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error("the token file is refused")]
    SecretFile(#[source] core_config::secret_file::SecretFileError),
    #[error("the token file {path} is larger than {max} bytes")]
    TokenTooLarge { path: String, max: usize },
    #[error("the token file {0} is empty")]
    TokenEmpty(String),
    #[error("the token file {0} holds a control character")]
    TokenInvalid(String),
    #[error("invalid OTLP setting: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Audit(#[from] core_audit::error::AuditError),
    #[error("{USAGE}")]
    Usage,
    #[error("the configuration has no `{0}` output")]
    MissingSection(&'static str),
}


/// A post error that must not be retried (OTLP/HTTP permanent failure); `deliver` turns it into `ExportError::Rejected`.
#[derive(Debug, Error)]
#[error("permanent rejection with status {status}")]
pub struct PermanentRejection {
    pub status: u16,
}


/// What a failed delivery tells: a fixed class, never text the peer chose (a rustls name error lists the certificate names raw).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransportKind {
    #[error("the request timed out")]
    Timeout,
    #[error("the TLS handshake was refused")]
    Tls,
    #[error("the connection could not be made")]
    Connect,
    #[error("an I/O failure ({kind})")]
    Io { kind: io::ErrorKind },
    #[error("the HTTP exchange was refused")]
    Protocol,
}


/// A certificate refusal is a ureq `Rustls` or an `Io` of kind `InvalidData`.
pub fn transport_kind(error: &ureq::Error) -> TransportKind {
    match error {
        ureq::Error::Timeout(_) => TransportKind::Timeout,
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => TransportKind::Tls,
        ureq::Error::Io(source) if source.kind() == io::ErrorKind::InvalidData => TransportKind::Tls,
        ureq::Error::Io(source) => TransportKind::Io { kind: source.kind() },
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => TransportKind::Connect,
        _ => TransportKind::Protocol,
    }
}


/// A status answer keeps its ureq error (a number, read by `classify_status`); every other failure becomes its fixed kind.
pub fn peer_failure(error: ureq::Error) -> BoxError {
    match error {
        ureq::Error::StatusCode(_) => BoxError::from(error),
        other => BoxError::from(transport_kind(&other)),
    }
}


/// The next cause: the error an `io::Error` wraps (its `source` skips it), else the plain `source`.
pub fn next_cause<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a (dyn std::error::Error + 'static)> {
    error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
        .map(|inner| inner as &(dyn std::error::Error + 'static))
        .or_else(|| error.source())
}


/// The same kind with a fixed text when a rustls error sits inside, so a peer's handshake error is never logged or kept.
pub fn without_peer_text(error: io::Error) -> io::Error {
    let inner_tls = std::iter::successors(Some(&error as &(dyn std::error::Error + 'static)), |cause| next_cause(*cause))
        .any(|cause| cause.is::<rustls::Error>());
    if inner_tls {
        io::Error::new(error.kind(), TransportKind::Tls)
    } else {
        error
    }
}
