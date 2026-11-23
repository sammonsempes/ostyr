use core_audit::error::AuditError;
use core_config::error::{ApplyError, ConfigError};
use std::io;
use std::path::PathBuf;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ClientError {
    #[error("cannot read the CA file {path}: {source}")]
    CaFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the CA certificate is refused")]
    CaInvalid(#[source] ureq::Error),
    #[error("transport failed: {0}")]
    Transport(TransportKind),
    #[error("invalid request: {0}")]
    Request(#[from] ureq::http::Error),
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("the server address must start with https://")]
    InsecureServer,
    #[error("no server address: pass --server or log in first")]
    NoServer,
    #[error("no user configuration directory: pass --config-dir")]
    NoConfigDir,
    #[error("not logged in: run `xdrctl login`")]
    NotLoggedIn,
    #[error("session file {path}: {source}")]
    Session {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("session file {path} is unreadable: {source}")]
    SessionFormat {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("the server refused the request ({status}): {code}: {message}")]
    Refused { status: u16, code: String, message: String },
    #[error("unexpected reply from the server (status {status})")]
    BadReply {
        status: u16,
        category: &'static str,
        line: usize,
        column: usize,
    },
    #[error("cannot read the input: {0}")]
    Input(#[source] io::Error),
    #[error("cannot write the output: {0}")]
    Output(#[from] io::Error),
    #[error("cannot encode the output: {0}")]
    Encode(#[from] serde_json::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{path}: {source}")]
    Directory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Apply(#[from] ApplyError),
    #[error("invalid {0}")]
    InvalidArgument(&'static str),
    #[error("the session is not valid: run `xdrctl login`")]
    Unauthorized,
    #[error("permission denied: the account lacks the permission for this request")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("too many requests: retry later")]
    RateLimited,
    #[error("risk scores unavailable, retry later")]
    Unavailable,
    #[error("apply cancelled")]
    Cancelled,
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
