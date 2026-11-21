use core_audit::error::AuditError;
use core_config::secret_file::SecretFileError;
use rustls::server::VerifierBuilderError;
use rustls_pki_types::pem;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::watch::error::RecvError;
use tonic::Status;
use x509_parser::error::X509Error;


/// What a peer's TLS failure is called: never the rustls text, which can list the peer certificate's names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum TlsClass {
    #[error("the certificate was refused")]
    Certificate,
    #[error("the TLS alert was received")]
    Alert,
    #[error("the TLS exchange was refused")]
    Protocol,
    #[error("the connection failed")]
    Other,
}


/// Why serving an established connection ended: a fixed kind, never the text of the peer's bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ServeKind {
    #[error("{0}")]
    Tls(TlsClass),
    #[error("the HTTP/2 exchange failed")]
    Http,
    #[error("the connection failed")]
    Other,
}


pub fn class_of(error: &rustls::Error) -> TlsClass {
    match error {
        rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => TlsClass::Certificate,
        rustls::Error::AlertReceived(_) => TlsClass::Alert,
        _ => TlsClass::Protocol,
    }
}


/// The rustls error itself, or the one an `io::Error` wraps (its `source` skips the wrapped error).
pub fn rustls_in<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a rustls::Error> {
    error.downcast_ref::<rustls::Error>().or_else(|| {
        error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    })
}


/// The next cause: the error an `io::Error` wraps (its `source` skips it), else the plain `source`.
pub fn next_cause<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a (dyn Error + 'static)> {
    error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
        .map(|inner| inner as &(dyn Error + 'static))
        .or_else(|| error.source())
}


pub fn error_class(error: &(dyn Error + 'static)) -> TlsClass {
    std::iter::successors(Some(error), |inner| next_cause(*inner))
        .find_map(rustls_in)
        .map_or(TlsClass::Other, class_of)
}


/// A rustls error in the chain gives its class, else a hyper error gives `Http`, else `Other`.
pub fn serve_kind(error: &(dyn Error + 'static)) -> ServeKind {
    let chain = std::iter::successors(Some(error), |inner| next_cause(*inner));
    let tls = chain.clone().find_map(rustls_in).map(class_of);
    let http = chain.clone().any(|inner| inner.is::<hyper::Error>());
    match (tls, http) {
        (Some(class), _) => ServeKind::Tls(class),
        (None, true) => ServeKind::Http,
        (None, false) => ServeKind::Other,
    }
}


/// The same kind with a fixed text, so a peer's handshake error is never carried further.
pub fn without_peer_text(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), error_class(&error))
}


#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("the peer presented no certificate")]
    NoCertificate,
    #[error("the peer certificate cannot be parsed: {0}")]
    Certificate(#[source] x509_parser::nom::Err<X509Error>),
    #[error("the peer certificate alternative names cannot be read: {0}")]
    Names(#[source] X509Error),
    #[error("the peer certificate must carry exactly one URI name, found {0}")]
    UriCount(usize),
    #[error("the peer certificate serial is negative, which RFC 5280 forbids")]
    NegativeSerial,
    #[error("the URI name {0} is not urn:ostyr:agent:<tenant>:<agent-id>")]
    BadUri(String),
}


#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path}: the key file is refused")]
    KeyPermissions {
        path: PathBuf,
        #[source]
        source: SecretFileError,
    },
    #[error("{path}: {source}")]
    Pem {
        path: PathBuf,
        #[source]
        source: pem::Error,
    },
    #[error("{path}: no certificate found")]
    NoCertificate { path: PathBuf },
    #[error("{path}: the agent CA bundle holds {count} certificates, exactly one is accepted so a revoked serial names one issuer")]
    MultipleAgentCa { path: PathBuf, count: usize },
    #[error("TLS configuration refused: {0}")]
    Tls(#[from] rustls::Error),
    #[error("client certificate verifier refused: {0}")]
    Verifier(#[from] VerifierBuilderError),
    #[error("invalid server name: {0}")]
    ServerName(#[from] rustls_pki_types::InvalidDnsNameError),
    #[error("TLS handshake failed: {0}")]
    Handshake(TlsClass),
    #[error("TLS handshake not finished after {seconds} seconds, connection dropped")]
    HandshakeTimeout { seconds: u64 },
    #[error("no HTTP/2 request {seconds} seconds after the TLS handshake, connection dropped")]
    FirstRequestTimeout { seconds: u64 },
    #[error("TLS handshake dropped to make room for a newer connection")]
    HandshakeEvicted,
    #[error("{limit} authenticated connections already open, connection dropped")]
    ConnectionCapped { limit: usize },
    #[error("peer identity refused: {0}")]
    Identity(#[from] IdentityError),
    #[error("agent certificate {serial} is revoked")]
    Revoked { serial: String },
    #[error("agent {tenant}/{agent_id} holds too many connections, connection refused")]
    TooManyConnections { tenant: String, agent_id: String },
    #[error("the revocation list is no longer maintained, connection closed: {0}")]
    RevocationClosed(#[source] RecvError),
    #[error("connection failed: {0}")]
    Serve(ServeKind),
    #[error("cannot connect: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("call refused: {0}")]
    Status(#[source] Box<Status>),
    #[error("delivery attempt not finished after {seconds} seconds")]
    AttemptTimedOut { seconds: u64 },
    #[error("unary call not answered after {seconds} seconds")]
    CallTimedOut { seconds: u64 },
    #[error("the server closed the event stream with {unacknowledged} batches unacknowledged")]
    StreamEnded { unacknowledged: usize },
    #[error("event delivery abandoned after {attempts} consecutive failed attempts: {last}")]
    RetriesExhausted {
        attempts: u32,
        #[source]
        last: Box<ChannelError>,
    },
}


#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("serial `{0}` is not a hexadecimal number")]
    NotHexadecimal(String),
    #[error("serial `{0}` is zero")]
    Zero(String),
}


#[derive(Debug, Error)]
pub enum SettingsError {
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error("settings out of range: {0}")]
    Invalid(String),
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolDirReason {
    Missing,
    NotDirectory,
    WrongOwner,
    Writable,
}


impl std::fmt::Display for SpoolDirReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "it does not exist",
            Self::NotDirectory => "it is not a directory (a symlink is refused)",
            Self::WrongOwner => "it belongs to neither the agent user nor root",
            Self::Writable => "it is writable by group or others",
        })
    }
}


#[derive(Debug, Error)]
pub enum SinkError {
    #[error("{path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("event file line {line} is not `<tenant> <agent-id> <sequence> <hex>`")]
    Corrupt { line: usize },
    #[error("event file: {0}")]
    Io(#[from] io::Error),
}


#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Channel(#[from] ChannelError),
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error(transparent)]
    Watch(#[from] core_config::error::WatchError),
    #[error(transparent)]
    Sink(#[from] SinkError),
    #[error(transparent)]
    Store(#[from] agent_command::error::StoreError),
    #[error("invalid server address: {0}")]
    Address(#[from] std::net::AddrParseError),
    #[error("input or output failed: {0}")]
    Io(#[from] io::Error),
    #[error("a task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("sequence file {} would overflow", .0.display())]
    SequenceOverflow(PathBuf),
    #[error("sequence file {} does not hold `<used> <count>`", .0.display())]
    Sequence(PathBuf),
    #[error("spool directory of {} is refused: {reason}", .path.display())]
    SpoolDir { path: PathBuf, reason: SpoolDirReason },
    #[error("spool directory ACL refused: {0}")]
    SpoolDirAcl(#[from] sys_windows::types::DirAclError),
    #[error("agent session abandoned after {attempts} consecutive failed attempts")]
    AttemptsExhausted {
        attempts: u32,
        #[source]
        last: Option<Box<ChannelError>>,
    },
}
