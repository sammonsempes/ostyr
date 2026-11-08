use core_audit::error::AuditError;
use rustls::server::VerifierBuilderError;
use rustls_pki_types::pem;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::watch::error::RecvError;
use tonic::Status;
use x509_parser::error::X509Error;


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
    #[error("{path}: the key file must not be accessible by group or other: {source}")]
    KeyPermissions {
        path: PathBuf,
        #[source]
        source: AuditError,
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
    Handshake(#[source] io::Error),
    #[error("TLS handshake not finished after {seconds} seconds, connection dropped")]
    HandshakeTimeout { seconds: u64 },
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
    Serve(#[source] Box<dyn Error + Send + Sync>),
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
    #[error("sequence file {} does not hold `<used> <count>`", .0.display())]
    Sequence(PathBuf),
    #[error("agent session abandoned after {attempts} consecutive failed attempts")]
    AttemptsExhausted {
        attempts: u32,
        #[source]
        last: Option<Box<ChannelError>>,
    },
}
