use core_config::error::ConfigError;
use core_config::types::BoxError;
use std::error::Error;
use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("`{field}` is {value}, outside {min}..={max}")]
    OutOfRange { field: &'static str, value: u64, min: u64, max: u64 },
    #[error("`{smaller}` ({smaller_value}) must not exceed `{larger}` ({larger_value})")]
    Inconsistent {
        smaller: &'static str,
        smaller_value: u64,
        larger: &'static str,
        larger_value: u64,
    },
    #[error("`{field}` is invalid: {reason}")]
    Invalid { field: &'static str, reason: &'static str },
}


#[derive(Debug, Error)]
pub enum IngestError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("invalid settings: {0}")]
    Settings(#[from] SettingsError),
}


/// The message stays with the caller: it flushes and pushes again, or leaves it unacknowledged for redelivery.
#[derive(Debug, Error)]
pub enum PushError {
    #[error("the buffer holds {buffered} of {cap} bytes, the message was refused")]
    BufferFull { buffered: usize, cap: usize },
    #[error("the open batch belongs to tenant `{open}`, flush it before pushing tenant `{incoming}`")]
    OtherTenant { open: String, incoming: String },
}


/// Refused before the batcher; the text never echoes the subject, which a peer chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TenantError {
    #[error("the subject does not follow the events subject layout")]
    Subject,
    #[error("the tenant token is empty")]
    Empty,
    #[error("the tenant token exceeds the length cap")]
    TooLong,
    #[error("the tenant token is not a valid tenant name")]
    Characters,
}


/// Fixed text per class: a ClickHouse message, which quotes the row, never reaches a log or a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertClass {
    ParseError,
    Unavailable,
    Timeout,
    Unauthorized,
    Rejected,
}


#[derive(Debug, Error)]
pub enum InsertError {
    #[error("ClickHouse insert failed: {0:?}")]
    Class(InsertClass),
    #[error("the ClickHouse password file could not be read")]
    Credentials(#[source] std::io::Error),
    #[error("the ClickHouse password file is refused")]
    CredentialsFile(#[source] core_config::secret_file::SecretFileError),
    #[error("the ClickHouse password file exceeds the size cap")]
    CredentialsTooLarge,
    #[error("the ClickHouse CA file could not be read")]
    CaFile(#[source] std::io::Error),
    #[error("the ClickHouse CA file exceeds the size cap")]
    CaTooLarge,
    #[error("the ClickHouse CA file holds no usable PEM certificate")]
    CaInvalid(#[source] ureq::Error),
}


#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("fetching from the bus failed")]
    Fetch(#[source] core_config::types::BoxError),
}


/// The text is fixed per variant: the cause stays in the source chain, so no credential or payload reaches a log line.
#[derive(Debug, Error)]
pub enum NatsError {
    #[error("the NATS runtime could not start")]
    Runtime(#[source] std::io::Error),
    #[error("the NATS {what} file could not be read")]
    File {
        what: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("the NATS {what} file is refused: {source}")]
    SecretFile {
        what: &'static str,
        #[source]
        source: core_config::secret_file::SecretFileError,
    },
    #[error("the NATS {what} file exceeds the size cap")]
    FileTooLarge { what: &'static str },
    #[error("the NATS CA file holds no readable PEM certificate")]
    CaInvalid(#[source] rustls_pki_types::pem::Error),
    #[error("the NATS CA file holds no usable certificate")]
    CaEmpty,
    #[error("the NATS TLS configuration is invalid")]
    Tls(#[source] rustls::Error),
    #[error("the NATS credentials file is not valid")]
    Credentials(#[source] std::io::Error),
    #[error("the NATS server request failed")]
    Request(#[source] core_config::types::BoxError),
    #[error("the NATS server did not answer before the deadline")]
    Timeout(#[source] tokio::time::error::Elapsed),
    #[error("the NATS server accepts payloads of {server} bytes, above the {cap} byte batch cap")]
    PayloadLimit { server: usize, cap: usize },
    #[error("the NATS durable consumer is not the pre-created one: `{field}` differs")]
    ConsumerConfig { field: &'static str },
    #[error("no NATS session is open")]
    NotConnected,
    #[error("the acknowledgement token is unknown to the NATS session")]
    UnknownToken,
    #[error("the NATS server would not deliver the head of the stream, which exceeds the pull's byte cap")]
    HeadTooLarge,
}


/// What a server's TLS failure is called: never the rustls text, which can list the server certificate's names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum TlsClass {
    #[error("the certificate was refused")]
    Certificate,
    #[error("the TLS alert was received")]
    Alert,
    #[error("the TLS exchange was refused")]
    Protocol,
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


pub fn handshake_class(error: &(dyn Error + 'static)) -> Option<TlsClass> {
    std::iter::successors(Some(error), |inner| next_cause(*inner))
        .find_map(rustls_in)
        .map(class_of)
}


/// What a failed peer exchange is called: fixed text, never a byte the peer sent (an unauthenticated server speaks before TLS).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum PeerFailure {
    #[error("the TLS exchange failed: {0}")]
    Tls(TlsClass),
    #[error("the connection failed: {0:?}")]
    Io(io::ErrorKind),
    #[error("the request failed")]
    Other,
}


/// The `io::ErrorKind` of the first `io::Error` in the cause chain.
pub fn io_kind(error: &(dyn Error + 'static)) -> Option<io::ErrorKind> {
    std::iter::successors(Some(error), |inner| next_cause(*inner))
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .map(io::Error::kind)
}


/// Any failure of an exchange with the server becomes a fixed class with no source: the cause chain can hold peer text (T506).
pub fn without_peer_text(error: BoxError) -> BoxError {
    let failure = handshake_class(error.as_ref())
        .map(PeerFailure::Tls)
        .or_else(|| io_kind(error.as_ref()).map(PeerFailure::Io))
        .unwrap_or(PeerFailure::Other);
    BoxError::from(failure)
}
