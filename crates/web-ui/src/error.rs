use serde_json::error::Category;
use std::error::Error;
use std::io;
use thiserror::Error;


pub const MIN_TIMEOUT_SECONDS: u64 = 1;


pub const MAX_TIMEOUT_SECONDS: u64 = 60;


pub const MAX_API_CONNECTIONS: usize = 60;


pub const MAX_USER_SESSIONS: usize = 100;


pub const MAX_SESSIONS: usize = 1_000_000;


/// Why a call to the REST API gave no usable answer; no variant carries text of the API.
#[derive(Debug, Error)]
pub enum ApiFailure {
    #[error("the API refused the session or the credentials")]
    Unauthorized,
    #[error("the API refused the permission")]
    Forbidden,
    #[error("the API has no such object")]
    NotFound,
    #[error("the API asked to retry later")]
    Throttled,
    #[error("the API refused the request as malformed")]
    BadRequest,
    #[error("the API cannot be reached: {0}")]
    Unavailable(#[source] reqwest::Error),
    #[error("the TLS exchange with the API failed: {0}")]
    Handshake(TlsClass),
    #[error("the API refused the change: {0}")]
    Conflict(&'static str),
    #[error("the API answered with status {0}")]
    Status(u16),
    #[error("the API answer is larger than the bound")]
    TooLarge,
    #[error("the API answer is malformed: {0}")]
    Malformed(&'static str),
    #[error("the API answer is not valid JSON: {category} at line {line} column {column}")]
    Json { category: &'static str, line: usize, column: usize },
}


impl From<serde_json::Error> for ApiFailure {
    fn from(error: serde_json::Error) -> Self {
        let category = match error.classify() {
            Category::Io => "io",
            Category::Syntax => "syntax",
            Category::Data => "data",
            Category::Eof => "eof",
        };
        Self::Json {
            category,
            line: error.line(),
            column: error.column(),
        }
    }
}


#[derive(Debug, Error)]
pub enum SessionError {
    #[error("no randomness: {0}")]
    Random(#[from] core_auth::error::AuthError),
    #[error("the session table is full")]
    Full,
}


/// A settings file that cannot become a runtime.
#[derive(Debug, Error)]
pub enum ConfigIssue {
    #[error("base_url is not a URL: {0}")]
    BadUrl(#[from] url::ParseError),
    #[error("base_url must use https, or http on a loopback host")]
    Scheme,
    #[error("base_url must not carry credentials, a query or a fragment")]
    Decorated,
    #[error("timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}")]
    Timeout,
    #[error("max_connections must be between 1 and {MAX_API_CONNECTIONS}")]
    Connections,
}


#[derive(Debug, Error)]
pub enum WebError {
    #[error("{0}")]
    Startup(#[from] core_api::error::StartupError),
    #[error("configuration: {0}")]
    Config(#[from] core_config::error::ConfigError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("PEM file: {0}")]
    Pem(#[from] rustls_pki_types::pem::Error),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("audit log: {0}")]
    Audit(#[from] core_audit::error::AuditError),
    #[error("file watch: {0}")]
    Watch(#[from] core_config::error::WatchError),
    #[error("HTTP client: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{file} holds no certificate")]
    NoCertificate { file: String },
    #[error("{file} holds more than {max} certificates")]
    TooManyCertificates { file: String, max: usize },
    #[error("the {0} setting cannot change at run time")]
    Fixed(&'static str),
    #[error("max_sessions_per_user must be between 1 and {MAX_USER_SESSIONS}")]
    UserSessions,
    #[error("max_sessions must be between 1 and {MAX_SESSIONS}")]
    Sessions,
    #[error("usage: <web-ui.yaml>")]
    Usage,
}


/// Why a posted form or a query string was refused before any call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormRefusal {
    Timeout,
    TooLarge,
    Malformed,
}


/// What the API's TLS failure is called: never the rustls text, which can list the server certificate's names.
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


/// A request failure with a rustls error in its chain is a fixed `Handshake`; any other stays `Unavailable`.
pub fn unavailable(error: reqwest::Error) -> ApiFailure {
    match handshake_class(&error) {
        Some(class) => ApiFailure::Handshake(class),
        None => ApiFailure::Unavailable(error),
    }
}
