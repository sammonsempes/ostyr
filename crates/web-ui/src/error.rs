use thiserror::Error;


pub const MIN_TIMEOUT_SECONDS: u64 = 1;


pub const MAX_TIMEOUT_SECONDS: u64 = 60;


pub const MAX_API_CONNECTIONS: usize = 60;


pub const MAX_USER_SESSIONS: usize = 100;


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
    #[error("the API answered with status {0}")]
    Status(u16),
    #[error("the API answer is larger than the bound")]
    TooLarge,
    #[error("the API answer is malformed: {0}")]
    Malformed(&'static str),
    #[error("the API answer is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
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
