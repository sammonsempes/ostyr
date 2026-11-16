use core_config::error::ConfigError;
use core_pg::error::PgError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ParseError {
    #[error("cannot read the list: {0}")]
    Read(#[source] std::io::Error),
    #[error("list is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("list is not valid JSON ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("list kind is not {expected}")]
    WrongKind { expected: &'static str },
    #[error("list holds {count} items, above the {max} limit")]
    TooManyItems { count: usize, max: usize },
    #[error("the continue token is outside the allowed grammar")]
    BadContinue,
    #[error("the page run is not complete: it must end on a page without a continue token, within the page limit")]
    Incomplete,
    #[error("the page limits are above their ceilings")]
    BadPageLimits,
}


#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("invalid tenant: {0}")]
    Tenant(#[source] PgError),
    #[error("invalid cluster id: {0}")]
    Cluster(#[source] PgError),
    #[error("the two inventories are not of the same tenant and cluster")]
    ScopeMismatch,
}


/// Every text is fixed: the token, the URL, a continue token and a response body never reach an error.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("api_url must be https://host[:port] with no path, query, fragment or userinfo, at most 255 bytes")]
    ApiUrl,
    #[error("{field} is outside its allowed range {min}..={max}")]
    Range { field: &'static str, min: u64, max: u64 },
    #[error(transparent)]
    Scope(#[from] InventoryError),
    #[error("the token file could not be used")]
    Token(#[source] PgError),
    #[error("the token is not printable ASCII without spaces")]
    TokenEncoding,
    #[error("the CA file could not be used")]
    CaFile(#[source] PgError),
    #[error("the CA file holds no valid certificate")]
    CaInvalid(#[source] ureq::Error),
    #[error("the API request failed: {0}")]
    Transport(TransportKind),
    #[error("the run deadline passed")]
    Deadline,
    #[error("the API answered status {status}")]
    Status { status: u16 },
    #[error("the answer body could not be read")]
    Body(#[source] std::io::Error),
    #[error("an answer is above the {max} byte page limit")]
    TooLarge { max: u64 },
    #[error("the run read more than {max} bytes")]
    RunTooLarge { max: u64 },
    #[error("the access review answer is malformed ({category:?})")]
    ReviewMalformed { category: serde_json::error::Category },
    #[error("the credential may {verb} {resource} (group \"{group}\"): it is not read-only, nothing was listed")]
    WritableCredential { verb: String, group: String, resource: String },
    #[error("the rights of namespace {namespace} cannot be verified: {reason}")]
    RulesUnverifiable { namespace: String, reason: &'static str },
    #[error("the review lists more than {max} {what}")]
    TooMany { what: &'static str, max: usize },
    #[error("the credential may not list {resource}")]
    MissingRead { resource: &'static str },
    #[error(transparent)]
    Parse(#[from] ParseError),
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
