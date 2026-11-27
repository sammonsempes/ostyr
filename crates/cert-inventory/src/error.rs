use crate::model::StoreCounts;
use thiserror::Error;
use x509_parser::error::{PEMError, X509Error};


#[derive(Debug, Error)]
pub enum CertError {
    #[error("input is {size} bytes, above the {max} byte limit")]
    InputTooLarge { size: usize, max: usize },
    #[error("input holds more than {max} PEM blocks")]
    TooManyBlocks { max: usize },
    #[error("input holds more than {max} certificates")]
    TooManyCertificates { max: usize },
    #[error("invalid PEM block: {0}")]
    Pem(#[source] PEMError),
    #[error("invalid certificate: {0}")]
    Certificate(#[source] x509_parser::nom::Err<X509Error>),
    #[error("invalid certificate extension: {0}")]
    Extension(#[source] X509Error),
}


/// No variant carries input bytes: the serde_json message is replaced by its position and category.
#[derive(Debug, Error)]
pub enum CtError {
    #[error("get-entries response is {size} bytes, above the {max} byte limit")]
    JsonTooLarge { size: usize, max: usize },
    #[error("get-entries response holds more than {max} entries")]
    TooManyEntries { max: usize },
    #[error("invalid get-entries JSON ({category:?}) at line {line} column {column}")]
    Json {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
}


#[derive(Debug, Error)]
pub enum ScanError {
    #[error("{name} must be at least 1")]
    Zero { name: &'static str },
    #[error("{name} is {value}, above the {max} ceiling")]
    AboveCeiling { name: &'static str, value: u64, max: u64 },
    #[error("an extension is 1 to {max} bytes without a dot or a path separator")]
    BadExtension { max: usize },
}


/// Why one watched zone is refused; fixed text only, the zone itself is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ZoneReason {
    #[error("longer than the hostname limit")]
    TooLong,
    #[error("a label is empty, too long, or starts or ends with a hyphen")]
    BadLabel,
    #[error("only a-z, 0-9, hyphen and dot are allowed")]
    BadCharacter,
    #[error("a zone has at least two labels")]
    TooFewLabels,
    #[error("an IP address or a numeric top-level label")]
    IpLiteral,
    #[error("a public suffix alone watches every registrant")]
    PublicSuffix,
    #[error("listed twice")]
    Duplicate,
}


#[derive(Debug, Error)]
pub enum WatchError {
    #[error(transparent)]
    File(#[from] core_config::error::ConfigError),
    #[error("tenant name refused")]
    Tenant(#[source] core_pg::error::PgError),
    #[error("more than {max} zones")]
    TooManyZones { max: usize },
    #[error("zone {index} refused: {reason}")]
    Zone { index: usize, reason: ZoneReason },
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Timeout,
    Tls,
    Other,
}


/// No variant carries text from the log: statuses are numbers, parse errors are reduced to a category and a position.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("log URL refused: https, or http on loopback, without userinfo, query or fragment")]
    Url,
    #[error("HTTP agent refused")]
    Agent(#[source] siem_ingest::error::InsertError),
    #[error("start is above end")]
    StartAfterEnd,
    #[error("end {end} is not below the tree size {tree_size}")]
    BeyondTree { end: u64, tree_size: u64 },
    #[error("a range holds at most {max} entries")]
    RangeTooWide { max: u64 },
    #[error("transport failure: {0:?}")]
    Transport(TransportKind),
    #[error("the log refused the range (400)")]
    RangeRefused,
    #[error("the log rate-limited the request (429)")]
    RateLimited,
    #[error("the log failed (5xx)")]
    Server,
    #[error("unexpected HTTP status {0}")]
    Status(u16),
    #[error("the answer body could not be read ({0:?})")]
    Body(std::io::ErrorKind),
    #[error("the answer body hit the deadline")]
    Timeout,
    #[error("the tree head answer is above {max} bytes")]
    SthTooLarge { max: usize },
    #[error("the log answered no entry for a valid range")]
    Empty,
    #[error(transparent)]
    Ct(#[from] CtError),
}


#[derive(Debug, Error)]
pub enum RoundError {
    #[error("the scan task failed: {0}")]
    Scan(#[from] tokio::task::JoinError),
    #[error("database: {0}")]
    Pg(#[from] core_pg::error::PgError),
    #[error("store of path {path_index}: {source}")]
    Store {
        path_index: usize,
        counts: StoreCounts,
        #[source]
        source: Box<InventoryStoreError>,
    },
}


#[derive(Debug, Error)]
pub enum InventoryStoreError {
    #[error("database: {0}")]
    Pg(#[from] core_pg::error::PgError),
    #[error("connection: {0}")]
    Lease(#[from] alerts::error::StoreError),
    #[error("the time of the call is outside the range a column can hold")]
    BadNow,
    #[error("a limit does not fit the statement")]
    BadLimit,
    #[error("page size must be between 1 and {limit}")]
    BadPageSize { limit: usize },
    #[error("cursor is malformed")]
    BadCursor,
    #[error("expiring_before is not a Unix time inside years 0 to 9999")]
    BadExpiringBefore,
    #[error("a stored time cannot be written as an RFC 3339 date")]
    Unrepresentable,
    #[error("fingerprint is not 64 lowercase hexadecimal characters")]
    BadFingerprint,
    #[error("the store returned a malformed value in column {column}")]
    BadRow { column: usize },
}
