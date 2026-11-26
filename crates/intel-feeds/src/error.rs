use crate::config::TaxiiConfigError;
use crate::limits::{MAX_DOCUMENT_BYTES, MAX_FEED_IOCS, MAX_MISP_ATTRIBUTES, MAX_TAXII_OBJECTS_PER_PAGE, MAX_URL_BYTES};
use core_pg::error::PgError;
use serde_json::error::Category;
use siem_ingest::error::InsertError;
use std::io;
use std::str::Utf8Error;
use thiserror::Error;


/// A fixed category for a refused secret or CA file: never the path, never the cause text.
pub fn pg_category(failure: &PgError) -> &'static str {
    match failure {
        PgError::Io { .. } => "unreadable",
        PgError::NotRegular { .. } | PgError::SecretSymlink { .. } => "not a regular file",
        PgError::SecretMode { .. } | PgError::SecretOwner { .. } => "permissions",
        PgError::TooLarge { .. } => "too large",
        PgError::EmptyPassword { .. } => "empty",
        _ => "invalid",
    }
}


#[derive(Debug, Error)]
pub enum CanonError {
    #[error("invalid address: {0}")]
    Address(#[source] std::net::AddrParseError),
    #[error("invalid network: {0}")]
    Network(#[source] ipnet::AddrParseError),
    #[error("invalid domain name")]
    Domain(#[source] idna::Errors),
    #[error("invalid URL: {0}")]
    Url(#[source] url::ParseError),
    #[error("URL without a host or longer than {MAX_URL_BYTES} bytes")]
    UrlShape,
    #[error("network or domain too broad to match on")]
    TooBroad,
    #[error("hash must be {expected} hexadecimal characters")]
    Hash { expected: usize },
}


/// One feed entry that cannot be used; the feed itself goes on.
#[derive(Debug, Error)]
pub enum EntryError {
    #[error("line longer than the cap")]
    LineTooLong,
    #[error("object larger than the cap")]
    ObjectTooLarge,
    #[error("line is not UTF-8: {0}")]
    InvalidUtf8(#[source] Utf8Error),
    #[error("malformed CSV: {0}")]
    Csv(#[source] csv::Error),
    #[error("entry is not a JSON object")]
    NotAnObject,
    #[error("missing field `{0}`")]
    MissingField(&'static str),
    #[error("invalid timestamp `{value}`: {source}")]
    Timestamp {
        value: String,
        #[source]
        source: time::error::Parse,
    },
    #[error("timestamp `{value}` is out of range in UTC")]
    TimestampRange { value: String },
    #[error("invalid confidence `{value}`")]
    Confidence {
        value: String,
        #[source]
        source: Option<std::num::ParseIntError>,
    },
    #[error(transparent)]
    Canon(#[from] CanonError),
    #[error("unsupported pattern or attribute type")]
    UnsupportedPattern,
    #[error("attribute is not marked for detection")]
    NotForDetection,
    #[error("attribute is deleted")]
    Deleted,
    #[error("value holds a control character")]
    ControlCharacter,
}


/// The whole feed cannot be read.
#[derive(Debug, Error)]
pub enum FeedError {
    #[error("cannot read the feed: {0}")]
    Io(#[from] io::Error),
    #[error("document larger than {MAX_DOCUMENT_BYTES} bytes")]
    DocumentTooLarge,
    #[error("invalid JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("the document is not a JSON array")]
    NotAnArray,
    #[error("the document is not a STIX bundle with an `objects` array")]
    NotABundle,
    #[error("the document is not a MISP event with array `Attribute` and `Object` fields")]
    NotAnEvent,
    #[error("more than {MAX_MISP_ATTRIBUTES} attributes in the event")]
    TooManyAttributes,
    #[error("a TAXII feed is polled, not read from a file")]
    PollOnly,
    #[error("too_many_iocs: more than {MAX_FEED_IOCS} IOCs in the feed, none kept")]
    TooManyIocs,
}


pub fn reason_key(error: &EntryError) -> &'static str {
    match error {
        EntryError::LineTooLong => "line_too_long",
        EntryError::ObjectTooLarge => "object_too_large",
        EntryError::InvalidUtf8(_) => "invalid_utf8",
        EntryError::Csv(_) => "malformed_csv",
        EntryError::NotAnObject => "not_an_object",
        EntryError::MissingField(_) => "missing_field",
        EntryError::Timestamp { .. } | EntryError::TimestampRange { .. } => "invalid_timestamp",
        EntryError::Confidence { .. } => "invalid_confidence",
        EntryError::Canon(CanonError::TooBroad) => "too_broad",
        EntryError::Canon(_) => "invalid_value",
        EntryError::UnsupportedPattern => "unsupported_pattern",
        EntryError::NotForDetection => "not_for_detection",
        EntryError::Deleted => "deleted",
        EntryError::ControlCharacter => "control_character",
    }
}


/// Fixed text per class: a server's body, header values, the password and the `Authorization` header never reach an error.
#[derive(Debug, Error)]
pub enum TaxiiError {
    #[error(transparent)]
    Settings(#[from] TaxiiConfigError),
    #[error("the feed has no taxii section")]
    NoSection,
    #[error("the TAXII password file could not be used: {}", pg_category(.0))]
    Password(#[source] PgError),
    #[error("the TAXII CA file could not be used: {}", pg_category(.0))]
    CaFile(#[source] PgError),
    #[error("the TAXII client could not be built")]
    Agent(#[source] InsertError),
    #[error("the cursor is out of range in UTC")]
    CursorRange,
    #[error("the cursor cannot be written as RFC 3339")]
    Cursor(#[source] time::error::Format),
    #[error("the TAXII server refused the credentials")]
    Unauthorized,
    #[error("the TAXII collection is unknown to the server")]
    UnknownCollection,
    #[error("the TAXII server refused version 2.1")]
    VersionRefused,
    #[error("the TAXII server is unavailable")]
    Unavailable,
    #[error("the TAXII server answered status {0}")]
    Status(u16),
    #[error("the TAXII poll ran out of time")]
    Timeout,
    #[error("the TAXII server connection failed")]
    Connect,
    #[error("the TAXII TLS handshake failed")]
    Tls,
    #[error("the TAXII connection failed with an I/O error of kind {kind:?}")]
    Io { kind: io::ErrorKind },
    #[error("the TAXII request broke the HTTP protocol")]
    Protocol,
    #[error("a TAXII page is larger than {MAX_DOCUMENT_BYTES} bytes")]
    PageTooLarge,
    #[error("a TAXII page is not a valid envelope ({category:?} at line {line} column {column})")]
    Envelope { category: Category, line: usize, column: usize },
    #[error("a TAXII page holds more than {MAX_TAXII_OBJECTS_PER_PAGE} objects")]
    TooManyObjects,
}
