//! Error types.

use crate::model::Family;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum VersionError {
    #[error("unsupported ecosystem {0}")]
    UnknownEcosystem(String),
    #[error("unparsable {family:?} version {text}")]
    Unparsable { family: Family, text: String },
}


#[derive(Debug, Error)]
pub enum OsvError {
    #[error("record of {size} bytes exceeds the limit of {max}")]
    TooLarge { size: usize, max: usize },
    #[error("{what}: {count} exceeds the limit of {max}")]
    TooMany { what: &'static str, count: usize, max: usize },
    #[error("invalid OSV JSON")]
    Json(#[from] serde_json::Error),
}


#[derive(Debug, Error)]
pub enum FeedError {
    #[error("cannot read the feed archive")]
    Io(#[from] std::io::Error),
    #[error("archive exceeds the limit of {max} bytes")]
    ArchiveTooLarge { max: u64 },
    #[error("archive checksum {actual} does not match the configured {expected}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("archive holds {count} entries, the limit is {max}")]
    TooManyEntries { count: u64, max: usize },
    #[error("the archive ends inside a header or an entry")]
    Truncated,
    #[error("unexpected record where an entry header was expected")]
    BadHeader,
    #[error("data descriptor not followed by a known record")]
    BadDescriptor,
    #[error("archive retains more than {max} versions and events")]
    TooManyRetained { max: u64 },
    #[error("no licence is allowed in the feed settings")]
    NoAllowedLicences,
    #[error("entry {name:?} uses an unsupported compression method")]
    UnsupportedMethod { name: String },
    #[error("unsafe entry name {name:?}")]
    UnsafeName { name: String },
    #[error("entry {name:?} exceeds {max} uncompressed bytes")]
    EntryTooLarge { name: String, max: u64 },
    #[error("archive exceeds {max} uncompressed bytes in total")]
    TotalTooLarge { max: u64 },
    #[error("entry {name:?} exceeds the compression ratio of {max}")]
    RatioExceeded { name: String, max: u64 },
}


#[derive(Debug, Error)]
pub enum EolError {
    #[error("end-of-life table: {count} entries exceed the limit of {max}")]
    TooMany { count: usize, max: usize },
    #[error("end-of-life table: {0}")]
    Config(#[from] core_config::error::ConfigError),
}


#[derive(Debug, Error)]
pub enum KevError {
    #[error("cannot read the KEV catalogue")]
    Io(#[from] std::io::Error),
    #[error("KEV catalogue exceeds the limit of {max} bytes")]
    TooLarge { max: u64 },
    #[error("KEV catalogue holds {count} entries, the limit is {max}")]
    TooMany { count: usize, max: usize },
    #[error("invalid KEV JSON")]
    Json(#[from] serde_json::Error),
}


#[derive(Debug, Error)]
pub enum EpssError {
    #[error("cannot read the EPSS file")]
    Io(#[from] std::io::Error),
    #[error("EPSS file exceeds the limit of {max} bytes")]
    TooLarge { max: u64 },
    #[error("EPSS line {line} exceeds the limit of {max} bytes")]
    LineTooLong { line: usize, max: usize },
    #[error("EPSS file holds more than {max} rows")]
    TooMany { max: usize },
    #[error("EPSS first line is not a model version and score date comment")]
    BadMeta,
    #[error("EPSS header is not cve,epss,percentile")]
    BadHeader,
}
