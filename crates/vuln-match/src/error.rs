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
    #[error("invalid zip archive")]
    Zip(#[from] zip::result::ZipError),
    #[error("archive holds {count} entries, the limit is {max}")]
    TooManyEntries { count: u64, max: usize },
    #[error("the central directory cannot be read before indexing")]
    UnreadableDirectory,
    #[error("more than one end-of-central-directory record")]
    AmbiguousDirectory,
    #[error("directory of {bytes} bytes cannot hold {entries} entries")]
    InconsistentDirectory { entries: u64, bytes: u64 },
    #[error("entries overlap or share a byte range")]
    OverlappingEntries,
    #[error("archive retains more than {max} versions and events")]
    TooManyRetained { max: u64 },
    #[error("no licence is allowed in the feed settings")]
    NoAllowedLicences,
    #[error("entry {name:?} lies outside the archive")]
    EntryOutOfBounds { name: String },
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
