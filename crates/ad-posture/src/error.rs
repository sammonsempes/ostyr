use crate::filetime::FiletimeError;
use core_config::error::ConfigError;
use thiserror::Error;


/// Every text is fixed: no input text reaches an error.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("cannot read the snapshot: {0}")]
    Read(#[source] std::io::Error),
    #[error("snapshot is above the {max} byte limit")]
    TooLarge { max: u64 },
    #[error("snapshot is not UTF-8")]
    NotUtf8(#[source] std::str::Utf8Error),
    #[error("snapshot is not a valid JSON array ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    #[error("snapshot holds {count} entries, above the {max} limit")]
    TooManyEntries { count: usize, max: usize },
    #[error("entry {index}: {field} has the wrong shape ({category:?})")]
    BadEntry {
        index: usize,
        field: &'static str,
        category: serde_json::error::Category,
    },
    #[error("entry {index}: {field} holds {count} values, above the {max} limit")]
    TooManyValues {
        index: usize,
        field: &'static str,
        count: usize,
        max: usize,
    },
    #[error("entry {index}: {field} is refused: {reason}")]
    BadText {
        index: usize,
        field: &'static str,
        reason: &'static str,
    },
    #[error("entry {index}: {field} is not a usable FILETIME")]
    BadFiletime {
        index: usize,
        field: &'static str,
        #[source]
        source: FiletimeError,
    },
    #[error("entry {index} repeats the distinguished name of an earlier entry")]
    DuplicateDn { index: usize },
}


#[derive(Debug, Error)]
pub enum ThresholdsError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{field} is outside its allowed range {min}..={max}")]
    Range { field: &'static str, min: u64, max: u64 },
}
