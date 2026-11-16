use crate::filetime::FiletimeError;
use core_config::error::ConfigError;
use thiserror::Error;


/// Every text is fixed: no input text reaches an error.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("cannot read the snapshot: {0}")]
    Read(#[source] std::io::Error),
    #[error("snapshot is not UTF-8")]
    NotUtf8(#[source] std::str::Utf8Error),
    #[error("snapshot is not a valid JSON array ({category:?}) at line {line} column {column}")]
    Malformed {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
}


/// One entry that cannot be read: the entry is set aside, the rest of the snapshot is assessed. Every text is fixed.
#[derive(Debug, Error)]
pub enum EntryError {
    #[error("{field} has the wrong shape ({category:?})")]
    BadEntry {
        field: &'static str,
        category: serde_json::error::Category,
    },
    #[error("{field} is refused: {reason}")]
    BadText { field: &'static str, reason: &'static str },
    #[error("{field} is not a usable FILETIME")]
    BadFiletime {
        field: &'static str,
        #[source]
        source: FiletimeError,
    },
}


#[derive(Debug, Error)]
pub enum ThresholdsError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{field} is outside its allowed range {min}..={max}")]
    Range { field: &'static str, min: u64, max: u64 },
}
