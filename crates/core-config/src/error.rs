use crate::types::BoxError;
use std::io;
use thiserror::Error;


/// A `line` and `column` of 0 mean the parser gave no position.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{file}: cannot access: {source}")]
    Io {
        file: String,
        #[source]
        source: io::Error,
    },
    #[error("{file}:{line}:{column}: at `{field_path}`: {message}")]
    Parse {
        file: String,
        line: u64,
        column: u64,
        field_path: String,
        message: String,
        #[source]
        source: Box<serde_saphyr::Error>,
    },
}


#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("applying `{key}` failed after {} change(s): {source}", applied.len())]
    Applier {
        key: String,
        applied: Vec<String>,
        #[source]
        source: BoxError,
    },
    #[error("audit failed after {} applied change(s): {source}", applied.len())]
    Audit {
        applied: Vec<String>,
        #[source]
        source: core_audit::error::AuditError,
    },
    #[error("cannot read the real state back: {0}")]
    ReadBack(#[source] BoxError),
    #[error("real state differs from the desired state after apply: {}", keys.join(", "))]
    Mismatch { keys: Vec<String> },
}
