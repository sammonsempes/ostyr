use crate::types::BoxError;
use core_audit::error::AuditError;
use std::io;
use std::path::PathBuf;
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
    #[error("{file}: larger than {max} bytes")]
    TooLarge { file: String, max: u64 },
    #[error("{file}: not valid UTF-8 after {valid_up_to} bytes")]
    NotUtf8 { file: String, valid_up_to: usize },
    #[error("watched file `{file}` refused: {reason}")]
    WatchedFile { file: String, reason: String },
    #[error("{file}: module `tenant` refused: {reason}")]
    Tenant { file: String, reason: &'static str },
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


/// Why a reload left the old configuration in force.
#[derive(Debug, Error)]
pub enum ReloadRefusal {
    #[error(transparent)]
    Load(#[from] ConfigError),
    #[error("section `{section}` refused the new configuration: {source}")]
    Subscriber {
        section: String,
        #[source]
        source: BoxError,
    },
    #[error("cannot audit the reload, nothing swapped: {0}")]
    Audit(#[from] AuditError),
}


#[derive(Debug, Error)]
pub enum WatchError {
    #[error("cannot watch: {0}")]
    Notify(#[from] notify::Error),
    #[error("cannot watch {0}: a drive without a root is relative to the drive's current directory, give a full path")]
    DriveRelative(PathBuf),
    #[error("cannot watch {0}: a root without a drive depends on the current drive, give a full path")]
    RootRelative(PathBuf),
    #[error("cannot watch {0}: a short 8.3 name is never reported by the file system, use another name")]
    ShortName(PathBuf),
    #[error("cannot watch {0}: a ':' after the drive is stream syntax and never matches an event")]
    StreamSyntax(PathBuf),
    #[error("cannot watch {0}: the file name must be ASCII letters, digits, '.', '_' or '-' and not end in a dot")]
    FileName(PathBuf),
}
