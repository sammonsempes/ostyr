use core_config::error::ConfigError;
use serde_json::Error as JsonError;
use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum PolicyError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: invalid `{field}`")]
    Invalid { file: String, field: &'static str },
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("usage: shell_decide <policy.yaml> <case.json>")]
    Usage,
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: invalid case")]
    Case {
        file: String,
        #[source]
        source: JsonError,
    },
    #[error("cannot write the result")]
    Write(#[from] io::Error),
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("field `{field}` is outside its grammar")]
    Invalid { field: &'static str },
    #[error("the header or recording belongs to another tenant")]
    TenantMismatch,
    #[error("the recording is not the one of session `{session_id}`")]
    RecordingMismatch { session_id: String },
    #[error("session `{session_id}` is already registered")]
    Duplicate { session_id: String },
    #[error("no session `{session_id}` for this tenant")]
    Unknown { session_id: String },
    #[error("session `{session_id}` is already closed")]
    AlreadyClosed { session_id: String },
    #[error("session `{session_id}` cannot close before it opened")]
    CloseBeforeOpen { session_id: String },
    #[error("limit {limit} is outside 1..={max}")]
    LimitOutOfRange { limit: u32, max: u32 },
    #[error("value of `{field}` does not fit the store")]
    OutOfRange { field: &'static str },
    #[error("unexpected value in column `{column}`")]
    BadRow { column: &'static str },
    #[error(transparent)]
    Pg(#[from] core_pg::error::PgError),
}
