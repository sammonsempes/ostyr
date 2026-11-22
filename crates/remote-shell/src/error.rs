use crate::open::OpenRefusal;
use crate::types::BoxedCause;
use agent_channel::model::GateError;
use agent_command::error::{ActionError, SignError as CommandSignError};
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
    #[error("stored value of `{field}` is outside its grammar")]
    StoredValue { field: &'static str },
    #[error("the page cursor is malformed")]
    BadCursor,
    #[error(transparent)]
    Pg(#[from] core_pg::error::PgError),
    #[error("no database connection: {0}")]
    Lease(#[from] alerts::error::StoreError),
}


/// Fixed texts: no field value, session id or peer byte is ever part of a signing refusal.
#[derive(Debug, Error)]
pub enum SignError {
    #[error("field `{field}` is outside its grammar")]
    Invalid { field: &'static str },
    #[error("the row is older than the signing delay")]
    Stale,
    #[error("the session is closed")]
    Closed,
    #[error("the session is not in the register or is not the row given")]
    RowMismatch,
    #[error("the session is already signed")]
    AlreadySigned,
    #[error("the tenant holds too many signed shells")]
    TenantFull,
    #[error("the claim was refused")]
    Unclaimed,
    #[error("the opening is refused: {0}")]
    Refused(OpenRefusal),
    #[error("no agent is declared for the asset")]
    UnknownAsset,
    #[error("the limits do not fit the command")]
    Limit,
    #[error("the clock is before the epoch")]
    Clock,
    #[error("the sequence could not be recorded")]
    SequenceRecord,
    #[error("the sequence does not fit the register")]
    SequenceRange,
    #[error(transparent)]
    Action(#[from] ActionError),
    #[error(transparent)]
    Gate(#[from] GateError),
    #[error(transparent)]
    Sign(#[from] CommandSignError),
    #[error("the nonce could not be drawn")]
    Nonce(#[source] BoxedCause),
    #[error("the sequence could not be allocated")]
    Sequence(#[source] BoxedCause),
    #[error("the register refused the statement")]
    Store(#[from] StoreError),
}
