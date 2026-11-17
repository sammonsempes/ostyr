use agent_channel::error::AppError;
use async_nats::jetstream::context::PublishErrorKind;
use core_audit::error::AuditError;
use core_config::error::{ConfigError, WatchError};
use serde_json::error::Category;
use siem_ingest::error::{NatsError, SettingsError};
use thiserror::Error;


/// Every text is fixed and no variant keeps a source built from peer bytes, so no credential or payload reaches a log line.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error(transparent)]
    Nats(#[from] NatsError),
    #[error("invalid gateway settings: {0}")]
    Settings(#[from] SettingsError),
    #[error("{max} batches are already being published")]
    Busy { max: usize },
    #[error("NATS is unreachable, retrying after a backoff")]
    BackingOff,
    #[error("the batch was not published before the deadline")]
    Timeout(#[source] tokio::time::error::Elapsed),
    #[error("the batch holds {count} events, above the limit of {max}")]
    TooManyEvents { count: usize, max: usize },
    #[error("an event of {size} bytes does not fit the NATS server limit of {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("the agent identity cannot be used in a NATS subject or message id")]
    Identity,
    #[error("an event is not exactly one JSON object ({category:?} at line {line} column {column})")]
    NotAnObject { category: Category, line: usize, column: usize },
    #[error("an event could not be re-encoded with the identity tenant ({category:?} at line {line} column {column})")]
    Encode { category: Category, line: usize, column: usize },
    #[error("NATS refused or did not confirm an event: {0}")]
    Publish(PublishErrorKind),
    #[error(transparent)]
    App(#[from] AppError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Watch(#[from] WatchError),
    #[error("input or output failed: {0}")]
    Io(#[from] std::io::Error),
}


/// Keeps the category and position of a parse error, never its text: serde repeats the peer's bytes in it.
pub fn not_an_object(error: serde_json::Error) -> GatewayError {
    GatewayError::NotAnObject {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


/// Same for an encoding error.
pub fn encode_failed(error: serde_json::Error) -> GatewayError {
    GatewayError::Encode {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}
