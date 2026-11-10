use agent_channel::error::AppError;
use agent_channel::types::BoxError;
use core_audit::error::AuditError;
use core_config::error::{ConfigError, WatchError};
use siem_ingest::error::{NatsError, SettingsError};
use thiserror::Error;


/// Every text is fixed: the cause stays in the source chain, so no credential or payload reaches a log line.
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
    #[error("an event is not exactly one JSON object")]
    NotAnObject(#[source] serde_json::Error),
    #[error("an event could not be re-encoded with the identity tenant")]
    Encode(#[source] serde_json::Error),
    #[error("NATS refused or did not confirm an event")]
    Publish(#[source] BoxError),
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
