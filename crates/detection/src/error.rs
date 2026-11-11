use core_audit::error::AuditError;
use core_config::error::{ConfigError, WatchError};
use siem_ingest::error::{IngestError, NatsError};
use std::path::PathBuf;
use stream_correlation::error::CorrelationError;
use thiserror::Error;


/// The text is fixed per variant and never carries alert or event content.
#[derive(Debug, Error)]
pub enum SinkError {
    #[error("cannot open the alerts file {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read the alerts file")]
    Read(#[source] std::io::Error),
    #[error("cannot rotate the alerts file")]
    Rotate(#[source] std::io::Error),
    #[error("the store kept refusing the alerts until the retry cap")]
    Exhausted,
    #[error("the alerts file holds more than {max} alerts")]
    TooManyAlerts { max: usize },
    #[error("cannot write the alerts file")]
    Write(#[source] std::io::Error),
    #[error("cannot flush the alerts file to disk")]
    Sync(#[source] std::io::Error),
    #[error("an alert belongs to another tenant than the batch")]
    TenantMismatch,
    #[error("an alert cannot be serialised")]
    Serialize(#[source] serde_json::Error),
    #[error("the store given is not the one this sink writes to")]
    WrongStore,
    #[error("the database refused the alerts")]
    Database(#[source] core_pg::error::PgError),
    #[error("the alert store refused the alerts")]
    Store(#[source] alerts::error::StoreError),
    #[error("the database runtime cannot start")]
    Runtime(#[source] std::io::Error),
    #[error("an event identity is longer than {max} characters")]
    EventIdTooLong { max: usize },
    #[error("the event time is outside the supported range")]
    EventTimeRange(#[source] time::error::ComponentRange),
    #[error("the event time cannot be written")]
    EventTimeFormat(#[source] time::error::Format),
}


#[derive(Debug, Error)]
pub enum DetectionError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Ingest(#[from] IngestError),
    #[error(transparent)]
    Nats(#[from] NatsError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Watch(#[from] WatchError),
    #[error(transparent)]
    Correlation(#[from] CorrelationError),
    #[error(transparent)]
    Sink(#[from] SinkError),
    #[error("input or output failed")]
    Io(#[from] std::io::Error),
    #[error("the tenant is empty or is refused by core-pg's tenant rule")]
    InvalidTenant,
    #[error("more than {max} tenants")]
    TooManyTenants { max: usize },
}
