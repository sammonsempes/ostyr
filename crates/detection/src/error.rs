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
    #[error("line {line} of the alerts file exceeds the line cap")]
    LineTooLong { line: usize },
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
    #[error("the tenant is empty or holds a character outside letters, digits, `-` and `_`")]
    InvalidTenant,
    #[error("more than {max} tenants")]
    TooManyTenants { max: usize },
}
