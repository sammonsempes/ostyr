use core_audit::error::AuditError;
use core_config::error::{ConfigError, WatchError};
use siem_ingest::error::{IngestError, InsertClass, InsertError, NatsError, SettingsError};
use sigma_sql::error::SigmaError;
use std::io;
use std::path::PathBuf;
use std::str::Utf8Error;
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


/// Every text is fixed: the server's message, a row, an event id, the SQL and the URL never reach an error.
#[derive(Debug, Error)]
pub enum RetroError {
    #[error("the rule cannot be compiled")]
    Rule(#[source] SigmaError),
    #[error("the reader url is refused")]
    Url(#[source] SettingsError),
    #[error("retro setting out of range: {0}")]
    Settings(&'static str),
    #[error("the tenant is empty or is refused by core-pg's tenant rule")]
    Tenant,
    #[error("the window is empty or outside the supported range")]
    Window,
    #[error("the window is longer than {0} days")]
    WindowTooLong(i64),
    #[error("the ClickHouse password file could not be used")]
    Password(#[source] core_pg::error::PgError),
    #[error("the ClickHouse password is not valid UTF-8")]
    PasswordEncoding(#[source] Utf8Error),
    #[error("the ClickHouse CA file could not be used")]
    CaFile(#[source] core_pg::error::PgError),
    #[error("the ClickHouse agent cannot be built")]
    Agent(#[source] InsertError),
    #[error("the read was refused: {0:?}")]
    Refused(InsertClass),
    #[error("timeout")]
    Timeout,
    #[error("read_limit_reached")]
    ReadLimit,
    #[error("the reply body could not be read: {0:?}")]
    Body(io::ErrorKind),
    #[error("reply larger than {0} bytes")]
    TooManyBytes(u64),
    #[error("more than {0} rows")]
    TooManyRows(usize),
    #[error("malformed_reply")]
    MalformedReply,
    #[error("the event time cannot be written")]
    EventTime(#[from] SinkError),
    #[error("reader_profile_changed: {0} setting(s) outside the allowed list")]
    ReaderProfileChanged(usize),
}
