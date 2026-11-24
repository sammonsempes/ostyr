use crate::model::{Channel, Message};


pub type Sender<'sender> = &'sender mut dyn FnMut(&Channel, &Message) -> Result<(), String>;


pub type Headers = Vec<(&'static str, zeroize::Zeroizing<String>)>;


pub type ClockFn<'clock> = &'clock dyn Fn() -> std::time::Instant;


pub type Row = Vec<crate::alert::Cell>;


pub type FillFn = fn(&mut [u8]) -> Result<(), getrandom::Error>;


pub type IssueError = crate::error::LinkError<std::convert::Infallible>;


/// A signing key of at least `MIN_LINK_KEY_BYTES`; only `linkkey` builds one. No `Debug`: it is a secret.
pub struct LinkKey(pub(crate) zeroize::Zeroizing<Vec<u8>>);


pub type NowFn = fn() -> chrono::DateTime<chrono::Utc>;


pub type TenantOutcome = (String, Result<crate::alert_source::TenantCounts, crate::error::SourceError>);


pub type WaitFn = fn(std::time::Duration) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;


pub type ReportFn = fn(&crate::alert_source::Round);


pub type PurgedCounts = std::collections::BTreeMap<String, usize>;


pub type AuditPurgeFn<'audit> = &'audit dyn Fn(&PurgedCounts);


/// Returns the current live settings snapshot (read again just before a purge).
pub type LiveSettingsFn<'live> = &'live dyn Fn() -> crate::alert_source::SourceSettings;


pub type ListFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<crate::alert::AlertPage, crate::error::ReadError>> + Send>>;


pub type GetFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<crate::alert::Alert>, crate::error::ReadError>> + Send>>;


/// The unresolved alerts of one tenant, at most the limit.
pub type ListFn = std::sync::Arc<dyn Fn(core_pg::scope::TenantScope, u32) -> ListFuture + Send + Sync>;


/// One alert of one tenant by id; `None` when the tenant has no such alert.
pub type GetFn = std::sync::Arc<dyn Fn(core_pg::scope::TenantScope, i64) -> GetFuture + Send + Sync>;


pub type ApplyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<crate::alert::Alert, crate::error::ReadError>> + Send>>;


/// Applies one lifecycle event to one alert of one tenant at the given time; the store's `apply_event` behind a leased connection.
pub type ApplyFn =
    std::sync::Arc<dyn Fn(core_pg::scope::TenantScope, i64, crate::alert::Event, chrono::DateTime<chrono::Utc>) -> ApplyFuture + Send + Sync>;


pub type Refused = Box<axum::response::Response>;


/// Resolves when the process is asked to stop (SIGINT or SIGTERM).
pub type StartRead = fn(&std::path::Path) -> Result<crate::serve::ServiceSettings, core_config::error::ConfigError>;


pub type InterruptWait = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>>>>;


/// Appends one declared audit entry, whatever the sink.
pub type AppendFn<'append> = &'append dyn Fn(core_audit::model::NewEntry) -> Result<(), core_audit::error::AuditError>;
