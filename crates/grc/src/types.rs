use crate::error::StoreError;
use crate::service::Declarations;
use crate::store::{ReportMeta, StoredReport};
use core_config::error::ConfigError;
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;


pub type Row = Vec<String>;


pub type RowFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Row>, PgError>> + Send + 'a>>;


/// Runs one statement for a tenant: the tenant is bound as `$1`, the parameters start at `$2`, every column comes back as text.
pub type Executor<'a, 'b> = &'a (dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'b> + Sync);


pub type ListFuture = Pin<Box<dyn Future<Output = Result<Vec<ReportMeta>, StoreError>> + Send>>;


pub type GetFuture = Pin<Box<dyn Future<Output = Result<Option<StoredReport>, StoreError>> + Send>>;


/// Reads one page of report metadata for a tenant: framework filter and limit.
pub type ListFn = Arc<dyn Fn(TenantScope, Option<String>, usize) -> ListFuture + Send + Sync>;


/// Reads one stored report of a tenant by id.
pub type GetFn = Arc<dyn Fn(TenantScope, i64) -> GetFuture + Send + Sync>;


/// Reads and validates every declaration of the service from its settings file; production passes `service::load_declarations`.
pub type DeclarationsReader = Arc<dyn Fn(&Path) -> Result<Declarations, ConfigError> + Send + Sync>;


pub type PauseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;


/// The sleep between two rounds.
pub type PauseFn = dyn Fn(Duration) -> PauseFuture + Sync;


/// The wall clock, one reading per round.
pub type ClockFn = dyn Fn() -> OffsetDateTime + Sync;


/// The file watch: `Debouncer::stop` joins its thread, a drop only flags it.
pub type WatchGuard = notify_debouncer_full::Debouncer<notify::RecommendedWatcher, notify_debouncer_full::RecommendedCache>;
