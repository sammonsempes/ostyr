use crate::error::{GraphError, LimitsError, PathsError, StoreError, TagsError, TenantError};
use crate::model::{PathSet, Tags};
use crate::serve::TenantReport;
use crate::store::{ReportMeta, StoredReport};
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type GraphResult = Result<(), GraphError>;


pub type LimitsResult = Result<(), LimitsError>;


pub type TagsResult = Result<Tags, TagsError>;


pub type ApplyResult = Result<(), TagsError>;


pub type PathsResult = Result<PathSet, PathsError>;


pub type Row = Vec<String>;


pub type RowFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Row>, PgError>> + Send + 'a>>;


/// Runs one statement for a tenant: the tenant is bound as `$1`, the parameters start at `$2`, every column comes back as text.
pub type Executor<'a, 'b> = &'a (dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'b> + Sync);


pub type ListFuture = Pin<Box<dyn Future<Output = Result<Vec<ReportMeta>, StoreError>> + Send>>;


pub type GetFuture = Pin<Box<dyn Future<Output = Result<Option<StoredReport>, StoreError>> + Send>>;


/// Reads the newest report metadata of a tenant, at most `limit` rows.
pub type ListFn = Arc<dyn Fn(TenantScope, usize) -> ListFuture + Send + Sync>;


/// Reads one stored report of a tenant by id.
pub type GetFn = Arc<dyn Fn(TenantScope, i64) -> GetFuture + Send + Sync>;


/// Called with the path of an input file after its bytes were read and before its handle is stamped again; production does nothing.
pub type MidRead = fn(&std::path::Path) -> std::io::Result<()>;


pub type InterruptWait = Pin<Box<dyn Future<Output = std::io::Result<()>>>>;


pub type InterruptFn = fn() -> std::io::Result<InterruptWait>;


pub type WaitFn = fn(std::time::Duration) -> Pin<Box<dyn Future<Output = ()>>>;


pub type ServiceFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + 'a>>;


/// Stops the settings file watch and joins its thread.
pub type StopWatchFn = Box<dyn FnOnce()>;


#[cfg(unix)]
pub type Hangups = signal_hook::iterator::Signals;


#[cfg(not(unix))]
pub struct Hangups;


/// Registers the SIGHUP stream; called before the first file is read, so a hangup during start is held, not fatal.
pub type HangupFn = fn() -> std::io::Result<Hangups>;


pub type TenantRun = (String, Result<TenantReport, TenantError>);


pub type RoundResult = Result<Vec<TenantRun>, PgError>;
