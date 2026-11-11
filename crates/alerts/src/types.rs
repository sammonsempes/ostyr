use crate::error::StoreError;
use crate::model::{AlertDetail, AlertPage, Page, Triage, TriageChange};
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type Row = Vec<String>;


pub type RowFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Row>, PgError>> + Send + 'a>>;


/// Runs one statement for a tenant: the tenant is bound as `$1`, the parameters start at `$2`, every column comes back as text.
pub type Executor<'a, 'b> = &'a (dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'b> + Sync);


pub type StoreFuture<Output> = Pin<Box<dyn Future<Output = Result<Output, StoreError>> + Send>>;


pub type ListFn = Arc<dyn Fn(TenantScope, Page) -> StoreFuture<AlertPage> + Send + Sync>;


pub type GetFn = Arc<dyn Fn(TenantScope, String) -> StoreFuture<Option<AlertDetail>> + Send + Sync>;


pub type TriageFn = Arc<dyn Fn(TenantScope, String, TriageChange, Option<i64>) -> StoreFuture<Triage> + Send + Sync>;


/// Microseconds since the Unix epoch.
pub type ClockFn = fn() -> u64;
