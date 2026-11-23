use crate::error::{GraphError, LimitsError, PathsError, StoreError, TagsError};
use crate::model::{PathSet, Tags};
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
