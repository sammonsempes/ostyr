use crate::error::StoreError;
use crate::model::{FindingsPage, PageCursor};
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use sha2::Sha256;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type Digest = sha2::digest::Output<Sha256>;


pub type RowFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Vec<String>>, PgError>> + Send + 'a>>;


/// Runs one statement for a tenant: the tenant is bound as `$1`, the parameters start at `$2`, every column comes back as text.
pub type Executor<'a, 'b> = &'a (dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'b> + Sync);


pub type PageFuture = Pin<Box<dyn Future<Output = Result<FindingsPage, StoreError>> + Send>>;


/// Reads one page for a tenant, an account, a cursor already parsed and a limit already checked.
pub type ReadFn = Arc<dyn Fn(TenantScope, String, Option<PageCursor>, usize) -> PageFuture + Send + Sync>;
