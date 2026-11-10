use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;


pub type Row = Vec<String>;


pub type RowFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Row>, PgError>> + 'a>>;


/// Runs one statement for a tenant: the tenant is bound as `$1`, the parameters start at `$2`, every column comes back as text.
pub type Executor<'a, 'b> = &'a dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'b>;
