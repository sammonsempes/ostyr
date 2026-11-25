use crate::model::SkipReason;
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use time::OffsetDateTime;


pub type SkipCounts = BTreeMap<SkipReason, u64>;


pub type Clock = fn() -> OffsetDateTime;


pub type Row = Vec<String>;


pub type RowFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Row>, PgError>> + Send + 'a>>;


/// Runs one statement for a tenant: the tenant is bound as `$1`, the parameters start at `$2`, every column comes back as text.
pub type Executor<'a, 'b> = &'a (dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'b> + Sync);


#[cfg(unix)]
pub type Identity = (u64, u64);


#[cfg(unix)]
pub type InterruptWait = Pin<Box<dyn Future<Output = std::io::Result<()>>>>;


#[cfg(unix)]
pub type SettingsReader =
    std::sync::Arc<dyn Fn(&std::path::Path) -> Result<crate::service::ServiceSettings, core_config::error::ConfigError> + Send + Sync>;
