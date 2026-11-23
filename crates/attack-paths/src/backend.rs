use crate::api_model::AttackPathsBackend;
use crate::error::StoreError;
use crate::store::{get_report, list_reports, ReportMeta, StoredReport};
use alerts::backend::lease;
use alerts::error::StoreError as LeaseError;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::{tenant_of, TenantScope};
use core_pg::settings::PgSettings;
use std::sync::Arc;
use tokio::sync::Semaphore;


/// A full pool is `Busy` (a 429), a connection failure is a store failure, nothing else can come out of a lease.
pub fn pool_failure(error: LeaseError) -> StoreError {
    match error {
        LeaseError::Busy => StoreError::Busy,
        LeaseError::Pg(source) => StoreError::Store(source),
        _other => StoreError::BadRow,
    }
}


pub async fn pg_list(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    limit: usize,
) -> Result<Vec<ReportMeta>, StoreError> {
    let held = lease(&engine, &permits).await.map_err(pool_failure)?;
    let executor = pg_executor(&held.client, held.deadline);
    list_reports(&executor, tenant_of(&scope), limit).await
}


pub async fn pg_get(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    id: i64,
) -> Result<Option<StoredReport>, StoreError> {
    let held = lease(&engine, &permits).await.map_err(pool_failure)?;
    let executor = pg_executor(&held.client, held.deadline);
    get_report(&executor, tenant_of(&scope), id).await
}


/// One connection per request through the alerts `lease`, which never queues: at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> AttackPathsBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    AttackPathsBackend {
        list: Arc::new(move |scope, limit| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, limit))),
        get: Arc::new(move |scope, id| Box::pin(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, id))),
    }
}
