use crate::api_model::CertBackend;
use crate::error::InventoryStoreError;
use crate::model::{CertDetail, CertPage, ListRequest};
use crate::store::{get_detail, list_certificates};
use alerts::backend::lease;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Semaphore;


pub fn now_seconds() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}


pub async fn pg_list(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    request: ListRequest,
) -> Result<CertPage, InventoryStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    list_certificates(&executor, &scope, &request.filter, request.cursor.as_deref(), request.limit).await
}


pub async fn pg_get(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    fingerprint: String,
) -> Result<Option<CertDetail>, InventoryStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    get_detail(&executor, &scope, &fingerprint).await
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> CertBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    CertBackend {
        list: Arc::new(move |scope, request| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, request))),
        get: Arc::new(move |scope, fingerprint| Box::pin(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, fingerprint))),
        clock: now_seconds,
    }
}
