use crate::error::StoreError;
use crate::model::{Alert, AlertPage, Backend, Lease, Page};
use crate::pg::pg_executor;
use crate::store::{get_alert, list_alerts};
use core_config::reload::{current_config, reload, ReloadEngine};
use core_pg::connect::connect;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;


/// Database connections open at once for the REST routes; one more request is answered 429, never queued.
pub const MAX_CONNECTIONS: usize = 8;


/// The crate whose `log` records must never reach `tracing`: it logs bound parameters at debug.
pub const LOG_IGNORED_CRATE: &str = "tokio_postgres";


/// One connection per request, with the settings in force at that moment: the file is re-read first, an invalid one keeps the old settings.
pub async fn lease(engine: &ReloadEngine<PgSettings>, permits: &Arc<Semaphore>) -> Result<Lease, StoreError> {
    let permit = Arc::clone(permits).try_acquire_owned().map_err(|_closed_or_full| StoreError::Busy)?;
    reload(engine);
    let settings = current_config(engine);
    let client = connect(&settings).await?;
    Ok(Lease {
        client,
        deadline: Duration::from_secs(settings.statement_timeout_secs),
        permit,
    })
}


pub async fn pg_list(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    page: Page,
) -> Result<AlertPage, StoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    list_alerts(&executor, &scope, &page).await
}


pub async fn pg_get(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    id: String,
) -> Result<Option<Alert>, StoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    get_alert(&executor, &scope, &id).await
}


pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> Backend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    Backend {
        list: Arc::new(move |scope, page| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, page))),
        get: Arc::new(move |scope, id| Box::pin(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, id))),
    }
}
