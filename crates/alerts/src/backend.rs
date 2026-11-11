use crate::error::StoreError;
use crate::model::{AlertDetail, AlertPage, Backend, Lease, Page, Triage, TriageChange};
use crate::pg::pg_executor;
use crate::store::{get_detail, list_alerts, set_triage};
use core_config::reload::{current_config, ReloadEngine};
use core_pg::connect::connect;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Semaphore;


/// Database connections open at once for the REST routes; one more request is answered 429, never queued.
pub const MAX_CONNECTIONS: usize = 8;


/// The crate whose `log` records must never reach `tracing`: it logs bound parameters at debug.
pub const LOG_IGNORED_CRATE: &str = "tokio_postgres";


pub const MICROS_PER_SECOND: u64 = 1_000_000;


/// One connection per request, with the settings in force at that moment; the engine is reloaded by the file watch and `SIGHUP`, never here.
pub async fn lease(engine: &ReloadEngine<PgSettings>, permits: &Arc<Semaphore>) -> Result<Lease, StoreError> {
    let permit = Arc::clone(permits).try_acquire_owned().map_err(|_closed_or_full| StoreError::Busy)?;
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
) -> Result<Option<AlertDetail>, StoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    get_detail(&executor, &scope, &id).await
}


pub async fn pg_triage(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    id: String,
    change: TriageChange,
    expected: Option<i64>,
) -> Result<Triage, StoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    set_triage(&executor, &scope, &id, &change, expected).await
}


pub fn unix_micros() -> u64 {
    let now = OffsetDateTime::now_utc();
    now.unix_timestamp().unsigned_abs() * MICROS_PER_SECOND + u64::from(now.microsecond())
}


pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> Backend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    let triage_engine = Arc::clone(&engine);
    let triage_permits = Arc::clone(&permits);
    Backend {
        list: Arc::new(move |scope, page| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, page))),
        get: Arc::new(move |scope, id| Box::pin(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, id))),
        triage: Arc::new(move |scope, id, change, expected| {
            Box::pin(pg_triage(
                Arc::clone(&triage_engine),
                Arc::clone(&triage_permits),
                scope,
                id,
                change,
                expected,
            ))
        }),
        clock: unix_micros,
    }
}
