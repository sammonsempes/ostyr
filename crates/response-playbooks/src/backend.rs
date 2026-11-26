use crate::api_model::{RunDetail, RunList, RunPage, RunsBackend};
use crate::error::ReadError;
use crate::runs_read::{get_run, list_runs};
use alerts::backend::lease;
use alerts::error::StoreError as LeaseError;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::{tenant_of, TenantScope};
use core_pg::settings::PgSettings;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Semaphore;


/// A full pool is `Busy` (a 429), a connection failure is a store failure, nothing else can come out of a lease.
pub fn pool_failure(error: LeaseError) -> ReadError {
    match error {
        LeaseError::Busy => ReadError::Busy,
        LeaseError::Pg(source) => ReadError::Pg(source),
        _other => ReadError::BadRow,
    }
}


/// The read runs as a task: a client that leaves never cancels a statement in flight, so its permit is held until the statement ends.
pub async fn detached<Reply: Send + 'static>(work: impl Future<Output = Result<Reply, ReadError>> + Send + 'static) -> Result<Reply, ReadError> {
    tokio::spawn(work).await.unwrap_or_else(|failure| {
        let panicked = failure.is_panic();
        tracing::warn!(panicked, "playbook run read task failed");
        Err(ReadError::TaskFailed)
    })
}


pub async fn pg_list(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    page: RunPage,
) -> Result<RunList, ReadError> {
    let held = lease(&engine, &permits).await.map_err(pool_failure)?;
    let executor = pg_executor(&held.client, held.deadline);
    list_runs(&executor, tenant_of(&scope), page).await
}


pub async fn pg_get(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    id: String,
) -> Result<Option<RunDetail>, ReadError> {
    let held = lease(&engine, &permits).await.map_err(pool_failure)?;
    let executor = pg_executor(&held.client, held.deadline);
    get_run(&executor, tenant_of(&scope), &id).await
}


/// One connection per request through the alerts `lease`, which never queues: the module's own permits, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> RunsBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    RunsBackend {
        list: Arc::new(move |scope, page| Box::pin(detached(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, page)))),
        get: Arc::new(move |scope, id| Box::pin(detached(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, id)))),
    }
}
