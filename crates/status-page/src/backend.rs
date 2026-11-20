use crate::api_model::{PageServices, StatusBackend};
use crate::error::StoreError;
use crate::pg::execute;
use crate::store::{add_update, create_incident, resolve_incident};
use crate::store_model::{IncidentRef, NewIncident, Statement};
use alerts::backend::lease;
use core_config::reload::ReloadEngine;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Semaphore;


pub fn now_seconds() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}


pub async fn pg_create(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    incident: NewIncident,
) -> Result<IncidentRef, StoreError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&held.client, query_scope.clone(), statement, held.deadline);
    create_incident(&mut exec, &scope, &incident).await
}


pub async fn pg_update(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    incident: IncidentRef,
    note: (i64, String, String),
) -> Result<IncidentRef, StoreError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&held.client, query_scope.clone(), statement, held.deadline);
    add_update(&mut exec, &scope, incident, note.0, &note.1, &note.2).await
}


pub async fn pg_resolve(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    incident: IncidentRef,
    at: i64,
) -> Result<IncidentRef, StoreError> {
    let held = lease(&engine, &permits).await?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&held.client, query_scope.clone(), statement, held.deadline);
    resolve_incident(&mut exec, &scope, incident, at).await
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>, page: Arc<PageServices>) -> StatusBackend {
    let update_engine = Arc::clone(&engine);
    let update_permits = Arc::clone(&permits);
    let resolve_engine = Arc::clone(&engine);
    let resolve_permits = Arc::clone(&permits);
    StatusBackend {
        create: Arc::new(move |scope, incident| Box::pin(pg_create(Arc::clone(&engine), Arc::clone(&permits), scope, incident))),
        update: Arc::new(move |scope, incident, at, message, note| {
            Box::pin(pg_update(
                Arc::clone(&update_engine),
                Arc::clone(&update_permits),
                scope,
                incident,
                (at, message, note),
            ))
        }),
        resolve: Arc::new(move |scope, incident, at| {
            Box::pin(pg_resolve(Arc::clone(&resolve_engine), Arc::clone(&resolve_permits), scope, incident, at))
        }),
        clock: now_seconds,
        page,
    }
}
