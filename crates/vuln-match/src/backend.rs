use crate::api_model::FindingsBackend;
use crate::error::StoreError;
use crate::limits::MAX_ASSET_FINDINGS;
use crate::model::FindingsPage;
use crate::store::{open_findings_of_asset, open_findings_parsed};
use alerts::backend::lease;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use tokio::sync::Semaphore;


pub async fn pg_list(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    cursor: Option<Vec<String>>,
    limit: usize,
) -> Result<FindingsPage, StoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    open_findings_parsed(&executor, &scope, cursor, limit).await
}


pub async fn pg_asset(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    asset: String,
) -> Result<FindingsPage, StoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    open_findings_of_asset(&executor, &scope, &asset, MAX_ASSET_FINDINGS).await
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> FindingsBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    FindingsBackend {
        list: Arc::new(move |scope, cursor, limit| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, cursor, limit))),
        asset: Arc::new(move |scope, asset| Box::pin(pg_asset(Arc::clone(&engine), Arc::clone(&permits), scope, asset))),
    }
}
