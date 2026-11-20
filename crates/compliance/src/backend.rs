use crate::api_model::StateBackend;
use crate::error::ReadError;
use crate::read::{asset_state, list_state};
use crate::read_model::{AssetResults, ListRequest, StatePage};
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
    request: ListRequest,
) -> Result<StatePage, ReadError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    list_state(&executor, &scope, &request.filter, request.cursor.as_ref(), request.limit).await
}


pub async fn pg_asset(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    asset: String,
) -> Result<Option<AssetResults>, ReadError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    asset_state(&executor, &scope, &asset).await
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> StateBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    StateBackend {
        list: Arc::new(move |scope, request| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, request))),
        asset: Arc::new(move |scope, asset| Box::pin(pg_asset(Arc::clone(&engine), Arc::clone(&permits), scope, asset))),
    }
}
