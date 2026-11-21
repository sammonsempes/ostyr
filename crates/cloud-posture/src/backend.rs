use crate::api_model::PostureBackend;
use crate::error::StoreError;
use crate::model::{FindingsPage, PageCursor};
use crate::page::read_parsed;
use alerts::backend::lease;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use tokio::sync::Semaphore;


pub async fn pg_read(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    account: String,
    cursor: Option<PageCursor>,
    limit: usize,
) -> Result<FindingsPage, StoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    read_parsed(&executor, &scope, &account, cursor.as_ref(), limit).await
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> PostureBackend {
    PostureBackend {
        read: Arc::new(move |scope, account, cursor, limit| {
            Box::pin(pg_read(Arc::clone(&engine), Arc::clone(&permits), scope, account, cursor, limit))
        }),
    }
}
