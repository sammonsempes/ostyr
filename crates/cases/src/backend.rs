use crate::api_model::CasesBackend;
use crate::error::CaseStoreError;
use crate::stored::{CaseDetail, CasePage, SummaryList};
use crate::summary::{get_case_detail, list_case_summaries};
use alerts::backend::lease;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use tokio::sync::Semaphore;


pub const ACTOR: &str = "cases";


pub async fn pg_list(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    page: CasePage,
) -> Result<SummaryList, CaseStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    list_case_summaries(&executor, &scope, &page).await
}


pub async fn pg_get(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    id: String,
) -> Result<Option<CaseDetail>, CaseStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    get_case_detail(&executor, &scope, &id).await
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> CasesBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    CasesBackend {
        list: Arc::new(move |scope, page| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, page))),
        get: Arc::new(move |scope, id| Box::pin(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, id))),
    }
}
