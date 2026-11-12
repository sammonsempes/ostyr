use crate::api_model::CasesBackend;
use crate::error::CaseStoreError;
use crate::model::Comment;
use crate::store::{add_comment, attach_alert, list_links};
use crate::stored::{CaseDetail, CasePage, LinkList, LinkPage, SummaryList};
use crate::summary::{get_case_detail, list_case_summaries};
use crate::transition::CaseAction;
use crate::write::act_on_case;
use alerts::backend::lease;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use time::OffsetDateTime;
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


pub async fn pg_act(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    (id, action, actor, now): (String, CaseAction, String, i64),
) -> Result<CaseDetail, CaseStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    act_on_case(&executor, &scope, &id, action, &actor, now).await
}


pub async fn pg_comment(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    (id, comment): (String, Comment),
) -> Result<(), CaseStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    add_comment(&executor, &scope, &id, &comment).await
}


pub async fn pg_link(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    (id, alert_id, actor, now): (String, String, String, i64),
) -> Result<bool, CaseStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    attach_alert(&executor, &scope, &id, &alert_id, (&actor, now)).await
}


pub async fn pg_links(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    (id, page): (String, LinkPage),
) -> Result<LinkList, CaseStoreError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    list_links(&executor, &scope, &id, &page).await
}


pub fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}


/// One connection per request through the alerts `lease`, at most `alerts::backend::MAX_CONNECTIONS` at once, else 429.
pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> CasesBackend {
    let list_engine = Arc::clone(&engine);
    let list_permits = Arc::clone(&permits);
    let act_engine = Arc::clone(&engine);
    let act_permits = Arc::clone(&permits);
    let comment_engine = Arc::clone(&engine);
    let comment_permits = Arc::clone(&permits);
    let link_engine = Arc::clone(&engine);
    let link_permits = Arc::clone(&permits);
    let links_engine = Arc::clone(&engine);
    let links_permits = Arc::clone(&permits);
    CasesBackend {
        list: Arc::new(move |scope, page| Box::pin(pg_list(Arc::clone(&list_engine), Arc::clone(&list_permits), scope, page))),
        get: Arc::new(move |scope, id| Box::pin(pg_get(Arc::clone(&engine), Arc::clone(&permits), scope, id))),
        act: Arc::new(move |scope, id, action, actor, now| {
            Box::pin(pg_act(Arc::clone(&act_engine), Arc::clone(&act_permits), scope, (id, action, actor, now)))
        }),
        comment: Arc::new(move |scope, id, comment| {
            Box::pin(pg_comment(
                Arc::clone(&comment_engine),
                Arc::clone(&comment_permits),
                scope,
                (id, comment),
            ))
        }),
        link: Arc::new(move |scope, id, alert_id, actor, now| {
            Box::pin(pg_link(
                Arc::clone(&link_engine),
                Arc::clone(&link_permits),
                scope,
                (id, alert_id, actor, now),
            ))
        }),
        links: Arc::new(move |scope, id, page| Box::pin(pg_links(Arc::clone(&links_engine), Arc::clone(&links_permits), scope, (id, page)))),
        clock: unix_now,
    }
}
