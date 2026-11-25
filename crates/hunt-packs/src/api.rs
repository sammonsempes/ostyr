use crate::api_model::{FindingView, FindingsQuery, FindingsReply, FindingsView, ListQuery, OversizedView};
use crate::error::FindingsError;
use crate::packs::MAX_ID_CHARS;
use crate::schedule::checked_time;
use crate::store::{count_oversized, list_findings, FindingRow, Param, StateError, MAX_FINDINGS_PAGE, OVERSIZED_REPORT_CAP};
use crate::types::{FindingsFn, ListResult};
use axum::extract::rejection::QueryRejection;
use axum::extract::Query;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::{DateTime, SecondsFormat, Utc};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::PERMISSION_EVENTS_READ;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use data_encoding::BASE64URL_NOPAD;
use std::future::{ready, Future};
use std::sync::Arc;
use tokio::sync::Semaphore;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: i64 = 50;


pub const FINDINGS_PATH: &str = "/hunts/findings";


/// The first cursor: year 0, the earliest window end `checked_time` admits, with an empty pack id.
pub const FIRST_END: i64 = -62_167_219_200;


/// The longest decimal `i64` end (`-9223372036854775808`): a cursor accepts every end the store can hold.
pub const MAX_END_CHARS: usize = 20;


/// Base64url length of `<end>:<pack id>` with the longest end and a 64-byte pack id (85 bytes).
pub const MAX_CURSOR_CHARS: usize = 114;


pub const CURSOR_SEPARATOR: char = ':';


#[derive(OpenApi)]
#[openapi(paths(findings_endpoint), components(schemas(FindingView, FindingsView, OversizedView)))]
pub struct HuntsDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, FindingsError> {
    Ok(tenant_scope(&identity.tenant).map_err(StateError::from)?)
}


pub fn parse_limit(text: Option<&str>) -> Result<i64, FindingsError> {
    text.map_or(Ok(DEFAULT_LIMIT), |figures| {
        figures
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| figures.parse::<i64>().ok())
            .flatten()
            .filter(|size| (1..=MAX_FINDINGS_PAGE).contains(size))
            .ok_or(FindingsError::BadPageSize)
    })
}


/// Base64url of `<end>:<pack id>`: the id is kept as stored, whether or not it is a valid pack id.
pub fn encode_cursor(end: i64, pack_id: &str) -> String {
    BASE64URL_NOPAD.encode(format!("{end}{CURSOR_SEPARATOR}{pack_id}").as_bytes())
}


/// Accepts every cursor `encode_cursor` prints for a listed row: an end of `FIRST_END` or more, any pack id of at most 64 bytes without NUL.
pub fn decode_cursor(text: &str) -> Result<(i64, String), FindingsError> {
    let bytes = (text.len() <= MAX_CURSOR_CHARS)
        .then(|| BASE64URL_NOPAD.decode(text.as_bytes()).ok())
        .flatten()
        .ok_or(FindingsError::BadCursor)?;
    let decoded = String::from_utf8(bytes).map_err(|_source| FindingsError::BadCursor)?;
    let (end_text, pack_id) = decoded.split_once(CURSOR_SEPARATOR).ok_or(FindingsError::BadCursor)?;
    let end = end_text.parse::<i64>().map_err(|_source| FindingsError::BadCursor)?;
    (end >= FIRST_END && pack_id.len() <= MAX_ID_CHARS && !pack_id.contains('\0'))
        .then(|| (end, pack_id.to_owned()))
        .ok_or(FindingsError::BadCursor)
}


pub fn query_of(parsed: &ListQuery) -> Result<FindingsQuery, FindingsError> {
    let after = parsed.cursor.as_deref().map(decode_cursor).transpose()?;
    Ok(FindingsQuery {
        after: after.unwrap_or((FIRST_END, String::new())),
        size: parse_limit(parsed.limit.as_deref())?,
    })
}


/// The error class that is logged, never the error: a store error can hold server text.
pub fn store_category(error: &StateError) -> &'static str {
    match error {
        StateError::Pg(_) => "database",
        StateError::BadReply => "reply",
        _ => "refused",
    }
}


/// A bad cursor or limit is the caller's 400, a full pool is a 429; a store failure is a generic 500 and only its class is logged.
pub fn findings_failure(error: &FindingsError) -> ApiError {
    match error {
        FindingsError::BadCursor | FindingsError::BadPageSize => ApiError::BadRequest,
        FindingsError::Busy => ApiError::TooManyRequests,
        FindingsError::Join => {
            tracing::warn!(category = "task", "hunt findings task failed");
            ApiError::Internal
        }
        FindingsError::Store(inner) => {
            let category = store_category(inner);
            tracing::warn!(category, "hunt findings store failure");
            ApiError::Internal
        }
    }
}


/// One page: the list statement, then the count of rows that are never listed (two statements, the tenant `$1` in both).
pub async fn read_findings<ListExec, ListPending, CountExec, CountPending>(
    list_exec: &mut ListExec,
    count_exec: &mut CountExec,
    scope: &TenantScope,
    query: &FindingsQuery,
) -> Result<FindingsReply, FindingsError>
where
    ListExec: FnMut(&TenantScope, &'static str, Vec<Param>) -> ListPending,
    ListPending: Future<Output = ListResult>,
    CountExec: FnMut(&TenantScope, &'static str, Vec<Param>) -> CountPending,
    CountPending: Future<Output = Result<Vec<i64>, PgError>>,
{
    let tenant = tenant_of(scope);
    let page = list_findings(list_exec, tenant, query.after.0, &query.after.1, query.size).await?;
    let oversized = count_oversized(count_exec, tenant).await?;
    Ok(FindingsReply { page, oversized })
}


/// Takes one permit before any task exists, else 429; the permit and the store call run in one spawned task that outlives a dropped route future.
pub fn permit_backend(permits: Arc<Semaphore>, inner: FindingsFn) -> FindingsFn {
    Arc::new(move |scope, query| match Arc::clone(&permits).try_acquire_owned() {
        Ok(permit) => {
            let pending = inner(scope, query);
            let handle = tokio::spawn(async move {
                let outcome = pending.await;
                drop(permit);
                outcome
            });
            Box::pin(async move { handle.await.unwrap_or_else(|_join| Err(FindingsError::Join)) })
        }
        Err(_closed_or_full) => Box::pin(ready(Err(FindingsError::Busy))),
    })
}


/// RFC 3339 UTC; a time `checked_time` refuses is `None`.
pub fn time_text(seconds: i64) -> Option<String> {
    checked_time(seconds)
        .ok()
        .and_then(|valid| DateTime::<Utc>::from_timestamp(valid, 0))
        .map(|moment| moment.to_rfc3339_opts(SecondsFormat::Secs, true))
}


pub fn finding_item(row: &FindingRow) -> Option<FindingView> {
    Some(FindingView {
        pack_id: row.pack_id.clone(),
        window_start: time_text(row.window_start)?,
        window_end: time_text(row.window_end)?,
        matches: row.matches,
        max_matches: row.max_matches,
    })
}


pub fn oversized_view(count: i64) -> OversizedView {
    OversizedView {
        count: count.min(OVERSIZED_REPORT_CAP),
        capped: count > OVERSIZED_REPORT_CAP,
    }
}


/// A refused time is left out and counted in `skipped`; the cursor is the stored end and id of the last row read, whatever its time.
pub fn findings_view(found: FindingsReply) -> FindingsView {
    let items: Vec<FindingView> = found.page.rows.iter().filter_map(finding_item).collect();
    let refused_time = found.page.rows.len().saturating_sub(items.len());
    FindingsView {
        skipped: found.page.skipped.saturating_add(refused_time),
        oversized: oversized_view(found.oversized),
        next_cursor: found.page.next.map(|(end, pack_id)| encode_cursor(end, &pack_id)),
        items,
    }
}


pub async fn findings_flow(identity: &ApiIdentity, backend: &FindingsFn, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| findings_failure(&error))?;
    let checked = query_of(&parsed).map_err(|error| findings_failure(&error))?;
    let found = backend(scope, checked).await.map_err(|error| findings_failure(&error))?;
    Ok(Json(findings_view(found)).into_response())
}


#[utoipa::path(
    get,
    path = "/hunts/findings",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of the tenant's hunt findings, oldest window end first", body = FindingsView),
        (status = 400, description = "Malformed cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn findings_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<FindingsFn>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(findings_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


pub fn hunts_router(backend: FindingsFn) -> Router<SharedState> {
    Router::new().route(FINDINGS_PATH, get(findings_endpoint)).layer(Extension(backend))
}


pub fn hunts_access() -> AccessTable {
    [(
        route_key("GET", FINDINGS_PATH),
        Rule {
            requirement: Requirement::Permission(PERMISSION_EVENTS_READ.to_owned()),
            sensitive: false,
        },
    )]
    .into_iter()
    .collect()
}


pub fn hunts_document() -> OpenApiDocument {
    HuntsDoc::openapi()
}
