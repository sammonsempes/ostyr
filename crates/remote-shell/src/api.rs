use crate::api_model::{ListQuery, SessionView, SessionsBackend, SessionsListView};
use crate::error::StoreError;
use crate::grammar::valid_reference;
use crate::serve::{parse_cursor, writable_time};
use crate::store::{check_asset, check_requester, MAX_PAGE};
use crate::store_model::{ListFilter, Page, SessionRow};
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use core_api::failure::error_response;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, ErrorDetail, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::PERMISSION_AUDIT_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const LIST_PATH: &str = "/remote-shell/sessions";


pub const GET_PATH: &str = "/remote-shell/sessions/{id}";


pub const DEFAULT_PAGE: u32 = 50;


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such session";


pub const STORED_VALUE_CODE: &str = "stored_value";


pub const STORED_VALUE_MESSAGE: &str = "a stored value cannot be served";


pub const OPEN_TRUE: &str = "true";


pub const OPEN_FALSE: &str = "false";


#[derive(OpenApi)]
#[openapi(paths(list_endpoint, get_endpoint), components(schemas(SessionView, SessionsListView)))]
pub struct RemoteShellDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, StoreError> {
    Ok(tenant_scope(&identity.tenant)?)
}


/// ASCII digits only, 1 to `MAX_PAGE`, default `DEFAULT_PAGE`.
pub fn parse_limit(text: Option<&str>) -> Result<u32, StoreError> {
    text.map_or(Ok(DEFAULT_PAGE), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<u32>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE).contains(size))
            .ok_or(StoreError::Invalid { field: "limit" })
    })
}


/// Exactly `true` or `false`; absent means every session.
pub fn parse_open(text: Option<&str>) -> Result<bool, StoreError> {
    match text {
        None | Some(OPEN_FALSE) => Ok(false),
        Some(OPEN_TRUE) => Ok(true),
        Some(_other) => Err(StoreError::Invalid { field: "open" }),
    }
}


pub fn checked_filter(value: Option<&String>, check: fn(&str) -> Result<(), StoreError>) -> Result<Option<String>, StoreError> {
    value.map(|text| check(text).map(|()| text.clone())).transpose()
}


/// Every value is checked here, before any lease or connection.
pub fn list_request(query: &ListQuery) -> Result<(ListFilter, Option<String>, u32), StoreError> {
    let limit = parse_limit(query.limit.as_deref())?;
    let filter = ListFilter {
        asset: checked_filter(query.asset.as_ref(), check_asset)?,
        requester: checked_filter(query.requester.as_ref(), check_requester)?,
        open_only: parse_open(query.open.as_deref())?,
    };
    let cursor = query
        .cursor
        .as_deref()
        .map(|text| parse_cursor(text).map(|_parsed| text.to_owned()))
        .transpose()?;
    Ok((filter, cursor, limit))
}


pub fn failure_category(error: &StoreError) -> &'static str {
    match error {
        StoreError::Pg(_) | StoreError::Lease(_) => "database",
        StoreError::StoredValue { .. } | StoreError::BadRow { .. } => "stored_value",
        _other => "request",
    }
}


pub fn not_found() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: NOT_FOUND_CODE.to_owned(),
            message: NOT_FOUND_MESSAGE.to_owned(),
        },
    };
    (StatusCode::NOT_FOUND, Json(body)).into_response()
}


pub fn stored_value() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: STORED_VALUE_CODE.to_owned(),
            message: STORED_VALUE_MESSAGE.to_owned(),
        },
    };
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}


/// A bad request is the caller's 400, a full pool a 429; anything else is logged by category only and answered with a fixed body.
pub fn failure_reply(error: &StoreError) -> Response {
    match error {
        StoreError::BadCursor | StoreError::Invalid { .. } | StoreError::LimitOutOfRange { .. } => error_response(&ApiError::BadRequest),
        StoreError::Lease(alerts::error::StoreError::Busy) => error_response(&ApiError::TooManyRequests),
        other => {
            let category = failure_category(other);
            tracing::warn!(category, "remote shell sessions failure");
            match other {
                StoreError::StoredValue { .. } | StoreError::BadRow { .. } => stored_value(),
                _else => error_response(&ApiError::Internal),
            }
        }
    }
}


/// RFC 3339 UTC text of a stored time; a time that years 0 to 9999 cannot hold is `None`.
pub fn rfc3339(seconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .filter(|_moment| writable_time(seconds))
        .and_then(|moment| moment.format(&Rfc3339).ok())
}


pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}


pub fn session_view(row: &SessionRow) -> Option<SessionView> {
    Some(SessionView {
        session_id: row.session_id.clone(),
        requester: row.requester.clone(),
        asset: row.asset.clone(),
        ticket: row.ticket.clone(),
        opened_at: rfc3339(row.opened_at)?,
        closed_at: row.closed_at.map_or(Some(None), |closed| rfc3339(closed).map(Some))?,
        close_reason: row.close_reason.clone(),
        recording_frames: row.recording_frames,
        recording_hash: row.recording_hash.as_deref().map(hex),
        recording_bytes: row.recording_bytes,
    })
}


/// A row whose times cannot be written is left out and counted with the rows the store refused; one warning per page.
pub fn list_view(page: &Page) -> SessionsListView {
    let items: Vec<SessionView> = page.rows.iter().filter_map(session_view).collect();
    let skipped = page.skipped + (page.rows.len() - items.len());
    if skipped > 0 {
        tracing::warn!(skipped, "remote shell sessions skipped");
    }
    SessionsListView {
        items,
        skipped,
        next_cursor: page.next_cursor.clone(),
    }
}


pub async fn list_outcome(identity: &ApiIdentity, backend: &SessionsBackend, query: Result<ListQuery, StoreError>) -> Result<Response, StoreError> {
    let parsed = query?;
    let scope = scope_of(identity)?;
    let (filter, cursor, limit) = list_request(&parsed)?;
    let page = (backend.list)(scope, filter, cursor, limit).await?;
    Ok(Json(list_view(&page)).into_response())
}


pub async fn list_flow(identity: &ApiIdentity, backend: &SessionsBackend, query: Result<ListQuery, StoreError>) -> Response {
    list_outcome(identity, backend, query).await.unwrap_or_else(|error| failure_reply(&error))
}


pub async fn get_outcome(identity: &ApiIdentity, backend: &SessionsBackend, id: Option<String>) -> Result<Response, StoreError> {
    let scope = scope_of(identity)?;
    match id.filter(|text| valid_reference(text)) {
        None => Ok(not_found()),
        Some(text) => match (backend.get)(scope, text).await? {
            None => Ok(not_found()),
            Some(row) => session_view(&row)
                .map(|view| Json(view).into_response())
                .ok_or(StoreError::StoredValue { field: "time" }),
        },
    }
}


/// A malformed id, or one the extractor refuses, is answered like a missing one, without a store call and without echoing it.
pub async fn get_flow(identity: &ApiIdentity, backend: &SessionsBackend, id: Option<String>) -> Response {
    get_outcome(identity, backend, id).await.unwrap_or_else(|error| failure_reply(&error))
}


#[utoipa::path(
    get,
    path = "/remote-shell/sessions",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of the tenant's sessions, newest first", body = SessionsListView),
        (status = 400, description = "Malformed filter, cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<SessionsBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    list_flow(
        &identity,
        &backend,
        query.map(|found| found.0).map_err(|_rejection| StoreError::Invalid { field: "query" }),
    )
    .await
}


#[utoipa::path(
    get,
    path = "/remote-shell/sessions/{id}",
    params(("id" = String, Path, description = "Session id, percent-encoded")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One session of the tenant", body = SessionView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such session in this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<SessionsBackend>,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    get_flow(&identity, &backend, id.ok().map(|found| found.0)).await
}


pub fn remote_shell_router(backend: SessionsBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


pub fn remote_shell_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
        .into_iter()
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_AUDIT_READ.to_owned()),
                    sensitive: true,
                },
            )
        })
        .collect()
}


pub fn remote_shell_document() -> OpenApiDocument {
    RemoteShellDoc::openapi()
}
