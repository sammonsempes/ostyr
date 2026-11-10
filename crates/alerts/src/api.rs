use crate::error::StoreError;
use crate::model::{Alert, AlertListView, AlertView, Backend, Cursor, ListQuery, Page, Summary};
use crate::store::{format_cursor, parse_cursor, MAX_PAGE_SIZE};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, ErrorDetail, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::PERMISSION_ALERTS_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use data_encoding::BASE64URL_NOPAD;
use serde_json::{json, Value};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: usize = 50;


/// A cursor is `<at most 19 digits>.<64 hex>` encoded in base64: far below this.
pub const MAX_CURSOR_CHARS: usize = 256;


pub const NANOS_PER_MICRO: i128 = 1_000;


pub const LIST_PATH: &str = "/alerts";


pub const GET_PATH: &str = "/alerts/{id}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such alert";


#[derive(OpenApi)]
#[openapi(paths(list_endpoint, get_endpoint), components(schemas(AlertView, AlertListView)))]
pub struct AlertsDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under (a session carries none): no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, StoreError> {
    Ok(tenant_scope(&identity.tenant)?)
}


pub fn parse_limit(text: Option<&str>) -> Result<usize, StoreError> {
    text.map_or(Ok(DEFAULT_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE_SIZE).contains(size))
            .ok_or(StoreError::BadPageSize { limit: MAX_PAGE_SIZE })
    })
}


pub fn encode_cursor(cursor: &Cursor) -> String {
    BASE64URL_NOPAD.encode(format_cursor(cursor).as_bytes())
}


pub fn decode_cursor(text: &str) -> Result<Cursor, StoreError> {
    let bytes = (text.len() <= MAX_CURSOR_CHARS)
        .then(|| BASE64URL_NOPAD.decode(text.as_bytes()).ok())
        .flatten()
        .ok_or(StoreError::BadCursor)?;
    let decoded = String::from_utf8(bytes).map_err(|_source| StoreError::BadCursor)?;
    parse_cursor(&decoded)
}


pub fn page_of(query: &ListQuery) -> Result<Page, StoreError> {
    Ok(Page {
        after: query.cursor.as_deref().map(decode_cursor).transpose()?,
        size: parse_limit(query.limit.as_deref())?,
    })
}


/// A cut summary is not JSON any more, so it is served as `{"text": ...}`; a whole one is served as the stored object.
pub fn summary_value(summary: &Summary) -> Value {
    let parsed = (!summary.truncated)
        .then(|| serde_json::from_str::<Value>(&summary.text).ok())
        .flatten()
        .filter(Value::is_object);
    parsed.unwrap_or_else(|| json!({ "text": summary.text }))
}


pub fn created_time(micros: u64) -> Result<String, StoreError> {
    let nanos = i128::from(micros) * NANOS_PER_MICRO;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()
        .and_then(|moment| moment.format(&Rfc3339).ok())
        .ok_or(StoreError::BadCreated)
}


pub fn view_of(alert: &Alert) -> Result<AlertView, StoreError> {
    Ok(AlertView {
        id: alert.id.clone(),
        rule_id: alert.rule_id.clone(),
        rule_title: alert.rule_title.clone(),
        severity: alert.severity.to_string(),
        event_time: alert.event_time.clone(),
        created: created_time(alert.created_micros)?,
        host_name: alert.host_name.clone(),
        user_name: alert.user_name.clone(),
        event_ids: alert.event_ids.clone(),
        summary: summary_value(&alert.summary),
        summary_truncated: alert.summary.truncated,
    })
}


/// A bad cursor or limit is the caller's 400; anything else is logged and answered with a generic error, never the database text.
pub fn store_failure(error: &StoreError) -> ApiError {
    match error {
        StoreError::BadCursor | StoreError::BadPageSize { .. } => ApiError::BadRequest,
        StoreError::Busy => ApiError::TooManyRequests,
        other => {
            tracing::warn!(error = %other, "alerts store failure");
            ApiError::Internal
        }
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


pub fn list_view(page: &crate::model::AlertPage) -> Result<AlertListView, StoreError> {
    Ok(AlertListView {
        items: page.alerts.iter().map(view_of).collect::<Result<Vec<AlertView>, StoreError>>()?,
        next_cursor: page.next.as_ref().map(encode_cursor),
    })
}


pub async fn list_flow(identity: &ApiIdentity, backend: &Backend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let page = page_of(&parsed).map_err(|error| store_failure(&error))?;
    let found = (backend.list)(scope, page).await.map_err(|error| store_failure(&error))?;
    let view = list_view(&found).map_err(|error| store_failure(&error))?;
    Ok(Json(view).into_response())
}


/// A malformed id cannot name a stored alert, so it is answered like a missing one.
pub async fn get_flow(identity: &ApiIdentity, backend: &Backend, id: String) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let found = (backend.get)(scope, id).await;
    match found {
        Err(StoreError::BadId) | Ok(None) => Ok(not_found()),
        Err(error) => Err(store_failure(&error)),
        Ok(Some(alert)) => {
            let view = view_of(&alert).map_err(|error| store_failure(&error))?;
            Ok(Json(view).into_response())
        }
    }
}


#[utoipa::path(
    get,
    path = "/alerts",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of alerts, newest first", body = AlertListView),
        (status = 400, description = "Malformed cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<Backend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/alerts/{id}",
    params(("id" = String, Path, description = "Alert id, 64 lowercase hexadecimal characters")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The alert", body = AlertView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such alert for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<Backend>,
    Path(id): Path<String>,
) -> Response {
    reply(get_flow(&identity, &backend, id).await)
}


pub fn alerts_router(backend: Backend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


pub fn alerts_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
        .into_iter()
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_ALERTS_READ.to_owned()),
                    sensitive: false,
                },
            )
        })
        .collect()
}


pub fn alerts_document() -> OpenApiDocument {
    AlertsDoc::openapi()
}
