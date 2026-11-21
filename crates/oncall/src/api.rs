use crate::alert::{Alert, AlertPage};
use crate::api_model::{AlertListView, AlertView, ListQuery, OncallBackend};
use crate::error::{ReadError, StoreError};
use crate::limits::{MAX_FINGERPRINT_BYTES, MAX_OPEN_ALERTS};
use crate::rows::phase_name;
use crate::store::valid_text;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, ErrorDetail, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const PERMISSION_ONCALL_READ: &str = "oncall.read";


pub const DEFAULT_LIMIT: u32 = 50;


pub const LIST_PATH: &str = "/oncall/alerts";


pub const GET_PATH: &str = "/oncall/alerts/{id}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such alert";


pub const UNREADABLE_CODE: &str = "unreadable_alert";


pub const UNREADABLE_MESSAGE: &str = "the stored alert cannot be shown";


pub const FIRST_YEAR: i32 = 0;


pub const LAST_YEAR: i32 = 9999;


#[derive(OpenApi)]
#[openapi(paths(list_endpoint, get_endpoint), components(schemas(AlertView, AlertListView)))]
pub struct OncallDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, ApiError> {
    tenant_scope(&identity.tenant).map_err(|_invalid| ApiError::Internal)
}


/// Digits only, 1 to `MAX_OPEN_ALERTS`.
pub fn parse_limit(text: Option<&str>) -> Result<u32, ApiError> {
    text.map_or(Ok(DEFAULT_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<u32>().ok())
            .flatten()
            .filter(|size| (1..=MAX_OPEN_ALERTS).contains(size))
            .ok_or(ApiError::BadRequest)
    })
}


/// Digits only and inside `i64`; anything else cannot be a stored id.
pub fn parse_id(text: &str) -> Option<i64> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse::<i64>().ok()).flatten()
}


/// RFC 3339 UTC text; a time whose year RFC 3339 cannot write (outside 0 to 9999) is refused.
pub fn rfc3339(moment: DateTime<Utc>) -> Result<String, ReadError> {
    (FIRST_YEAR..=LAST_YEAR)
        .contains(&moment.year())
        .then(|| moment.to_rfc3339_opts(SecondsFormat::Micros, true))
        .ok_or(ReadError::Unrepresentable)
}


pub fn alert_view(alert: &Alert) -> Result<AlertView, ReadError> {
    valid_text(&alert.fingerprint, MAX_FINGERPRINT_BYTES)
        .then_some(())
        .ok_or(ReadError::Unrepresentable)?;
    Ok(AlertView {
        id: alert.id,
        fingerprint: alert.fingerprint.clone(),
        state: phase_name(alert.state.phase).to_owned(),
        level: alert.state.level,
        occurrences: alert.occurrences,
        opened_at: rfc3339(alert.opened_at)?,
        acknowledged_at: alert.acknowledged_at.map(rfc3339).transpose()?,
        resolved_at: alert.resolved_at.map(rfc3339).transpose()?,
    })
}


pub fn failure_category(error: &ReadError) -> &'static str {
    match error {
        ReadError::Lease(_) => "connection",
        ReadError::Store(_) => "database",
        ReadError::Unrepresentable => "stored_value",
    }
}


/// A full pool is the caller's 429; anything else is logged by category only and answered with a generic error.
pub fn read_failure(error: &ReadError) -> ApiError {
    match error {
        ReadError::Lease(alerts::error::StoreError::Busy) => ApiError::TooManyRequests,
        other => {
            let category = failure_category(other);
            tracing::warn!(category, "on-call read failure");
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


/// A row of the caller's tenant that exists but cannot be shown: a fixed 422 that holds no stored text and no field name.
pub fn unreadable() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: UNREADABLE_CODE.to_owned(),
            message: UNREADABLE_MESSAGE.to_owned(),
        },
    };
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}


/// Both causes of an unshowable row: a value the view refuses and a cell the driver could not decode.
pub fn is_unreadable(error: &ReadError) -> bool {
    matches!(error, ReadError::Unrepresentable | ReadError::Store(StoreError::BadRow { .. }))
}


/// A row whose fingerprint or times cannot be written is left out and counted in `skipped`, like a row the decoder refused.
pub fn list_view(page: &AlertPage) -> AlertListView {
    let (shown, failed): (Vec<_>, Vec<_>) = page.alerts.iter().map(alert_view).partition(Result::is_ok);
    let unwritable = failed.len();
    if unwritable > 0 {
        tracing::warn!(unwritable, "stored alerts refused and skipped");
    }
    AlertListView {
        items: shown.into_iter().flatten().collect(),
        skipped: page.skipped + unwritable,
    }
}


pub async fn list_flow(identity: &ApiIdentity, backend: &OncallBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity)?;
    let limit = parse_limit(parsed.limit.as_deref())?;
    let page = (backend.list)(scope, limit).await.map_err(|error| read_failure(&error))?;
    Ok(Json(list_view(&page)).into_response())
}


/// A malformed id, or one the extractor refuses, is answered like a missing one, without a store call and without echoing it.
pub async fn get_flow(identity: &ApiIdentity, backend: &OncallBackend, id: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity)?;
    match id.ok().as_deref().and_then(parse_id) {
        None => Ok(not_found()),
        Some(number) => {
            let found = (backend.get)(scope, number)
                .await
                .and_then(|stored| stored.map(|alert| alert_view(&alert)).transpose());
            get_answer(found)
        }
    }
}


/// A missing row is the 404, an unshowable one the 422, any other failure the logged generic error.
pub fn get_answer(found: Result<Option<AlertView>, ReadError>) -> Result<Response, ApiError> {
    match found {
        Ok(Some(view)) => Ok(Json(view).into_response()),
        Ok(None) => Ok(not_found()),
        Err(error) if is_unreadable(&error) => {
            let category = failure_category(&error);
            tracing::warn!(category, "on-call stored alert cannot be shown");
            Ok(unreadable())
        }
        Err(error) => Err(read_failure(&error)),
    }
}


#[utoipa::path(
    get,
    path = "/oncall/alerts",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The oldest unresolved alerts of the tenant", body = AlertListView),
        (status = 400, description = "Malformed limit or unknown parameter", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<OncallBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/oncall/alerts/{id}",
    params(("id" = String, Path, description = "Alert id, digits only")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The alert", body = AlertView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such alert for this tenant", body = ErrorBody),
        (status = 422, description = "The stored alert cannot be shown", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<OncallBackend>,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    reply(get_flow(&identity, &backend, id.map(|found| found.0)).await)
}


pub fn oncall_router(backend: OncallBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


pub fn oncall_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
        .into_iter()
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_ONCALL_READ.to_owned()),
                    sensitive: false,
                },
            )
        })
        .collect()
}


pub fn oncall_document() -> OpenApiDocument {
    OncallDoc::openapi()
}
