use crate::alerting::is_id;
use crate::api_model::{AssetView, ListQuery, StateBackend, StateListView, StateView};
use crate::error::ReadError;
use crate::read::{decode_cursor, is_asset, DEFAULT_LIMIT, MAX_PAGE, VERDICTS, VERDICT_ALL};
use crate::read_model::{AssetResults, ListRequest, StateFilter, StatePage, StoredState};
use crate::store::VERDICT_FAIL;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, ErrorDetail, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::PERMISSION_CMDB_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const LIST_PATH: &str = "/compliance/state";


pub const ASSET_PATH: &str = "/compliance/assets/{asset}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such asset";


pub const NANOS_PER_MICRO: i128 = 1_000;


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9_999;


#[derive(OpenApi)]
#[openapi(paths(list_endpoint, asset_endpoint), components(schemas(StateView, StateListView, AssetView)))]
pub struct ComplianceDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, ReadError> {
    Ok(tenant_scope(&identity.tenant)?)
}


pub fn parse_limit(text: Option<&str>) -> Result<usize, ReadError> {
    text.map_or(Ok(DEFAULT_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE).contains(size))
            .ok_or(ReadError::BadPageSize { limit: MAX_PAGE })
    })
}


/// `fail` when absent, `None` for `all`, else one of the four stored verdicts.
pub fn parse_verdict(text: Option<&str>) -> Result<Option<String>, ReadError> {
    match text.unwrap_or(VERDICT_FAIL) {
        VERDICT_ALL => Ok(None),
        known if VERDICTS.contains(&known) => Ok(Some(known.to_owned())),
        _other => Err(ReadError::BadVerdict),
    }
}


pub fn parse_baseline(text: Option<&str>) -> Result<Option<String>, ReadError> {
    text.map(|name| is_id(name).then(|| name.to_owned()).ok_or(ReadError::BadBaseline))
        .transpose()
}


pub fn request_of(query: &ListQuery) -> Result<ListRequest, ReadError> {
    Ok(ListRequest {
        filter: StateFilter {
            verdict: parse_verdict(query.verdict.as_deref())?,
            baseline: parse_baseline(query.baseline.as_deref())?,
        },
        cursor: query.cursor.as_deref().map(decode_cursor).transpose()?,
        limit: parse_limit(query.limit.as_deref())?,
    })
}


pub fn failure_category(error: &ReadError) -> &'static str {
    match error {
        ReadError::Pg(_) | ReadError::Lease(_) => "database",
        ReadError::BadKey | ReadError::BadRow | ReadError::Unrepresentable => "stored_value",
        _other => "request",
    }
}


/// A bad cursor, limit, verdict or baseline is the caller's 400; anything else is logged by category only and answered with a generic error.
pub fn store_failure(error: &ReadError) -> ApiError {
    match error {
        ReadError::BadCursor | ReadError::BadPageSize { .. } | ReadError::BadVerdict | ReadError::BadBaseline => ApiError::BadRequest,
        ReadError::Lease(alerts::error::StoreError::Busy) => ApiError::TooManyRequests,
        other => {
            let category = failure_category(other);
            tracing::warn!(category, "compliance state failure");
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


/// RFC 3339 UTC text of a stored time; a time that years 0 to 9999 cannot hold is refused.
pub fn rfc3339(micros: i64) -> Result<String, ReadError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * NANOS_PER_MICRO)
        .ok()
        .filter(|moment| (MIN_YEAR..=MAX_YEAR).contains(&moment.year()))
        .and_then(|moment| moment.format(&Rfc3339).ok())
        .ok_or(ReadError::Unrepresentable)
}


pub fn state_view(stored: &StoredState) -> Result<StateView, ReadError> {
    Ok(StateView {
        baseline: stored.baseline.clone(),
        control: stored.control.clone(),
        asset: stored.asset.clone(),
        verdict: stored.verdict.clone(),
        first_failed: stored.first_failed_micros.map(rfc3339).transpose()?,
        last_seen: rfc3339(stored.last_seen_micros)?,
    })
}


/// A row whose times cannot be written is left out and counted, like a row the store refused.
pub fn views_of(rows: &[StoredState]) -> (Vec<StateView>, usize) {
    let (shown, failed): (Vec<_>, Vec<_>) = rows.iter().map(state_view).partition(Result::is_ok);
    let unwritable = failed.len();
    if unwritable > 0 {
        tracing::warn!(unwritable, "stored compliance times refused and skipped");
    }
    (shown.into_iter().flatten().collect(), unwritable)
}


pub fn list_view(page: &StatePage) -> StateListView {
    let (items, unwritable) = views_of(&page.rows);
    StateListView {
        items,
        skipped: page.skipped + unwritable,
        next_cursor: page.next_cursor.clone(),
    }
}


pub fn asset_view(found: &AssetResults) -> AssetView {
    let (items, unwritable) = views_of(&found.rows);
    AssetView {
        items,
        skipped: found.skipped + unwritable,
        truncated: found.truncated,
    }
}


pub async fn list_flow(identity: &ApiIdentity, backend: &StateBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let request = request_of(&parsed).map_err(|error| store_failure(&error))?;
    let page = (backend.list)(scope, request).await.map_err(|error| store_failure(&error))?;
    Ok(Json(list_view(&page)).into_response())
}


/// A malformed asset, or one the extractor refuses, is answered like a missing one, without a store call and without echoing it.
pub async fn asset_flow(identity: &ApiIdentity, backend: &StateBackend, asset: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let checked = asset.ok().filter(|text| is_asset(text));
    match checked {
        None => Ok(not_found()),
        Some(text) => match (backend.asset)(scope, text).await.map_err(|error| store_failure(&error))? {
            None => Ok(not_found()),
            Some(found) => Ok(Json(asset_view(&found)).into_response()),
        },
    }
}


#[utoipa::path(
    get,
    path = "/compliance/state",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of control results ordered by baseline, control and asset", body = StateListView),
        (status = 400, description = "Malformed cursor, limit, verdict or baseline", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<StateBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/compliance/assets/{asset}",
    params(("asset" = String, Path, description = "Asset name, percent-encoded")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The control results of one asset", body = AssetView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such asset for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn asset_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<StateBackend>,
    asset: Result<Path<String>, PathRejection>,
) -> Response {
    reply(asset_flow(&identity, &backend, asset.map(|found| found.0)).await)
}


pub fn compliance_router(backend: StateBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(ASSET_PATH, get(asset_endpoint))
        .layer(Extension(backend))
}


pub fn compliance_access() -> AccessTable {
    [LIST_PATH, ASSET_PATH]
        .into_iter()
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_CMDB_READ.to_owned()),
                    sensitive: false,
                },
            )
        })
        .collect()
}


pub fn compliance_document() -> OpenApiDocument {
    ComplianceDoc::openapi()
}
