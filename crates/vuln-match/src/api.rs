use crate::api_model::{AssetView, FindingView, FindingsBackend, FindingsListView, ListQuery};
use crate::error::StoreError;
use crate::limits::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
use crate::model::{FindingsPage, StoredFinding};
use crate::store::is_field;
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


pub const LIST_PATH: &str = "/vulnerabilities/findings";


pub const ASSET_PATH: &str = "/vulnerabilities/assets/{asset}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such asset";


pub const NANOS_PER_MICRO: i128 = 1_000;


pub const MIN_YEAR: i32 = 0;


pub const MAX_YEAR: i32 = 9_999;


#[derive(OpenApi)]
#[openapi(paths(list_endpoint, asset_endpoint), components(schemas(FindingView, FindingsListView, AssetView)))]
pub struct VulnerabilitiesDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, StoreError> {
    Ok(tenant_scope(&identity.tenant)?)
}


pub fn parse_limit(text: Option<&str>) -> Result<usize, StoreError> {
    text.map_or(Ok(DEFAULT_PAGE_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE_LIMIT).contains(size))
            .ok_or(StoreError::BadLimit { max: MAX_PAGE_LIMIT })
    })
}


pub fn failure_category(error: &StoreError) -> &'static str {
    match error {
        StoreError::Pg(_) | StoreError::Lease(_) => "database",
        StoreError::StoredValue | StoreError::BadAnswer => "stored_value",
        _other => "request",
    }
}


/// A bad cursor or limit is the caller's 400; anything else is logged by category only and answered with a generic error.
pub fn store_failure(error: &StoreError) -> ApiError {
    match error {
        StoreError::BadCursor | StoreError::BadLimit { .. } => ApiError::BadRequest,
        StoreError::Lease(alerts::error::StoreError::Busy) => ApiError::TooManyRequests,
        other => {
            let category = failure_category(other);
            tracing::warn!(category, "vulnerability findings failure");
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


/// RFC 3339 UTC text of a stored time; a time that years 0 to 9999 cannot hold is `None`.
pub fn rfc3339(micros: u64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * NANOS_PER_MICRO)
        .ok()
        .filter(|moment| (MIN_YEAR..=MAX_YEAR).contains(&moment.year()))
        .and_then(|moment| moment.format(&Rfc3339).ok())
}


pub fn finding_view(stored: &StoredFinding) -> Option<FindingView> {
    Some(FindingView {
        asset: stored.asset.clone(),
        ecosystem: stored.ecosystem.clone(),
        package: stored.package.clone(),
        record_id: stored.record_id.clone(),
        installed_version: stored.installed_version.clone(),
        fixed_version: stored.fixed_version.clone(),
        cvss: stored.cvss,
        epss: stored.epss,
        kev: stored.kev,
        priority: stored.priority,
        first_seen: rfc3339(stored.first_seen_micros)?,
        last_seen: rfc3339(stored.last_seen_micros)?,
    })
}


/// A row whose times cannot be written is left out and counted, like a row the store refused.
pub fn views_of(rows: &[StoredFinding]) -> (Vec<FindingView>, usize) {
    let shown: Vec<FindingView> = rows.iter().filter_map(finding_view).collect();
    let unwritable = rows.len() - shown.len();
    if unwritable > 0 {
        tracing::warn!(unwritable, "stored finding times refused and skipped");
    }
    (shown, unwritable)
}


pub fn list_view(page: &FindingsPage) -> FindingsListView {
    let (items, unwritable) = views_of(&page.findings);
    FindingsListView {
        items,
        skipped: page.skipped + unwritable,
        next_cursor: page.next.clone(),
    }
}


/// `None` when the asset has no open row and no skipped one: the fixed 404.
pub fn asset_view(page: &FindingsPage) -> Option<AssetView> {
    let (items, unwritable) = views_of(&page.findings);
    (!(page.findings.is_empty() && page.skipped == 0)).then(|| AssetView {
        items,
        skipped: page.skipped + unwritable,
        truncated: page.next.is_some(),
    })
}


pub async fn list_flow(identity: &ApiIdentity, backend: &FindingsBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let limit = parse_limit(parsed.limit.as_deref()).map_err(|error| store_failure(&error))?;
    let page = (backend.list)(scope, parsed.cursor, limit).await.map_err(|error| store_failure(&error))?;
    Ok(Json(list_view(&page)).into_response())
}


/// A malformed asset, or one the extractor refuses, is answered like a missing one, without a store call and without echoing it.
pub async fn asset_flow(identity: &ApiIdentity, backend: &FindingsBackend, asset: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let checked = asset.ok().filter(|text| is_field(text));
    match checked {
        None => Ok(not_found()),
        Some(text) => {
            let page = (backend.asset)(scope, text).await.map_err(|error| store_failure(&error))?;
            Ok(asset_view(&page).map_or_else(not_found, |view| Json(view).into_response()))
        }
    }
}


#[utoipa::path(
    get,
    path = "/vulnerabilities/findings",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of the tenant's open findings, highest priority first", body = FindingsListView),
        (status = 400, description = "Malformed cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<FindingsBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/vulnerabilities/assets/{asset}",
    params(("asset" = String, Path, description = "Asset name, percent-encoded")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The open findings of one asset", body = AssetView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No open finding for this asset in this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn asset_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<FindingsBackend>,
    asset: Result<Path<String>, PathRejection>,
) -> Response {
    reply(asset_flow(&identity, &backend, asset.map(|found| found.0)).await)
}


pub fn vulnerabilities_router(backend: FindingsBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(ASSET_PATH, get(asset_endpoint))
        .layer(Extension(backend))
}


pub fn vulnerabilities_access() -> AccessTable {
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


pub fn vulnerabilities_document() -> OpenApiDocument {
    VulnerabilitiesDoc::openapi()
}
