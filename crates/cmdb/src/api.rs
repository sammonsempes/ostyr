use crate::api_model::{AssetListView, CmdbBackend, ListQuery};
use crate::error::StoreError;
use crate::stored::{AssetCounts, AssetDetail, AssetPage, AssetSummary, AttributeView, KeyView, SummaryList};
use crate::summary::{check_id, MAX_LIST_LIMIT};
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
use data_encoding::BASE64URL_NOPAD;
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: usize = 50;


/// An id of `MAX_ID_BYTES` (512) bytes is 683 base64 characters: a cursor of any admitted id fits.
pub const MAX_CURSOR_CHARS: usize = 768;


pub const LIST_PATH: &str = "/assets";


pub const GET_PATH: &str = "/assets/{id}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such asset";


#[derive(OpenApi)]
#[openapi(
    paths(list_endpoint, get_endpoint),
    components(schemas(AssetSummary, AssetDetail, AssetCounts, AssetListView, KeyView, AttributeView))
)]
pub struct CmdbDoc;


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
            .filter(|size| (1..=MAX_LIST_LIMIT).contains(size))
            .ok_or(StoreError::BadPageSize { limit: MAX_LIST_LIMIT })
    })
}


pub fn encode_cursor(id: &str) -> String {
    BASE64URL_NOPAD.encode(id.as_bytes())
}


pub fn decode_cursor(text: &str) -> Result<String, StoreError> {
    let bytes = (text.len() <= MAX_CURSOR_CHARS)
        .then(|| BASE64URL_NOPAD.decode(text.as_bytes()).ok())
        .flatten()
        .ok_or(StoreError::BadCursor)?;
    let decoded = String::from_utf8(bytes).map_err(|_source| StoreError::BadCursor)?;
    check_id(&decoded).map(|()| decoded).map_err(|_bad| StoreError::BadCursor)
}


pub fn page_of(query: &ListQuery) -> Result<AssetPage, StoreError> {
    Ok(AssetPage {
        after: query.cursor.as_deref().map(decode_cursor).transpose()?,
        size: parse_limit(query.limit.as_deref())?,
    })
}


/// A bad cursor or limit is the caller's 400; anything else is logged and answered with a generic error, never the database text.
pub fn store_failure(error: &StoreError) -> ApiError {
    match error {
        StoreError::BadCursor | StoreError::BadPageSize { .. } | StoreError::BadId => ApiError::BadRequest,
        StoreError::Lease(alerts::error::StoreError::Busy) => ApiError::TooManyRequests,
        other => {
            tracing::warn!(error = %other, "cmdb store failure");
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


pub fn list_view(found: SummaryList) -> AssetListView {
    AssetListView {
        next_cursor: found.next.as_deref().map(encode_cursor),
        items: found.summaries,
    }
}


pub async fn list_flow(identity: &ApiIdentity, backend: &CmdbBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let page = page_of(&parsed).map_err(|error| store_failure(&error))?;
    let found = (backend.list)(scope, page).await.map_err(|error| store_failure(&error))?;
    Ok(Json(list_view(found)).into_response())
}


/// A malformed id, or one the extractor refuses (not UTF-8), is answered like a missing one, without a store call.
pub async fn get_flow(identity: &ApiIdentity, backend: &CmdbBackend, id: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let checked = id
        .map_err(|_rejection| ())
        .and_then(|text| check_id(&text).map(|()| text).map_err(|_malformed| ()));
    match checked {
        Err(()) => Ok(not_found()),
        Ok(text) => (backend.get)(scope, text)
            .await
            .map_err(|error| store_failure(&error))
            .map(|found| found.map_or_else(not_found, |detail| Json(detail).into_response())),
    }
}


#[utoipa::path(
    get,
    path = "/assets",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of asset summaries ordered by id", body = AssetListView),
        (status = 400, description = "Malformed cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CmdbBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/assets/{id}",
    params(("id" = String, Path, description = "Asset id")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The asset with its keys and attributes, truncated flag set when some are not shown", body = AssetDetail),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such asset for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CmdbBackend>,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    reply(get_flow(&identity, &backend, id.map(|found| found.0)).await)
}


pub fn cmdb_router(backend: CmdbBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


pub fn cmdb_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
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


pub fn cmdb_document() -> OpenApiDocument {
    CmdbDoc::openapi()
}
