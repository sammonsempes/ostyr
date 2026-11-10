use crate::api_model::{CaseListView, CasesBackend, ListQuery};
use crate::error::CaseStoreError;
use crate::store::{check_text, format_cursor, parse_cursor, MAX_ID_CHARS, MAX_PAGE_SIZE};
use crate::stored::{CaseCounts, CaseCursor, CaseDetail, CasePage, CaseSummary, SummaryList};
use alerts::error::StoreError;
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
use core_auth::rbac::PERMISSION_CASES_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use data_encoding::BASE64URL_NOPAD;
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: usize = 50;


/// `<19 digits>.<128 characters of up to 4 bytes>` is 532 bytes, 710 base64 characters: a cursor of any stored id fits.
pub const MAX_CURSOR_CHARS: usize = 768;


pub const LIST_PATH: &str = "/cases";


pub const GET_PATH: &str = "/cases/{id}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such case";


#[derive(OpenApi)]
#[openapi(
    paths(list_endpoint, get_endpoint),
    components(schemas(CaseSummary, CaseDetail, CaseCounts, CaseListView))
)]
pub struct CasesDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under (a session carries none): no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, CaseStoreError> {
    Ok(tenant_scope(&identity.tenant)?)
}


pub fn parse_limit(text: Option<&str>) -> Result<usize, CaseStoreError> {
    text.map_or(Ok(DEFAULT_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE_SIZE).contains(size))
            .ok_or(CaseStoreError::BadPageSize { limit: MAX_PAGE_SIZE })
    })
}


pub fn encode_cursor(cursor: &CaseCursor) -> String {
    BASE64URL_NOPAD.encode(format_cursor(cursor).as_bytes())
}


pub fn decode_cursor(text: &str) -> Result<CaseCursor, CaseStoreError> {
    let bytes = (text.len() <= MAX_CURSOR_CHARS)
        .then(|| BASE64URL_NOPAD.decode(text.as_bytes()).ok())
        .flatten()
        .ok_or(CaseStoreError::BadCursor)?;
    let decoded = String::from_utf8(bytes).map_err(|_source| CaseStoreError::BadCursor)?;
    parse_cursor(&decoded)
}


pub fn page_of(query: &ListQuery) -> Result<CasePage, CaseStoreError> {
    Ok(CasePage {
        after: query.cursor.as_deref().map(decode_cursor).transpose()?,
        size: parse_limit(query.limit.as_deref())?,
    })
}


/// A bad cursor or limit is the caller's 400; anything else is logged and answered with a generic error, never the database text.
pub fn store_failure(error: &CaseStoreError) -> ApiError {
    match error {
        CaseStoreError::BadCursor | CaseStoreError::BadPageSize { .. } => ApiError::BadRequest,
        CaseStoreError::Lease(StoreError::Busy) => ApiError::TooManyRequests,
        other => {
            tracing::warn!(error = %other, "cases store failure");
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


pub fn list_view(found: SummaryList) -> CaseListView {
    CaseListView {
        next_cursor: found.next.as_ref().map(encode_cursor),
        items: found.summaries,
    }
}


pub async fn list_flow(identity: &ApiIdentity, backend: &CasesBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let page = page_of(&parsed).map_err(|error| store_failure(&error))?;
    let found = (backend.list)(scope, page).await.map_err(|error| store_failure(&error))?;
    Ok(Json(list_view(found)).into_response())
}


/// A malformed id cannot name a stored case, so it is answered like a missing one, without a store call.
pub async fn get_flow(identity: &ApiIdentity, backend: &CasesBackend, id: String) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    match check_text("id", &id, MAX_ID_CHARS) {
        Err(_malformed) => Ok(not_found()),
        Ok(()) => (backend.get)(scope, id)
            .await
            .map_err(|error| store_failure(&error))
            .map(|found| found.map_or_else(not_found, |detail| Json(detail).into_response())),
    }
}


#[utoipa::path(
    get,
    path = "/cases",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of case summaries, newest first", body = CaseListView),
        (status = 400, description = "Malformed cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/cases/{id}",
    params(("id" = String, Path, description = "Case id")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The case; comments, observables, history and alert links are counts", body = CaseDetail),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such case for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    Path(id): Path<String>,
) -> Response {
    reply(get_flow(&identity, &backend, id).await)
}


pub fn cases_router(backend: CasesBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


pub fn cases_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
        .into_iter()
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_CASES_READ.to_owned()),
                    sensitive: false,
                },
            )
        })
        .collect()
}


pub fn cases_document() -> OpenApiDocument {
    CasesDoc::openapi()
}
