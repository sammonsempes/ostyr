use crate::api_model::{ListQuery, NoQuery, RunDetail, RunDetailView, RunItem, RunList, RunListView, RunMeta, RunPage, RunsBackend};
use crate::error::ReadError;
use crate::runs_read::{parse_cursor, parse_limit};
use alerts::api::unavailable;
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
use core_auth::rbac::PERMISSION_PLAYBOOKS_READ;
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: usize = 50;


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such playbook run";


pub const LIST_PATH: &str = "/playbooks/runs";


pub const GET_PATH: &str = "/playbooks/runs/{id}";


#[derive(OpenApi)]
#[openapi(paths(list_endpoint, get_endpoint), components(schemas(RunItem, RunListView, RunDetailView)))]
pub struct PlaybooksDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, ApiError> {
    tenant_scope(&identity.tenant).map_err(|_refused| {
        tracing::warn!("playbook run read refused: the module tenant is unusable");
        ApiError::Internal
    })
}


pub fn page_of(query: &ListQuery) -> Result<RunPage, ReadError> {
    Ok(RunPage {
        after: query.cursor.as_deref().map(parse_cursor).transpose()?,
        size: parse_limit(query.limit.as_deref(), DEFAULT_LIMIT)?,
    })
}


/// A bad cursor or limit is the caller's 400, a full pool 429, an unreachable database the fixed 503; the rest is logged and answered with a generic error.
pub fn read_reply(error: &ReadError) -> Result<Response, ApiError> {
    match error {
        ReadError::BadCursor | ReadError::BadLimit { .. } => Err(ApiError::BadRequest),
        ReadError::Busy => Err(ApiError::TooManyRequests),
        ReadError::Pg(PgError::ConnectTimeout { .. }) => Ok(unavailable()),
        other => {
            tracing::warn!(error = %other, "playbook run read failed");
            Err(ApiError::Internal)
        }
    }
}


pub fn item_of(meta: &RunMeta) -> RunItem {
    RunItem {
        id: meta.id.clone(),
        alert_id: meta.alert_id.clone(),
        playbook: meta.playbook.clone(),
        mode: meta.mode.clone(),
        outcome: meta.outcome.clone(),
        steps: meta.steps,
        created: meta.created,
    }
}


pub fn list_view(list: &RunList) -> RunListView {
    RunListView {
        items: list.runs.iter().map(item_of).collect(),
        next_cursor: list.next.map(|seq| seq.to_string()),
    }
}


pub fn detail_view(detail: &RunDetail) -> RunDetailView {
    RunDetailView {
        run: item_of(&detail.meta),
        trace: detail.trace.clone(),
    }
}


pub async fn list_flow(identity: &ApiIdentity, backend: &RunsBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity)?;
    match page_of(&parsed) {
        Err(error) => read_reply(&error),
        Ok(page) => match (backend.list)(scope, page).await {
            Ok(found) => Ok(Json(list_view(&found)).into_response()),
            Err(error) => read_reply(&error),
        },
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


/// An unknown id, another tenant's id and a malformed id are the same fixed 404.
pub async fn get_flow(identity: &ApiIdentity, backend: &RunsBackend, id: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity)?;
    match id {
        Err(_rejection) => Ok(not_found()),
        Ok(text) => match (backend.get)(scope, text).await {
            Ok(None) => Ok(not_found()),
            Ok(Some(detail)) => Ok(Json(detail_view(&detail)).into_response()),
            Err(error) => read_reply(&error),
        },
    }
}


#[utoipa::path(
    get,
    path = "/playbooks/runs",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of dry runs, newest first, without traces", body = RunListView),
        (status = 400, description = "Malformed cursor or limit, or an unknown query key", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody),
        (status = 503, description = "Database unavailable", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<RunsBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/playbooks/runs/{id}",
    params(("id" = String, Path, description = "Run id, 64 lowercase hexadecimal characters")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The run with its trace (parameter names and kinds, never values)", body = RunDetailView),
        (status = 400, description = "The request has a query string", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such run for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody),
        (status = 503, description = "Database unavailable", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<RunsBackend>,
    id: Result<Path<String>, PathRejection>,
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Response {
    let checked = query.map(|_none| ()).map_err(|_rejection| ApiError::BadRequest);
    let flow = match checked {
        Ok(()) => get_flow(&identity, &backend, id.map(|found| found.0)).await,
        Err(error) => Err(error),
    };
    reply(flow)
}


pub fn playbooks_router(backend: RunsBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


/// `playbooks.read`, deny by default: a role without it is a 403 before any handler.
pub fn playbooks_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_PLAYBOOKS_READ.to_owned()),
                    sensitive: false,
                },
            )
        })
        .into_iter()
        .collect()
}


pub fn playbooks_document() -> OpenApiDocument {
    PlaybooksDoc::openapi()
}
