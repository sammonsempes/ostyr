use crate::api_model::{Caller, GrcBackend, ListQuery, NoQuery, ReportItem, ReportListView};
use crate::error::StoreError;
use crate::load::{is_identifier, MAX_ID_CHARS};
use crate::store::{ReportMeta, MAX_LIST_LIMIT};
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use core_api::failure::{error_response, reply};
use core_api::model::{ApiError, ApiIdentity, Authenticated, ErrorBody, ErrorDetail, RequestId, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_audit::log::append_declared;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_auth::rbac::PERMISSION_GRC_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use tokio::task::JoinError;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: usize = 50;


pub const LIST_PATH: &str = "/grc/reports";


pub const GET_PATH: &str = "/grc/reports/{id}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such report";


pub const JSON_CONTENT_TYPE: &str = "application/json";


pub const ACTION_READ: &str = "grc.report.read";


pub const LIST_TARGET: &str = "list";


pub const INVALID_TARGET: &str = "invalid";


pub const UNKNOWN_ACTOR: &str = "unknown";


pub const AUDIT_DECLARED_KEYS: [&str; 1] = ["status"];


/// The named log class of a stored body that no longer matches its digest.
pub const DIGEST_MISMATCH_CLASS: &str = "report_digest_mismatch";


#[derive(OpenApi)]
#[openapi(paths(list_endpoint, get_endpoint), components(schemas(ReportItem, ReportListView)))]
pub struct GrcDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, ApiError> {
    tenant_scope(&identity.tenant).map_err(|_refused| {
        tracing::warn!("grc read refused: the module tenant is unusable");
        ApiError::Internal
    })
}


pub fn parse_limit(text: Option<&str>) -> Result<usize, ApiError> {
    text.map_or(Ok(DEFAULT_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_LIST_LIMIT).contains(size))
            .ok_or(ApiError::BadRequest)
    })
}


/// A framework name follows the grc id grammar, so no NUL, no leading `-`, no path and no long text reaches the store.
pub fn parse_framework(text: Option<String>) -> Result<Option<String>, ApiError> {
    text.map(|name| is_identifier(&name, MAX_ID_CHARS).then_some(name).ok_or(ApiError::BadRequest))
        .transpose()
}


/// The report id of the path: decimal digits only; `None` for anything else, which is answered like an unknown id.
pub fn parse_id(id: Result<String, PathRejection>) -> Option<i64> {
    id.ok()
        .filter(|text| text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<i64>().ok())
}


/// A full pool is 429; a digest mismatch is logged by its class; the rest is logged and answered with a generic error, never the database text.
pub fn store_failure(error: &StoreError) -> ApiError {
    match error {
        StoreError::Busy => ApiError::TooManyRequests,
        StoreError::DigestMismatch => {
            tracing::error!(class = DIGEST_MISMATCH_CLASS, "a stored report failed its digest check");
            ApiError::Internal
        }
        other => {
            tracing::warn!(error = %other, "grc report read failed in the store");
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


pub fn item_of(meta: &ReportMeta) -> ReportItem {
    ReportItem {
        id: meta.id,
        framework: meta.framework.clone(),
        version: meta.version,
        generated: meta.generated.clone(),
        digest: meta.digest.clone(),
        bytes: meta.bytes,
        stored_at: meta.stored_epoch,
    }
}


pub async fn list_flow(identity: &ApiIdentity, backend: &GrcBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity)?;
    let framework = parse_framework(parsed.framework)?;
    let limit = parse_limit(parsed.limit.as_deref())?;
    let found = (backend.list)(scope, framework, limit).await.map_err(|error| store_failure(&error))?;
    Ok(Json(ReportListView {
        items: found.iter().map(item_of).collect(),
    })
    .into_response())
}


/// The stored bytes, as they were digested; an unknown id, another tenant's id and a malformed id are the same fixed 404.
pub async fn get_flow(identity: &ApiIdentity, backend: &GrcBackend, request: Result<Option<i64>, ApiError>) -> Result<Response, ApiError> {
    let id = request?;
    let scope = scope_of(identity)?;
    match id {
        None => Ok(not_found()),
        Some(number) => (backend.get)(scope, number)
            .await
            .map_err(|error| store_failure(&error))
            .map(|found| found.map_or_else(not_found, |stored| ([(CONTENT_TYPE, JSON_CONTENT_TYPE)], stored.body).into_response())),
    }
}


/// Records the read with the actor and the target, never the body; when the append fails the body is dropped and the caller gets a 500.
pub fn audited(caller: &Caller, target: &str, response: Response) -> Response {
    let status = response.status();
    let outcome = if status.is_success() { Outcome::Success } else { Outcome::Failure };
    let actor = caller.user.clone().unwrap_or_else(|| UNKNOWN_ACTOR.to_owned());
    let entry = NewEntry {
        timestamp: (caller.app.clock)(),
        actor: Actor {
            kind: ActorKind::User,
            id: actor,
        },
        tenant: caller.identity.tenant.clone(),
        module: caller.identity.module.clone(),
        action: ACTION_READ.to_owned(),
        target: target.to_owned(),
        outcome,
        request_id: caller.request_id.clone(),
        justification: None,
        parameters: [("status".to_owned(), status.as_u16().to_string())].into_iter().collect(),
    };
    match append_declared(&caller.app.audit, entry, &AUDIT_DECLARED_KEYS) {
        Ok(_record) => response,
        Err(error) => {
            tracing::error!(%error, "grc read audit failed");
            error_response(&ApiError::Internal)
        }
    }
}


pub async fn list_task(caller: Caller, backend: GrcBackend, query: Result<ListQuery, ApiError>) -> Response {
    let response = reply(list_flow(&caller.identity, &backend, query).await);
    audited(&caller, LIST_TARGET, response)
}


pub async fn get_task(caller: Caller, backend: GrcBackend, request: Result<Option<i64>, ApiError>) -> Response {
    let target = request
        .as_ref()
        .ok()
        .copied()
        .flatten()
        .map_or_else(|| INVALID_TARGET.to_owned(), |number| number.to_string());
    let response = reply(get_flow(&caller.identity, &backend, request).await);
    audited(&caller, &target, response)
}


/// A handler task that panicked is a fixed 500, never the payload.
pub fn finished(joined: Result<Response, JoinError>) -> Response {
    joined.unwrap_or_else(|_error| {
        tracing::error!("grc read task failed");
        error_response(&ApiError::Internal)
    })
}


pub fn caller_of(app: SharedState, identity: Arc<ApiIdentity>, request_id: RequestId, session: Option<Extension<Authenticated>>) -> Caller {
    Caller {
        app,
        identity,
        request_id: request_id.0,
        user: session.map(|found| found.0.user),
    }
}


#[utoipa::path(
    get,
    path = "/grc/reports",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The newest reports first, at most `limit` of them (no cursor), metadata only", body = ReportListView),
        (status = 400, description = "Bad framework, bad limit or an unknown query key", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    State(app): State<SharedState>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(request_id): Extension<RequestId>,
    Extension(backend): Extension<GrcBackend>,
    session: Option<Extension<Authenticated>>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    let caller = caller_of(app, identity, request_id, session);
    let parsed = query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest);
    finished(tokio::spawn(list_task(caller, backend, parsed)).await)
}


#[utoipa::path(
    get,
    path = "/grc/reports/{id}",
    params(("id" = String, Path, description = "Report id")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The stored report body, byte for byte, after the digest check", content_type = "application/json", body = Object),
        (status = 400, description = "The request has a query string", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such report for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody),
        (status = 500, description = "The stored body no longer matches its digest, or the audit failed", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    State(app): State<SharedState>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(request_id): Extension<RequestId>,
    Extension(backend): Extension<GrcBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Response {
    let caller = caller_of(app, identity, request_id, session);
    let request = query
        .map(|_found| parse_id(id.map(|found| found.0)))
        .map_err(|_rejection| ApiError::BadRequest);
    finished(tokio::spawn(get_task(caller, backend, request)).await)
}


/// The reads run in their own task: a client that leaves never cancels a read between its answer and its audit record.
pub fn grc_router(backend: GrcBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


/// `grc.read`, deny by default: a role without it is a 403 before any handler. Not `sensitive`: the handlers write their own `grc.report.read` record.
pub fn grc_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_GRC_READ.to_owned()),
                    sensitive: false,
                },
            )
        })
        .into_iter()
        .collect()
}


pub fn grc_document() -> OpenApiDocument {
    GrcDoc::openapi()
}
