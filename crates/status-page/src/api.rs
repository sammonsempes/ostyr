use crate::api_model::{CreateRequest, IncidentView, ResolveRequest, StatusBackend, UpdateRequest};
use crate::error::StoreError;
use crate::store::{validate_new_incident, validate_update};
use crate::store_model::{IncidentRef, NewIncident};
use crate::types::Refused;
use alerts::error::StoreError as LeaseError;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use core_api::failure::error_response;
use core_api::model::{ApiError, ApiIdentity, ApiState, Authenticated, ErrorBody, ErrorDetail, RequestId, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_audit::log::append_declared;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_auth::rbac::PERMISSION_STATUS_WRITE;
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const CREATE_PATH: &str = "/status/incidents";


pub const UPDATE_PATH: &str = "/status/incidents/{id}/updates";


pub const RESOLVE_PATH: &str = "/status/incidents/{id}/resolve";


/// A JSON string spends at most 12 bytes on one character (a surrogate pair written as two `\uXXXX` escapes).
pub const JSON_BYTES_PER_CHAR: usize = 12;


pub const JSON_OVERHEAD_BYTES: usize = 512;


pub const CREATE_BODY_LIMIT: usize = (crate::store::MAX_SERVICE_CHARACTERS + crate::store::MAX_TITLE_CHARACTERS + crate::store::MAX_NOTE_CHARACTERS)
    * JSON_BYTES_PER_CHAR
    + JSON_OVERHEAD_BYTES;


pub const UPDATE_BODY_LIMIT: usize =
    (crate::store::MAX_MESSAGE_CHARACTERS + crate::store::MAX_NOTE_CHARACTERS) * JSON_BYTES_PER_CHAR + JSON_OVERHEAD_BYTES;


pub const RESOLVE_BODY_LIMIT: usize = 1_024;


/// A time more than this many seconds ahead of the server clock is refused.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;


pub const BAD_REQUEST_CODE: &str = "bad_request";


pub const CONFLICT_CODE: &str = "conflict";


pub const CONFLICT_MESSAGE: &str = "the incident changed or does not exist";


pub const ACTION_CREATE: &str = "status.incident.create";


pub const ACTION_UPDATE: &str = "status.incident.update";


pub const ACTION_RESOLVE: &str = "status.incident.resolve";


pub const NEW_TARGET: &str = "new";


pub const UNKNOWN_ACTOR: &str = "unknown";


pub const AUDIT_DECLARED_KEYS: [&str; 1] = ["status"];


#[derive(OpenApi)]
#[openapi(
    paths(create_endpoint, update_endpoint, resolve_endpoint),
    components(schemas(CreateRequest, UpdateRequest, ResolveRequest, IncidentView))
)]
pub struct StatusDoc;


/// What the handler knows about the caller: the admitted identity, the request id and the session `guard` validated.
pub struct Caller<'a> {
    pub app: &'a ApiState,
    pub identity: &'a ApiIdentity,
    pub request_id: &'a str,
    pub session: Option<&'a Authenticated>,
}


pub fn error_reply(status: StatusCode, code: &str, message: String) -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: code.to_owned(),
            message,
        },
    };
    (status, Json(body)).into_response()
}


/// Names the field, never its value.
pub fn bad_field(field: &str, reason: &str) -> Response {
    error_reply(StatusCode::BAD_REQUEST, BAD_REQUEST_CODE, format!("field `{field}` {reason}"))
}


pub fn conflict() -> Response {
    error_reply(StatusCode::CONFLICT, CONFLICT_CODE, CONFLICT_MESSAGE.to_owned())
}


/// A body over the route's limit is the 413, any other refusal (syntax, unknown field, wrong type, content type) the 400.
pub fn body_failure(rejection: &JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge
    } else {
        ApiError::BadRequest
    }
}


/// Text bounds name the field; a stale version, a foreign or unknown id and a full list are one fixed 409; a busy pool is 429; the rest is logged by class and answered 500.
pub fn store_failure(error: &StoreError) -> Response {
    match error {
        StoreError::TextTooLong { field, .. } => bad_field(field, "is too long"),
        StoreError::TextInvalid { field } => bad_field(field, "is empty or holds a control character"),
        StoreError::Conflict => conflict(),
        StoreError::Lease(LeaseError::Busy) => error_response(&ApiError::TooManyRequests),
        _ => {
            tracing::warn!("status incident write failed in the store");
            error_response(&ApiError::Internal)
        }
    }
}


/// The tenant is the one of the identity snapshot `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, Refused> {
    tenant_scope(&identity.tenant).map_err(|_refused| {
        tracing::warn!("status write refused: the module tenant is unusable");
        refuse(error_response(&ApiError::Internal))
    })
}


/// A handler reached without a session never writes.
pub fn admit(caller: &Caller<'_>) -> Result<TenantScope, Refused> {
    if caller.session.is_none() {
        tracing::warn!("status write reached without a session");
        Err(refuse(error_response(&ApiError::Internal)))
    } else {
        scope_of(caller.identity)
    }
}


/// The incident id of the path: decimal digits only, as the store holds it.
pub fn parse_id(id: Result<String, PathRejection>) -> Result<i64, Refused> {
    id.ok()
        .filter(|text| text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<i64>().ok())
        .ok_or_else(|| refuse(error_response(&ApiError::BadRequest)))
}


pub fn service_declared(backend: &StatusBackend, identity: &ApiIdentity, service: &str) -> bool {
    backend.page.tenant == identity.tenant && backend.page.services.contains(service)
}


/// From zero to `MAX_CLOCK_SKEW_SECONDS` past the request clock.
pub fn check_time(field: &str, value: i64, now: i64) -> Result<(), Refused> {
    if (0..=now.saturating_add(MAX_CLOCK_SKEW_SECONDS)).contains(&value) {
        Ok(())
    } else {
        Err(refuse(bad_field(field, "is outside the accepted range")))
    }
}


pub fn view_reply(status: StatusCode, written: IncidentRef) -> Response {
    (
        status,
        Json(IncidentView {
            id: written.id,
            version: written.version,
        }),
    )
        .into_response()
}


/// Records the outcome with the actor and the incident id, never a text; the write is already done when it fails, so the caller is told.
pub fn audited(caller: &Caller<'_>, action: &str, target: &str, response: Response) -> Response {
    let status = response.status();
    let outcome = if status.is_success() { Outcome::Success } else { Outcome::Failure };
    let actor = caller.session.map_or(UNKNOWN_ACTOR, |session| session.user.as_str());
    let entry = NewEntry {
        timestamp: (caller.app.clock)(),
        actor: Actor {
            kind: ActorKind::User,
            id: actor.to_owned(),
        },
        tenant: caller.identity.tenant.clone(),
        module: caller.identity.module.clone(),
        action: action.to_owned(),
        target: target.to_owned(),
        outcome,
        request_id: caller.request_id.to_owned(),
        justification: None,
        parameters: [("status".to_owned(), status.as_u16().to_string())].into_iter().collect(),
    };
    match append_declared(&caller.app.audit, entry, &AUDIT_DECLARED_KEYS) {
        Ok(_record) => response,
        Err(error) => {
            tracing::error!(%error, "status write audit failed");
            error_response(&ApiError::Internal)
        }
    }
}


pub async fn create_checked(caller: &Caller<'_>, backend: &StatusBackend, body: Result<CreateRequest, ApiError>) -> Result<IncidentRef, Refused> {
    let request = body.map_err(|error| refuse(error_response(&error)))?;
    let scope = admit(caller)?;
    check_time("started_at", request.started_at, (backend.clock)())?;
    let incident = NewIncident {
        service: request.service,
        title: request.title,
        published: request.published,
        started_at: request.started_at,
        internal_note: request.internal_note,
    };
    validate_new_incident(&incident).map_err(|error| refuse(store_failure(&error)))?;
    if service_declared(backend, caller.identity, &incident.service) {
        (backend.create)(scope, incident).await.map_err(|error| refuse(store_failure(&error)))
    } else {
        Err(refuse(bad_field("service", "is not declared on the status page")))
    }
}


pub async fn create_flow(caller: &Caller<'_>, backend: &StatusBackend, body: Result<CreateRequest, ApiError>) -> Response {
    let result = create_checked(caller, backend, body).await;
    let target = result
        .as_ref()
        .map_or_else(|_refused| NEW_TARGET.to_owned(), |created| created.id.to_string());
    let response = result.map_or_else(|refused| *refused, |created| view_reply(StatusCode::CREATED, created));
    audited(caller, ACTION_CREATE, &target, response)
}


pub async fn update_checked(
    caller: &Caller<'_>,
    backend: &StatusBackend,
    id: i64,
    body: Result<UpdateRequest, ApiError>,
) -> Result<IncidentRef, Refused> {
    let request = body.map_err(|error| refuse(error_response(&error)))?;
    let scope = admit(caller)?;
    check_time("at", request.at, (backend.clock)())?;
    validate_update(&request.message, &request.internal_note).map_err(|error| refuse(store_failure(&error)))?;
    let incident = IncidentRef {
        id,
        version: request.version,
    };
    (backend.update)(scope, incident, request.at, request.message, request.internal_note)
        .await
        .map_err(|error| refuse(store_failure(&error)))
}


pub async fn update_flow(
    caller: &Caller<'_>,
    backend: &StatusBackend,
    id: Result<String, PathRejection>,
    body: Result<UpdateRequest, ApiError>,
) -> Response {
    let parsed = parse_id(id);
    let target = parsed.as_ref().map_or_else(|_refused| NEW_TARGET.to_owned(), i64::to_string);
    let response = match parsed {
        Ok(number) => update_checked(caller, backend, number, body)
            .await
            .map_or_else(|refused| *refused, |written| view_reply(StatusCode::OK, written)),
        Err(refused) => *refused,
    };
    audited(caller, ACTION_UPDATE, &target, response)
}


pub async fn resolve_checked(
    caller: &Caller<'_>,
    backend: &StatusBackend,
    id: i64,
    body: Result<ResolveRequest, ApiError>,
) -> Result<IncidentRef, Refused> {
    let request = body.map_err(|error| refuse(error_response(&error)))?;
    let scope = admit(caller)?;
    check_time("at", request.at, (backend.clock)())?;
    let incident = IncidentRef {
        id,
        version: request.version,
    };
    (backend.resolve)(scope, incident, request.at)
        .await
        .map_err(|error| refuse(store_failure(&error)))
}


pub async fn resolve_flow(
    caller: &Caller<'_>,
    backend: &StatusBackend,
    id: Result<String, PathRejection>,
    body: Result<ResolveRequest, ApiError>,
) -> Response {
    let parsed = parse_id(id);
    let target = parsed.as_ref().map_or_else(|_refused| NEW_TARGET.to_owned(), i64::to_string);
    let response = match parsed {
        Ok(number) => resolve_checked(caller, backend, number, body)
            .await
            .map_or_else(|refused| *refused, |written| view_reply(StatusCode::OK, written)),
        Err(refused) => *refused,
    };
    audited(caller, ACTION_RESOLVE, &target, response)
}


#[utoipa::path(
    post,
    path = "/status/incidents",
    request_body = CreateRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The incident id and its version", body = IncidentView),
        (status = 400, description = "Malformed body, unknown field or query, undeclared service, bad text or time", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn create_endpoint(
    State(app): State<SharedState>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(request_id): Extension<RequestId>,
    Extension(backend): Extension<StatusBackend>,
    session: Option<Extension<Authenticated>>,
    body: Result<Json<CreateRequest>, JsonRejection>,
) -> Response {
    let caller = Caller {
        app: &app,
        identity: &identity,
        request_id: &request_id.0,
        session: session.as_ref().map(|found| &found.0),
    };
    create_flow(&caller, &backend, body.map(|found| found.0).map_err(|rejection| body_failure(&rejection))).await
}


#[utoipa::path(
    post,
    path = "/status/incidents/{id}/updates",
    params(("id" = String, Path, description = "Incident id")),
    request_body = UpdateRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The incident id and its new version", body = IncidentView),
        (status = 400, description = "Malformed id or body, unknown field or query, bad text or time", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 409, description = "Stale version, unknown or foreign id, or the update limit", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn update_endpoint(
    State(app): State<SharedState>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(request_id): Extension<RequestId>,
    Extension(backend): Extension<StatusBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<UpdateRequest>, JsonRejection>,
) -> Response {
    let caller = Caller {
        app: &app,
        identity: &identity,
        request_id: &request_id.0,
        session: session.as_ref().map(|found| &found.0),
    };
    update_flow(
        &caller,
        &backend,
        id.map(|found| found.0),
        body.map(|found| found.0).map_err(|rejection| body_failure(&rejection)),
    )
    .await
}


#[utoipa::path(
    post,
    path = "/status/incidents/{id}/resolve",
    params(("id" = String, Path, description = "Incident id")),
    request_body = ResolveRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The incident id and its new version", body = IncidentView),
        (status = 400, description = "Malformed id or body, unknown field or query, bad time", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 409, description = "Stale version, unknown or foreign id, or already resolved", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn resolve_endpoint(
    State(app): State<SharedState>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(request_id): Extension<RequestId>,
    Extension(backend): Extension<StatusBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ResolveRequest>, JsonRejection>,
) -> Response {
    let caller = Caller {
        app: &app,
        identity: &identity,
        request_id: &request_id.0,
        session: session.as_ref().map(|found| &found.0),
    };
    resolve_flow(
        &caller,
        &backend,
        id.map(|found| found.0),
        body.map(|found| found.0).map_err(|rejection| body_failure(&rejection)),
    )
    .await
}


pub fn refuse(response: Response) -> Refused {
    Box::new(response)
}


/// No write route takes a query string: a `tenant` parameter, or any other, is a 400 before the handler.
pub async fn refuse_query(request: Request, next: Next) -> Response {
    if request.uri().query().is_some() {
        error_response(&ApiError::BadRequest)
    } else {
        next.run(request).await
    }
}


pub fn status_router(backend: StatusBackend) -> Router<SharedState> {
    Router::new()
        .route(CREATE_PATH, post(create_endpoint).layer(DefaultBodyLimit::max(CREATE_BODY_LIMIT)))
        .route(UPDATE_PATH, post(update_endpoint).layer(DefaultBodyLimit::max(UPDATE_BODY_LIMIT)))
        .route(RESOLVE_PATH, post(resolve_endpoint).layer(DefaultBodyLimit::max(RESOLVE_BODY_LIMIT)))
        .layer(from_fn(refuse_query))
        .layer(Extension(backend))
}


/// `status.write`, deny by default: a role without it is a 403 before any handler.
pub fn status_access() -> AccessTable {
    [CREATE_PATH, UPDATE_PATH, RESOLVE_PATH]
        .map(|path| {
            (
                route_key("POST", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_STATUS_WRITE.to_owned()),
                    sensitive: false,
                },
            )
        })
        .into_iter()
        .collect()
}


pub fn status_document() -> OpenApiDocument {
    StatusDoc::openapi()
}
