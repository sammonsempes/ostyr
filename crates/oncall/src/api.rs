use crate::alert::{Alert, AlertPage, Event};
use crate::api_model::{AlertListView, AlertView, ChangeRequest, ListQuery, OncallBackend};
use crate::error::{ReadError, StoreError};
use crate::limits::{MAX_FINGERPRINT_BYTES, MAX_OPEN_ALERTS};
use crate::rows::phase_name;
use crate::store::valid_text;
use crate::types::Refused;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use core_api::failure::{error_response, reply};
use core_api::model::{ApiError, ApiIdentity, ApiState, Authenticated, ErrorBody, ErrorDetail, RequestId, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_audit::log::append_declared;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_audit::types::ParameterMap;
use core_auth::rbac::{PERMISSION_ONCALL_ACKNOWLEDGE, PERMISSION_ONCALL_READ};
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: u32 = 50;


pub const LIST_PATH: &str = "/oncall/alerts";


pub const GET_PATH: &str = "/oncall/alerts/{id}";


pub const ACKNOWLEDGE_PATH: &str = "/oncall/alerts/{id}/acknowledge";


pub const RESOLVE_PATH: &str = "/oncall/alerts/{id}/resolve";


/// `{}` and a little room; core-api's `body_deadline` caps every body at 16 384 bytes first.
pub const CHANGE_BODY_LIMIT: usize = 64;


pub const CONFLICT_CODE: &str = "conflict";


pub const CONFLICT_MESSAGE: &str = "the alert changed or cannot take this action";


pub const ACTION_ACKNOWLEDGE: &str = "oncall.alert.acknowledge";


pub const ACTION_RESOLVE: &str = "oncall.alert.resolve";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such alert";


pub const UNREADABLE_CODE: &str = "unreadable_alert";


pub const UNREADABLE_MESSAGE: &str = "the stored alert cannot be shown";


pub const FIRST_YEAR: i32 = 0;


pub const LAST_YEAR: i32 = 9999;


#[derive(OpenApi)]
#[openapi(
    paths(list_endpoint, get_endpoint, acknowledge_endpoint, resolve_endpoint),
    components(schemas(AlertView, AlertListView, ChangeRequest))
)]
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


/// One fixed 409 for a transition the lifecycle refuses and for a version that moved: never a hint of which.
pub fn conflict() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: CONFLICT_CODE.to_owned(),
            message: CONFLICT_MESSAGE.to_owned(),
        },
    };
    (StatusCode::CONFLICT, Json(body)).into_response()
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


/// What the handler knows about the caller: the admitted identity, the request id and the session `guard` validated.
pub struct Caller<'a> {
    pub app: &'a ApiState,
    pub identity: &'a ApiIdentity,
    pub request_id: &'a str,
    pub session: Option<&'a Authenticated>,
}


pub fn refuse(response: Response) -> Refused {
    Box::new(response)
}


/// A body over the route's limit is the 413, any other refusal (syntax, unknown field, wrong type, content type) the 400.
pub fn body_failure(rejection: &JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge
    } else {
        ApiError::BadRequest
    }
}


/// An unknown id and another tenant's are the same `NotFound`; a refused transition and a moved version are the one 409.
pub fn change_failure(error: &ReadError) -> Response {
    match error {
        ReadError::Store(StoreError::NotFound) => not_found(),
        ReadError::Store(StoreError::Conflict | StoreError::Lifecycle(_)) => conflict(),
        other => error_response(&read_failure(other)),
    }
}


/// A handler reached without a session never writes; the actor is the session user.
pub fn admit<'a>(caller: &Caller<'a>) -> Result<(TenantScope, &'a str), Refused> {
    match caller.session {
        None => {
            tracing::warn!("on-call write reached without a session");
            Err(refuse(error_response(&ApiError::Internal)))
        }
        Some(session) => scope_of(caller.identity)
            .map(|scope| (scope, session.user.as_str()))
            .map_err(|error| refuse(error_response(&error))),
    }
}


/// The body is checked first, then the id: a malformed one is the read route's 404, with no store call.
pub async fn change_checked(
    scope: TenantScope,
    backend: &OncallBackend,
    id: Result<String, PathRejection>,
    body: Result<ChangeRequest, ApiError>,
    event: Event,
) -> Result<Alert, Refused> {
    body.map_err(|error| refuse(error_response(&error)))?;
    let number = id.ok().as_deref().and_then(parse_id).ok_or_else(|| refuse(not_found()))?;
    (backend.apply)(scope, number, event, (backend.clock)())
        .await
        .map_err(|error| refuse(change_failure(&error)))
}


/// The committed alert as the read route shows it; a stored value that cannot be shown is the fixed 422 after the change.
pub fn changed_view(alert: &Alert) -> Response {
    match alert_view(alert) {
        Ok(view) => Json(view).into_response(),
        Err(error) => {
            let category = failure_category(&error);
            tracing::warn!(category, "on-call changed alert cannot be shown");
            unreadable()
        }
    }
}


/// One record per committed change: actor, alert id, no parameter. The write is done when the append fails, so the caller is told.
pub fn changed(caller: &Caller<'_>, actor: &str, action: &str, alert: &Alert) -> Response {
    let entry = NewEntry {
        timestamp: (caller.app.clock)(),
        actor: Actor {
            kind: ActorKind::User,
            id: actor.to_owned(),
        },
        tenant: caller.identity.tenant.clone(),
        module: caller.identity.module.clone(),
        action: action.to_owned(),
        target: alert.id.to_string(),
        outcome: Outcome::Success,
        request_id: caller.request_id.to_owned(),
        justification: None,
        parameters: ParameterMap::new(),
    };
    match append_declared(&caller.app.audit, entry, &[]) {
        Ok(_record) => changed_view(alert),
        Err(error) => {
            tracing::error!(%error, "on-call write audit failed");
            error_response(&ApiError::Internal)
        }
    }
}


pub async fn change_flow(
    caller: &Caller<'_>,
    backend: &OncallBackend,
    id: Result<String, PathRejection>,
    body: Result<ChangeRequest, ApiError>,
    event: Event,
) -> Response {
    let action = if event == Event::Resolve { ACTION_RESOLVE } else { ACTION_ACKNOWLEDGE };
    match admit(caller) {
        Err(refused) => *refused,
        Ok((scope, actor)) => change_checked(scope, backend, id, body, event)
            .await
            .map_or_else(|refused| *refused, |alert| changed(caller, actor, action, &alert)),
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


#[utoipa::path(
    post,
    path = "/oncall/alerts/{id}/acknowledge",
    params(("id" = String, Path, description = "Alert id, digits only")),
    request_body = ChangeRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The alert in its new state", body = AlertView),
        (status = 400, description = "Malformed body, unknown field or query", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such alert for this tenant", body = ErrorBody),
        (status = 409, description = "The alert changed or cannot take this action", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn acknowledge_endpoint(
    State(app): State<SharedState>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(request_id): Extension<RequestId>,
    Extension(backend): Extension<OncallBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ChangeRequest>, JsonRejection>,
) -> Response {
    let caller = Caller {
        app: &app,
        identity: &identity,
        request_id: &request_id.0,
        session: session.as_ref().map(|found| &found.0),
    };
    change_flow(
        &caller,
        &backend,
        id.map(|found| found.0),
        body.map(|found| found.0).map_err(|rejection| body_failure(&rejection)),
        Event::Acknowledge,
    )
    .await
}


#[utoipa::path(
    post,
    path = "/oncall/alerts/{id}/resolve",
    params(("id" = String, Path, description = "Alert id, digits only")),
    request_body = ChangeRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The alert in its new state", body = AlertView),
        (status = 400, description = "Malformed body, unknown field or query", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such alert for this tenant", body = ErrorBody),
        (status = 409, description = "The alert changed or cannot take this action", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn resolve_endpoint(
    State(app): State<SharedState>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(request_id): Extension<RequestId>,
    Extension(backend): Extension<OncallBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ChangeRequest>, JsonRejection>,
) -> Response {
    let caller = Caller {
        app: &app,
        identity: &identity,
        request_id: &request_id.0,
        session: session.as_ref().map(|found| &found.0),
    };
    change_flow(
        &caller,
        &backend,
        id.map(|found| found.0),
        body.map(|found| found.0).map_err(|rejection| body_failure(&rejection)),
        Event::Resolve,
    )
    .await
}


/// No write route takes a query string: a `tenant` parameter, or any other, is a 400 before the handler.
pub async fn refuse_query(request: Request, next: Next) -> Response {
    if request.uri().query().is_some() {
        error_response(&ApiError::BadRequest)
    } else {
        next.run(request).await
    }
}


pub fn oncall_router(backend: OncallBackend) -> Router<SharedState> {
    let writes = Router::new()
        .route(ACKNOWLEDGE_PATH, post(acknowledge_endpoint))
        .route(RESOLVE_PATH, post(resolve_endpoint))
        .layer(from_fn(refuse_query))
        .layer(DefaultBodyLimit::max(CHANGE_BODY_LIMIT));
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .merge(writes)
        .layer(Extension(backend))
}


/// `oncall.read` for the two reads, `oncall.acknowledge` for the two writes, deny by default for the rest.
pub fn oncall_access() -> AccessTable {
    let reads = [LIST_PATH, GET_PATH].map(|path| (route_key("GET", path), PERMISSION_ONCALL_READ));
    let writes = [ACKNOWLEDGE_PATH, RESOLVE_PATH].map(|path| (route_key("POST", path), PERMISSION_ONCALL_ACKNOWLEDGE));
    reads
        .into_iter()
        .chain(writes)
        .map(|(key, permission)| {
            (
                key,
                Rule {
                    requirement: Requirement::Permission(permission.to_owned()),
                    sensitive: false,
                },
            )
        })
        .collect()
}


pub fn oncall_document() -> OpenApiDocument {
    OncallDoc::openapi()
}
