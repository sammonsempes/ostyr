use crate::error::StoreError;
use crate::id::is_alert_id;
use crate::model::{
    Alert, AlertDetail, AlertDetailView, AlertListView, AlertView, Backend, Cursor, ListQuery, NoQuery, Page, Summary, Triage, TriageChange,
    TriageRequest, TriageStatus, TriageView,
};
use crate::store::{check_optional, format_cursor, parse_cursor, MAX_NOTE_CHARS, MAX_PAGE_SIZE};
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, Authenticated, ErrorBody, ErrorDetail, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::{PERMISSION_ALERTS_READ, PERMISSION_ALERTS_TRIAGE};
use core_pg::error::PgError;
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


pub const TRIAGE_PATH: &str = "/alerts/{id}/triage";


pub const UTF8_BYTES_PER_CHAR: usize = 4;


pub const BODY_OVERHEAD_BYTES: usize = 256;


/// The note cap in raw UTF-8 plus the other fields; core-api's own cap (16 384) applies first to anything larger.
pub const TRIAGE_BODY_LIMIT: usize = MAX_NOTE_CHARS * UTF8_BYTES_PER_CHAR + BODY_OVERHEAD_BYTES;


pub const BAD_REQUEST_CODE: &str = "bad_request";


pub const CHANGED_CODE: &str = "triage_changed";


pub const UNAVAILABLE_CODE: &str = "unavailable";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such alert";


#[derive(OpenApi)]
#[openapi(
    paths(list_endpoint, get_endpoint, triage_endpoint),
    components(schemas(AlertView, AlertListView, AlertDetailView, TriageView, TriageRequest, TriageStatus))
)]
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


/// A database that cannot be reached in time is the 503 with a fixed code, never the database text.
pub fn unavailable() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: UNAVAILABLE_CODE.to_owned(),
            message: "the database is unavailable, retry later".to_owned(),
        },
    };
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}


pub fn store_reply(error: &StoreError) -> Result<Response, ApiError> {
    match error {
        StoreError::Pg(PgError::ConnectTimeout { .. }) => Ok(unavailable()),
        other => Err(store_failure(other)),
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
    match (backend.list)(scope, page).await {
        Ok(found) => Ok(Json(list_view(&found).map_err(|error| store_failure(&error))?).into_response()),
        Err(error) => store_reply(&error),
    }
}


/// A malformed id, or one the extractor refuses (not UTF-8), cannot name a stored alert: it is answered like a missing one, without a store call.
pub async fn get_flow(identity: &ApiIdentity, backend: &Backend, id: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let found = match id {
        Ok(text) => (backend.get)(scope, text).await,
        Err(_rejection) => Err(StoreError::BadId),
    };
    match found {
        Err(StoreError::BadId) | Ok(None) => Ok(not_found()),
        Err(error) => store_reply(&error),
        Ok(Some(detail)) => {
            let view = detail_view(&detail).map_err(|error| store_failure(&error))?;
            Ok(Json(view).into_response())
        }
    }
}


pub fn triage_view(triage: &Triage) -> Result<TriageView, StoreError> {
    Ok(TriageView {
        status: triage.status.to_string(),
        actor: triage.actor.clone(),
        note: triage.note.clone(),
        updated_at: created_time(triage.updated_at)?,
        version: triage.version,
    })
}


pub fn detail_view(detail: &AlertDetail) -> Result<AlertDetailView, StoreError> {
    Ok(AlertDetailView {
        alert: view_of(&detail.alert)?,
        triage: detail.triage.as_ref().map(triage_view).transpose()?,
    })
}


/// Names the field, never its value.
pub fn bad_field(field: &str, reason: &str) -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: BAD_REQUEST_CODE.to_owned(),
            message: format!("field `{field}` {reason}"),
        },
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}


/// A body over the route's limit is the 413, any other refusal (syntax, unknown field, wrong type or status, content type) the 400.
pub fn body_failure(rejection: &JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge
    } else {
        ApiError::BadRequest
    }
}


/// The user of the session `guard` validated; a request that reached a handler without one is never written anonymously.
pub fn actor_of(session: Option<&Authenticated>) -> Result<String, ApiError> {
    session.map(|found| found.user.clone()).ok_or_else(|| {
        tracing::warn!("alerts triage reached without a session");
        ApiError::Internal
    })
}


/// A moved version or a second first triage is the 409; another tenant's alert is the 404 of the read route.
pub fn triage_failure(error: &StoreError) -> Result<Response, ApiError> {
    match error {
        StoreError::NotFound | StoreError::BadId => Ok(not_found()),
        StoreError::Conflict => {
            let body = ErrorBody {
                error: ErrorDetail {
                    code: CHANGED_CODE.to_owned(),
                    message: "the triage changed, read the alert again".to_owned(),
                },
            };
            Ok((StatusCode::CONFLICT, Json(body)).into_response())
        }
        other => store_reply(other),
    }
}


/// The refusal for a body field, before any store call: a version below 1 or a note that is empty, too long or holds NUL.
pub fn request_fault(request: &TriageRequest) -> Option<Response> {
    if request.version.is_some_and(|read| read < 1) {
        Some(bad_field("version", "must be at least 1"))
    } else {
        check_optional("note", request.note.as_deref(), MAX_NOTE_CHARS)
            .err()
            .map(|_refused| bad_field("note", "is empty, too long or holds a NUL character"))
    }
}


pub async fn triage_flow(
    identity: &ApiIdentity,
    session: Option<&Authenticated>,
    backend: &Backend,
    id: Result<String, PathRejection>,
    body: Result<TriageRequest, ApiError>,
) -> Result<Response, ApiError> {
    match body {
        Err(ApiError::BadRequest) => Ok(bad_field(
            "body",
            "must be a JSON object with `status` (acknowledged or closed), optional `note` and `version`, and no other field",
        )),
        Err(other) => Err(other),
        Ok(request) => {
            let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
            let actor = actor_of(session)?;
            let checked = id.ok().filter(|text| is_alert_id(text));
            match (checked, request_fault(&request)) {
                (None, _) => Ok(not_found()),
                (Some(_), Some(refusal)) => Ok(refusal),
                (Some(text), None) => {
                    let change = TriageChange {
                        status: request.status,
                        actor,
                        note: request.note,
                        now: (backend.clock)(),
                    };
                    let done = (backend.triage)(scope, text, change, request.version).await;
                    match done {
                        Ok(triage) => Ok(Json(triage_view(&triage).map_err(|error| store_failure(&error))?).into_response()),
                        Err(error) => triage_failure(&error),
                    }
                }
            }
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
        (status = 429, description = "Too many requests", body = ErrorBody),
        (status = 503, description = "Database unavailable", body = ErrorBody)
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
        (status = 200, description = "The alert with its triage", body = AlertDetailView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such alert for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<Backend>,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    reply(get_flow(&identity, &backend, id.map(|found| found.0)).await)
}


#[utoipa::path(
    post,
    path = "/alerts/{id}/triage",
    params(("id" = String, Path, description = "Alert id, 64 lowercase hexadecimal characters")),
    request_body = TriageRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The triage as stored", body = TriageView),
        (status = 400, description = "Malformed body, unknown field or status, bad version, or a note that is empty, too long or holds NUL", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such alert for this tenant", body = ErrorBody),
        (status = 409, description = "The triage changed or already exists", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn triage_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<Backend>,
    session: Option<Extension<Authenticated>>,
    query: Result<Query<NoQuery>, QueryRejection>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<TriageRequest>, JsonRejection>,
) -> Response {
    let parsed = body.map(|found| found.0).map_err(|rejection| body_failure(&rejection));
    let outcome = match query {
        Err(_rejection) => Err(ApiError::BadRequest),
        Ok(_none) => {
            triage_flow(
                &identity,
                session.as_ref().map(|found| &found.0),
                &backend,
                id.map(|found| found.0),
                parsed,
            )
            .await
        }
    };
    reply(outcome)
}


pub fn alerts_router(backend: Backend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .route(TRIAGE_PATH, post(triage_endpoint).layer(DefaultBodyLimit::max(TRIAGE_BODY_LIMIT)))
        .layer(Extension(backend))
}


pub fn alerts_access() -> AccessTable {
    let reads = [LIST_PATH, GET_PATH].map(|path| (route_key("GET", path), PERMISSION_ALERTS_READ));
    let writes = [(route_key("POST", TRIAGE_PATH), PERMISSION_ALERTS_TRIAGE)];
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


pub fn alerts_document() -> OpenApiDocument {
    AlertsDoc::openapi()
}
