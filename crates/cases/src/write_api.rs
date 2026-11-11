use crate::api::{checked_id, not_found, scope_of, store_failure};
use crate::api_model::{ActionName, ActionRequest, CasesBackend, CommentRequest};
use crate::error::{CaseStoreError, TransitionError};
use crate::model::Comment;
use crate::store::{check_text, MAX_COMMENT_CHARS};
use crate::stored::CaseDetail;
use crate::transition::CaseAction;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, Authenticated, ErrorBody, ErrorDetail};
use std::sync::Arc;


pub const ACTIONS_PATH: &str = "/cases/{id}/actions";


pub const COMMENTS_PATH: &str = "/cases/{id}/comments";


pub const ACTION_BODY_LIMIT: usize = 4_096;


/// A JSON string spends at most 12 bytes on one character (a surrogate pair written as two `\uXXXX` escapes).
pub const JSON_BYTES_PER_CHAR: usize = 12;


pub const JSON_OVERHEAD_BYTES: usize = 256;


pub const COMMENT_BODY_LIMIT: usize = MAX_COMMENT_CHARS * JSON_BYTES_PER_CHAR + JSON_OVERHEAD_BYTES;


pub const TEXT_FIELD: &str = "text";


pub const BAD_REQUEST_CODE: &str = "bad_request";


pub const RESOLUTION_REQUIRED_CODE: &str = "resolution_required";


pub const NOT_ALLOWED_CODE: &str = "transition_not_allowed";


pub const CHANGED_CODE: &str = "case_changed";


pub const FULL_CODE: &str = "full";


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


pub fn conflict(code: &str, message: &str) -> Response {
    error_reply(StatusCode::CONFLICT, code, message.to_owned())
}


/// A body over the route's limit is the 413, any other refusal (syntax, unknown field, wrong type, content type) the 400.
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
        tracing::warn!("cases write reached without a session");
        ApiError::Internal
    })
}


/// A resolution goes with `close` only.
pub fn case_action(request: &ActionRequest) -> Option<CaseAction> {
    match (request.action, request.resolution) {
        (ActionName::Close, resolution) => Some(CaseAction::Close(resolution)),
        (ActionName::Start, None) => Some(CaseAction::Start),
        (ActionName::Reopen, None) => Some(CaseAction::Reopen),
        (ActionName::Start | ActionName::Reopen, Some(_)) => None,
    }
}


/// Refused transitions, a moved version and a full list are 409s with fixed codes; the rest is `store_failure`.
pub fn write_failure(error: &CaseStoreError) -> Result<Response, ApiError> {
    match error {
        CaseStoreError::NotFound => Ok(not_found()),
        CaseStoreError::Transition(TransitionError::ResolutionRequired) => {
            Ok(conflict(RESOLUTION_REQUIRED_CODE, "closing a case needs a resolution"))
        }
        CaseStoreError::Transition(TransitionError::NotAllowed { .. }) => {
            Ok(conflict(NOT_ALLOWED_CODE, "the action is not allowed in the status of the case"))
        }
        CaseStoreError::Conflict => Ok(conflict(CHANGED_CODE, "the case changed, read it again")),
        CaseStoreError::Full { what, limit } => Ok(conflict(FULL_CODE, &format!("`{what}` is full at {limit}"))),
        other => Err(store_failure(other)),
    }
}


pub async fn action_flow(
    identity: &ApiIdentity,
    session: Option<&Authenticated>,
    backend: &CasesBackend,
    id: Result<String, PathRejection>,
    body: Result<ActionRequest, ApiError>,
) -> Result<Response, ApiError> {
    let request = body?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let actor = actor_of(session)?;
    match (checked_id(id), case_action(&request)) {
        (None, _) => Ok(not_found()),
        (Some(_), None) => Ok(bad_field("resolution", "is only allowed with `close`")),
        (Some(text), Some(action)) => {
            let now = (backend.clock)();
            let done = (backend.act)(scope, text, action, actor, now).await;
            done.map_or_else(|error| write_failure(&error), |detail: CaseDetail| Ok(Json(detail).into_response()))
        }
    }
}


pub async fn comment_flow(
    identity: &ApiIdentity,
    session: Option<&Authenticated>,
    backend: &CasesBackend,
    id: Result<String, PathRejection>,
    body: Result<CommentRequest, ApiError>,
) -> Result<Response, ApiError> {
    let request = body?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let actor = actor_of(session)?;
    let checked_text = check_text(TEXT_FIELD, &request.text, MAX_COMMENT_CHARS);
    match (checked_id(id), checked_text) {
        (None, _) => Ok(not_found()),
        (Some(_), Err(_)) => Ok(bad_field(TEXT_FIELD, "is empty, too long or holds a NUL character")),
        (Some(text), Ok(())) => {
            let comment = Comment {
                author: actor,
                at: (backend.clock)(),
                text: request.text,
            };
            let done = (backend.comment)(scope, text, comment.clone()).await;
            done.map_or_else(
                |error| write_failure(&error),
                |()| Ok((StatusCode::CREATED, Json(comment)).into_response()),
            )
        }
    }
}


#[utoipa::path(
    post,
    path = "/cases/{id}/actions",
    params(("id" = String, Path, description = "Case id")),
    request_body = ActionRequest,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The case after the action", body = CaseDetail),
        (status = 400, description = "Malformed body, unknown field, or a resolution with another action than close", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such case for this tenant", body = ErrorBody),
        (status = 409, description = "Action refused for the status, resolution missing, or the case changed", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn action_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ActionRequest>, JsonRejection>,
) -> Response {
    let parsed = body.map(|found| found.0).map_err(|rejection| body_failure(&rejection));
    reply(
        action_flow(
            &identity,
            session.as_ref().map(|found| &found.0),
            &backend,
            id.map(|found| found.0),
            parsed,
        )
        .await,
    )
}


#[utoipa::path(
    post,
    path = "/cases/{id}/comments",
    params(("id" = String, Path, description = "Case id")),
    request_body = CommentRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The comment as stored", body = Comment),
        (status = 400, description = "Malformed body, unknown field, or a text that is empty, too long or holds NUL", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such case for this tenant", body = ErrorBody),
        (status = 409, description = "The case holds the maximum number of comments", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn comment_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<CommentRequest>, JsonRejection>,
) -> Response {
    let parsed = body.map(|found| found.0).map_err(|rejection| body_failure(&rejection));
    reply(
        comment_flow(
            &identity,
            session.as_ref().map(|found| &found.0),
            &backend,
            id.map(|found| found.0),
            parsed,
        )
        .await,
    )
}
