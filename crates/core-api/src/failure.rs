use crate::model::{ApiError, ErrorBody, ErrorDetail};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use core_auth::error::AuthError;


pub fn error_parts(error: &ApiError) -> (StatusCode, &'static str, &'static str) {
    match error {
        ApiError::BadRequest => (StatusCode::BAD_REQUEST, "bad_request", "the request is malformed"),
        ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "authentication is required"),
        ApiError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials", "invalid credentials"),
        ApiError::MfaRequired => (StatusCode::UNAUTHORIZED, "mfa_required", "a second factor is required"),
        ApiError::MfaInvalid => (StatusCode::UNAUTHORIZED, "mfa_invalid", "the second factor is invalid"),
        ApiError::MfaEnrolmentRequired => (StatusCode::FORBIDDEN, "mfa_enrolment_required", "a second factor must be enrolled first"),
        ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "the operation is not permitted"),
        ApiError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "the request body is too large"),
        ApiError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", "too many requests, retry later"),
        ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "the request could not be processed"),
    }
}


pub fn error_response(error: &ApiError) -> Response {
    let (status, code, message) = error_parts(error);
    let body = ErrorBody {
        error: ErrorDetail {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    };
    (status, Json(body)).into_response()
}


pub fn reply(result: Result<Response, ApiError>) -> Response {
    result.unwrap_or_else(|error| error_response(&error))
}


pub fn auth_failure(error: &AuthError) -> ApiError {
    match error {
        AuthError::InvalidCredentials => ApiError::InvalidCredentials,
        AuthError::SessionInvalid => ApiError::Unauthorized,
        AuthError::PermissionDenied => ApiError::Forbidden,
        AuthError::MfaRequired => ApiError::MfaRequired,
        AuthError::MfaInvalid => ApiError::MfaInvalid,
        AuthError::MfaEnrolmentRequired => ApiError::MfaEnrolmentRequired,
        AuthError::Locked { .. } => ApiError::TooManyRequests,
        other => {
            tracing::warn!(error = %other, "internal authentication failure");
            ApiError::Internal
        }
    }
}
