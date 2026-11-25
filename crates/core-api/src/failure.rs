use crate::model::{ApiError, ErrorBody, ErrorDetail};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::Json;
use core_auth::error::{AuthError, OidcDenial};


/// `Retry-After` of a refused sender decode: one second.
pub const SENDER_RETRY_SECONDS: &str = "1";


pub fn error_parts(error: &ApiError) -> (StatusCode, &'static str, &'static str) {
    match error {
        ApiError::BadRequest => (StatusCode::BAD_REQUEST, "bad_request", "the request is malformed"),
        ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "authentication is required"),
        ApiError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials", "invalid credentials"),
        ApiError::MfaRequired => (StatusCode::UNAUTHORIZED, "mfa_required", "a second factor is required"),
        ApiError::MfaInvalid => (StatusCode::UNAUTHORIZED, "mfa_invalid", "the second factor is invalid"),
        ApiError::MfaEnrolmentRequired => (StatusCode::FORBIDDEN, "mfa_enrolment_required", "a second factor must be enrolled first"),
        ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "the operation is not permitted"),
        ApiError::RequestTimeout => (
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "the request body was not received in time",
        ),
        ApiError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "the request body is too large"),
        ApiError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", "too many requests, retry later"),
        ApiError::Busy => (StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy, retry later"),
        ApiError::UnsupportedMediaType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "the content type or encoding is not supported",
        ),
        ApiError::SenderBusy => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", "too many requests, retry later"),
        ApiError::BadGateway => (StatusCode::BAD_GATEWAY, "bad_gateway", "the identity provider is unavailable"),
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
    let retry = matches!(error, ApiError::SenderBusy).then_some((RETRY_AFTER, HeaderValue::from_static(SENDER_RETRY_SECONDS)));
    (status, AppendHeaders(retry), Json(body)).into_response()
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
        AuthError::Locked { .. } | AuthError::Oidc(OidcDenial::TooManyPending) => ApiError::TooManyRequests,
        AuthError::Oidc(OidcDenial::Provider) => ApiError::BadGateway,
        other => {
            tracing::warn!(error = %other, "internal authentication failure");
            ApiError::Internal
        }
    }
}
