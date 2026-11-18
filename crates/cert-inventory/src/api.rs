use crate::alerting::{is_fingerprint, NEAR_DAYS};
use crate::api_model::{CertBackend, CertDetailView, CertListView, CertView, ListQuery, SightingView};
use crate::error::InventoryStoreError;
use crate::expiry::expiry_state;
use crate::model::{CertDetail, CertFilter, CertPage, ExpiryState, ListRequest, Sighting, StoredCert};
use crate::store::{key_type_text, kind_text, time_in_range, MAX_PAGE};
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
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: usize = 50;


/// The longest canonical cursor: a 20 character signed number, the separator and 64 hexadecimal characters.
pub const MAX_CURSOR_CHARS: usize = 85;


pub const LIST_PATH: &str = "/certificates";


pub const GET_PATH: &str = "/certificates/{fingerprint}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such certificate";


#[derive(OpenApi)]
#[openapi(
    paths(list_endpoint, get_endpoint),
    components(schemas(CertView, CertListView, CertDetailView, SightingView))
)]
pub struct CertDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, InventoryStoreError> {
    Ok(tenant_scope(&identity.tenant)?)
}


pub fn parse_limit(text: Option<&str>) -> Result<usize, InventoryStoreError> {
    text.map_or(Ok(DEFAULT_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE).contains(size))
            .ok_or(InventoryStoreError::BadPageSize { limit: MAX_PAGE })
    })
}


/// Digits with an optional leading minus, inside years 0 to 9999.
pub fn parse_expiring_before(text: &str) -> Result<i64, InventoryStoreError> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse::<i64>().ok())
        .flatten()
        .filter(|seconds| time_in_range(*seconds))
        .ok_or(InventoryStoreError::BadExpiringBefore)
}


pub fn request_of(query: &ListQuery) -> Result<ListRequest, InventoryStoreError> {
    let cursor = query.cursor.clone();
    if cursor.as_ref().is_some_and(|text| text.len() > MAX_CURSOR_CHARS) {
        Err(InventoryStoreError::BadCursor)
    } else {
        Ok(ListRequest {
            filter: CertFilter {
                expiring_before: query.expiring_before.as_deref().map(parse_expiring_before).transpose()?,
            },
            cursor,
            limit: parse_limit(query.limit.as_deref())?,
        })
    }
}


pub fn failure_category(error: &InventoryStoreError) -> &'static str {
    match error {
        InventoryStoreError::Pg(_) | InventoryStoreError::Lease(_) => "database",
        InventoryStoreError::BadRow { .. } | InventoryStoreError::Unrepresentable => "stored_value",
        _other => "request",
    }
}


/// A bad cursor, limit or time is the caller's 400; anything else is logged by category only and answered with a generic error.
pub fn store_failure(error: &InventoryStoreError) -> ApiError {
    match error {
        InventoryStoreError::BadCursor
        | InventoryStoreError::BadPageSize { .. }
        | InventoryStoreError::BadExpiringBefore
        | InventoryStoreError::BadFingerprint => ApiError::BadRequest,
        InventoryStoreError::Lease(alerts::error::StoreError::Busy) => ApiError::TooManyRequests,
        other => {
            let category = failure_category(other);
            tracing::warn!(category, "certificate store failure");
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


/// RFC 3339 UTC text of a stored time; a time that years 0 to 9999 cannot hold is refused.
pub fn rfc3339(seconds: i64) -> Result<String, InventoryStoreError> {
    time_in_range(seconds)
        .then(|| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .flatten()
        .and_then(|moment| moment.format(&Rfc3339).ok())
        .ok_or(InventoryStoreError::Unrepresentable)
}


pub fn expiry_text(state: ExpiryState) -> &'static str {
    match state {
        ExpiryState::Expired => "expired",
        ExpiryState::Crossed { .. } => "near",
        ExpiryState::Valid => "ok",
    }
}


pub fn cert_view(stored: &StoredCert, now: i64) -> Result<CertView, InventoryStoreError> {
    let record = &stored.record;
    Ok(CertView {
        fingerprint: record.fingerprint_sha256.clone(),
        subject: record.subject.clone(),
        issuer: record.issuer.clone(),
        dns_names: record.dns_names.clone(),
        not_before: rfc3339(record.not_before)?,
        not_after: rfc3339(record.not_after)?,
        key_type: key_type_text(record.key_type).to_owned(),
        key_bits: record.key_bits,
        self_signed: record.self_signed,
        first_seen: rfc3339(stored.first_seen)?,
        last_seen: rfc3339(stored.last_seen)?,
        expiry: expiry_text(expiry_state(record, now, &[NEAR_DAYS])).to_owned(),
    })
}


pub fn sighting_view(sighting: &Sighting) -> Result<SightingView, InventoryStoreError> {
    Ok(SightingView {
        kind: kind_text(sighting.kind).to_owned(),
        reference: sighting.reference.clone(),
        last_seen: rfc3339(sighting.last_seen)?,
    })
}


/// A row whose times cannot be written is left out and counted in `skipped`, like a row the store refused.
pub fn list_view(page: &CertPage, now: i64) -> CertListView {
    let (shown, failed): (Vec<_>, Vec<_>) = page.certs.iter().map(|stored| cert_view(stored, now)).partition(Result::is_ok);
    let unwritable = failed.len();
    if unwritable > 0 {
        tracing::warn!(unwritable, "stored certificate times refused and skipped");
    }
    CertListView {
        items: shown.into_iter().flatten().collect(),
        skipped: page.skipped + unwritable,
        next_cursor: page.next_cursor.clone(),
    }
}


pub fn detail_view(detail: &CertDetail, now: i64) -> Result<CertDetailView, InventoryStoreError> {
    let (shown, failed): (Vec<_>, Vec<_>) = detail.sightings.sightings.iter().map(sighting_view).partition(Result::is_ok);
    let unwritable = failed.len();
    if unwritable > 0 {
        tracing::warn!(unwritable, "stored sighting times refused and skipped");
    }
    Ok(CertDetailView {
        cert: cert_view(&detail.cert, now)?,
        sightings: shown.into_iter().flatten().collect(),
        sightings_skipped: detail.sightings.skipped + unwritable,
        sightings_truncated: detail.sightings.truncated,
    })
}


pub async fn list_flow(identity: &ApiIdentity, backend: &CertBackend, query: Result<ListQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let request = request_of(&parsed).map_err(|error| store_failure(&error))?;
    let now = (backend.clock)();
    let page = (backend.list)(scope, request).await.map_err(|error| store_failure(&error))?;
    Ok(Json(list_view(&page, now)).into_response())
}


/// A malformed fingerprint, or one the extractor refuses, is answered like a missing one, without a store call and without echoing it.
pub async fn get_flow(identity: &ApiIdentity, backend: &CertBackend, fingerprint: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let checked = fingerprint.ok().filter(|text| is_fingerprint(text));
    match checked {
        None => Ok(not_found()),
        Some(text) => {
            let now = (backend.clock)();
            match (backend.get)(scope, text).await.map_err(|error| store_failure(&error))? {
                None => Ok(not_found()),
                Some(detail) => {
                    let view = detail_view(&detail, now).map_err(|error| store_failure(&error))?;
                    Ok(Json(view).into_response())
                }
            }
        }
    }
}


#[utoipa::path(
    get,
    path = "/certificates",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of certificates ordered by expiry", body = CertListView),
        (status = 400, description = "Malformed cursor, limit or time", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CertBackend>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(list_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/certificates/{fingerprint}",
    params(("fingerprint" = String, Path, description = "SHA-256 fingerprint, 64 lowercase hexadecimal characters")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The certificate with its sightings", body = CertDetailView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such certificate for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CertBackend>,
    fingerprint: Result<Path<String>, PathRejection>,
) -> Response {
    reply(get_flow(&identity, &backend, fingerprint.map(|found| found.0)).await)
}


pub fn certificates_router(backend: CertBackend) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(backend))
}


pub fn certificates_access() -> AccessTable {
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


pub fn certificates_document() -> OpenApiDocument {
    CertDoc::openapi()
}
