use crate::api_model::{AtQuery, DhcpBackend, LeaseView, LookupView, MacQuery};
use crate::error::HistoryError;
use crate::history::{in_range, LeaseInterval, LookupResult};
use crate::row::normalise_mac;
use axum::extract::rejection::QueryRejection;
use axum::extract::Query;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::PERMISSION_CMDB_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const AT_PATH: &str = "/dhcp/leases/at";


pub const MAC_PATH: &str = "/dhcp/leases/mac";


pub const MAX_WINDOW_DAYS: i64 = 400;


pub const SECONDS_PER_DAY: i64 = 86_400;


pub const MAX_WINDOW_SECONDS: i64 = MAX_WINDOW_DAYS * SECONDS_PER_DAY;


pub const MAX_TIME_CHARS: usize = 20;


#[derive(OpenApi)]
#[openapi(paths(at_endpoint, mac_endpoint), components(schemas(LeaseView, LookupView)))]
pub struct DhcpDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, HistoryError> {
    Ok(tenant_scope(&identity.tenant)?)
}


/// Digits with an optional leading `-`, then the store's range; nothing else (no `+`, no spaces, no Unicode digits).
pub fn parse_time(text: Option<&str>) -> Result<i64, HistoryError> {
    let digits = text.ok_or(HistoryError::TimeRange)?;
    let unsigned = digits.strip_prefix('-').unwrap_or(digits);
    let plain = !unsigned.is_empty() && digits.len() <= MAX_TIME_CHARS && unsigned.bytes().all(|byte| byte.is_ascii_digit());
    plain
        .then(|| digits.parse::<i64>().ok())
        .flatten()
        .filter(|seconds| in_range(*seconds))
        .ok_or(HistoryError::TimeRange)
}


pub fn parse_address(text: Option<&str>) -> Result<IpAddr, HistoryError> {
    text.and_then(|found| IpAddr::from_str(found).ok()).ok_or(HistoryError::Address)
}


pub fn parse_mac(text: Option<&str>) -> Result<String, HistoryError> {
    text.and_then(normalise_mac).ok_or(HistoryError::Mac)
}


pub fn parse_window(from: Option<&str>, to: Option<&str>) -> Result<(i64, i64), HistoryError> {
    let start = parse_time(from)?;
    let end = parse_time(to)?;
    (start <= end && end - start <= MAX_WINDOW_SECONDS)
        .then_some((start, end))
        .ok_or(HistoryError::Window)
}


/// A bad parameter is the caller's 400 and a full pool is a 429; anything else is a generic 500 and logs a fixed text, never the store error.
pub fn store_failure(error: &HistoryError) -> ApiError {
    match error {
        HistoryError::Address | HistoryError::Mac | HistoryError::TimeRange | HistoryError::Window => ApiError::BadRequest,
        HistoryError::Busy => ApiError::TooManyRequests,
        HistoryError::Pg(_) | HistoryError::Settings | HistoryError::Answer => {
            tracing::warn!("dhcp lease lookup failed");
            ApiError::Internal
        }
    }
}


fn time_text(seconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|moment| moment.format(&Rfc3339).ok())
}


fn lease_view(interval: &LeaseInterval) -> Option<LeaseView> {
    Some(LeaseView {
        address: interval.address.clone(),
        mac: interval.mac.clone(),
        hostname: interval.hostname.clone(),
        starts: time_text(interval.starts)?,
        ends: time_text(interval.ends)?,
        action: interval.action.clone(),
        subnet_id: interval.subnet_id,
    })
}


/// An interval whose times cannot be written back as RFC 3339 is skipped and counted with the rows the store could not read.
pub fn lookup_view(found: &LookupResult) -> LookupView {
    let intervals: Vec<LeaseView> = found.intervals.iter().filter_map(lease_view).collect();
    LookupView {
        skipped: found.skipped + found.intervals.len() - intervals.len(),
        intervals,
        truncated: found.truncated,
    }
}


pub async fn at_flow(identity: &ApiIdentity, backend: &DhcpBackend, query: Result<AtQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let address = parse_address(parsed.address.as_deref()).map_err(|error| store_failure(&error))?;
    let at = parse_time(parsed.at.as_deref()).map_err(|error| store_failure(&error))?;
    let found = (backend.at)(scope, address.to_string(), at)
        .await
        .map_err(|error| store_failure(&error))?;
    Ok(Json(lookup_view(&found)).into_response())
}


pub async fn mac_flow(identity: &ApiIdentity, backend: &DhcpBackend, query: Result<MacQuery, ApiError>) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let mac = parse_mac(parsed.mac.as_deref()).map_err(|error| store_failure(&error))?;
    let (from, to) = parse_window(parsed.from.as_deref(), parsed.to.as_deref()).map_err(|error| store_failure(&error))?;
    let found = (backend.by_mac)(scope, mac, from, to).await.map_err(|error| store_failure(&error))?;
    Ok(Json(lookup_view(&found)).into_response())
}


#[utoipa::path(
    get,
    path = "/dhcp/leases/at",
    params(AtQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The lease intervals of the address holding at that time, newest first, at most 100", body = LookupView),
        (status = 400, description = "Malformed address or time", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn at_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<DhcpBackend>,
    query: Result<Query<AtQuery>, QueryRejection>,
) -> Response {
    reply(at_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/dhcp/leases/mac",
    params(MacQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The lease intervals of the MAC overlapping the window, newest first, at most 100", body = LookupView),
        (status = 400, description = "Malformed MAC, time or window", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn mac_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<DhcpBackend>,
    query: Result<Query<MacQuery>, QueryRejection>,
) -> Response {
    reply(mac_flow(&identity, &backend, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


pub fn dhcp_router(backend: DhcpBackend) -> Router<SharedState> {
    Router::new()
        .route(AT_PATH, get(at_endpoint))
        .route(MAC_PATH, get(mac_endpoint))
        .layer(Extension(backend))
}


pub fn dhcp_access() -> AccessTable {
    [AT_PATH, MAC_PATH]
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


pub fn dhcp_document() -> OpenApiDocument {
    DhcpDoc::openapi()
}
