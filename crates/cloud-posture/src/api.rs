use crate::api_model::{FindingView, PostureBackend, PostureView, ReadQuery, RunView};
use crate::error::StoreError;
use crate::model::{Finding, FindingsPage, RunHeader};
use crate::page::{check_read, refusal_pending, MAX_PAGE_LIMIT};
use crate::text::{escaped_whole, severity_text, shown, status_text, valid_reference, MAX_ACCOUNT_BYTES};
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use core_api::failure::error_response;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, ErrorDetail, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::PERMISSION_CMDB_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const READ_PATH: &str = "/posture/accounts/{account}/findings";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such account";


pub const RUN_CHANGED_CODE: &str = "run_changed";


pub const RUN_CHANGED_MESSAGE: &str = "the stored run changed: restart from the first page";


pub const DEFAULT_PAGE_LIMIT: usize = 50;


#[derive(OpenApi)]
#[openapi(paths(read_endpoint), components(schemas(RunView, FindingView, PostureView)))]
pub struct PostureDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, StoreError> {
    Ok(tenant_scope(&identity.tenant)?)
}


pub fn parse_limit(text: Option<&str>) -> Result<usize, StoreError> {
    text.map_or(Ok(DEFAULT_PAGE_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_PAGE_LIMIT).contains(size))
            .ok_or(StoreError::BadLimit { max: MAX_PAGE_LIMIT })
    })
}


pub fn failure_category(error: &StoreError) -> &'static str {
    match error {
        StoreError::Pg(_) | StoreError::Lease(_) => "database",
        StoreError::StoredValue => "stored_value",
        StoreError::BadAnswer => "bad_answer",
        _other => "request",
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


/// One fixed body for every cause (another run, another tenant's run, a cursor on an account with no run).
pub fn run_changed() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: RUN_CHANGED_CODE.to_owned(),
            message: RUN_CHANGED_MESSAGE.to_owned(),
        },
    };
    (StatusCode::CONFLICT, Json(body)).into_response()
}


/// A bad query, cursor or limit is the caller's 400, a refused account a 404, a changed run a 409; anything else is logged by category only and answered with a generic 500.
pub fn failure_response(error: &StoreError) -> Response {
    match error {
        StoreError::BadCursor | StoreError::BadLimit { .. } | StoreError::BadQuery => error_response(&ApiError::BadRequest),
        StoreError::BadAccount => not_found(),
        StoreError::RunChanged => run_changed(),
        StoreError::Lease(alerts::error::StoreError::Busy) => error_response(&ApiError::TooManyRequests),
        other => {
            let category = failure_category(other);
            tracing::warn!(category, "posture findings failure");
            error_response(&ApiError::Internal)
        }
    }
}


pub fn run_view(run: &RunHeader) -> RunView {
    RunView {
        run_id: run.run_id.clone(),
        finished_micros: run.finished_micros,
        refused_micros: run.refused_micros,
        refused_items: run.refused_items,
        items: run.items,
        unparsable: run.unparsable,
        bad_field: run.bad_field,
        duplicate: run.duplicate,
        foreign_account: run.foreign_account,
        refused_pass: run.refused_pass,
        refused_muted: run.refused_muted,
        refused_manual: run.refused_manual,
        refused_fail: run.refused_fail,
        store_refused: run.store_refused,
        refusal_pending: refusal_pending(run),
    }
}


/// The raw text fields are never served: `title` and `detail` through `shown`, `uid` through `escaped_whole`.
pub fn finding_view(finding: &Finding) -> FindingView {
    FindingView {
        uid: escaped_whole(&finding.uid),
        check_id: finding.check_id.clone(),
        status: status_text(finding.status).to_owned(),
        severity: severity_text(finding.severity).to_owned(),
        provider: finding.provider.clone(),
        account: finding.account.clone(),
        region: finding.region.clone(),
        resource_uid: finding.resource_uid.clone(),
        resource_type: finding.resource_type.clone(),
        time_unix: finding.time_unix,
        title: shown(&finding.title, finding.title_cut),
        title_cut: finding.title_cut,
        detail: shown(&finding.detail, finding.detail_cut),
        detail_cut: finding.detail_cut,
    }
}


pub fn read_view(page: &FindingsPage) -> PostureView {
    PostureView {
        run: page.run.as_ref().map(run_view),
        unservable: page.unservable,
        items: page.items.iter().map(finding_view).collect(),
        next_cursor: page.next.clone(),
    }
}


/// Order of refusals: the tenant, the account (404, no store call, no echo), the query, then limit and cursor: all before any connection is leased.
pub async fn read_flow(
    identity: &ApiIdentity,
    backend: &PostureBackend,
    account: Result<String, PathRejection>,
    query: Result<ReadQuery, QueryRejection>,
) -> Result<Response, StoreError> {
    let scope = scope_of(identity)?;
    let name = account
        .ok()
        .filter(|text| valid_reference(text, MAX_ACCOUNT_BYTES))
        .ok_or(StoreError::BadAccount)?;
    let parsed = query.map_err(|_rejection| StoreError::BadQuery)?;
    let limit = parse_limit(parsed.limit.as_deref())?;
    let cursor = check_read(&name, parsed.cursor.as_deref(), limit)?;
    let page = (backend.read)(scope, name, cursor, limit).await?;
    Ok(Json(read_view(&page)).into_response())
}


#[utoipa::path(
    get,
    path = "/posture/accounts/{account}/findings",
    params(("account" = String, Path, description = "Account id, percent-encoded"), ReadQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of the account's stored run, highest severity first; run is null when the account has none", body = PostureView),
        (status = 400, description = "Malformed query, cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "Not a valid account id", body = ErrorBody),
        (status = 409, description = "The stored run changed since the cursor was printed: restart", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn read_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<PostureBackend>,
    account: Result<Path<String>, PathRejection>,
    query: Result<Query<ReadQuery>, QueryRejection>,
) -> Response {
    read_flow(&identity, &backend, account.map(|found| found.0), query.map(|found| found.0))
        .await
        .unwrap_or_else(|error| failure_response(&error))
}


pub fn posture_router(backend: PostureBackend) -> Router<SharedState> {
    Router::new().route(READ_PATH, get(read_endpoint)).layer(Extension(backend))
}


/// `cmdb.read`, and `sensitive`: core-api audits every read (tenant, subject, route pattern, status).
pub fn posture_access() -> AccessTable {
    [READ_PATH]
        .into_iter()
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_CMDB_READ.to_owned()),
                    sensitive: true,
                },
            )
        })
        .collect()
}


pub fn posture_document() -> OpenApiDocument {
    PostureDoc::openapi()
}
