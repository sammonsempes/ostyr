use crate::error::GroupError;
use crate::group::group_alerts;
use crate::model::{Group, GroupLimits};
use crate::view::{GroupListView, GroupRoute, GroupView, Read, ReadPlan, ReadStop};
use alerts::api::{created_time, scope_of, store_failure, store_reply, unavailable};
use alerts::error::StoreError;
use alerts::model::{Backend, NoQuery, Page};
use alerts::store::MAX_PAGE_SIZE;
use axum::extract::rejection::QueryRejection;
use axum::extract::Query;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, ErrorBody, Requirement, Rule};
use core_api::routes::route_key;
use core_api::types::{AccessTable, SharedState};
use core_auth::rbac::PERMISSION_ALERTS_READ;
use core_pg::scope::TenantScope;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const GROUPS_PATH: &str = "/alert-groups";


pub const GROUP_READS_AT_ONCE: usize = 2;


pub const GROUP_READ_PAGES: usize = 10;


pub const GROUP_READ_DEADLINE_SECONDS: u64 = 10;


pub const GROUP_READ_DEADLINE: Duration = Duration::from_secs(GROUP_READ_DEADLINE_SECONDS);


pub const MICROS_PER_SECOND: u64 = 1_000_000;


pub const SECONDS_PER_MINUTE: u64 = 60;


pub const WINDOW_MINUTES: u64 = 15;


pub const MAX_GROUPS: usize = 1_000;


pub const MAX_ALERTS_PER_GROUP: usize = 50;


pub const DEFAULT_PLAN: ReadPlan = ReadPlan {
    limits: GroupLimits {
        window_micros: WINDOW_MINUTES * SECONDS_PER_MINUTE * MICROS_PER_SECOND,
        max_alerts: GROUP_READ_PAGES * MAX_PAGE_SIZE,
        max_groups: MAX_GROUPS,
        max_alerts_per_group: MAX_ALERTS_PER_GROUP,
    },
    max_pages: GROUP_READ_PAGES,
    deadline: GROUP_READ_DEADLINE,
};


#[derive(OpenApi)]
#[openapi(paths(groups_endpoint), components(schemas(GroupView, GroupListView)))]
pub struct GroupsDoc;


/// One page, after the deadline check; a page in flight is never cancelled, so a database backend never outlives its permit.
pub async fn read_page(scope: &TenantScope, backend: &Backend, plan: &ReadPlan, started: Instant, read: &mut Read) -> Result<(), ReadStop> {
    (Instant::now() < started + plan.deadline).then_some(()).ok_or(ReadStop::Late)?;
    let page = (backend.list)(
        scope.clone(),
        Page {
            after: read.next.take(),
            size: MAX_PAGE_SIZE,
        },
    )
    .await?;
    read.done = page.next.is_none();
    read.next = page.next;
    read.alerts.extend(page.alerts);
    Ok(())
}


/// At most `max_pages` pages, stopping early once a page has no next cursor.
pub async fn read_pages(scope: &TenantScope, backend: &Backend, plan: &ReadPlan, started: Instant) -> Result<Read, ReadStop> {
    let mut read = Read::default();
    for _ in 0..plan.max_pages {
        if !read.done {
            read_page(scope, backend, plan, started, &mut read).await?;
        }
    }
    Ok(read)
}


/// Older unread alerts can join a group only within one window of its first alert.
pub fn is_cut_at_older(group: &Group, oldest: Option<u64>, complete: bool, window_micros: u64) -> bool {
    !complete && oldest.is_some_and(|oldest_micros| group.first_micros.saturating_sub(oldest_micros) <= window_micros)
}


pub fn group_view(group: &Group, cut_at_older: bool) -> Result<GroupView, StoreError> {
    Ok(GroupView {
        rule_id: group.key.rule_id.clone(),
        host_name: group.key.host_name.clone(),
        user_name: group.key.user_name.clone(),
        representative: group.representative.clone(),
        alert_ids: group.alert_ids.clone(),
        omitted: group.omitted,
        alert_count: group.alert_count,
        duplicates: group.duplicates,
        first_time: created_time(group.first_micros)?,
        last_time: created_time(group.last_micros)?,
        max_severity: group.max_severity.to_string(),
        cut_at_older,
    })
}


pub fn list_view(groups: &[Group], read: &Read, window_micros: u64) -> Result<GroupListView, StoreError> {
    let complete = read.next.is_none();
    let oldest = read.alerts.iter().map(|alert| alert.created_micros).min();
    Ok(GroupListView {
        groups: groups
            .iter()
            .map(|group| group_view(group, is_cut_at_older(group, oldest, complete, window_micros)))
            .collect::<Result<Vec<GroupView>, StoreError>>()?,
        complete,
        alerts_read: read.alerts.len(),
        oldest_read: oldest.map(created_time).transpose()?,
    })
}


/// With the default plan neither error can occur (the read is capped at `max_alerts`); both are a fixed 500.
pub fn group_failure(error: &GroupError) -> ApiError {
    tracing::warn!(error = %error, "alert grouping refused its own read");
    ApiError::Internal
}


/// The route takes no cursor or size from the caller, so a store refusal of either is a fault of the store, never the caller's 400.
pub fn own_cursor_failure(error: &StoreError) -> ApiError {
    tracing::warn!(error = %error, "alert grouping read a cursor the store refused");
    ApiError::Internal
}


pub async fn groups_flow(identity: &ApiIdentity, route: &GroupRoute, plan: &ReadPlan, query: Result<(), ApiError>) -> Result<Response, ApiError> {
    query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let _held = route.reads.try_acquire().map_err(|_full| ApiError::TooManyRequests)?;
    match read_pages(&scope, &route.backend, plan, Instant::now()).await {
        Ok(read) => {
            let groups = group_alerts(&read.alerts, &plan.limits).map_err(|error| group_failure(&error))?;
            let view = list_view(&groups, &read, plan.limits.window_micros).map_err(|error| store_failure(&error))?;
            Ok(Json(view).into_response())
        }
        Err(ReadStop::Late) => Ok(unavailable()),
        Err(ReadStop::Store(error @ (StoreError::BadCursor | StoreError::BadPageSize { .. }))) => Err(own_cursor_failure(&error)),
        Err(ReadStop::Store(error)) => store_reply(&error),
    }
}


#[utoipa::path(
    get,
    path = "/alert-groups",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Groups of the tenant's newest alerts (at most 1000), with a visible cut", body = GroupListView),
        (status = 400, description = "Any query parameter", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 429, description = "Too many group reads or requests", body = ErrorBody),
        (status = 503, description = "Database unavailable or read deadline passed", body = ErrorBody)
    )
)]
pub async fn groups_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(route): Extension<GroupRoute>,
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Response {
    let checked = query.map(|_none| ()).map_err(|_rejection| ApiError::BadRequest);
    reply(groups_flow(&identity, &route, &DEFAULT_PLAN, checked).await)
}


pub fn alert_groups_router(backend: Backend) -> Router<SharedState> {
    Router::new().route(GROUPS_PATH, get(groups_endpoint)).layer(Extension(GroupRoute {
        backend,
        reads: Arc::new(Semaphore::new(GROUP_READS_AT_ONCE)),
    }))
}


pub fn alert_groups_access() -> AccessTable {
    [(
        route_key("GET", GROUPS_PATH),
        Rule {
            requirement: Requirement::Permission(PERMISSION_ALERTS_READ.to_owned()),
            sensitive: false,
        },
    )]
    .into_iter()
    .collect()
}


pub fn alert_groups_document() -> OpenApiDocument {
    GroupsDoc::openapi()
}
