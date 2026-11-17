use crate::api_model::{Computed, EntityView, Failure, ListQuery, RiskEntityView, RiskListView, RiskState, TruncatedView};
use crate::cache::scores_for;
use crate::model::{EntityKind, EntityRef, Score};
use crate::score::check_contribution;
use crate::source::{Limit, Truncated};
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
use core_auth::rbac::PERMISSION_ALERTS_READ;
use core_pg::scope::{tenant_scope, TenantScope};
use std::collections::BTreeMap;
use std::sync::Arc;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const DEFAULT_LIMIT: usize = 50;


pub const MAX_LIST_LIMIT: usize = 500;


pub const LIST_PATH: &str = "/risk/entities";


pub const GET_PATH: &str = "/risk/entities/{kind}/{id}";


pub const NOT_FOUND_CODE: &str = "not_found";


pub const NOT_FOUND_MESSAGE: &str = "no such entity";


pub const UNAVAILABLE_CODE: &str = "unavailable";


pub const UNAVAILABLE_MESSAGE: &str = "the risk scores are unavailable, retry later";


#[derive(OpenApi)]
#[openapi(
    paths(list_endpoint, get_endpoint),
    components(schemas(RiskListView, RiskEntityView, EntityView, TruncatedView))
)]
pub struct RiskDoc;


/// The tenant is the one of the identity snapshot core-api's `guard` admitted the request under: no request value selects it.
pub fn scope_of(identity: &ApiIdentity) -> Result<TenantScope, ApiError> {
    tenant_scope(&identity.tenant).map_err(|_invalid| ApiError::Internal)
}


/// Digits only, 1 to `MAX_LIST_LIMIT`.
pub fn parse_limit(text: Option<&str>) -> Result<usize, ApiError> {
    text.map_or(Ok(DEFAULT_LIMIT), |digits| {
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse::<usize>().ok())
            .flatten()
            .filter(|size| (1..=MAX_LIST_LIMIT).contains(size))
            .ok_or(ApiError::BadRequest)
    })
}


pub fn parse_kind(text: &str) -> Option<EntityKind> {
    match text {
        "host" => Some(EntityKind::Host),
        "user" => Some(EntityKind::User),
        _ => None,
    }
}


pub fn kind_name(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::User => "user",
        EntityKind::Host => "host",
        EntityKind::Ip => "ip",
        EntityKind::Container => "container",
        EntityKind::CloudAccount => "cloud_account",
    }
}


pub fn limit_name(limit: Limit) -> &'static str {
    match limit {
        Limit::Alerts => "alerts",
        Limit::Contributions => "contributions",
        Limit::Entities => "entities",
    }
}


pub fn truncated_view(truncated: &Truncated) -> TruncatedView {
    TruncatedView {
        limit: limit_name(truncated.limit).to_owned(),
        read: truncated.read,
        cap: truncated.cap,
    }
}


pub fn entity_view(score: &Score) -> EntityView {
    EntityView {
        kind: kind_name(score.entity.kind).to_owned(),
        id: score.entity.id.clone(),
        value: score.value,
        contributions_used: score.contributions_used,
        contributions_dropped: score.contributions_dropped,
    }
}


pub fn list_view(computed: &Computed, kind: Option<EntityKind>, limit: usize) -> RiskListView {
    let outcome = &computed.outcome;
    RiskListView {
        computed_at: computed.computed_at,
        alerts_read: outcome.alerts_read,
        informational: outcome.informational,
        refused: outcome
            .refused
            .iter()
            .map(|(refused_kind, count)| (kind_name(*refused_kind).to_owned(), *count))
            .collect::<BTreeMap<_, _>>(),
        truncated: outcome.truncated.as_ref().map(truncated_view),
        entities: outcome
            .scores
            .iter()
            .filter(|score| kind.is_none_or(|wanted| score.entity.kind == wanted))
            .take(limit)
            .map(entity_view)
            .collect(),
    }
}


/// A refused kind or id (grammar of `check_contribution`) is `None`, answered like a missing entity and never echoed.
pub fn entity_ref(kind: &str, id: String) -> Option<EntityRef> {
    let parsed = parse_kind(kind)?;
    let candidate = EntityRef { kind: parsed, id };
    check_id(&candidate).then_some(candidate)
}


pub fn check_id(entity: &EntityRef) -> bool {
    let probe = crate::model::Contribution {
        entity: entity.clone(),
        rule_id: String::new(),
        severity: crate::model::Severity::Low,
        observed_at: 0,
        fleet_rate: 0,
        entity_rate: 0,
        false_positive_rate: 0,
    };
    check_contribution(&probe).is_ok()
}


pub fn entity_view_of(computed: &Computed, entity: &EntityRef) -> Option<RiskEntityView> {
    computed
        .outcome
        .scores
        .iter()
        .find(|score| &score.entity == entity)
        .map(|score| RiskEntityView {
            computed_at: computed.computed_at,
            truncated: computed.outcome.truncated.as_ref().map(truncated_view),
            entity: entity_view(score),
        })
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


pub fn unavailable() -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: UNAVAILABLE_CODE.to_owned(),
            message: UNAVAILABLE_MESSAGE.to_owned(),
        },
    };
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}


pub fn failure_response(result: Result<Response, Failure>) -> Response {
    match result {
        Ok(response) => response,
        Err(Failure::Api(error)) => error_response(&error),
        Err(Failure::Unavailable) => unavailable(),
    }
}


pub async fn list_flow(identity: &ApiIdentity, state: &RiskState, query: Result<ListQuery, ApiError>) -> Result<Response, Failure> {
    let parsed = query?;
    let scope = scope_of(identity)?;
    let limit = parse_limit(parsed.limit.as_deref())?;
    let kind = parsed
        .kind
        .as_deref()
        .map(|text| parse_kind(text).ok_or(ApiError::BadRequest))
        .transpose()?;
    let computed = scores_for(state, scope).await?;
    Ok(Json(list_view(&computed, kind, limit)).into_response())
}


/// A refused kind or id, or one the extractor refuses, is the fixed 404 without any computation.
pub async fn get_flow(identity: &ApiIdentity, state: &RiskState, path: Result<(String, String), PathRejection>) -> Result<Response, Failure> {
    let scope = scope_of(identity)?;
    let checked = path.ok().and_then(|(kind, id)| entity_ref(&kind, id));
    match checked {
        None => Ok(not_found()),
        Some(entity) => {
            let computed = scores_for(state, scope).await?;
            Ok(entity_view_of(&computed, &entity).map_or_else(not_found, |view| Json(view).into_response()))
        }
    }
}


#[utoipa::path(
    get,
    path = "/risk/entities",
    params(ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant's entity risk scores, highest first", body = RiskListView),
        (status = 400, description = "Malformed limit or kind", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 503, description = "The scores could not be computed in time", body = ErrorBody)
    )
)]
pub async fn list_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(state): Extension<RiskState>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    failure_response(list_flow(&identity, &state, query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest)).await)
}


#[utoipa::path(
    get,
    path = "/risk/entities/{kind}/{id}",
    params(("kind" = String, Path, description = "host or user"), ("id" = String, Path, description = "Entity id")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The entity's score", body = RiskEntityView),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such entity for this tenant", body = ErrorBody),
        (status = 503, description = "The scores could not be computed in time", body = ErrorBody)
    )
)]
pub async fn get_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(state): Extension<RiskState>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Response {
    failure_response(get_flow(&identity, &state, path.map(|found| found.0)).await)
}


pub fn risk_router(state: RiskState) -> Router<SharedState> {
    Router::new()
        .route(LIST_PATH, get(list_endpoint))
        .route(GET_PATH, get(get_endpoint))
        .layer(Extension(state))
}


pub fn risk_access() -> AccessTable {
    [LIST_PATH, GET_PATH]
        .into_iter()
        .map(|path| {
            (
                route_key("GET", path),
                Rule {
                    requirement: Requirement::Permission(PERMISSION_ALERTS_READ.to_owned()),
                    sensitive: false,
                },
            )
        })
        .collect()
}


pub fn risk_document() -> OpenApiDocument {
    RiskDoc::openapi()
}
