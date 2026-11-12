use crate::api::{checked_id, not_found, parse_limit, scope_of, store_failure, MAX_CURSOR_CHARS};
use crate::api_model::{AlertLinkListView, CasesBackend, LinkRequest, ListQuery};
use crate::error::CaseStoreError;
use crate::stored::{AlertLink, LinkList, LinkPage};
use crate::write_api::{actor_of, bad_field, body_failure, conflict, error_reply, write_failure};
use alerts::id::is_alert_id;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, Authenticated, ErrorBody};
use data_encoding::BASE64URL_NOPAD;
use std::sync::Arc;


pub const ALERTS_PATH: &str = "/cases/{id}/alerts";


pub const ALERT_FIELD: &str = "alert_id";


pub const ALERT_NOT_FOUND_CODE: &str = "alert_not_found";


pub const ALERTS_FULL_CODE: &str = "alerts_full";


pub const LINK_BODY_LIMIT: usize = 1_024;


pub fn encode_link_cursor(alert_id: &str) -> String {
    BASE64URL_NOPAD.encode(alert_id.as_bytes())
}


/// Base64url of a 64-character lowercase hexadecimal alert id, checked before any store call.
pub fn decode_link_cursor(text: &str) -> Result<String, CaseStoreError> {
    let bytes = (text.len() <= MAX_CURSOR_CHARS)
        .then(|| BASE64URL_NOPAD.decode(text.as_bytes()).ok())
        .flatten()
        .ok_or(CaseStoreError::BadCursor)?;
    String::from_utf8(bytes)
        .ok()
        .filter(|alert_id| is_alert_id(alert_id))
        .ok_or(CaseStoreError::BadCursor)
}


pub fn link_page_of(query: &ListQuery) -> Result<LinkPage, CaseStoreError> {
    Ok(LinkPage {
        after: query.cursor.as_deref().map(decode_link_cursor).transpose()?,
        size: parse_limit(query.limit.as_deref())?,
    })
}


pub fn links_view(found: LinkList) -> AlertLinkListView {
    AlertLinkListView {
        next_cursor: found.next.as_deref().map(encode_link_cursor),
        items: found.alerts.into_iter().map(|alert_id| AlertLink { alert_id }).collect(),
    }
}


/// A missing alert and a full list have their own codes; every other failure is `write_failure`.
pub fn link_failure(error: &CaseStoreError) -> Result<Response, ApiError> {
    match error {
        CaseStoreError::AlertNotFound => Ok(error_reply(StatusCode::NOT_FOUND, ALERT_NOT_FOUND_CODE, "no such alert".to_owned())),
        CaseStoreError::Full { what: "alerts", limit } => Ok(conflict(ALERTS_FULL_CODE, &format!("the case holds the maximum of {limit} alerts"))),
        other => write_failure(other),
    }
}


pub async fn link_flow(
    identity: &ApiIdentity,
    session: Option<&Authenticated>,
    backend: &CasesBackend,
    id: Result<String, PathRejection>,
    body: Result<LinkRequest, ApiError>,
) -> Result<Response, ApiError> {
    let request = body?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let actor = actor_of(session)?;
    match (checked_id(id), is_alert_id(&request.alert_id)) {
        (None, _) => Ok(not_found()),
        (Some(_), false) => Ok(bad_field(ALERT_FIELD, "must be 64 lowercase hexadecimal characters")),
        (Some(text), true) => {
            let now = (backend.clock)();
            let alert_id = request.alert_id;
            let done = (backend.link)(scope, text, alert_id.clone(), actor, now).await;
            done.map_or_else(
                |error| link_failure(&error),
                |added| {
                    let status = if added { StatusCode::CREATED } else { StatusCode::OK };
                    Ok((status, Json(AlertLink { alert_id })).into_response())
                },
            )
        }
    }
}


pub async fn links_flow(
    identity: &ApiIdentity,
    backend: &CasesBackend,
    id: Result<String, PathRejection>,
    query: Result<ListQuery, ApiError>,
) -> Result<Response, ApiError> {
    let parsed = query?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    let page = link_page_of(&parsed).map_err(|error| store_failure(&error))?;
    match checked_id(id) {
        None => Ok(not_found()),
        Some(text) => (backend.links)(scope, text, page)
            .await
            .map_or_else(|error| write_failure(&error), |found| Ok(Json(links_view(found)).into_response())),
    }
}


#[utoipa::path(
    post,
    path = "/cases/{id}/alerts",
    params(("id" = String, Path, description = "Case id")),
    request_body = LinkRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The alert is newly linked", body = AlertLink),
        (status = 200, description = "The alert was already linked", body = AlertLink),
        (status = 400, description = "Malformed body, unknown field or a bad alert id", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such case, or code alert_not_found for an alert absent from the tenant", body = ErrorBody),
        (status = 409, description = "The case holds the maximum number of alerts (alerts_full) or history events", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn link_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<LinkRequest>, JsonRejection>,
) -> Response {
    let parsed = body.map(|found| found.0).map_err(|rejection| body_failure(&rejection));
    reply(
        link_flow(
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
    get,
    path = "/cases/{id}/alerts",
    params(("id" = String, Path, description = "Case id"), ListQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of linked alert ids, ascending", body = AlertLinkListView),
        (status = 400, description = "Malformed cursor or limit", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such case for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn links_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    id: Result<Path<String>, PathRejection>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Response {
    reply(
        links_flow(
            &identity,
            &backend,
            id.map(|found| found.0),
            query.map(|found| found.0).map_err(|_rejection| ApiError::BadRequest),
        )
        .await,
    )
}
