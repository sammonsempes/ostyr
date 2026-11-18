use crate::api::{checked_id, not_found, scope_of, store_failure};
use crate::api_model::{CasesBackend, NoQuery, ObservableAdded, ObservableListView, ObservableRequest};
use crate::grammar::{is_plain_text, is_valid_value};
use crate::model::Observable;
use crate::observable::normalise_value;
use crate::store::{check_text, MAX_NAME_CHARS, MAX_OBSERVABLE_CHARS};
use crate::stored::SeenObservable;
use crate::write_api::{actor_of, bad_field, body_failure, write_failure, JSON_BYTES_PER_CHAR, JSON_OVERHEAD_BYTES};
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use core_api::failure::reply;
use core_api::model::{ApiError, ApiIdentity, Authenticated, ErrorBody};
use std::sync::Arc;


pub const OBSERVABLES_PATH: &str = "/cases/{id}/observables";


pub const VALUE_FIELD: &str = "value";


pub const SOURCE_FIELD: &str = "source";


pub const OBSERVABLE_BODY_LIMIT: usize = (MAX_OBSERVABLE_CHARS + MAX_NAME_CHARS) * JSON_BYTES_PER_CHAR + JSON_OVERHEAD_BYTES;


/// The observable with its normalised value, or the name of the field that is refused (the grammar of the kind applies to the normalised value).
pub fn checked_request(request: ObservableRequest) -> Result<Observable, &'static str> {
    let value = normalise_value(request.kind, &request.value);
    let value_fits =
        check_text(VALUE_FIELD, &request.value, MAX_OBSERVABLE_CHARS).is_ok() && check_text(VALUE_FIELD, &value, MAX_OBSERVABLE_CHARS).is_ok();
    let source_fits = check_text(SOURCE_FIELD, &request.source, MAX_NAME_CHARS).is_ok() && is_plain_text(&request.source);
    if !value_fits || !is_valid_value(request.kind, &value) {
        Err(VALUE_FIELD)
    } else if !source_fits {
        Err(SOURCE_FIELD)
    } else {
        Ok(Observable {
            kind: request.kind,
            value,
            tlp: request.tlp,
            pap: request.pap,
            ioc: request.ioc,
            source: request.source,
        })
    }
}


pub async fn observable_flow(
    identity: &ApiIdentity,
    session: Option<&Authenticated>,
    backend: &CasesBackend,
    id: Result<String, PathRejection>,
    body: Result<ObservableRequest, ApiError>,
) -> Result<Response, ApiError> {
    let request = body?;
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    actor_of(session)?;
    match (checked_id(id), checked_request(request)) {
        (None, _) => Ok(not_found()),
        (Some(_), Err(field)) => Ok(bad_field(field, "is empty, too long or not valid for its kind")),
        (Some(text), Ok(observable)) => {
            let stored = observable.clone();
            let done = (backend.observable)(scope, text, observable).await;
            done.map_or_else(
                |error| write_failure(&error),
                |added| {
                    let status = if added { StatusCode::CREATED } else { StatusCode::OK };
                    let view = ObservableAdded {
                        observable: stored,
                        already_present: !added,
                    };
                    Ok((status, Json(view)).into_response())
                },
            )
        }
    }
}


pub async fn observables_flow(identity: &ApiIdentity, backend: &CasesBackend, id: Result<String, PathRejection>) -> Result<Response, ApiError> {
    let scope = scope_of(identity).map_err(|error| store_failure(&error))?;
    match checked_id(id) {
        None => Ok(not_found()),
        Some(text) => (backend.observables)(scope, text).await.map_or_else(
            |error| write_failure(&error),
            |items: Vec<SeenObservable>| Ok(Json(ObservableListView { items }).into_response()),
        ),
    }
}


#[utoipa::path(
    post,
    path = "/cases/{id}/observables",
    params(("id" = String, Path, description = "Case id")),
    request_body = ObservableRequest,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The observable as stored, value normalised", body = ObservableAdded),
        (status = 200, description = "The case already held the same kind and value (already_present)", body = ObservableAdded),
        (status = 400, description = "Malformed body, unknown field, or a value or source refused by the grammar of its kind", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such case for this tenant", body = ErrorBody),
        (status = 409, description = "The case holds the maximum number of observables", body = ErrorBody),
        (status = 413, description = "Body too large", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn observable_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    session: Option<Extension<Authenticated>>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Json<ObservableRequest>, JsonRejection>,
) -> Response {
    let parsed = body.map(|found| found.0).map_err(|rejection| body_failure(&rejection));
    reply(
        observable_flow(
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
    path = "/cases/{id}/observables",
    params(("id" = String, Path, description = "Case id")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The observables in stored order, each with the other cases of the tenant holding it (at most 20)", body = ObservableListView),
        (status = 400, description = "A query parameter", body = ErrorBody),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 403, description = "Permission denied", body = ErrorBody),
        (status = 404, description = "No such case for this tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn observables_endpoint(
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(backend): Extension<CasesBackend>,
    id: Result<Path<String>, PathRejection>,
    query: Result<Query<NoQuery>, QueryRejection>,
) -> Response {
    let refused = query.err().map(|_rejection| ApiError::BadRequest);
    reply(match refused {
        Some(error) => Err(error),
        None => observables_flow(&identity, &backend, id.map(|found| found.0)).await,
    })
}
