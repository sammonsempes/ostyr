mod fixture;
mod http;
mod types;


use alerts::error::StoreError as LeaseError;
use axum::body::Body;
use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity};
use fixture::WRITTEN;
use fixture::{fixture, fixture_with, memory_backend, recorded, written, Fixture, ANALYST, NOW, READER, RESPONDER, SERVICE, TENANT};
use http::{body_json, call, login};
use serde_json::{json, Value};
use status_page::api::{
    admit, audited, bad_field, check_time, create_flow, parse_id, resolve_flow, scope_of, service_declared, status_document, store_failure,
    update_flow, Caller, CREATE_BODY_LIMIT, MAX_CLOCK_SKEW_SECONDS, RESOLVE_BODY_LIMIT, UPDATE_BODY_LIMIT,
};
use status_page::api_model::{CreateRequest, ResolveRequest, UpdateRequest};
use status_page::error::StoreError;
use status_page::store::{MAX_MESSAGE_CHARACTERS, MAX_NOTE_CHARACTERS, MAX_TITLE_CHARACTERS};
use std::sync::{Arc, PoisonError};
use types::{Outcome, TestError, TestResult};


const A_MINUTE: i64 = 60;


const HALF_A_MINUTE: i64 = 30;


const PRIOR_VERSION: i64 = 2;


const CALLS_MADE: usize = 3;


const TWO_SWAPS: u64 = 2;


const AUDITED_CALLS: usize = 4;


const PARSED_ID: i64 = 12;


const SECRET_NOTE: &str = "SECRET-NOTE-10.0.0.5";


const PUBLIC_TITLE: &str = "Checkout is slow";


const PUBLIC_MESSAGE: &str = "We are looking into it";


const UPDATES: &str = "/status/incidents/7/updates";


const RESOLVE: &str = "/status/incidents/7/resolve";


const CREATE: &str = "/status/incidents";


const ONE_OVER: usize = 1;


const PADDING: usize = 2_000;


async fn post(fx: &Fixture, path: &str, token: Option<&str>, body: &Value) -> Result<(StatusCode, Value), TestError> {
    let response = call(&fx.router, "POST", path, token, Body::from(body.to_string())).await?;
    let status = response.status();
    Ok((status, body_json(response).await?))
}


fn written_json() -> Value {
    json!({ "id": WRITTEN.id, "version": WRITTEN.version })
}


fn create_body() -> Value {
    json!({ "service": SERVICE, "title": PUBLIC_TITLE, "published": true, "started_at": NOW - A_MINUTE, "internal_note": SECRET_NOTE })
}


fn update_body() -> Value {
    json!({ "version": PRIOR_VERSION, "at": NOW - HALF_A_MINUTE, "message": PUBLIC_MESSAGE, "internal_note": SECRET_NOTE })
}


fn resolve_body() -> Value {
    json!({ "version": WRITTEN.version, "at": NOW - 1 })
}


fn audit(fx: &Fixture) -> Result<Vec<Value>, TestError> {
    std::fs::read_to_string(&fx.audit_path)?
        .lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect::<Result<Vec<Value>, TestError>>()
        .map(|all| {
            all.into_iter()
                .filter(|record| {
                    record
                        .get("action")
                        .and_then(Value::as_str)
                        .is_some_and(|action| action.starts_with("status."))
                })
                .collect()
        })
}


fn error_code(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


fn conflict() -> Result<status_page::store_model::IncidentRef, StoreError> {
    Err(StoreError::Conflict)
}


fn busy() -> Result<status_page::store_model::IncidentRef, StoreError> {
    Err(StoreError::Lease(LeaseError::Busy))
}


fn broken() -> Result<status_page::store_model::IncidentRef, StoreError> {
    Err(StoreError::ReadTimeout)
}


async fn responder_fixture(outcome: Outcome) -> Result<(Fixture, String), TestError> {
    let fx = fixture_with(outcome)?;
    let token = login(&fx.router, RESPONDER).await?;
    Ok((fx, token))
}


#[tokio::test]
async fn create_update_and_resolve_answer_the_id_and_version_and_bind_the_session_tenant() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    let (created, view) = post(&fx, CREATE, Some(&token), &create_body()).await?;
    assert_eq!(created, StatusCode::CREATED);
    assert_eq!(view, written_json());
    let updated = post(&fx, UPDATES, Some(&token), &update_body()).await?;
    assert_eq!(updated, (StatusCode::OK, written_json()));
    let resolved = post(&fx, RESOLVE, Some(&token), &resolve_body()).await?;
    assert_eq!(resolved, (StatusCode::OK, written_json()));
    let calls = recorded(&fx.calls);
    assert_eq!(calls.len(), CALLS_MADE);
    assert!(calls.iter().all(|entry| entry.contains(TENANT)), "{calls:?}");
    assert!(calls
        .first()
        .is_some_and(|entry| entry.contains(PUBLIC_TITLE) && entry.contains(SECRET_NOTE)));
    assert!(calls.get(1).is_some_and(|entry| entry.contains(" 7 2 ")), "{calls:?}");
    assert!(calls.get(CALLS_MADE - 1).is_some_and(|entry| entry.contains(" 7 3 ")), "{calls:?}");
    Ok(())
}


#[tokio::test]
async fn every_write_is_audited_with_actor_and_id_and_no_text() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    post(&fx, CREATE, Some(&token), &create_body()).await?;
    post(&fx, UPDATES, Some(&token), &update_body()).await?;
    post(&fx, RESOLVE, Some(&token), &resolve_body()).await?;
    let refused = post(&fx, UPDATES, Some(&token), &json!({ "version": 1 })).await?;
    assert_eq!(refused.0, StatusCode::BAD_REQUEST);
    let records = audit(&fx)?;
    let facts: Vec<(&str, &str, &str, &str)> = records
        .iter()
        .map(|record| {
            let text = |key: &str| record.get(key).and_then(Value::as_str).unwrap_or("");
            (text("action"), text("target"), text("actor_id"), text("outcome"))
        })
        .collect();
    assert_eq!(
        facts,
        [
            ("status.incident.create", "7", RESPONDER, "success"),
            ("status.incident.update", "7", RESPONDER, "success"),
            ("status.incident.resolve", "7", RESPONDER, "success"),
            ("status.incident.update", "7", RESPONDER, "failure"),
        ]
    );
    let raw = std::fs::read_to_string(&fx.audit_path)?;
    assert!(!raw.contains(SECRET_NOTE) && !raw.contains(PUBLIC_TITLE) && !raw.contains(PUBLIC_MESSAGE));
    Ok(())
}


#[tokio::test]
async fn no_session_is_401_and_roles_without_status_write_are_403_before_any_store_call() -> TestResult {
    let fx = fixture()?;
    let reader = login(&fx.router, READER).await?;
    let analyst = login(&fx.router, ANALYST).await?;
    for (path, body) in [(CREATE, create_body()), (UPDATES, update_body()), (RESOLVE, resolve_body())] {
        assert_eq!(post(&fx, path, None, &body).await?.0, StatusCode::UNAUTHORIZED);
        assert_eq!(post(&fx, path, Some("bogus"), &body).await?.0, StatusCode::UNAUTHORIZED);
        assert_eq!(post(&fx, path, Some(&reader), &body).await?.0, StatusCode::FORBIDDEN);
        assert_eq!(post(&fx, path, Some(&analyst), &body).await?.0, StatusCode::FORBIDDEN);
    }
    assert!(recorded(&fx.calls).is_empty());
    let records = audit(&fx)?;
    assert!(records.is_empty(), "only the guard's route records exist");
    Ok(())
}


fn with(mut body: Value, key: &str, value: Value) -> Value {
    if let Some(map) = body.as_object_mut() {
        map.insert(key.to_owned(), value);
    }
    body
}


fn without(mut body: Value, key: &str) -> Value {
    if let Some(map) = body.as_object_mut() {
        map.remove(key);
    }
    body
}


#[tokio::test]
async fn malformed_creates_are_400_without_a_store_call_and_echo_nothing() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    let long_title = "t".repeat(MAX_TITLE_CHARACTERS + ONE_OVER);
    let long_note = "n".repeat(MAX_NOTE_CHARACTERS + ONE_OVER);
    let bodies = [
        with(create_body(), "service", json!("svc-undeclared-SECRETSERVICE")),
        with(create_body(), "tenant", json!("globex")),
        with(create_body(), "actor", json!("mallory")),
        without(create_body(), "title"),
        with(create_body(), "title", json!("   ")),
        with(create_body(), "title", json!("bad \u{1b}[31m escape")),
        with(create_body(), "title", json!("bad \u{202e} bidi")),
        with(create_body(), "title", json!("bad \u{0} nul")),
        with(create_body(), "title", json!(long_title)),
        with(create_body(), "internal_note", json!(long_note)),
        with(create_body(), "started_at", json!(NOW + MAX_CLOCK_SKEW_SECONDS + 1)),
        with(create_body(), "started_at", json!(-1)),
        with(create_body(), "published", json!("yes")),
    ];
    for body in bodies {
        let (status, answer) = post(&fx, CREATE, Some(&token), &body).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(error_code(&answer), Some("bad_request"), "{body}");
        assert!(!answer.to_string().contains("SECRETSERVICE"));
    }
    let (status, _answer) = post(&fx, "/status/incidents?tenant=globex", Some(&token), &create_body()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let raw = call(&fx.router, "POST", CREATE, Some(&token), Body::from("{not json")).await?;
    assert_eq!(raw.status(), StatusCode::BAD_REQUEST);
    assert!(recorded(&fx.calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_create_at_the_skew_limit_and_without_a_note_is_accepted() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    let body = without(with(create_body(), "started_at", json!(NOW + MAX_CLOCK_SKEW_SECONDS)), "internal_note");
    assert_eq!(post(&fx, CREATE, Some(&token), &body).await?.0, StatusCode::CREATED);
    Ok(())
}


#[tokio::test]
async fn malformed_updates_and_resolves_are_400_without_a_store_call() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    let long_message = "m".repeat(MAX_MESSAGE_CHARACTERS + ONE_OVER);
    let updates = [
        without(update_body(), "version"),
        with(update_body(), "message", json!("")),
        with(update_body(), "message", json!(long_message)),
        with(update_body(), "message", json!("nul \u{0}")),
        with(update_body(), "at", json!(NOW + MAX_CLOCK_SKEW_SECONDS + 1)),
        with(update_body(), "tenant", json!("globex")),
    ];
    for body in updates {
        assert_eq!(post(&fx, UPDATES, Some(&token), &body).await?.0, StatusCode::BAD_REQUEST, "{body}");
    }
    let resolves = [
        with(resolve_body(), "at", json!(NOW + MAX_CLOCK_SKEW_SECONDS + 1)),
        with(resolve_body(), "at", json!(-1)),
        with(resolve_body(), "tenant", json!("globex")),
        without(resolve_body(), "at"),
    ];
    for body in resolves {
        assert_eq!(post(&fx, RESOLVE, Some(&token), &body).await?.0, StatusCode::BAD_REQUEST, "{body}");
    }
    for id in ["abc", "-1", "%ff", "99999999999999999999", "1.5", "%00"] {
        let updates_path = format!("/status/incidents/{id}/updates");
        assert_eq!(
            post(&fx, &updates_path, Some(&token), &update_body()).await?.0,
            StatusCode::BAD_REQUEST,
            "{id}"
        );
        let resolve_path = format!("/status/incidents/{id}/resolve");
        assert_eq!(
            post(&fx, &resolve_path, Some(&token), &resolve_body()).await?.0,
            StatusCode::BAD_REQUEST,
            "{id}"
        );
    }
    let (status, _answer) = post(&fx, "/status/incidents/7/resolve?tenant=globex", Some(&token), &resolve_body()).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(recorded(&fx.calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_body_over_the_route_limit_is_413() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    let padded = with(resolve_body(), "pad", json!("x".repeat(RESOLVE_BODY_LIMIT + PADDING)));
    assert_eq!(post(&fx, RESOLVE, Some(&token), &padded).await?.0, StatusCode::PAYLOAD_TOO_LARGE);
    let huge = Body::from("x".repeat(CREATE_BODY_LIMIT + UPDATE_BODY_LIMIT));
    let response = call(&fx.router, "POST", CREATE, Some(&token), huge).await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(recorded(&fx.calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_stale_foreign_or_unknown_id_is_one_fixed_409() -> TestResult {
    let (fx, token) = responder_fixture(conflict).await?;
    let (first, left) = post(&fx, UPDATES, Some(&token), &update_body()).await?;
    let (second, right) = post(&fx, RESOLVE, Some(&token), &resolve_body()).await?;
    assert_eq!((first, second), (StatusCode::CONFLICT, StatusCode::CONFLICT));
    assert_eq!(left, right);
    assert_eq!(error_code(&left), Some("conflict"));
    assert!(!left.to_string().contains('7'));
    Ok(())
}


#[tokio::test]
async fn a_busy_pool_is_429_and_any_other_store_failure_a_generic_500() -> TestResult {
    let (busy_fx, busy_token) = responder_fixture(busy).await?;
    assert_eq!(
        post(&busy_fx, CREATE, Some(&busy_token), &create_body()).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let (fx, token) = responder_fixture(broken).await?;
    let (status, answer) = post(&fx, CREATE, Some(&token), &create_body()).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_code(&answer), Some("internal_error"));
    Ok(())
}


#[tokio::test]
async fn an_identity_of_another_tenant_than_the_page_declares_no_service() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    let current = fx.state.identity.load();
    fx.state.identity.store(Arc::new(ApiIdentity {
        module: current.module.clone(),
        tenant: "globex".to_owned(),
        generation: current.generation + 1,
    }));
    assert_eq!(post(&fx, CREATE, Some(&token), &create_body()).await?.0, StatusCode::BAD_REQUEST);
    assert!(recorded(&fx.calls).is_empty());
    fx.state.identity.store(Arc::new(ApiIdentity {
        module: current.module.clone(),
        tenant: "bad tenant".to_owned(),
        generation: current.generation + TWO_SWAPS,
    }));
    assert_eq!(
        post(&fx, CREATE, Some(&token), &create_body()).await?.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(recorded(&fx.calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_audit_log_is_a_500_not_a_silent_success() -> TestResult {
    let (fx, token) = responder_fixture(written).await?;
    fx.state.audit.state.lock().unwrap_or_else(PoisonError::into_inner).poisoned = true;
    let (status, answer) = post(&fx, CREATE, Some(&token), &create_body()).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_code(&answer), Some("internal_error"));
    Ok(())
}


fn caller<'a>(fx: &'a Fixture, identity: &'a ApiIdentity) -> Caller<'a> {
    Caller {
        app: &fx.state,
        identity,
        request_id: "direct",
        session: None,
    }
}


fn identity(tenant: &str) -> ApiIdentity {
    ApiIdentity {
        module: "status".to_owned(),
        tenant: tenant.to_owned(),
        generation: 0,
    }
}


fn create_request() -> CreateRequest {
    CreateRequest {
        service: SERVICE.to_owned(),
        title: PUBLIC_TITLE.to_owned(),
        published: false,
        started_at: NOW,
        internal_note: String::new(),
    }
}


#[tokio::test]
async fn a_handler_reached_without_a_session_writes_nothing_and_a_refused_body_is_audited() -> TestResult {
    let fx = fixture()?;
    let backend = memory_backend(&fx.calls, written);
    let who = identity(TENANT);
    let held = caller(&fx, &who);
    assert!(admit(&held).is_err());
    let created = create_flow(&held, &backend, Ok(create_request())).await;
    assert_eq!(created.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let updated = update_flow(
        &held,
        &backend,
        Ok("7".to_owned()),
        Ok(UpdateRequest {
            version: 1,
            at: NOW,
            message: PUBLIC_MESSAGE.to_owned(),
            internal_note: String::new(),
        }),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let resolved = resolve_flow(&held, &backend, Ok("7".to_owned()), Ok(ResolveRequest { version: 1, at: NOW })).await;
    assert_eq!(resolved.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let refused = resolve_flow(&held, &backend, Ok("x".to_owned()), Err(ApiError::BadRequest)).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(recorded(&fx.calls).is_empty());
    let records = audit(&fx)?;
    assert_eq!(records.len(), AUDITED_CALLS);
    assert!(records.iter().all(|record| record.get("actor_id") == Some(&json!("unknown"))));
    assert_eq!(records.last().and_then(|record| record.get("target")), Some(&json!("new")));
    Ok(())
}


#[tokio::test]
async fn the_helpers_decide_ids_times_services_and_failures() -> TestResult {
    let fx = fixture()?;
    let backend = memory_backend(&fx.calls, written);
    assert!(service_declared(&backend, &identity(TENANT), SERVICE));
    assert!(!service_declared(&backend, &identity(TENANT), "other"));
    assert!(!service_declared(&backend, &identity("globex"), SERVICE));
    assert!(matches!(parse_id(Ok("12".to_owned())), Ok(PARSED_ID)));
    assert!(parse_id(Ok(String::new())).is_err());
    assert!(parse_id(Ok("1a".to_owned())).is_err());
    assert!(check_time("at", 0, NOW).is_ok());
    assert!(check_time("at", NOW + MAX_CLOCK_SKEW_SECONDS, NOW).is_ok());
    assert!(check_time("at", NOW + MAX_CLOCK_SKEW_SECONDS + 1, NOW).is_err());
    assert!(check_time("at", -1, NOW).is_err());
    assert!(check_time("at", i64::MAX, i64::MAX).is_ok());
    assert!(scope_of(&identity("bad tenant")).is_err());
    assert_eq!(bad_field("x", "y").status(), StatusCode::BAD_REQUEST);
    let statuses = [
        (StoreError::TextTooLong { field: "title", limit: 1 }, StatusCode::BAD_REQUEST),
        (StoreError::TextInvalid { field: "title" }, StatusCode::BAD_REQUEST),
        (StoreError::Conflict, StatusCode::CONFLICT),
        (StoreError::Lease(LeaseError::Busy), StatusCode::TOO_MANY_REQUESTS),
        (StoreError::Lease(LeaseError::BadId), StatusCode::INTERNAL_SERVER_ERROR),
        (StoreError::ReadTimeout, StatusCode::INTERNAL_SERVER_ERROR),
    ];
    statuses
        .iter()
        .for_each(|(error, status)| assert_eq!(store_failure(error).status(), *status, "{error}"));
    let who = identity(TENANT);
    let answered = audited(&caller(&fx, &who), "status.test", "1", bad_field("x", "y"));
    assert_eq!(answered.status(), StatusCode::BAD_REQUEST);
    Ok(())
}


#[tokio::test]
async fn the_openapi_document_lists_the_three_routes() -> TestResult {
    let fx = fixture()?;
    let document = body_json(http::get(&fx.router, "/openapi.json", None).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    [CREATE, UPDATES.replace('7', "{id}").as_str(), RESOLVE.replace('7', "{id}").as_str()]
        .iter()
        .for_each(|path| assert!(paths.get(*path).and_then(|entry| entry.get("post")).is_some(), "{path}"));
    assert!(serde_json::to_string(&status_document())?.contains("IncidentView"));
    Ok(())
}
