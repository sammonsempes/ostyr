use crate::fixture::{alert, busy_triage, fixed_clock, fixture, fixture_with, store, Fixture, ANALYST, BASE_TIME, OTHER_TENANT, READER, TENANT};
use crate::http::{body_json, call, get, login};
use crate::memory::{lock, Forced};
use crate::types::{TestError, TestResult};
use alerts::api::{actor_of, alerts_document, triage_flow, TRIAGE_BODY_LIMIT};
use alerts::backend::unix_micros;
use alerts::error::StoreError;
use alerts::model::{AlertDetail, Backend, Triage, TriageChange, TriageRequest, TriageStatus};
use alerts::store::{check_triage, MAX_NOTE_CHARS};
use axum::body::Body;
use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity};
use core_pg::error::PgError;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;


const FIRST_VERSION: i64 = 1;


const SECOND_VERSION: i64 = 2;


const HEX_LENGTH: usize = 64;


const CONNECT_SECONDS: u64 = 5;


const TEN_MEGABYTES: usize = 10_485_760;


const WIDE_CHAR: &str = "\u{1F600}";


async fn seeded() -> Result<(Fixture, String, String), TestError> {
    let fx = fixture()?;
    let own = alert(TENANT, "r1", &["e1"], BASE_TIME);
    store(&fx.db, std::slice::from_ref(&own)).await?;
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token, own.id))
}


async fn post(fx: &Fixture, id: &str, token: Option<&str>, body: &Value) -> Result<(StatusCode, Value), TestError> {
    let response = call(&fx.router, "POST", &format!("/alerts/{id}/triage"), token, Body::from(body.to_string())).await?;
    let status = response.status();
    let json = body_json(response).await.unwrap_or(Value::Null);
    Ok((status, json))
}


async fn post_raw(fx: &Fixture, id: &str, token: &str, body: String) -> Result<StatusCode, TestError> {
    let response = call(&fx.router, "POST", &format!("/alerts/{id}/triage"), Some(token), Body::from(body)).await?;
    Ok(response.status())
}


fn code(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


fn message(json: &Value) -> &str {
    json.get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("")
}


fn counting(calls: &Arc<AtomicUsize>) -> Backend {
    let counted = Arc::clone(calls);
    Backend {
        list: Arc::new(|_scope, _page| Box::pin(async { Err(StoreError::Busy) })),
        get: Arc::new(|_scope, _id| Box::pin(async { Ok(None) })),
        triage: Arc::new(move |_scope, _id, change, _expected| {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(Triage {
                    status: change.status,
                    actor: change.actor,
                    note: change.note,
                    updated_at: BASE_TIME,
                    version: FIRST_VERSION,
                })
            })
        }),
        clock: fixed_clock,
    }
}


#[tokio::test]
async fn acknowledge_then_close_walks_the_versions() -> TestResult {
    let (fx, token, id) = seeded().await?;
    let (status, first) = post(&fx, &id, Some(&token), &json!({"status": "acknowledged"})).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        first,
        json!({"status": "acknowledged", "actor": ANALYST, "note": null, "updated_at": "2023-11-14T22:13:20Z", "version": FIRST_VERSION})
    );
    let (again, body) = post(&fx, &id, Some(&token), &json!({"status": "closed"})).await?;
    assert_eq!(again, StatusCode::CONFLICT);
    assert_eq!(code(&body), Some("triage_changed"));
    let (closed, second) = post(
        &fx,
        &id,
        Some(&token),
        &json!({"status": "closed", "note": "done", "version": FIRST_VERSION}),
    )
    .await?;
    assert_eq!(closed, StatusCode::OK);
    assert_eq!(second.get("version"), Some(&json!(SECOND_VERSION)));
    assert_eq!(second.get("note"), Some(&json!("done")));
    let (stale, _) = post(&fx, &id, Some(&token), &json!({"status": "acknowledged", "version": FIRST_VERSION})).await?;
    assert_eq!(stale, StatusCode::CONFLICT);
    let detail = body_json(get(&fx.router, &format!("/alerts/{id}"), Some(&token)).await?).await?;
    let triage = detail.get("triage").ok_or("no triage")?;
    assert_eq!(triage.get("status"), Some(&json!("closed")));
    assert_eq!(triage.get("version"), Some(&json!(SECOND_VERSION)));
    assert_eq!(detail.get("rule_id"), Some(&json!("r1")));
    Ok(())
}


#[tokio::test]
async fn the_detail_shows_no_triage_until_one_is_written_and_the_list_has_no_field() -> TestResult {
    let (fx, token, id) = seeded().await?;
    let detail = body_json(get(&fx.router, &format!("/alerts/{id}"), Some(&token)).await?).await?;
    assert_eq!(detail.get("triage"), Some(&Value::Null));
    let list = body_json(get(&fx.router, "/alerts", Some(&token)).await?).await?;
    let first = list
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or("no item")?;
    assert!(first.get("triage").is_none());
    Ok(())
}


#[tokio::test]
async fn a_reader_is_forbidden_and_no_token_is_unauthorised_and_nothing_is_written() -> TestResult {
    let (fx, _token, id) = seeded().await?;
    let reader = login(&fx.router, READER).await?;
    let (denied, _) = post(&fx, &id, Some(&reader), &json!({"status": "closed"})).await?;
    assert_eq!(denied, StatusCode::FORBIDDEN);
    let (anonymous, _) = post(&fx, &id, None, &json!({"status": "closed"})).await?;
    assert_eq!(anonymous, StatusCode::UNAUTHORIZED);
    assert!(lock(&fx.db.triage).is_empty());
    Ok(())
}


#[tokio::test]
async fn forged_fields_and_bad_values_are_400_naming_the_field() -> TestResult {
    let (fx, token, id) = seeded().await?;
    let bodies = [
        json!({"status": "closed", "actor": "root"}),
        json!({"status": "closed", "tenant": OTHER_TENANT}),
        json!({"status": "deleted"}),
        json!({"note": "x"}),
        json!({"status": "closed", "version": "1"}),
    ];
    for body in &bodies {
        let (status, json) = post(&fx, &id, Some(&token), body).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(message(&json).contains("`status`") && !message(&json).contains(OTHER_TENANT), "{json}");
    }
    let (zero, version) = post(&fx, &id, Some(&token), &json!({"status": "closed", "version": 0})).await?;
    assert_eq!(zero, StatusCode::BAD_REQUEST);
    assert!(message(&version).contains("`version`"));
    let (negative, _) = post(&fx, &id, Some(&token), &json!({"status": "closed", "version": -1})).await?;
    assert_eq!(negative, StatusCode::BAD_REQUEST);
    assert_eq!(post_raw(&fx, &id, &token, "{".to_owned()).await?, StatusCode::BAD_REQUEST);
    assert!(lock(&fx.db.triage).is_empty());
    Ok(())
}


#[tokio::test]
async fn another_tenants_alert_and_unknown_ids_are_404_and_write_nothing() -> TestResult {
    let (fx, token, _id) = seeded().await?;
    let other = alert(OTHER_TENANT, "r9", &["e9"], BASE_TIME);
    store(&fx.db, std::slice::from_ref(&other)).await?;
    let (foreign, body) = post(&fx, &other.id, Some(&token), &json!({"status": "closed"})).await?;
    assert_eq!(foreign, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), Some("not_found"));
    let (absent, _) = post(&fx, &"0".repeat(HEX_LENGTH), Some(&token), &json!({"status": "closed"})).await?;
    assert_eq!(absent, StatusCode::NOT_FOUND);
    assert!(lock(&fx.db.triage).is_empty());
    Ok(())
}


#[tokio::test]
async fn refused_input_never_reaches_the_store() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let fx = fixture_with(|_db| counting(&calls))?;
    let token = login(&fx.router, ANALYST).await?;
    let id = "a".repeat(HEX_LENGTH);
    let long = "x".repeat(MAX_NOTE_CHARS + 1);
    let refused = [
        (id.clone(), json!({"status": "closed", "note": long})),
        (id.clone(), json!({"status": "closed", "note": "bad\u{0}note"})),
        (id.clone(), json!({"status": "closed", "note": ""})),
        (id.clone(), json!({"status": "closed", "version": 0})),
        ("abc".to_owned(), json!({"status": "closed"})),
        (id.to_uppercase(), json!({"status": "closed"})),
        ("%ff".to_owned(), json!({"status": "closed"})),
    ];
    for (target, body) in &refused {
        let status = post_raw(&fx, target, &token, body.to_string()).await?;
        assert!(status.is_client_error(), "{body}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let exact = json!({"status": "closed", "note": "x".repeat(MAX_NOTE_CHARS)});
    assert_eq!(post_raw(&fx, &id, &token, exact.to_string()).await?, StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}


#[tokio::test]
async fn a_note_of_wide_characters_fits_the_route_limit_and_a_huge_body_is_413() -> TestResult {
    let (fx, token, id) = seeded().await?;
    let body = format!("{{\"status\":\"closed\",\"note\":\"{}\"}}", WIDE_CHAR.repeat(MAX_NOTE_CHARS));
    assert!(body.len() <= TRIAGE_BODY_LIMIT);
    assert_eq!(post_raw(&fx, &id, &token, body).await?, StatusCode::OK);
    let over_route_limit = format!("{{\"status\":\"closed\",\"note\":\"{}\"}}", "x".repeat(TRIAGE_BODY_LIMIT + 1));
    assert_eq!(post_raw(&fx, &id, &token, over_route_limit).await?, StatusCode::PAYLOAD_TOO_LARGE);
    let huge = format!("{{\"status\":\"closed\",\"note\":\"{}\"}}", "x".repeat(TEN_MEGABYTES));
    assert_eq!(post_raw(&fx, &id, &token, huge).await?, StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}


#[tokio::test]
async fn store_failures_are_429_or_a_generic_500() -> TestResult {
    let (fx, token, id) = seeded().await?;
    lock(&fx.db.forced).push_back(Forced::Fail);
    let (failed, body) = post(&fx, &id, Some(&token), &json!({"status": "closed"})).await?;
    assert_eq!(failed, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.to_string().contains("XX000"));
    let busy = fixture_with(|_db| Backend {
        triage: busy_triage(),
        ..counting(&Arc::new(AtomicUsize::new(0)))
    })?;
    let busy_token = login(&busy.router, ANALYST).await?;
    let (limited, _) = post(&busy, &id, Some(&busy_token), &json!({"status": "closed"})).await?;
    assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}


#[tokio::test]
async fn a_triage_that_cannot_be_rendered_is_a_generic_500() -> TestResult {
    let huge = Triage {
        status: TriageStatus::Closed,
        actor: ANALYST.to_owned(),
        note: None,
        updated_at: u64::MAX,
        version: FIRST_VERSION,
    };
    let written = huge.clone();
    let read = huge;
    let fx = fixture_with(move |_db| Backend {
        get: Arc::new(move |_scope, _id| {
            let triage = read.clone();
            Box::pin(async move {
                Ok(Some(AlertDetail {
                    alert: alert(TENANT, "r1", &["e1"], BASE_TIME),
                    triage: Some(triage),
                }))
            })
        }),
        triage: Arc::new(move |_scope, _id, _change, _expected| {
            let triage = written.clone();
            Box::pin(async move { Ok(triage) })
        }),
        ..counting(&Arc::new(AtomicUsize::new(0)))
    })?;
    let token = login(&fx.router, ANALYST).await?;
    let id = "a".repeat(HEX_LENGTH);
    let (status, _) = post(&fx, &id, Some(&token), &json!({"status": "closed"})).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let detail = get(&fx.router, &format!("/alerts/{id}"), Some(&token)).await?;
    assert_eq!(detail.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}


#[tokio::test]
async fn a_request_without_a_session_is_never_written() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = counting(&calls);
    let identity = ApiIdentity {
        module: "alerts".to_owned(),
        tenant: TENANT.to_owned(),
        generation: 0,
    };
    let request = TriageRequest {
        status: TriageStatus::Closed,
        note: None,
        version: None,
    };
    let refused = triage_flow(&identity, None, &backend, Ok("a".repeat(HEX_LENGTH)), Ok(request)).await;
    assert!(matches!(refused, Err(ApiError::Internal)));
    let unusable = ApiIdentity {
        module: "alerts".to_owned(),
        tenant: "-x".to_owned(),
        generation: 0,
    };
    let again = TriageRequest {
        status: TriageStatus::Closed,
        note: None,
        version: None,
    };
    let refused_tenant = triage_flow(&unusable, None, &backend, Ok("a".repeat(HEX_LENGTH)), Ok(again)).await;
    assert!(matches!(refused_tenant, Err(ApiError::Internal)));
    assert!(matches!(actor_of(None), Err(ApiError::Internal)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn the_document_describes_the_route_and_the_detail_triage() -> TestResult {
    let document = serde_json::to_value(alerts_document())?;
    let route = document
        .get("paths")
        .and_then(|paths| paths.get("/alerts/{id}/triage"))
        .ok_or("no route")?;
    assert!(route.get("post").is_some());
    let schemas = document
        .get("components")
        .and_then(|components| components.get("schemas"))
        .ok_or("no schemas")?;
    assert!(["TriageRequest", "TriageView", "AlertDetailView", "TriageStatus"]
        .iter()
        .all(|name| schemas.get(*name).is_some()));
    assert!(schemas.get("AlertDetailView").is_some_and(|detail| detail.to_string().contains("triage")));
    Ok(())
}


#[tokio::test]
async fn a_query_string_on_triage_is_400_and_never_reaches_the_store() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let fx = fixture_with(|_db| counting(&calls))?;
    let token = login(&fx.router, ANALYST).await?;
    let id = "a".repeat(HEX_LENGTH);
    let body = json!({"status": "closed"}).to_string();
    for query in ["tenant=b", "x=1", "version=2"] {
        let response = call(
            &fx.router,
            "POST",
            &format!("/alerts/{id}/triage?{query}"),
            Some(&token),
            Body::from(body.clone()),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn a_connect_deadline_is_503_unavailable_on_every_route() -> TestResult {
    let fx = fixture_with(|_db| Backend {
        list: Arc::new(|_scope, _page| Box::pin(async { Err(StoreError::Pg(PgError::ConnectTimeout { seconds: CONNECT_SECONDS })) })),
        get: Arc::new(|_scope, _id| Box::pin(async { Err(StoreError::Pg(PgError::ConnectTimeout { seconds: CONNECT_SECONDS })) })),
        triage: Arc::new(|_scope, _id, _change, _expected| {
            Box::pin(async { Err(StoreError::Pg(PgError::ConnectTimeout { seconds: CONNECT_SECONDS })) })
        }),
        clock: fixed_clock,
    })?;
    let token = login(&fx.router, ANALYST).await?;
    let id = "a".repeat(HEX_LENGTH);
    let (triaged, triage_body) = post(&fx, &id, Some(&token), &json!({"status": "closed"})).await?;
    assert_eq!(triaged, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(code(&triage_body), Some("unavailable"));
    assert!(!triage_body.to_string().contains("deadline"));
    for path in ["/alerts".to_owned(), format!("/alerts/{id}")] {
        let response = get(&fx.router, &path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
    }
    Ok(())
}


#[test]
fn a_too_large_triage_time_names_updated_at() -> TestResult {
    let change = TriageChange {
        status: TriageStatus::Closed,
        actor: "u".to_owned(),
        note: None,
        now: u64::MAX,
    };
    let refused = check_triage(&"a".repeat(HEX_LENGTH), &change).err().ok_or("accepted")?;
    assert!(matches!(refused, StoreError::BadUpdatedAt));
    assert!(refused.to_string().contains("updated_at"));
    Ok(())
}


#[test]
fn the_clock_reads_current_microseconds() -> TestResult {
    assert!(unix_micros() > BASE_TIME);
    Ok(())
}
