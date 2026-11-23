use crate::fixture::{
    alert, busy_triage, fixed_clock, fixture, fixture_adjusted, fixture_with, frozen_clock, memory_backend, store, with_frozen_clock, Fixture,
    ANALYST, BASE_TIME, OTHER_TENANT, READER, TENANT,
};
use crate::http::{body_json, call, get, login};
use crate::memory::{lock, Forced};
use crate::types::{TestError, TestResult};
use alerts::api::{actor_of, alerts_document, request_id_of, triage_entry, triage_flow, TRIAGE_AUDIT_KEYS, TRIAGE_BODY_LIMIT};
use alerts::backend::unix_micros;
use alerts::error::StoreError;
use alerts::model::{AlertDetail, AuditStamp, Backend, Triage, TriageChange, TriageRequest, TriageStatus, Triaged};
use alerts::store::{check_triage, MAX_NOTE_CHARS};
use axum::body::Body;
use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity, Authenticated, RequestId};
use core_api::routes::BODY_LIMIT_BYTES;
use core_audit::error::AuditError;
use core_audit::model::NewEntry;
use core_pg::error::PgError;
use serde_json::{json, Value};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;


fn accept(_entry: NewEntry) -> Result<(), AuditError> {
    Ok(())
}


const THREE_WRITES: usize = 3;


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
                Ok(Triaged {
                    triage: Triage {
                        status: change.status,
                        actor: change.actor,
                        note: change.note,
                        updated_at: BASE_TIME,
                        version: FIRST_VERSION,
                    },
                    rule_id: "r1".to_owned(),
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
async fn a_note_of_escaped_controls_fits_the_limit_and_one_byte_more_is_413() -> TestResult {
    let (fx, token, id) = seeded().await?;
    assert_eq!(TRIAGE_BODY_LIMIT.min(BODY_LIMIT_BYTES), TRIAGE_BODY_LIMIT);
    let escaped = serde_json::to_string(&json!({"status": "closed", "note": "\u{1}".repeat(MAX_NOTE_CHARS)}))?;
    assert!(escaped.len() <= TRIAGE_BODY_LIMIT);
    assert_eq!(post_raw(&fx, &id, &token, escaped.clone()).await?, StatusCode::OK);
    let padded = format!("{escaped}{}", " ".repeat(TRIAGE_BODY_LIMIT - escaped.len()));
    assert_eq!(padded.len(), TRIAGE_BODY_LIMIT);
    assert_eq!(post_raw(&fx, &id, &token, padded.clone()).await?, StatusCode::CONFLICT);
    let over = format!("{padded} ");
    assert_eq!(post_raw(&fx, &id, &token, over).await?, StatusCode::PAYLOAD_TOO_LARGE);
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
            Box::pin(async move {
                Ok(Triaged {
                    triage,
                    rule_id: "r1".to_owned(),
                })
            })
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
    let refused = triage_flow(&identity, None, &backend, Ok("a".repeat(HEX_LENGTH)), Ok(request), stamp(), &accept).await;
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
    let refused_tenant = triage_flow(&unusable, None, &backend, Ok("a".repeat(HEX_LENGTH)), Ok(again), stamp(), &accept).await;
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


fn triage_records(fx: &Fixture) -> Result<Vec<Value>, TestError> {
    let text = fs::read_to_string(fx._dir.path().join("audit.log"))?;
    let records = text.lines().map(serde_json::from_str::<Value>).collect::<Result<Vec<_>, _>>()?;
    Ok(records
        .into_iter()
        .filter(|record| record.get("action") == Some(&json!("alerts.triage")))
        .collect())
}


fn lock_audit(fx: &Fixture) -> TestResult {
    fx.state.audit.state.lock().map_err(|_poisoned| "audit lock")?.poisoned = true;
    Ok(())
}


fn refuse(_entry: NewEntry) -> Result<(), AuditError> {
    Err(AuditError::LogPoisoned)
}


fn identity() -> ApiIdentity {
    ApiIdentity {
        module: "alerts".to_owned(),
        tenant: TENANT.to_owned(),
        generation: 0,
    }
}


#[tokio::test]
async fn a_false_positive_needs_a_note_and_the_others_keep_it_optional() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let fx = fixture_with(|_db| counting(&calls))?;
    let token = login(&fx.router, ANALYST).await?;
    let id = "a".repeat(HEX_LENGTH);
    let (missing, body) = post(&fx, &id, Some(&token), &json!({"status": "false_positive"})).await?;
    assert_eq!(missing, StatusCode::BAD_REQUEST);
    assert!(message(&body).contains("`note`"), "{body}");
    let (empty, _) = post(&fx, &id, Some(&token), &json!({"status": "false_positive", "note": ""})).await?;
    assert_eq!(empty, StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (verdict, stored) = post(&fx, &id, Some(&token), &json!({"status": "false_positive", "note": "noise"})).await?;
    assert_eq!(verdict, StatusCode::OK);
    assert_eq!(stored.get("status"), Some(&json!("false_positive")));
    for status in ["acknowledged", "closed"] {
        let (done, _) = post(&fx, &id, Some(&token), &json!({"status": status})).await?;
        assert_eq!(done, StatusCode::OK, "{status}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), THREE_WRITES);
    Ok(())
}


#[tokio::test]
async fn other_spellings_of_the_verdict_are_the_typed_body_400() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let fx = fixture_with(|_db| counting(&calls))?;
    let token = login(&fx.router, ANALYST).await?;
    let id = "a".repeat(HEX_LENGTH);
    for spelling in [
        "falsepositive",
        "False_Positive",
        " false_positive",
        "false_positive ",
        "FALSE_POSITIVE",
        "false-positive",
    ] {
        let (status, body) = post(&fx, &id, Some(&token), &json!({"status": spelling, "note": "x"})).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{spelling}");
        assert!(message(&body).contains("`body`") && message(&body).contains("false_positive"), "{body}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}


#[tokio::test]
async fn each_successful_write_is_audited_without_the_note_and_each_refusal_is_not() -> TestResult {
    let (fx, token, id) = seeded().await?;
    let reader = login(&fx.router, READER).await?;
    let other = alert(OTHER_TENANT, "r9", &["e9"], BASE_TIME);
    store(&fx.db, std::slice::from_ref(&other)).await?;
    let secret_note = "the-secret-note-text";
    post(&fx, &id, Some(&reader), &json!({"status": "false_positive", "note": secret_note})).await?;
    post(&fx, &other.id, Some(&token), &json!({"status": "false_positive", "note": secret_note})).await?;
    post(&fx, &id, Some(&token), &json!({"status": "false_positive"})).await?;
    post(&fx, &id, Some(&token), &json!({"status": "closed", "version": FIRST_VERSION})).await?;
    assert!(triage_records(&fx)?.is_empty());
    let (written, _) = post(&fx, &id, Some(&token), &json!({"status": "false_positive", "note": secret_note})).await?;
    assert_eq!(written, StatusCode::OK);
    let (next, _) = post(&fx, &id, Some(&token), &json!({"status": "acknowledged", "version": FIRST_VERSION})).await?;
    assert_eq!(next, StatusCode::OK);
    let records = triage_records(&fx)?;
    assert_eq!(records.len(), SECOND_VERSION as usize);
    let first = records.first().ok_or("no record")?;
    assert_eq!(
        (first.get("actor_id"), first.get("tenant"), first.get("target"), first.get("outcome")),
        (Some(&json!(ANALYST)), Some(&json!(TENANT)), Some(&json!(id)), Some(&json!("success")))
    );
    assert_eq!(
        first.get("parameters"),
        Some(&json!({"rule_id": "r1", "status": "false_positive", "version": "1", "note_chars": secret_note.len().to_string()}))
    );
    let second = records.get(1).ok_or("no second record")?;
    assert_eq!(
        second.get("parameters"),
        Some(&json!({"rule_id": "r1", "status": "acknowledged", "version": "2", "note_chars": "0"}))
    );
    assert!(!fs::read_to_string(fx._dir.path().join("audit.log"))?.contains(secret_note));
    Ok(())
}


#[tokio::test]
async fn a_failed_audit_append_is_the_generic_500_after_the_row_is_written() -> TestResult {
    let (fx, token, id) = seeded().await?;
    lock_audit(&fx)?;
    let (failed, body) = post(&fx, &id, Some(&token), &json!({"status": "false_positive", "note": "noise"})).await?;
    assert_eq!(failed, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.to_string().contains("noise"));
    assert_eq!(lock(&fx.db.triage).len(), 1);
    Ok(())
}


#[tokio::test]
async fn the_flow_answers_500_when_the_injected_audit_refuses() -> TestResult {
    let backend = counting(&Arc::new(AtomicUsize::new(0)));
    let session = Authenticated {
        user: ANALYST.to_owned(),
        token: "t".to_owned().into(),
    };
    let request = TriageRequest {
        status: TriageStatus::FalsePositive,
        note: Some("n".to_owned()),
        version: None,
    };
    let outcome = triage_flow(
        &identity(),
        Some(&session),
        &backend,
        Ok("a".repeat(HEX_LENGTH)),
        Ok(request),
        stamp(),
        &refuse,
    )
    .await;
    assert!(matches!(outcome, Err(ApiError::Internal)));
    Ok(())
}


#[test]
fn the_entry_names_actor_tenant_alert_rule_status_version_and_the_note_length_only() -> TestResult {
    let written = Triaged {
        triage: Triage {
            status: TriageStatus::FalsePositive,
            actor: ANALYST.to_owned(),
            note: Some("secret".to_owned()),
            updated_at: BASE_TIME,
            version: SECOND_VERSION,
        },
        rule_id: "r7".to_owned(),
    };
    let entry = triage_entry(&identity(), ANALYST, "abc", "rid", &written, 1, frozen_clock());
    assert_eq!(
        (
            entry.actor.id.as_str(),
            entry.tenant.as_str(),
            entry.target.as_str(),
            entry.request_id.as_str(),
            entry.action.as_str()
        ),
        (ANALYST, TENANT, "abc", "rid", "alerts.triage")
    );
    assert!(entry.parameters.values().all(|value| value != "secret"));
    assert_eq!(entry.parameters.len(), TRIAGE_AUDIT_KEYS.len());
    assert!(TRIAGE_AUDIT_KEYS.iter().all(|key| entry.parameters.contains_key(*key)));
    assert_eq!(request_id_of(None), "none");
    assert_eq!(request_id_of(Some(&RequestId("x".to_owned()))), "x");
    Ok(())
}


#[test]
fn the_verdict_is_a_status_with_its_exact_wire_text() -> TestResult {
    assert_eq!(TriageStatus::FalsePositive.to_string(), "false_positive");
    assert_eq!("false_positive".parse::<TriageStatus>()?, TriageStatus::FalsePositive);
    assert_eq!(serde_json::to_value(TriageStatus::FalsePositive)?, json!("false_positive"));
    assert_eq!(serde_json::to_value(TriageStatus::Acknowledged)?, json!("acknowledged"));
    assert_eq!(serde_json::to_value(TriageStatus::Closed)?, json!("closed"));
    for spelling in ["falsepositive", "False_Positive", " false_positive", ""] {
        assert!(spelling.parse::<TriageStatus>().is_err(), "{spelling}");
    }
    assert!(serde_json::to_string(&alerts_document())?.contains("false_positive"));
    Ok(())
}


#[tokio::test]
async fn a_false_positive_note_needs_a_visible_letter_or_number() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let fx = fixture_with(|_db| counting(&calls))?;
    let token = login(&fx.router, ANALYST).await?;
    let id = "a".repeat(HEX_LENGTH);
    for note in ["   ", "\u{200B}", "\u{3164}", "\u{0301}", "-", ".", "\u{3164}\u{FFA0}\u{2800}\u{0301} -"] {
        let (status, body) = post(&fx, &id, Some(&token), &json!({"status": "false_positive", "note": note})).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{note:?}");
        assert!(message(&body).contains("`note`"), "{body}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    for note in ["x", "\u{0663}", "\u{00E9}", "\u{3164} ok"] {
        let (status, _) = post(&fx, &id, Some(&token), &json!({"status": "false_positive", "note": note})).await?;
        assert_eq!(status, StatusCode::OK, "{note:?}");
    }
    let (kept, _) = post(&fx, &id, Some(&token), &json!({"status": "closed", "note": " "})).await?;
    assert_eq!(kept, StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn the_audit_record_carries_the_injected_clock() -> TestResult {
    let fx = fixture_adjusted(with_frozen_clock, memory_backend)?;
    let own = alert(TENANT, "r1", &["e1"], BASE_TIME);
    store(&fx.db, std::slice::from_ref(&own)).await?;
    let token = login(&fx.router, ANALYST).await?;
    let (status, _) = post(&fx, &own.id, Some(&token), &json!({"status": "closed"})).await?;
    assert_eq!(status, StatusCode::OK);
    let records = triage_records(&fx)?;
    let record = records.first().ok_or("no record")?;
    assert_eq!(record.get("timestamp"), Some(&json!(frozen_clock().format(&Rfc3339)?)));
    Ok(())
}


fn stamp() -> AuditStamp<'static> {
    AuditStamp {
        request_id: "rid",
        timestamp: frozen_clock(),
    }
}
