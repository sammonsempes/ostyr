mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
#[path = "../common/posture_fake.rs"]
mod posture_fake;
mod types;


use alerts::error::StoreError as LeaseError;
use axum::body::to_bytes;
use axum::http::StatusCode;
use cloud_posture::api::{failure_category, failure_response, parse_limit, posture_access, posture_document, read_view, run_view, scope_of};
use cloud_posture::error::StoreError;
use cloud_posture::model::{FindingsPage, RunHeader, Severity};
use cloud_posture::page::MAX_PAGE_LIMIT;
use core_api::model::ApiIdentity;
use core_pg::error::PgError;
use fixture::{fixture, fixture_over, keep, other_router, router_of, ANALYST, AUDITOR, OTHER_TENANT, READER, TENANT};
use http::{body_json, get, login};
use posture_fake::{capture_dispatch, captured, finding, put, run_of, statements, Capture, Fake};
use serde_json::{json, Value};
use std::sync::Arc;
use types::{Failure, TestError, TestResult};


const ACCOUNT: &str = "123456789012";


const FINISHED: i64 = 1_700_000_000_000_000;


const NEWER: i64 = FINISHED + 1;


const HUGE_CURSOR: usize = 60_000;


const OVER_LIMIT: usize = 257;


const FIVE: usize = 5;


const TIME_UNIX: i64 = 1_700_000_000;


const SHOWN_CHARS: usize = 40;


const PAIR: usize = 2;


const CAUSES: usize = 3;


const CUT_BYTES: usize = 7;


const PRINTABLE_FIRST: u8 = 0x20;


const PRINTABLE_LAST: u8 = 0x7e;


const FAILURES: usize = 7;


const REFUSED: u64 = 2;


const AUDITED_READS: usize = 2;


const MARKER: &str = "SECRET-MARKER-7f3a";


fn path_of(account: &str, query: &str) -> String {
    format!("/posture/accounts/{account}/findings{query}")
}


fn encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}


fn items(json: &Value) -> Result<&Vec<Value>, TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


fn uids(json: &Value) -> Result<Vec<String>, TestError> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| item.get("uid").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}


fn code_of(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


fn five_findings(account: &str) -> Vec<cloud_posture::model::Finding> {
    [Severity::Low, Severity::Critical, Severity::High, Severity::Medium, Severity::Fatal]
        .into_iter()
        .enumerate()
        .map(|(index, severity)| finding(account, &format!("u{index}"), severity))
        .collect()
}


fn seed(fake: &Fake) {
    put(fake, run_of(TENANT, ACCOUNT, "run-a", FINISHED, five_findings(ACCOUNT)));
    put(
        fake,
        run_of(OTHER_TENANT, ACCOUNT, "run-b", FINISHED, vec![finding(ACCOUNT, "b-only", Severity::High)]),
    );
}


async fn raw_body(response: axum::http::Response<axum::body::Body>) -> Result<Vec<u8>, TestError> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}


#[tokio::test]
async fn the_default_page_is_the_tenants_run_by_severity_with_its_header() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, &path_of(ACCOUNT, ""), Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_json(response).await?;
    assert_eq!(uids(&page)?, ["u4", "u1", "u2", "u3", "u0"]);
    assert_eq!(page.get("next_cursor"), Some(&Value::Null));
    assert_eq!(page.get("unservable"), Some(&json!(0)));
    let run = page.get("run").ok_or("no run")?;
    assert_eq!(run.get("run_id"), Some(&json!("run-a")));
    assert_eq!(run.get("finished_micros"), Some(&json!(FINISHED)));
    assert_eq!(run.get("items"), Some(&json!(FIVE)));
    assert_eq!(run.get("refused_micros"), Some(&Value::Null));
    assert_eq!(run.get("refusal_pending"), Some(&json!(false)));
    let head = items(&page)?.first().ok_or("empty")?;
    assert_eq!(head.get("severity"), Some(&json!("Fatal")));
    assert_eq!(head.get("status"), Some(&json!("FAIL")));
    assert_eq!(head.get("account"), Some(&json!(ACCOUNT)));
    assert_eq!(head.get("time_unix"), Some(&json!(TIME_UNIX)));
    assert!(head.get("tenant").is_none());
    Ok(())
}


#[tokio::test]
async fn a_refusal_newer_than_the_run_is_pending_and_times_are_integers() -> TestResult {
    let fx = fixture()?;
    let mut run = run_of(TENANT, ACCOUNT, "run-a", FINISHED, five_findings(ACCOUNT));
    run.refused_micros = Some(NEWER);
    put(&fx.fake, run);
    let token = login(&fx.router, ANALYST).await?;
    let page = body_json(get(&fx.router, &path_of(ACCOUNT, "?limit=1"), Some(&token)).await?).await?;
    let header = page.get("run").ok_or("no run")?;
    assert_eq!(header.get("refusal_pending"), Some(&json!(true)));
    assert_eq!(header.get("refused_micros"), Some(&json!(NEWER)));
    Ok(())
}


#[tokio::test]
async fn a_walk_by_cursor_serves_every_finding_once_and_a_replace_is_a_409() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    let token = login(&fx.router, ANALYST).await?;
    let first = body_json(get(&fx.router, &path_of(ACCOUNT, "?limit=2"), Some(&token)).await?).await?;
    let second_path = path_of(
        ACCOUNT,
        &format!(
            "?limit=2&cursor={}",
            encoded(first.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?)
        ),
    );
    let second = body_json(get(&fx.router, &second_path, Some(&token)).await?).await?;
    let third_cursor = second.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let third = body_json(
        get(
            &fx.router,
            &path_of(ACCOUNT, &format!("?limit=2&cursor={}", encoded(&third_cursor))),
            Some(&token),
        )
        .await?,
    )
    .await?;
    let mut walked = uids(&first)?;
    walked.extend(uids(&second)?);
    walked.extend(uids(&third)?);
    assert_eq!(walked, ["u4", "u1", "u2", "u3", "u0"]);
    assert_eq!(third.get("next_cursor"), Some(&Value::Null));
    put(&fx.fake, run_of(TENANT, ACCOUNT, "run-a2", NEWER, five_findings(ACCOUNT)));
    let changed = get(
        &fx.router,
        &path_of(ACCOUNT, &format!("?cursor={}", encoded(&third_cursor))),
        Some(&token),
    )
    .await?;
    assert_eq!(changed.status(), StatusCode::CONFLICT);
    assert_eq!(code_of(&body_json(changed).await?), Some("run_changed"));
    Ok(())
}


#[tokio::test]
async fn refused_queries_are_a_fixed_400_before_any_store_call() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    let token = login(&fx.router, ANALYST).await?;
    let huge = "1".repeat(HUGE_CURSOR);
    let long = "1".repeat(MAX_PAGE_LIMIT + MAX_PAGE_LIMIT);
    let queries = [
        "?limit=0".to_owned(),
        "?limit=501".to_owned(),
        "?limit=%2B5".to_owned(),
        "?limit=".to_owned(),
        "?limit=1.5".to_owned(),
        format!("?limit={long}"),
        "?tenant=globex".to_owned(),
        "?other=1".to_owned(),
        "?cursor=junk".to_owned(),
        format!("?cursor={huge}"),
        "?cursor=run-a%201%203%20abc".to_owned(),
        "?limit=1&limit=2".to_owned(),
    ];
    for query in &queries {
        let response = get(&fx.router, &path_of(ACCOUNT, query), Some(&token)).await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            query.chars().take(SHOWN_CHARS).collect::<String>()
        );
        assert_eq!(code_of(&body_json(response).await?), Some("bad_request"));
    }
    assert_eq!(statements(&fx.fake), 0);
    Ok(())
}


#[tokio::test]
async fn refused_accounts_are_one_fixed_404_with_no_store_call() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    let token = login(&fx.router, ANALYST).await?;
    let long = "a".repeat(OVER_LIMIT);
    let refused = [
        "-x".to_owned(),
        "a%20b".to_owned(),
        "a%00b".to_owned(),
        "%FF".to_owned(),
        "a%09b".to_owned(),
        "a%3Cb".to_owned(),
        long,
    ];
    let mut bodies = Vec::new();
    for account in &refused {
        let response = get(&fx.router, &path_of(account, ""), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{account}");
        bodies.push(raw_body(response).await?);
    }
    assert!(bodies.windows(PAIR).all(|pair| pair.first() == pair.get(1)));
    let with_bad_query = get(&fx.router, &path_of("-x", "?limit=0"), Some(&token)).await?;
    assert_eq!(with_bad_query.status(), StatusCode::NOT_FOUND);
    assert_eq!(statements(&fx.fake), 0);
    Ok(())
}


#[tokio::test]
async fn an_unknown_account_and_another_tenants_account_answer_the_same_empty_run() -> TestResult {
    let fx = fixture()?;
    put(
        &fx.fake,
        run_of(
            OTHER_TENANT,
            "only-b",
            "run-b",
            FINISHED,
            vec![finding("only-b", "b-only", Severity::High)],
        ),
    );
    let token = login(&fx.router, ANALYST).await?;
    let foreign = get(&fx.router, &path_of("only-b", ""), Some(&token)).await?;
    let unknown = get(&fx.router, &path_of("nobody", ""), Some(&token)).await?;
    assert_eq!((foreign.status(), unknown.status()), (StatusCode::OK, StatusCode::OK));
    let foreign_body = raw_body(foreign).await?;
    assert_eq!(foreign_body, raw_body(unknown).await?);
    let parsed: Value = serde_json::from_slice(&foreign_body)?;
    assert_eq!(parsed.get("run"), Some(&Value::Null));
    assert!(items(&parsed)?.is_empty());
    assert_eq!(parsed.get("next_cursor"), Some(&Value::Null));
    assert!(!String::from_utf8_lossy(&foreign_body).contains("b-only"));
    Ok(())
}


#[tokio::test]
async fn a_tenant_never_reads_another_tenants_rows_with_the_same_account_id() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    let other = other_router(&fx.fake)?;
    let token_a = login(&fx.router, ANALYST).await?;
    let token_b = login(&other.router, ANALYST).await?;
    let page_a = body_json(get(&fx.router, &path_of(ACCOUNT, ""), Some(&token_a)).await?).await?;
    let page_b = body_json(get(&other.router, &path_of(ACCOUNT, ""), Some(&token_b)).await?).await?;
    assert_eq!(uids(&page_a)?.len(), FIVE);
    assert_eq!(uids(&page_b)?, ["b-only"]);
    assert_eq!(page_b.pointer("/run/run_id"), Some(&json!("run-b")));
    let forced = get(&fx.router, &path_of(ACCOUNT, "?tenant=globex"), Some(&token_a)).await?;
    assert_eq!(forced.status(), StatusCode::BAD_REQUEST);
    Ok(())
}


#[tokio::test]
async fn every_run_changed_cause_is_one_byte_equal_409() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    put(&fx.fake, run_of(TENANT, "empty-a", "run-e", FINISHED, five_findings("empty-a")));
    let other = other_router(&fx.fake)?;
    let token_a = login(&fx.router, ANALYST).await?;
    let token_b = login(&other.router, ANALYST).await?;
    let walk = body_json(get(&other.router, &path_of(ACCOUNT, "?limit=1"), Some(&token_b)).await?).await?;
    let own = body_json(get(&fx.router, &path_of(ACCOUNT, "?limit=1"), Some(&token_a)).await?).await?;
    let from_b = own.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    assert_eq!(walk.get("next_cursor"), Some(&Value::Null));
    let b_run = body_json(get(&other.router, &path_of(ACCOUNT, ""), Some(&token_b)).await?).await?;
    assert_eq!(uids(&b_run)?.len(), 1);
    put(
        &fx.fake,
        run_of(
            OTHER_TENANT,
            "two",
            "run-b2",
            FINISHED,
            vec![finding("two", "x", Severity::High), finding("two", "y", Severity::Low)],
        ),
    );
    let b_walk = body_json(get(&other.router, &path_of("two", "?limit=1"), Some(&token_b)).await?).await?;
    let b_cursor = b_walk.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    put(
        &fx.fake,
        run_of(TENANT, "two", "run-a-two", FINISHED, vec![finding("two", "x", Severity::High)]),
    );
    let replayed = get(&fx.router, &path_of("two", &format!("?cursor={}", encoded(&b_cursor))), Some(&token_a)).await?;
    let no_run = get(&fx.router, &path_of("nobody", &format!("?cursor={}", encoded(&from_b))), Some(&token_a)).await?;
    let stale = get(&fx.router, &path_of(ACCOUNT, &format!("?cursor={}", encoded(&b_cursor))), Some(&token_a)).await?;
    let bodies = [replayed, no_run, stale];
    let statuses: Vec<StatusCode> = bodies.iter().map(axum::http::Response::status).collect();
    assert_eq!(statuses, [StatusCode::CONFLICT; CAUSES]);
    let mut raw = Vec::new();
    for response in bodies {
        raw.push(raw_body(response).await?);
    }
    assert!(raw.windows(PAIR).all(|pair| pair.first() == pair.get(1)));
    Ok(())
}


#[tokio::test]
async fn hostile_text_is_served_escaped_as_ascii_and_a_cut_stays_visible() -> TestResult {
    let fx = fixture()?;
    let mut hostile = finding(ACCOUNT, "uid\u{1b}[31m\u{202e}x", Severity::Critical);
    hostile.title = "t\u{1b}\u{9b}\u{7f}\u{202e}\u{3164}\\[5 bytes cut]".to_owned();
    hostile.detail = "detail".to_owned();
    hostile.resource_uid = "res-h".to_owned();
    hostile.detail_cut = FIVE;
    let mut plain = finding(ACCOUNT, "plain", Severity::Low);
    plain.title = "cut title".to_owned();
    plain.title_cut = CUT_BYTES;
    put(&fx.fake, run_of(TENANT, ACCOUNT, "run-a", FINISHED, vec![hostile, plain]));
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, &path_of(ACCOUNT, ""), Some(&token)).await?;
    let raw = raw_body(response).await?;
    assert!(
        raw.iter().all(|byte| (PRINTABLE_FIRST..=PRINTABLE_LAST).contains(byte)),
        "non-ASCII byte in the body"
    );
    let page: Value = serde_json::from_slice(&raw)?;
    let first = items(&page)?.first().ok_or("empty")?;
    assert_eq!(first.get("uid"), Some(&json!("uid\\u{1b}[31m\\u{202e}x")));
    assert_eq!(
        first.get("title"),
        Some(&json!("t\\u{1b}\\u{9b}\\u{7f}\\u{202e}\\u{3164}\\u{5c}[5 bytes cut]"))
    );
    assert_eq!(first.get("detail"), Some(&json!("detail\\[5 bytes cut]")));
    assert_eq!(first.get("detail_cut"), Some(&json!(FIVE)));
    let second = items(&page)?.get(1).ok_or("one item")?;
    assert_eq!(second.get("title"), Some(&json!("cut title\\[7 bytes cut]")));
    assert_eq!(second.get("title_cut"), Some(&json!(CUT_BYTES)));
    Ok(())
}


#[tokio::test]
async fn an_unservable_row_is_counted_in_the_header_of_the_page() -> TestResult {
    let fx = fixture()?;
    let mut bad = finding(ACCOUNT, "bad", Severity::High);
    bad.check_id = "bad id".to_owned();
    put(
        &fx.fake,
        run_of(TENANT, ACCOUNT, "run-a", FINISHED, vec![bad, finding(ACCOUNT, "good", Severity::Low)]),
    );
    let token = login(&fx.router, ANALYST).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let guard = tracing::dispatcher::set_default(&dispatch);
    let page = body_json(get(&fx.router, &path_of(ACCOUNT, ""), Some(&token)).await?).await?;
    drop(guard);
    assert_eq!(uids(&page)?, ["good"]);
    assert_eq!(page.get("unservable"), Some(&json!(1)));
    assert!(captured(&capture).contains("unservable=1"));
    Ok(())
}


#[tokio::test]
async fn only_cmdb_read_holders_read_and_a_reader_gets_403_with_an_audit_record() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    let reader = login(&fx.router, READER).await?;
    let denied = get(&fx.router, &path_of(ACCOUNT, ""), Some(&reader)).await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let auditor = login(&fx.router, AUDITOR).await?;
    assert_eq!(get(&fx.router, &path_of(ACCOUNT, ""), Some(&auditor)).await?.status(), StatusCode::OK);
    assert_eq!(get(&fx.router, &path_of(ACCOUNT, ""), None).await?.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(statements(&fx.fake), 1);
    let log = std::fs::read_to_string(fx._dir.path().join("audit.log"))?;
    assert!(
        log.matches("\"target\":\"GET /posture/accounts/{account}/findings\"").count() >= AUDITED_READS,
        "{log}"
    );
    Ok(())
}


#[tokio::test]
async fn an_analyst_read_is_audited_by_route_pattern_never_by_account_or_cursor() -> TestResult {
    let fx = fixture()?;
    seed(&fx.fake);
    let token = login(&fx.router, ANALYST).await?;
    let before = std::fs::read_to_string(fx._dir.path().join("audit.log"))?;
    let cursor = encoded("run-a 1 3 abc");
    get(&fx.router, &path_of(ACCOUNT, &format!("?limit=1&cursor={cursor}")), Some(&token)).await?;
    get(&fx.router, &path_of(ACCOUNT, "?limit=1"), Some(&token)).await?;
    let log = std::fs::read_to_string(fx._dir.path().join("audit.log"))?;
    let added = log.strip_prefix(&before).ok_or("log rewritten")?;
    assert_eq!(
        added.matches("\"target\":\"GET /posture/accounts/{account}/findings\"").count(),
        AUDITED_READS,
        "{added}"
    );
    assert!(!added.contains(ACCOUNT), "{added}");
    assert!(
        !added.contains("run-a") && !added.contains("limit=") && !added.contains("cursor"),
        "{added}"
    );
    assert!(added.contains("\"tenant\":\"acme\"") && added.contains(ANALYST), "{added}");
    Ok(())
}


#[tokio::test]
async fn a_failed_audit_append_answers_500() -> TestResult {
    let fx = fixture_over(Arc::new(Fake::default()), TENANT, keep)?;
    seed(&fx.fake);
    let token = login(&fx.router, ANALYST).await?;
    fx.state.audit.state.lock().map_err(|_poisoned| "poisoned")?.poisoned = true;
    let response = get(&fx.router, &path_of(ACCOUNT, ""), Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}


#[tokio::test]
async fn store_failures_are_fixed_answers_and_only_the_category_is_logged() -> TestResult {
    let failures: [Failure; FAILURES] = [
        (|| StoreError::Lease(LeaseError::Busy), StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
        (
            || StoreError::Pg(PgError::NotRegular { file: MARKER.to_owned() }),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
        ),
        (|| StoreError::StoredValue, StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        (|| StoreError::BadAnswer, StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        (|| StoreError::RunChanged, StatusCode::CONFLICT, "run_changed"),
        (|| StoreError::BadAccount, StatusCode::NOT_FOUND, "not_found"),
        (|| StoreError::BadCursor, StatusCode::BAD_REQUEST, "bad_request"),
    ];
    for (make, status, code) in failures {
        let backend = cloud_posture::api_model::PostureBackend {
            read: Arc::new(move |_scope, _account, _cursor, _limit| Box::pin(async move { Err(make()) })),
        };
        let fx = router_of(backend)?;
        let token = login(&fx.router, ANALYST).await?;
        let capture = Capture::default();
        let dispatch = capture_dispatch(&capture);
        let guard = tracing::dispatcher::set_default(&dispatch);
        let response = get(&fx.router, &path_of(ACCOUNT, ""), Some(&token)).await?;
        drop(guard);
        assert_eq!(response.status(), status);
        let raw = raw_body(response).await?;
        assert_eq!(code_of(&serde_json::from_slice(&raw)?), Some(code));
        assert!(!String::from_utf8_lossy(&raw).contains(MARKER));
        assert!(!captured(&capture).contains(MARKER), "{}", captured(&capture));
    }
    Ok(())
}


#[test]
fn categories_limits_and_scopes_are_checked_by_hand() -> TestResult {
    assert_eq!(failure_category(&StoreError::Lease(LeaseError::Busy)), "database");
    assert_eq!(failure_category(&StoreError::StoredValue), "stored_value");
    assert_eq!(failure_category(&StoreError::BadAnswer), "bad_answer");
    assert_eq!(failure_category(&StoreError::BadCursor), "request");
    assert_eq!(failure_response(&StoreError::BadQuery).status(), StatusCode::BAD_REQUEST);
    assert_eq!(parse_limit(None)?, cloud_posture::api::DEFAULT_PAGE_LIMIT);
    assert_eq!(parse_limit(Some("500"))?, MAX_PAGE_LIMIT);
    assert!(["0", "501", "", "+1", "1 ", "99999999999999999999999"]
        .iter()
        .all(|text| parse_limit(Some(text)).is_err()));
    let identity = ApiIdentity {
        module: "cloud-posture".to_owned(),
        tenant: "-bad".to_owned(),
        generation: 0,
    };
    assert!(scope_of(&identity).is_err());
    assert_eq!(posture_access().len(), 1);
    assert!(posture_access().values().all(|rule| rule.sensitive));
    assert!(posture_document().paths.paths.contains_key("/posture/accounts/{account}/findings"));
    Ok(())
}


#[test]
fn a_page_without_a_run_is_the_empty_view() -> TestResult {
    let empty = read_view(&FindingsPage {
        run: None,
        items: Vec::new(),
        unservable: 0,
        next: None,
    });
    assert_eq!(
        serde_json::to_value(&empty)?,
        json!({"run": null, "unservable": 0, "items": [], "next_cursor": null})
    );
    let header = RunHeader {
        run_id: None,
        finished_micros: None,
        items: 0,
        unparsable: 0,
        bad_field: 0,
        duplicate: 0,
        foreign_account: 0,
        refused_pass: 0,
        refused_muted: 0,
        refused_manual: 0,
        refused_fail: 0,
        store_refused: 0,
        refused_micros: Some(1),
        refused_items: REFUSED,
    };
    let view = run_view(&header);
    assert!(view.refusal_pending);
    assert_eq!((view.run_id, view.finished_micros, view.refused_items), (None, None, REFUSED));
    Ok(())
}
