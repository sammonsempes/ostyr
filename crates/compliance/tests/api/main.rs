mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
#[path = "../common/state_fake.rs"]
mod state_fake;
#[path = "../common/types.rs"]
mod types;


use alerts::error::StoreError as LeaseError;
use axum::http::StatusCode;
use compliance::alerting::MAX_ASSET_CHARS;
use compliance::api::{
    asset_flow, asset_view, compliance_access, compliance_document, failure_category, list_flow, list_view, parse_baseline, parse_limit,
    parse_verdict, request_of, rfc3339, scope_of, store_failure, views_of,
};
use compliance::api_model::{ListQuery, StateBackend};
use compliance::error::ReadError;
use compliance::read::{encode_cursor, DEFAULT_LIMIT, MAX_ASSET_RESULTS, MAX_CURSOR_HEX, MAX_PAGE};
use compliance::read_model::{AssetResults, StatePage, StoredState};
use core_api::model::{ApiError, ApiIdentity};
use core_pg::error::PgError;
use fixture::{fixture, fixture_with, memory_backend, put_row, read_count, ANALYST, OTHER_TENANT, READER, TENANT};
use http::{body_json, call, get, login};
use serde_json::{json, Value};
use state_fake::{capture_dispatch, captured, Capture};
use std::sync::Arc;
use types::TestResult;


const MARKER: &str = "SECRET-MARKER-7f3a";


const SEEN: &str = "1700000000000000";


const FAILED: &str = "1600000000000000";


const HUGE_CURSOR: usize = 60_000;


const SECOND: usize = 2;


const THIRD: usize = 3;


const FOURTH: usize = 4;


const FAR_MICROS: i64 = 253_402_300_800_000_000;


fn items(json: &Value) -> Result<&Vec<Value>, types::TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


fn controls(json: &Value) -> Result<Vec<String>, types::TestError> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| item.get("control").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}


fn code_of(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


fn seed(fx: &fixture::Fixture) {
    put_row(&fx.fake, TENANT, ("base", "c1", "host-a"), ("fail", FAILED, SEEN));
    put_row(&fx.fake, TENANT, ("base", "c2", "host-a"), ("fail", FAILED, SEEN));
    put_row(&fx.fake, TENANT, ("base", "c3", "host-a"), ("fail", FAILED, SEEN));
    put_row(&fx.fake, TENANT, ("base", "c4", "host-a"), ("pass", "", SEEN));
    put_row(&fx.fake, TENANT, ("base", "c5", "host-a"), ("excepted", "", SEEN));
    put_row(&fx.fake, OTHER_TENANT, ("base", "c1", "host-z"), ("fail", FAILED, SEEN));
}


#[tokio::test]
async fn the_default_listing_is_the_failed_rows_of_the_tenant_with_rfc3339_times() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, "/compliance/state", Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_json(response).await?;
    assert_eq!(controls(&page)?, ["c1", "c2", "c3"]);
    assert_eq!(page.get("skipped"), Some(&json!(0)));
    assert_eq!(page.get("next_cursor"), Some(&Value::Null));
    let head = items(&page)?.first().ok_or("empty")?;
    assert_eq!(head.get("first_failed"), Some(&json!("2020-09-13T12:26:40Z")));
    assert_eq!(head.get("last_seen"), Some(&json!("2023-11-14T22:13:20Z")));
    assert_eq!(head.get("verdict"), Some(&json!("fail")));
    assert!(head.get("tenant").is_none());
    let everything = body_json(get(&fx.router, "/compliance/state?verdict=all", Some(&token)).await?).await?;
    assert_eq!(items(&everything)?.len(), FIVE);
    let passed = body_json(get(&fx.router, "/compliance/state?verdict=pass&baseline=base", Some(&token)).await?).await?;
    assert_eq!(controls(&passed)?, ["c4"]);
    let excepted = body_json(get(&fx.router, "/compliance/state?verdict=excepted", Some(&token)).await?).await?;
    assert_eq!(items(&excepted)?.first().and_then(|item| item.get("first_failed")), Some(&Value::Null));
    let foreign = body_json(get(&fx.router, "/compliance/state?verdict=all&baseline=nobody", Some(&token)).await?).await?;
    assert!(items(&foreign)?.is_empty());
    Ok(())
}


const FIVE: usize = 5;


#[tokio::test]
async fn limits_verdicts_and_baselines_are_checked_before_any_store_call() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    for query in [
        "limit=1",
        "limit=500",
        "verdict=all",
        "verdict=error",
        "baseline=base",
        "baseline=a.b_c-1",
    ] {
        let response = get(&fx.router, &format!("/compliance/state?{query}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::OK, "{query}");
    }
    let before = read_count(&fx.fake);
    let bad = [
        "limit=0".to_owned(),
        "limit=501".to_owned(),
        "limit=abc".to_owned(),
        "limit=-1".to_owned(),
        "limit=+5".to_owned(),
        "limit=".to_owned(),
        "limit=1&limit=2".to_owned(),
        "verdict=FAIL".to_owned(),
        "verdict=other".to_owned(),
        "verdict=".to_owned(),
        "baseline=".to_owned(),
        "baseline=-x".to_owned(),
        "baseline=a%20b".to_owned(),
        "baseline=a%00b".to_owned(),
        format!("baseline={}", "b".repeat(MAX_ASSET_CHARS)),
        "cursor=junk".to_owned(),
        format!("cursor={}", "1".repeat(HUGE_CURSOR)),
        format!("cursor={}", "1".repeat(MAX_CURSOR_HEX + SECOND)),
        format!("tenant={OTHER_TENANT}"),
    ];
    for query in bad {
        let response = get(&fx.router, &format!("/compliance/state?{query}"), Some(&token)).await?;
        let shown = query.chars().take(MARKER.len()).collect::<String>();
        assert!(matches!(response.status(), StatusCode::BAD_REQUEST | StatusCode::URI_TOO_LONG), "{shown}");
    }
    assert_eq!(read_count(&fx.fake), before);
    let default = body_json(get(&fx.router, "/compliance/state?verdict=all", Some(&token)).await?).await?;
    assert_eq!(items(&default)?.len(), FIVE);
    Ok(())
}


#[tokio::test]
async fn a_cursor_walks_three_rows_of_one_baseline() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let first = body_json(get(&fx.router, "/compliance/state?limit=1", Some(&token)).await?).await?;
    assert_eq!(controls(&first)?, ["c1"]);
    let cursor = first.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let second = body_json(get(&fx.router, &format!("/compliance/state?limit=1&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(controls(&second)?, ["c2"]);
    let after_second = second.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let third = body_json(get(&fx.router, &format!("/compliance/state?limit=1&cursor={after_second}"), Some(&token)).await?).await?;
    assert_eq!(controls(&third)?, ["c3"]);
    assert_eq!(third.get("next_cursor"), Some(&Value::Null));
    let forged = encode_cursor(&("base".to_owned(), "c1".to_owned(), "host-z".to_owned()));
    let moved = body_json(get(&fx.router, &format!("/compliance/state?cursor={forged}"), Some(&token)).await?).await?;
    assert_eq!(controls(&moved)?, ["c2", "c3"]);
    let tenants: Vec<String> = state_fake::recorded(&fx.fake).into_iter().map(|(tenant, _sql)| tenant).collect();
    assert!(tenants.iter().all(|tenant| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn a_bad_row_is_served_around_and_a_page_of_bad_rows_moves_on() -> TestResult {
    let fx = fixture()?;
    put_row(&fx.fake, TENANT, ("base", "c1", "a1"), ("fail", FAILED, SEEN));
    put_row(&fx.fake, TENANT, ("base", "c2", "a1"), ("fail", FAILED, "x"));
    put_row(&fx.fake, TENANT, ("base", "c3", "a1"), ("fail", FAILED, SEEN));
    put_row(&fx.fake, TENANT, ("base", "c4", "a1"), ("fail", "9223372036854775807", SEEN));
    put_row(&fx.fake, TENANT, ("base", "c5", "a1"), ("fail", "-9223372036854775808", SEEN));
    put_row(&fx.fake, TENANT, ("base", "c6", "a1"), ("fail", FAILED, "9223372036854775807"));
    put_row(&fx.fake, TENANT, ("base", "c7", "a1"), ("fail", FAILED, SEEN));
    let token = login(&fx.router, ANALYST).await?;
    let first = body_json(get(&fx.router, "/compliance/state?limit=3", Some(&token)).await?).await?;
    assert_eq!(controls(&first)?, ["c1", "c3"]);
    assert_eq!(first.get("skipped"), Some(&json!(1)));
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let guard = tracing::dispatcher::set_default(&dispatch);
    let cursor = first.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let bad_only = body_json(get(&fx.router, &format!("/compliance/state?limit=3&cursor={cursor}"), Some(&token)).await?).await?;
    drop(guard);
    assert!(items(&bad_only)?.is_empty());
    assert_eq!(bad_only.get("skipped"), Some(&json!(THIRD)));
    let next = bad_only.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let rest = body_json(get(&fx.router, &format!("/compliance/state?limit=3&cursor={next}"), Some(&token)).await?).await?;
    assert_eq!(controls(&rest)?, ["c7"]);
    assert_eq!(rest.get("next_cursor"), Some(&Value::Null));
    let logs = captured(&capture);
    assert!(logs.contains("unwritable=3"), "{logs}");
    Ok(())
}


#[tokio::test]
async fn an_asset_lists_its_results_and_unknown_malformed_and_foreign_ones_answer_alike() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    put_row(&fx.fake, TENANT, ("base", "c1", "host/with:slash"), ("pass", "", SEEN));
    let token = login(&fx.router, ANALYST).await?;
    let found = body_json(get(&fx.router, "/compliance/assets/host-a", Some(&token)).await?).await?;
    assert_eq!(controls(&found)?, ["c1", "c2", "c3", "c4", "c5"]);
    assert_eq!((found.get("skipped"), found.get("truncated")), (Some(&json!(0)), Some(&json!(false))));
    let slash = body_json(get(&fx.router, "/compliance/assets/host%2Fwith%3Aslash", Some(&token)).await?).await?;
    assert_eq!(controls(&slash)?, ["c1"]);
    let long = format!("/compliance/assets/{}", "a".repeat(MAX_ASSET_CHARS + 1));
    let paths = [
        "/compliance/assets/unknown".to_owned(),
        "/compliance/assets/host-z".to_owned(),
        long,
        "/compliance/assets/a%20b".to_owned(),
        "/compliance/assets/a%00b".to_owned(),
        "/compliance/assets/-a".to_owned(),
        "/compliance/assets/%2Fa".to_owned(),
        "/compliance/assets/h%E2%84%AA".to_owned(),
    ];
    let before = read_count(&fx.fake);
    let mut bodies = Vec::new();
    for path in &paths {
        let response = get(&fx.router, path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let bytes = axum::body::to_bytes(response.into_body(), http::BODY_READ_LIMIT).await?;
        bodies.push(bytes);
    }
    assert!(bodies.windows(SECOND).all(|pair| pair.first() == pair.get(1)));
    assert!(!String::from_utf8(bodies.first().ok_or("none")?.to_vec())?.contains("unknown"));
    assert_eq!(read_count(&fx.fake) - before, SECOND);
    Ok(())
}


#[tokio::test]
async fn more_results_than_the_maximum_set_truncated_and_a_skipped_asset_is_a_200() -> TestResult {
    let fx = fixture()?;
    (0..=MAX_ASSET_RESULTS).for_each(|index| put_row(&fx.fake, TENANT, ("base", &format!("c{index:05}"), "big"), ("pass", "", SEEN)));
    put_row(&fx.fake, TENANT, ("base", "c1", "broken"), ("weird", "", SEEN));
    let token = login(&fx.router, ANALYST).await?;
    let big = body_json(get(&fx.router, "/compliance/assets/big", Some(&token)).await?).await?;
    assert_eq!((items(&big)?.len(), big.get("truncated")), (MAX_ASSET_RESULTS, Some(&json!(true))));
    let broken = get(&fx.router, "/compliance/assets/broken", Some(&token)).await?;
    assert_eq!(broken.status(), StatusCode::OK);
    let json = body_json(broken).await?;
    assert_eq!((items(&json)?.len(), json.get("skipped")), (0, Some(&json!(1))));
    Ok(())
}


#[tokio::test]
async fn the_permission_is_cmdb_read_and_other_methods_are_refused() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let reader = login(&fx.router, READER).await?;
    let before = read_count(&fx.fake);
    for path in ["/compliance/state", "/compliance/assets/host-a"] {
        assert_eq!(get(&fx.router, path, None).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some("bogus")).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
        assert_eq!(get(&fx.router, path, Some(&token)).await?.status(), StatusCode::OK);
        let posted = call(&fx.router, "POST", path, Some(&token), axum::body::Body::empty()).await?;
        assert!(!posted.status().is_success(), "{}", posted.status());
        let deleted = call(&fx.router, "DELETE", path, Some(&token), axum::body::Body::empty()).await?;
        assert!(!deleted.status().is_success(), "{}", deleted.status());
    }
    assert_eq!(read_count(&fx.fake) - before, SECOND);
    assert_eq!(compliance_access().len(), SECOND);
    assert!(compliance_document().paths.paths.contains_key("/compliance/state"));
    assert!(compliance_document().paths.paths.contains_key("/compliance/assets/{asset}"));
    Ok(())
}


fn failing_backend(error: fn() -> ReadError) -> impl FnOnce(&Arc<state_fake::Fake>) -> StateBackend {
    move |_fake| StateBackend {
        list: Arc::new(move |_scope, _request| Box::pin(async move { Err(error()) })),
        asset: Arc::new(move |_scope, _asset| Box::pin(async move { Err(error()) })),
    }
}


fn marked_pg_error() -> ReadError {
    ReadError::Pg(PgError::Io {
        file: MARKER.to_owned(),
        source: std::io::Error::other(MARKER),
    })
}


#[tokio::test]
async fn a_store_error_is_a_fixed_500_and_its_text_reaches_neither_body_nor_log() -> TestResult {
    let fx = fixture_with(failing_backend(marked_pg_error))?;
    let token = login(&fx.router, ANALYST).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    for path in ["/compliance/state", "/compliance/assets/host-a"] {
        let response = get(&fx.router, path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let shown = format!("{response:?}");
        let json = body_json(response).await?;
        assert_eq!(code_of(&json), Some("internal_error"));
        assert!(!json.to_string().contains(MARKER) && !shown.contains(MARKER));
    }
    let logs = captured(&capture);
    assert!(logs.contains("compliance state failure") && logs.contains("database"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_429_and_an_unmigrated_key_is_a_stored_value_500() -> TestResult {
    let busy = fixture_with(failing_backend(|| ReadError::Lease(LeaseError::Busy)))?;
    let token = login(&busy.router, ANALYST).await?;
    assert_eq!(
        get(&busy.router, "/compliance/state", Some(&token)).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let unmigrated = fixture_with(failing_backend(|| ReadError::BadKey))?;
    let other = login(&unmigrated.router, ANALYST).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    assert_eq!(
        get(&unmigrated.router, "/compliance/state", Some(&other)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(captured(&capture).contains("stored_value"));
    Ok(())
}


fn stored(first_failed: Option<i64>, last_seen: i64) -> StoredState {
    StoredState {
        baseline: "base".to_owned(),
        control: "c1".to_owned(),
        asset: "a1".to_owned(),
        verdict: "fail".to_owned(),
        first_failed_micros: first_failed,
        last_seen_micros: last_seen,
    }
}


#[test]
fn times_outside_rfc_3339_are_refused_and_counted() -> TestResult {
    assert_eq!(rfc3339(0)?, "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339(1)?, "1970-01-01T00:00:00.000001Z");
    assert!(rfc3339(FAR_MICROS - 1).is_ok());
    assert!(matches!(rfc3339(FAR_MICROS), Err(ReadError::Unrepresentable)));
    assert!(matches!(rfc3339(i64::MIN), Err(ReadError::Unrepresentable)));
    assert!(matches!(rfc3339(-FAR_MICROS), Err(ReadError::Unrepresentable)));
    let rows = [
        stored(Some(1), 1),
        stored(Some(FAR_MICROS), 1),
        stored(Some(1), FAR_MICROS),
        stored(None, 1),
    ];
    let (shown, unwritable) = views_of(&rows);
    assert_eq!((shown.len(), unwritable), (SECOND, SECOND));
    let page = StatePage {
        rows: rows.to_vec(),
        skipped: 1,
        next_cursor: Some("c".to_owned()),
    };
    let view = list_view(&page);
    assert_eq!((view.items.len(), view.skipped, view.next_cursor.as_deref()), (SECOND, THIRD, Some("c")));
    let asset = asset_view(&AssetResults {
        rows: rows.to_vec(),
        skipped: 0,
        truncated: true,
    });
    assert_eq!((asset.items.len(), asset.skipped, asset.truncated), (SECOND, SECOND, true));
    Ok(())
}


#[test]
fn the_request_parsers_and_failure_mapping() -> TestResult {
    assert_eq!(parse_limit(None)?, DEFAULT_LIMIT);
    assert_eq!(parse_limit(Some("500"))?, MAX_PAGE);
    assert!(parse_limit(Some("99999999999999999999999")).is_err());
    assert_eq!(parse_verdict(None)?.as_deref(), Some("fail"));
    assert_eq!(parse_verdict(Some("all"))?, None);
    assert!(matches!(parse_verdict(Some("x")), Err(ReadError::BadVerdict)));
    assert_eq!(parse_baseline(None)?, None);
    assert!(matches!(parse_baseline(Some("-x")), Err(ReadError::BadBaseline)));
    let query = ListQuery {
        verdict: Some("error".to_owned()),
        baseline: Some("base".to_owned()),
        cursor: Some(encode_cursor(&("base".to_owned(), "c1".to_owned(), "a1".to_owned()))),
        limit: Some("7".to_owned()),
    };
    let request = request_of(&query)?;
    assert_eq!(
        (request.limit, request.filter.verdict.as_deref(), request.filter.baseline.as_deref()),
        (FOURTH + THIRD, Some("error"), Some("base"))
    );
    assert!(request.cursor.is_some());
    let identity = ApiIdentity {
        module: "compliance".to_owned(),
        tenant: "-bad".to_owned(),
        generation: 0,
    };
    assert!(matches!(scope_of(&identity), Err(ReadError::Pg(_))));
    assert!(matches!(store_failure(&ReadError::BadLimit), ApiError::Internal));
    assert_eq!(failure_category(&ReadError::BadLimit), "request");
    assert_eq!(failure_category(&ReadError::BadRow), "stored_value");
    assert_eq!(failure_category(&ReadError::Unrepresentable), "stored_value");
    Ok(())
}


#[tokio::test]
async fn an_identity_with_a_malformed_tenant_reaches_no_store() -> TestResult {
    let fx = fixture()?;
    put_row(&fx.fake, TENANT, ("base", "c1", "host-a"), ("fail", FAILED, SEEN));
    let backend = memory_backend(&fx.fake);
    let identity = ApiIdentity {
        module: "compliance".to_owned(),
        tenant: "-bad".to_owned(),
        generation: 0,
    };
    let query = ListQuery {
        verdict: None,
        baseline: None,
        cursor: None,
        limit: None,
    };
    assert!(matches!(list_flow(&identity, &backend, Ok(query)).await, Err(ApiError::Internal)));
    assert!(matches!(
        asset_flow(&identity, &backend, Ok("host-a".to_owned())).await,
        Err(ApiError::Internal)
    ));
    assert_eq!(read_count(&fx.fake), 0);
    Ok(())
}
