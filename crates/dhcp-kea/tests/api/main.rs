mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
mod memory;
mod types;


use axum::body::to_bytes;
use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity};
use core_api::state::RATE_MAX_REQUESTS;
use dhcp_kea::api::{
    dhcp_access, dhcp_document, lookup_view, parse_address, parse_mac, parse_time, parse_window, scope_of, store_failure, AT_PATH, MAC_PATH,
    MAX_WINDOW_SECONDS,
};
use dhcp_kea::error::HistoryError;
use dhcp_kea::history::{LeaseInterval, LookupResult, MAX_LOOKUP_ROWS};
use fixture::{fixture, fixture_adjusted, ANALYST, OTHER_TENANT, READER, TENANT};
use http::{body_json, get, login, BODY_READ_LIMIT};
use memory::{lock, row, seed, Forced, MARKER, NULL_CELL};
use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, LazyLock};
use types::{TestError, TestResult};


const NOW: i64 = 1_700_000_000;


const NEAR: i64 = 100;


const FAR_START: i64 = 1_000;


const FAR_END: i64 = 500;


const MIDDLE: i64 = 50;


const SHORT: i64 = 10;


const LONGER: i64 = 20;


const SUBNET: i64 = 7;


const PAIR: usize = 2;


const CUT_AT: usize = 3;


const SKIPPED_IN_VIEW: usize = 3;


const SHOWN_CHARS: usize = 80;


const FLOOD: usize = 10;


const MAC_TEXT: &str = "AA-BB-CC-DD-EE-01";


const YEAR_10000: i64 = 253_402_300_800;


const DAYS_401: i64 = 401;


const SECONDS_PER_DAY: i64 = 86_400;


const LONG_QUERY: usize = 60_000;


static ANCHOR: LazyLock<tracing::Dispatch> = LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


async fn seeded() -> Result<(fixture::Fixture, String), TestError> {
    let fx = fixture()?;
    seed(
        &fx.mem,
        TENANT,
        vec![
            row("10.0.0.42", MAC_TEXT, "pc-one", NOW - NEAR, NOW + NEAR),
            row("10.0.0.42", "AA-BB-CC-DD-EE-02", "", NOW - FAR_START, NOW - FAR_END),
        ],
    );
    seed(
        &fx.mem,
        OTHER_TENANT,
        vec![row("10.9.9.9", "FF-FF-FF-FF-FF-FF", "foreign", NOW - NEAR, NOW + NEAR)],
    );
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


async fn body_bytes(response: axum::http::Response<axum::body::Body>) -> Result<Vec<u8>, TestError> {
    Ok(to_bytes(response.into_body(), BODY_READ_LIMIT).await?.to_vec())
}


fn intervals(json: &Value) -> Result<&Vec<Value>, TestError> {
    Ok(json.get("intervals").and_then(Value::as_array).ok_or("no intervals")?)
}


#[tokio::test]
async fn an_address_lookup_answers_the_session_tenant_rows_in_rfc3339() -> TestResult {
    let (fx, token) = seeded().await?;
    let response = get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await?;
    let first = intervals(&json)?.first().ok_or("empty")?;
    assert_eq!(first.get("address"), Some(&json!("10.0.0.42")));
    assert_eq!(first.get("mac"), Some(&json!(MAC_TEXT)));
    assert_eq!(first.get("hostname"), Some(&json!("pc-one")));
    assert_eq!(first.get("starts"), Some(&json!("2023-11-14T22:11:40Z")));
    assert_eq!(first.get("subnet_id"), Some(&json!(SUBNET)));
    assert_eq!((json.get("skipped"), json.get("truncated")), (Some(&json!(0)), Some(&json!(false))));
    let statements = lock(&fx.mem.statements);
    assert!(statements.iter().all(|(tenant, _sql, _params)| tenant == TENANT));
    assert_eq!(statements.len(), 1);
    Ok(())
}


#[tokio::test]
async fn ipv6_and_mapped_addresses_reach_the_store_in_canonical_form() -> TestResult {
    let (fx, token) = seeded().await?;
    for (given, bound) in [
        ("2001:db8::1", "2001:db8::1"),
        ("::ffff:10.0.0.1", "::ffff:10.0.0.1"),
        ("2001:DB8:0:0::2", "2001:db8::2"),
    ] {
        let response = get(&fx.router, &format!("/dhcp/leases/at?address={given}&at={NOW}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let seen = lock(&fx.mem.statements).last().map(|(_tenant, _sql, params)| params.first().cloned());
        assert_eq!(seen, Some(Some(bound.to_owned())));
    }
    Ok(())
}


#[tokio::test]
async fn a_mac_lookup_normalises_three_spellings_and_lists_intervals() -> TestResult {
    let (fx, token) = seeded().await?;
    let window = format!("from={}&to={NOW}", NOW - SECONDS_PER_DAY);
    for spelling in ["aa:bb:cc:dd:ee:01", "AA-BB-CC-DD-EE-01", "Aa:bB-cC:dD-eE:01"] {
        let response = get(&fx.router, &format!("/dhcp/leases/mac?mac={spelling}&{window}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await?;
        assert_eq!(intervals(&json)?.len(), PAIR);
        let bound = lock(&fx.mem.statements).last().map(|(_tenant, _sql, params)| params.first().cloned());
        assert_eq!(bound, Some(Some(MAC_TEXT.to_owned())));
    }
    Ok(())
}


#[tokio::test]
async fn every_refused_parameter_is_the_same_400_without_a_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let from = NOW - SECONDS_PER_DAY;
    let wide = format!("from={}&to={NOW}", NOW - DAYS_401 * SECONDS_PER_DAY);
    let long = "9".repeat(LONG_QUERY);
    let paths = [
        format!("/dhcp/leases/at?address=fe80::1%25eth0&at={NOW}"),
        format!("/dhcp/leases/at?address=%5B::1%5D&at={NOW}"),
        format!("/dhcp/leases/at?address=10.0.0.1%00&at={NOW}"),
        format!("/dhcp/leases/at?address=10.0.0.1&address=10.0.0.2&at={NOW}"),
        format!("/dhcp/leases/at?address={long}&at={NOW}"),
        "/dhcp/leases/at?address=10.0.0.1&at=-5".to_owned(),
        format!("/dhcp/leases/at?address=10.0.0.1&at={YEAR_10000}"),
        "/dhcp/leases/at?address=10.0.0.1&at=12x".to_owned(),
        "/dhcp/leases/at?address=10.0.0.1&at=%2B5".to_owned(),
        "/dhcp/leases/at?address=10.0.0.1&at=%D9%A1%D9%A2".to_owned(),
        format!("/dhcp/leases/at?address=10.0.0.1&at={long}"),
        "/dhcp/leases/at?address=10.0.0.1&at=".to_owned(),
        "/dhcp/leases/at?address=10.0.0.1".to_owned(),
        "/dhcp/leases/at".to_owned(),
        format!("/dhcp/leases/at?address=10.0.0.1&at={NOW}&tenant=globex"),
        format!("/dhcp/leases/mac?mac=garbage&from={from}&to={NOW}"),
        format!("/dhcp/leases/mac?mac=aa:bb:cc:dd:ee&from={from}&to={NOW}"),
        format!("/dhcp/leases/mac?mac={MAC_TEXT}&from={NOW}&to={from}"),
        format!("/dhcp/leases/mac?mac={MAC_TEXT}&{wide}"),
        format!("/dhcp/leases/mac?mac={MAC_TEXT}&from=-1&to={NOW}"),
        format!("/dhcp/leases/mac?mac={MAC_TEXT}&from={from}"),
        format!("/dhcp/leases/mac?mac={MAC_TEXT}"),
        "/dhcp/leases/mac".to_owned(),
    ];
    let mut bodies = Vec::new();
    for path in &paths {
        let response = get(&fx.router, path, Some(&token)).await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            path.chars().take(SHOWN_CHARS).collect::<String>()
        );
        bodies.push(body_bytes(response).await?);
    }
    assert!(bodies.windows(PAIR).all(|pair| pair.first() == pair.get(1)));
    assert!(lock(&fx.mem.statements).is_empty());
    let exact = format!("from={}&to={NOW}", NOW - MAX_WINDOW_SECONDS);
    let edge = get(&fx.router, &format!("/dhcp/leases/mac?mac={MAC_TEXT}&{exact}"), Some(&token)).await?;
    assert_eq!(edge.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn one_bad_stored_row_is_skipped_and_counted() -> TestResult {
    let (fx, token) = seeded().await?;
    let mut broken = row("10.0.0.42", MAC_TEXT, "pc", NOW - MIDDLE, NOW + MIDDLE);
    broken.truncate(CUT_AT);
    seed(
        &fx.mem,
        TENANT,
        vec![
            row("10.0.0.42", MAC_TEXT, "a", NOW - SHORT, NOW + SHORT),
            broken,
            row("10.0.0.42", MAC_TEXT, "c", NOW - LONGER, NOW + LONGER),
        ],
    );
    let json = body_json(get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?).await?;
    assert_eq!(intervals(&json)?.len(), PAIR);
    assert_eq!(json.get("skipped"), Some(&json!(1)));
    Ok(())
}


#[tokio::test]
async fn a_null_mac_or_hostname_is_served_as_null_and_never_a_500() -> TestResult {
    let (fx, token) = seeded().await?;
    seed(
        &fx.mem,
        TENANT,
        vec![
            row("10.0.0.42", NULL_CELL, NULL_CELL, NOW - SHORT, NOW + SHORT),
            row("10.0.0.42", MAC_TEXT, NULL_CELL, NOW - LONGER, NOW + LONGER),
        ],
    );
    let at = get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?;
    assert_eq!(at.status(), StatusCode::OK);
    let json = body_json(at).await?;
    let first = intervals(&json)?.first().ok_or("empty")?;
    assert_eq!((first.get("mac"), first.get("hostname")), (Some(&Value::Null), Some(&Value::Null)));
    assert_eq!(intervals(&json)?.len(), PAIR);
    let window = format!("from={}&to={NOW}", NOW - SECONDS_PER_DAY);
    let by_mac = get(&fx.router, &format!("/dhcp/leases/mac?mac={MAC_TEXT}&{window}"), Some(&token)).await?;
    assert_eq!(by_mac.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn more_than_the_bound_gives_a_truncated_answer() -> TestResult {
    let (fx, token) = seeded().await?;
    let many: Vec<Vec<String>> = (0..=MAX_LOOKUP_ROWS)
        .map(|index| row("10.0.0.42", MAC_TEXT, "pc", NOW - SHORT - i64::try_from(index).unwrap_or(0), NOW + SHORT))
        .collect();
    seed(&fx.mem, TENANT, many);
    let json = body_json(get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?).await?;
    assert_eq!(intervals(&json)?.len(), MAX_LOOKUP_ROWS);
    assert_eq!(json.get("truncated"), Some(&json!(true)));
    Ok(())
}


#[tokio::test]
async fn a_hostname_with_control_bytes_is_json_escaped() -> TestResult {
    let (fx, token) = seeded().await?;
    seed(
        &fx.mem,
        TENANT,
        vec![row("10.0.0.42", MAC_TEXT, "bad\u{1b}[31m\nname", NOW - SHORT, NOW + SHORT)],
    );
    let response = get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?;
    let text = String::from_utf8(body_bytes(response).await?)?;
    assert!(text.contains("\\u001b[31m\\nname"));
    assert!(!text.contains('\u{1b}') && !text.contains('\n'));
    Ok(())
}


#[tokio::test]
async fn another_tenants_rows_are_never_served_and_no_parameter_selects_a_tenant() -> TestResult {
    let (fx, token) = seeded().await?;
    let json = body_json(get(&fx.router, &format!("/dhcp/leases/at?address=10.9.9.9&at={NOW}"), Some(&token)).await?).await?;
    let foreign = intervals(&json)?.iter().any(|item| item.get("hostname") == Some(&json!("foreign")));
    assert!(!foreign);
    assert!(lock(&fx.mem.statements).iter().all(|(tenant, _sql, _params)| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn no_session_is_401_and_a_reader_is_403_before_any_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let reader = login(&fx.router, READER).await?;
    for path in [
        format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"),
        format!("/dhcp/leases/mac?mac={MAC_TEXT}&from=0&to=1"),
    ] {
        assert_eq!(get(&fx.router, &path, None).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, &path, Some("bogus")).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, &path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
    }
    assert!(lock(&fx.mem.statements).is_empty());
    let allowed = get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?;
    assert_eq!(allowed.status(), StatusCode::OK);
    let post = http::call(&fx.router, "POST", "/dhcp/leases/at", Some(&token), axum::body::Body::empty()).await?;
    assert!(post.status() == StatusCode::FORBIDDEN || post.status() == StatusCode::METHOD_NOT_ALLOWED);
    Ok(())
}


#[tokio::test]
async fn an_unauthenticated_flood_is_rate_limited_before_any_store_call() -> TestResult {
    let fx = fixture_adjusted(RATE_MAX_REQUESTS, fixture::with_frozen_clock, memory::lookup_backend)?;
    let mut last = StatusCode::OK;
    for _ in 0..(RATE_MAX_REQUESTS as usize + FLOOD) {
        last = get(&fx.router, AT_PATH, None).await?.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(lock(&fx.mem.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_a_fixed_500_and_its_text_reaches_neither_body_nor_log() -> TestResult {
    let (fx, token) = seeded().await?;
    *lock(&fx.mem.forced) = Some(Forced::Fail);
    let capture = Arc::new(tempfile::tempfile()?);
    let writer = Arc::clone(&capture);
    LazyLock::force(&ANCHOR);
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Arc::clone(&writer))
            .finish(),
    );
    let guard = tracing::dispatcher::set_default(&dispatch);
    let at = get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?;
    let by_mac = get(&fx.router, &format!("/dhcp/leases/mac?mac={MAC_TEXT}&from=0&to=1"), Some(&token)).await?;
    drop(guard);
    assert_eq!(
        (at.status(), by_mac.status()),
        (StatusCode::INTERNAL_SERVER_ERROR, StatusCode::INTERNAL_SERVER_ERROR)
    );
    let body = String::from_utf8(body_bytes(at).await?)?;
    assert!(!body.contains(MARKER));
    let mut logged = String::new();
    let mut reader: &std::fs::File = &capture;
    reader.seek(SeekFrom::Start(0))?;
    reader.read_to_string(&mut logged)?;
    assert!(logged.contains("dhcp lease lookup failed"));
    assert!(!logged.contains(MARKER));
    let marker_error = HistoryError::Pg(core_pg::error::PgError::Io {
        file: MARKER.to_owned(),
        source: std::io::Error::other(MARKER),
    });
    assert!(matches!(store_failure(&marker_error), ApiError::Internal));
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_a_429() -> TestResult {
    let (fx, token) = seeded().await?;
    *lock(&fx.mem.forced) = Some(Forced::Busy);
    let at = get(&fx.router, &format!("/dhcp/leases/at?address=10.0.0.42&at={NOW}"), Some(&token)).await?;
    let by_mac = get(&fx.router, &format!("/dhcp/leases/mac?mac={MAC_TEXT}&from=0&to=1"), Some(&token)).await?;
    assert_eq!(
        (at.status(), by_mac.status()),
        (StatusCode::TOO_MANY_REQUESTS, StatusCode::TOO_MANY_REQUESTS)
    );
    Ok(())
}


#[tokio::test]
async fn an_unusable_module_tenant_is_a_500_and_the_store_is_never_asked() -> TestResult {
    let fx = fixture()?;
    let token = login(&fx.router, ANALYST).await?;
    let current = fx.state.identity.load();
    fx.state.identity.store(Arc::new(ApiIdentity {
        module: current.module.clone(),
        tenant: "bad tenant".to_owned(),
        generation: current.generation + 1,
    }));
    assert!(matches!(scope_of(&fx.state.identity.load()), Err(HistoryError::Pg(_))));
    for path in [
        format!("/dhcp/leases/at?address=10.0.0.1&at={NOW}"),
        format!("/dhcp/leases/mac?mac={MAC_TEXT}&from=0&to=1"),
    ] {
        assert_eq!(get(&fx.router, &path, Some(&token)).await?.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert!(lock(&fx.mem.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn the_openapi_document_lists_both_routes_and_the_access_table_covers_them() -> TestResult {
    let fx = fixture()?;
    let document = body_json(get(&fx.router, "/openapi.json", None).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    assert!(paths.get(AT_PATH).and_then(|path| path.get("get")).is_some());
    assert!(paths.get(MAC_PATH).and_then(|path| path.get("get")).is_some());
    assert!(serde_json::to_string(&dhcp_document())?.contains(MAC_PATH));
    assert_eq!(dhcp_access().len(), PAIR);
    Ok(())
}


#[test]
fn parameters_parse_strictly() -> TestResult {
    assert!(parse_time(Some("1700000000")).is_ok());
    assert!(matches!(parse_time(None), Err(HistoryError::TimeRange)));
    assert!(matches!(parse_time(Some("-")), Err(HistoryError::TimeRange)));
    assert!(matches!(parse_time(Some("-1")), Err(HistoryError::TimeRange)));
    assert!(matches!(parse_time(Some("+1")), Err(HistoryError::TimeRange)));
    assert!(matches!(parse_time(Some(&YEAR_10000.to_string())), Err(HistoryError::TimeRange)));
    assert!(parse_address(Some("::1")).is_ok());
    assert!(matches!(parse_address(Some("fe80::1%eth0")), Err(HistoryError::Address)));
    assert!(matches!(parse_address(None), Err(HistoryError::Address)));
    assert_eq!(parse_mac(Some("aa:bb:cc:dd:ee:01"))?, MAC_TEXT);
    assert!(matches!(parse_mac(None), Err(HistoryError::Mac)));
    assert!(matches!(parse_window(Some("5"), Some("1")), Err(HistoryError::Window)));
    assert!(matches!(
        parse_window(Some("0"), Some(&(MAX_WINDOW_SECONDS + 1).to_string())),
        Err(HistoryError::Window)
    ));
    assert_eq!(parse_window(Some("0"), Some(&MAX_WINDOW_SECONDS.to_string()))?, (0, MAX_WINDOW_SECONDS));
    Ok(())
}


#[test]
fn failures_map_to_stable_errors_and_an_unwritable_time_is_skipped() -> TestResult {
    assert!(matches!(store_failure(&HistoryError::Address), ApiError::BadRequest));
    assert!(matches!(store_failure(&HistoryError::Mac), ApiError::BadRequest));
    assert!(matches!(store_failure(&HistoryError::TimeRange), ApiError::BadRequest));
    assert!(matches!(store_failure(&HistoryError::Window), ApiError::BadRequest));
    assert!(matches!(store_failure(&HistoryError::Busy), ApiError::TooManyRequests));
    assert!(matches!(store_failure(&HistoryError::Settings), ApiError::Internal));
    assert!(matches!(store_failure(&HistoryError::Answer), ApiError::Internal));
    let interval = |starts: i64| LeaseInterval {
        address: "10.0.0.1".to_owned(),
        mac: None,
        hostname: None,
        starts,
        ends: NOW,
        action: "lease-assigned".to_owned(),
        subnet_id: 1,
    };
    let view = lookup_view(&LookupResult {
        intervals: vec![interval(NOW - 1), interval(i64::MAX), interval(i64::MIN)],
        skipped: 1,
        truncated: false,
    });
    assert_eq!((view.intervals.len(), view.skipped), (1, SKIPPED_IN_VIEW));
    Ok(())
}
