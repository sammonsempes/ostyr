mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
mod types;


use axum::body::to_bytes;
use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity};
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use data_encoding::BASE64URL_NOPAD;
use fixture::{
    finding, fixture, fixture_with, lock, marker_error, memory_backend, put, Fixture, BYTE_CAP, MARKER, MATCHES, NOBODY, OTHER_TENANT, PERMITS,
    READER, TENANT,
};
use http::{body_json, get, login, BODY_READ_LIMIT};
use hunt_packs::api::{
    decode_cursor, encode_cursor, findings_failure, findings_flow, findings_view, hunts_document, oversized_view, parse_limit, permit_backend,
    query_of, scope_of, store_category, time_text, DEFAULT_LIMIT, FIRST_END, MAX_CURSOR_CHARS, MAX_END_CHARS,
};
use hunt_packs::api_model::{FindingsQuery, FindingsReply, ListQuery};
use hunt_packs::error::FindingsError;
use hunt_packs::packs::MAX_ID_CHARS;
use hunt_packs::schedule::checked_time;
use hunt_packs::store::{FindingPage, StateError, MAX_FINDINGS_PAGE, OVERSIZED_REPORT_CAP};
use hunt_packs::types::FindingsFn;
use serde_json::Value;
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::sync::Semaphore;
use tracing::instrument::WithSubscriber;
use tracing::Dispatch;
use types::{TestError, TestResult};


const BASE: i64 = 1_800_000_000;


const PAGE_OF_TWO: usize = 2;


const PAGE_CAP: i64 = 500;


const THIRD_STEP: i64 = 2;


const FOURTH_STEP: i64 = 3;


const LATE_STEP: i64 = 10_000;


const MANY_BAD: usize = 1_200;


const FLOOD: usize = 200;


const YEAR_10000: i64 = 253_402_300_800;


const MAX_END: i64 = 253_402_300_799;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);


impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn items(json: &Value) -> Result<&Vec<Value>, TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


fn packs(json: &Value) -> Result<Vec<String>, TestError> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| item.get("pack_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}


fn next_of(json: &Value) -> Option<String> {
    json.get("next_cursor").and_then(Value::as_str).map(str::to_owned)
}


async fn seeded() -> Result<(Fixture, String), TestError> {
    let fx = fixture()?;
    ["alpha", "beta", "gamma"]
        .iter()
        .zip(0..)
        .for_each(|(pack, step)| put(&fx.db, TENANT, finding(pack, BASE + step)));
    put(&fx.db, OTHER_TENANT, finding("foreign", BASE));
    let token = login(&fx.router, READER).await?;
    Ok((fx, token))
}


#[tokio::test]
async fn paging_serves_the_session_tenant_only_oldest_first() -> TestResult {
    let (fx, token) = seeded().await?;
    let first = body_json(get(&fx.router, "/hunts/findings?limit=2", Some(&token)).await?).await?;
    assert_eq!(packs(&first)?, ["alpha", "beta"]);
    let cursor = next_of(&first).ok_or("no cursor")?;
    let second = body_json(get(&fx.router, &format!("/hunts/findings?limit=2&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(packs(&second)?, ["gamma"]);
    assert_eq!(second.get("next_cursor"), Some(&Value::Null));
    let head = items(&first)?.first().ok_or("empty")?;
    assert_eq!(head.get("window_end"), Some(&Value::from("2027-01-15T08:00:00Z")));
    assert_eq!(head.get("window_start"), Some(&Value::from("2027-01-15T07:00:00Z")));
    assert_eq!(head.get("matches"), Some(&Value::from(MATCHES)));
    assert_eq!(head.get("max_matches"), Some(&Value::from(1)));
    assert_eq!(first.get("skipped"), Some(&Value::from(0)));
    assert_eq!(first.get("oversized"), Some(&serde_json::json!({"count": 0, "capped": false})));
    let all = body_json(get(&fx.router, "/hunts/findings", Some(&token)).await?).await?;
    assert_eq!(packs(&all)?, ["alpha", "beta", "gamma"]);
    assert!(lock(&fx.db.tenants_seen).iter().all(|tenant| tenant == TENANT));
    assert_eq!(fx.permits.available_permits(), PERMITS);
    Ok(())
}


#[tokio::test]
async fn limits_are_digits_between_one_and_the_page_cap() -> TestResult {
    let (fx, token) = seeded().await?;
    for limit in ["1", "500"] {
        let found = get(&fx.router, &format!("/hunts/findings?limit={limit}"), Some(&token)).await?;
        assert_eq!(found.status(), StatusCode::OK, "{limit}");
    }
    for limit in ["501", "0", "abc", "", "+5", "-1", "5%20", "99999999999999999999"] {
        let found = get(&fx.router, &format!("/hunts/findings?limit={limit}"), Some(&token)).await?;
        assert_eq!(found.status(), StatusCode::BAD_REQUEST, "{limit}");
    }
    assert!(matches!(parse_limit(None), Ok(DEFAULT_LIMIT)));
    assert_eq!(MAX_FINDINGS_PAGE, PAGE_CAP);
    Ok(())
}


#[tokio::test]
async fn an_ordinary_an_uppercase_and_a_longest_id_cursor_round_trip() -> TestResult {
    let (fx, token) = seeded().await?;
    let longest = "A".repeat(BYTE_CAP);
    let cursor_ids = ["alpha", "Upper-Case", longest.as_str()];
    for id in cursor_ids {
        let cursor = encode_cursor(BASE, id);
        assert!(cursor.len() <= MAX_CURSOR_CHARS);
        assert_eq!(decode_cursor(&cursor)?, (BASE, id.to_owned()));
        let found = get(&fx.router, &format!("/hunts/findings?cursor={cursor}"), Some(&token)).await?;
        assert_eq!(found.status(), StatusCode::OK, "{id}");
    }
    let after_alpha = body_json(
        get(
            &fx.router,
            &format!("/hunts/findings?cursor={}", encode_cursor(BASE, "alpha")),
            Some(&token),
        )
        .await?,
    )
    .await?;
    assert_eq!(packs(&after_alpha)?, ["beta", "gamma"]);
    let widest = encode_cursor(FIRST_END, &"z".repeat(BYTE_CAP));
    assert_eq!(widest.len(), MAX_CURSOR_CHARS);
    assert_eq!(decode_cursor(&widest)?.1.len(), BYTE_CAP);
    assert_eq!(FIRST_END.to_string().len(), MAX_END_CHARS);
    assert_eq!(MAX_END.to_string().len(), MAX_END_CHARS);
    assert!(checked_time(FIRST_END).is_ok() && checked_time(FIRST_END - 1).is_err());
    assert_eq!(MAX_ID_CHARS, BYTE_CAP);
    Ok(())
}


#[tokio::test]
async fn a_bad_cursor_is_a_fixed_400_that_never_echoes_the_input() -> TestResult {
    let (fx, token) = seeded().await?;
    let long = "A".repeat(MAX_CURSOR_CHARS + 1);
    let nul = BASE64URL_NOPAD.encode(format!("{BASE}:a\0b").as_bytes());
    let utf8 = BASE64URL_NOPAD.encode(&INVALID_UTF8);
    let negative = BASE64URL_NOPAD.encode(format!("{}:a", FIRST_END - 1).as_bytes());
    let future = BASE64URL_NOPAD.encode(format!("{YEAR_10000}:a").as_bytes());
    let too_long_id = BASE64URL_NOPAD.encode(format!("{BASE}:{}", "a".repeat(BYTE_CAP + 1)).as_bytes());
    let no_separator = BASE64URL_NOPAD.encode(b"12345");
    let not_a_number = BASE64URL_NOPAD.encode(b"x:a");
    let bad = [
        "!!!notbase64".to_owned(),
        "AA".to_owned(),
        long,
        nul,
        utf8,
        negative,
        future,
        too_long_id,
        no_separator,
        not_a_number,
    ];
    let reference = {
        let found = get(&fx.router, "/hunts/findings?cursor=!!!", Some(&token)).await?;
        to_bytes(found.into_body(), BODY_READ_LIMIT).await?
    };
    for cursor in bad {
        let found = get(&fx.router, &format!("/hunts/findings?cursor={cursor}"), Some(&token)).await?;
        assert_eq!(found.status(), StatusCode::BAD_REQUEST, "{cursor}");
        let body = to_bytes(found.into_body(), BODY_READ_LIMIT).await?;
        assert_eq!(body, reference);
        assert!(!String::from_utf8_lossy(&body).contains(&cursor));
        assert!(decode_cursor(&cursor).is_err());
    }
    let tenant = get(&fx.router, "/hunts/findings?tenant=globex", Some(&token)).await?;
    assert_eq!(tenant.status(), StatusCode::BAD_REQUEST);
    assert!(lock(&fx.db.tenants_seen).is_empty());
    Ok(())
}


#[tokio::test]
async fn refused_ids_are_counted_and_walked_past() -> TestResult {
    let fx = fixture()?;
    put(&fx.db, TENANT, finding("Bad-One", BASE));
    put(&fx.db, TENANT, finding("Bad-Two", BASE + 1));
    put(&fx.db, TENANT, finding("good", BASE + THIRD_STEP));
    put(&fx.db, TENANT, finding(&"y".repeat(BYTE_CAP + MAX_ID_CHARS), BASE + FOURTH_STEP));
    let token = login(&fx.router, READER).await?;
    let first = body_json(get(&fx.router, "/hunts/findings?limit=2", Some(&token)).await?).await?;
    assert!(items(&first)?.is_empty());
    assert_eq!(first.get("skipped"), Some(&Value::from(PAGE_OF_TWO)));
    let cursor = next_of(&first).ok_or("a full page of refused rows must carry a cursor")?;
    assert_eq!(decode_cursor(&cursor)?, (BASE + 1, "Bad-Two".to_owned()));
    let second = body_json(get(&fx.router, &format!("/hunts/findings?limit=2&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(packs(&second)?, ["good"]);
    assert_eq!(second.get("oversized"), Some(&serde_json::json!({"count": 1, "capped": false})));
    Ok(())
}


#[tokio::test]
async fn a_long_run_of_refused_rows_is_walked_page_by_page() -> TestResult {
    let fx = fixture()?;
    (0..MANY_BAD)
        .zip(0..)
        .for_each(|(index, step)| put(&fx.db, TENANT, finding(&format!("BAD-{index:05}"), BASE + step)));
    put(&fx.db, TENANT, finding("good", BASE + LATE_STEP));
    let token = login(&fx.router, READER).await?;
    let mut cursor: Option<String> = None;
    let mut seen: Vec<String> = Vec::new();
    let mut pages = 0;
    let mut skipped = 0;
    while pages < FLOOD {
        pages += 1;
        let path = cursor.as_ref().map_or_else(
            || "/hunts/findings?limit=500".to_owned(),
            |next| format!("/hunts/findings?limit=500&cursor={next}"),
        );
        let page = body_json(get(&fx.router, &path, Some(&token)).await?).await?;
        seen.extend(packs(&page)?);
        skipped += page.get("skipped").and_then(Value::as_u64).ok_or("no skipped")?;
        cursor = next_of(&page);
        if cursor.is_none() {
            pages = FLOOD;
        }
    }
    assert_eq!(seen, ["good"]);
    assert_eq!(skipped, u64::try_from(MANY_BAD)?);
    Ok(())
}


#[tokio::test]
async fn a_refused_time_is_left_out_and_counted_without_a_cursor_past_it() -> TestResult {
    let fx = fixture()?;
    put(&fx.db, TENANT, finding("good", BASE));
    let mut bad_start = finding("early", BASE + 1);
    bad_start.window_start = FIRST_END - 1;
    put(&fx.db, TENANT, bad_start);
    put(&fx.db, TENANT, finding("late", YEAR_10000));
    let token = login(&fx.router, READER).await?;
    let page = body_json(get(&fx.router, "/hunts/findings?limit=3", Some(&token)).await?).await?;
    assert_eq!(packs(&page)?, ["good"]);
    assert_eq!(page.get("skipped"), Some(&Value::from(PAGE_OF_TWO)));
    assert_eq!(page.get("next_cursor"), Some(&Value::Null));
    let cut = body_json(get(&fx.router, "/hunts/findings?limit=2", Some(&token)).await?).await?;
    assert_eq!(packs(&cut)?, ["good"]);
    assert!(next_of(&cut).is_some());
    Ok(())
}


#[tokio::test]
async fn only_events_read_is_admitted() -> TestResult {
    let (fx, token) = seeded().await?;
    assert_eq!(get(&fx.router, "/hunts/findings", Some(&token)).await?.status(), StatusCode::OK);
    let nobody = login(&fx.router, NOBODY).await?;
    assert_eq!(get(&fx.router, "/hunts/findings", Some(&nobody)).await?.status(), StatusCode::FORBIDDEN);
    assert_eq!(get(&fx.router, "/hunts/findings", None).await?.status(), StatusCode::UNAUTHORIZED);
    let post = http::call(&fx.router, "POST", "/hunts/findings", Some(&token), axum::body::Body::empty()).await?;
    assert!(post.status().is_client_error());
    Ok(())
}


async fn capture(fx: &Fixture, token: &str) -> Result<(StatusCode, String, String), TestError> {
    std::sync::LazyLock::force(&ANCHOR);
    let sink = Sink::default();
    let writer = sink.clone();
    let dispatch = Dispatch::new(tracing_subscriber::fmt().with_writer(move || writer.clone()).finish());
    let found = get(&fx.router, "/hunts/findings", Some(token)).with_subscriber(dispatch).await?;
    let status = found.status();
    let body = String::from_utf8(to_bytes(found.into_body(), BODY_READ_LIMIT).await?.to_vec())?;
    let logs = String::from_utf8(lock(&sink.0).clone())?;
    Ok((status, body, logs))
}


#[tokio::test]
async fn a_store_failure_is_a_fixed_500_and_its_text_reaches_neither_reply_nor_log() -> TestResult {
    let (fx, token) = seeded().await?;
    *lock(&fx.db.fail_list) = true;
    let (status, body, logs) = capture(&fx, &token).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.contains(MARKER) && !logs.contains(MARKER), "{body} {logs}");
    assert!(logs.contains("database"), "{logs}");
    *lock(&fx.db.fail_list) = false;
    *lock(&fx.db.empty_count) = true;
    let (second, second_body, second_logs) = capture(&fx, &token).await?;
    assert_eq!(second, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!second_body.contains(MARKER) && second_logs.contains("reply"), "{second_logs}");
    assert_eq!(fx.permits.available_permits(), PERMITS);
    Ok(())
}


#[test]
fn failures_map_to_stable_errors_and_categories() -> TestResult {
    assert_eq!(findings_failure(&FindingsError::BadCursor), ApiError::BadRequest);
    assert_eq!(findings_failure(&FindingsError::BadPageSize), ApiError::BadRequest);
    assert_eq!(findings_failure(&FindingsError::Busy), ApiError::TooManyRequests);
    assert_eq!(findings_failure(&FindingsError::Store(StateError::InvalidPackId)), ApiError::Internal);
    assert_eq!(store_category(&StateError::Pg(marker_error())), "database");
    assert_eq!(store_category(&StateError::BadReply), "reply");
    assert_eq!(store_category(&StateError::InvalidPackId), "refused");
    let bad_tenant = tenant_scope("-x").err().ok_or("accepted")?;
    assert!(matches!(bad_tenant, PgError::InvalidTenant));
    Ok(())
}


#[test]
fn views_cut_the_oversized_count_and_check_times() -> TestResult {
    assert_eq!(oversized_view(1).count, 1);
    assert!(!oversized_view(OVERSIZED_REPORT_CAP).capped);
    let capped = oversized_view(OVERSIZED_REPORT_CAP + 1);
    assert_eq!((capped.count, capped.capped), (OVERSIZED_REPORT_CAP, true));
    assert_eq!(time_text(0).as_deref(), Some("1970-01-01T00:00:00Z"));
    assert_eq!(time_text(MAX_END).as_deref(), Some("9999-12-31T23:59:59Z"));
    assert!(time_text(YEAR_10000).is_none());
    let empty = findings_view(FindingsReply {
        page: FindingPage::default(),
        oversized: 0,
    });
    assert!(empty.items.is_empty() && empty.next_cursor.is_none());
    let query = query_of(&ListQuery { cursor: None, limit: None })?;
    assert_eq!(
        query,
        FindingsQuery {
            after: (FIRST_END, String::new()),
            size: DEFAULT_LIMIT
        }
    );
    assert!(serde_json::to_string(&hunts_document())?.contains("/hunts/findings"));
    Ok(())
}


#[tokio::test]
async fn a_flood_takes_one_permit_each_and_never_more_than_the_shared_pool() -> TestResult {
    let db = Arc::new(fixture::Db::default());
    let permits = Arc::new(Semaphore::new(PERMITS));
    let during = Arc::new(Mutex::new(Vec::new()));
    let probe_permits = Arc::clone(&permits);
    let probe_during = Arc::clone(&during);
    let inner: FindingsFn = Arc::new(move |scope, query| {
        lock(&probe_during).push(probe_permits.available_permits());
        memory_backend(&db)(scope, query)
    });
    let backend = permit_backend(Arc::clone(&permits), inner);
    let scope = tenant_scope(TENANT)?;
    let query = FindingsQuery {
        after: (FIRST_END, String::new()),
        size: 1,
    };
    let pending: Vec<_> = (0..FLOOD).map(|_| backend(scope.clone(), query.clone())).collect();
    assert_eq!(permits.available_permits(), 0);
    let outcomes = futures_join(pending).await;
    let busy = outcomes.iter().filter(|outcome| matches!(outcome, Err(FindingsError::Busy))).count();
    assert_eq!(busy, FLOOD - PERMITS);
    assert_eq!(lock(&during).len(), PERMITS);
    assert_eq!(permits.available_permits(), PERMITS);
    Ok(())
}


async fn futures_join<Output>(pending: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = Output> + Send>>>) -> Vec<Output> {
    let mut done = Vec::new();
    for future in pending {
        done.push(future.await);
    }
    done
}


#[tokio::test]
async fn a_full_pool_is_a_429_before_any_statement() -> TestResult {
    let fx = fixture_with(0, memory_backend)?;
    let token = login(&fx.router, READER).await?;
    assert_eq!(
        get(&fx.router, "/hunts/findings", Some(&token)).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(lock(&fx.db.tenants_seen).is_empty());
    Ok(())
}


#[tokio::test]
async fn an_invalid_session_tenant_is_refused_before_the_backend() -> TestResult {
    let db = Arc::new(fixture::Db::default());
    let backend = memory_backend(&db);
    let session = ApiIdentity {
        module: "hunts".to_owned(),
        tenant: "-x".to_owned(),
        generation: 0,
    };
    let query = ListQuery { cursor: None, limit: None };
    let refused = findings_flow(&session, &backend, Ok(query)).await;
    assert_eq!(refused.err(), Some(ApiError::Internal));
    assert!(scope_of(&session).is_err());
    assert!(lock(&db.tenants_seen).is_empty());
    Ok(())
}
