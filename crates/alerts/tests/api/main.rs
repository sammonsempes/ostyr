mod fixture;
mod http;
mod memory;
mod settings;
mod swap;
mod types;


use alerts::api::{
    alerts_document, created_time, decode_cursor, encode_cursor, parse_limit, scope_of, store_failure, summary_value, view_of, DEFAULT_LIMIT,
    MAX_CURSOR_CHARS,
};
use alerts::error::StoreError;
use alerts::model::{AlertPage, Backend, Cursor, Summary};
use alerts::store::{MAX_PAGE_SIZE, NEXT_SQL};
use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity};
use core_api::state::RATE_MAX_REQUESTS;
use data_encoding::BASE64URL_NOPAD;
use fixture::{alert, fixture, fixture_with, memory_backend, store, ANALYST, BASE_TIME, OTHER_TENANT, READER, TENANT};
use http::{body_json, get, login};
use memory::{lock, Forced};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use types::TestResult;


const ONE_SECOND_MICROS: u64 = 1_000_000;


const THREE: usize = 3;


const TWO_SECONDS_MICROS: u64 = 2_000_000;


const THREE_SECONDS_MICROS: u64 = 3_000_000;


const TEN_SECONDS_MICROS: u64 = 10_000_000;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const CUT_ORIGINAL_BYTES: u64 = 99;


const BROKEN_ORIGINAL_BYTES: u64 = 8;


const FLOOD: usize = 10;


const HEX_LENGTH: usize = 64;


const HALF_HEX_LENGTH: usize = 32;


async fn seeded() -> Result<(fixture::Fixture, String), types::TestError> {
    let fx = fixture()?;
    store(
        &fx.db,
        &[
            alert(TENANT, "r1", &["e1"], BASE_TIME),
            alert(TENANT, "r2", &["e2"], BASE_TIME + ONE_SECOND_MICROS),
            alert(TENANT, "r3", &["e3"], BASE_TIME + TWO_SECONDS_MICROS),
        ],
    )
    .await?;
    store(&fx.db, &[alert(OTHER_TENANT, "r1", &["e9"], BASE_TIME + THREE_SECONDS_MICROS)]).await?;
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


fn error_code(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


fn items(json: &Value) -> Result<&Vec<Value>, types::TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


#[tokio::test]
async fn listing_pages_newest_first_for_the_module_tenant_only() -> TestResult {
    let (fx, token) = seeded().await?;
    let first = get(&fx.router, "/alerts?limit=2", Some(&token)).await?;
    assert_eq!(first.status(), StatusCode::OK);
    let page = body_json(first).await?;
    let rules: Vec<&str> = items(&page)?
        .iter()
        .filter_map(|item| item.get("rule_id").and_then(Value::as_str))
        .collect();
    assert_eq!(rules, ["r3", "r2"]);
    let cursor = page.get("next_cursor").and_then(Value::as_str).ok_or("no next cursor")?.to_owned();
    assert!(cursor.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    let second = body_json(get(&fx.router, &format!("/alerts?limit=2&cursor={cursor}"), Some(&token)).await?).await?;
    let rest: Vec<&str> = items(&second)?
        .iter()
        .filter_map(|item| item.get("rule_id").and_then(Value::as_str))
        .collect();
    assert_eq!(rest, ["r1"]);
    assert_eq!(second.get("next_cursor"), Some(&Value::Null));
    let first_item = items(&page)?.first().ok_or("empty")?;
    assert_eq!(first_item.get("created").and_then(Value::as_str), Some("2023-11-14T22:13:22Z"));
    assert_eq!(first_item.get("summary"), Some(&json!({"process": {"name": "whoami"}})));
    assert_eq!(first_item.get("summary_truncated"), Some(&json!(false)));
    assert_eq!(first_item.get("host_name"), Some(&json!("host-1")));
    assert_eq!(first_item.get("user_name"), Some(&Value::Null));
    assert_eq!(first_item.get("severity"), Some(&json!("high")));
    assert_eq!(first_item.get("event_ids"), Some(&json!(["e3"])));
    assert!(first_item.get("tenant").is_none());
    Ok(())
}


#[tokio::test]
async fn the_default_limit_serves_every_alert_of_a_small_tenant() -> TestResult {
    let (fx, token) = seeded().await?;
    let page = body_json(get(&fx.router, "/alerts", Some(&token)).await?).await?;
    assert_eq!(items(&page)?.len(), THREE);
    Ok(())
}


#[tokio::test]
async fn a_tenant_cannot_be_chosen_by_parameter_or_header() -> TestResult {
    let (fx, token) = seeded().await?;
    let seeding = lock(&fx.db.statements).len();
    let refused = get(&fx.router, &format!("/alerts?tenant={OTHER_TENANT}"), Some(&token)).await?;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let other = alert(OTHER_TENANT, "r1", &["e9"], BASE_TIME);
    let by_id = get(&fx.router, &format!("/alerts/{}", other.id), Some(&token)).await?;
    assert_eq!(by_id.status(), StatusCode::NOT_FOUND);
    let missing = get(&fx.router, &format!("/alerts/{}", "0".repeat(HEX_LENGTH)), Some(&token)).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let (left, right) = (body_json(by_id).await?, body_json(missing).await?);
    assert_eq!(left, right);
    assert_eq!(error_code(&left), Some("not_found"));
    assert!(lock(&fx.db.statements).iter().skip(seeding).all(|(tenant, _sql)| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn an_own_alert_is_served_by_id_and_a_malformed_id_is_a_404() -> TestResult {
    let (fx, token) = seeded().await?;
    let own = alert(TENANT, "r2", &["e2"], BASE_TIME);
    let found = get(&fx.router, &format!("/alerts/{}", own.id), Some(&token)).await?;
    assert_eq!(found.status(), StatusCode::OK);
    assert_eq!(body_json(found).await?.get("id"), Some(&json!(own.id)));
    let before = lock(&fx.db.statements).len();
    let malformed = get(&fx.router, "/alerts/not-an-id", Some(&token)).await?;
    assert_eq!(malformed.status(), StatusCode::NOT_FOUND);
    assert_eq!(lock(&fx.db.statements).len(), before);
    let missing = body_json(get(&fx.router, &format!("/alerts/{}", "0".repeat(HEX_LENGTH)), Some(&token)).await?).await?;
    let not_utf8 = get(&fx.router, "/alerts/%ff", Some(&token)).await?;
    assert_eq!(not_utf8.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(not_utf8).await?, missing);
    assert_eq!(lock(&fx.db.statements).len(), before + 1);
    Ok(())
}


#[tokio::test]
async fn no_session_is_401_and_a_role_without_alerts_read_is_403_before_any_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let reader = login(&fx.router, READER).await?;
    let before = lock(&fx.db.statements).len();
    for path in ["/alerts", "/alerts/abc"] {
        assert_eq!(get(&fx.router, path, None).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some("bogus")).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(lock(&fx.db.statements).len(), before);
    assert_eq!(get(&fx.router, "/alerts", Some(&token)).await?.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn an_unauthenticated_flood_is_rate_limited_before_any_store_call() -> TestResult {
    let fx = fixture()?;
    let mut last = StatusCode::OK;
    for _ in 0..(RATE_MAX_REQUESTS as usize + FLOOD) {
        last = get(&fx.router, "/alerts", None).await?.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn malformed_queries_are_a_generic_400_without_a_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = lock(&fx.db.statements).len();
    let not_base64 = "!!!";
    let junk = BASE64URL_NOPAD.encode(b"junk");
    let negative = BASE64URL_NOPAD.encode(b"-1.00");
    let injection = BASE64URL_NOPAD.encode(format!("1.{}'; DROP TABLE alerts;--", "a".repeat(HEX_LENGTH)).as_bytes());
    let non_utf8 = BASE64URL_NOPAD.encode(&INVALID_UTF8);
    let too_long = "A".repeat(MAX_CURSOR_CHARS + 1);
    let queries = [
        format!("cursor={not_base64}"),
        format!("cursor={junk}"),
        format!("cursor={negative}"),
        format!("cursor={injection}"),
        format!("cursor={non_utf8}"),
        format!("cursor={too_long}"),
        "limit=0".to_owned(),
        format!("limit={}", MAX_PAGE_SIZE + 1),
        "limit=abc".to_owned(),
        "limit=-1".to_owned(),
        "limit=1&limit=2".to_owned(),
        "limit=99999999999999999999999".to_owned(),
        "unknown=1".to_owned(),
    ];
    for query in queries {
        let response = get(&fx.router, &format!("/alerts?{query}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        let json = body_json(response).await?;
        assert_eq!(error_code(&json), Some("bad_request"), "{query}");
    }
    assert_eq!(lock(&fx.db.statements).len(), before);
    Ok(())
}


#[tokio::test]
async fn a_cursor_only_moves_within_the_session_tenant() -> TestResult {
    let (fx, token) = seeded().await?;
    let seeding = lock(&fx.db.statements).len();
    let forged = encode_cursor(&Cursor {
        created_micros: BASE_TIME + TEN_SECONDS_MICROS,
        id: "f".repeat(HEX_LENGTH),
    });
    let page = body_json(get(&fx.router, &format!("/alerts?cursor={forged}"), Some(&token)).await?).await?;
    assert_eq!(items(&page)?.len(), THREE);
    let statements = lock(&fx.db.statements).clone();
    assert!(statements.iter().any(|(tenant, sql)| tenant == TENANT && *sql == NEXT_SQL));
    assert!(statements.iter().skip(seeding).all(|(tenant, _sql)| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn database_failures_are_a_generic_500() -> TestResult {
    let (fx, token) = seeded().await?;
    lock(&fx.db.forced).push_back(Forced::Fail);
    let listed = get(&fx.router, "/alerts", Some(&token)).await?;
    assert_eq!(listed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(listed).await?;
    assert_eq!(error_code(&json), Some("internal_error"));
    assert!(!json.to_string().contains("XX000") && !json.to_string().contains("internal\""));
    lock(&fx.db.forced).push_back(Forced::Fail);
    let own = alert(TENANT, "r2", &["e2"], BASE_TIME);
    assert_eq!(
        get(&fx.router, &format!("/alerts/{}", own.id), Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    lock(&fx.db.forced).push_back(Forced::Rows(vec![vec![]]));
    assert_eq!(
        get(&fx.router, &format!("/alerts/{}", own.id), Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}


#[tokio::test]
async fn a_path_the_extractor_refuses_never_reaches_the_backend() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let fx = fixture_with(move |_db| Backend {
        list: Arc::new(|_scope, _page| Box::pin(async { Err(StoreError::Busy) })),
        get: Arc::new(move |_scope, _id| {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(None) })
        }),
    })?;
    let token = login(&fx.router, ANALYST).await?;
    assert_eq!(get(&fx.router, "/alerts/%ff", Some(&token)).await?.status(), StatusCode::NOT_FOUND);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(get(&fx.router, "/alerts/abc", Some(&token)).await?.status(), StatusCode::NOT_FOUND);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_a_429() -> TestResult {
    let fx = fixture_with(|_db| Backend {
        list: Arc::new(|_scope, _page| Box::pin(async { Err(StoreError::Busy) })),
        get: Arc::new(|_scope, _id| Box::pin(async { Err(StoreError::Busy) })),
    })?;
    let token = login(&fx.router, ANALYST).await?;
    assert_eq!(get(&fx.router, "/alerts", Some(&token)).await?.status(), StatusCode::TOO_MANY_REQUESTS);
    let id = "0".repeat(HEX_LENGTH);
    assert_eq!(
        get(&fx.router, &format!("/alerts/{id}"), Some(&token)).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}


#[tokio::test]
async fn an_alert_that_cannot_be_rendered_is_a_generic_500() -> TestResult {
    let fx = fixture_with(|_db| Backend {
        list: Arc::new(|_scope, _page| {
            Box::pin(async {
                let mut huge = alert(TENANT, "r", &["e"], BASE_TIME);
                huge.created_micros = u64::MAX;
                Ok(AlertPage {
                    alerts: vec![huge],
                    next: None,
                })
            })
        }),
        get: Arc::new(|_scope, _id| {
            Box::pin(async {
                let mut huge = alert(TENANT, "r", &["e"], BASE_TIME);
                huge.created_micros = u64::MAX;
                Ok(Some(huge))
            })
        }),
    })?;
    let token = login(&fx.router, ANALYST).await?;
    assert_eq!(
        get(&fx.router, "/alerts", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let id = "0".repeat(HEX_LENGTH);
    assert_eq!(
        get(&fx.router, &format!("/alerts/{id}"), Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}


#[tokio::test]
async fn an_unusable_module_tenant_is_a_500_and_the_store_is_never_asked() -> TestResult {
    let fx = fixture_with(memory_backend)?;
    let token = login(&fx.router, ANALYST).await?;
    let current = fx.state.identity.load();
    fx.state.identity.store(Arc::new(ApiIdentity {
        module: current.module.clone(),
        tenant: "bad tenant".to_owned(),
        generation: current.generation + 1,
    }));
    assert!(matches!(scope_of(&fx.state.identity.load()), Err(StoreError::Pg(_))));
    assert_eq!(
        get(&fx.router, "/alerts", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let id = "0".repeat(HEX_LENGTH);
    assert_eq!(
        get(&fx.router, &format!("/alerts/{id}"), Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn the_openapi_document_lists_both_routes() -> TestResult {
    let fx = fixture()?;
    let document = body_json(get(&fx.router, "/openapi.json", None).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    assert!(paths.get("/alerts").and_then(|path| path.get("get")).is_some());
    assert!(paths.get("/alerts/{id}").and_then(|path| path.get("get")).is_some());
    let schemas = document
        .get("components")
        .and_then(|components| components.get("schemas"))
        .ok_or("no schemas")?;
    assert!(schemas.get("AlertView").is_some() && schemas.get("AlertListView").is_some());
    assert!(serde_json::to_string(&alerts_document())?.contains("/alerts/{id}"));
    Ok(())
}


#[test]
fn limits_parse_strictly() -> TestResult {
    assert!(matches!(parse_limit(None), Ok(DEFAULT_LIMIT)));
    assert!(matches!(parse_limit(Some("1")), Ok(1)));
    assert!(matches!(parse_limit(Some("100")), Ok(MAX_PAGE_SIZE)));
    ["", "0", "101", "+5", " 5", "5 ", "0x10", "1e2"]
        .into_iter()
        .for_each(|text| assert!(parse_limit(Some(text)).is_err(), "{text}"));
    Ok(())
}


#[test]
fn cursors_round_trip_and_refuse_bad_text() -> TestResult {
    let cursor = Cursor {
        created_micros: BASE_TIME,
        id: "ab".repeat(HALF_HEX_LENGTH),
    };
    assert_eq!(decode_cursor(&encode_cursor(&cursor))?, cursor);
    assert!(decode_cursor("").is_err());
    assert!(decode_cursor(&"A".repeat(MAX_CURSOR_CHARS + 1)).is_err());
    Ok(())
}


#[test]
fn times_and_summaries_are_rendered_or_refused() -> TestResult {
    assert_eq!(created_time(0)?, "1970-01-01T00:00:00Z");
    assert!(matches!(created_time(u64::MAX), Err(StoreError::BadCreated)));
    let cut = Summary {
        text: "{\"a\":".to_owned(),
        truncated: true,
        original_bytes: CUT_ORIGINAL_BYTES,
    };
    assert_eq!(summary_value(&cut), json!({"text": "{\"a\":"}));
    let scalar = Summary {
        text: "5".to_owned(),
        truncated: false,
        original_bytes: 1,
    };
    assert_eq!(summary_value(&scalar), json!({"text": "5"}));
    let broken = Summary {
        text: "not json".to_owned(),
        truncated: false,
        original_bytes: BROKEN_ORIGINAL_BYTES,
    };
    assert_eq!(summary_value(&broken), json!({"text": "not json"}));
    let mut huge = alert(TENANT, "r", &["e"], BASE_TIME);
    huge.created_micros = u64::MAX;
    assert!(view_of(&huge).is_err());
    Ok(())
}


#[test]
fn store_failures_map_to_stable_errors() -> TestResult {
    assert_eq!(store_failure(&StoreError::BadCursor), ApiError::BadRequest);
    assert_eq!(store_failure(&StoreError::BadPageSize { limit: 1 }), ApiError::BadRequest);
    assert_eq!(store_failure(&StoreError::Busy), ApiError::TooManyRequests);
    assert_eq!(store_failure(&StoreError::BadSummary), ApiError::Internal);
    Ok(())
}
