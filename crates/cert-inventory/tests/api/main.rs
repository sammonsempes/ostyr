mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
#[path = "../common/store_fake.rs"]
mod store_fake;
mod types;


use alerts::error::StoreError as LeaseError;
use axum::http::StatusCode;
use cert_inventory::api::{
    certificates_access, certificates_document, expiry_text, failure_category, parse_expiring_before, parse_limit, rfc3339, scope_of, store_failure,
    DEFAULT_LIMIT, MAX_CURSOR_CHARS,
};
use cert_inventory::api_model::CertBackend;
use cert_inventory::error::InventoryStoreError;
use cert_inventory::model::ExpiryState;
use cert_inventory::store::{get_detail, MAX_PAGE, MAX_SIGHTINGS_READ};
use core_api::model::{ApiError, ApiIdentity};
use core_pg::error::PgError;
use fixture::{fingerprint_of, fixture, fixture_with, memory_backend, put, reads, sight, stored, ANALYST, DAY, NOW, OTHER_TENANT, READER, TENANT};
use http::{body_json, call, get, login};
use serde_json::{json, Value};
use std::sync::Arc;
use store_fake::{capture_dispatch, fixed, Capture};
use types::TestResult;


const FAR_YEAR_10000: i64 = 253_402_300_800;


const MARKER: &str = "SECRET-MARKER-7f3a";


const HUGE_CURSOR: usize = 60_000;


const MANY: usize = 20;


const SECOND: usize = 2;


const THIRD: usize = 3;


const FOURTH: usize = 4;


const FIFTH: usize = 5;


const SIXTH: usize = 6;


const NINTH: usize = 9;


const KEY_BITS: usize = 2048;


const ESC_BYTE: u8 = 0x1b;


const FIFTH_SECONDS: i64 = 5;


const TWO_DAYS: i64 = 2 * DAY;


const THREE_DAYS: i64 = 3 * DAY;


const HUNDRED_DAYS: i64 = 100 * DAY;


fn items(json: &Value) -> Result<&Vec<Value>, types::TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


fn fingerprints(json: &Value) -> Result<Vec<String>, types::TestError> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| item.get("fingerprint").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}


fn code_of(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


#[tokio::test]
async fn the_list_is_ordered_by_expiry_with_the_state_and_only_the_tenant_rows() -> TestResult {
    let fx = fixture()?;
    put(&fx.fake, TENANT, 1, stored("CN=expired", NOW - 1));
    put(&fx.fake, TENANT, SECOND, stored("CN=near", NOW + DAY));
    put(&fx.fake, TENANT, THIRD, stored("CN=ok", NOW + HUNDRED_DAYS));
    put(&fx.fake, OTHER_TENANT, FOURTH, stored("CN=foreign", NOW));
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, "/certificates", Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_json(response).await?;
    assert_eq!(fingerprints(&page)?, [fingerprint_of(1), fingerprint_of(SECOND), fingerprint_of(THIRD)]);
    let states: Vec<&str> = items(&page)?
        .iter()
        .filter_map(|item| item.get("expiry").and_then(Value::as_str))
        .collect();
    assert_eq!(states, ["expired", "near", "ok"]);
    assert_eq!(page.get("skipped"), Some(&json!(0)));
    assert_eq!(page.get("next_cursor"), Some(&Value::Null));
    let head = items(&page)?.first().ok_or("empty")?;
    assert_eq!(head.get("not_after"), Some(&json!("2027-01-15T07:59:59Z")));
    assert_eq!(head.get("key_bits"), Some(&json!(KEY_BITS)));
    assert_eq!(head.get("dns_names"), Some(&json!(["a.example.com"])));
    assert!(head.get("tenant").is_none());
    assert_eq!(reads(&fx.fake), 1);
    Ok(())
}


#[tokio::test]
async fn limits_and_times_are_checked_before_any_store_call() -> TestResult {
    let fx = fixture()?;
    (0..MANY).for_each(|index| put(&fx.fake, TENANT, index, stored("CN=x", NOW + i64::try_from(index).unwrap_or(0))));
    let token = login(&fx.router, ANALYST).await?;
    let ok = [
        "limit=1",
        "limit=500",
        "expiring_before=-5",
        "expiring_before=0",
        "expiring_before=253402300799",
    ];
    for query in ok {
        let response = get(&fx.router, &format!("/certificates?{query}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::OK, "{query}");
    }
    let before = reads(&fx.fake);
    let bad = [
        "limit=0".to_owned(),
        "limit=501".to_owned(),
        "limit=abc".to_owned(),
        "limit=-1".to_owned(),
        "limit=+5".to_owned(),
        "limit=1&limit=2".to_owned(),
        "expiring_before=253402300800".to_owned(),
        "expiring_before=-62167219201".to_owned(),
        "expiring_before=abc".to_owned(),
        "expiring_before=".to_owned(),
        "expiring_before=-".to_owned(),
        "expiring_before=99999999999999999999999".to_owned(),
        "cursor=junk".to_owned(),
        format!("cursor={}", "1".repeat(HUGE_CURSOR)),
        format!("cursor={}", "1".repeat(MAX_CURSOR_CHARS + 1)),
        format!("tenant={OTHER_TENANT}"),
    ];
    for query in bad {
        let response = get(&fx.router, &format!("/certificates?{query}"), Some(&token)).await?;
        let shown = query.chars().take(MARKER.len()).collect::<String>();
        assert!(matches!(response.status(), StatusCode::BAD_REQUEST | StatusCode::URI_TOO_LONG), "{shown}");
    }
    assert_eq!(reads(&fx.fake), before);
    let default = body_json(get(&fx.router, "/certificates", Some(&token)).await?).await?;
    assert_eq!(items(&default)?.len(), MANY);
    let five_hundred = body_json(get(&fx.router, "/certificates?limit=500", Some(&token)).await?).await?;
    assert_eq!(items(&five_hundred)?.len(), MANY);
    Ok(())
}


#[tokio::test]
async fn a_cursor_walks_two_certificates_with_one_expiry_and_every_page_size() -> TestResult {
    let fx = fixture()?;
    put(&fx.fake, TENANT, 1, stored("CN=a", NOW + DAY));
    put(&fx.fake, TENANT, SECOND, stored("CN=b", NOW + DAY));
    put(&fx.fake, TENANT, THIRD, stored("CN=c", NOW + TWO_DAYS));
    put(&fx.fake, OTHER_TENANT, FOURTH, stored("CN=foreign", NOW + DAY));
    let token = login(&fx.router, ANALYST).await?;
    let first = body_json(get(&fx.router, "/certificates?limit=1", Some(&token)).await?).await?;
    assert_eq!(fingerprints(&first)?, [fingerprint_of(1)]);
    let cursor = first.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let second = body_json(get(&fx.router, &format!("/certificates?limit=1&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(fingerprints(&second)?, [fingerprint_of(SECOND)]);
    let after_second = second.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let third = body_json(get(&fx.router, &format!("/certificates?limit=1&cursor={after_second}"), Some(&token)).await?).await?;
    assert_eq!(fingerprints(&third)?, [fingerprint_of(THIRD)]);
    assert_eq!(third.get("next_cursor"), Some(&Value::Null));
    let forged = format!("0:{}", fingerprint_of(FOURTH));
    let moved = body_json(get(&fx.router, &format!("/certificates?cursor={forged}"), Some(&token)).await?).await?;
    assert_eq!(fingerprints(&moved)?, [fingerprint_of(1), fingerprint_of(SECOND), fingerprint_of(THIRD)]);
    assert!(lock_reads(&fx).iter().all(|(tenant, _sql)| tenant == TENANT));
    Ok(())
}


fn lock_reads(fx: &fixture::Fixture) -> Vec<(String, &'static str)> {
    fixture::lock(&fx.fake.state).reads.clone()
}


#[tokio::test]
async fn a_bad_stored_row_is_skipped_and_counted_and_the_walk_goes_on() -> TestResult {
    let fx = fixture()?;
    put(&fx.fake, TENANT, 1, stored("CN=a", NOW + DAY));
    let mut broken = stored("CN=broken", NOW + TWO_DAYS);
    broken.key_type = "dsa".to_owned();
    put(&fx.fake, TENANT, SECOND, broken.clone());
    put(&fx.fake, TENANT, THIRD, stored("CN=c", NOW + THREE_DAYS));
    put(&fx.fake, TENANT, FOURTH, stored("CN=far", FAR_YEAR_10000));
    let token = login(&fx.router, ANALYST).await?;
    let all = body_json(get(&fx.router, "/certificates", Some(&token)).await?).await?;
    assert_eq!(fingerprints(&all)?, [fingerprint_of(1), fingerprint_of(THIRD)]);
    assert_eq!(all.get("skipped"), Some(&json!(SECOND)));
    let middle = body_json(get(&fx.router, "/certificates?limit=2", Some(&token)).await?).await?;
    assert_eq!(fingerprints(&middle)?, [fingerprint_of(1)]);
    assert_eq!(middle.get("skipped"), Some(&json!(1)));
    let cursor = middle.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let rest = body_json(get(&fx.router, &format!("/certificates?limit=2&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(fingerprints(&rest)?, [fingerprint_of(THIRD)]);
    assert_eq!(rest.get("skipped"), Some(&json!(1)));
    put(&fx.fake, TENANT, FIFTH, broken.clone());
    put(&fx.fake, TENANT, SIXTH, broken);
    let only_bad = body_json(get(&fx.router, "/certificates?expiring_before=1900000000&limit=2", Some(&token)).await?).await?;
    assert!(only_bad.get("next_cursor").is_some());
    Ok(())
}


#[tokio::test]
async fn a_full_page_of_bad_rows_still_returns_the_next_cursor() -> TestResult {
    let fx = fixture()?;
    let mut broken = stored("CN=broken", NOW + DAY);
    broken.key_type = "dsa".to_owned();
    (1..=THIRD).for_each(|index| put(&fx.fake, TENANT, index, broken.clone()));
    put(&fx.fake, TENANT, FOURTH, stored("CN=good", NOW + TWO_DAYS));
    let token = login(&fx.router, ANALYST).await?;
    let page = body_json(get(&fx.router, "/certificates?limit=2", Some(&token)).await?).await?;
    assert!(items(&page)?.is_empty());
    assert_eq!(page.get("skipped"), Some(&json!(SECOND)));
    let cursor = page.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let next = body_json(get(&fx.router, &format!("/certificates?limit=2&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(fingerprints(&next)?, [fingerprint_of(FOURTH)]);
    assert_eq!(next.get("skipped"), Some(&json!(1)));
    Ok(())
}


#[tokio::test]
async fn the_detail_holds_the_sightings_and_skips_the_bad_ones() -> TestResult {
    let fx = fixture()?;
    put(&fx.fake, TENANT, 1, stored("CN=a", NOW + DAY));
    put(&fx.fake, OTHER_TENANT, 1, stored("CN=a", NOW + DAY));
    sight(&fx.fake, TENANT, 1, "scan", "host:/a.pem", NOW);
    sight(&fx.fake, TENANT, 1, "ct", "log.example.org", NOW - DAY);
    sight(&fx.fake, TENANT, 1, "mail", "bad-kind", NOW);
    sight(&fx.fake, TENANT, 1, "scan", "bad-time", FAR_YEAR_10000);
    sight(&fx.fake, OTHER_TENANT, 1, "scan", "host:/foreign.pem", NOW);
    let token = login(&fx.router, ANALYST).await?;
    let before = reads(&fx.fake);
    let response = get(&fx.router, &format!("/certificates/{}", fingerprint_of(1)), Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let detail = body_json(response).await?;
    assert_eq!(reads(&fx.fake) - before, SECOND);
    assert_eq!(detail.get("subject"), Some(&json!("CN=a")));
    assert_eq!(detail.get("expiry"), Some(&json!("near")));
    assert_eq!(
        detail.get("sightings"),
        Some(&json!([
            {"kind": "ct", "reference": "log.example.org", "last_seen": "2027-01-14T08:00:00Z"},
            {"kind": "scan", "reference": "host:/a.pem", "last_seen": "2027-01-15T08:00:00Z"}
        ]))
    );
    assert_eq!(detail.get("sightings_skipped"), Some(&json!(SECOND)));
    assert_eq!(detail.get("sightings_truncated"), Some(&json!(false)));
    Ok(())
}


#[tokio::test]
async fn five_hundred_sightings_set_the_truncated_flag() -> TestResult {
    let fx = fixture()?;
    put(&fx.fake, TENANT, 1, stored("CN=a", NOW + DAY));
    (0..MAX_SIGHTINGS_READ + 1).for_each(|index| sight(&fx.fake, TENANT, 1, "scan", &format!("host:/{index:04}.pem"), NOW));
    let token = login(&fx.router, ANALYST).await?;
    let detail = body_json(get(&fx.router, &format!("/certificates/{}", fingerprint_of(1)), Some(&token)).await?).await?;
    assert_eq!(detail.get("sightings_truncated"), Some(&json!(true)));
    assert_eq!(detail.get("sightings").and_then(Value::as_array).map(Vec::len), Some(MAX_SIGHTINGS_READ));
    Ok(())
}


#[tokio::test]
async fn a_malformed_or_foreign_fingerprint_is_the_same_fixed_404() -> TestResult {
    let fx = fixture()?;
    put(&fx.fake, OTHER_TENANT, 1, stored("CN=foreign", NOW));
    let token = login(&fx.router, ANALYST).await?;
    let unknown = get(&fx.router, &format!("/certificates/{}", fingerprint_of(NINTH)), Some(&token)).await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let expected = axum::body::to_bytes(unknown.into_body(), http::BODY_READ_LIMIT).await?;
    let upper = fingerprint_of(1).to_uppercase().replace('0', "A");
    let paths = [
        format!("/certificates/{}", fingerprint_of(1)),
        format!("/certificates/{upper}"),
        format!("/certificates/{}", &fingerprint_of(1)[1..]),
        format!("/certificates/{}0", fingerprint_of(1)),
        format!("/certificates/{}%2F", &fingerprint_of(1)[1..]),
        "/certificates/%00".to_owned(),
        "/certificates/%ff".to_owned(),
        format!("/certificates/{}", "x".repeat(MAX_CURSOR_CHARS * SECOND)),
    ];
    let seeded = reads(&fx.fake);
    for path in paths {
        let response = get(&fx.router, &path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{}", path.len());
        let bytes = axum::body::to_bytes(response.into_body(), http::BODY_READ_LIMIT).await?;
        assert_eq!(bytes, expected);
    }
    let json: Value = serde_json::from_slice(&expected)?;
    assert_eq!(code_of(&json), Some("not_found"));
    assert_eq!(reads(&fx.fake) - seeded, 1);
    assert!(lock_reads(&fx).iter().all(|(tenant, _sql)| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn control_bytes_in_stored_text_come_out_json_escaped() -> TestResult {
    let fx = fixture()?;
    let subject = "CN=\u{1b}[31mred\nline";
    put(&fx.fake, TENANT, 1, stored(subject, NOW + DAY));
    sight(&fx.fake, TENANT, 1, "scan", "host:\u{1b}[2J\n", NOW);
    let token = login(&fx.router, ANALYST).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let response = get(&fx.router, &format!("/certificates/{}", fingerprint_of(1)), Some(&token)).await?;
    let bytes = axum::body::to_bytes(response.into_body(), http::BODY_READ_LIMIT).await?;
    let text = String::from_utf8(bytes.to_vec())?;
    assert!(!text.contains('\u{1b}') && !text.contains('\n'));
    assert!(text.contains("\\u001b[31mred\\nline"));
    let listed = get(&fx.router, "/certificates", Some(&token)).await?;
    let list_bytes = axum::body::to_bytes(listed.into_body(), http::BODY_READ_LIMIT).await?;
    assert!(!list_bytes.contains(&ESC_BYTE));
    let logs = String::from_utf8(fixture::lock(&capture.bytes).clone())?;
    assert!(!logs.contains("red") && !logs.contains('\u{1b}'));
    Ok(())
}


#[tokio::test]
async fn the_permission_is_cmdb_read_and_other_methods_are_refused() -> TestResult {
    let fx = fixture()?;
    put(&fx.fake, TENANT, 1, stored("CN=a", NOW + DAY));
    let token = login(&fx.router, ANALYST).await?;
    let reader = login(&fx.router, READER).await?;
    let before = reads(&fx.fake);
    for path in ["/certificates".to_owned(), format!("/certificates/{}", fingerprint_of(1))] {
        assert_eq!(get(&fx.router, &path, None).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, &path, Some("bogus")).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, &path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
        assert_eq!(get(&fx.router, &path, Some(&token)).await?.status(), StatusCode::OK);
        let posted = call(&fx.router, "POST", &path, Some(&token), axum::body::Body::empty()).await?;
        assert!(!posted.status().is_success(), "{}", posted.status());
        let deleted = call(&fx.router, "DELETE", &path, Some(&token), axum::body::Body::empty()).await?;
        assert!(!deleted.status().is_success(), "{}", deleted.status());
    }
    assert_eq!(reads(&fx.fake) - before, THIRD);
    assert_eq!(certificates_access().len(), SECOND);
    Ok(())
}


fn failing_backend(error: fn() -> InventoryStoreError) -> impl FnOnce(&Arc<store_fake::Fake>) -> CertBackend {
    move |fake| CertBackend {
        list: Arc::new(move |_scope, _request| Box::pin(async move { Err(error()) })),
        get: Arc::new(move |_scope, _fingerprint| Box::pin(async move { Err(error()) })),
        ..memory_backend(fake)
    }
}


fn marked_pg_error() -> InventoryStoreError {
    InventoryStoreError::Pg(PgError::Io {
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
    for path in ["/certificates".to_owned(), format!("/certificates/{}", fingerprint_of(1))] {
        let response = get(&fx.router, &path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let shown = format!("{response:?}");
        let json = body_json(response).await?;
        assert_eq!(code_of(&json), Some("internal_error"));
        assert!(!json.to_string().contains(MARKER) && !shown.contains(MARKER));
    }
    let logs = String::from_utf8(fixture::lock(&capture.bytes).clone())?;
    assert!(logs.contains("certificate store failure") && logs.contains("database"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_429_and_an_unwritable_detail_is_500() -> TestResult {
    let busy = fixture_with(failing_backend(|| InventoryStoreError::Lease(LeaseError::Busy)))?;
    let token = login(&busy.router, ANALYST).await?;
    assert_eq!(
        get(&busy.router, "/certificates", Some(&token)).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let fx = fixture()?;
    put(&fx.fake, TENANT, 1, stored("CN=far", FAR_YEAR_10000));
    let analyst = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, &format!("/certificates/{}", fingerprint_of(1)), Some(&analyst)).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
    assert!(matches!(scope_of(&fx.state.identity.load()), Err(InventoryStoreError::Pg(_))));
    assert_eq!(
        get(&fx.router, "/certificates", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let path = format!("/certificates/{}", fingerprint_of(1));
    assert_eq!(get(&fx.router, &path, Some(&token)).await?.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reads(&fx.fake), 0);
    Ok(())
}


#[tokio::test]
async fn the_openapi_document_lists_both_routes() -> TestResult {
    let fx = fixture()?;
    let document = body_json(get(&fx.router, "/openapi.json", None).await?).await?;
    let paths = document.get("paths").ok_or("no paths")?;
    assert!(paths.get("/certificates").and_then(|path| path.get("get")).is_some());
    assert!(paths.get("/certificates/{fingerprint}").and_then(|path| path.get("get")).is_some());
    assert!(serde_json::to_string(&certificates_document())?.contains("CertDetailView"));
    Ok(())
}


#[test]
fn parsers_and_mappings_are_strict() -> TestResult {
    assert!(matches!(parse_limit(None), Ok(DEFAULT_LIMIT)));
    assert!(matches!(parse_limit(Some("500")), Ok(MAX_PAGE)));
    ["", "0", "501", "+5", " 5", "0x10", "1e2"]
        .into_iter()
        .for_each(|text| assert!(parse_limit(Some(text)).is_err(), "{text}"));
    assert_eq!(parse_expiring_before("-5")?, -FIFTH_SECONDS);
    assert_eq!(parse_expiring_before("001")?, 1);
    ["", "-", "--5", "+5", "5 ", "1e3", "253402300800"]
        .into_iter()
        .for_each(|text| assert!(parse_expiring_before(text).is_err(), "{text}"));
    assert_eq!(store_failure(&InventoryStoreError::BadCursor), ApiError::BadRequest);
    assert_eq!(store_failure(&InventoryStoreError::BadFingerprint), ApiError::BadRequest);
    assert_eq!(store_failure(&InventoryStoreError::BadExpiringBefore), ApiError::BadRequest);
    assert_eq!(store_failure(&InventoryStoreError::BadPageSize { limit: 1 }), ApiError::BadRequest);
    assert_eq!(store_failure(&InventoryStoreError::Lease(LeaseError::Busy)), ApiError::TooManyRequests);
    assert_eq!(store_failure(&InventoryStoreError::BadRow { column: 0 }), ApiError::Internal);
    assert_eq!(failure_category(&InventoryStoreError::BadRow { column: 0 }), "stored_value");
    assert_eq!(failure_category(&InventoryStoreError::Unrepresentable), "stored_value");
    assert_eq!(failure_category(&InventoryStoreError::BadNow), "request");
    assert_eq!(expiry_text(ExpiryState::Valid), "ok");
    assert_eq!(expiry_text(ExpiryState::Expired), "expired");
    assert_eq!(expiry_text(ExpiryState::Crossed { threshold_days: 1 }), "near");
    assert_eq!(rfc3339(0)?, "1970-01-01T00:00:00Z");
    assert!(rfc3339(FAR_YEAR_10000).is_err());
    assert!(rfc3339(i64::MIN).is_err());
    Ok(())
}


#[tokio::test]
async fn a_malformed_detail_row_is_a_fixed_500() -> TestResult {
    let fx = fixture_with(|fake| CertBackend {
        get: Arc::new(|scope, fingerprint| Box::pin(async move { get_detail(&fixed(vec![vec!["short".to_owned()]]), &scope, &fingerprint).await })),
        ..memory_backend(fake)
    })?;
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, &format!("/certificates/{}", fingerprint_of(1)), Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}
