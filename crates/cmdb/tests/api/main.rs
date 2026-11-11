mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
mod memory;
mod settings;
mod swap;
mod types;


use alerts::error::StoreError as LeaseError;
use axum::body::to_bytes;
use axum::http::StatusCode;
use cmdb::api::{cmdb_document, decode_cursor, encode_cursor, list_view, parse_limit, scope_of, store_failure, DEFAULT_LIMIT, MAX_CURSOR_CHARS};
use cmdb::api_model::CmdbBackend;
use cmdb::error::StoreError;
use cmdb::stored::{AssetPage, SummaryList};
use cmdb::summary::{get_asset_detail, list_asset_summaries, MAX_DETAIL_ATTRIBUTES, MAX_DETAIL_KEYS, MAX_ID_BYTES, MAX_LIST_LIMIT, NEXT_LIST_SQL};
use core_api::model::{ApiError, ApiIdentity};
use core_api::state::RATE_MAX_REQUESTS;
use core_pg::scope::tenant_scope;
use data_encoding::BASE64URL_NOPAD;
use fixture::{asset, executor, fixture, fixture_with, memory_backend, store, ANALYST, OTHER_TENANT, READER, TENANT};
use http::{body_json, get, login, BODY_READ_LIMIT};
use memory::{lock, Forced};
use serde_json::{json, Value};
use std::sync::Arc;
use types::{TestError, TestResult};


const TOTAL: usize = 120;


const SIZES: [usize; 3] = [1, 7, 50];


const LONG_ID: usize = 1_000;


const FLOOD: usize = 10;


const MANY_ATTRIBUTES: usize = 5_000;


const MANY_KEYS: usize = 70;


const SMALL_RESPONSE_BYTES: usize = 4_096;


const BOUNDED_RESPONSE_BYTES: usize = 100_000;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const INVALID_BYTE: u8 = 0xff;


const ASSET_ROWS: usize = 2;


const WIDEST_CHAR_BYTES: usize = 4;


async fn seeded() -> Result<(fixture::Fixture, String), TestError> {
    let fx = fixture()?;
    ["srv-a", "srv-b", "srv-c"].iter().for_each(|id| store(&fx.db, TENANT, id, asset(1)));
    store(&fx.db, OTHER_TENANT, "foreign", asset(1));
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


fn error_code(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


fn items(json: &Value) -> Result<&Vec<Value>, TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


fn ids(json: &Value) -> Result<Vec<String>, TestError> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}


#[tokio::test]
async fn listing_pages_by_id_for_the_session_tenant_only() -> TestResult {
    let (fx, token) = seeded().await?;
    let first = get(&fx.router, "/assets?limit=2", Some(&token)).await?;
    assert_eq!(first.status(), StatusCode::OK);
    let page = body_json(first).await?;
    assert_eq!(ids(&page)?, ["srv-a", "srv-b"]);
    let cursor = page.get("next_cursor").and_then(Value::as_str).ok_or("no next cursor")?.to_owned();
    assert!(cursor.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    let second = body_json(get(&fx.router, &format!("/assets?limit=2&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(ids(&second)?, ["srv-c"]);
    assert_eq!(second.get("next_cursor"), Some(&Value::Null));
    let head = items(&page)?.first().ok_or("empty")?;
    assert_eq!(head.get("kind"), Some(&json!("server")));
    assert_eq!(head.get("lifecycle"), Some(&json!("in_service")));
    assert_eq!(head.get("version"), Some(&json!(1)));
    assert_eq!(
        head.get("counts"),
        Some(&json!({"keys": ASSET_ROWS, "attributes": ASSET_ROWS, "open_conflicts": 1}))
    );
    assert!(head.get("tenant").is_none() && head.get("keys").is_none() && head.get("attributes").is_none());
    let everything = body_json(get(&fx.router, "/assets", Some(&token)).await?).await?;
    assert_eq!(ids(&everything)?, ["srv-a", "srv-b", "srv-c"]);
    Ok(())
}


#[tokio::test]
async fn the_detail_holds_keys_attributes_and_the_conflict_count() -> TestResult {
    let (fx, token) = seeded().await?;
    let found = get(&fx.router, "/assets/srv-b", Some(&token)).await?;
    assert_eq!(found.status(), StatusCode::OK);
    let detail = body_json(found).await?;
    assert_eq!(detail.get("id"), Some(&json!("srv-b")));
    assert_eq!(detail.get("counts").and_then(|counts| counts.get("open_conflicts")), Some(&json!(1)));
    assert_eq!(
        detail.get("keys"),
        Some(&json!([{"key": "mac", "value": "aa:bb"}, {"key": "serial_number", "value": "SN-1"}]))
    );
    assert_eq!(
        detail.get("attributes"),
        Some(&json!([
            {"name": "owner", "value": "alice", "source": "declared"},
            {"name": "rack", "value": "r1", "source": "agent"}
        ]))
    );
    assert_eq!(detail.get("truncated"), Some(&json!(false)));
    assert!(detail.get("tenant").is_none());
    Ok(())
}


#[tokio::test]
async fn a_tenant_cannot_be_chosen_by_parameter_or_header() -> TestResult {
    let (fx, token) = seeded().await?;
    let seeding = lock(&fx.db.statements).len();
    let refused = get(&fx.router, &format!("/assets?tenant={OTHER_TENANT}"), Some(&token)).await?;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let by_id = get(&fx.router, "/assets/foreign", Some(&token)).await?;
    assert_eq!(by_id.status(), StatusCode::NOT_FOUND);
    let missing = get(&fx.router, "/assets/nothing", Some(&token)).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let (left, right) = (body_json(by_id).await?, body_json(missing).await?);
    assert_eq!(left, right);
    assert_eq!(error_code(&left), Some("not_found"));
    assert!(lock(&fx.db.statements).iter().skip(seeding).all(|(tenant, _sql)| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn a_malformed_id_is_the_same_404_without_a_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let missing = body_json(get(&fx.router, "/assets/nothing", Some(&token)).await?).await?;
    let before = lock(&fx.db.statements).len();
    let paths = [
        "/assets/%00".to_owned(),
        "/assets/%ff".to_owned(),
        "/assets/%c0%af".to_owned(),
        "/assets/%ed%a0%80".to_owned(),
        format!("/assets/{}", "x".repeat(MAX_ID_BYTES + 1)),
        format!("/assets/{}", "x".repeat(LONG_ID)),
    ];
    for path in paths {
        let response = get(&fx.router, &path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body_json(response).await?, missing);
    }
    assert_eq!(lock(&fx.db.statements).len(), before);
    Ok(())
}


#[tokio::test]
async fn an_encoded_slash_or_a_double_encoding_is_the_same_404() -> TestResult {
    let (fx, token) = seeded().await?;
    let missing = body_json(get(&fx.router, "/assets/nothing", Some(&token)).await?).await?;
    for path in ["/assets/srv-a%2fx", "/assets/%252f", "/assets/%2e%2e%2fsrv-a"] {
        let response = get(&fx.router, path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body_json(response).await?, missing, "{path}");
    }
    Ok(())
}


#[tokio::test]
async fn no_session_is_401_and_a_reader_is_403_before_any_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let reader = login(&fx.router, READER).await?;
    let before = lock(&fx.db.statements).len();
    for path in ["/assets", "/assets/srv-a"] {
        assert_eq!(get(&fx.router, path, None).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some("bogus")).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(lock(&fx.db.statements).len(), before);
    assert_eq!(get(&fx.router, "/assets", Some(&token)).await?.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn an_unauthenticated_flood_is_rate_limited_before_any_store_call() -> TestResult {
    let fx = fixture_with(memory_backend)?;
    let mut last = StatusCode::OK;
    for _ in 0..(RATE_MAX_REQUESTS as usize + FLOOD) {
        last = get(&fx.router, "/assets", None).await?.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn malformed_queries_are_a_generic_400_without_a_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = lock(&fx.db.statements).len();
    let junk = BASE64URL_NOPAD.encode(&[INVALID_BYTE]);
    let empty_id = BASE64URL_NOPAD.encode(b"");
    let nul = BASE64URL_NOPAD.encode(b"a\0b");
    let injection = BASE64URL_NOPAD.encode(b"x'; DROP TABLE cmdb_assets;--\0");
    let non_utf8 = BASE64URL_NOPAD.encode(&INVALID_UTF8);
    let long_id = BASE64URL_NOPAD.encode("x".repeat(MAX_ID_BYTES + 1).as_bytes());
    let too_long = "A".repeat(MAX_CURSOR_CHARS + 1);
    let queries = [
        "cursor=!!!".to_owned(),
        format!("cursor={junk}"),
        format!("cursor={empty_id}"),
        format!("cursor={nul}"),
        format!("cursor={injection}"),
        format!("cursor={non_utf8}"),
        format!("cursor={long_id}"),
        format!("cursor={too_long}"),
        "limit=0".to_owned(),
        format!("limit={}", MAX_LIST_LIMIT + 1),
        "limit=1e3".to_owned(),
        "limit=abc".to_owned(),
        "limit=-1".to_owned(),
        "limit=1&limit=2".to_owned(),
        "limit=99999999999999999999999".to_owned(),
        "unknown=1".to_owned(),
        format!("tenant={OTHER_TENANT}"),
    ];
    for query in queries {
        let response = get(&fx.router, &format!("/assets?{query}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(error_code(&body_json(response).await?), Some("bad_request"), "{query}");
    }
    assert_eq!(lock(&fx.db.statements).len(), before);
    Ok(())
}


#[tokio::test]
async fn a_forged_cursor_only_moves_within_the_session_tenant() -> TestResult {
    let (fx, token) = seeded().await?;
    let seeding = lock(&fx.db.statements).len();
    let forged = encode_cursor("zzz");
    let page = body_json(get(&fx.router, &format!("/assets?cursor={forged}"), Some(&token)).await?).await?;
    assert_eq!(ids(&page)?, Vec::<String>::new());
    let before_all = encode_cursor("a");
    let all = body_json(get(&fx.router, &format!("/assets?cursor={before_all}"), Some(&token)).await?).await?;
    assert_eq!(ids(&all)?, ["srv-a", "srv-b", "srv-c"]);
    let statements = lock(&fx.db.statements).clone();
    assert!(statements.iter().any(|(tenant, sql)| tenant == TENANT && *sql == NEXT_LIST_SQL));
    assert!(statements.iter().skip(seeding).all(|(tenant, _sql)| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn every_asset_is_listed_once_whatever_the_page_size() -> TestResult {
    let fx = fixture()?;
    (0..TOTAL).for_each(|index| store(&fx.db, TENANT, &format!("asset-{index:03}"), asset(1)));
    store(&fx.db, OTHER_TENANT, "foreign", asset(1));
    let token = login(&fx.router, ANALYST).await?;
    for size in SIZES {
        let mut listed = Vec::new();
        let mut path = format!("/assets?limit={size}");
        let mut attempts = 0;
        while attempts <= TOTAL {
            let page = body_json(get(&fx.router, &path, Some(&token)).await?).await?;
            listed.extend(ids(&page)?);
            let next = page.get("next_cursor").and_then(Value::as_str).map(str::to_owned);
            attempts = next.as_ref().map_or(TOTAL + 1, |_cursor| attempts + 1);
            path = next.map_or_else(String::new, |cursor| format!("/assets?limit={size}&cursor={cursor}"));
        }
        let mut sorted = listed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(listed.len(), TOTAL, "size {size}");
        assert_eq!(sorted, listed, "size {size}");
        assert!(!listed.iter().any(|id| id == "foreign"));
    }
    Ok(())
}


#[tokio::test]
async fn an_asset_with_thousands_of_attributes_gives_a_bounded_detail_with_the_flag() -> TestResult {
    let (fx, token) = seeded().await?;
    let mut big = asset(1);
    big.attributes = (0..MANY_ATTRIBUTES)
        .map(|index| (format!("attr-{index:05}"), "v".to_owned(), "agent".to_owned()))
        .collect();
    big.keys = (0..MANY_KEYS).map(|index| (format!("key-{index:03}"), "v".to_owned())).collect();
    store(&fx.db, TENANT, "big", big);
    let detail = get(&fx.router, "/assets/big", Some(&token)).await?;
    let bytes = to_bytes(detail.into_body(), BODY_READ_LIMIT).await?;
    assert!(bytes.len() < BOUNDED_RESPONSE_BYTES, "{}", bytes.len());
    let json: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(json.get("truncated"), Some(&json!(true)));
    assert_eq!(
        json.get("attributes").and_then(Value::as_array).map(Vec::len),
        Some(MAX_DETAIL_ATTRIBUTES)
    );
    assert_eq!(json.get("keys").and_then(Value::as_array).map(Vec::len), Some(MAX_DETAIL_KEYS));
    assert_eq!(
        json.get("counts").and_then(|counts| counts.get("attributes")),
        Some(&json!(MANY_ATTRIBUTES))
    );
    let first = json.get("attributes").and_then(Value::as_array).and_then(|list| list.first());
    assert_eq!(first.and_then(|item| item.get("name")), Some(&json!("attr-00000")));
    let listed = get(&fx.router, "/assets", Some(&token)).await?;
    assert!(to_bytes(listed.into_body(), BODY_READ_LIMIT).await?.len() < SMALL_RESPONSE_BYTES);
    Ok(())
}


#[tokio::test]
async fn only_one_side_over_the_cap_still_sets_the_flag() -> TestResult {
    let (fx, token) = seeded().await?;
    let mut many_keys = asset(1);
    many_keys.keys = (0..MANY_KEYS).map(|index| (format!("key-{index:03}"), "v".to_owned())).collect();
    store(&fx.db, TENANT, "keys-only", many_keys);
    let keys_json = body_json(get(&fx.router, "/assets/keys-only", Some(&token)).await?).await?;
    assert_eq!(keys_json.get("truncated"), Some(&json!(true)));
    let mut many_attributes = asset(1);
    many_attributes.attributes = (0..=MAX_DETAIL_ATTRIBUTES)
        .map(|index| (format!("attr-{index:05}"), "v".to_owned(), "agent".to_owned()))
        .collect();
    store(&fx.db, TENANT, "attributes-only", many_attributes);
    let attributes_json = body_json(get(&fx.router, "/assets/attributes-only", Some(&token)).await?).await?;
    assert_eq!(attributes_json.get("truncated"), Some(&json!(true)));
    Ok(())
}


#[tokio::test]
async fn database_failures_are_a_generic_500() -> TestResult {
    let (fx, token) = seeded().await?;
    lock(&fx.db.forced).push_back(Forced::Fail);
    let listed = get(&fx.router, "/assets", Some(&token)).await?;
    assert_eq!(listed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(listed).await?;
    assert_eq!(error_code(&json), Some("internal_error"));
    assert!(!json.to_string().contains("XX000") && !json.to_string().contains("internal\""));
    lock(&fx.db.forced).push_back(Forced::Fail);
    assert_eq!(
        get(&fx.router, "/assets/srv-a", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    lock(&fx.db.forced).push_back(Forced::Rows(vec![vec![]]));
    assert_eq!(
        get(&fx.router, "/assets/srv-a", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    lock(&fx.db.forced).push_back(Forced::Rows(vec![vec![]]));
    assert_eq!(
        get(&fx.router, "/assets", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}


#[tokio::test]
async fn a_second_statement_failing_or_malformed_is_a_generic_500() -> TestResult {
    let (fx, token) = seeded().await?;
    let summary = ["srv-a", "server", "in_service", "1", "2", "2", "0"].map(str::to_owned).to_vec();
    let bad_count = ["srv-a", "server", "in_service", "1", "x", "2", "0"].map(str::to_owned).to_vec();
    let forced = [
        vec![Forced::Rows(vec![summary.clone()]), Forced::Fail],
        vec![Forced::Rows(vec![summary.clone()]), Forced::Rows(Vec::new()), Forced::Fail],
        vec![Forced::Rows(vec![summary]), Forced::Rows(vec![vec![]])],
        vec![Forced::Rows(vec![bad_count])],
    ];
    for steps in forced {
        steps.into_iter().for_each(|step| lock(&fx.db.forced).push_back(step));
        assert_eq!(
            get(&fx.router, "/assets/srv-a", Some(&token)).await?.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        lock(&fx.db.forced).clear();
    }
    Ok(())
}


#[tokio::test]
async fn a_malformed_attribute_row_is_a_generic_500() -> TestResult {
    let (fx, token) = seeded().await?;
    let summary = ["srv-a", "server", "in_service", "1", "0", "1", "0"].map(str::to_owned).to_vec();
    lock(&fx.db.forced).push_back(Forced::Rows(vec![summary]));
    lock(&fx.db.forced).push_back(Forced::Rows(Vec::new()));
    lock(&fx.db.forced).push_back(Forced::Rows(vec![vec!["only".to_owned()]]));
    assert_eq!(
        get(&fx.router, "/assets/srv-a", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_a_429() -> TestResult {
    let fx = fixture_with(|_db| CmdbBackend {
        list: Arc::new(|_scope, _page| Box::pin(async { Err(StoreError::Lease(LeaseError::Busy)) })),
        get: Arc::new(|_scope, _id| Box::pin(async { Err(StoreError::Lease(LeaseError::Busy)) })),
    })?;
    let token = login(&fx.router, ANALYST).await?;
    assert_eq!(get(&fx.router, "/assets", Some(&token)).await?.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(get(&fx.router, "/assets/a", Some(&token)).await?.status(), StatusCode::TOO_MANY_REQUESTS);
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
    assert!(matches!(scope_of(&fx.state.identity.load()), Err(StoreError::Pg(_))));
    assert_eq!(
        get(&fx.router, "/assets", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get(&fx.router, "/assets/a", Some(&token)).await?.status(),
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
    assert!(paths.get("/assets").and_then(|path| path.get("get")).is_some());
    assert!(paths.get("/assets/{id}").and_then(|path| path.get("get")).is_some());
    let schemas = document
        .get("components")
        .and_then(|components| components.get("schemas"))
        .ok_or("no schemas")?;
    assert!(["AssetSummary", "AssetDetail", "AssetCounts", "AssetListView"]
        .iter()
        .all(|name| schemas.get(*name).is_some()));
    assert!(serde_json::to_string(&cmdb_document())?.contains("/assets/{id}"));
    Ok(())
}


#[test]
fn limits_parse_strictly() -> TestResult {
    assert!(matches!(parse_limit(None), Ok(DEFAULT_LIMIT)));
    assert!(matches!(parse_limit(Some("1")), Ok(1)));
    assert!(matches!(parse_limit(Some("100")), Ok(MAX_LIST_LIMIT)));
    ["", "0", "101", "+5", " 5", "5 ", "0x10", "1e2"]
        .into_iter()
        .for_each(|text| assert!(parse_limit(Some(text)).is_err(), "{text}"));
    Ok(())
}


#[test]
fn cursors_round_trip_and_a_longest_id_fits() -> TestResult {
    let widest = "\u{1F600}".repeat(MAX_ID_BYTES / WIDEST_CHAR_BYTES);
    assert_eq!(decode_cursor(&encode_cursor(&widest))?, widest);
    let longest = "x".repeat(MAX_ID_BYTES);
    assert!(encode_cursor(&longest).len() <= MAX_CURSOR_CHARS);
    assert_eq!(decode_cursor(&encode_cursor(&longest))?, longest);
    assert!(decode_cursor("").is_err());
    assert!(decode_cursor(&"A".repeat(MAX_CURSOR_CHARS + 1)).is_err());
    Ok(())
}


#[test]
fn store_failures_map_to_stable_errors_and_an_empty_page_has_no_cursor() -> TestResult {
    assert_eq!(store_failure(&StoreError::BadCursor), ApiError::BadRequest);
    assert_eq!(store_failure(&StoreError::BadId), ApiError::BadRequest);
    assert_eq!(store_failure(&StoreError::BadPageSize { limit: 1 }), ApiError::BadRequest);
    assert_eq!(store_failure(&StoreError::Lease(LeaseError::Busy)), ApiError::TooManyRequests);
    assert_eq!(store_failure(&StoreError::Lease(LeaseError::BadCursor)), ApiError::Internal);
    assert_eq!(store_failure(&StoreError::VersionConflict), ApiError::Internal);
    let view = list_view(SummaryList {
        summaries: Vec::new(),
        next: None,
    });
    assert!(view.items.is_empty() && view.next_cursor.is_none());
    Ok(())
}


#[tokio::test]
async fn the_store_refuses_a_bad_page_or_id_before_any_statement() -> TestResult {
    let fx = fixture()?;
    let scope = tenant_scope(TENANT)?;
    let run = executor(&fx.db);
    let pages = [
        AssetPage { after: None, size: 0 },
        AssetPage {
            after: None,
            size: MAX_LIST_LIMIT + 1,
        },
        AssetPage {
            after: Some(String::new()),
            size: 1,
        },
        AssetPage {
            after: Some("a\0".to_owned()),
            size: 1,
        },
    ];
    for page in pages {
        assert!(list_asset_summaries(&run, &scope, &page).await.is_err());
    }
    assert!(matches!(get_asset_detail(&run, &scope, "").await, Err(StoreError::BadId)));
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}
