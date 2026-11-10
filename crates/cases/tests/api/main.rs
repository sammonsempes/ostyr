mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
#[path = "../store/memory.rs"]
mod memory;
mod swap;
mod types;


use alerts::error::StoreError;
use axum::body::to_bytes;
use axum::http::StatusCode;
use cases::api::{cases_document, decode_cursor, encode_cursor, list_view, parse_limit, scope_of, store_failure, DEFAULT_LIMIT, MAX_CURSOR_CHARS};
use cases::api_model::CasesBackend;
use cases::error::CaseStoreError;
use cases::model::Comment;
use cases::store::{add_comment, MAX_COMMENTS, MAX_COMMENT_CHARS, MAX_ID_CHARS, MAX_PAGE_SIZE, NEXT_SUMMARY_SQL};
use cases::stored::{CaseCursor, SummaryList};
use core_api::model::{ApiError, ApiIdentity};
use core_api::state::RATE_MAX_REQUESTS;
use data_encoding::BASE64URL_NOPAD;
use fixture::{case, executor, fixture, fixture_with, memory_backend, store, ANALYST, BASE_TIME, OTHER_TENANT, READER, TENANT};
use http::{body_json, get, login, BODY_READ_LIMIT};
use memory::{lock, Forced};
use serde_json::{json, Value};
use std::sync::Arc;
use types::{TestError, TestResult};


const TOTAL: usize = 120;


const SIZES: [usize; 3] = [1, 7, 50];


const FLOOD: usize = 10;


const NEWEST_OFFSET: i64 = 2;


const CASES_OF_TENANT: usize = 3;


const HALF: usize = 2;


const TIE_GROUPS: usize = 30;


const TEN_SECONDS: i64 = 10;


const SMALL_RESPONSE_BYTES: usize = 4_096;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


async fn seeded() -> Result<(fixture::Fixture, String), TestError> {
    let fx = fixture()?;
    store(
        &fx.db,
        &[
            case(TENANT, "c1", BASE_TIME),
            case(TENANT, "c2", BASE_TIME + 1),
            case(TENANT, "c3", BASE_TIME + NEWEST_OFFSET),
            case(OTHER_TENANT, "foreign", BASE_TIME + THREE_OFFSET),
        ],
    )
    .await?;
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


const THREE_OFFSET: i64 = 3;


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
async fn listing_pages_newest_first_for_the_session_tenant_only() -> TestResult {
    let (fx, token) = seeded().await?;
    let first = get(&fx.router, "/cases?limit=2", Some(&token)).await?;
    assert_eq!(first.status(), StatusCode::OK);
    let page = body_json(first).await?;
    assert_eq!(ids(&page)?, ["c3", "c2"]);
    let cursor = page.get("next_cursor").and_then(Value::as_str).ok_or("no next cursor")?.to_owned();
    assert!(cursor.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    let second = body_json(get(&fx.router, &format!("/cases?limit=2&cursor={cursor}"), Some(&token)).await?).await?;
    assert_eq!(ids(&second)?, ["c1"]);
    assert_eq!(second.get("next_cursor"), Some(&Value::Null));
    let head = items(&page)?.first().ok_or("empty")?;
    assert_eq!(head.get("severity"), Some(&json!("high")));
    assert_eq!(head.get("status"), Some(&json!("new")));
    assert_eq!(head.get("created_at"), Some(&json!(BASE_TIME + NEWEST_OFFSET)));
    assert_eq!(head.get("counts").and_then(|counts| counts.get("tasks")), Some(&json!(1)));
    assert!(head.get("tenant").is_none() && head.get("comments").is_none() && head.get("description").is_none());
    let everything = body_json(get(&fx.router, "/cases", Some(&token)).await?).await?;
    assert_eq!(items(&everything)?.len(), CASES_OF_TENANT);
    Ok(())
}


#[tokio::test]
async fn the_detail_holds_the_case_and_tasks_with_counts_for_the_lists() -> TestResult {
    let (fx, token) = seeded().await?;
    let found = get(&fx.router, "/cases/c2", Some(&token)).await?;
    assert_eq!(found.status(), StatusCode::OK);
    let detail = body_json(found).await?;
    assert_eq!(detail.get("id"), Some(&json!("c2")));
    assert_eq!(detail.get("description"), Some(&json!("details")));
    assert_eq!(detail.get("template"), Some(&json!("incident")));
    assert_eq!(detail.get("resolution"), Some(&Value::Null));
    assert_eq!(detail.get("version"), Some(&json!(1)));
    assert_eq!(detail.get("tasks").and_then(Value::as_array).map(Vec::len), Some(1));
    assert!(["comments", "observables", "history", "tenant"]
        .iter()
        .all(|field| detail.get(*field).is_none()));
    assert_eq!(detail.get("counts").and_then(|counts| counts.get("alerts")), Some(&json!(0)));
    Ok(())
}


#[tokio::test]
async fn a_tenant_cannot_be_chosen_by_parameter_or_header() -> TestResult {
    let (fx, token) = seeded().await?;
    let seeding = lock(&fx.db.statements).len();
    let refused = get(&fx.router, &format!("/cases?tenant={OTHER_TENANT}"), Some(&token)).await?;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let by_id = get(&fx.router, "/cases/foreign", Some(&token)).await?;
    assert_eq!(by_id.status(), StatusCode::NOT_FOUND);
    let missing = get(&fx.router, "/cases/nothing", Some(&token)).await?;
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
    let missing = body_json(get(&fx.router, "/cases/nothing", Some(&token)).await?).await?;
    let before = lock(&fx.db.statements).len();
    for path in ["/cases/%00".to_owned(), format!("/cases/{}", "x".repeat(MAX_ID_CHARS + 1))] {
        let response = get(&fx.router, &path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body_json(response).await?, missing);
    }
    assert_eq!(lock(&fx.db.statements).len(), before);
    Ok(())
}


#[tokio::test]
async fn no_session_is_401_and_a_role_without_cases_read_is_403_before_any_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let reader = login(&fx.router, READER).await?;
    let before = lock(&fx.db.statements).len();
    for path in ["/cases", "/cases/c1"] {
        assert_eq!(get(&fx.router, path, None).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some("bogus")).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(lock(&fx.db.statements).len(), before);
    assert_eq!(get(&fx.router, "/cases", Some(&token)).await?.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn an_unauthenticated_flood_is_rate_limited_before_any_store_call() -> TestResult {
    let fx = fixture_with(memory_backend)?;
    let mut last = StatusCode::OK;
    for _ in 0..(RATE_MAX_REQUESTS as usize + FLOOD) {
        last = get(&fx.router, "/cases", None).await?.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert!(lock(&fx.db.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn malformed_queries_are_a_generic_400_without_a_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    let before = lock(&fx.db.statements).len();
    let junk = BASE64URL_NOPAD.encode(b"junk");
    let negative = BASE64URL_NOPAD.encode(b"-1.c1");
    let no_id = BASE64URL_NOPAD.encode(b"1.");
    let injection = BASE64URL_NOPAD.encode(b"1.x'; DROP TABLE cases;--\0");
    let non_utf8 = BASE64URL_NOPAD.encode(&INVALID_UTF8);
    let too_long = "A".repeat(MAX_CURSOR_CHARS + 1);
    let queries = [
        "cursor=!!!".to_owned(),
        format!("cursor={junk}"),
        format!("cursor={negative}"),
        format!("cursor={no_id}"),
        format!("cursor={injection}"),
        format!("cursor={non_utf8}"),
        format!("cursor={too_long}"),
        "limit=0".to_owned(),
        format!("limit={}", MAX_PAGE_SIZE + 1),
        "limit=1e3".to_owned(),
        "limit=abc".to_owned(),
        "limit=-1".to_owned(),
        "limit=1&limit=2".to_owned(),
        "limit=99999999999999999999999".to_owned(),
        "unknown=1".to_owned(),
        format!("tenant={OTHER_TENANT}"),
    ];
    for query in queries {
        let response = get(&fx.router, &format!("/cases?{query}"), Some(&token)).await?;
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
    let forged = encode_cursor(&CaseCursor {
        created_at: BASE_TIME + TEN_SECONDS,
        id: "zzz".to_owned(),
    });
    let page = body_json(get(&fx.router, &format!("/cases?cursor={forged}"), Some(&token)).await?).await?;
    assert_eq!(ids(&page)?, ["c3", "c2", "c1"]);
    let statements = lock(&fx.db.statements).clone();
    assert!(statements.iter().any(|(tenant, sql)| tenant == TENANT && *sql == NEXT_SUMMARY_SQL));
    assert!(statements.iter().skip(seeding).all(|(tenant, _sql)| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn every_case_is_listed_once_whatever_the_page_size() -> TestResult {
    let fx = fixture()?;
    let mut batch = Vec::new();
    for index in 0..TOTAL {
        batch.push(case(TENANT, &format!("case-{index:03}"), BASE_TIME + i64::try_from(index % TIE_GROUPS)?));
    }
    store(&fx.db, &batch).await?;
    store(&fx.db, &[case(OTHER_TENANT, "foreign", BASE_TIME)]).await?;
    let token = login(&fx.router, ANALYST).await?;
    for size in SIZES {
        let mut listed = Vec::new();
        let mut path = format!("/cases?limit={size}");
        let mut attempts = 0;
        while attempts <= TOTAL {
            let page = body_json(get(&fx.router, &path, Some(&token)).await?).await?;
            listed.extend(ids(&page)?);
            let next = page.get("next_cursor").and_then(Value::as_str).map(str::to_owned);
            attempts = next.as_ref().map_or(TOTAL + 1, |_cursor| attempts + 1);
            path = next.map_or_else(String::new, |cursor| format!("/cases?limit={size}&cursor={cursor}"));
        }
        let mut sorted = listed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(listed.len(), TOTAL, "size {size}");
        assert_eq!(sorted.len(), TOTAL, "size {size}");
        assert!(!listed.iter().any(|id| id == "foreign"));
    }
    Ok(())
}


#[tokio::test]
async fn a_case_at_the_caps_keeps_both_responses_small() -> TestResult {
    let (fx, token) = seeded().await?;
    let scope = cases_scope()?;
    let text = "é".repeat(MAX_COMMENT_CHARS);
    for _ in 0..MAX_COMMENTS {
        let comment = Comment {
            author: "alice".to_owned(),
            at: BASE_TIME,
            text: text.clone(),
        };
        add_comment(&executor(&fx.db), &scope, "c1", &comment).await?;
    }
    let listed = get(&fx.router, "/cases", Some(&token)).await?;
    let list_bytes = to_bytes(listed.into_body(), BODY_READ_LIMIT).await?.len();
    let detailed = get(&fx.router, "/cases/c1", Some(&token)).await?;
    let detail_bytes = to_bytes(detailed.into_body(), BODY_READ_LIMIT).await?.len();
    assert!(
        list_bytes < SMALL_RESPONSE_BYTES && detail_bytes < SMALL_RESPONSE_BYTES,
        "{list_bytes} {detail_bytes}"
    );
    let detail = body_json(get(&fx.router, "/cases/c1", Some(&token)).await?).await?;
    assert_eq!(detail.get("counts").and_then(|counts| counts.get("comments")), Some(&json!(MAX_COMMENTS)));
    Ok(())
}


fn cases_scope() -> Result<core_pg::scope::TenantScope, TestError> {
    Ok(core_pg::scope::tenant_scope(TENANT)?)
}


#[tokio::test]
async fn database_failures_are_a_generic_500() -> TestResult {
    let (fx, token) = seeded().await?;
    lock(&fx.db.forced).push_back(Forced::Fail);
    let listed = get(&fx.router, "/cases", Some(&token)).await?;
    assert_eq!(listed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(listed).await?;
    assert_eq!(error_code(&json), Some("internal_error"));
    assert!(!json.to_string().contains("XX000") && !json.to_string().contains("internal\""));
    lock(&fx.db.forced).push_back(Forced::Fail);
    assert_eq!(
        get(&fx.router, "/cases/c1", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    lock(&fx.db.forced).push_back(Forced::Rows(vec![vec![]]));
    assert_eq!(
        get(&fx.router, "/cases/c1", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_a_429() -> TestResult {
    let fx = fixture_with(|_db| CasesBackend {
        list: Arc::new(|_scope, _page| Box::pin(async { Err(CaseStoreError::Lease(StoreError::Busy)) })),
        get: Arc::new(|_scope, _id| Box::pin(async { Err(CaseStoreError::Lease(StoreError::Busy)) })),
    })?;
    let token = login(&fx.router, ANALYST).await?;
    assert_eq!(get(&fx.router, "/cases", Some(&token)).await?.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(get(&fx.router, "/cases/c1", Some(&token)).await?.status(), StatusCode::TOO_MANY_REQUESTS);
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
    assert!(matches!(scope_of(&fx.state.identity.load()), Err(CaseStoreError::Pg(_))));
    assert_eq!(get(&fx.router, "/cases", Some(&token)).await?.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        get(&fx.router, "/cases/c1", Some(&token)).await?.status(),
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
    assert!(paths.get("/cases").and_then(|path| path.get("get")).is_some());
    assert!(paths.get("/cases/{id}").and_then(|path| path.get("get")).is_some());
    let schemas = document
        .get("components")
        .and_then(|components| components.get("schemas"))
        .ok_or("no schemas")?;
    assert!(["CaseSummary", "CaseDetail", "CaseCounts", "CaseListView"]
        .iter()
        .all(|name| schemas.get(*name).is_some()));
    assert!(serde_json::to_string(&cases_document())?.contains("/cases/{id}"));
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
fn cursors_round_trip_and_a_longest_id_fits() -> TestResult {
    let cursor = CaseCursor {
        created_at: BASE_TIME,
        id: "é".repeat(MAX_ID_CHARS / HALF),
    };
    assert_eq!(decode_cursor(&encode_cursor(&cursor))?, cursor);
    let widest = CaseCursor {
        created_at: i64::MAX,
        id: "\u{1F600}".repeat(MAX_ID_CHARS),
    };
    assert_eq!(decode_cursor(&encode_cursor(&widest))?, widest);
    assert!(decode_cursor("").is_err());
    assert!(decode_cursor(&"A".repeat(MAX_CURSOR_CHARS + 1)).is_err());
    Ok(())
}


#[test]
fn store_failures_map_to_stable_errors_and_an_empty_page_has_no_cursor() -> TestResult {
    assert_eq!(store_failure(&CaseStoreError::BadCursor), ApiError::BadRequest);
    assert_eq!(store_failure(&CaseStoreError::BadPageSize { limit: 1 }), ApiError::BadRequest);
    assert_eq!(store_failure(&CaseStoreError::Lease(StoreError::Busy)), ApiError::TooManyRequests);
    assert_eq!(store_failure(&CaseStoreError::Lease(StoreError::BadCursor)), ApiError::Internal);
    assert_eq!(store_failure(&CaseStoreError::Conflict), ApiError::Internal);
    let view = list_view(SummaryList {
        summaries: Vec::new(),
        next: None,
    });
    assert!(view.items.is_empty() && view.next_cursor.is_none());
    Ok(())
}
