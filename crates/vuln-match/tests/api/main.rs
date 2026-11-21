#[path = "../common/finding_fake.rs"]
mod finding_fake;
mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
#[path = "../common/types.rs"]
mod types;


use alerts::error::StoreError as LeaseError;
use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity};
use core_pg::error::PgError;
use finding_fake::{capture_dispatch, captured, Capture};
use fixture::{fixture, fixture_with, memory_backend, put_finding, read_count, ANALYST, OTHER_TENANT, READER, TENANT};
use http::{body_json, call, get, login};
use serde_json::{json, Value};
use std::sync::Arc;
use types::TestResult;
use vuln_match::api::{
    asset_flow, asset_view, failure_category, finding_view, list_flow, list_view, parse_limit, rfc3339, scope_of, store_failure, views_of,
    vulnerabilities_access, vulnerabilities_document,
};
use vuln_match::api_model::{FindingsBackend, ListQuery};
use vuln_match::error::StoreError;
use vuln_match::limits::{DEFAULT_PAGE_LIMIT, MAX_ASSET_FINDINGS, MAX_FIELD_BYTES, MAX_PAGE_LIMIT};
use vuln_match::model::{FindingsPage, StoredFinding};


const MARKER: &str = "SECRET-MARKER-7f3a";


const HUGE_CURSOR: usize = 60_000;


const SECOND: usize = 2;


const THIRD: usize = 3;


const SEVEN: usize = 7;


const FAR_MICROS: u64 = 253_402_300_800_000_000;


const TWO_MICROS: u64 = 2;


const OVER_U32: &str = "4294967296";


const HIGH: u32 = 9_000;


const MID: u32 = 5_000;


const LOW: u32 = 100;


const FAKE_CVSS: f64 = 7.5;


const STORED_CVSS: f64 = 1.0;


const STORED_EPSS: f64 = 0.5;


fn items(json: &Value) -> Result<&Vec<Value>, types::TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


fn field_of(json: &Value, name: &str) -> Result<Vec<String>, types::TestError> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| item.get(name).and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}


fn code_of(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
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


fn seed(fx: &fixture::Fixture) {
    put_finding(&fx.fake, TENANT, ("host-a", "Debian:12", "openssl", "CVE-1"), MID);
    put_finding(&fx.fake, TENANT, ("host-a", "Debian:12", "curl", "CVE-2"), HIGH);
    put_finding(&fx.fake, TENANT, ("host-b", "Debian:12", "zlib", "CVE-3"), LOW);
    put_finding(&fx.fake, OTHER_TENANT, ("host-z", "Debian:12", "curl", "CVE-2"), HIGH);
}


#[tokio::test]
async fn the_default_listing_is_the_tenant_by_priority_with_rfc3339_times() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, "/vulnerabilities/findings", Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_json(response).await?;
    assert_eq!(field_of(&page, "package")?, ["curl", "openssl", "zlib"]);
    assert_eq!(page.get("skipped"), Some(&json!(0)));
    assert_eq!(page.get("next_cursor"), Some(&Value::Null));
    let head = items(&page)?.first().ok_or("empty")?;
    assert_eq!(head.get("first_seen"), Some(&json!("2023-11-14T22:13:20Z")));
    assert_eq!(head.get("last_seen"), Some(&json!("2023-11-14T22:13:20Z")));
    assert_eq!(head.get("fixed_version"), Some(&json!("1.2")));
    assert_eq!(head.get("priority"), Some(&json!(HIGH)));
    assert_eq!(head.get("kev"), Some(&json!(false)));
    assert_eq!(head.get("cvss"), Some(&json!(FAKE_CVSS)));
    assert!(head.get("tenant").is_none());
    Ok(())
}


#[tokio::test]
async fn limits_and_cursors_are_checked_before_any_store_call() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    for query in ["limit=1", "limit=500", "limit=50"] {
        let response = get(&fx.router, &format!("/vulnerabilities/findings?{query}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::OK, "{query}");
    }
    let before = read_count(&fx.fake);
    let long_field = "a".repeat(MAX_FIELD_BYTES + 1);
    let bad = [
        "limit=0".to_owned(),
        "limit=501".to_owned(),
        "limit=abc".to_owned(),
        "limit=-1".to_owned(),
        "limit=+5".to_owned(),
        "limit=".to_owned(),
        "limit=1&limit=2".to_owned(),
        "cursor=junk".to_owned(),
        "cursor=".to_owned(),
        format!("cursor={}", encoded(&format!("1 {long_field} e p r"))),
        format!("cursor={}", encoded(&format!("{OVER_U32} a e p r"))),
        format!("cursor={}", encoded("100 -a e p r")),
        format!("cursor={}", encoded("100 a\te p r")),
        format!("cursor={}", encoded("100 a e p r s")),
        format!("cursor={}", encoded("100 a  e p")),
        format!("cursor={}", encoded("100     ")),
        format!("cursor={}", encoded("01 a e p r")),
        format!("cursor={}", encoded("100 a e p r\0")),
        format!("cursor={}", "1".repeat(HUGE_CURSOR)),
        format!("tenant={OTHER_TENANT}"),
    ];
    for query in bad {
        let response = get(&fx.router, &format!("/vulnerabilities/findings?{query}"), Some(&token)).await?;
        let shown = query.chars().take(MARKER.len()).collect::<String>();
        assert!(matches!(response.status(), StatusCode::BAD_REQUEST | StatusCode::URI_TOO_LONG), "{shown}");
    }
    assert_eq!(read_count(&fx.fake), before);
    Ok(())
}


#[tokio::test]
async fn a_cursor_walks_findings_of_one_priority_with_special_characters() -> TestResult {
    let fx = fixture()?;
    let assets = ["a%b", "a&b", "a+b", "a/b", "a=b", "a?b", "a#b"];
    assets
        .iter()
        .for_each(|asset| put_finding(&fx.fake, TENANT, (asset, "Debian:12", "p+q%r&s=t/u?v", "CVE-1"), MID));
    put_finding(&fx.fake, TENANT, ("zzz", "Debian:12", "p", "CVE-1"), LOW);
    let token = login(&fx.router, ANALYST).await?;
    let mut seen = Vec::new();
    let mut next = Some("/vulnerabilities/findings?limit=3".to_owned());
    let mut attempts = 0;
    while next.is_some() && attempts < SEVEN {
        let path = next.take().ok_or("no path")?;
        let page = body_json(get(&fx.router, &path, Some(&token)).await?).await?;
        assert!(page.get("items").is_some(), "{path} {page}");
        seen.extend(field_of(&page, "asset")?);
        next = page
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(|cursor| format!("/vulnerabilities/findings?limit=3&cursor={}", encoded(cursor)));
        attempts += 1;
    }
    assert_eq!(seen, ["a#b", "a%b", "a&b", "a+b", "a/b", "a=b", "a?b", "zzz"]);
    let raw = "5000 a+b Debian:12 p+q%r&s=t/u?v CVE-1";
    let after = body_json(get(&fx.router, &format!("/vulnerabilities/findings?cursor={}", encoded(raw)), Some(&token)).await?).await?;
    assert_eq!(field_of(&after, "asset")?, ["a/b", "a=b", "a?b", "zzz"]);
    let plus_as_space = body_json(
        get(
            &fx.router,
            &format!("/vulnerabilities/findings?cursor={}", encoded(raw).replace("%20", "+")),
            Some(&token),
        )
        .await?,
    )
    .await?;
    assert_eq!(field_of(&plus_as_space, "asset")?, ["a/b", "a=b", "a?b", "zzz"]);
    let tenants: Vec<String> = finding_fake::recorded(&fx.fake).into_iter().map(|(tenant, _sql)| tenant).collect();
    assert!(tenants.iter().all(|tenant| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn a_bad_row_is_served_around_and_a_page_of_bad_rows_moves_on() -> TestResult {
    let fx = fixture()?;
    put_finding(&fx.fake, TENANT, ("a1", "e", "p1", "r"), HIGH);
    let broken = |package: &str, column: usize, value: &str| {
        let mut cells = finding_fake::cells_of(("a1", "e", package, "r"), MID);
        if let Some(cell) = cells.get_mut(column) {
            *cell = value.to_owned();
        }
        finding_fake::put(&fx.fake, TENANT, cells);
    };
    broken("p2", finding_fake::COL_CVSS, "x");
    broken("p3", finding_fake::COL_PRIORITY, "5000");
    broken("p4", finding_fake::COL_CVSS, "y");
    broken("p5", finding_fake::COL_CVSS, "z");
    broken("p6", finding_fake::COL_CVSS, "w");
    broken("p7", finding_fake::COL_CVSS, "v");
    let token = login(&fx.router, ANALYST).await?;
    let first = body_json(get(&fx.router, "/vulnerabilities/findings?limit=3", Some(&token)).await?).await?;
    assert_eq!(field_of(&first, "package")?, ["p1", "p3"]);
    assert_eq!(first.get("skipped"), Some(&json!(1)));
    let cursor = first.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let bad_only = body_json(
        get(
            &fx.router,
            &format!("/vulnerabilities/findings?limit=3&cursor={}", encoded(&cursor)),
            Some(&token),
        )
        .await?,
    )
    .await?;
    assert!(items(&bad_only)?.is_empty());
    assert_eq!(bad_only.get("skipped"), Some(&json!(THIRD)));
    let next = bad_only.get("next_cursor").and_then(Value::as_str).ok_or("no cursor")?.to_owned();
    let rest = body_json(
        get(
            &fx.router,
            &format!("/vulnerabilities/findings?limit=3&cursor={}", encoded(&next)),
            Some(&token),
        )
        .await?,
    )
    .await?;
    assert!(items(&rest)?.is_empty());
    assert_eq!(rest.get("skipped"), Some(&json!(1)));
    assert_eq!(rest.get("next_cursor"), Some(&Value::Null));
    Ok(())
}


#[tokio::test]
async fn a_time_outside_rfc_3339_is_a_counted_skip_with_a_log() -> TestResult {
    let fx = fixture()?;
    put_finding(&fx.fake, TENANT, ("a1", "e", "p1", "r"), HIGH);
    let mut cells = finding_fake::cells_of(("a1", "e", "p2", "r"), MID);
    if let Some(cell) = cells.get_mut(finding_fake::COL_PRIORITY + 1) {
        *cell = u64::MAX.to_string();
    }
    finding_fake::put(&fx.fake, TENANT, cells);
    let token = login(&fx.router, ANALYST).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let guard = tracing::dispatcher::set_default(&dispatch);
    let page = body_json(get(&fx.router, "/vulnerabilities/findings", Some(&token)).await?).await?;
    drop(guard);
    assert_eq!(field_of(&page, "package")?, ["p1"]);
    assert_eq!(page.get("skipped"), Some(&json!(1)));
    assert!(captured(&capture).contains("unwritable=1"));
    Ok(())
}


#[tokio::test]
async fn a_key_outside_the_grammar_is_a_stored_value_500_and_never_a_cursor() -> TestResult {
    let fx = fixture()?;
    put_finding(&fx.fake, TENANT, ("a1", "e", "p1", "r"), HIGH);
    put_finding(&fx.fake, TENANT, ("a1", "e", "p 2", "r"), MID);
    let token = login(&fx.router, ANALYST).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let bad = get(&fx.router, "/vulnerabilities/findings", Some(&token)).await?;
    assert_eq!(bad.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let json = body_json(bad).await?;
    assert_eq!(code_of(&json), Some("internal_error"));
    assert!(!json.to_string().contains("p 2"));
    assert!(captured(&capture).contains("stored_value"));
    Ok(())
}


#[tokio::test]
async fn an_asset_lists_its_findings_and_unknown_malformed_and_foreign_ones_answer_alike() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    put_finding(&fx.fake, TENANT, ("a/b", "Debian:12", "slash", "CVE-9"), MID);
    let token = login(&fx.router, ANALYST).await?;
    let found = body_json(get(&fx.router, "/vulnerabilities/assets/host-a", Some(&token)).await?).await?;
    assert_eq!(field_of(&found, "package")?, ["curl", "openssl"]);
    assert_eq!((found.get("skipped"), found.get("truncated")), (Some(&json!(0)), Some(&json!(false))));
    let slash = body_json(get(&fx.router, "/vulnerabilities/assets/a%2Fb", Some(&token)).await?).await?;
    assert_eq!(field_of(&slash, "package")?, ["slash"]);
    let long = format!("/vulnerabilities/assets/{}", "a".repeat(MAX_FIELD_BYTES + 1));
    let refused = [
        long,
        "/vulnerabilities/assets/a%20b".to_owned(),
        "/vulnerabilities/assets/a%00b".to_owned(),
        "/vulnerabilities/assets/%FF".to_owned(),
        "/vulnerabilities/assets/-a".to_owned(),
        "/vulnerabilities/assets/a%09b".to_owned(),
    ];
    let before = read_count(&fx.fake);
    let mut bodies = Vec::new();
    for path in refused
        .iter()
        .map(String::as_str)
        .chain(["/vulnerabilities/assets/unknown", "/vulnerabilities/assets/host-z"])
    {
        let response = get(&fx.router, path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        bodies.push(axum::body::to_bytes(response.into_body(), http::BODY_READ_LIMIT).await?);
    }
    assert!(bodies.windows(SECOND).all(|pair| pair.first() == pair.get(1)));
    assert!(!String::from_utf8(bodies.first().ok_or("none")?.to_vec())?.contains("unknown"));
    assert_eq!(read_count(&fx.fake) - before, SECOND);
    Ok(())
}


#[tokio::test]
async fn more_findings_than_the_maximum_set_truncated_and_a_skipped_asset_is_a_200() -> TestResult {
    let fx = fixture()?;
    (0..=MAX_ASSET_FINDINGS).for_each(|index| put_finding(&fx.fake, TENANT, ("big", "e", &format!("p{index:05}"), "r"), MID));
    let mut cells = finding_fake::cells_of(("broken", "e", "p", "r"), MID);
    if let Some(cell) = cells.get_mut(finding_fake::COL_CVSS) {
        *cell = "x".to_owned();
    }
    finding_fake::put(&fx.fake, TENANT, cells);
    let token = login(&fx.router, ANALYST).await?;
    let big = body_json(get(&fx.router, "/vulnerabilities/assets/big", Some(&token)).await?).await?;
    assert_eq!((items(&big)?.len(), big.get("truncated")), (MAX_ASSET_FINDINGS, Some(&json!(true))));
    let broken = get(&fx.router, "/vulnerabilities/assets/broken", Some(&token)).await?;
    assert_eq!(broken.status(), StatusCode::OK);
    let json = body_json(broken).await?;
    assert_eq!((items(&json)?.len(), json.get("skipped")), (0, Some(&json!(1))));
    Ok(())
}


#[tokio::test]
async fn every_read_is_audited_with_the_route_pattern_and_never_the_asset_or_query() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let reader = login(&fx.router, READER).await?;
    assert_eq!(
        get(&fx.router, "/vulnerabilities/findings?limit=5", Some(&token)).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        get(&fx.router, "/vulnerabilities/assets/host-a", Some(&token)).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        get(&fx.router, "/vulnerabilities/findings", Some(&reader)).await?.status(),
        StatusCode::FORBIDDEN
    );
    let text = std::fs::read_to_string(fx._dir.path().join("audit.log"))?;
    let records: Vec<Value> = text.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
    let reads: Vec<(String, String)> = records
        .iter()
        .filter(|line| line.get("action") == Some(&json!("api.request")))
        .filter_map(|line| {
            line.get("target").and_then(Value::as_str).map(|target| {
                (
                    target.to_owned(),
                    line.get("outcome").map_or(String::new(), |outcome| outcome.to_string()),
                )
            })
        })
        .filter(|(target, _)| target.contains("vulnerabilities"))
        .collect();
    assert_eq!(reads.len(), THIRD, "{reads:?}");
    assert!(reads.iter().any(|(target, _)| target == "GET /vulnerabilities/assets/{asset}"));
    assert!(reads.iter().any(|(_, outcome)| outcome.contains("denied")));
    assert!(!text.contains("host-a") && !text.contains("limit=5"));
    Ok(())
}


#[tokio::test]
async fn the_permission_is_cmdb_read_and_other_methods_are_refused() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let reader = login(&fx.router, READER).await?;
    let before = read_count(&fx.fake);
    for path in ["/vulnerabilities/findings", "/vulnerabilities/assets/host-a"] {
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
    assert_eq!(vulnerabilities_access().len(), SECOND);
    assert!(vulnerabilities_document().paths.paths.contains_key("/vulnerabilities/findings"));
    assert!(vulnerabilities_document().paths.paths.contains_key("/vulnerabilities/assets/{asset}"));
    Ok(())
}


fn failing_backend(error: fn() -> StoreError) -> impl FnOnce(&Arc<finding_fake::Fake>) -> FindingsBackend {
    move |_fake| FindingsBackend {
        list: Arc::new(move |_scope, _cursor, _limit| Box::pin(async move { Err(error()) })),
        asset: Arc::new(move |_scope, _asset| Box::pin(async move { Err(error()) })),
    }
}


fn marked_pg_error() -> StoreError {
    StoreError::Pg(PgError::Io {
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
    for path in ["/vulnerabilities/findings", "/vulnerabilities/assets/host-a"] {
        let response = get(&fx.router, path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let shown = format!("{response:?}");
        let json = body_json(response).await?;
        assert_eq!(code_of(&json), Some("internal_error"));
        assert!(!json.to_string().contains(MARKER) && !shown.contains(MARKER));
    }
    let logs = captured(&capture);
    assert!(logs.contains("vulnerability findings failure") && logs.contains("database"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_429_and_a_cursor_the_store_refuses_is_400() -> TestResult {
    let busy = fixture_with(failing_backend(|| StoreError::Lease(LeaseError::Busy)))?;
    let token = login(&busy.router, ANALYST).await?;
    assert_eq!(
        get(&busy.router, "/vulnerabilities/findings", Some(&token)).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let refusing = fixture_with(failing_backend(|| StoreError::BadCursor))?;
    let other = login(&refusing.router, ANALYST).await?;
    assert_eq!(
        get(&refusing.router, "/vulnerabilities/findings", Some(&other)).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}


fn stored(first_seen: u64, last_seen: u64) -> StoredFinding {
    StoredFinding {
        asset: "a1".to_owned(),
        ecosystem: "e".to_owned(),
        package: "p".to_owned(),
        record_id: "r".to_owned(),
        installed_version: "1".to_owned(),
        fixed_version: None,
        cvss: STORED_CVSS,
        epss: STORED_EPSS,
        kev: true,
        priority: 1,
        first_seen_micros: first_seen,
        last_seen_micros: last_seen,
    }
}


#[test]
fn times_outside_rfc_3339_are_refused_and_counted() -> TestResult {
    assert_eq!(rfc3339(0).as_deref(), Some("1970-01-01T00:00:00Z"));
    assert_eq!(rfc3339(1).as_deref(), Some("1970-01-01T00:00:00.000001Z"));
    assert!(rfc3339(FAR_MICROS - 1).is_some());
    assert!(rfc3339(FAR_MICROS).is_none());
    assert!(rfc3339(u64::MAX).is_none());
    assert!(finding_view(&stored(1, 1)).is_some());
    assert!(finding_view(&stored(FAR_MICROS, 1)).is_none());
    assert!(finding_view(&stored(1, FAR_MICROS)).is_none());
    let rows = [stored(1, 1), stored(FAR_MICROS, 1), stored(1, FAR_MICROS), stored(TWO_MICROS, 1)];
    let (shown, unwritable) = views_of(&rows);
    assert_eq!((shown.len(), unwritable), (SECOND, SECOND));
    let page = FindingsPage {
        findings: rows.to_vec(),
        skipped: 1,
        next: Some("c".to_owned()),
    };
    let view = list_view(&page);
    assert_eq!((view.items.len(), view.skipped, view.next_cursor.as_deref()), (SECOND, THIRD, Some("c")));
    let asset = asset_view(&page).ok_or("no view")?;
    assert_eq!((asset.items.len(), asset.skipped, asset.truncated), (SECOND, THIRD, true));
    let empty = FindingsPage {
        findings: Vec::new(),
        skipped: 0,
        next: None,
    };
    assert!(asset_view(&empty).is_none());
    let only_skipped = FindingsPage { skipped: 1, ..empty };
    assert!(asset_view(&only_skipped).is_some());
    Ok(())
}


#[test]
fn the_limit_parser_and_failure_mapping() -> TestResult {
    assert_eq!(parse_limit(None)?, DEFAULT_PAGE_LIMIT);
    assert_eq!(parse_limit(Some("500"))?, MAX_PAGE_LIMIT);
    assert_eq!(parse_limit(Some("1"))?, 1);
    assert!(parse_limit(Some("0")).is_err());
    assert!(parse_limit(Some("501")).is_err());
    assert!(parse_limit(Some("99999999999999999999999")).is_err());
    assert!(parse_limit(Some("+5")).is_err());
    let identity = ApiIdentity {
        module: "vuln-match".to_owned(),
        tenant: "-bad".to_owned(),
        generation: 0,
    };
    assert!(matches!(scope_of(&identity), Err(StoreError::Pg(_))));
    assert!(matches!(store_failure(&StoreError::BadAsset), ApiError::Internal));
    assert!(matches!(store_failure(&StoreError::BadLimit { max: 1 }), ApiError::BadRequest));
    assert_eq!(failure_category(&StoreError::BadAsset), "request");
    assert_eq!(failure_category(&StoreError::BadAnswer), "stored_value");
    assert_eq!(failure_category(&StoreError::StoredValue), "stored_value");
    assert_eq!(failure_category(&StoreError::Lease(LeaseError::Busy)), "database");
    Ok(())
}


#[tokio::test]
async fn an_identity_with_a_malformed_tenant_reaches_no_store() -> TestResult {
    let fx = fixture()?;
    put_finding(&fx.fake, TENANT, ("host-a", "e", "p", "r"), HIGH);
    let backend = memory_backend(&fx.fake);
    let identity = ApiIdentity {
        module: "vuln-match".to_owned(),
        tenant: "-bad".to_owned(),
        generation: 0,
    };
    let query = ListQuery { cursor: None, limit: None };
    assert!(matches!(list_flow(&identity, &backend, Ok(query)).await, Err(ApiError::Internal)));
    assert!(matches!(
        asset_flow(&identity, &backend, Ok("host-a".to_owned())).await,
        Err(ApiError::Internal)
    ));
    assert_eq!(read_count(&fx.fake), 0);
    Ok(())
}
