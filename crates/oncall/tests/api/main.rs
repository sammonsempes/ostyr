#[path = "../common/capture.rs"]
mod capture;
mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
mod types;


use axum::http::StatusCode;
use capture::{Capture, ANCHOR};
use chrono::{TimeZone, Utc};
use core_api::model::{ApiError, ApiIdentity, Requirement};
use core_api::routes::route_key;
use fixture::{alert, at, fixture, lock, set_mode, stored, Mode, ANALYST, OTHER_TENANT, READER, TENANT};
use http::{body_json, get, login};
use oncall::alert::{AlertPage, Phase};
use oncall::api::{
    alert_view, failure_category, list_view, oncall_access, oncall_document, parse_id, parse_limit, read_failure, rfc3339, scope_of, DEFAULT_LIMIT,
    GET_PATH, LIST_PATH, PERMISSION_ONCALL_READ,
};
use oncall::error::{ReadError, StoreError};
use oncall::limits::{MAX_FINGERPRINT_BYTES, MAX_OPEN_ALERTS};
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock};
use tracing::Dispatch;
use types::{TestError, TestResult};


const MARKER: &str = "STORE-SECRET-MARKER";


const BIG_QUERY: usize = 10_240;


const FAR_YEAR: i32 = 10_000;


const LEVEL: u32 = 2;


const FIRST_ID: i64 = 11;


const SECOND_ID: i64 = 12;


const FOREIGN_ID: i64 = 99;


const SECOND: i64 = 2;


const THIRD: i64 = 3;


const FOURTH: i64 = 4;


const FIFTH: i64 = 5;


const SIXTH: i64 = 6;


const COUNT_TWO: usize = 2;


const COUNT_THREE: usize = 3;


const COUNT_FIVE: usize = 5;


const SEVEN: u32 = 7;


const ID_FORTY_TWO: i64 = 42;


const PREVIEW_CHARS: usize = 40;


fn error_code(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


fn item_ids(json: &Value) -> Result<Vec<i64>, TestError> {
    Ok(json
        .get("items")
        .and_then(Value::as_array)
        .ok_or("no items")?
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_i64))
        .collect())
}


fn seeded(fx: &fixture::Fixture) -> TestResult {
    stored(
        &fx.script,
        TENANT,
        vec![alert(FIRST_ID, "cpu-high", at(0)?), alert(SECOND_ID, "disk-full", at(1)?)],
    );
    stored(&fx.script, OTHER_TENANT, vec![alert(FOREIGN_ID, "foreign", at(SECOND)?)]);
    Ok(())
}


#[tokio::test]
async fn the_list_is_the_tenant_alerts_and_never_another_tenant() -> TestResult {
    let fx = fixture()?;
    seeded(&fx)?;
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, LIST_PATH, Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await?;
    assert_eq!(item_ids(&json)?, [FIRST_ID, SECOND_ID]);
    assert_eq!(json.get("skipped"), Some(&json!(0)));
    let head = json.get("items").and_then(Value::as_array).and_then(|list| list.first()).ok_or("empty")?;
    assert_eq!(
        head,
        &json!({
            "id": FIRST_ID, "fingerprint": "cpu-high", "state": "open", "level": 0, "occurrences": 1,
            "opened_at": "2027-01-15T08:00:00.000000Z", "acknowledged_at": null, "resolved_at": null
        })
    );
    assert_eq!(lock(&fx.script.calls).as_slice(), [(TENANT.to_owned(), Some(DEFAULT_LIMIT), None)]);
    Ok(())
}


#[tokio::test]
async fn the_limit_reaches_the_backend_and_stays_in_range() -> TestResult {
    let fx = fixture()?;
    seeded(&fx)?;
    let token = login(&fx.router, ANALYST).await?;
    let one = body_json(get(&fx.router, "/oncall/alerts?limit=1", Some(&token)).await?).await?;
    assert_eq!(item_ids(&one)?, [FIRST_ID]);
    let max = get(&fx.router, &format!("/oncall/alerts?limit={MAX_OPEN_ALERTS}"), Some(&token)).await?;
    assert_eq!(max.status(), StatusCode::OK);
    let limits: Vec<Option<u32>> = lock(&fx.script.calls).iter().map(|call| call.1).collect();
    assert_eq!(limits, [Some(1), Some(MAX_OPEN_ALERTS)]);
    Ok(())
}


#[tokio::test]
async fn a_bad_limit_or_parameter_is_a_400_without_a_store_call() -> TestResult {
    let fx = fixture()?;
    seeded(&fx)?;
    let token = login(&fx.router, ANALYST).await?;
    let queries = [
        "limit=0".to_owned(),
        format!("limit={}", MAX_OPEN_ALERTS + 1),
        "limit=501x".to_owned(),
        "limit=1e3".to_owned(),
        "limit=-1".to_owned(),
        "limit=".to_owned(),
        "limit=99999999999999999999999".to_owned(),
        "limit=1&limit=2".to_owned(),
        "unknown=1".to_owned(),
        format!("tenant={OTHER_TENANT}"),
        format!("limit=1&tenant={OTHER_TENANT}"),
        format!("{}=1", "k".repeat(BIG_QUERY)),
        format!("limit={}", "1".repeat(BIG_QUERY)),
    ];
    for query in queries {
        let response = get(&fx.router, &format!("/oncall/alerts?{query}"), Some(&token)).await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{}",
            query.chars().take(PREVIEW_CHARS).collect::<String>()
        );
    }
    assert!(lock(&fx.script.calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn one_alert_by_id_and_another_tenants_id_is_the_same_404_as_an_unknown_id() -> TestResult {
    let fx = fixture()?;
    seeded(&fx)?;
    let token = login(&fx.router, ANALYST).await?;
    let own = get(&fx.router, &format!("/oncall/alerts/{FIRST_ID}"), Some(&token)).await?;
    assert_eq!(own.status(), StatusCode::OK);
    assert_eq!(body_json(own).await?.get("fingerprint"), Some(&json!("cpu-high")));
    let foreign = get(&fx.router, &format!("/oncall/alerts/{FOREIGN_ID}"), Some(&token)).await?;
    let unknown = get(&fx.router, "/oncall/alerts/5000", Some(&token)).await?;
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let foreign_body = body_json(foreign).await?;
    assert_eq!(foreign_body, body_json(unknown).await?);
    assert_eq!(error_code(&foreign_body), Some("not_found"));
    let calls = lock(&fx.script.calls).clone();
    assert!(calls.iter().all(|call| call.0 == TENANT && call.2.is_some()), "{calls:?}");
    assert_eq!(calls.len(), COUNT_THREE);
    Ok(())
}


#[tokio::test]
async fn an_id_that_is_not_a_number_is_a_404_without_a_store_call() -> TestResult {
    let fx = fixture()?;
    let token = login(&fx.router, ANALYST).await?;
    for id in ["abc", "-1", "1e3", "99999999999999999999999", "%20"] {
        let response = get(&fx.router, &format!("/oncall/alerts/{id}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{id}");
    }
    assert!(lock(&fx.script.calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn no_token_is_401_and_a_role_without_the_permission_is_403() -> TestResult {
    let fx = fixture()?;
    seeded(&fx)?;
    let anonymous = get(&fx.router, LIST_PATH, None).await?;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let reader = login(&fx.router, READER).await?;
    for path in [LIST_PATH.to_owned(), format!("/oncall/alerts/{FIRST_ID}")] {
        assert_eq!(get(&fx.router, &path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert!(lock(&fx.script.calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_full_pool_is_429_and_a_store_failure_is_a_generic_500() -> TestResult {
    let fx = fixture()?;
    seeded(&fx)?;
    let token = login(&fx.router, ANALYST).await?;
    set_mode(&fx.script, Mode::Busy);
    assert_eq!(get(&fx.router, LIST_PATH, Some(&token)).await?.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        get(&fx.router, "/oncall/alerts/11", Some(&token)).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    set_mode(&fx.script, Mode::Fail);
    let failed = get(&fx.router, LIST_PATH, Some(&token)).await?;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body_json(failed).await?.to_string().contains(MARKER));
    assert_eq!(
        get(&fx.router, "/oncall/alerts/11", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}


#[tokio::test]
async fn a_row_outside_the_grammar_is_refused_alone_and_counted() -> TestResult {
    let fx = fixture()?;
    let far = Utc.with_ymd_and_hms(FAR_YEAR, 1, 1, 0, 0, 0).single().ok_or("far")?;
    let mut late_ack = alert(THIRD, "late-ack", at(THIRD)?);
    late_ack.acknowledged_at = Some(far);
    let long = "f".repeat(MAX_FINGERPRINT_BYTES + 1);
    stored(
        &fx.script,
        TENANT,
        vec![
            alert(1, "good", at(0)?),
            alert(SECOND, "bad\u{1b}[31m", at(1)?),
            late_ack,
            alert(FOURTH, &long, at(FOURTH)?),
            alert(FIFTH, "", at(FIFTH)?),
            alert(SIXTH, "far", far),
        ],
    );
    let token = login(&fx.router, ANALYST).await?;
    let json = body_json(get(&fx.router, LIST_PATH, Some(&token)).await?).await?;
    assert_eq!(item_ids(&json)?, [1]);
    assert_eq!(json.get("skipped"), Some(&json!(COUNT_FIVE)));
    assert_eq!(
        get(&fx.router, "/oncall/alerts/2", Some(&token)).await?.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}


#[test]
fn the_view_writes_every_time_and_the_state() -> TestResult {
    let mut moved = alert(FIRST_ID, "x", at(0)?);
    moved.state.phase = Phase::Escalated;
    moved.state.level = LEVEL;
    moved.acknowledged_at = Some(at(1)?);
    moved.resolved_at = Some(at(SECOND)?);
    let view = alert_view(&moved)?;
    assert_eq!(view.state, "escalated");
    assert_eq!(view.level, LEVEL);
    assert_eq!(view.acknowledged_at.as_deref(), Some("2027-01-15T08:00:01.000000Z"));
    assert_eq!(view.resolved_at.as_deref(), Some("2027-01-15T08:00:02.000000Z"));
    let page = AlertPage {
        alerts: vec![moved],
        skipped: COUNT_TWO,
    };
    let listed = list_view(&page);
    assert_eq!((listed.items.len(), listed.skipped), (1, COUNT_TWO));
    Ok(())
}


#[test]
fn rfc3339_refuses_the_years_it_cannot_write() -> TestResult {
    let year_zero = Utc.with_ymd_and_hms(0, 1, 1, 0, 0, 0).single().ok_or("zero")?;
    assert!(rfc3339(year_zero).is_ok());
    let negative = Utc.with_ymd_and_hms(-1, 1, 1, 0, 0, 0).single().ok_or("negative")?;
    assert!(matches!(rfc3339(negative), Err(ReadError::Unrepresentable)));
    let far = Utc.with_ymd_and_hms(FAR_YEAR, 1, 1, 0, 0, 0).single().ok_or("far")?;
    assert!(matches!(rfc3339(far), Err(ReadError::Unrepresentable)));
    Ok(())
}


#[test]
fn the_parsers_accept_digits_only() -> TestResult {
    assert_eq!(parse_limit(None).ok(), Some(DEFAULT_LIMIT));
    assert_eq!(parse_limit(Some("7")).ok(), Some(SEVEN));
    assert!(matches!(parse_limit(Some("0")), Err(ApiError::BadRequest)));
    assert_eq!(parse_id("42"), Some(ID_FORTY_TWO));
    assert_eq!(parse_id(""), None);
    assert_eq!(parse_id("4 2"), None);
    assert_eq!(parse_id("9223372036854775808"), None);
    Ok(())
}


#[test]
fn failures_are_categorised_without_text() -> TestResult {
    let busy = ReadError::Lease(alerts::error::StoreError::Busy);
    assert!(matches!(read_failure(&busy), ApiError::TooManyRequests));
    let other = ReadError::Lease(alerts::error::StoreError::BadCursor);
    assert!(matches!(read_failure(&other), ApiError::Internal));
    let store = ReadError::Store(StoreError::NotFound);
    assert!(matches!(read_failure(&store), ApiError::Internal));
    assert_eq!(failure_category(&busy), "connection");
    assert_eq!(failure_category(&store), "database");
    assert_eq!(failure_category(&ReadError::Unrepresentable), "stored_value");
    Ok(())
}


#[test]
fn an_identity_with_an_invalid_tenant_has_no_scope() -> TestResult {
    let identity = ApiIdentity {
        module: "oncall".to_owned(),
        tenant: "-bad".to_owned(),
        generation: 0,
    };
    assert!(matches!(scope_of(&identity), Err(ApiError::Internal)));
    Ok(())
}


#[test]
fn the_access_table_requires_the_permission_on_both_routes() -> TestResult {
    let table = oncall_access();
    assert_eq!(table.len(), COUNT_TWO);
    for path in [LIST_PATH, GET_PATH] {
        let rule = table.get(&route_key("GET", path)).ok_or("missing")?;
        assert_eq!(rule.requirement, Requirement::Permission(PERMISSION_ONCALL_READ.to_owned()));
    }
    assert_eq!(PERMISSION_ONCALL_READ, "oncall.read");
    let document = serde_json::to_value(oncall_document())?;
    let paths = document.get("paths").and_then(Value::as_object).ok_or("no paths")?;
    assert!(paths.contains_key(LIST_PATH) && paths.contains_key(GET_PATH));
    Ok(())
}


#[tokio::test]
async fn a_stored_line_separator_fingerprint_is_skipped_and_never_logged() -> TestResult {
    let fx = fixture()?;
    stored(&fx.script, TENANT, vec![alert(1, "good", at(0)?), alert(SECOND, "a\u{2028}b", at(1)?)]);
    let token = login(&fx.router, ANALYST).await?;
    let capture = Capture(Arc::default());
    LazyLock::force(&ANCHOR);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer({
                let sink = capture.clone();
                move || sink.clone()
            })
            .finish(),
    );
    let (listed, single) = {
        let _guard = tracing::dispatcher::set_default(&dispatch);
        (
            get(&fx.router, LIST_PATH, Some(&token)).await?,
            get(&fx.router, "/oncall/alerts/2", Some(&token)).await?,
        )
    };
    assert_eq!(listed.status(), StatusCode::OK);
    let json = body_json(listed).await?;
    assert_eq!(item_ids(&json)?, [1]);
    assert_eq!(json.get("skipped"), Some(&json!(1)));
    assert_eq!(single.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(single).await?.to_string();
    let logs = String::from_utf8(capture.0.lock().map_err(|error| error.to_string())?.clone())?;
    assert!(logs.contains("stored_value"));
    assert!(!logs.contains("2028") && !logs.contains('\u{2028}') && !body.contains('\u{2028}') && !body.contains("2028"));
    Ok(())
}


#[tokio::test]
async fn a_stored_fingerprint_with_an_edge_space_is_skipped_not_a_500() -> TestResult {
    let fx = fixture()?;
    stored(&fx.script, TENANT, vec![alert(1, "good", at(0)?), alert(SECOND, "x ", at(1)?)]);
    let token = login(&fx.router, ANALYST).await?;
    let listed = get(&fx.router, LIST_PATH, Some(&token)).await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let json = body_json(listed).await?;
    assert_eq!(item_ids(&json)?, [1]);
    assert_eq!(json.get("skipped"), Some(&json!(1)));
    Ok(())
}
