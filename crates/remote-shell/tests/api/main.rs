mod fake;
mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
#[path = "../common/types.rs"]
mod types;


use alerts::error::StoreError as LeaseError;
use axum::http::StatusCode;
use core_api::model::ApiIdentity;
use core_pg::error::PgError;
use fake::{capture_dispatch, captured, put_row, row_of, Capture, CLOSED, HASH_BYTES, HASH_FILL, OPENED};
use fixture::{fixture, fixture_with, put_session, ANALYST, AUDITOR, OTHER_TENANT, TENANT};
use http::{body_json, call, get, login};
use remote_shell::api::{
    failure_category, get_flow, hex, list_flow, list_view, parse_limit, parse_open, remote_shell_access, remote_shell_document, rfc3339,
    session_view, DEFAULT_PAGE,
};
use remote_shell::api_model::{ListQuery, SessionsBackend};
use remote_shell::error::StoreError;
use remote_shell::store::MAX_PAGE;
use remote_shell::store_model::{Page, SessionRow};
use serde_json::{json, Value};
use std::sync::Arc;
use types::TestResult;


const MARKER: &str = "SECRET-MARKER-7f3a";


const YEAR_10000: i64 = 253_402_300_800;


const SEEDED: i64 = 7;


const OVER_REFERENCE: usize = 129;


const PAIR: usize = 2;


const TICKET_COLUMN: usize = 3;


const AUDITED_READS: usize = 3;


const DETAIL_READS: usize = 3;


const NIBBLE_MAX: u8 = 15;


const COLUMNS: usize = 10;


const HUGE_CURSOR: usize = 20_000;


const EVERY_SECOND: i64 = 2;


const HOSTILE: &str = "ev\u{1b}il\u{202e}MARK";


fn items(json: &Value) -> Result<&Vec<Value>, types::TestError> {
    Ok(json.get("items").and_then(Value::as_array).ok_or("no items")?)
}


fn ids_of(json: &Value) -> Result<Vec<String>, types::TestError> {
    Ok(items(json)?
        .iter()
        .filter_map(|item| item.get("session_id").and_then(Value::as_str))
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
    (0..SEEDED).for_each(|index| {
        put_session(
            &fx.fake,
            TENANT,
            &format!("a-{index}"),
            "host-1",
            OPENED + index,
            index % EVERY_SECOND == 0,
        )
    });
    put_session(&fx.fake, TENANT, "a-other", "host-2", OPENED, false);
    put_session(&fx.fake, OTHER_TENANT, "b-1", "host-1", OPENED, false);
    put_session(&fx.fake, OTHER_TENANT, "a-0", "host-9", OPENED, false);
}


#[tokio::test]
async fn the_listing_is_the_tenant_newest_first_and_names_the_recording() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, AUDITOR).await?;
    let response = get(&fx.router, "/remote-shell/sessions", Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_json(response).await?;
    let ids = ids_of(&page)?;
    assert_eq!(ids.len(), usize::try_from(SEEDED)? + 1);
    assert!(!ids.contains(&"b-1".to_owned()));
    assert_eq!(ids.first().map(String::as_str), Some("a-6"));
    assert_eq!(page.get("skipped"), Some(&json!(0)));
    assert_eq!(page.get("next_cursor"), Some(&Value::Null));
    let closed = items(&page)?
        .iter()
        .find(|item| item.get("session_id") == Some(&json!("a-6")))
        .ok_or("no a-6")?;
    assert_eq!(closed.get("opened_at"), Some(&json!("2027-01-15T08:00:06Z")));
    assert_eq!(closed.get("closed_at"), Some(&json!("2027-01-15T08:10:00Z")));
    assert_eq!(closed.get("close_reason"), Some(&json!("user_close")));
    assert_eq!(closed.get("recording_hash"), Some(&json!("ab".repeat(HASH_BYTES))));
    assert_eq!(closed.get("recording_frames"), Some(&json!(fake::FRAMES)));
    assert_eq!(closed.get("recording_bytes"), Some(&json!(fake::BYTES)));
    assert!(closed.get("tenant").is_none());
    let open = items(&page)?
        .iter()
        .find(|item| item.get("session_id") == Some(&json!("a-5")))
        .ok_or("no a-5")?;
    assert_eq!(open.get("closed_at"), Some(&Value::Null));
    assert_eq!(open.get("recording_hash"), Some(&Value::Null));
    Ok(())
}


#[tokio::test]
async fn a_walk_with_every_limit_gives_each_session_once() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, AUDITOR).await?;
    for limit in ["1", "3", "200"] {
        let mut collected = Vec::new();
        let mut path = Some(format!("/remote-shell/sessions?limit={limit}"));
        let mut rounds = 0;
        while let Some(current) = path.take().filter(|_next| rounds <= SEEDED + 1) {
            let page = body_json(get(&fx.router, &current, Some(&token)).await?).await?;
            collected.extend(ids_of(&page)?);
            path = page
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(|cursor| format!("/remote-shell/sessions?limit={limit}&cursor={}", encoded(cursor)));
            rounds += 1;
        }
        let mut sorted = collected.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), collected.len(), "{limit}");
        assert_eq!(collected.len(), usize::try_from(SEEDED)? + 1, "{limit}");
    }
    Ok(())
}


#[tokio::test]
async fn filters_narrow_the_list_and_a_requester_with_punctuation_is_percent_encoded() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    fake::put(&fx.fake, TENANT, "p-1", "auth0|a+b/c=d", "host-3", OPENED, false);
    let token = login(&fx.router, AUDITOR).await?;
    let by_asset = body_json(get(&fx.router, "/remote-shell/sessions?asset=host-2", Some(&token)).await?).await?;
    assert_eq!(ids_of(&by_asset)?, ["a-other"]);
    let open_only = body_json(get(&fx.router, "/remote-shell/sessions?open=true&asset=host-1", Some(&token)).await?).await?;
    assert_eq!(items(&open_only)?.len(), usize::try_from(SEEDED / EVERY_SECOND)?);
    let all = body_json(get(&fx.router, "/remote-shell/sessions?open=false&asset=host-1", Some(&token)).await?).await?;
    assert_eq!(items(&all)?.len(), usize::try_from(SEEDED)?);
    let path = format!("/remote-shell/sessions?requester={}", encoded("auth0|a+b/c=d"));
    let by_requester = body_json(get(&fx.router, &path, Some(&token)).await?).await?;
    assert_eq!(ids_of(&by_requester)?, ["p-1"]);
    let plus_unencoded = get(&fx.router, "/remote-shell/sessions?requester=a+b", Some(&token)).await?;
    assert_eq!(plus_unencoded.status(), StatusCode::BAD_REQUEST);
    Ok(())
}


#[tokio::test]
async fn a_bad_query_is_a_fixed_400_before_any_store_call() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, AUDITOR).await?;
    let huge = "1".repeat(HUGE_CURSOR);
    let over_asset = "a".repeat(OVER_REFERENCE);
    let bad = [
        "limit=201".to_owned(),
        "limit=+5".to_owned(),
        "limit=0".to_owned(),
        "limit=".to_owned(),
        "limit=-1".to_owned(),
        "limit=99999999999999999999".to_owned(),
        "open=1".to_owned(),
        "open=TRUE".to_owned(),
        "open=".to_owned(),
        "tenant=globex".to_owned(),
        "asset=".to_owned(),
        "asset=-x".to_owned(),
        format!("asset={over_asset}"),
        "requester=".to_owned(),
        "requester=al%00ice".to_owned(),
        "cursor=junk".to_owned(),
        "cursor=1800000000.-x".to_owned(),
        "cursor=%2B1800000000.s-1".to_owned(),
        format!("cursor={huge}"),
        "limit=1&limit=2".to_owned(),
        "limit=%FF".to_owned(),
    ];
    let mut bodies = Vec::new();
    for query in &bad {
        let response = get(&fx.router, &format!("/remote-shell/sessions?{query}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        bodies.push(body_json(response).await?);
    }
    assert!(bodies.windows(PAIR).all(|pair| pair.first() == pair.get(1)));
    assert_eq!(code_of(bodies.first().ok_or("none")?), Some("bad_request"));
    assert_eq!(fake::read_count(&fx.fake), 0);
    let edge = get(&fx.router, "/remote-shell/sessions?limit=200", Some(&token)).await?;
    assert_eq!(edge.status(), StatusCode::OK);
    assert_eq!(fake::read_count(&fx.fake), 1);
    Ok(())
}


#[tokio::test]
async fn a_forged_cursor_or_tenant_never_reaches_another_tenant() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, AUDITOR).await?;
    let page = body_json(get(&fx.router, "/remote-shell/sessions?tenant=globex", Some(&token)).await?).await?;
    assert_eq!(code_of(&page), Some("bad_request"));
    let forged = encoded(&format!("{}.b-1", OPENED + 1));
    let walked = body_json(get(&fx.router, &format!("/remote-shell/sessions?cursor={forged}&limit=200"), Some(&token)).await?).await?;
    assert!(!ids_of(&walked)?.iter().any(|id| id == "b-1"));
    let foreign = get(&fx.router, "/remote-shell/sessions/b-1", Some(&token)).await?;
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    let foreign_filter = body_json(get(&fx.router, "/remote-shell/sessions?asset=host-9", Some(&token)).await?).await?;
    assert!(items(&foreign_filter)?.is_empty());
    Ok(())
}


#[tokio::test]
async fn the_detail_answers_unknown_foreign_and_refused_ids_alike() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, AUDITOR).await?;
    let found = get(&fx.router, "/remote-shell/sessions/a-6", Some(&token)).await?;
    assert_eq!(found.status(), StatusCode::OK);
    let view = body_json(found).await?;
    assert_eq!(view.get("session_id"), Some(&json!("a-6")));
    assert_eq!(view.get("asset"), Some(&json!("host-1")));
    let reads_before = fake::read_count(&fx.fake);
    let long = "a".repeat(OVER_REFERENCE);
    let mut bodies = Vec::new();
    for id in ["nope", "b-1", "-x", "%00", "%FF", "a%20b", long.as_str(), "a%2F..%2Fb-1"] {
        let response = get(&fx.router, &format!("/remote-shell/sessions/{id}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{id}");
        bodies.push((id, response.into_body()));
    }
    let mut texts = Vec::new();
    for (id, body) in bodies {
        let bytes = axum::body::to_bytes(body, http::BODY_READ_LIMIT).await?;
        assert!(!String::from_utf8_lossy(&bytes).contains(id) || id == "nope", "{id}");
        texts.push(bytes);
    }
    assert!(texts.windows(PAIR).all(|pair| pair.first() == pair.get(1)));
    assert_eq!(fake::read_count(&fx.fake) - reads_before, DETAIL_READS);
    Ok(())
}


#[tokio::test]
async fn a_hostile_stored_row_is_skipped_in_the_list_and_a_stored_value_500_in_the_detail() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    fake::put(&fx.fake, TENANT, "evil-1", HOSTILE, "host-1", OPENED + SEEDED + 1, false);
    let token = login(&fx.router, AUDITOR).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let listed = get(&fx.router, "/remote-shell/sessions?limit=200", Some(&token)).await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let page = body_json(listed).await?;
    assert_eq!(page.get("skipped"), Some(&json!(1)));
    assert!(!page.to_string().contains("MARK") && !ids_of(&page)?.contains(&"evil-1".to_owned()));
    let detail = get(&fx.router, "/remote-shell/sessions/evil-1", Some(&token)).await?;
    assert_eq!(detail.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(detail).await?;
    assert_eq!(code_of(&body), Some("stored_value"));
    assert!(!body.to_string().contains("MARK") && !body.to_string().contains("evil-1"));
    let logs = captured(&capture);
    assert!(logs.contains("skipped=1") && logs.contains("category=\"stored_value\""), "{logs}");
    assert!(!logs.contains("MARK") && !logs.contains("evil-1"), "{logs}");
    assert_eq!(logs.matches("remote shell sessions skipped").count(), 1, "{logs}");
    Ok(())
}


#[tokio::test]
async fn only_the_audit_read_permission_reads_the_register() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let analyst = login(&fx.router, ANALYST).await?;
    let auditor = login(&fx.router, AUDITOR).await?;
    for path in ["/remote-shell/sessions", "/remote-shell/sessions/a-6"] {
        assert_eq!(get(&fx.router, path, Some(&analyst)).await?.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(get(&fx.router, path, None).await?.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(get(&fx.router, path, Some(&auditor)).await?.status(), StatusCode::OK, "{path}");
        let post = call(&fx.router, "POST", path, Some(&auditor), axum::body::Body::empty()).await?;
        assert!(post.status().is_client_error(), "{path}");
    }
    assert_eq!(fake::read_count(&fx.fake), PAIR);
    Ok(())
}


fn failing_backend(error: fn() -> StoreError) -> impl FnOnce(&Arc<fake::Fake>) -> SessionsBackend {
    move |_fake| SessionsBackend {
        list: Arc::new(move |_scope, _filter, _after, _limit| Box::pin(async move { Err(error()) })),
        get: Arc::new(move |_scope, _id| Box::pin(async move { Err(error()) })),
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
    let token = login(&fx.router, AUDITOR).await?;
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let _guard = tracing::dispatcher::set_default(&dispatch);
    for path in ["/remote-shell/sessions", "/remote-shell/sessions/s-1"] {
        let response = get(&fx.router, path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let shown = format!("{response:?}");
        let json = body_json(response).await?;
        assert_eq!(code_of(&json), Some("internal_error"));
        assert!(!json.to_string().contains(MARKER) && !shown.contains(MARKER));
    }
    let logs = captured(&capture);
    assert!(logs.contains("remote shell sessions failure") && logs.contains("database"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
    Ok(())
}


#[tokio::test]
async fn a_busy_store_is_429_and_a_refusing_store_is_400() -> TestResult {
    let busy = fixture_with(failing_backend(|| StoreError::Lease(LeaseError::Busy)))?;
    let token = login(&busy.router, AUDITOR).await?;
    for path in ["/remote-shell/sessions", "/remote-shell/sessions/s-1"] {
        assert_eq!(get(&busy.router, path, Some(&token)).await?.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    let refusing = fixture_with(failing_backend(|| StoreError::BadCursor))?;
    let other = login(&refusing.router, AUDITOR).await?;
    assert_eq!(
        get(&refusing.router, "/remote-shell/sessions", Some(&other)).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}


fn stored(opened: i64, closed: Option<i64>) -> SessionRow {
    SessionRow {
        session_id: "s-1".to_owned(),
        requester: "alice".to_owned(),
        asset: "host-1".to_owned(),
        ticket: "INC-1".to_owned(),
        opened_at: opened,
        closed_at: closed,
        close_reason: closed.map(|_at| "user_close".to_owned()),
        recording_frames: None,
        recording_hash: closed.map(|_at| vec![HASH_FILL; HASH_BYTES]),
        recording_bytes: None,
    }
}


#[test]
fn times_outside_rfc_3339_are_refused_and_counted() -> TestResult {
    assert_eq!(rfc3339(OPENED).as_deref(), Some("2027-01-15T08:00:00Z"));
    assert_eq!(rfc3339(YEAR_10000), None);
    assert_eq!(rfc3339(i64::MAX), None);
    assert!(session_view(&stored(OPENED, Some(CLOSED))).is_some());
    assert!(session_view(&stored(YEAR_10000, None)).is_none());
    assert!(session_view(&stored(OPENED, Some(YEAR_10000))).is_none());
    let page = Page {
        rows: vec![stored(OPENED, None), stored(YEAR_10000, None)],
        skipped: PAIR,
        next_cursor: Some("1.x".to_owned()),
    };
    let view = list_view(&page);
    assert_eq!((view.items.len(), view.skipped), (1, PAIR + 1));
    assert_eq!(view.next_cursor.as_deref(), Some("1.x"));
    assert_eq!(hex(&[0, NIBBLE_MAX, u8::MAX]), "000fff");
    Ok(())
}


#[test]
fn the_parsers_failure_mapping_access_and_document() -> TestResult {
    assert_eq!(parse_limit(None)?, DEFAULT_PAGE);
    assert_eq!(parse_limit(Some("0050"))?, DEFAULT_PAGE);
    assert_eq!(parse_limit(Some("200"))?, MAX_PAGE);
    ["0", "201", "", "+5", "5 ", "x", "4294967296"]
        .iter()
        .for_each(|text| assert!(parse_limit(Some(text)).is_err(), "{text}"));
    assert_eq!(
        (parse_open(None)?, parse_open(Some("false"))?, parse_open(Some("true"))?),
        (false, false, true)
    );
    assert!(parse_open(Some("1")).is_err());
    assert_eq!(failure_category(&StoreError::Lease(LeaseError::Busy)), "database");
    assert_eq!(failure_category(&StoreError::StoredValue { field: "x" }), "stored_value");
    assert_eq!(failure_category(&StoreError::BadRow { column: "x" }), "stored_value");
    assert_eq!(failure_category(&StoreError::BadCursor), "request");
    assert_eq!(remote_shell_access().len(), PAIR);
    let document = serde_json::to_value(remote_shell_document())?;
    let paths = document.get("paths").and_then(Value::as_object).ok_or("no paths")?;
    assert!(paths.contains_key("/remote-shell/sessions") && paths.contains_key("/remote-shell/sessions/{id}"));
    assert_eq!(row_of("s", "r", "a", OPENED, false).len(), COLUMNS);
    Ok(())
}


#[tokio::test]
async fn an_identity_with_a_malformed_tenant_reaches_no_store() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let backend = fake::memory_backend(&fx.fake);
    let identity = ApiIdentity {
        module: "remote-shell".to_owned(),
        tenant: "-bad".to_owned(),
        generation: 0,
    };
    let listed = list_flow(&identity, &backend, Ok(ListQuery::default())).await;
    let detail = get_flow(&identity, &backend, Some("a-6".to_owned())).await;
    assert_eq!(listed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(detail.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(fake::read_count(&fx.fake), 0);
    Ok(())
}


fn null_ticket_row(session: &str) -> remote_shell::types::Row {
    let mut row = row_of(session, "alice", "host-1", OPENED, false);
    if let Some(cell) = row.get_mut(TICKET_COLUMN) {
        *cell = remote_shell::store_model::Cell::Null;
    }
    row
}


fn wrong_typed_row(session: &str) -> remote_shell::types::Row {
    let mut row = row_of(session, "alice", "host-1", OPENED, false);
    if let Some(cell) = row.get_mut(TICKET_COLUMN) {
        *cell = remote_shell::store_model::Cell::Int(1);
    }
    row
}


#[tokio::test]
async fn a_row_that_does_not_decode_is_a_stored_value_500_in_the_detail() -> TestResult {
    let fx = fixture()?;
    put_row(&fx.fake, TENANT, "null-1", OPENED, null_ticket_row("null-1"));
    put_row(&fx.fake, TENANT, "typed-1", OPENED, wrong_typed_row("typed-1"));
    let token = login(&fx.router, AUDITOR).await?;
    for id in ["null-1", "typed-1"] {
        let detail = get(&fx.router, &format!("/remote-shell/sessions/{id}"), Some(&token)).await?;
        assert_eq!(detail.status(), StatusCode::INTERNAL_SERVER_ERROR, "{id}");
        let body = body_json(detail).await?;
        assert_eq!(code_of(&body), Some("stored_value"), "{id}");
    }
    Ok(())
}


#[tokio::test]
async fn a_page_ending_on_an_undecodable_key_is_a_stored_value_500() -> TestResult {
    let fx = fixture()?;
    let mut broken = row_of("last-1", "alice", "host-1", OPENED, false);
    if let Some(cell) = broken.get_mut(0) {
        *cell = remote_shell::store_model::Cell::Null;
    }
    put_row(
        &fx.fake,
        TENANT,
        "first-1",
        OPENED + 1,
        row_of("first-1", "alice", "host-1", OPENED + 1, false),
    );
    put_row(&fx.fake, TENANT, "last-1", OPENED, broken);
    put_row(
        &fx.fake,
        TENANT,
        "more-1",
        OPENED - 1,
        row_of("more-1", "alice", "host-1", OPENED - 1, false),
    );
    let token = login(&fx.router, AUDITOR).await?;
    let page = get(&fx.router, "/remote-shell/sessions?limit=2", Some(&token)).await?;
    assert_eq!(page.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(code_of(&body_json(page).await?), Some("stored_value"));
    Ok(())
}


#[tokio::test]
async fn another_tenants_row_is_never_returned_by_the_detail_or_the_list() -> TestResult {
    let fx = fixture()?;
    put_session(&fx.fake, OTHER_TENANT, "b-only", "host-1", OPENED, false);
    let token = login(&fx.router, AUDITOR).await?;
    let detail = get(&fx.router, "/remote-shell/sessions/b-only", Some(&token)).await?;
    assert_eq!(detail.status(), StatusCode::NOT_FOUND);
    let listed = body_json(get(&fx.router, "/remote-shell/sessions", Some(&token)).await?).await?;
    assert!(items(&listed)?.is_empty());
    Ok(())
}


#[tokio::test]
async fn every_read_of_the_register_is_audited() -> TestResult {
    let fx = fixture()?;
    seed(&fx);
    let token = login(&fx.router, AUDITOR).await?;
    for path in [
        "/remote-shell/sessions?asset=host-1",
        "/remote-shell/sessions/a-6",
        "/remote-shell/sessions/nope",
    ] {
        get(&fx.router, path, Some(&token)).await?;
    }
    let log = std::fs::read_to_string(fx._dir.path().join("audit.log"))?;
    assert_eq!(log.matches("\"target\":\"GET /remote-shell").count(), AUDITED_READS, "{log}");
    assert!(!log.contains("asset=host-1"), "{log}");
    Ok(())
}
