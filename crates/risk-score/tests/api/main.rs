mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
mod types;


use axum::http::StatusCode;
use core_api::model::{ApiError, ApiIdentity, Requirement};
use core_api::routes::route_key;
use core_auth::rbac::PERMISSION_ALERTS_READ;
use core_config::reload::{reload, ReloadOutcome};
use core_pg::scope::tenant_of;
use fixture::{
    calls, fixture, fixture_with, lock, outcome_of, scope, score, set_mode, set_outcome, ticking_clock, weights_engine, Mode, ANALYST, FIRST_NOW,
    FULL_POINTS, MARKER, OTHER_TENANT, OUT_OF_RANGE_TEXT, READER, SWAPPED_POINTS, SWAPPED_TEXT, TENANT,
};
use http::{body_json, get, login};
use risk_score::api::{
    entity_ref, kind_name, limit_name, parse_kind, parse_limit, risk_access, risk_document, scope_of, DEFAULT_LIMIT, GET_PATH, LIST_PATH,
    MAX_LIST_LIMIT,
};
use risk_score::api_model::{Failure, RiskState, Unavailable};
use risk_score::backend::{system_clock, system_now};
use risk_score::cache::{default_bounds, scores_for, uncached_count, CACHE_SECONDS, MAX_CACHED_TENANTS, MAX_COMPUTE_SECONDS};
use risk_score::model::EntityKind;
use risk_score::source::{Limit, Truncated};
use risk_score::weights::weights_state;
use serde_json::{json, Value};
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tracing::subscriber::set_default;
use types::{TestError, TestResult};


const THREE: usize = 3;


const EIGHT: usize = 8;


const FOUR: usize = 4;


const TWO: usize = 2;


const TWO_PERMITS: u32 = 2;


const HIGH: u8 = 80;


const MEDIUM: u8 = 50;


const LOW: u8 = 10;


const ALERTS_READ: usize = 7;


const INFORMATIONAL: usize = 2;


const REFUSED_HOSTS: usize = 3;


const READ_AT_CAP: usize = 100;


const EPOCH_2020: i64 = 1_577_836_800;


const LONG_ID: usize = 300;


const ONE_SECOND: Duration = Duration::from_secs(1);


static ANCHOR: LazyLock<tracing::Dispatch> = LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn seeded(fx: &fixture::Fixture) {
    let mut acme = outcome_of(vec![
        score(EntityKind::Host, "web01", HIGH),
        score(EntityKind::User, "alice", MEDIUM),
        score(EntityKind::Host, "db01", LOW),
    ]);
    acme.alerts_read = ALERTS_READ;
    acme.informational = INFORMATIONAL;
    acme.refused.insert(EntityKind::Host, REFUSED_HOSTS);
    set_outcome(&fx.script, TENANT, acme);
    set_outcome(&fx.script, OTHER_TENANT, outcome_of(vec![score(EntityKind::Host, "foreign", HIGH)]));
}


fn entity_ids(json: &Value) -> Result<Vec<String>, TestError> {
    Ok(json
        .get("entities")
        .and_then(Value::as_array)
        .ok_or("no entities")?
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}


fn error_code(json: &Value) -> Option<&str> {
    json.get("error").and_then(|error| error.get("code")).and_then(Value::as_str)
}


#[tokio::test]
async fn the_list_is_the_tenant_scores_highest_first_with_the_counts() -> TestResult {
    let fx = fixture()?;
    seeded(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let response = get(&fx.router, LIST_PATH, Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await?;
    assert_eq!(entity_ids(&json)?, ["web01", "alice", "db01"]);
    assert_eq!(json.get("computed_at"), Some(&json!(FIRST_NOW)));
    assert_eq!(json.get("alerts_read"), Some(&json!(ALERTS_READ)));
    assert_eq!(json.get("informational"), Some(&json!(INFORMATIONAL)));
    assert_eq!(json.get("refused"), Some(&json!({"host": REFUSED_HOSTS})));
    assert_eq!(json.get("truncated"), Some(&Value::Null));
    let head = json
        .get("entities")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .ok_or("empty")?;
    assert_eq!(
        head,
        &json!({"kind": "host", "id": "web01", "value": HIGH, "contributions_used": 1, "contributions_dropped": 0})
    );
    assert_eq!(lock(&fx.script.tenants).as_slice(), [TENANT]);
    Ok(())
}


#[tokio::test]
async fn limit_and_kind_shape_the_list() -> TestResult {
    let fx = fixture()?;
    seeded(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let one = body_json(get(&fx.router, "/risk/entities?limit=1", Some(&token)).await?).await?;
    assert_eq!(entity_ids(&one)?, ["web01"]);
    let max = get(&fx.router, &format!("/risk/entities?limit={MAX_LIST_LIMIT}"), Some(&token)).await?;
    assert_eq!(max.status(), StatusCode::OK);
    let hosts = body_json(get(&fx.router, "/risk/entities?kind=host", Some(&token)).await?).await?;
    assert_eq!(entity_ids(&hosts)?, ["web01", "db01"]);
    let users = body_json(get(&fx.router, "/risk/entities?kind=user&limit=5", Some(&token)).await?).await?;
    assert_eq!(entity_ids(&users)?, ["alice"]);
    Ok(())
}


#[tokio::test]
async fn a_bad_limit_or_kind_or_parameter_is_a_400_without_a_computation() -> TestResult {
    let fx = fixture()?;
    let token = login(&fx.router, ANALYST).await?;
    let queries = [
        "limit=0".to_owned(),
        format!("limit={}", MAX_LIST_LIMIT + 1),
        "limit=abc".to_owned(),
        "limit=1e3".to_owned(),
        "limit=-1".to_owned(),
        "limit=+5".to_owned(),
        "limit=99999999999999999999999".to_owned(),
        "limit=1&limit=2".to_owned(),
        "kind=ip".to_owned(),
        "kind=Host".to_owned(),
        "kind=".to_owned(),
        "unknown=1".to_owned(),
        format!("tenant={OTHER_TENANT}"),
    ];
    for query in queries {
        let response = get(&fx.router, &format!("/risk/entities?{query}"), Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(error_code(&body_json(response).await?), Some("bad_request"), "{query}");
    }
    assert_eq!(calls(&fx.script), 0);
    Ok(())
}


#[tokio::test]
async fn a_truncated_outcome_is_served_with_truncated_set() -> TestResult {
    let fx = fixture()?;
    let mut outcome = outcome_of(vec![score(EntityKind::Host, "web01", HIGH)]);
    outcome.truncated = Some(Truncated {
        limit: Limit::Contributions,
        read: READ_AT_CAP,
        cap: READ_AT_CAP,
    });
    set_outcome(&fx.script, TENANT, outcome);
    let token = login(&fx.router, ANALYST).await?;
    let json = body_json(get(&fx.router, LIST_PATH, Some(&token)).await?).await?;
    assert_eq!(
        json.get("truncated"),
        Some(&json!({"limit": "contributions", "read": READ_AT_CAP, "cap": READ_AT_CAP}))
    );
    let one = body_json(get(&fx.router, "/risk/entities/host/web01", Some(&token)).await?).await?;
    assert_eq!(one.get("truncated").and_then(|cut| cut.get("limit")), Some(&json!("contributions")));
    Ok(())
}


#[tokio::test]
async fn an_entity_is_read_by_kind_and_id_for_the_session_tenant_only() -> TestResult {
    let fx = fixture()?;
    seeded(&fx);
    let token = login(&fx.router, ANALYST).await?;
    let found = get(&fx.router, "/risk/entities/user/alice", Some(&token)).await?;
    assert_eq!(found.status(), StatusCode::OK);
    let json = body_json(found).await?;
    assert_eq!(json.get("computed_at"), Some(&json!(FIRST_NOW)));
    assert_eq!(json.get("entity").and_then(|entity| entity.get("value")), Some(&json!(MEDIUM)));
    let unknown = get(&fx.router, "/risk/entities/host/nothing", Some(&token)).await?;
    let foreign = get(&fx.router, "/risk/entities/host/foreign", Some(&token)).await?;
    let wrong_kind = get(&fx.router, "/risk/entities/host/alice", Some(&token)).await?;
    for response in [&unknown, &foreign, &wrong_kind] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let (left, right) = (body_json(unknown).await?, body_json(foreign).await?);
    assert_eq!(left, right);
    assert_eq!(error_code(&left), Some("not_found"));
    assert!(lock(&fx.script.tenants).iter().all(|tenant| tenant == TENANT));
    Ok(())
}


#[tokio::test]
async fn a_refused_kind_or_id_is_the_same_404_without_a_computation() -> TestResult {
    let fx = fixture()?;
    let token = login(&fx.router, ANALYST).await?;
    let paths = [
        "/risk/entities/ip/1.2.3.4".to_owned(),
        "/risk/entities/HOST/web01".to_owned(),
        "/risk/entities/host/%00".to_owned(),
        "/risk/entities/host/%ff".to_owned(),
        "/risk/entities/host/%c0%af".to_owned(),
        "/risk/entities/host/a%0ab".to_owned(),
        "/risk/entities/host/a%e2%80%aeb".to_owned(),
        "/risk/entities/host/%e3%85%a4".to_owned(),
        "/risk/entities/host/%2e%2e".to_owned(),
        format!("/risk/entities/host/{}", "x".repeat(LONG_ID)),
    ];
    let fixed = body_json(get(&fx.router, "/risk/entities/host/nothing", Some(&token)).await?).await?;
    let before = calls(&fx.script);
    for path in paths {
        let response = get(&fx.router, &path, Some(&token)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body_json(response).await?, fixed, "{path}");
    }
    assert_eq!(calls(&fx.script), before);
    Ok(())
}


#[tokio::test]
async fn no_session_is_401_and_a_reader_is_403_before_any_computation() -> TestResult {
    let fx = fixture()?;
    let reader = login(&fx.router, READER).await?;
    for path in [LIST_PATH, "/risk/entities/host/web01"] {
        assert_eq!(get(&fx.router, path, None).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some("bogus")).await?.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(get(&fx.router, path, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(calls(&fx.script), 0);
    let token = login(&fx.router, ANALYST).await?;
    assert_eq!(get(&fx.router, LIST_PATH, Some(&token)).await?.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn another_method_is_denied_by_the_deny_by_default_table() -> TestResult {
    let fx = fixture()?;
    let token = login(&fx.router, ANALYST).await?;
    let response = http::call(&fx.router, "POST", LIST_PATH, Some(&token), axum::body::Body::empty()).await?;
    assert!(response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(calls(&fx.script), 0);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_computation_past_the_deadline_is_a_503_and_nothing_is_cached() -> TestResult {
    let fx = fixture()?;
    let token = login(&fx.router, ANALYST).await?;
    set_mode(&fx.script, Mode::Hang);
    let timed_out = get(&fx.router, LIST_PATH, Some(&token)).await?;
    assert_eq!(timed_out.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&body_json(timed_out).await?), Some("unavailable"));
    assert_eq!(calls(&fx.script), 1);
    set_mode(&fx.script, Mode::Answer);
    assert_eq!(get(&fx.router, LIST_PATH, Some(&token)).await?.status(), StatusCode::OK);
    assert_eq!(calls(&fx.script), TWO);
    Ok(())
}


#[tokio::test]
async fn a_store_error_is_the_fixed_503_and_its_text_reaches_neither_reply_nor_log() -> TestResult {
    let fx = fixture()?;
    let token = login(&fx.router, ANALYST).await?;
    LazyLock::force(&ANCHOR);
    let captured = Capture(Arc::default());
    let guard = set_default(
        tracing_subscriber::fmt()
            .with_writer({
                let sink = captured.clone();
                move || sink.clone()
            })
            .with_ansi(false)
            .finish(),
    );
    set_mode(&fx.script, Mode::Fail);
    let failed = get(&fx.router, LIST_PATH, Some(&token)).await?;
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(failed).await?;
    assert_eq!(error_code(&body), Some("unavailable"));
    assert!(!body.to_string().contains(MARKER));
    let by_id = get(&fx.router, "/risk/entities/host/web01", Some(&token)).await?;
    assert_eq!(by_id.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(guard);
    let logs = String::from_utf8(lock(&captured.0).clone())?;
    assert!(logs.contains("computation failed"), "{logs}");
    assert!(!logs.contains(MARKER), "{logs}");
    Ok(())
}


#[tokio::test]
async fn two_requests_of_one_tenant_run_the_computation_once_and_two_tenants_twice() -> TestResult {
    let fx = fixture()?;
    set_mode(&fx.script, Mode::Gated);
    let script = Arc::clone(&fx.script);
    let release = async {
        script.entered.acquire().await?.forget();
        tokio::task::yield_now().await;
        script.gate.add_permits(1);
        Ok::<(), TestError>(())
    };
    let (first, second, released) = tokio::join!(scores_for(&fx.risk, scope(TENANT)?), scores_for(&fx.risk, scope(TENANT)?), release);
    released?;
    assert!(Arc::ptr_eq(&first?, &second?));
    assert_eq!(calls(&fx.script), 1);
    let other = Arc::clone(&fx.script);
    let release_both = async {
        other.entered.acquire_many(TWO_PERMITS).await?.forget();
        other.gate.add_permits(TWO_PERMITS as usize);
        Ok::<(), TestError>(())
    };
    let (left, right, released_both) = tokio::join!(
        scores_for(&fx.risk, scope("tenant-a")?),
        scores_for(&fx.risk, scope("tenant-b")?),
        release_both
    );
    released_both?;
    left?;
    right?;
    assert_eq!(calls(&fx.script), THREE);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_result_is_served_for_the_cache_period_and_recomputed_after() -> TestResult {
    let fx = fixture()?;
    let first = scores_for(&fx.risk, scope(TENANT)?).await?;
    tokio::time::advance(Duration::from_secs(CACHE_SECONDS) - ONE_SECOND).await;
    let again = scores_for(&fx.risk, scope(TENANT)?).await?;
    assert!(Arc::ptr_eq(&first, &again));
    assert_eq!(calls(&fx.script), 1);
    tokio::time::advance(TWO_SECONDS).await;
    let later = scores_for(&fx.risk, scope(TENANT)?).await?;
    assert_eq!(calls(&fx.script), TWO);
    assert_eq!(later.computed_at, first.computed_at + 1);
    Ok(())
}


const TWO_SECONDS: Duration = Duration::from_secs(2);


#[tokio::test]
async fn a_weights_swap_empties_the_cache_and_a_refused_one_keeps_it() -> TestResult {
    let fx = fixture()?;
    scores_for(&fx.risk, scope(TENANT)?).await?;
    std::fs::write(&fx.weights_file, OUT_OF_RANGE_TEXT)?;
    assert!(matches!(reload(&fx.engine), ReloadOutcome::Refused { .. }));
    std::fs::write(&fx.weights_file, "not: [valid")?;
    assert!(matches!(reload(&fx.engine), ReloadOutcome::Refused { .. }));
    scores_for(&fx.risk, scope(TENANT)?).await?;
    assert_eq!(calls(&fx.script), 1);
    std::fs::write(&fx.weights_file, SWAPPED_TEXT)?;
    assert!(matches!(reload(&fx.engine), ReloadOutcome::Applied { .. }));
    scores_for(&fx.risk, scope(TENANT)?).await?;
    scores_for(&fx.risk, scope(TENANT)?).await?;
    assert_eq!(calls(&fx.script), TWO);
    assert_eq!(lock(&fx.script.weights_seen).as_slice(), [FULL_POINTS, SWAPPED_POINTS]);
    Ok(())
}


#[tokio::test]
async fn a_swap_during_a_computation_keeps_its_snapshot_and_is_not_served_after() -> TestResult {
    let fx = fixture()?;
    set_mode(&fx.script, Mode::Gated);
    let script = Arc::clone(&fx.script);
    let swap = async {
        script.entered.acquire().await?.forget();
        std::fs::write(&fx.weights_file, SWAPPED_TEXT)?;
        assert!(matches!(reload(&fx.engine), ReloadOutcome::Applied { .. }));
        script.gate.add_permits(1);
        Ok::<(), TestError>(())
    };
    let (running, swapped) = tokio::join!(scores_for(&fx.risk, scope(TENANT)?), swap);
    swapped?;
    running?;
    assert_eq!(lock(&fx.script.weights_seen).as_slice(), [FULL_POINTS]);
    script.gate.add_permits(1);
    scores_for(&fx.risk, scope(TENANT)?).await?;
    assert_eq!(calls(&fx.script), TWO);
    assert_eq!(lock(&fx.script.weights_seen).as_slice(), [FULL_POINTS, SWAPPED_POINTS]);
    Ok(())
}


fn capped(state: RiskState) -> RiskState {
    RiskState {
        bounds: risk_score::api_model::Bounds {
            max_tenants: TWO,
            ..state.bounds
        },
        ..state
    }
}


#[tokio::test]
async fn a_tenant_beyond_the_cap_computes_uncached_and_is_counted() -> TestResult {
    let fx = fixture_with(capped)?;
    scores_for(&fx.risk, scope("tenant-a")?).await?;
    scores_for(&fx.risk, scope("tenant-b")?).await?;
    scores_for(&fx.risk, scope("tenant-c")?).await?;
    scores_for(&fx.risk, scope("tenant-c")?).await?;
    scores_for(&fx.risk, scope("tenant-a")?).await?;
    assert_eq!(calls(&fx.script), FOUR);
    assert_eq!(uncached_count(&fx.risk.uncached), TWO as u64);
    assert_eq!(fx.risk.uncached.load(Ordering::Relaxed), TWO as u64);
    assert_eq!(lock(&fx.risk.slots).len(), TWO);
    Ok(())
}


#[test]
fn the_tenant_comes_from_the_identity_and_a_bad_one_is_internal() -> TestResult {
    let identity = ApiIdentity {
        module: "risk".to_owned(),
        tenant: TENANT.to_owned(),
        generation: 0,
    };
    assert_eq!(scope_of(&identity).map(|found| tenant_of(&found).to_owned()), Ok(TENANT.to_owned()));
    let bad = ApiIdentity {
        tenant: "bad tenant/".to_owned(),
        ..identity
    };
    assert_eq!(scope_of(&bad).map(|found| tenant_of(&found).to_owned()), Err(ApiError::Internal));
    Ok(())
}


#[test]
fn small_helpers_cover_their_edges() -> TestResult {
    assert_eq!(parse_limit(None), Ok(DEFAULT_LIMIT));
    assert_eq!(parse_limit(Some("500")), Ok(MAX_LIST_LIMIT));
    assert_eq!(parse_limit(Some("501")), Err(ApiError::BadRequest));
    assert_eq!(parse_kind("host"), Some(EntityKind::Host));
    assert_eq!(parse_kind("user"), Some(EntityKind::User));
    assert_eq!(parse_kind("ip"), None);
    let names = [
        EntityKind::User,
        EntityKind::Host,
        EntityKind::Ip,
        EntityKind::Container,
        EntityKind::CloudAccount,
    ]
    .map(kind_name);
    assert_eq!(names, ["user", "host", "ip", "container", "cloud_account"]);
    assert_eq!(
        [Limit::Alerts, Limit::Contributions, Limit::Entities].map(limit_name),
        ["alerts", "contributions", "entities"]
    );
    assert!(entity_ref("host", "web01".to_owned()).is_some());
    assert!(entity_ref("host", String::new()).is_none());
    assert_eq!(Failure::from(Unavailable), Failure::Unavailable);
    assert_eq!(Failure::from(ApiError::Internal), Failure::Api(ApiError::Internal));
    assert_eq!(Unavailable.to_string(), "risk scores are unavailable");
    let bounds = default_bounds();
    assert_eq!(
        (bounds.max_tenants, bounds.cache, bounds.deadline),
        (
            MAX_CACHED_TENANTS,
            Duration::from_secs(CACHE_SECONDS),
            Duration::from_secs(MAX_COMPUTE_SECONDS)
        )
    );
    assert!(system_now() > EPOCH_2020);
    assert!(system_clock()() > EPOCH_2020);
    assert_eq!(ticking_clock()(), FIRST_NOW);
    Ok(())
}


#[test]
fn access_and_document_cover_both_routes_with_the_alerts_permission() -> TestResult {
    let table = risk_access();
    for path in [LIST_PATH, GET_PATH] {
        let rule = table.get(&route_key("GET", path)).ok_or("no rule")?;
        assert_eq!(rule.requirement, Requirement::Permission(PERMISSION_ALERTS_READ.to_owned()));
    }
    assert_eq!(table.len(), TWO);
    let document = serde_json::to_value(risk_document())?;
    let paths = document.get("paths").and_then(Value::as_object).ok_or("no paths")?;
    assert!(paths.contains_key(LIST_PATH) && paths.contains_key(GET_PATH));
    Ok(())
}


#[test]
fn the_weights_state_names_every_value() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (engine, _file) = weights_engine(&dir)?;
    let state = weights_state(&core_config::reload::current_config(&engine));
    assert_eq!(state.len(), EIGHT);
    assert_eq!(state.get("full_score_points").map(String::as_str), Some("100"));
    Ok(())
}
