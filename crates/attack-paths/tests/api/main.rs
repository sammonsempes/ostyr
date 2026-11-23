mod fixture;
#[path = "../../../alerts/tests/api/http.rs"]
mod http;
mod memory;
mod types;


use attack_paths::api::{
    attack_paths_access, attack_paths_document, get_endpoint, item_of, parse_id, parse_limit, scope_of, store_failure, COLUMNS_MISMATCH_CLASS,
    DEFAULT_LIMIT, DIGEST_MISMATCH_CLASS, GET_PATH, LIST_PATH,
};
use attack_paths::api_model::{AttackPathsBackend, NoQuery};
use attack_paths::error::StoreError;
use attack_paths::store::{build_body, decode_meta, digest_hex, graph_digest, render_body, ReportMeta, MAX_LIST_LIMIT};
use axum::body::to_bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Extension;
use core_api::model::{ApiError, ApiIdentity, RequestId};
use core_auth::rbac::{builtin_catalog, is_allowed, PERMISSION_ATTACK_PATHS_READ};
use core_auth::types::RoleSet;
use fixture::{
    fixture, fixture_over, found, graph, memory_backend, seed, Fixture, ADMINISTRATOR, ANALYST, AUDITOR, GENERATED, OTHER_TENANT, READER, RESPONDER,
    TENANT,
};
use http::{get, login, BODY_READ_LIMIT};
use memory::{lock, malformed, STORED_BASE};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::sync::{Notify, Semaphore};
use tracing::Dispatch;
use types::{Calls, TestError, TestResult};


const ID_GAMMA: i64 = 3;


const ID_BETA: i64 = 2;


const ITEMS_TOTAL: usize = 3;


const PERMITTED_CALLS: usize = 4;


const PARSED_ID: i64 = 12;


const ROUTE_COUNT: usize = 2;


const META_ID: i64 = 7;


const META_BYTES: u64 = 10;


const META_STORED: i64 = 5;


const META_UNSEARCHED: u64 = 3;


const SPIN_CAP: usize = 100_000;


const FOURTH_ID: &str = "4";


const UNKNOWN_ID: &str = "999";


const GLOBEX_MARKER: &str = "globex-secret";


const BAD_LIMITS: [&str; 9] = ["0", "101", "-1", "1e3", "", "+5", "5.0", "%205", "abc"];


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct Captured(Arc<Mutex<Vec<u8>>>);


impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        lock(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn capture() -> (Dispatch, Arc<Mutex<Vec<u8>>>) {
    LazyLock::force(&ANCHOR);
    let sink: Arc<Mutex<Vec<u8>>> = Arc::default();
    let writer = Arc::clone(&sink);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Captured(Arc::clone(&writer)))
            .finish(),
    );
    (dispatch, sink)
}


async fn seeded() -> Result<(Fixture, String), TestError> {
    let fx = fixture()?;
    seed(&fx.db, TENANT, "alpha", false).await?;
    seed(&fx.db, TENANT, "beta", true).await?;
    seed(&fx.db, TENANT, "gamma", false).await?;
    seed(&fx.db, OTHER_TENANT, GLOBEX_MARKER, false).await?;
    let token = login(&fx.router, ANALYST).await?;
    Ok((fx, token))
}


async fn read(fx: &Fixture, path: &str, token: Option<&str>) -> Result<(StatusCode, Option<String>, Vec<u8>), TestError> {
    let response = get(&fx.router, path, token).await?;
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = to_bytes(response.into_body(), BODY_READ_LIMIT).await?;
    Ok((status, content_type, bytes.to_vec()))
}


async fn read_json(fx: &Fixture, path: &str, token: Option<&str>) -> Result<(StatusCode, Value), TestError> {
    let (status, _type, bytes) = read(fx, path, token).await?;
    Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
}


fn audit(fx: &Fixture) -> Result<Vec<Value>, TestError> {
    Ok(std::fs::read_to_string(&fx.audit_path)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<Value>, _>>()?
        .into_iter()
        .filter(|record| record.get("action").and_then(Value::as_str) == Some("attack_paths.report.read"))
        .collect())
}


fn stored_body(fx: &Fixture, id: i64) -> Result<String, TestError> {
    Ok(lock(&fx.db.rows).iter().find(|stored| stored.id == id).ok_or("no such row")?.body.clone())
}


fn item(id: i64, marker: &str, truncated: bool) -> Result<Value, TestError> {
    let body = render_body(&build_body(graph_digest(&graph(marker))?, &found(marker, truncated)))?;
    Ok(json!({
        "id": id,
        "graph_digest": graph_digest(&graph(marker))?,
        "generated": GENERATED,
        "digest": digest_hex(&body),
        "bytes": body.len(),
        "truncated": truncated,
        "budget_reached": truncated,
        "unsearched_count": found(marker, truncated).unsearched.len(),
        "stored_at": STORED_BASE + id,
    }))
}


fn identity(tenant: &str) -> ApiIdentity {
    ApiIdentity {
        module: "attack-paths".to_owned(),
        tenant: tenant.to_owned(),
        generation: 0,
    }
}


fn calls_of(fx: &Fixture) -> Vec<String> {
    lock(&fx.calls).clone()
}


#[tokio::test]
async fn the_list_is_newest_first_with_exact_metadata_and_no_body() -> TestResult {
    let (fx, token) = seeded().await?;
    let (status, answer) = read_json(&fx, LIST_PATH, Some(&token)).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        answer,
        json!({ "items": [
            item(ID_GAMMA, "gamma", false)?,
            item(ID_BETA, "beta", true)?,
            item(1, "alpha", false)?,
        ] })
    );
    assert!(!answer.to_string().contains(GLOBEX_MARKER));
    assert!(!answer.to_string().contains("entry-alpha") && !answer.to_string().contains("\"paths\""));
    assert_eq!(calls_of(&fx), vec![format!("list {TENANT} {DEFAULT_LIMIT}")]);
    Ok(())
}


#[tokio::test]
async fn the_limit_narrows_the_list() -> TestResult {
    let (fx, token) = seeded().await?;
    let (_status, only) = read_json(&fx, "/attack-paths/reports?limit=1", Some(&token)).await?;
    assert_eq!(only, json!({ "items": [item(ID_GAMMA, "gamma", false)?] }));
    let (status, max) = read_json(&fx, &format!("/attack-paths/reports?limit={MAX_LIST_LIMIT}"), Some(&token)).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(max.get("items").and_then(Value::as_array).map(Vec::len), Some(ITEMS_TOTAL));
    Ok(())
}


#[tokio::test]
async fn a_bad_limit_is_a_400_before_any_store_call() -> TestResult {
    let (fx, token) = seeded().await?;
    for limit in BAD_LIMITS {
        let (status, answer) = read_json(&fx, &format!("/attack-paths/reports?limit={limit}"), Some(&token)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{limit}");
        assert_eq!(answer.pointer("/error/code").and_then(Value::as_str), Some("bad_request"));
    }
    assert!(calls_of(&fx).is_empty());
    Ok(())
}


#[tokio::test]
async fn an_extra_or_repeated_query_key_is_a_400() -> TestResult {
    let (fx, token) = seeded().await?;
    for query in ["x=1", "limit=1&limit=2", "framework=nis2", "limit=1&extra=1", "tenant=globex"] {
        let (status, _answer) = read_json(&fx, &format!("/attack-paths/reports?{query}"), Some(&token)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
    let (status, _answer) = read_json(&fx, "/attack-paths/reports/1?x=1", Some(&token)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(calls_of(&fx).is_empty());
    Ok(())
}


#[tokio::test]
async fn the_tenant_never_comes_from_the_request() -> TestResult {
    let (fx, token) = seeded().await?;
    let (query_status, _query_answer) = read_json(&fx, &format!("/attack-paths/reports?tenant={OTHER_TENANT}"), Some(&token)).await?;
    assert_eq!(query_status, StatusCode::BAD_REQUEST);
    let (_listed_status, listed) = read_json(&fx, LIST_PATH, Some(&token)).await?;
    assert!(!listed.to_string().contains(GLOBEX_MARKER));
    let (tenant_status, _tenant_type, tenant_bytes) =
        read(&fx, &format!("/attack-paths/reports/{FOURTH_ID}?tenant={OTHER_TENANT}"), Some(&token)).await?;
    assert_eq!(tenant_status, StatusCode::BAD_REQUEST);
    assert!(!String::from_utf8_lossy(&tenant_bytes).contains(GLOBEX_MARKER));
    let (foreign_status, _foreign_type, foreign_bytes) = read(&fx, &format!("/attack-paths/reports/{FOURTH_ID}"), Some(&token)).await?;
    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    assert!(!String::from_utf8_lossy(&foreign_bytes).contains(GLOBEX_MARKER));
    assert!(calls_of(&fx).iter().all(|call| call.contains(&format!(" {TENANT} "))));
    Ok(())
}


#[tokio::test]
async fn a_report_is_returned_byte_for_byte_as_stored() -> TestResult {
    let (fx, token) = seeded().await?;
    let (status, content_type, bytes) = read(&fx, "/attack-paths/reports/2", Some(&token)).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    assert_eq!(String::from_utf8(bytes)?, stored_body(&fx, ID_BETA)?);
    assert_eq!(
        stored_body(&fx, ID_BETA)?,
        render_body(&build_body(graph_digest(&graph("beta"))?, &found("beta", true)))?
    );
    Ok(())
}


#[tokio::test]
async fn another_tenants_id_is_byte_identical_to_an_unknown_or_malformed_id() -> TestResult {
    let (fx, token) = seeded().await?;
    let (foreign_status, foreign_type, foreign) = read(&fx, &format!("/attack-paths/reports/{FOURTH_ID}"), Some(&token)).await?;
    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    assert_eq!(
        String::from_utf8(foreign.clone())?,
        json!({ "error": { "code": "not_found", "message": "no such report" } }).to_string()
    );
    for id in [UNKNOWN_ID, "abc", "-1", "99999999999999999999", "%ff%fe", "0x1", "1%2F2", "%00"] {
        let (status, content_type, bytes) = read(&fx, &format!("/attack-paths/reports/{id}"), Some(&token)).await?;
        assert_eq!(status, foreign_status, "{id}");
        assert_eq!(content_type, foreign_type, "{id}");
        assert_eq!(bytes, foreign, "{id}");
    }
    assert!(!calls_of(&fx).iter().any(|call| call.ends_with(" -1")));
    Ok(())
}


#[tokio::test]
async fn a_tampered_body_is_a_fixed_500_that_names_its_class_and_never_returns_the_body() -> TestResult {
    let (fx, token) = seeded().await?;
    lock(&fx.db.rows)
        .iter_mut()
        .filter(|stored| stored.id == ID_BETA)
        .for_each(|stored| stored.body = stored.body.replace("entry-beta", "TAMPERED-BODY"));
    let (dispatch, sink) = capture();
    let guard = tracing::dispatcher::set_default(&dispatch);
    let (status, _type, bytes) = read(&fx, "/attack-paths/reports/2", Some(&token)).await?;
    drop(guard);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let text = String::from_utf8(bytes)?;
    assert!(!text.contains("TAMPERED-BODY"));
    assert_eq!(
        text,
        json!({ "error": { "code": "internal_error", "message": "the request could not be processed" } }).to_string()
    );
    let logged = String::from_utf8(lock(&sink).clone())?;
    assert!(logged.contains(DIGEST_MISMATCH_CLASS), "{logged}");
    assert!(!logged.contains("TAMPERED-BODY"));
    let records = audit(&fx)?;
    assert_eq!(
        records.last().and_then(|record| record.get("outcome")).and_then(Value::as_str),
        Some("failure")
    );
    Ok(())
}


#[tokio::test]
async fn tampered_columns_are_a_fixed_500_that_names_their_class_and_never_return_the_body() -> TestResult {
    let (fx, token) = seeded().await?;
    lock(&fx.db.rows)
        .iter_mut()
        .filter(|stored| stored.id == 1)
        .for_each(|stored| stored.truncated = "true".to_owned());
    lock(&fx.db.rows)
        .iter_mut()
        .filter(|stored| stored.id == ID_BETA)
        .for_each(|stored| stored.unsearched = "0".to_owned());
    let (dispatch, sink) = capture();
    let guard = tracing::dispatcher::set_default(&dispatch);
    let first = read(&fx, "/attack-paths/reports/1", Some(&token)).await?;
    let second = read(&fx, "/attack-paths/reports/2", Some(&token)).await?;
    drop(guard);
    for (status, _type, bytes) in [first, second] {
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!String::from_utf8(bytes)?.contains("entry-"));
    }
    let logged = String::from_utf8(lock(&sink).clone())?;
    assert!(logged.contains(COLUMNS_MISMATCH_CLASS), "{logged}");
    assert!(!logged.contains(DIGEST_MISMATCH_CLASS) && !logged.contains("entry-"));
    assert_eq!(COLUMNS_MISMATCH_CLASS, "report_columns_mismatch");
    Ok(())
}


#[tokio::test]
async fn the_class_is_logged_by_the_store_failure_mapping() -> TestResult {
    let (dispatch, sink) = capture();
    let mapped = tracing::dispatcher::with_default(&dispatch, || store_failure(&StoreError::DigestMismatch));
    assert_eq!(mapped, ApiError::Internal);
    assert!(String::from_utf8(lock(&sink).clone())?.contains("report_digest_mismatch"));
    assert_eq!(DIGEST_MISMATCH_CLASS, "report_digest_mismatch");
    assert_eq!(store_failure(&StoreError::MetadataMismatch), ApiError::Internal);
    assert_eq!(store_failure(&StoreError::BadBody), ApiError::Internal);
    assert_eq!(store_failure(&StoreError::Busy), ApiError::TooManyRequests);
    assert_eq!(store_failure(&StoreError::Store(malformed())), ApiError::Internal);
    assert_eq!(store_failure(&StoreError::BadRow), ApiError::Internal);
    Ok(())
}


#[tokio::test]
async fn no_token_is_a_401_and_a_reader_without_the_permission_is_a_403() -> TestResult {
    let (fx, _token) = seeded().await?;
    for path in [LIST_PATH, "/attack-paths/reports/1"] {
        let (open_status, _open_answer) = read_json(&fx, path, None).await?;
        assert_eq!(open_status, StatusCode::UNAUTHORIZED, "{path}");
        for role in [READER, RESPONDER] {
            let token = login(&fx.router, role).await?;
            let (denied_status, _denied_answer) = read_json(&fx, path, Some(&token)).await?;
            assert_eq!(denied_status, StatusCode::FORBIDDEN, "{role} {path}");
        }
        for role in [ANALYST, AUDITOR] {
            let token = login(&fx.router, role).await?;
            let (allowed_status, _allowed_answer) = read_json(&fx, path, Some(&token)).await?;
            assert_eq!(allowed_status, StatusCode::OK, "{role} {path}");
        }
    }
    assert_eq!(calls_of(&fx).len(), PERMITTED_CALLS);
    let catalog = builtin_catalog();
    let administrators: RoleSet = [ADMINISTRATOR.to_owned()].into();
    assert!(is_allowed(&catalog, &administrators, PERMISSION_ATTACK_PATHS_READ));
    Ok(())
}


#[tokio::test]
async fn every_read_is_audited_with_the_actor_and_the_target_and_no_body() -> TestResult {
    let (fx, token) = seeded().await?;
    read(&fx, "/attack-paths/reports/2", Some(&token)).await?;
    read(&fx, LIST_PATH, Some(&token)).await?;
    read(&fx, &format!("/attack-paths/reports/{UNKNOWN_ID}"), Some(&token)).await?;
    read(&fx, "/attack-paths/reports/%ff%fe", Some(&token)).await?;
    let records = audit(&fx)?;
    let summary: Vec<(String, String, String, String)> = records
        .iter()
        .map(|record| {
            let text = |pointer: &str| {
                record
                    .pointer(pointer)
                    .map_or_else(|| "?".to_owned(), |value| value.as_str().unwrap_or("?").to_owned())
            };
            (text("/target"), text("/outcome"), text("/actor_id"), text("/parameters/status"))
        })
        .collect();
    let analyst = ANALYST.to_owned();
    assert_eq!(
        summary,
        vec![
            ("2".to_owned(), "success".to_owned(), analyst.clone(), "200".to_owned()),
            ("list".to_owned(), "success".to_owned(), analyst.clone(), "200".to_owned()),
            (UNKNOWN_ID.to_owned(), "failure".to_owned(), analyst.clone(), "404".to_owned()),
            ("invalid".to_owned(), "failure".to_owned(), analyst, "404".to_owned()),
        ]
    );
    let raw = std::fs::read_to_string(&fx.audit_path)?;
    assert!(!raw.contains("entry-beta") && !raw.contains("choke_points"));
    Ok(())
}


#[tokio::test]
async fn a_failing_audit_log_drops_the_body_and_answers_500() -> TestResult {
    let (fx, token) = seeded().await?;
    fx.state.audit.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).poisoned = true;
    let (status, _type, bytes) = read(&fx, "/attack-paths/reports/2", Some(&token)).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!String::from_utf8_lossy(&bytes).contains("entry-beta"));
    Ok(())
}


#[tokio::test]
async fn a_client_that_leaves_mid_read_still_gets_its_audit_record() -> TestResult {
    let gate_owner = Arc::new(Semaphore::new(0));
    let arrived_owner = Arc::new(Notify::new());
    let alive_owner = Arc::new(());
    let gated = {
        let gate = Arc::clone(&gate_owner);
        let arrived = Arc::clone(&arrived_owner);
        let alive = Arc::clone(&alive_owner);
        move |db: &Arc<memory::Db>, calls: &Calls| -> AttackPathsBackend {
            let inner = memory_backend(db, calls);
            let real = Arc::clone(&inner.get);
            AttackPathsBackend {
                list: inner.list,
                get: Arc::new(move |scope, id| {
                    let call_gate = Arc::clone(&gate);
                    let call_arrived = Arc::clone(&arrived);
                    let marker = Arc::clone(&alive);
                    let next = real(scope, id);
                    Box::pin(async move {
                        call_arrived.notify_one();
                        let permit = call_gate.acquire().await;
                        drop(permit);
                        let answer = next.await;
                        drop(marker);
                        answer
                    })
                }),
            }
        }
    };
    let fx = fixture_over(Arc::default(), gated)?;
    seed(&fx.db, TENANT, "alpha", false).await?;
    let token = login(&fx.router, ANALYST).await?;
    let baseline = Arc::strong_count(&alive_owner);
    let router = fx.router.clone();
    let reader = tokio::spawn(async move { get(&router, "/attack-paths/reports/1", Some(&token)).await.is_ok() });
    arrived_owner.notified().await;
    assert!(Arc::strong_count(&alive_owner) > baseline);
    reader.abort();
    assert!(reader.await.err().is_some_and(|error| error.is_cancelled()));
    assert!(audit(&fx)?.is_empty());
    gate_owner.add_permits(1);
    let mut spins = 0;
    while Arc::strong_count(&alive_owner) > baseline && spins < SPIN_CAP {
        tokio::task::yield_now().await;
        spins += 1;
    }
    let records = audit(&fx)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records.first().and_then(|record| record.get("target")).and_then(Value::as_str), Some("1"));
    assert_eq!(
        records.first().and_then(|record| record.get("outcome")).and_then(Value::as_str),
        Some("success")
    );
    Ok(())
}


#[tokio::test]
async fn a_panicking_read_is_a_fixed_500() -> TestResult {
    let panicking = |db: &Arc<memory::Db>, calls: &Calls| -> AttackPathsBackend {
        AttackPathsBackend {
            list: Arc::new(|_scope, _limit| {
                Box::pin(async {
                    let zero = std::hint::black_box(usize::MIN);
                    Ok(Vec::with_capacity(1 / zero))
                })
            }),
            get: memory_backend(db, calls).get,
        }
    };
    let fx = fixture_over(Arc::default(), panicking)?;
    let token = login(&fx.router, ANALYST).await?;
    let (status, answer) = read_json(&fx, LIST_PATH, Some(&token)).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(answer.pointer("/error/code").and_then(Value::as_str), Some("internal_error"));
    Ok(())
}


#[tokio::test]
async fn store_errors_and_a_full_pool_are_fixed_answers() -> TestResult {
    let failing = |_db: &Arc<memory::Db>, _calls: &Calls| -> AttackPathsBackend {
        AttackPathsBackend {
            list: Arc::new(|_scope, _limit| Box::pin(async { Err(StoreError::Busy) })),
            get: Arc::new(|_scope, _id| Box::pin(async { Err(StoreError::Store(malformed())) })),
        }
    };
    let fx = fixture_over(Arc::default(), failing)?;
    let token = login(&fx.router, ANALYST).await?;
    let (status, answer) = read_json(&fx, LIST_PATH, Some(&token)).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(answer.pointer("/error/code").and_then(Value::as_str), Some("too_many_requests"));
    let (refused_status, refused) = read_json(&fx, "/attack-paths/reports/1", Some(&token)).await?;
    assert_eq!(refused_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!refused.to_string().contains("22P02"));
    Ok(())
}


#[tokio::test]
async fn a_handler_reached_without_a_session_audits_an_unknown_actor_and_an_unusable_tenant_is_refused() -> TestResult {
    let (fx, _token) = seeded().await?;
    let backend = memory_backend(&fx.db, &fx.calls);
    let answered = get_endpoint(
        State(fx.state.clone()),
        Extension(Arc::new(identity(TENANT))),
        Extension(RequestId("direct".to_owned())),
        Extension(backend.clone()),
        None,
        Ok(Path("1".to_owned())),
        Ok(Query(NoQuery {})),
    )
    .await;
    assert_eq!(answered.status(), StatusCode::OK);
    let records = audit(&fx)?;
    assert_eq!(
        records.last().and_then(|record| record.pointer("/actor_id")).and_then(Value::as_str),
        Some("unknown")
    );
    let refused = get_endpoint(
        State(fx.state.clone()),
        Extension(Arc::new(identity("-x"))),
        Extension(RequestId("direct".to_owned())),
        Extension(backend),
        None,
        Ok(Path("1".to_owned())),
        Ok(Query(NoQuery {})),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(scope_of(&identity("-x")).err(), Some(ApiError::Internal));
    Ok(())
}


#[test]
fn the_parsers_follow_their_grammars() -> TestResult {
    assert_eq!(parse_limit(None), Ok(DEFAULT_LIMIT));
    assert_eq!(parse_limit(Some("1")), Ok(1));
    assert_eq!(parse_limit(Some("100")), Ok(MAX_LIST_LIMIT));
    assert_eq!(parse_limit(Some("101")), Err(ApiError::BadRequest));
    assert_eq!(parse_limit(Some("99999999999999999999999")), Err(ApiError::BadRequest));
    assert_eq!(parse_id(Ok("12".to_owned())), Some(PARSED_ID));
    assert_eq!(parse_id(Ok("1a".to_owned())), None);
    assert_eq!(parse_id(Ok(String::new())), None);
    Ok(())
}


#[test]
fn the_access_table_and_the_document_name_both_routes() -> TestResult {
    let table = attack_paths_access();
    assert_eq!(table.len(), ROUTE_COUNT);
    assert!(table.contains_key(&format!("GET {LIST_PATH}")) && table.contains_key(&format!("GET {GET_PATH}")));
    let document = serde_json::to_value(attack_paths_document())?;
    assert!(document.pointer("/paths/~1attack-paths~1reports/get").is_some());
    assert!(document.pointer("/paths/~1attack-paths~1reports~1{id}/get").is_some());
    let cells = ["7", "g", "2026-11-23T10:00:00Z", "d", "10", "true", "false", "3", "5"]
        .map(str::to_owned)
        .to_vec();
    let meta = decode_meta(&cells)?;
    let viewed = item_of(&meta);
    assert_eq!((viewed.id, viewed.bytes, viewed.stored_at), (META_ID, META_BYTES, META_STORED));
    assert_eq!(
        (viewed.truncated, viewed.budget_reached, viewed.unsearched_count),
        (true, false, META_UNSEARCHED)
    );
    assert_eq!(meta, ReportMeta { ..meta.clone() });
    Ok(())
}
