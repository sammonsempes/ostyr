use crate::fixture::{config_in, seed_reader, Fixture};
use crate::http::{audit_lines, client, login_body, send_from};
use crate::logging::capture_dispatch;
use crate::types::{TestError, TestResult};
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode};
use axum::routing::post;
use axum::{Extension, Router};
use core_api::example::example_document;
use core_api::middleware::{detaches, note_sender_refused, sender_digest, sender_media_ok};
use core_api::model::{AdmittedSender, ApiIdentity, ApiState, Requirement, Rule};
use core_api::routes::{build_router, BODY_LIMIT_BYTES};
use core_api::state::{build_state_from_files, detached_pool, replace_senders, MAX_TRACE_DECODES, MAX_TRACE_DECODES_PER_SENDER};
use core_api::types::{AccessTable, SenderTable, SharedState};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::fs::{self, File};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tower::ServiceExt;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const HANG_GUARD: Duration = Duration::from_secs(120);


const BLOCKING_GUARD: Duration = Duration::from_secs(20);


const ROUTE_INGEST: &str = "/ingest/v1";


const SENDER_BODY_CEILING: usize = 32_768;


const MEDIUM_BODY: usize = 20_000;


const LARGE_CEILING: usize = 4_194_304;


const LARGE_BODY: usize = 3_000_000;


const CHUNK_BYTES: usize = 1024;


const CHUNKS: usize = 4;


const SMALL_POOL: u16 = 2;


const OTHER_SOURCE: u8 = 2;


const TOKEN_REPEATS: usize = 4;


const TOKEN_LENGTH: usize = 64;


const REFUSALS: u64 = 3;


const WARNINGS_LOGGED: usize = 2;


const WARNING: &str = "sender requests refused";


const PROTOBUF: &str = "application/x-protobuf";


const SENDER_ALPHA: &str = "alpha";


const SENDER_BETA: &str = "beta";


fn token_alpha() -> String {
    "0123456789abcdef".repeat(TOKEN_REPEATS)
}


fn token_beta() -> String {
    "fedcba9876543210".repeat(TOKEN_REPEATS)
}


fn digest_of(token: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}


#[derive(Clone)]
struct Probe {
    gate: Arc<Semaphore>,
    started: Arc<Semaphore>,
    handled: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
}


fn probe() -> Probe {
    Probe {
        gate: Arc::new(Semaphore::new(0)),
        started: Arc::new(Semaphore::new(0)),
        handled: Arc::new(AtomicUsize::new(0)),
        reads: Arc::new(AtomicUsize::new(0)),
    }
}


async fn ingest(probe: Probe, sender: AdmittedSender, identity: Arc<ApiIdentity>, body: Bytes) -> Result<String, StatusCode> {
    probe.handled.fetch_add(1, Ordering::SeqCst);
    let permit = sender.permit.clone();
    let (gate, started) = (probe.gate.clone(), probe.started.clone());
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _held = permit;
        started.add_permits(1);
        if let Ok(Ok(acquired)) = runtime.block_on(tokio::time::timeout(BLOCKING_GUARD, gate.acquire())) {
            acquired.forget();
        }
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(format!("{}:{}:{}", sender.name, identity.tenant, body.len()))
}


fn access_with(ceiling: usize) -> AccessTable {
    [(
        format!("POST {ROUTE_INGEST}"),
        Rule {
            requirement: Requirement::Sender(ceiling),
            sensitive: false,
        },
    )]
    .into_iter()
    .collect()
}


fn access() -> AccessTable {
    access_with(SENDER_BODY_CEILING)
}


fn extra(probe: &Probe) -> Router<SharedState> {
    let held = probe.clone();
    Router::new().route(
        ROUTE_INGEST,
        post(
            move |Extension(sender): Extension<AdmittedSender>, Extension(identity): Extension<Arc<ApiIdentity>>, body: Bytes| {
                ingest(held.clone(), sender, identity, body)
            },
        ),
    )
}


fn table() -> SenderTable {
    [
        (digest_of(&token_alpha()), SENDER_ALPHA.to_owned()),
        (digest_of(&token_beta()), SENDER_BETA.to_owned()),
    ]
    .into_iter()
    .collect()
}


fn fixture_over(probe: &Probe, adjust: impl FnOnce(ApiState) -> ApiState) -> Result<Fixture, TestError> {
    fixture_with(probe, access(), adjust)
}


fn fixture_with(probe: &Probe, rules: AccessTable, adjust: impl FnOnce(ApiState) -> ApiState) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_reader(&config)?;
    let built = build_state_from_files(&config, rules, vec![example_document()])?;
    replace_senders(&built, table());
    let state: SharedState = Arc::new(adjust(built));
    let router = build_router(state.clone(), extra(probe));
    Ok(Fixture { dir, state, router, config })
}


fn ingest_request(token: Option<&str>, body: Body) -> Result<Request<Body>, TestError> {
    let mut builder = Request::builder().method("POST").uri(ROUTE_INGEST).header("content-type", PROTOBUF);
    if let Some(value) = token {
        builder = builder.header("authorization", format!("Bearer {value}"));
    }
    Ok(builder.body(body)?)
}


fn counted_body(reads: &Arc<AtomicUsize>) -> Body {
    let counter = reads.clone();
    Body::from_stream(tokio_stream::iter(0..CHUNKS).map(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok::<Bytes, Infallible>(Bytes::from(vec![u8::MIN; CHUNK_BYTES]))
    }))
}


async fn guarded<Output>(work: impl Future<Output = Output>) -> Result<Output, TestError> {
    tokio::time::timeout(HANG_GUARD, work)
        .await
        .map_err(|_| "hang guard: the test did not finish".into())
}


fn start(fx: &Fixture, source: u8, request: Request<Body>) -> JoinHandle<Result<Response<Body>, Infallible>> {
    let router = fx.router.clone();
    let mut sent = request;
    sent.extensions_mut().insert(ConnectInfo(client(source)));
    tokio::spawn(async move { router.oneshot(sent).await })
}


async fn finish(handle: JoinHandle<Result<Response<Body>, Infallible>>) -> Result<Response<Body>, TestError> {
    let outcome = guarded(handle).await??;
    Ok(outcome?)
}


async fn send_ingest(fx: &Fixture, source: u8, request: Request<Body>) -> Result<Response<Body>, TestError> {
    send_from(&fx.router, client(source), request).await
}


async fn text(response: Response<Body>) -> Result<String, TestError> {
    let bytes = axum::body::to_bytes(response.into_body(), SENDER_BODY_CEILING).await?;
    Ok(String::from_utf8(bytes.to_vec())?)
}


async fn pool_free(fx: &Fixture) -> TestResult {
    let all = guarded(fx.state.sender_pool.permits.clone().acquire_many_owned(fx.state.sender_pool.size)).await??;
    drop(all);
    Ok(())
}


fn slots_held(fx: &Fixture) -> usize {
    fx.state.sender_slots.lock().map(|table| table.values().sum()).unwrap_or(usize::MAX)
}


fn assert_untouched(fx: &Fixture, probe: &Probe) {
    assert_eq!(probe.handled.load(Ordering::SeqCst), 0);
    assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fx.state.sender_pool.permits.available_permits(), usize::from(MAX_TRACE_DECODES));
    assert_eq!(slots_held(fx), 0);
}


async fn open_and_wait(probe: &Probe, fx: &Fixture, handles: Vec<JoinHandle<Result<Response<Body>, Infallible>>>) -> Result<Vec<String>, TestError> {
    probe.gate.add_permits(handles.len());
    let mut bodies = Vec::new();
    for handle in handles {
        bodies.push(text(finish(handle).await?).await?);
    }
    pool_free(fx).await?;
    Ok(bodies)
}


fn record_text(fx: &Fixture) -> Result<String, TestError> {
    Ok(fs::read_to_string(&fx.config.audit_log)?)
}


#[tokio::test]
async fn a_valid_token_is_served_under_the_identity_tenant() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| state)?;
    probe.gate.add_permits(1);
    let reads = Arc::new(AtomicUsize::new(0));
    let response = send_ingest(&fx, 1, ingest_request(Some(&token_alpha()), counted_body(&reads))?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let tenant = fx.state.identity.load().tenant.clone();
    assert_eq!(text(response).await?, format!("{SENDER_ALPHA}:{tenant}:{}", CHUNKS * CHUNK_BYTES));
    assert_eq!(reads.load(Ordering::SeqCst), CHUNKS);
    pool_free(&fx).await?;
    assert_eq!(slots_held(&fx), 0);
    let records = audit_lines(&fx)?;
    let actors: Vec<&str> = records
        .iter()
        .filter_map(|line| line.get("actor_id").and_then(serde_json::Value::as_str))
        .collect();
    assert_eq!(actors, vec![format!("sender:{SENDER_ALPHA}")]);
    Ok(())
}


fn bad_authorizations() -> Vec<Vec<(&'static str, String)>> {
    let good = format!("Bearer {}", token_alpha());
    vec![
        vec![],
        vec![("authorization", good.clone()), ("authorization", good.clone())],
        vec![("authorization", format!("Basic {}", token_alpha()))],
        vec![("authorization", format!("bearer {}", token_alpha()))],
        vec![("authorization", format!("Bearer {}", "0123456789abcdef".repeat(TOKEN_REPEATS - 1)))],
        vec![("authorization", format!("Bearer {}0", token_alpha()))],
        vec![("authorization", format!("Bearer {}", token_alpha().to_uppercase()))],
        vec![("authorization", format!("Bearer {}", "g".repeat(TOKEN_LENGTH)))],
        vec![("authorization", format!("Bearer  {}", token_alpha()))],
        vec![("authorization", format!("Bearer {}", "a".repeat(TOKEN_LENGTH)))],
        vec![("authorization", format!("Bearer {}", token_alpha().replace('0', "1")))],
    ]
}


#[tokio::test]
async fn every_bad_token_is_refused_before_the_body_and_any_slot() -> TestResult {
    for headers in bad_authorizations() {
        let probe = probe();
        let fx = fixture_over(&probe, |state| state)?;
        let mut builder = Request::builder().method("POST").uri(ROUTE_INGEST).header("content-type", PROTOBUF);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = send_ingest(&fx, 1, builder.body(counted_body(&probe.reads))?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_untouched(&fx, &probe);
        assert_eq!(fx.state.sender_refused.load(Ordering::SeqCst), 1);
    }
    Ok(())
}


#[tokio::test]
async fn a_media_type_other_than_protobuf_is_415_before_the_body() -> TestResult {
    let variants: Vec<Vec<(&str, &str)>> = vec![
        vec![("content-type", "application/json")],
        vec![("content-type", "application/x-protobuf; charset=utf-8")],
        vec![("content-type", PROTOBUF), ("content-encoding", "gzip")],
        vec![
            ("content-type", PROTOBUF),
            ("content-encoding", "identity"),
            ("content-encoding", "identity"),
        ],
        vec![("content-type", PROTOBUF), ("content-type", PROTOBUF)],
        vec![],
    ];
    for headers in variants {
        let probe = probe();
        let fx = fixture_over(&probe, |state| state)?;
        let mut builder = Request::builder()
            .method("POST")
            .uri(ROUTE_INGEST)
            .header("authorization", format!("Bearer {}", token_alpha()));
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = send_ingest(&fx, 1, builder.body(counted_body(&probe.reads))?).await?;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_untouched(&fx, &probe);
    }
    Ok(())
}


#[tokio::test]
async fn identity_encoding_is_accepted() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| state)?;
    probe.gate.add_permits(1);
    let request = Request::builder()
        .method("POST")
        .uri(ROUTE_INGEST)
        .header("authorization", format!("Bearer {}", token_alpha()))
        .header("content-type", PROTOBUF)
        .header("content-encoding", "identity")
        .body(Body::empty())?;
    assert_eq!(send_ingest(&fx, 1, request).await?.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn the_per_sender_cap_answers_429_before_the_body_and_another_sender_passes() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| state)?;
    let mut running = Vec::new();
    for _ in 0..MAX_TRACE_DECODES_PER_SENDER {
        running.push(start(&fx, 1, ingest_request(Some(&token_alpha()), Body::empty())?));
    }
    guarded(probe.started.acquire_many(u32::try_from(MAX_TRACE_DECODES_PER_SENDER)?))
        .await??
        .forget();
    assert_eq!(slots_held(&fx), MAX_TRACE_DECODES_PER_SENDER);
    let reads = Arc::new(AtomicUsize::new(0));
    let refused = send_ingest(&fx, OTHER_SOURCE, ingest_request(Some(&token_alpha()), counted_body(&reads))?).await?;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.headers().get("retry-after").and_then(|value| value.to_str().ok()), Some("1"));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(probe.handled.load(Ordering::SeqCst), MAX_TRACE_DECODES_PER_SENDER);
    assert_eq!(slots_held(&fx), MAX_TRACE_DECODES_PER_SENDER);
    running.push(start(&fx, OTHER_SOURCE, ingest_request(Some(&token_beta()), Body::empty())?));
    guarded(probe.started.acquire_many(1)).await??.forget();
    let bodies = open_and_wait(&probe, &fx, running).await?;
    assert_eq!(bodies.len(), MAX_TRACE_DECODES_PER_SENDER + 1);
    assert_eq!(slots_held(&fx), 0);
    let refusals: Vec<String> = audit_lines(&fx)?
        .iter()
        .filter(|line| line.get("outcome").and_then(serde_json::Value::as_str) == Some("failure"))
        .filter_map(|line| line.get("actor_id").and_then(serde_json::Value::as_str).map(str::to_owned))
        .collect();
    assert_eq!(refusals, vec![format!("sender:{SENDER_ALPHA}")]);
    Ok(())
}


#[tokio::test]
async fn the_global_cap_answers_429_before_the_body_and_frees_the_sender_slot() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| ApiState {
        sender_pool: detached_pool(SMALL_POOL),
        ..state
    })?;
    let mut running = vec![
        start(&fx, 1, ingest_request(Some(&token_alpha()), Body::empty())?),
        start(&fx, 1, ingest_request(Some(&token_beta()), Body::empty())?),
    ];
    guarded(probe.started.acquire_many(u32::from(SMALL_POOL))).await??.forget();
    let reads = Arc::new(AtomicUsize::new(0));
    let refused = send_ingest(&fx, OTHER_SOURCE, ingest_request(Some(&token_alpha()), counted_body(&reads))?).await?;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(slots_held(&fx), usize::from(SMALL_POOL));
    probe.gate.add_permits(running.len());
    for handle in running.drain(..) {
        assert_eq!(finish(handle).await?.status(), StatusCode::OK);
    }
    pool_free(&fx).await?;
    assert_eq!(slots_held(&fx), 0);
    Ok(())
}


#[tokio::test]
async fn a_full_pool_still_answers_401_and_415_not_429() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| ApiState {
        sender_pool: detached_pool(SMALL_POOL),
        ..state
    })?;
    let running = vec![
        start(&fx, 1, ingest_request(Some(&token_alpha()), Body::empty())?),
        start(&fx, 1, ingest_request(Some(&token_beta()), Body::empty())?),
    ];
    guarded(probe.started.acquire_many(u32::from(SMALL_POOL))).await??.forget();
    let unknown = "9".repeat(TOKEN_LENGTH);
    let bad = send_ingest(&fx, OTHER_SOURCE, ingest_request(Some(&unknown), counted_body(&probe.reads))?).await?;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    let json = Request::builder()
        .method("POST")
        .uri(ROUTE_INGEST)
        .header("authorization", format!("Bearer {}", token_alpha()))
        .header("content-type", "application/json")
        .body(counted_body(&probe.reads))?;
    assert_eq!(send_ingest(&fx, OTHER_SOURCE, json).await?.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
    assert_eq!(slots_held(&fx), usize::from(SMALL_POOL));
    open_and_wait(&probe, &fx, running).await?;
    Ok(())
}


#[tokio::test]
async fn a_client_that_leaves_keeps_the_slot_until_the_blocking_task_ends() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| state)?;
    let client_task = start(&fx, 1, ingest_request(Some(&token_alpha()), Body::empty())?);
    guarded(probe.started.acquire_many(1)).await??.forget();
    client_task.abort();
    assert!(guarded(client_task).await?.err().is_some_and(|error| error.is_cancelled()));
    assert_eq!(slots_held(&fx), 1);
    assert_eq!(fx.state.sender_pool.permits.available_permits(), usize::from(MAX_TRACE_DECODES) - 1);
    probe.gate.add_permits(1);
    pool_free(&fx).await?;
    assert_eq!(slots_held(&fx), 0);
    Ok(())
}


#[tokio::test]
async fn the_sender_body_ceiling_applies_to_its_route_only() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| state)?;
    probe.gate.add_permits(1);
    let medium = send_ingest(&fx, 1, ingest_request(Some(&token_alpha()), Body::from(vec![u8::MIN; MEDIUM_BODY]))?).await?;
    assert_eq!(medium.status(), StatusCode::OK);
    assert_eq!(
        text(medium).await?,
        format!("{SENDER_ALPHA}:{}:{MEDIUM_BODY}", fx.state.identity.load().tenant)
    );
    let over = send_ingest(
        &fx,
        1,
        ingest_request(Some(&token_alpha()), Body::from(vec![u8::MIN; SENDER_BODY_CEILING + 1]))?,
    )
    .await?;
    assert_eq!(over.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(probe.handled.load(Ordering::SeqCst), 1);
    let padding = "x".repeat(BODY_LIMIT_BYTES);
    let login = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(login_body("reader", &padding))?;
    assert_eq!(send_ingest(&fx, 1, login).await?.status(), StatusCode::PAYLOAD_TOO_LARGE);
    pool_free(&fx).await?;
    assert_eq!(slots_held(&fx), 0);
    Ok(())
}


#[tokio::test]
async fn a_ceiling_above_two_mebibytes_applies_and_refuses_with_the_fixed_json() -> TestResult {
    let probe = probe();
    let fx = fixture_with(&probe, access_with(LARGE_CEILING), |state| state)?;
    probe.gate.add_permits(1);
    let large = send_ingest(&fx, 1, ingest_request(Some(&token_alpha()), Body::from(vec![u8::MIN; LARGE_BODY]))?).await?;
    assert_eq!(large.status(), StatusCode::OK);
    assert_eq!(
        text(large).await?,
        format!("{SENDER_ALPHA}:{}:{LARGE_BODY}", fx.state.identity.load().tenant)
    );
    let over = send_ingest(
        &fx,
        1,
        ingest_request(Some(&token_alpha()), Body::from(vec![u8::MIN; LARGE_CEILING + 1]))?,
    )
    .await?;
    assert_eq!(over.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(text(over).await?.contains("\"payload_too_large\""));
    assert_eq!(probe.handled.load(Ordering::SeqCst), 1);
    pool_free(&fx).await?;
    assert_eq!(slots_held(&fx), 0);
    Ok(())
}


#[tokio::test]
async fn a_token_of_the_wrong_shape_is_refused_even_when_its_digest_is_known() -> TestResult {
    let short = token_alpha().get(1..).map(str::to_owned).ok_or("token too short")?;
    let upper = token_alpha().to_uppercase();
    for token in [short, upper] {
        let probe = probe();
        let fx = fixture_over(&probe, |state| state)?;
        let mut known = table();
        known.insert(digest_of(&token), SENDER_ALPHA.to_owned());
        replace_senders(&fx.state, known);
        let response = send_ingest(&fx, 1, ingest_request(Some(&token), counted_body(&probe.reads))?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_untouched(&fx, &probe);
    }
    Ok(())
}


#[tokio::test]
async fn a_streamed_body_over_the_ceiling_is_413() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| state)?;
    let chunks = SENDER_BODY_CEILING / CHUNK_BYTES + 1;
    let counter = probe.reads.clone();
    let body = Body::from_stream(tokio_stream::iter(0..chunks).map(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok::<Bytes, Infallible>(Bytes::from(vec![u8::MIN; CHUNK_BYTES]))
    }));
    let response = send_ingest(&fx, 1, ingest_request(Some(&token_alpha()), body)?).await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(probe.handled.load(Ordering::SeqCst), 0);
    pool_free(&fx).await?;
    assert_eq!(slots_held(&fx), 0);
    Ok(())
}


#[tokio::test]
async fn a_replaced_table_refuses_the_removed_sender_at_once() -> TestResult {
    let probe = probe();
    let fx = fixture_over(&probe, |state| state)?;
    let only_beta: SenderTable = table().into_iter().filter(|(_, name)| name == SENDER_BETA).collect();
    replace_senders(&fx.state, only_beta);
    let gone = send_ingest(&fx, 1, ingest_request(Some(&token_alpha()), Body::empty())?).await?;
    assert_eq!(gone.status(), StatusCode::UNAUTHORIZED);
    probe.gate.add_permits(1);
    let served = send_ingest(&fx, 1, ingest_request(Some(&token_beta()), Body::empty())?).await?;
    assert_eq!(served.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn neither_the_token_nor_its_digest_reaches_the_audit_or_the_log() -> TestResult {
    let log_dir = tempdir()?;
    let log_path = log_dir.path().join("platform.log");
    let dispatch = capture_dispatch(BoxMakeWriter::new(Mutex::new(File::create(&log_path)?)));
    let probe = probe();
    let fx = fixture_over(&probe, |state| ApiState { dispatch, ..state })?;
    let unknown = "9".repeat(TOKEN_LENGTH);
    assert_eq!(
        send_ingest(&fx, 1, ingest_request(Some(&unknown), Body::empty())?).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    probe.gate.add_permits(1);
    assert_eq!(
        send_ingest(&fx, 1, ingest_request(Some(&token_alpha()), Body::empty())?).await?.status(),
        StatusCode::OK
    );
    let (audit, log) = (record_text(&fx)?, fs::read_to_string(&log_path)?);
    for secret in [unknown.clone(), digest_of(&unknown), token_alpha(), digest_of(&token_alpha())] {
        assert!(!audit.contains(&secret));
        assert!(!log.contains(&secret));
    }
    assert!(audit.contains("anonymous"));
    Ok(())
}


#[test]
fn a_sender_route_is_never_detached() -> TestResult {
    let sender = Rule {
        requirement: Requirement::Sender(SENDER_BODY_CEILING),
        sensitive: false,
    };
    assert!(!detaches(Some(&sender)));
    Ok(())
}


#[test]
fn the_digest_and_media_helpers_follow_the_grammar() -> TestResult {
    let mut headers = axum::http::HeaderMap::new();
    assert_eq!(sender_digest(&headers), None);
    headers.insert("authorization", format!("Bearer {}", token_alpha()).parse()?);
    assert_eq!(sender_digest(&headers), Some(digest_of(&token_alpha())));
    assert!(!sender_media_ok(&headers));
    headers.insert("content-type", PROTOBUF.parse()?);
    assert!(sender_media_ok(&headers));
    Ok(())
}


#[test]
fn a_refusal_warns_at_powers_of_two_without_secrets() -> TestResult {
    let log_dir = tempdir()?;
    let log_path = log_dir.path().join("platform.log");
    let dispatch = capture_dispatch(BoxMakeWriter::new(Mutex::new(File::create(&log_path)?)));
    let probe = probe();
    let fx = fixture_over(&probe, |state| ApiState { dispatch, ..state })?;
    let counts: Vec<u64> = (0..REFUSALS).map(|_| note_sender_refused(&fx.state)).collect();
    assert_eq!(counts, (1..=REFUSALS).collect::<Vec<u64>>());
    assert_eq!(fs::read_to_string(&log_path)?.matches(WARNING).count(), WARNINGS_LOGGED);
    Ok(())
}
