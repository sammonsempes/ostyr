use crate::fixture::{config_in, keep, seed_reader, Fixture, PASSWORD, READER};
use crate::http::{audit_lines, body_json, client, login_body, login_token, request, send_from};
use crate::limits::with_limits;
use crate::types::{TestError, TestResult};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use core_api::example::example_document;
use core_api::middleware::{detaches, drain_detached, note_detached_refused};
use core_api::model::{ApiState, Requirement, Rule};
use core_api::routes::{build_router, BODY_LIMIT_BYTES};
use core_api::server::serve;
use core_api::state::{build_state_from_files, MAX_DETACHED_PER_SOURCE, MAX_DETACHED_WRITES};
use core_api::types::{AccessTable, ServerHandle, SharedState};
use core_audit::log::append_declared;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tower::ServiceExt;


const HANG_GUARD: Duration = Duration::from_secs(120);


const SHORT_WAIT: Duration = Duration::from_millis(50);


const YIELDS: usize = 200;


const OTHER_SOURCE: u8 = 2;


const IDLE_REFERENCES: usize = 2;


const QUEUED_REFERENCES: usize = 3;


const REFUSALS: u64 = 3;


const ROUTE_HOLD: &str = "/example/hold";


const ROUTE_HOLD_PERMISSION: &str = "/example/hold-permission";


const ROUTE_PANIC: &str = "/example/hold-panic";


const ROUTE_QUICK: &str = "/example/quick";


const WRITE_ACTION: &str = "test.write";


const REQUEST_ACTION: &str = "api.request";


#[derive(Clone)]
struct Holds {
    gate: Arc<Semaphore>,
    started: Arc<Semaphore>,
    effect: Arc<AtomicUsize>,
    token: Arc<()>,
}


fn holds() -> Holds {
    Holds {
        gate: Arc::new(Semaphore::new(0)),
        started: Arc::new(Semaphore::new(0)),
        effect: Arc::new(AtomicUsize::new(0)),
        token: Arc::new(()),
    }
}


async fn arrive_and_wait(holds: &Holds) {
    let _held = holds.token.clone();
    holds.started.add_permits(1);
    if let Ok(permit) = holds.gate.acquire().await {
        permit.forget();
    }
}


async fn hold(holds: Holds, state: SharedState) -> Result<&'static str, StatusCode> {
    arrive_and_wait(&holds).await;
    holds.effect.fetch_add(1, Ordering::SeqCst);
    append_declared(
        &state.audit,
        NewEntry {
            timestamp: OffsetDateTime::now_utc(),
            actor: Actor {
                kind: ActorKind::User,
                id: "handler".to_owned(),
            },
            tenant: "acme".to_owned(),
            module: "example".to_owned(),
            action: WRITE_ACTION.to_owned(),
            target: "hold".to_owned(),
            outcome: Outcome::Success,
            request_id: "handler".to_owned(),
            justification: None,
            parameters: Default::default(),
        },
        &[],
    )
    .map(|_| "held")
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}


async fn panicking(holds: Holds) -> String {
    arrive_and_wait(&holds).await;
    let zero = std::hint::black_box(u32::MIN);
    (1 / zero).to_string()
}


async fn quick() -> &'static str {
    "quick"
}


fn rule(requirement: Requirement) -> Rule {
    Rule {
        requirement,
        sensitive: false,
    }
}


fn extra(holds: &Holds) -> Router<SharedState> {
    let (write, permission, safe, panic) = (holds.clone(), holds.clone(), holds.clone(), holds.clone());
    Router::new()
        .route(
            ROUTE_HOLD,
            post(move |State(state): State<SharedState>| hold(write.clone(), state))
                .get(move |State(state): State<SharedState>| hold(safe.clone(), state)),
        )
        .route(
            ROUTE_HOLD_PERMISSION,
            post(move |State(state): State<SharedState>| hold(permission.clone(), state)),
        )
        .route(ROUTE_PANIC, post(move || panicking(panic.clone())))
        .route(ROUTE_QUICK, post(quick))
        .route("/example/nothing", get(quick))
}


fn access() -> AccessTable {
    [
        (format!("POST {ROUTE_HOLD}"), rule(Requirement::Session)),
        (format!("GET {ROUTE_HOLD}"), rule(Requirement::Session)),
        (
            format!("POST {ROUTE_HOLD_PERMISSION}"),
            rule(Requirement::Permission("events.read".to_owned())),
        ),
        (format!("POST {ROUTE_PANIC}"), rule(Requirement::Session)),
        (format!("POST {ROUTE_QUICK}"), rule(Requirement::Session)),
    ]
    .into_iter()
    .collect()
}


fn fixture_over(holds: &Holds, adjust: impl FnOnce(ApiState) -> Result<ApiState, TestError>) -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    seed_reader(&config)?;
    let built = build_state_from_files(&config, access(), vec![example_document()])?;
    let state: SharedState = Arc::new(adjust(built)?);
    let router = build_router(state.clone(), extra(holds));
    Ok(Fixture { dir, state, router, config })
}


fn start_client(
    fx: &Fixture,
    source: SocketAddr,
    method: &str,
    path: &str,
    token: &str,
) -> Result<JoinHandle<Result<Response<Body>, Infallible>>, TestError> {
    let router = fx.router.clone();
    let mut request = request(method, path, Some(token), Body::empty())?;
    request.extensions_mut().insert(ConnectInfo(source));
    Ok(tokio::spawn(async move { router.oneshot(request).await }))
}


async fn abandon(client: JoinHandle<Result<Response<Body>, Infallible>>) -> TestResult {
    client.abort();
    let outcome = client.await;
    assert!(outcome.err().is_some_and(|error| error.is_cancelled()));
    Ok(())
}


async fn arrived(holds: &Holds, count: u32) -> TestResult {
    holds.started.acquire_many(count).await?.forget();
    Ok(())
}


async fn drained(fx: &Fixture) {
    assert!(drain_detached(&fx.state, HANG_GUARD).await);
}


async fn guarded<Output>(work: impl Future<Output = Output>) -> Result<Output, TestError> {
    tokio::time::timeout(HANG_GUARD, work)
        .await
        .map_err(|_| "hang guard: the test did not finish".into())
}


async fn yield_often() {
    for _ in 0..YIELDS {
        tokio::task::yield_now().await;
    }
}


fn records(fx: &Fixture, action: &str, target: Option<&str>) -> Result<Vec<serde_json::Value>, TestError> {
    Ok(audit_lines(fx)?
        .into_iter()
        .filter(|line| line.get("action").and_then(serde_json::Value::as_str) == Some(action))
        .filter(|line| target.is_none_or(|wanted| line.get("target").and_then(serde_json::Value::as_str) == Some(wanted)))
        .collect())
}


fn field<'a>(record: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    record.get(name).and_then(serde_json::Value::as_str)
}


fn status_parameter(record: &serde_json::Value) -> Option<&str> {
    record
        .get("parameters")
        .and_then(|parameters| parameters.get("status"))
        .and_then(serde_json::Value::as_str)
}


#[tokio::test]
async fn a_write_survives_a_client_that_leaves() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    let token = login_token(&fx.router).await?;
    let idle = Arc::strong_count(&holds.token);
    let client = start_client(&fx, client(1), "POST", ROUTE_HOLD, &token)?;
    arrived(&holds, 1).await?;
    abandon(client).await?;
    assert!(Arc::strong_count(&holds.token) > idle);
    assert_eq!(holds.effect.load(Ordering::SeqCst), 0);
    holds.gate.add_permits(1);
    drained(&fx).await;
    assert_eq!(holds.effect.load(Ordering::SeqCst), 1);
    assert_eq!(Arc::strong_count(&holds.token), idle);
    assert_eq!(records(&fx, WRITE_ACTION, None)?.len(), 1);
    let exchange = records(&fx, REQUEST_ACTION, Some("POST /example/hold"))?;
    assert_eq!(exchange.len(), 1);
    assert_eq!(exchange.first().and_then(|record| field(record, "outcome")), Some("success"));
    assert_eq!(exchange.first().and_then(status_parameter), Some("200"));
    assert_eq!(fx.state.detached.available_permits(), usize::from(MAX_DETACHED_WRITES));
    assert!(fx.state.detached_sources.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_permission_write_survives_a_client_that_leaves() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    let token = login_token(&fx.router).await?;
    let client = start_client(&fx, client(1), "POST", ROUTE_HOLD_PERMISSION, &token)?;
    arrived(&holds, 1).await?;
    abandon(client).await?;
    holds.gate.add_permits(1);
    drained(&fx).await;
    assert_eq!(holds.effect.load(Ordering::SeqCst), 1);
    assert_eq!(records(&fx, REQUEST_ACTION, Some("POST /example/hold-permission"))?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_safe_request_that_is_dropped_is_not_continued() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    let token = login_token(&fx.router).await?;
    let idle = Arc::strong_count(&holds.token);
    let client = start_client(&fx, client(1), "GET", ROUTE_HOLD, &token)?;
    arrived(&holds, 1).await?;
    assert!(Arc::strong_count(&holds.token) > idle);
    abandon(client).await?;
    assert_eq!(Arc::strong_count(&holds.token), idle);
    holds.gate.add_permits(1);
    yield_often().await;
    assert_eq!(holds.effect.load(Ordering::SeqCst), 0);
    assert!(records(&fx, WRITE_ACTION, None)?.is_empty());
    assert_eq!(fx.state.detached.available_permits(), usize::from(MAX_DETACHED_WRITES));
    Ok(())
}


#[tokio::test]
async fn a_full_pool_answers_busy_with_one_record() -> TestResult {
    guarded(full_pool()).await?
}


async fn full_pool() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, |state| {
        Ok(ApiState {
            detached: Arc::new(Semaphore::new(1)),
            detached_size: 1,
            ..state
        })
    })?;
    let token = login_token(&fx.router).await?;
    let first = start_client(&fx, client(1), "POST", ROUTE_HOLD, &token)?;
    arrived(&holds, 1).await?;
    let refused = start_client(&fx, client(OTHER_SOURCE), "POST", ROUTE_HOLD, &token)?.await??;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(refused).await?;
    assert_eq!(body.get("error").and_then(|error| field(error, "code")), Some("busy"));
    assert_eq!(fx.state.detached_refused.load(Ordering::SeqCst), 1);
    let exchange = records(&fx, REQUEST_ACTION, Some("POST /example/hold"))?;
    assert_eq!(exchange.len(), 1);
    assert_eq!(exchange.first().and_then(|record| field(record, "outcome")), Some("failure"));
    assert_eq!(exchange.first().and_then(status_parameter), Some("503"));
    assert_eq!(holds.effect.load(Ordering::SeqCst), 0);
    holds.gate.add_permits(1);
    assert_eq!(first.await??.status(), StatusCode::OK);
    assert_eq!(holds.effect.load(Ordering::SeqCst), 1);
    assert_eq!(records(&fx, REQUEST_ACTION, Some("POST /example/hold"))?.len(), IDLE_REFERENCES);
    Ok(())
}


#[tokio::test]
async fn one_source_cannot_hold_more_than_its_share() -> TestResult {
    guarded(source_share()).await?
}


async fn source_share() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    let token = login_token(&fx.router).await?;
    let share = u32::try_from(MAX_DETACHED_PER_SOURCE)?;
    let held = (0..MAX_DETACHED_PER_SOURCE)
        .map(|_| start_client(&fx, client(1), "POST", ROUTE_HOLD, &token))
        .collect::<Result<Vec<_>, _>>()?;
    arrived(&holds, share).await?;
    let refused = start_client(&fx, client(1), "POST", ROUTE_HOLD, &token)?.await??;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    let other = start_client(&fx, client(OTHER_SOURCE), "POST", ROUTE_HOLD, &token)?;
    arrived(&holds, 1).await?;
    holds.gate.add_permits(MAX_DETACHED_PER_SOURCE + 1);
    for waiting in held.into_iter().chain([other]) {
        assert_eq!(waiting.await??.status(), StatusCode::OK);
    }
    assert_eq!(holds.effect.load(Ordering::SeqCst), MAX_DETACHED_PER_SOURCE + 1);
    assert_eq!(fx.state.detached_refused.load(Ordering::SeqCst), 1);
    let busy = records(&fx, REQUEST_ACTION, Some("POST /example/hold"))?
        .iter()
        .filter(|record| status_parameter(record) == Some("503"))
        .count();
    assert_eq!(busy, 1);
    Ok(())
}


#[tokio::test]
async fn a_handler_that_panics_after_the_client_left_is_audited_as_a_failure() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    let token = login_token(&fx.router).await?;
    let client = start_client(&fx, client(1), "POST", ROUTE_PANIC, &token)?;
    arrived(&holds, 1).await?;
    abandon(client).await?;
    holds.gate.add_permits(1);
    drained(&fx).await;
    let exchange = records(&fx, REQUEST_ACTION, Some("POST /example/hold-panic"))?;
    assert_eq!(exchange.len(), 1);
    assert_eq!(exchange.first().and_then(|record| field(record, "outcome")), Some("failure"));
    assert_eq!(exchange.first().and_then(status_parameter), Some("500"));
    assert_eq!(fx.state.detached.available_permits(), usize::from(MAX_DETACHED_WRITES));
    Ok(())
}


fn clock_that_fails_in_tasks() -> OffsetDateTime {
    let divisor = if tokio::task::try_id().is_some() {
        std::hint::black_box(u32::MIN)
    } else {
        1
    };
    OffsetDateTime::now_utc() + time::Duration::seconds(i64::from(1 / divisor))
}


#[tokio::test]
async fn a_detached_task_that_dies_after_the_handler_answers_500_and_frees_its_slots() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, |state| {
        Ok(ApiState {
            clock: clock_that_fails_in_tasks,
            ..state
        })
    })?;
    let token = login_token(&fx.router).await?;
    let answered = send_from(&fx.router, client(1), request("POST", ROUTE_QUICK, Some(&token), Body::empty())?).await?;
    assert_eq!(answered.status(), StatusCode::INTERNAL_SERVER_ERROR);
    drained(&fx).await;
    assert!(fx.state.detached_sources.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_login_dropped_while_queued_is_not_continued() -> TestResult {
    let holds = holds();
    let hashing = Arc::new(Semaphore::new(0));
    let lent = hashing.clone();
    let fx = fixture_over(&holds, move |state| Ok(ApiState { hashing: lent, ..state }))?;
    let mut request = request("POST", "/auth/login", None, login_body(READER, PASSWORD))?;
    request.extensions_mut().insert(ConnectInfo(client(1)));
    let router = fx.router.clone();
    let client = tokio::spawn(async move { router.oneshot(request).await });
    yield_often().await;
    assert_eq!(Arc::strong_count(&hashing), QUEUED_REFERENCES);
    abandon(client).await?;
    assert_eq!(Arc::strong_count(&hashing), IDLE_REFERENCES);
    hashing.add_permits(1);
    yield_often().await;
    assert!(records(&fx, "auth.login", None)?.is_empty());
    assert_eq!(fx.state.detached.available_permits(), usize::from(MAX_DETACHED_WRITES));
    Ok(())
}


#[test]
fn only_session_and_permission_writes_are_detached() -> TestResult {
    let session = rule(Requirement::Session);
    let permission = rule(Requirement::Permission("events.read".to_owned()));
    let public = rule(Requirement::Public);
    assert!(detaches(Some(&session), true));
    assert!(detaches(Some(&permission), true));
    assert!(!detaches(Some(&public), true));
    assert!(!detaches(None, true));
    assert!(!detaches(Some(&session), false));
    Ok(())
}


#[tokio::test]
async fn the_drain_waits_for_the_writes_and_gives_up_at_its_deadline() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    assert!(drain_detached(&fx.state, SHORT_WAIT).await);
    let held = fx.state.detached.clone().acquire_owned().await?;
    assert!(!drain_detached(&fx.state, SHORT_WAIT).await);
    drop(held);
    assert!(drain_detached(&fx.state, SHORT_WAIT).await);
    Ok(())
}


#[tokio::test]
async fn refusals_are_counted() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    (1..=REFUSALS).for_each(|expected| assert_eq!(note_detached_refused(&fx.state), expected));
    Ok(())
}


#[tokio::test]
async fn a_socket_closed_after_the_request_was_sent_leaves_the_write_and_its_records() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    let token = login_token(&fx.router).await?;
    let handle = ServerHandle::new();
    let (config, router, running) = (fx.config.clone(), fx.router.clone(), handle.clone());
    let server = tokio::spawn(async move { serve(&config, router, running).await });
    let address = handle.listening().await.ok_or("server did not start")?;
    let mut stream = TcpStream::connect(address).await?;
    let text = format!("POST {ROUTE_HOLD} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n");
    stream.write_all(text.as_bytes()).await?;
    arrived(&holds, 1).await?;
    drop(stream);
    holds.gate.add_permits(1);
    drained(&fx).await;
    assert_eq!(holds.effect.load(Ordering::SeqCst), 1);
    assert_eq!(records(&fx, WRITE_ACTION, None)?.len(), 1);
    assert_eq!(records(&fx, REQUEST_ACTION, Some("POST /example/hold"))?.len(), 1);
    handle.shutdown();
    assert!(server.await?.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_slow_body_never_takes_a_detached_slot() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, keep)?;
    let token = login_token(&fx.router).await?;
    let (sender, receiver) = mpsc::channel::<Result<Bytes, Infallible>>(1);
    let mut slow = request("POST", ROUTE_HOLD, Some(&token), Body::from_stream(ReceiverStream::new(receiver)))?;
    slow.extensions_mut().insert(ConnectInfo(client(1)));
    let router = fx.router.clone();
    let waiting = tokio::spawn(async move { router.oneshot(slow).await });
    yield_often().await;
    assert_eq!(fx.state.detached.available_permits(), usize::from(MAX_DETACHED_WRITES));
    assert!(fx.state.detached_sources.lock().map_err(|_| "poisoned")?.is_empty());
    assert_eq!(holds.started.available_permits(), 0);
    drop(sender);
    arrived(&holds, 1).await?;
    assert_eq!(fx.state.detached.available_permits(), usize::from(MAX_DETACHED_WRITES) - 1);
    holds.gate.add_permits(1);
    assert_eq!(guarded(waiting).await???.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn a_body_that_fails_is_refused_before_the_pool_with_one_record() -> TestResult {
    let holds = holds();
    let fx = fixture_over(&holds, |state| Ok(with_limits(state, |limits| limits.body_read_timeout = SHORT_WAIT)))?;
    let token = login_token(&fx.router).await?;
    let (sender, receiver) = mpsc::channel::<Result<Bytes, Infallible>>(1);
    let stalled = request("POST", ROUTE_HOLD, Some(&token), Body::from_stream(ReceiverStream::new(receiver)))?;
    assert_eq!(send_from(&fx.router, client(1), stalled).await?.status(), StatusCode::REQUEST_TIMEOUT);
    drop(sender);
    let oversized = request("POST", ROUTE_HOLD, Some(&token), Body::from(vec![u8::MIN; BODY_LIMIT_BYTES + 1]))?;
    assert_eq!(send_from(&fx.router, client(1), oversized).await?.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(holds.started.available_permits(), 0);
    assert_eq!(fx.state.detached.available_permits(), usize::from(MAX_DETACHED_WRITES));
    assert_eq!(records(&fx, REQUEST_ACTION, Some("POST /example/hold"))?.len(), IDLE_REFERENCES);
    Ok(())
}
