use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::net::TcpListener;


pub const ID_LENGTH: usize = 64;


pub const SUMMARY_COUNT: u32 = 3;


pub const TOKEN: &str = "tok-alice";


pub const LEAK: &str = "API-LEAK-TEXT";


pub const FIRST_CURSOR: &str = "abc_-=";


pub const OVERSIZE_BYTES: usize = 1_100_000;


pub const CHUNK_COUNT: usize = 5000;


pub const MANY_ITEMS: usize = 101;


pub const MANY_ENTRIES: usize = 70;


pub const MANY_EVENTS: usize = 60;


pub const LONG_TITLE_CHARS: usize = 300;


pub const HOSTILE: &str = "<script>alert(1)</script>\"'</td>&amp;";


#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Hostile,
    Oversize,
    Chunked,
    TooMany,
    BadSeverity,
    BadId,
    BadCursor,
    Status(StatusCode),
}


pub const LOCK_AFTER: u32 = 3;


pub struct StubState {
    pub forwarded: Mutex<Vec<Option<String>>>,
    pub failures: Mutex<BTreeMap<String, u32>>,
    pub logged_out: Mutex<Vec<String>>,
    pub mode: Mutex<Mode>,
    pub logouts: AtomicUsize,
    pub logins: AtomicUsize,
    pub details: AtomicUsize,
    pub last_query: Mutex<String>,
}


pub struct Stub {
    pub address: SocketAddr,
    pub state: Arc<StubState>,
}


pub fn id_of(fill: char) -> String {
    fill.to_string().repeat(ID_LENGTH)
}


pub fn alert(id: &str, title: &str) -> Value {
    json!({
        "id": id, "rule_id": "rule-1", "rule_title": title, "severity": "high",
        "event_time": "2026-11-10T10:00:00Z", "created": "2026-11-10T10:00:05Z",
        "host_name": "srv-1", "user_name": null, "event_ids": ["ev-1", "ev-2"],
        "summary": {"count": SUMMARY_COUNT, "note": "text"}, "summary_truncated": false
    })
}


pub fn hostile_alert(id: &str) -> Value {
    let long = "t".repeat(LONG_TITLE_CHARS);
    let summary: serde_json::Map<String, Value> = (0..MANY_ENTRIES).map(|index| (format!("k{index:03}{HOSTILE}"), json!(HOSTILE))).collect();
    let events: Vec<String> = (0..MANY_EVENTS).map(|index| format!("e{index}{HOSTILE}")).collect();
    json!({
        "id": id, "rule_id": HOSTILE, "rule_title": format!("{HOSTILE}\u{202e}{long}"), "severity": "critical",
        "event_time": HOSTILE, "created": HOSTILE, "host_name": HOSTILE, "user_name": HOSTILE,
        "event_ids": events, "summary": summary, "summary_truncated": true
    })
}


pub fn page(items: Vec<Value>, next: Option<&str>) -> Value {
    json!({ "items": items, "next_cursor": next })
}


pub fn authorised(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .is_some_and(|value| value.as_bytes().starts_with(b"Bearer tok-"))
}


pub fn mode_of(state: &StubState) -> Mode {
    *state.mode.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn error_reply(status: StatusCode) -> Response {
    (status, Json(json!({"error": {"code": "x", "message": LEAK}}))).into_response()
}


pub const NO_SOURCE: &str = "none";


pub fn note_forwarded(state: &StubState, headers: &HeaderMap) -> String {
    let seen = headers.get("forwarded").and_then(|value| value.to_str().ok()).map(str::to_owned);
    state.forwarded.lock().unwrap_or_else(PoisonError::into_inner).push(seen.clone());
    seen.unwrap_or_else(|| NO_SOURCE.to_owned())
}


pub fn locked(state: &StubState, source: &str) -> bool {
    state
        .failures
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(source)
        .is_some_and(|count| *count >= LOCK_AFTER)
}


pub fn fail_login(state: &StubState, source: &str) -> Response {
    *state
        .failures
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(source.to_owned())
        .or_insert(0) += 1;
    error_reply(StatusCode::UNAUTHORIZED)
}


pub fn login_reply(state: &StubState, source: &str, attempt: usize, username: &str, password: &str) -> Response {
    match (username, password) {
        ("alice", "secret") => Json(json!({"token": TOKEN, "token_type": "bearer"})).into_response(),
        ("multi", "secret") => Json(json!({"token": format!("tok-multi-{attempt}"), "token_type": "bearer"})).into_response(),
        ("mfa", _) => error_reply(StatusCode::UNAUTHORIZED),
        ("limited", _) => error_reply(StatusCode::TOO_MANY_REQUESTS),
        ("broken", _) => error_reply(StatusCode::INTERNAL_SERVER_ERROR),
        ("spacey", _) => Json(json!({"token": "a b", "token_type": "bearer"})).into_response(),
        ("garbage", _) => "not json".into_response(),
        _ => fail_login(state, source),
    }
}


pub async fn login_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let source = note_forwarded(&state, &headers);
    let attempt = state.logins.fetch_add(1, Ordering::SeqCst);
    let username = body.get("username").and_then(Value::as_str).unwrap_or("");
    let password = body.get("password").and_then(Value::as_str).unwrap_or("");
    if locked(&state, &source) {
        error_reply(StatusCode::TOO_MANY_REQUESTS)
    } else {
        login_reply(&state, &source, attempt, username, password)
    }
}


pub async fn logout_handler(State(state): State<Arc<StubState>>, headers: HeaderMap) -> Response {
    note_forwarded(&state, &headers);
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    state.logged_out.lock().unwrap_or_else(PoisonError::into_inner).push(bearer);
    state.logouts.fetch_add(1, Ordering::SeqCst);
    match mode_of(&state) {
        Mode::Status(status) => error_reply(status),
        _ => Json(json!({})).into_response(),
    }
}


pub fn stream_body() -> Body {
    Body::from_stream(tokio_stream::iter(
        (0..CHUNK_COUNT).map(|_| Ok::<Bytes, Infallible>(Bytes::from_static(b" "))),
    ))
}


pub async fn alerts_handler(
    State(state): State<Arc<StubState>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    uri: axum::http::Uri,
) -> Response {
    note_forwarded(&state, &headers);
    *state.last_query.lock().unwrap_or_else(PoisonError::into_inner) = uri.query().unwrap_or("").to_owned();
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Hostile => Json(page(vec![hostile_alert(&id_of('a'))], None)).into_response(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::Chunked => stream_body().into_response(),
            Mode::TooMany => Json(page((0..MANY_ITEMS).map(|_| alert(&id_of('a'), "t")).collect(), None)).into_response(),
            Mode::BadSeverity => {
                let mut broken = alert(&id_of('a'), "t");
                broken.get_mut("severity").iter_mut().for_each(|slot| **slot = json!("urgent"));
                Json(page(vec![broken], None)).into_response()
            }
            Mode::BadId => Json(page(vec![alert("short", "t")], None)).into_response(),
            Mode::BadCursor => Json(page(vec![alert(&id_of('a'), "t")], Some("a b"))).into_response(),
            Mode::Normal => match query.get("cursor").map(String::as_str) {
                None => Json(page(
                    vec![alert(&id_of('a'), "Brute force"), alert(&id_of('b'), "Malware")],
                    Some(FIRST_CURSOR),
                ))
                .into_response(),
                Some(FIRST_CURSOR) => Json(page(vec![alert(&id_of('c'), "Beacon")], None)).into_response(),
                Some(_) => error_reply(StatusCode::BAD_REQUEST),
            },
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn detail_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    state.details.fetch_add(1, Ordering::SeqCst);
    note_forwarded(&state, &headers);
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Hostile => Json(hostile_alert(&id)).into_response(),
            Mode::BadId => Json(alert(&id_of('f'), "t")).into_response(),
            _ if id == id_of('d') => error_reply(StatusCode::NOT_FOUND),
            _ => Json(alert(&id, "Brute force")).into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn start_stub(mode: Mode) -> Result<Stub, std::io::Error> {
    let state = Arc::new(StubState {
        mode: Mutex::new(mode),
        forwarded: Mutex::new(Vec::new()),
        failures: Mutex::new(BTreeMap::new()),
        logged_out: Mutex::new(Vec::new()),
        logouts: AtomicUsize::new(0),
        logins: AtomicUsize::new(0),
        details: AtomicUsize::new(0),
        last_query: Mutex::new(String::new()),
    });
    let router = Router::new()
        .route("/auth/login", post(login_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/alerts", get(alerts_handler))
        .route("/alerts/{id}", get(detail_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, router).await });
    Ok(Stub { address, state })
}
