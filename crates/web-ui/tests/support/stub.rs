use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::net::TcpListener;
use web_ui::api::{POSTURE_LIMIT, POSTURE_TEXT_BYTES, POSTURE_UID_BYTES};


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
    UnreadableAlert,
    Oversize422,
    StoredValue,
    PostureWorst,
}


#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReadFault {
    Status(StatusCode),
    Hang,
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
    pub case_paths: Mutex<Vec<String>>,
    pub asset_paths: Mutex<Vec<String>>,
    pub risk_paths: Mutex<Vec<String>>,
    pub cert_paths: Mutex<Vec<String>>,
    pub hunt_paths: Mutex<Vec<String>>,
    pub state_paths: Mutex<Vec<String>>,
    pub vuln_paths: Mutex<Vec<String>>,
    pub dhcp_paths: Mutex<Vec<String>>,
    pub posture_paths: Mutex<Vec<String>>,
    pub shell_paths: Mutex<Vec<String>>,
    pub oncall_paths: Mutex<Vec<String>>,
    pub writes: Mutex<Vec<String>>,
    pub requests: AtomicUsize,
    pub conflict: Mutex<Option<String>>,
    pub last_query: Mutex<String>,
    pub read_fault: Mutex<Option<ReadFault>>,
    pub stored: AtomicBool,
    pub triage: Mutex<Option<Value>>,
    pub linked: Mutex<Vec<String>>,
    pub link_paths: Mutex<Vec<String>>,
    pub links_reply: Mutex<Option<Value>>,
    pub links_fault: Mutex<Option<StatusCode>>,
    pub observables: Mutex<Vec<Value>>,
    pub observables_reply: Mutex<Option<Value>>,
    pub observables_fault: Mutex<Option<StatusCode>>,
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
        ("Alice", "secret") => Json(json!({"token": format!("tok-upper-{attempt}"), "token_type": "bearer"})).into_response(),
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
            Mode::UnreadableAlert | Mode::Oversize422 => error_reply(StatusCode::UNPROCESSABLE_ENTITY),
            Mode::StoredValue => stored_value_reply(),
            Mode::Hostile => Json(page(vec![hostile_alert(&id_of('a'))], None)).into_response(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::PostureWorst => error_reply(StatusCode::NOT_IMPLEMENTED),
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
    let fault = *state.read_fault.lock().unwrap_or_else(PoisonError::into_inner);
    let stored = state.stored.load(Ordering::SeqCst);
    if authorised(&headers) {
        match mode_of(&state) {
            _ if stored && matches!(fault, Some(ReadFault::Status(_))) => error_reply(match fault {
                Some(ReadFault::Status(status)) => status,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }),
            Mode::Status(status) => error_reply(status),
            Mode::Hostile => Json(hostile_alert(&id)).into_response(),
            Mode::BadId => Json(alert(&id_of('f'), "t")).into_response(),
            _ if id == id_of('d') => error_reply(StatusCode::NOT_FOUND),
            _ => {
                let triage = state.triage.lock().unwrap_or_else(PoisonError::into_inner).clone().unwrap_or(Value::Null);
                Json(merged(alert(&id, "Brute force"), json!({ "triage": triage }))).into_response()
            }
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub fn triage_view(status: &str, note: &Value, version: i64) -> Value {
    json!({"status": status, "actor": "alice", "note": note, "updated_at": "2026-11-22T08:00:00Z", "version": version})
}


pub async fn triage_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    note_forwarded(&state, &headers);
    note_write(&state, format!("/alerts/{id}/triage"), &body);
    if authorised(&headers) {
        write_failure(&state).unwrap_or_else(|| {
            let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let status = parsed.get("status").and_then(Value::as_str).unwrap_or("closed");
            let version = parsed.get("version").and_then(Value::as_i64).unwrap_or(0) + 1;
            let view = triage_view(status, parsed.get("note").unwrap_or(&Value::Null), version);
            state.stored.store(true, Ordering::SeqCst);
            *state.triage.lock().unwrap_or_else(PoisonError::into_inner) = Some(view.clone());
            Json(view).into_response()
        })
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const LONG_CASE_ID_CHARS: usize = 129;


pub const ALERT_COUNT: u32 = SUMMARY_COUNT + SUMMARY_COUNT;


pub const HUGE_TITLE_CHARS: usize = 10_000;


pub const MANY_TASKS: usize = 70;


pub const CASE_CREATED: i64 = 1_700_000_000;


pub const FAR_FUTURE: i64 = i64::MAX;


pub const BEFORE_YEAR_ZERO: i64 = -100_000_000_000;


pub fn case(id: &str, title: &str, status: &str) -> Value {
    json!({
        "id": id, "title": title, "severity": "high", "status": status, "assignee": "bob", "case_type": null,
        "created_at": CASE_CREATED, "updated_at": CASE_CREATED, "version": 1,
        "counts": {"tasks": 0, "observables": SUMMARY_COUNT, "comments": 0, "history": 0, "alerts": ALERT_COUNT}
    })
}


pub fn merged(base: Value, extra: Value) -> Value {
    Value::Object(
        base.as_object()
            .into_iter()
            .chain(extra.as_object())
            .flat_map(|fields| fields.iter().map(|(name, value)| (name.clone(), value.clone())))
            .collect(),
    )
}


pub fn case_detail(id: &str, title: &str, status: &str) -> Value {
    merged(
        case(id, title, status),
        json!({
            "description": "Initial description", "resolution": "benign", "template": "phishing",
            "tasks": [{"title": "Isolate host", "status": "in_progress", "due": CASE_CREATED, "log": []}]
        }),
    )
}


pub fn hostile_cases() -> Vec<Value> {
    let huge = "h".repeat(HUGE_TITLE_CHARS);
    let hostile_title = format!("{HOSTILE}\u{202e}\"><img src=x></style>{huge}");
    vec![
        case("case-1", &format!("{HOSTILE}\u{202e}\"><img src=x></style>{huge}"), "weird"),
        merged(case("../x", &hostile_title, "new"), json!({"assignee": HOSTILE})),
        case("-x", "dash", "closed"),
        case(&"i".repeat(LONG_CASE_ID_CHARS), &hostile_title, "new"),
        case("a/b", "slash", "new"),
        case("%2e%2e", "encoded", "new"),
        case("line\nfeed", "newline", "new"),
    ]
}


pub fn hostile_detail(id: &str) -> Value {
    let tasks: Vec<Value> = (0..MANY_TASKS)
        .map(|index| json!({"title": format!("task{index}{HOSTILE}"), "status": "odd", "due": FAR_FUTURE, "log": []}))
        .collect();
    merged(
        case_detail(id, HOSTILE, "weird"),
        json!({
            "description": format!("{HOSTILE}\u{202e}"), "resolution": "mystery", "template": format!("{HOSTILE}\u{202e}"), "tasks": tasks, "severity": "urgent",
            "assignee": format!("{HOSTILE}\u{202e}"), "case_type": format!("{HOSTILE}\u{202e}"),
            "created_at": BEFORE_YEAR_ZERO, "updated_at": FAR_FUTURE
        }),
    )
}


pub async fn cases_handler(
    State(state): State<Arc<StubState>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    uri: axum::http::Uri,
) -> Response {
    note_forwarded(&state, &headers);
    state.case_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Hostile => Json(page(hostile_cases(), None)).into_response(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(page((0..MANY_ITEMS).map(|_| case("c", "t", "new")).collect(), None)).into_response(),
            Mode::BadCursor => Json(page(vec![case("c", "t", "new")], Some("a b"))).into_response(),
            Mode::Normal => match query.get("cursor").map(String::as_str) {
                None => Json(page(
                    vec![case("case-1", "Phishing wave", "new"), case("case-2", "Ransomware", "in_progress")],
                    Some(FIRST_CURSOR),
                ))
                .into_response(),
                Some(FIRST_CURSOR) => Json(page(vec![case("case-3", "Old case", "closed")], None)).into_response(),
                Some(_) => error_reply(StatusCode::BAD_REQUEST),
            },
            _ => Json(page(vec![], None)).into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn case_detail_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    note_forwarded(&state, &headers);
    state
        .case_paths
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(format!("/cases/{id}"));
    let fault = *state.read_fault.lock().unwrap_or_else(PoisonError::into_inner);
    let stored = state.stored.load(Ordering::SeqCst);
    if stored && fault == Some(ReadFault::Hang) {
        std::future::pending::<()>().await;
    }
    if authorised(&headers) {
        match (mode_of(&state), fault) {
            (_, Some(ReadFault::Status(status))) if stored => error_reply(status),
            (Mode::Status(status), _) => error_reply(status),
            (Mode::Hostile, _) => Json(hostile_detail(&id)).into_response(),
            (Mode::Oversize, _) => "x".repeat(OVERSIZE_BYTES).into_response(),
            (Mode::BadId, _) => Json(case_detail("other", "t", "new")).into_response(),
            _ if id == "missing" => error_reply(StatusCode::NOT_FOUND),
            _ => Json(case_detail(&id, "Phishing wave", status_of(&id))).into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const RAW_CONFLICT: &str = "raw";


pub fn status_of(id: &str) -> &'static str {
    if id.ends_with("-new") {
        "new"
    } else if id.ends_with("-closed") {
        "closed"
    } else {
        "in_progress"
    }
}


pub fn conflict_reply(code: &str) -> Response {
    if code == RAW_CONFLICT {
        (StatusCode::CONFLICT, "not json").into_response()
    } else {
        (StatusCode::CONFLICT, Json(json!({"error": {"code": code, "message": LEAK}}))).into_response()
    }
}


pub fn note_write(state: &StubState, path: String, body: &Bytes) {
    state
        .writes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(format!("{path} {}", String::from_utf8_lossy(body)));
}


pub fn write_failure(state: &StubState) -> Option<Response> {
    let conflict = state.conflict.lock().unwrap_or_else(PoisonError::into_inner).clone();
    match (conflict, mode_of(state)) {
        (Some(code), _) => Some(conflict_reply(&code)),
        (None, Mode::Status(status)) => Some(error_reply(status)),
        _ => None,
    }
}


pub fn action_reply(id: &str, body: &Value) -> Value {
    let status = match body.get("action").and_then(Value::as_str) {
        Some("close") => "closed",
        _ => "in_progress",
    };
    merged(
        case_detail(id, "Phishing wave", status),
        json!({"resolution": body.get("resolution").cloned().unwrap_or(Value::Null)}),
    )
}


pub async fn case_action_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    note_forwarded(&state, &headers);
    note_write(&state, format!("/cases/{id}/actions"), &body);
    if authorised(&headers) {
        write_failure(&state).unwrap_or_else(|| {
            let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let reply_id = if mode_of(&state) == Mode::BadId { "other" } else { id.as_str() };
            Json(action_reply(reply_id, &parsed)).into_response()
        })
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub fn hostile_author() -> Value {
    json!(format!("\"><img src=x>\u{202e}{}", "a".repeat(HUGE_TITLE_CHARS)))
}


pub async fn case_comment_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    note_forwarded(&state, &headers);
    note_write(&state, format!("/cases/{id}/comments"), &body);
    if authorised(&headers) {
        write_failure(&state).unwrap_or_else(|| {
            state.stored.store(true, Ordering::SeqCst);
            let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let (author, text) = match mode_of(&state) {
                Mode::Hostile => (hostile_author(), json!(format!("{HOSTILE}\u{202e}"))),
                _ => (json!("alice"), parsed.get("text").cloned().unwrap_or(Value::Null)),
            };
            (StatusCode::CREATED, Json(json!({"author": author, "at": CASE_CREATED, "text": text}))).into_response()
        })
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub fn link_item(alert_id: &str) -> Value {
    json!({"alert_id": alert_id, "linked_by": "alice", "linked_at": CASE_CREATED})
}


pub async fn links_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, RawQuery(query): RawQuery) -> Response {
    note_forwarded(&state, &headers);
    state
        .link_paths
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(format!("/cases/{id}/alerts?{}", query.unwrap_or_else(String::new)));
    let fault = *state.links_fault.lock().unwrap_or_else(PoisonError::into_inner);
    let forged = state.links_reply.lock().unwrap_or_else(PoisonError::into_inner).clone();
    if !authorised(&headers) {
        error_reply(StatusCode::UNAUTHORIZED)
    } else if let Some(status) = fault {
        error_reply(status)
    } else if let Some(reply) = forged {
        Json(reply).into_response()
    } else {
        let items: Vec<Value> = state
            .linked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|alert| link_item(alert))
            .collect();
        Json(json!({"items": items, "next_cursor": null})).into_response()
    }
}


pub async fn link_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    note_forwarded(&state, &headers);
    note_write(&state, format!("/cases/{id}/alerts"), &body);
    if authorised(&headers) {
        write_failure(&state).unwrap_or_else(|| {
            state.stored.store(true, Ordering::SeqCst);
            let alert = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|parsed| parsed.get("alert_id").and_then(Value::as_str).map(str::to_owned));
            match alert {
                Some(alert_id) => {
                    let mut linked = state.linked.lock().unwrap_or_else(PoisonError::into_inner);
                    let added = !linked.contains(&alert_id);
                    if added {
                        linked.push(alert_id.clone());
                    }
                    (
                        if added { StatusCode::CREATED } else { StatusCode::OK },
                        Json(json!({"alert_id": alert_id})),
                    )
                        .into_response()
                }
                None => error_reply(StatusCode::BAD_REQUEST),
            }
        })
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub fn seen_item(stored: &Value) -> Value {
    merged(stored.clone(), json!({"seen_in": ["case-2"], "seen_in_truncated": false}))
}


pub async fn observables_handler(State(state): State<Arc<StubState>>, headers: HeaderMap) -> Response {
    note_forwarded(&state, &headers);
    let fault = *state.observables_fault.lock().unwrap_or_else(PoisonError::into_inner);
    let forged = state.observables_reply.lock().unwrap_or_else(PoisonError::into_inner).clone();
    if !authorised(&headers) {
        error_reply(StatusCode::UNAUTHORIZED)
    } else if let Some(status) = fault {
        error_reply(status)
    } else if let Some(reply) = forged {
        Json(reply).into_response()
    } else {
        let items: Vec<Value> = state
            .observables
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(seen_item)
            .collect();
        Json(json!({"items": items})).into_response()
    }
}


pub async fn observable_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, body: Bytes) -> Response {
    note_forwarded(&state, &headers);
    note_write(&state, format!("/cases/{id}/observables"), &body);
    if authorised(&headers) {
        write_failure(&state).unwrap_or_else(|| {
            state.stored.store(true, Ordering::SeqCst);
            let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let mut stored = state.observables.lock().unwrap_or_else(PoisonError::into_inner);
            let present = stored
                .iter()
                .any(|held| held.get("kind") == parsed.get("kind") && held.get("value") == parsed.get("value"));
            if !present {
                stored.push(parsed.clone());
            }
            let status = if present { StatusCode::OK } else { StatusCode::CREATED };
            (status, Json(merged(parsed, json!({"already_present": present})))).into_response()
        })
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const ODD_ASSET_ID: &str = "serial:A/B?c#d %e \u{e9}";


pub const ASSET_KEYS: u32 = 2;


pub const ASSET_ATTRIBUTES: u32 = 4;


pub const BIG_ASSET: &str = "big";


pub const BIG_VALUE_BYTES: usize = 4096;


pub const BIG_ATTRIBUTES: usize = 500;


pub const MANY_ATTRIBUTES: usize = 501;


pub fn asset(id: &str, kind: &str) -> Value {
    json!({"id": id, "kind": kind, "lifecycle": "active", "version": 1, "counts": {"keys": ASSET_KEYS, "attributes": ASSET_ATTRIBUTES, "open_conflicts": 1}})
}


pub fn asset_detail(id: &str, attributes: Vec<Value>, truncated: bool) -> Value {
    merged(
        asset(id, "server"),
        json!({
            "keys": [{"key": "serial", "value": "A1"}, {"key": "hostname", "value": "srv-1"}],
            "attributes": attributes, "truncated": truncated
        }),
    )
}


pub fn attribute(name: &str, value: &str) -> Value {
    json!({"name": name, "value": value, "source": "agent"})
}


pub fn hostile_assets() -> Vec<Value> {
    vec![
        asset(&format!("a{HOSTILE}"), "kind"),
        asset("gap:victim\u{e0041}", "server"),
        asset("gap:\u{61c}mitciv", "server"),
        asset("gap:\u{115f}x", "server"),
        asset("gap:\u{2800}x", "server"),
        asset("gap:\u{ffa0}x", "server"),
        asset("gap:\u{180e}x", "server"),
        asset("gap:victim", &format!("{HOSTILE}\u{202e}kind")),
        asset("gap:kind-tag", "k\u{e0041}"),
        asset("gap:kept", "server"),
    ]
}


pub fn hostile_asset_detail(id: &str) -> Value {
    let huge = "v".repeat(BIG_VALUE_BYTES);
    merged(
        asset_detail(
            id,
            vec![
                attribute(
                    HOSTILE,
                    &format!("{HOSTILE}\u{202e}\u{e0041}\u{61c}\u{115f}\u{2800}\u{ffa0}\u{180e}{huge}"),
                ),
                attribute("name", "<script>alert(2)</script>"),
            ],
            false,
        ),
        json!({"kind": format!("{HOSTILE}\u{202e}"), "keys": [{"key": HOSTILE, "value": format!("{HOSTILE}\u{202e}")}]}),
    )
}


pub async fn assets_handler(
    State(state): State<Arc<StubState>>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
    uri: axum::http::Uri,
) -> Response {
    note_forwarded(&state, &headers);
    state.asset_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Hostile => Json(page(hostile_assets(), None)).into_response(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(page((0..MANY_ITEMS).map(|_| asset("c", "t")).collect(), None)).into_response(),
            Mode::BadCursor => Json(page(vec![asset("c", "t")], Some("a b"))).into_response(),
            Mode::BadId => Json(page(vec![asset("a\u{202e}b", "t")], None)).into_response(),
            Mode::Normal => match query.get("cursor").map(String::as_str) {
                None => Json(page(vec![asset("srv-1", "server"), asset(ODD_ASSET_ID, "switch")], Some(FIRST_CURSOR))).into_response(),
                Some(FIRST_CURSOR) => Json(page(vec![asset("srv-3", "laptop")], None)).into_response(),
                Some(_) => error_reply(StatusCode::BAD_REQUEST),
            },
            _ => Json(page(vec![], None)).into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn asset_detail_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    {
        let mut seen = state.asset_paths.lock().unwrap_or_else(PoisonError::into_inner);
        seen.push(uri.path().to_owned());
        seen.push(format!("id={id}"));
    }
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Hostile => Json(hostile_asset_detail(&id)).into_response(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::BadId => Json(asset_detail("other", vec![], false)).into_response(),
            Mode::TooMany => Json(asset_detail(&id, (0..MANY_ATTRIBUTES).map(|_| attribute("n", "v")).collect(), true)).into_response(),
            _ if id == "missing" => error_reply(StatusCode::NOT_FOUND),
            _ if id == BIG_ASSET => Json(asset_detail(
                &id,
                (0..BIG_ATTRIBUTES).map(|index| attribute(&format!("n{index}"), "v")).collect(),
                true,
            ))
            .into_response(),
            _ => Json(asset_detail(&id, vec![attribute("os", "linux")], false)).into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const RISK_ALERTS_READ: u32 = 1234;


pub const RISK_CAP: u32 = 5678;


pub const RISK_USED: u32 = 3;


pub const RISK_COMPUTED_AT: i64 = 1_700_000_000;


pub const RISK_DETAIL_SCORE: u32 = 55;


pub const RISK_WEB_SCORE: u32 = 80;


pub const RISK_DB_SCORE: u32 = 40;


pub const RISK_ALICE_SCORE: u32 = 10;


pub const RISK_ODD_ID: &str = "a/b?c#d%e";


pub const RISK_UNREADABLE_IDS: [&str; 6] = ["bad\u{202e}id", "two  spaces", "cafe\u{301}", "hole\u{3164}x", "", "trail "];


pub fn risk_entity(kind: &str, id: &str, value: u32) -> Value {
    json!({"kind": kind, "id": id, "value": value, "contributions_used": RISK_USED, "contributions_dropped": 0})
}


pub fn risk_list(entities: Vec<Value>, truncated: bool) -> Value {
    let bound = json!({"limit": "alerts", "read": RISK_ALERTS_READ, "cap": RISK_CAP});
    json!({
        "computed_at": RISK_COMPUTED_AT, "alerts_read": RISK_ALERTS_READ, "informational": 0, "refused": {"host": 1},
        "truncated": if truncated { bound } else { Value::Null }, "entities": entities
    })
}


pub async fn risk_list_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.risk_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(risk_list((0..=MAX_RISK_ROWS).map(|_| risk_entity("host", "h", 1)).collect(), false)).into_response(),
            Mode::Hostile => {
                let mut rows: Vec<Value> = RISK_UNREADABLE_IDS.iter().map(|id| risk_entity("host", id, 1)).collect();
                rows.push(risk_entity("host", "over", OVER_SCORE));
                rows.push(risk_entity("group", "g", 1));
                rows.push(risk_entity("host", RISK_ODD_ID, 1));
                Json(risk_list(rows, true)).into_response()
            }
            Mode::Chunked => Json(risk_list(vec![], false)).into_response(),
            _ => {
                let rows = vec![
                    risk_entity("host", "web01", RISK_WEB_SCORE),
                    risk_entity("host", "db01", RISK_DB_SCORE),
                    risk_entity("user", "alice", RISK_ALICE_SCORE),
                ];
                let wanted = uri.query().unwrap_or("").contains("kind=user");
                let kept = rows.into_iter().filter(|row| !wanted || row["kind"] == "user").collect();
                Json(risk_list(kept, true)).into_response()
            }
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn risk_detail_handler(
    State(state): State<Arc<StubState>>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, String)>,
    uri: axum::http::Uri,
) -> Response {
    note_forwarded(&state, &headers);
    {
        let mut seen = state.risk_paths.lock().unwrap_or_else(PoisonError::into_inner);
        seen.push(uri.path().to_owned());
        seen.push(format!("id={id}"));
    }
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::BadId => Json(json!({"computed_at": 1, "truncated": null, "entity": risk_entity(&kind, "other", 1)})).into_response(),
            Mode::Hostile => Json(json!({"computed_at": 1, "truncated": null, "entity": risk_entity(&kind, &id, OVER_SCORE)})).into_response(),
            _ if id == "swapped" => Json(json!({"computed_at": 1, "truncated": null, "entity": risk_entity("user", &id, 1)})).into_response(),
            _ => {
                let bound = json!({"limit": "weird", "read": RISK_ALERTS_READ, "cap": RISK_CAP});
                Json(json!({"computed_at": RISK_COMPUTED_AT, "truncated": bound, "entity": risk_entity(&kind, &id, RISK_DETAIL_SCORE)}))
                    .into_response()
            }
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const MAX_RISK_ROWS: usize = 500;


pub const CERT_CURSOR_TIME: &str = "1800000000";


pub const CERT_SKIPPED: u32 = 2;


pub const CERT_HUGE_SUBJECT: usize = 5000;


pub const CERT_MANY_NAMES: usize = 150;


pub const CERT_MANY_SIGHTINGS: usize = 501;


pub const CERT_HOSTILE_SUBJECT: &str = "evil\u{1b}[31m\u{202e}cn\nnext";


pub const CERT_BAD_FINGERPRINT_COUNT: usize = 3;


pub fn cert_fingerprint(fill: char) -> String {
    id_of(fill)
}


pub fn cert(fingerprint: &str, subject: &str, expiry: &str, names: usize) -> Value {
    let dns: Vec<String> = (0..names).map(|index| format!("host{index}.example.test")).collect();
    json!({
        "fingerprint": fingerprint, "subject": subject, "issuer": "CN=Test CA", "dns_names": dns,
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
        "first_seen": "2026-02-01T00:00:00Z", "last_seen": "2026-03-01T00:00:00Z",
        "key_type": "rsa", "key_bits": if expiry == "weird" { Value::Null } else { json!(CERT_KEY_BITS) }, "self_signed": expiry == "weird", "expiry": expiry
    })
}


pub fn cert_list(items: Vec<Value>, skipped: u32, next: Option<String>) -> Value {
    json!({"items": items, "skipped": skipped, "next_cursor": next})
}


pub fn cert_detail(fingerprint: &str, subject: &str, expiry: &str, names: usize, sightings: usize, flagged: bool) -> Value {
    let mut body = cert(fingerprint, subject, expiry, names);
    let seen: Vec<Value> = (0..sightings)
        .map(|index| json!({"kind": "file", "reference": format!("/etc/ssl/{index}.pem{CERT_HOSTILE_SUBJECT}"), "last_seen": "2026-03-01T00:00:00Z"}))
        .collect();
    if let Some(map) = body.as_object_mut() {
        map.insert("sightings".to_owned(), Value::Array(seen));
        map.insert("sightings_skipped".to_owned(), json!(if flagged { CERT_SKIPPED } else { 0 }));
        map.insert("sightings_truncated".to_owned(), json!(flagged));
    }
    body
}


pub fn cert_hostile_list() -> Value {
    let upper = format!("A{}", "a".repeat(CERT_SHORT_FINGERPRINT));
    let short = "a".repeat(CERT_SHORT_FINGERPRINT);
    let mut items: Vec<Value> = [upper.as_str(), short.as_str(), "../x"]
        .iter()
        .map(|fingerprint| cert(fingerprint, "bad", "ok", 0))
        .collect();
    let subject = format!("{CERT_HOSTILE_SUBJECT}{}", "s".repeat(CERT_HUGE_SUBJECT));
    items.push(cert(&cert_fingerprint('e'), &subject, "weird", CERT_ROW_NAMES));
    cert_list(items, CERT_SKIPPED, None)
}


pub async fn cert_list_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.cert_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(cert_list(
                (0..MANY_ITEMS).map(|_| cert(&cert_fingerprint('a'), "s", "ok", 0)).collect(),
                0,
                None,
            ))
            .into_response(),
            Mode::BadCursor => Json(cert_list(vec![], 0, Some("a b".to_owned()))).into_response(),
            Mode::Hostile => Json(cert_hostile_list()).into_response(),
            Mode::Chunked => Json(cert_list(vec![], 0, None)).into_response(),
            _ => Json(cert_list(
                vec![
                    cert(&cert_fingerprint('a'), "CN=one", "expired", CERT_PAIR),
                    cert(&cert_fingerprint('b'), "CN=two", "near", 1),
                    cert(&cert_fingerprint('c'), "CN=three", "ok", 0),
                ],
                CERT_SKIPPED,
                Some(format!("{CERT_CURSOR_TIME}:{}", cert_fingerprint('c'))),
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn cert_detail_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(fingerprint): Path<String>) -> Response {
    note_forwarded(&state, &headers);
    state
        .cert_paths
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(format!("/certificates/{fingerprint}"));
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::BadId => Json(cert_detail(&cert_fingerprint('f'), "s", "ok", 0, 0, false)).into_response(),
            Mode::TooMany => Json(cert_detail(&fingerprint, "s", "ok", 0, CERT_MANY_SIGHTINGS, false)).into_response(),
            Mode::Hostile => {
                let subject = format!("{CERT_HOSTILE_SUBJECT}{}", "s".repeat(CERT_HUGE_SUBJECT));
                Json(cert_detail(&fingerprint, &subject, "weird", CERT_MANY_NAMES, CERT_PAIR, true)).into_response()
            }
            _ => Json(cert_detail(&fingerprint, "CN=one", "near", CERT_PAIR, CERT_PAIR, false)).into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const HUNT_NEXT_CURSOR: &str = "MTgwMDAwMDAwMDpwYWNrLWM";


pub const HUNT_SKIPPED: u32 = 2;


pub const HUNT_MATCHES: u32 = 7;


pub const HUNT_MAX_MATCHES: u32 = 500;


pub const HUNT_OVERSIZED: u32 = 4;


pub const HUNT_HOSTILE_PACK: &str = "evil\u{1b}[31m\u{3164}pack";


pub fn finding(pack_id: &str, start: &str, end: &str) -> Value {
    json!({"pack_id": pack_id, "window_start": start, "window_end": end, "matches": HUNT_MATCHES, "max_matches": HUNT_MAX_MATCHES})
}


pub fn finding_list(items: Vec<Value>, skipped: u32, oversized: u32, capped: bool, next: Option<&str>) -> Value {
    json!({"items": items, "skipped": skipped, "oversized": {"count": oversized, "capped": capped}, "next_cursor": next})
}


pub const HUNT_START: &str = "2026-03-01T00:00:00Z";


pub const HUNT_END: &str = "2026-03-02T01:00:00+01:00";


pub fn hunt_hostile_list() -> Value {
    finding_list(
        vec![
            finding(HUNT_HOSTILE_PACK, HUNT_START, HUNT_END),
            finding("good-pack", "not a time", HUNT_END),
            finding("good-pack", HUNT_START, "0000-01-01T00:00:00+02:00"),
            finding("Upper", HUNT_START, HUNT_END),
            finding("fine.pack_1", HUNT_START, HUNT_END),
        ],
        HUNT_SKIPPED,
        HUNT_OVERSIZED,
        true,
        None,
    )
}


pub async fn hunt_list_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.hunt_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(finding_list(
                (0..MANY_ITEMS).map(|_| finding("p", HUNT_START, HUNT_END)).collect(),
                0,
                0,
                false,
                None,
            ))
            .into_response(),
            Mode::BadCursor => Json(finding_list(vec![], 0, 0, false, Some("a b"))).into_response(),
            Mode::Hostile => Json(hunt_hostile_list()).into_response(),
            Mode::Chunked => Json(finding_list(vec![], 0, 0, false, None)).into_response(),
            Mode::BadId => Json(finding_list(vec![], 1, 1, false, Some(HUNT_NEXT_CURSOR))).into_response(),
            Mode::BadSeverity => Json(finding_list(vec![finding("p", HUNT_START, HUNT_END)], 0, 1, true, None)).into_response(),
            _ => Json(finding_list(
                vec![finding("baseline-1", HUNT_START, HUNT_END), finding("lateral.move", HUNT_START, HUNT_END)],
                HUNT_SKIPPED,
                HUNT_OVERSIZED,
                false,
                Some(HUNT_NEXT_CURSOR),
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const STATE_ASSET_LIMIT: usize = 1000;


pub const STATE_MANY_SKIPPED: u32 = 3;


pub const STATE_ASSET_SKIPPED: u32 = 2;


pub const STATE_NEXT_CURSOR: &str = "626173650063746c00686f73742d31";


pub const STATE_HOSTILE_BASELINE: &str = "evil\u{1b}[31m";


pub const STATE_HOSTILE_ASSET: &str = "web\u{3164}01";


pub const STATE_FIRST_FAILED: &str = "2026-03-01T10:00:00+01:00";


pub const STATE_LAST_SEEN: &str = "2026-03-02T00:00:00Z";


pub fn state_item(baseline: &str, control: &str, asset: &str, verdict: &str, first_failed: Option<&str>, last_seen: &str) -> Value {
    json!({"baseline": baseline, "control": control, "asset": asset, "verdict": verdict, "first_failed": first_failed, "last_seen": last_seen})
}


pub fn state_list(items: Vec<Value>, skipped: u32, next: Option<&str>) -> Value {
    json!({"items": items, "skipped": skipped, "next_cursor": next})
}


pub fn state_asset(items: Vec<Value>, skipped: u32, truncated: bool) -> Value {
    json!({"items": items, "skipped": skipped, "truncated": truncated})
}


pub fn state_hostile_items(asset: &str) -> Vec<Value> {
    vec![
        state_item(STATE_HOSTILE_BASELINE, "c1", asset, "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN),
        state_item("base", "c<script>", asset, "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN),
        state_item("base", "c2", STATE_HOSTILE_ASSET, "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN),
        state_item("base", "c3", "-x", "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN),
        state_item("base", "c4", asset, "bogus", None, STATE_LAST_SEEN),
        state_item("base", "c5", asset, "fail", Some("not a time"), STATE_LAST_SEEN),
        state_item("base", "c6", asset, "pass", Some("0000-01-01T00:00:00+02:00"), STATE_LAST_SEEN),
        state_item("base", "c7", asset, "pass", None, "9999-12-31T23:00:00-02:00"),
        state_item("base", "c8", "other-asset", "pass", None, STATE_LAST_SEEN),
        state_item("base", "fine.1", asset, "excepted", None, STATE_LAST_SEEN),
    ]
}


pub async fn state_list_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.state_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(state_list(
                (0..MANY_ITEMS)
                    .map(|_| state_item("b", "c", "a", "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN))
                    .collect(),
                0,
                None,
            ))
            .into_response(),
            Mode::BadCursor => Json(state_list(vec![], 0, Some("ABCDEF"))).into_response(),
            Mode::Hostile => Json(state_list(state_hostile_items("web01"), 1, None)).into_response(),
            Mode::Chunked => Json(state_list(vec![], 0, None)).into_response(),
            Mode::BadId => Json(state_list(vec![], 1, Some(STATE_NEXT_CURSOR))).into_response(),
            Mode::BadSeverity => Json(state_list(vec![], STATE_MANY_SKIPPED, None)).into_response(),
            _ => Json(state_list(
                vec![
                    state_item("base", "ctl-1", "host-1", "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN),
                    state_item("base", "ctl-2", "a/b+c", "pass", None, STATE_LAST_SEEN),
                ],
                1,
                Some(STATE_NEXT_CURSOR),
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn state_asset_handler(
    State(state): State<Arc<StubState>>,
    headers: HeaderMap,
    Path(asset): Path<String>,
    uri: axum::http::Uri,
) -> Response {
    note_forwarded(&state, &headers);
    state.state_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(state_asset(
                (0..=STATE_ASSET_LIMIT)
                    .map(|_| state_item("b", "c", &asset, "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN))
                    .collect(),
                0,
                false,
            ))
            .into_response(),
            Mode::Hostile => Json(state_asset(state_hostile_items(&asset), 1, true)).into_response(),
            Mode::Chunked => Json(state_asset(vec![], 0, false)).into_response(),
            Mode::BadId => Json(state_asset(vec![], 1, false)).into_response(),
            _ if asset == "elsewhere" => error_reply(StatusCode::NOT_FOUND),
            _ => Json(state_asset(
                vec![
                    state_item("base", "ctl-1", &asset, "fail", Some(STATE_FIRST_FAILED), STATE_LAST_SEEN),
                    state_item("base", "ctl-2", &asset, "error", None, STATE_LAST_SEEN),
                ],
                STATE_ASSET_SKIPPED,
                true,
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const VULN_ASSET_LIMIT: usize = 1000;


pub const VULN_CVSS: f64 = 7.5;


pub const VULN_EPSS: f64 = 0.25;


pub const VULN_PRIORITY: u32 = 900;


pub const VULN_OVER_CVSS: u32 = 11;


pub const VULN_OVER_EPSS: u32 = 2;


pub const VULN_NEXT_CURSOR: &str = "900 host-1 npm lodash CVE-1";


pub const VULN_SEEN: &str = "2026-03-01T10:00:00+01:00";


pub const VULN_HOSTILE_PACKAGE: &str = "evil\u{1b}[31m";


pub const VULN_HOSTILE_RECORD: &str = "<script>x</script>";


pub struct VulnFields<'a> {
    pub asset: &'a str,
    pub package: &'a str,
    pub record: &'a str,
    pub installed: &'a str,
    pub fixed: Option<&'a str>,
    pub cvss: Value,
    pub epss: Value,
    pub kev: bool,
    pub seen: &'a str,
}


pub fn vuln_good(asset: &str) -> VulnFields<'_> {
    VulnFields {
        asset,
        package: "lodash",
        record: "CVE-2021-23337",
        installed: "4.17.0",
        fixed: Some("4.17.21"),
        cvss: json!(VULN_CVSS),
        epss: json!(VULN_EPSS),
        kev: false,
        seen: VULN_SEEN,
    }
}


pub fn vuln_item(fields: &VulnFields<'_>) -> Value {
    json!({
        "asset": fields.asset, "ecosystem": "npm", "package": fields.package, "record_id": fields.record,
        "installed_version": fields.installed, "fixed_version": fields.fixed, "cvss": fields.cvss, "epss": fields.epss,
        "kev": fields.kev, "priority": VULN_PRIORITY, "first_seen": fields.seen, "last_seen": "2026-03-02T00:00:00Z"
    })
}


pub fn vuln_list(items: Vec<Value>, skipped: u32, next: Option<&str>) -> Value {
    json!({"items": items, "skipped": skipped, "next_cursor": next})
}


pub fn vuln_asset(items: Vec<Value>, skipped: u32, truncated: bool) -> Value {
    json!({"items": items, "skipped": skipped, "truncated": truncated})
}


pub fn vuln_hostile_items(asset: &str) -> Vec<Value> {
    let good = || vuln_good(asset);
    vec![
        vuln_item(&VulnFields {
            package: VULN_HOSTILE_PACKAGE,
            ..good()
        }),
        vuln_item(&VulnFields {
            package: "pk\u{3164}g",
            ..good()
        }),
        vuln_item(&VulnFields { cvss: Value::Null, ..good() }),
        vuln_item(&VulnFields {
            cvss: json!(VULN_OVER_CVSS),
            ..good()
        }),
        vuln_item(&VulnFields {
            epss: json!(VULN_OVER_EPSS),
            ..good()
        }),
        vuln_item(&VulnFields {
            cvss: json!("NaN"),
            ..good()
        }),
        vuln_item(&VulnFields {
            seen: "not a time",
            ..good()
        }),
        vuln_item(&VulnFields { fixed: Some("-x"), ..good() }),
        vuln_item(&VulnFields { installed: "", ..good() }),
        vuln_item(&VulnFields {
            record: VULN_HOSTILE_RECORD,
            ..good()
        }),
        vuln_item(&VulnFields {
            kev: true,
            fixed: None,
            package: "fine",
            ..good()
        }),
        vuln_item(&VulnFields {
            asset: "other-asset",
            package: "foreign",
            ..good()
        }),
    ]
}


pub async fn vuln_list_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.vuln_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(vuln_list((0..MANY_ITEMS).map(|_| vuln_item(&vuln_good("a"))).collect(), 0, None)).into_response(),
            Mode::BadCursor => Json(vuln_list(vec![], 0, Some("ABCDEF"))).into_response(),
            Mode::Hostile => Json(vuln_list(vuln_hostile_items("web01"), 1, None)).into_response(),
            Mode::Chunked => Json(vuln_list(vec![], 0, None)).into_response(),
            Mode::BadId => Json(vuln_list(vec![], 1, Some(VULN_NEXT_CURSOR))).into_response(),
            Mode::BadSeverity => Json(vuln_list(vec![], STATE_MANY_SKIPPED, None)).into_response(),
            _ => Json(vuln_list(
                vec![
                    vuln_item(&VulnFields {
                        kev: true,
                        ..vuln_good("host-1")
                    }),
                    vuln_item(&VulnFields {
                        fixed: None,
                        ..vuln_good("a/b+c")
                    }),
                ],
                1,
                Some(VULN_NEXT_CURSOR),
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn vuln_asset_handler(
    State(state): State<Arc<StubState>>,
    headers: HeaderMap,
    Path(asset): Path<String>,
    uri: axum::http::Uri,
) -> Response {
    note_forwarded(&state, &headers);
    state.vuln_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(vuln_asset(
                (0..=VULN_ASSET_LIMIT).map(|_| vuln_item(&vuln_good(&asset))).collect(),
                0,
                false,
            ))
            .into_response(),
            Mode::Hostile => Json(vuln_asset(vuln_hostile_items(&asset), 1, true)).into_response(),
            Mode::Chunked => Json(vuln_asset(vec![], 0, false)).into_response(),
            Mode::BadId => Json(vuln_asset(vec![], 1, false)).into_response(),
            _ if asset == "elsewhere" => error_reply(StatusCode::NOT_FOUND),
            _ => Json(vuln_asset(
                vec![
                    vuln_item(&vuln_good(&asset)),
                    vuln_item(&VulnFields {
                        kev: true,
                        ..vuln_good(&asset)
                    }),
                ],
                STATE_ASSET_SKIPPED,
                true,
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const OVER_SCORE: u32 = 101;


pub async fn count_request(State(state): State<Arc<StubState>>, request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    next.run(request).await
}


pub const ONCALL_OPENED: &str = "2026-03-01T10:00:00+01:00";


pub const ONCALL_MANY: usize = 1001;


pub const ONCALL_LONG: usize = 257;


pub const ONCALL_FIRST_ID: i64 = 7;


pub const ONCALL_LEVEL: u32 = 2;


pub const ONCALL_OCCURRENCES: i64 = 3;


pub const ONCALL_MISSING_ID: &str = "99";


pub fn oncall_item(id: i64, fingerprint: &str, state: &str, opened: &str, acknowledged: Option<&str>, resolved: Option<&str>) -> Value {
    json!({
        "id": id, "fingerprint": fingerprint, "state": state, "level": ONCALL_LEVEL, "occurrences": ONCALL_OCCURRENCES,
        "opened_at": opened, "acknowledged_at": acknowledged, "resolved_at": resolved,
    })
}


pub fn oncall_hostile_items() -> Vec<Value> {
    let long = "a".repeat(ONCALL_LONG);
    let rows = vec![
        ("evil\u{1b}[31m", "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        ("a\u{3164}b", "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        ("<script>x</script>\u{e9}", "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        ("two  spaces", "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        (" lead", "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        ("trail ", "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        ("", "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        (&long, "open", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        ("fp", "bogus", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
        ("fp", "open", "not a time", None, None, ONCALL_OCCURRENCES),
        (
            "fp",
            "resolved",
            ONCALL_OPENED,
            Some("0000-01-01T00:00:00+02:00"),
            None,
            ONCALL_OCCURRENCES,
        ),
        (
            "fp",
            "resolved",
            ONCALL_OPENED,
            None,
            Some("9999-12-31T23:00:00-02:00"),
            ONCALL_OCCURRENCES,
        ),
        ("fp", "open", ONCALL_OPENED, None, None, -1),
        ("fine.fp 1", "escalated", ONCALL_OPENED, None, None, ONCALL_OCCURRENCES),
    ];
    rows.into_iter()
        .enumerate()
        .map(|(index, (fingerprint, state, opened, acknowledged, resolved, occurrences))| {
            json!({
                "id": index + 1, "fingerprint": fingerprint, "state": state, "level": ONCALL_LEVEL, "occurrences": occurrences,
                "opened_at": opened, "acknowledged_at": acknowledged, "resolved_at": resolved,
            })
        })
        .chain([oncall_item(-1, "fp", "open", ONCALL_OPENED, None, None)])
        .collect()
}


pub async fn oncall_list_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.oncall_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(
                json!({"items": (0..ONCALL_MANY).map(|_| oncall_item(1, "fp", "open", ONCALL_OPENED, None, None)).collect::<Vec<_>>(), "skipped": 0}),
            )
            .into_response(),
            Mode::Hostile => Json(json!({"items": oncall_hostile_items(), "skipped": 1})).into_response(),
            Mode::Chunked => Json(json!({"items": [], "skipped": 0})).into_response(),
            Mode::BadId => Json(json!({"items": [], "skipped": 1})).into_response(),
            Mode::BadSeverity => Json(json!({"items": [], "skipped": STATE_MANY_SKIPPED})).into_response(),
            Mode::BadCursor => Json(json!({"items": "wrong", "skipped": 0})).into_response(),
            _ => Json(json!({
                "items": [
                    oncall_item(ONCALL_FIRST_ID, "fp one", "open", ONCALL_OPENED, None, None),
                    oncall_item(ONCALL_FIRST_ID + 1, "fp-two", "acknowledged", ONCALL_OPENED, Some("2026-03-02T00:00:00Z"), None),
                ],
                "skipped": 1,
            }))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn oncall_alert_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.oncall_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    let number: i64 = id.parse().unwrap_or(0);
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::UnreadableAlert => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": {"code": "unreadable_alert", "message": LEAK}})),
            )
                .into_response(),
            Mode::Oversize422 => (StatusCode::UNPROCESSABLE_ENTITY, "x".repeat(OVERSIZE_BYTES)).into_response(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::Hostile => Json(oncall_item(number, "evil\u{1b}[31m", "open", ONCALL_OPENED, None, None)).into_response(),
            Mode::BadId => Json(oncall_item(number + 1, "fp", "open", ONCALL_OPENED, None, None)).into_response(),
            _ if id == ONCALL_MISSING_ID => error_reply(StatusCode::NOT_FOUND),
            _ => Json(oncall_item(
                number,
                "fp one",
                "resolved",
                ONCALL_OPENED,
                Some("2026-03-02T00:00:00Z"),
                Some("2026-03-03T00:00:00Z"),
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const SHELL_NEXT_CURSOR: &str = "1772000000.s-2";


pub const SHELL_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


pub const SHELL_OPENED: &str = "2026-03-01T10:00:00+01:00";


pub const SHELL_CLOSED: &str = "2026-03-01T11:00:00Z";


pub const SHELL_FRAMES: i64 = 12;


pub const SHELL_BYTES: i64 = 4096;


pub struct ShellFields<'a> {
    pub id: &'a str,
    pub requester: &'a str,
    pub asset: &'a str,
    pub ticket: &'a str,
    pub opened: &'a str,
    pub closed: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub frames: Option<i64>,
    pub hash: Option<&'a str>,
    pub bytes: Option<i64>,
}


pub fn shell_closed(id: &str) -> ShellFields<'_> {
    ShellFields {
        id,
        requester: "auth0|a+b/c=d",
        asset: "host/1",
        ticket: "T-1",
        opened: SHELL_OPENED,
        closed: Some(SHELL_CLOSED),
        reason: Some("user_close"),
        frames: Some(SHELL_FRAMES),
        hash: Some(SHELL_HASH),
        bytes: Some(SHELL_BYTES),
    }
}


pub fn shell_open(id: &str) -> ShellFields<'_> {
    ShellFields {
        closed: None,
        reason: None,
        frames: None,
        hash: None,
        bytes: None,
        ..shell_closed(id)
    }
}


pub fn shell_item(fields: &ShellFields<'_>) -> Value {
    json!({
        "session_id": fields.id, "requester": fields.requester, "asset": fields.asset, "ticket": fields.ticket,
        "opened_at": fields.opened, "closed_at": fields.closed, "close_reason": fields.reason,
        "recording_frames": fields.frames, "recording_hash": fields.hash, "recording_bytes": fields.bytes
    })
}


pub fn shell_list(items: Vec<Value>, skipped: u32, next: Option<&str>) -> Value {
    json!({"items": items, "skipped": skipped, "next_cursor": next})
}


pub const SHELL_HOSTILE_REQUESTER: &str = "evil\u{1b}[31m";


pub const SHELL_HOSTILE_TICKET: &str = "T\u{3164}1";


pub fn shell_hostile_items() -> Vec<Value> {
    let good = || shell_closed("s-1");
    vec![
        shell_item(&ShellFields {
            requester: SHELL_HOSTILE_REQUESTER,
            ..good()
        }),
        shell_item(&ShellFields {
            requester: "x\u{202e}y",
            ..good()
        }),
        shell_item(&ShellFields {
            ticket: SHELL_HOSTILE_TICKET,
            ..good()
        }),
        shell_item(&ShellFields {
            asset: "<script>x</script>",
            ..good()
        }),
        shell_item(&ShellFields { id: "-x", ..good() }),
        shell_item(&ShellFields {
            opened: "not a time",
            ..good()
        }),
        shell_item(&ShellFields {
            closed: Some("not a time"),
            ..good()
        }),
        shell_item(&ShellFields {
            reason: Some("evil"),
            ..good()
        }),
        shell_item(&ShellFields {
            hash: Some(&SHELL_HASH.to_ascii_uppercase()),
            ..good()
        }),
        shell_item(&ShellFields { hash: Some("abc"), ..good() }),
        shell_item(&ShellFields { frames: Some(1), ..good() }),
        shell_item(&ShellFields { bytes: Some(-1), ..good() }),
        shell_item(&ShellFields { reason: None, ..good() }),
        shell_item(&ShellFields { closed: None, ..good() }),
        shell_item(&ShellFields { frames: None, ..good() }),
        shell_item(&ShellFields { hash: None, ..good() }),
        shell_item(&ShellFields { bytes: None, ..good() }),
        shell_item(&shell_open("fine")),
    ]
}


pub fn stored_value_reply() -> Response {
    let body = json!({"error": {"code": "stored_value", "message": "a stored value cannot be served"}});
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}


pub async fn shell_list_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.shell_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::StoredValue => stored_value_reply(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(shell_list((0..MANY_ITEMS).map(|_| shell_item(&shell_open("s"))).collect(), 0, None)).into_response(),
            Mode::BadCursor => Json(shell_list(vec![], 0, Some("bad cursor"))).into_response(),
            Mode::Hostile => Json(shell_list(shell_hostile_items(), 1, None)).into_response(),
            Mode::Chunked => Json(shell_list(vec![], 0, None)).into_response(),
            Mode::BadId => Json(shell_list(vec![], 1, Some(SHELL_NEXT_CURSOR))).into_response(),
            Mode::BadSeverity => Json(shell_list(vec![], STATE_MANY_SKIPPED, None)).into_response(),
            _ => Json(shell_list(
                vec![shell_item(&shell_closed("s-1")), shell_item(&shell_open("s-2"))],
                1,
                Some(SHELL_NEXT_CURSOR),
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub async fn shell_detail_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(id): Path<String>, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.shell_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::StoredValue => stored_value_reply(),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::Hostile => Json(shell_item(&ShellFields {
                requester: SHELL_HOSTILE_REQUESTER,
                ..shell_closed(&id)
            }))
            .into_response(),
            Mode::BadId => Json(shell_item(&shell_closed("other"))).into_response(),
            Mode::Chunked => Json(shell_item(&shell_open(&id))).into_response(),
            _ if id == "elsewhere" => error_reply(StatusCode::NOT_FOUND),
            _ => Json(shell_item(&shell_closed(&id))).into_response(),
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
        case_paths: Mutex::new(Vec::new()),
        asset_paths: Mutex::new(Vec::new()),
        risk_paths: Mutex::new(Vec::new()),
        cert_paths: Mutex::new(Vec::new()),
        hunt_paths: Mutex::new(Vec::new()),
        state_paths: Mutex::new(Vec::new()),
        vuln_paths: Mutex::new(Vec::new()),
        dhcp_paths: Mutex::new(Vec::new()),
        posture_paths: Mutex::new(Vec::new()),
        shell_paths: Mutex::new(Vec::new()),
        oncall_paths: Mutex::new(Vec::new()),
        writes: Mutex::new(Vec::new()),
        requests: AtomicUsize::new(0),
        conflict: Mutex::new(None),
        last_query: Mutex::new(String::new()),
        read_fault: Mutex::new(None),
        stored: AtomicBool::new(false),
        triage: Mutex::new(None),
        linked: Mutex::new(Vec::new()),
        link_paths: Mutex::new(Vec::new()),
        links_reply: Mutex::new(None),
        links_fault: Mutex::new(None),
        observables: Mutex::new(Vec::new()),
        observables_reply: Mutex::new(None),
        observables_fault: Mutex::new(None),
    });
    let router = Router::new()
        .route("/auth/login", post(login_handler))
        .route("/auth/logout", post(logout_handler))
        .route("/alerts", get(alerts_handler))
        .route("/alerts/{id}", get(detail_handler))
        .route("/alerts/{id}/triage", post(triage_handler))
        .route("/assets", get(assets_handler))
        .route("/assets/{id}", get(asset_detail_handler))
        .route("/risk/entities", get(risk_list_handler))
        .route("/risk/entities/{kind}/{id}", get(risk_detail_handler))
        .route("/certificates", get(cert_list_handler))
        .route("/certificates/{fingerprint}", get(cert_detail_handler))
        .route("/hunts/findings", get(hunt_list_handler))
        .route("/compliance/state", get(state_list_handler))
        .route("/compliance/assets/{asset}", get(state_asset_handler))
        .route("/dhcp/leases/at", get(dhcp_handler))
        .route("/dhcp/leases/mac", get(dhcp_handler))
        .route("/posture/accounts/{account}/findings", get(posture_handler))
        .route("/remote-shell/sessions", get(shell_list_handler))
        .route("/remote-shell/sessions/{id}", get(shell_detail_handler))
        .route("/vulnerabilities/findings", get(vuln_list_handler))
        .route("/vulnerabilities/assets/{asset}", get(vuln_asset_handler))
        .route("/oncall/alerts", get(oncall_list_handler))
        .route("/oncall/alerts/{id}", get(oncall_alert_handler))
        .route("/cases", get(cases_handler))
        .route("/cases/{id}", get(case_detail_handler))
        .route("/cases/{id}/actions", post(case_action_handler))
        .route("/cases/{id}/comments", post(case_comment_handler))
        .route("/cases/{id}/alerts", get(links_handler).post(link_handler))
        .route("/cases/{id}/observables", get(observables_handler).post(observable_handler))
        .layer(axum::middleware::from_fn_with_state(state.clone(), count_request))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, router).await });
    Ok(Stub { address, state })
}


pub const CERT_KEY_BITS: u32 = 2048;


pub const CERT_SHORT_FINGERPRINT: usize = 63;


pub const CERT_ROW_NAMES: usize = 30;


pub const CERT_PAIR: usize = 2;


pub const DHCP_HOSTILE_HOSTNAMES: [&str; 3] = ["evil\u{1b}[31m", "\u{3164}x", "<script>x</script>"];


pub const DHCP_HOSTILE_BYTES: usize = 10_000;


pub const LEASE_SUBNET: i64 = 7;


pub fn lease_item(address: &str, mac: Value, hostname: Value, starts: &str, action: &str) -> Value {
    json!({"address": address, "mac": mac, "hostname": hostname, "starts": starts, "ends": "2026-03-02T00:00:00Z", "action": action, "subnet_id": LEASE_SUBNET})
}


pub fn lease_good(hostname: &str) -> Value {
    lease_item(
        "10.0.0.5",
        json!("AA-BB-CC-DD-EE-FF"),
        json!(hostname),
        "2026-03-01T10:00:00+01:00",
        "lease-assigned",
    )
}


pub fn lease_refused_hostname() -> Value {
    json!({
        "address": "10.0.0.10", "mac": "AA-BB-CC-DD-EE-01", "hostname": null, "hostname_refused": true, "starts": "2026-03-01T00:00:00Z",
        "ends": "2026-03-02T00:00:00Z", "action": "lease-assigned", "subnet_id": LEASE_SUBNET
    })
}


pub fn dhcp_lookup(items: Vec<Value>, skipped: u32, truncated: bool) -> Value {
    json!({"intervals": items, "skipped": skipped, "truncated": truncated})
}


pub fn dhcp_hostile_items() -> Vec<Value> {
    let mut items: Vec<Value> = DHCP_HOSTILE_HOSTNAMES.iter().map(|name| lease_good(name)).collect();
    items.push(lease_good(&"a".repeat(DHCP_HOSTILE_BYTES)));
    items.push(lease_good("-x"));
    items.push(lease_item(
        "-x",
        json!("AA-BB-CC-DD-EE-FF"),
        json!("ok"),
        "2026-03-01T00:00:00Z",
        "lease-assigned",
    ));
    items.push(lease_item(
        "10.0.0.6",
        json!("evil"),
        json!("ok"),
        "2026-03-01T00:00:00Z",
        "lease-assigned",
    ));
    items.push(lease_item(
        "10.0.0.7",
        json!("AA-BB-CC-DD-EE-FF"),
        json!("ok"),
        "not a time",
        "lease-assigned",
    ));
    items.push(lease_item(
        "10.0.0.8",
        json!("AA-BB-CC-DD-EE-FF"),
        json!("fine"),
        "2026-03-01T00:00:00Z",
        "evil\u{1b}action",
    ));
    items
}


pub async fn dhcp_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.dhcp_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    if authorised(&headers) {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::TooMany => Json(dhcp_lookup((0..MANY_ITEMS).map(|_| lease_good("ok")).collect(), 0, false)).into_response(),
            Mode::Hostile => Json(dhcp_lookup(dhcp_hostile_items(), 1, false)).into_response(),
            Mode::BadCursor => Json(json!({"intervals": LEAK, "skipped": 0, "truncated": false})).into_response(),
            Mode::Chunked => Json(dhcp_lookup(vec![], 0, false)).into_response(),
            Mode::BadId => Json(dhcp_lookup(vec![], 1, false)).into_response(),
            Mode::BadSeverity => Json(dhcp_lookup(vec![], STATE_MANY_SKIPPED, false)).into_response(),
            _ => Json(dhcp_lookup(
                vec![
                    lease_good("host-1.example.com"),
                    lease_item("2001:db8::1", Value::Null, Value::Null, "2026-03-01T00:00:00Z", "lease-state-9"),
                    lease_item(
                        "10.0.0.9",
                        json!("aa:bb:cc:dd:ee:00"),
                        Value::Null,
                        "2026-03-01T00:00:00Z",
                        "lease-expired-reclaimed",
                    ),
                    lease_refused_hostname(),
                ],
                1,
                true,
            ))
            .into_response(),
        }
    } else {
        error_reply(StatusCode::UNAUTHORIZED)
    }
}


pub const POSTURE_CURSOR: &str = "run1 1772000000000000 4 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


pub const POSTURE_FINISHED_MICROS: i64 = 1_772_000_000_000_000;


pub const POSTURE_TIME_UNIX: i64 = 1_772_000_000;


pub const POSTURE_HOSTILE_BYTES: usize = 10_000;


pub const POSTURE_CUT: u64 = 12;


pub fn posture_item(check: &str, status: &str, severity: &str, title: &str, detail: &str) -> Value {
    json!({
        "uid": "prowler-k8s-uid", "check_id": check, "status": status, "severity": severity, "provider": "kubernetes", "account": "a",
        "region": "r", "resource_uid": "pod/web", "resource_type": "Pod", "time_unix": POSTURE_TIME_UNIX,
        "title": title, "title_cut": 0, "detail": detail, "detail_cut": POSTURE_CUT
    })
}


pub const POSTURE_UNSERVABLE: u32 = 2;


pub const POSTURE_REFUSED: u32 = 2;


pub const POSTURE_ITEMS: u32 = 3;


pub const POSTURE_BAD_FIELD: u32 = 4;


pub const POSTURE_DUPLICATE: u32 = 5;


pub const POSTURE_FOREIGN: u32 = 6;


pub fn posture_run() -> Value {
    posture_run_with(true, Value::Null)
}


pub fn posture_run_with(pending: bool, refused_micros: Value) -> Value {
    json!({
        "run_id": "run1", "finished_micros": POSTURE_FINISHED_MICROS, "refused_micros": refused_micros, "refused_items": POSTURE_REFUSED,
        "items": POSTURE_ITEMS, "unparsable": 0, "bad_field": POSTURE_BAD_FIELD, "duplicate": POSTURE_DUPLICATE,
        "foreign_account": POSTURE_FOREIGN, "refused_pass": 1, "refused_muted": 0, "refused_manual": 0, "refused_fail": 1,
        "store_refused": 0, "refusal_pending": pending
    })
}


pub fn posture_view(run: Value, items: Vec<Value>, unservable: u32, next: Value) -> Value {
    json!({"run": run, "unservable": unservable, "items": items, "next_cursor": next})
}


pub fn posture_worst_items(count: usize) -> Vec<Value> {
    let escaped = "\\u{1b}";
    let item = json!({
        "uid": escaped.repeat(POSTURE_UID_BYTES), "check_id": "worst", "status": "FAIL", "severity": "High", "provider": "kubernetes",
        "account": "a", "region": "r", "resource_uid": "pod/web", "resource_type": "Pod", "time_unix": POSTURE_TIME_UNIX,
        "title": escaped.repeat(POSTURE_TEXT_BYTES), "title_cut": 0, "detail": escaped.repeat(POSTURE_TEXT_BYTES), "detail_cut": 0
    });
    vec![item; count]
}


pub fn posture_hostile_items() -> Vec<Value> {
    vec![
        posture_item(
            "evil\u{1b}[31mcheck",
            "FAIL",
            "High",
            "t\u{1b}[31mitle \u{202e}rtl",
            "det\u{3164}ail <script>x</script>",
        ),
        posture_item("c2", "evil\u{1b}", "weird", "forged \\[12 bytes cut]", &"a".repeat(POSTURE_HOSTILE_BYTES)),
    ]
}


pub async fn posture_handler(State(state): State<Arc<StubState>>, headers: HeaderMap, Path(account): Path<String>, uri: axum::http::Uri) -> Response {
    note_forwarded(&state, &headers);
    state.posture_paths.lock().unwrap_or_else(PoisonError::into_inner).push(uri.to_string());
    let conflict = state.conflict.lock().unwrap_or_else(PoisonError::into_inner).clone();
    if !authorised(&headers) {
        error_reply(StatusCode::UNAUTHORIZED)
    } else if let Some(code) = conflict {
        conflict_reply(&code)
    } else {
        match mode_of(&state) {
            Mode::Status(status) => error_reply(status),
            Mode::Oversize => "x".repeat(OVERSIZE_BYTES).into_response(),
            Mode::PostureWorst => Json(posture_view(posture_run(), posture_worst_items(POSTURE_LIMIT), 0, json!(POSTURE_CURSOR))).into_response(),
            Mode::TooMany => Json(posture_view(
                posture_run(),
                (0..=POSTURE_LIMIT).map(|_| posture_item("c", "PASS", "Low", "t", "d")).collect(),
                0,
                Value::Null,
            ))
            .into_response(),
            Mode::Hostile => Json(posture_view(
                posture_run_with(false, json!(POSTURE_FINISHED_MICROS)),
                posture_hostile_items(),
                1,
                json!(POSTURE_CURSOR),
            ))
            .into_response(),
            Mode::BadCursor => Json(posture_view(posture_run(), vec![], 0, json!("bad cursor"))).into_response(),
            Mode::Chunked => Json(posture_view(Value::Null, vec![], 0, Value::Null)).into_response(),
            Mode::BadId => Json(posture_view(posture_run(), vec![], POSTURE_UNSERVABLE, Value::Null)).into_response(),
            Mode::BadSeverity => Json(json!({"run": posture_run(), "unservable": 0, "items": LEAK, "next_cursor": null})).into_response(),
            _ => Json(posture_view(
                posture_run(),
                vec![
                    posture_item("check-1", "FAIL", "Critical", "Title one", "Detail one"),
                    posture_item(&account, "PASS", "Informational", "Title two", "Detail two"),
                    posture_item("c3", "MANUAL", "Fatal", "t3", "d3"),
                ],
                POSTURE_UNSERVABLE,
                json!(POSTURE_CURSOR),
            ))
            .into_response(),
        }
    }
}
