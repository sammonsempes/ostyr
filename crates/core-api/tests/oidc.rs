#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/http.rs"]
mod http;
#[path = "support/limits.rs"]
mod limits;
#[path = "support/oidc_provider.rs"]
mod oidc_provider;
#[path = "support/oidc/types.rs"]
mod oidc_types;
#[path = "support/types.rs"]
mod types;


use arc_swap::ArcSwapOption;
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};
use core_api::config::{api_config, oidc_files};
use core_api::error::StartupError;
use core_api::model::{ApiError, ApiIdentity, ApiState, CallbackQuery, OidcFiles, OidcRuntime, StateInputs};
use core_api::oidc::{
    binding_cookie, binding_of, callback_flow, count_callback_failure, load_oidc, provider_agent, read_secret, start_flow, start_response,
    BINDING_COOKIE, PENDING_PER_SOURCE_MAX,
};
use core_api::routes::core_access;
use core_api::state::{build_state, build_state_from_files, lock_auth, refresh_accounts};
use core_audit::log::{new_log, sync_file};
use core_audit::model::GENESIS_HASH;
use core_auth::cli::read_key_file;
use core_auth::error::AuthError;
use core_auth::limiter::{account_key, source_key, SOURCE_MAX_FAILURES};
use core_auth::model::{Attempts, PendingLogin};
use core_auth::oidc::{http_call, PENDING_MAX};
use core_auth::random::os_random;
use core_auth::rbac::builtin_catalog;
use core_auth::session::mark_sessions_revoked;
use core_auth::store::{load_store_file, update_store_file};
use core_auth::types::RoleSet;
use core_config::model::ModuleConfig;
use fixture::{config_in, fixture, fixture_with, private_file, Fixture, PASSWORD, READER};
use http::{audit_lines, body_json, call, client, login_body, login_token, request, send, send_from};
use limits::with_limits;
use oidc_provider::{make_jwt, respond, CLIENT_ID, CLIENT_SECRET, ISSUER};
use oidc_types::TokenCell;
use openidconnect::http::Request;
use openidconnect::url::Url;
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use secrecy::SecretString;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{spawn, JoinHandle};
use std::time::Duration as StdDuration;
use tempfile::tempdir;
use time::{Duration, OffsetDateTime};
use tokio::sync::Notify;
use types::{TestError, TestResult};


const CONFIG_TEXT: &str = "issuer: https://idp.example\nclient_id: test-client\nclient_secret: vault://kv/oidc\nredirect_url: https://ostyr.example/auth/oidc/callback\nrole_map:\n  soc-analysts: [analyst]\n";


const ANALYST_GROUP: &str = "soc-analysts";


const TOKEN_TTL: i64 = 3600;


const OTHER_HOST: u32 = 8;


const FLOOD_REQUESTS: usize = 31;


const LIMITER_BUDGET: usize = 30;


const LOCKOUT_THRESHOLD: usize = 20;


const HOUR_SECONDS: i64 = 3600;


const SUBJECT: &str = "user-1";


const CLIENT_OFFSET: u8 = 1;


const LOCALHOST_NAME: &str = "localhost";


const REQUEST_BUFFER: usize = 4096;


const GROUP_READABLE: u32 = 0o644;


const NON_UTF8_BYTE: u8 = 255;


const EXPECTED_REFUSALS: usize = 2;


const FIXTURE_SOURCE: &str = "127.0.0.2";


struct Started {
    state: String,
    cookie: String,
    nonce: String,
}


fn runtime_over(
    config_text: &str,
    http: Box<dyn Fn(openidconnect::HttpRequest) -> Result<openidconnect::HttpResponse, io::Error> + Send + Sync>,
) -> Result<OidcRuntime, TestError> {
    Ok(OidcRuntime {
        fingerprint: "test".to_owned(),
        config: core_auth::oidc::parse_oidc_config(config_text, "oidc.yaml", &builtin_catalog())?,
        http,
        resolve: Box::new(|_| Ok(SecretString::from(CLIENT_SECRET))),
        pending: Mutex::new(Default::default()),
        generations: Default::default(),
        refresh: Default::default(),
    })
}


fn mock_runtime(cell: &TokenCell) -> Result<OidcRuntime, TestError> {
    let shared = cell.clone();
    runtime_over(CONFIG_TEXT, Box::new(move |request| respond(&shared, request)))
}


fn frozen_clock() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::seconds(HOUR_SECONDS)
}


fn oidc_fixture() -> Result<(Fixture, TokenCell), TestError> {
    let cell = TokenCell::default();
    let runtime = mock_runtime(&cell)?;
    let built = fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(runtime),
            ..state
        })
    })?;
    Ok((built, cell))
}


fn failing_http_fixture() -> Result<Fixture, TestError> {
    let runtime = runtime_over(CONFIG_TEXT, Box::new(|_| Err(io::Error::other("provider down"))))?;
    fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(runtime),
            ..state
        })
    })
}


fn pending_nonce(fx: &Fixture) -> Result<String, TestError> {
    let runtime = fx.state.oidc.load_full().ok_or("no oidc")?;
    let pending = runtime.pending.lock().map_err(|_| "poisoned")?;
    Ok(pending.values().next().ok_or("no pending login")?.nonce.clone())
}


async fn start_from(fx: &Fixture, offset: u8) -> Result<Started, TestError> {
    let response = send_from(&fx.router, client(offset), request("GET", "/auth/oidc/start", None, Body::empty())?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie_header = response.headers().get("set-cookie").ok_or("no cookie")?.to_str()?.to_owned();
    let cookie = cookie_header.split(';').next().ok_or("empty cookie")?.to_owned();
    let url = Url::parse(
        body_json(response)
            .await?
            .get("authorization_url")
            .and_then(Value::as_str)
            .ok_or("no url")?,
    )?;
    let state = url.query_pairs().find(|(name, _)| name == "state").ok_or("no state")?.1.into_owned();
    Ok(Started {
        state,
        cookie,
        nonce: pending_nonce(fx)?,
    })
}


async fn start(fx: &Fixture) -> Result<Started, TestError> {
    start_from(fx, CLIENT_OFFSET).await
}


fn set_identity(cell: &TokenCell, started: &Started, groups: &Value) -> TestResult {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({
        "iss": ISSUER,
        "aud": [CLIENT_ID],
        "sub": SUBJECT,
        "exp": now + TOKEN_TTL,
        "iat": now,
        "nonce": started.nonce,
        "groups": groups,
    });
    *cell.lock().map_err(|_| "poisoned")? = Some(make_jwt(&claims)?);
    Ok(())
}


async fn callback(fx: &Fixture, offset: u8, query: &str, cookie: Option<&str>) -> Result<axum::http::Response<Body>, TestError> {
    let mut built = request("GET", &format!("/auth/oidc/callback?{query}"), None, Body::empty())?;
    if let Some(value) = cookie {
        built.headers_mut().insert("cookie", HeaderValue::from_str(value)?);
    }
    send_from(&fx.router, client(offset), built).await
}


fn records(fx: &Fixture, action: &str) -> Result<Vec<Value>, TestError> {
    Ok(audit_lines(fx)?
        .into_iter()
        .filter(|line| line.pointer("/action").and_then(Value::as_str) == Some(action))
        .collect())
}


fn has_reason(fx: &Fixture, action: &str, reason: &str) -> Result<bool, TestError> {
    Ok(records(fx, action)?
        .iter()
        .any(|line| line.pointer("/parameters/reason").and_then(Value::as_str) == Some(reason)))
}


fn query_for(started: &Started) -> String {
    format!("code=abc&state={}", started.state)
}


#[tokio::test]
async fn start_returns_the_url_and_binds_the_browser() -> TestResult {
    let (fx, _) = oidc_fixture()?;
    let response = send(&fx.router, request("GET", "/auth/oidc/start", None, Body::empty())?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers().get("set-cookie").ok_or("no cookie")?.to_str()?.to_owned();
    for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=600", BINDING_COOKIE] {
        assert!(cookie.contains(attribute), "{cookie}");
    }
    let json = body_json(response).await?;
    let url = Url::parse(json.get("authorization_url").and_then(Value::as_str).ok_or("no url")?)?;
    let pairs: Vec<(String, String)> = url.query_pairs().map(|(name, value)| (name.into_owned(), value.into_owned())).collect();
    let state = pairs.iter().find(|(name, _)| name == "state").ok_or("no state")?.1.clone();
    assert!(cookie.contains(&binding_of(&state)));
    assert!(pairs.iter().any(|(name, value)| name == "code_challenge_method" && value == "S256"));
    assert_eq!(
        fx.state.oidc.load_full().ok_or("no oidc")?.pending.lock().map_err(|_| "poisoned")?.len(),
        1
    );
    assert_eq!(records(&fx, "api.request")?.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_full_login_creates_a_session_and_audits_once() -> TestResult {
    let (fx, cell) = oidc_fixture()?;
    let started = start(&fx).await?;
    set_identity(&cell, &started, &json!([ANALYST_GROUP]))?;
    let response = callback(&fx, CLIENT_OFFSET, &query_for(&started), Some(&started.cookie)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cleared = response.headers().get("set-cookie").ok_or("no cookie")?.to_str()?.to_owned();
    assert!(cleared.contains("Max-Age=0"));
    let token = body_json(response)
        .await?
        .get("token")
        .and_then(Value::as_str)
        .ok_or("no token")?
        .to_owned();
    let me = call(&fx.router, "GET", "/auth/me", Some(&token)).await?;
    assert_eq!(me.status(), StatusCode::OK);
    let profile = body_json(me).await?;
    assert_eq!(profile.get("username"), Some(&json!("oidc:user-1")));
    assert_eq!(records(&fx, "auth.login")?.len(), 1);
    assert_eq!(records(&fx, "authz.oidc.map")?.len(), 1);
    assert!(fx
        .state
        .oidc
        .load_full()
        .ok_or("no oidc")?
        .pending
        .lock()
        .map_err(|_| "poisoned")?
        .is_empty());
    Ok(())
}


async fn oidc_token(fx: &Fixture, cell: &TokenCell) -> Result<String, TestError> {
    let started = start(fx).await?;
    set_identity(cell, &started, &json!([ANALYST_GROUP]))?;
    let response = callback(fx, CLIENT_OFFSET, &query_for(&started), Some(&started.cookie)).await?;
    let body = body_json(response).await?;
    Ok(body.get("token").and_then(Value::as_str).ok_or("no token")?.to_owned())
}


#[tokio::test]
async fn an_oidc_session_survives_store_refreshes_and_local_logins() -> TestResult {
    let (fx, cell) = oidc_fixture()?;
    let token = oidc_token(&fx, &cell).await?;
    assert_eq!(call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(), StatusCode::OK);
    login_token(&fx.router).await?;
    assert_eq!(call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(), StatusCode::OK);
    assert!(!load_store_file(&fx.config.accounts_store)?.0.contains_key("oidc:user-1"));
    Ok(())
}


#[tokio::test]
async fn a_file_revocation_ends_an_oidc_session_and_a_new_login_works() -> TestResult {
    let (fx, cell) = oidc_fixture()?;
    let token = oidc_token(&fx, &cell).await?;
    update_store_file(&fx.config.accounts_store, os_random, |accounts, _| {
        mark_sessions_revoked(accounts, "oidc:user-1", OffsetDateTime::now_utc());
        Ok(())
    })?
    .saved?;
    assert_eq!(
        call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let fresh = oidc_token(&fx, &cell).await?;
    assert_eq!(call(&fx.router, "GET", "/auth/me", Some(&fresh)).await?.status(), StatusCode::OK);
    login_token(&fx.router).await?;
    assert_eq!(call(&fx.router, "GET", "/auth/me", Some(&fresh)).await?.status(), StatusCode::OK);
    assert!(load_store_file(&fx.config.accounts_store)?.0.contains_key("oidc:user-1"));
    Ok(())
}


#[tokio::test]
async fn a_session_of_an_account_deleted_from_the_file_is_refused_everywhere() -> TestResult {
    let fx = fixture()?;
    let token = login_token(&fx.router).await?;
    update_store_file(&fx.config.accounts_store, os_random, |accounts, _| {
        accounts.remove(READER);
        Ok(())
    })?
    .saved?;
    assert_eq!(
        call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&fx.router, "POST", "/auth/logout", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}


#[tokio::test]
async fn a_replayed_callback_is_refused_and_audited() -> TestResult {
    let (fx, cell) = oidc_fixture()?;
    let started = start(&fx).await?;
    set_identity(&cell, &started, &json!([ANALYST_GROUP]))?;
    let first = callback(&fx, CLIENT_OFFSET, &query_for(&started), Some(&started.cookie)).await?;
    assert_eq!(first.status(), StatusCode::OK);
    let replay = callback(&fx, CLIENT_OFFSET, &query_for(&started), Some(&started.cookie)).await?;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert!(has_reason(&fx, "auth.login", "bad_state")?);
    Ok(())
}


#[tokio::test]
async fn a_callback_without_or_with_a_foreign_binding_is_refused_and_keeps_the_login() -> TestResult {
    let (fx, cell) = oidc_fixture()?;
    let victim = start(&fx).await?;
    set_identity(&cell, &victim, &json!([ANALYST_GROUP]))?;
    let without = callback(&fx, CLIENT_OFFSET, &query_for(&victim), None).await?;
    assert_eq!(without.status(), StatusCode::UNAUTHORIZED);
    let foreign = format!("{BINDING_COOKIE}={}", binding_of("another state"));
    let other = callback(&fx, CLIENT_OFFSET, &query_for(&victim), Some(&foreign)).await?;
    assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(records(&fx, "auth.login")?.len(), EXPECTED_REFUSALS);
    assert!(has_reason(&fx, "auth.login", "bad_binding")?);
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.sessions.is_empty());
    let genuine = callback(&fx, CLIENT_OFFSET, &query_for(&victim), Some(&format!("other=1; {}", victim.cookie))).await?;
    assert_eq!(genuine.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn a_callback_flood_gets_429_without_audit_records() -> TestResult {
    let cell = TokenCell::default();
    let runtime = mock_runtime(&cell)?;
    let fx = fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(runtime),
            clock: frozen_clock,
            ..state
        })
    })?;
    let mut statuses = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..FLOOD_REQUESTS {
        statuses.push(callback(&fx, CLIENT_OFFSET, "code=abc&state=zzz", None).await?.status());
        sizes.push(audit_lines(&fx)?.len());
    }
    let (before_lock, after_lock) = statuses.split_at(LOCKOUT_THRESHOLD);
    assert!(before_lock.iter().all(|status| *status == StatusCode::UNAUTHORIZED));
    assert!(after_lock.iter().all(|status| *status == StatusCode::TOO_MANY_REQUESTS));
    assert!(has_reason(&fx, "auth.login", "locked")?);
    assert_eq!(records(&fx, "auth.lockout")?.len(), 1);
    let (limited, previous) = (sizes.get(LIMITER_BUDGET), sizes.get(LIMITER_BUDGET - 1));
    assert_eq!(limited, previous);
    assert!(limited.is_some());
    Ok(())
}


#[tokio::test]
async fn malformed_and_provider_error_callbacks_are_refused() -> TestResult {
    let (fx, _) = oidc_fixture()?;
    for (query, expected) in [
        ("state=only", StatusCode::BAD_REQUEST),
        ("code=only", StatusCode::BAD_REQUEST),
        ("", StatusCode::BAD_REQUEST),
        ("state=a&state=b", StatusCode::BAD_REQUEST),
        ("error=access_denied&state=a", StatusCode::UNAUTHORIZED),
    ] {
        assert_eq!(callback(&fx, CLIENT_OFFSET, query, None).await?.status(), expected, "{query}");
    }
    assert!(has_reason(&fx, "auth.login", "bad_request")?);
    assert!(has_reason(&fx, "auth.login", "provider_error")?);
    Ok(())
}


#[tokio::test]
async fn an_unmapped_user_is_refused_and_gets_no_session() -> TestResult {
    let (fx, cell) = oidc_fixture()?;
    let started = start(&fx).await?;
    set_identity(&cell, &started, &json!(["nobody"]))?;
    let response = callback(&fx, CLIENT_OFFSET, &query_for(&started), Some(&started.cookie)).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(has_reason(&fx, "auth.login", "unmapped")?);
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.sessions.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_token_response_without_an_id_token_is_refused() -> TestResult {
    let (fx, _) = oidc_fixture()?;
    let started = start(&fx).await?;
    let response = callback(&fx, CLIENT_OFFSET, &query_for(&started), Some(&started.cookie)).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(has_reason(&fx, "auth.login", "missing_id_token")?);
    Ok(())
}


#[tokio::test]
async fn routes_are_absent_without_configuration() -> TestResult {
    let fx = fixture()?;
    let start_reply = call(&fx.router, "GET", "/auth/oidc/start", None).await?;
    assert_eq!(start_reply.status(), StatusCode::UNAUTHORIZED);
    let callback_reply = call(&fx.router, "GET", "/auth/oidc/callback?code=a&state=b", None).await?;
    assert_eq!(callback_reply.status(), StatusCode::UNAUTHORIZED);
    let unconfigured_start = start_flow(&fx.state, "id-1", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    assert!(unconfigured_start.is_err());
    let query = CallbackQuery {
        state: Some("s".to_owned()),
        code: Some(SecretString::from("c")),
        error: None,
    };
    let binding = Some(binding_of("s"));
    let unconfigured_callback = callback_flow(&fx.state, "id-1", IpAddr::V4(Ipv4Addr::LOCALHOST), binding, Some(query)).await;
    assert!(unconfigured_callback.is_err());
    Ok(())
}


#[tokio::test]
async fn the_access_table_and_the_document_list_both_routes() -> TestResult {
    let access = core_access();
    assert!(access.contains_key("GET /auth/oidc/start"));
    assert!(access.contains_key("GET /auth/oidc/callback"));
    let (fx, _) = oidc_fixture()?;
    let document = body_json(call(&fx.router, "GET", "/openapi.json", None).await?).await?;
    assert!(document.pointer("/paths/~1auth~1oidc~1start/get").is_some());
    assert!(document.pointer("/paths/~1auth~1oidc~1callback/get").is_some());
    Ok(())
}


#[tokio::test]
async fn a_full_pending_table_refuses_starts_with_429() -> TestResult {
    let (fx, _) = oidc_fixture()?;
    {
        let runtime = fx.state.oidc.load_full().ok_or("no oidc")?;
        let mut pending = runtime.pending.lock().map_err(|_| "poisoned")?;
        (0..PENDING_MAX).for_each(|index| {
            pending.insert(
                format!("key-{index}"),
                PendingLogin {
                    nonce: "n".to_owned(),
                    verifier: SecretString::from("v"),
                    created_at: OffsetDateTime::now_utc(),
                    source: "other".to_owned(),
                },
            );
        });
    }
    let response = send(&fx.router, request("GET", "/auth/oidc/start", None, Body::empty())?).await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(has_reason(&fx, "auth.login", "too_many_pending")?);
    Ok(())
}


const HANG_GUARD: StdDuration = StdDuration::from_secs(120);


struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}


fn poisoned<Guard>(_error: std::sync::PoisonError<Guard>) -> io::Error {
    io::Error::other("gate poisoned")
}


fn new_gate() -> Arc<Gate> {
    Arc::new(Gate {
        open: Mutex::new(false),
        changed: Condvar::new(),
    })
}


fn open_gate(gate: &Gate) -> Result<(), io::Error> {
    *gate.open.lock().map_err(poisoned)? = true;
    gate.changed.notify_all();
    Ok(())
}


fn wait_open(gate: &Gate) -> Result<(), io::Error> {
    let guard = gate.open.lock().map_err(poisoned)?;
    let (_guard, result) = gate.changed.wait_timeout_while(guard, HANG_GUARD, |open| !*open).map_err(poisoned)?;
    if result.timed_out() {
        Err(io::Error::other("hang guard expired"))
    } else {
        Ok(())
    }
}


const STALL_CLIENTS: u8 = 8;


async fn status_of(router: axum::Router, offset: u8, target: String, cookie: Option<String>) -> Result<StatusCode, String> {
    let mut built = request("GET", &target, None, Body::empty()).map_err(|error| error.to_string())?;
    if let Some(value) = cookie {
        built
            .headers_mut()
            .insert("cookie", HeaderValue::from_str(&value).map_err(|error| error.to_string())?);
    }
    send_from(&router, client(offset), built)
        .await
        .map(|response| response.status())
        .map_err(|error| error.to_string())
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_provider_and_forged_callbacks_do_not_stall_the_api() -> TestResult {
    let cell = TokenCell::default();
    let released = new_gate();
    let arrivals = Arc::new(Notify::new());
    let provider_released = Arc::clone(&released);
    let provider_arrivals = Arc::clone(&arrivals);
    let runtime = runtime_over(
        CONFIG_TEXT,
        Box::new(move |request| {
            provider_arrivals.notify_one();
            wait_open(&provider_released)?;
            respond(&cell, request)
        }),
    )?;
    let fx = fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(runtime),
            ..state
        })
    })?;
    let starts = (1..=STALL_CLIENTS)
        .map(|offset| tokio::spawn(status_of(fx.router.clone(), offset, "/auth/oidc/start".to_owned(), None)))
        .collect::<Vec<_>>();
    tokio::time::timeout(HANG_GUARD, arrivals.notified()).await?;
    let forged = (1..=STALL_CLIENTS)
        .map(|offset| {
            let state = format!("forged-{offset}");
            let cookie = format!("{BINDING_COOKIE}={}", binding_of(&state));
            let target = format!("/auth/oidc/callback?state={state}&code=x");
            tokio::spawn(status_of(fx.router.clone(), offset + STALL_CLIENTS, target, Some(cookie)))
        })
        .collect::<Vec<_>>();
    let health = call(&fx.router, "GET", "/health", None).await?;
    assert_eq!(health.status(), StatusCode::OK);
    for handle in forged {
        assert_eq!(handle.await??, StatusCode::UNAUTHORIZED);
    }
    open_gate(&released)?;
    for handle in starts {
        assert_eq!(handle.await??, StatusCode::OK);
    }
    Ok(())
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_in_flight_during_an_identity_change_is_refused() -> TestResult {
    let cell = TokenCell::default();
    let held = Arc::new(AtomicBool::new(false));
    let released = new_gate();
    let arrivals = Arc::new(Notify::new());
    let (provider_held, provider_released, provider_arrivals, provider_cell) =
        (Arc::clone(&held), Arc::clone(&released), Arc::clone(&arrivals), cell.clone());
    let runtime = runtime_over(
        CONFIG_TEXT,
        Box::new(move |request| {
            if provider_held.load(Ordering::SeqCst) {
                provider_arrivals.notify_one();
                wait_open(&provider_released)?;
            }
            respond(&provider_cell, request)
        }),
    )?;
    let fx = fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(runtime),
            ..state
        })
    })?;
    let started = start(&fx).await?;
    set_identity(&cell, &started, &json!([ANALYST_GROUP]))?;
    held.store(true, Ordering::SeqCst);
    let target = format!("/auth/oidc/callback?{}", query_for(&started));
    let inflight = tokio::spawn(status_of(fx.router.clone(), CLIENT_OFFSET, target, Some(started.cookie.clone())));
    tokio::time::timeout(HANG_GUARD, arrivals.notified()).await?;
    let original = fx.state.identity.load_full();
    let away = ApiIdentity {
        tenant: "other-tenant".to_owned(),
        generation: original.generation + 1,
        ..(*original).clone()
    };
    let back = ApiIdentity {
        generation: away.generation + 1,
        ..(*original).clone()
    };
    fx.state.identity.store(Arc::new(away));
    fx.state.identity.store(Arc::new(back));
    open_gate(&released)?;
    assert_eq!(inflight.await??, StatusCode::UNAUTHORIZED);
    assert!(has_reason(&fx, "auth.login", "identity_changed")?);
    assert!(lock_auth(&fx.state).sessions.is_empty());
    Ok(())
}


#[tokio::test]
async fn an_unreachable_provider_is_a_502_at_start() -> TestResult {
    let fx = failing_http_fixture()?;
    let response = send(&fx.router, request("GET", "/auth/oidc/start", None, Body::empty())?).await?;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_json(response).await?.pointer("/error/code"), Some(&json!("bad_gateway")));
    assert!(has_reason(&fx, "auth.login", "provider_error")?);
    Ok(())
}


fn panicking_http(_request: openidconnect::HttpRequest) -> Result<openidconnect::HttpResponse, io::Error> {
    let zero = std::hint::black_box(u32::MIN);
    Err(io::Error::other(format!("{}", 1 / zero)))
}


#[tokio::test]
async fn a_panicking_provider_call_is_contained() -> TestResult {
    let runtime = runtime_over(CONFIG_TEXT, Box::new(panicking_http))?;
    let fx = fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(runtime),
            ..state
        })
    })?;
    let response = send(&fx.router, request("GET", "/auth/oidc/start", None, Body::empty())?).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let (cell, armed) = (TokenCell::default(), Arc::new(Mutex::new(false)));
    let (shared, flag) = (cell.clone(), armed.clone());
    let switching = runtime_over(
        CONFIG_TEXT,
        Box::new(move |request| match flag.lock() {
            Ok(guard) if *guard => panicking_http(request),
            _ => respond(&shared, request),
        }),
    )?;
    let second = fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(switching),
            ..state
        })
    })?;
    let started = start(&second).await?;
    *armed.lock().map_err(|_| "poisoned")? = true;
    let reply = callback(&second, CLIENT_OFFSET, &query_for(&started), Some(&started.cookie)).await?;
    assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
    assert!(has_reason(&second, "auth.login", "provider_error")?);
    Ok(())
}


#[tokio::test]
async fn a_locked_source_and_a_full_table_are_refused_before_any_exchange() -> TestResult {
    let (fx, _) = oidc_fixture()?;
    let until = OffsetDateTime::now_utc() + Duration::seconds(HOUR_SECONDS);
    fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.insert(
        source_key(FIXTURE_SOURCE),
        Attempts {
            failures: Vec::new(),
            locked_until: Some(until),
        },
    );
    let locked = callback(&fx, CLIENT_OFFSET, "code=a&state=b", None).await?;
    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(has_reason(&fx, "auth.login", "locked")?);
    let runtime = mock_runtime(&TokenCell::default())?;
    let full = fixture_with(move |state| {
        Ok(ApiState {
            oidc: ArcSwapOption::from_pointee(runtime),
            ..with_limits(state, |limits| limits.max_attempts = 0)
        })
    })?;
    let refused = callback(&full, CLIENT_OFFSET, "code=a&state=b", None).await?;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(has_reason(&full, "auth.login", "table_full")?);
    Ok(())
}


#[tokio::test]
async fn failures_are_counted_only_while_the_table_has_room() -> TestResult {
    let roomy = fixture()?;
    (0..SOURCE_MAX_FAILURES).for_each(|_| count_callback_failure(&roomy.state, "id-1", FIXTURE_SOURCE));
    assert_eq!(records(&roomy, "auth.lockout")?.len(), 1);
    let full = fixture_with(|state| Ok(with_limits(state, |limits| limits.max_attempts = 1)))?;
    count_callback_failure(&full.state, "id-1", FIXTURE_SOURCE);
    assert!(full.state.auth.lock().map_err(|_| "poisoned")?.attempts.is_empty());
    Ok(())
}


#[tokio::test]
async fn the_failure_table_is_shared_with_login() -> TestResult {
    let (fx, _) = oidc_fixture()?;
    callback(&fx, CLIENT_OFFSET, "code=a&state=b", None).await?;
    let keys: Vec<String> = fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.keys().cloned().collect();
    assert_eq!(keys, [source_key(FIXTURE_SOURCE)]);
    assert!(!keys.contains(&account_key(READER)));
    Ok(())
}


#[test]
fn the_binding_cookie_is_read_among_others() -> TestResult {
    let mut headers = axum::http::HeaderMap::new();
    assert_eq!(binding_cookie(&headers), None);
    headers.append("cookie", HeaderValue::from_static("a=1; __Host-oidc_binding=abc"));
    headers.append("cookie", HeaderValue::from_bytes(&[NON_UTF8_BYTE])?);
    assert_eq!(binding_cookie(&headers), Some("abc".to_owned()));
    Ok(())
}


#[test]
fn a_start_response_needs_a_valid_url_with_a_state() -> TestResult {
    assert!(start_response("not a url").is_err());
    assert!(start_response("https://idp.example/authorize?code=1").is_err());
    assert!(start_response("https://idp.example/authorize?state=1").is_ok());
    Ok(())
}


fn module_with(settings: &[(&str, &str)]) -> ModuleConfig {
    ModuleConfig {
        name: "example".to_owned(),
        version: "1.0.0".to_owned(),
        tenant: None,
        listen: Some("127.0.0.1:0".to_owned()),
        secrets: Default::default(),
        settings: settings.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect(),
    }
}


#[test]
fn oidc_settings_come_in_a_pair() -> TestResult {
    assert_eq!(oidc_files(&module_with(&[]))?, None);
    let both = oidc_files(&module_with(&[("oidc", "/etc/oidc.yaml"), ("oidc_secret_file", "/etc/secret")]))?;
    assert_eq!(both.as_ref().map(|files| files.ca_file.clone()), Some(None));
    let with_ca = oidc_files(&module_with(&[("oidc", "a"), ("oidc_secret_file", "b"), ("oidc_ca_file", "c")]))?;
    assert_eq!(with_ca.and_then(|files| files.ca_file), Some("c".into()));
    assert!(matches!(oidc_files(&module_with(&[("oidc", "a")])), Err(StartupError::IncompleteOidc)));
    assert!(matches!(
        oidc_files(&module_with(&[("oidc_secret_file", "b")])),
        Err(StartupError::IncompleteOidc)
    ));
    let required = [
        ("accounts_store", "/x/a.json"),
        ("audit_log", "/x/a.log"),
        ("key_file", "/x/k"),
        ("compromised_list", "/x/c"),
    ];
    let settings: Vec<(&str, &str)> = required
        .iter()
        .copied()
        .chain([("oidc", "/x/o.yaml"), ("oidc_secret_file", "/x/s")])
        .collect();
    assert!(api_config(&module_with(&settings))?.oidc.is_some());
    Ok(())
}


#[test]
fn the_client_secret_file_must_be_private() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("secret");
    assert!(read_secret(&path).is_err());
    private_file(&path, b"s3cret\n")?;
    let secret = read_secret(&path)?;
    assert_eq!(secrecy::ExposeSecret::expose_secret(&secret), "s3cret");
    fixture::set_mode(&path, GROUP_READABLE)?;
    assert_eq!(read_secret(&path).is_err(), cfg!(unix));
    Ok(())
}


fn oidc_files_in(dir: &Path, config_text: &str) -> Result<OidcFiles, TestError> {
    let config = dir.join("oidc.yaml");
    fs::write(&config, config_text)?;
    let secret_file = dir.join("oidc.secret");
    private_file(&secret_file, CLIENT_SECRET.as_bytes())?;
    Ok(OidcFiles {
        config,
        ca_file: None,
        secret_file,
    })
}


#[test]
fn the_module_starts_with_or_without_oidc() -> TestResult {
    let dir = tempdir()?;
    let mut config = config_in(&dir)?;
    assert!(build_state_from_files(&config, Default::default(), Vec::new())?.oidc.load().is_none());
    config.oidc = Some(oidc_files_in(dir.path(), CONFIG_TEXT)?);
    let state = build_state_from_files(&config, Default::default(), Vec::new())?;
    let runtime = state.oidc.load_full().ok_or("no oidc")?;
    assert_eq!(runtime.config.client_id, CLIENT_ID);
    let secret = (runtime.resolve)(&runtime.config.client_secret)?;
    assert_eq!(secrecy::ExposeSecret::expose_secret(&secret), CLIENT_SECRET);
    let unreachable = Request::builder().uri("https://127.0.0.1:1/").body(Vec::new())?;
    assert!((runtime.http)(unreachable).is_err());
    Ok(())
}


#[test]
fn the_state_keeps_the_key_list_and_runtime_it_is_handed() -> TestResult {
    let dir = tempdir()?;
    let mut config = config_in(&dir)?;
    config.oidc = Some(oidc_files_in(dir.path(), CONFIG_TEXT)?);
    let runtime = Arc::new(runtime_over(CONFIG_TEXT, Box::new(panicking_http))?);
    let inputs = StateInputs {
        key: Arc::new(read_key_file(&config.key_file)?),
        compromised: Arc::new(Default::default()),
        oidc: Some(runtime.clone()),
    };
    let state = build_state(&config, &inputs, Default::default(), Vec::new())?;
    assert!(Arc::ptr_eq(&state.key.load_full(), &inputs.key));
    assert!(Arc::ptr_eq(&state.compromised.load_full(), &inputs.compromised));
    assert!(state.oidc.load_full().is_some_and(|held| Arc::ptr_eq(&held, &runtime)));
    Ok(())
}


#[test]
fn a_bad_oidc_configuration_stops_the_module() -> TestResult {
    let dir = tempdir()?;
    let mut config = config_in(&dir)?;
    let insecure = CONFIG_TEXT.replace("https://idp.example", "http://idp.example");
    config.oidc = Some(oidc_files_in(dir.path(), &insecure)?);
    assert!(matches!(
        build_state_from_files(&config, Default::default(), Vec::new()),
        Err(StartupError::Auth(_))
    ));
    config.oidc = Some(OidcFiles {
        config: dir.path().join("missing.yaml"),
        ca_file: None,
        secret_file: dir.path().join("oidc.secret"),
    });
    assert!(matches!(
        load_oidc(config.oidc.as_ref().ok_or("none")?, &builtin_catalog()),
        Err(StartupError::Io(_))
    ));
    Ok(())
}


fn serve_tls_once(certificate: &str, key: &str) -> Result<(u16, JoinHandle<Result<usize, io::Error>>), TestError> {
    let certificates = CertificateDer::pem_slice_iter(certificate.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let private = PrivateKeyDer::from_pem_slice(key.as_bytes())?;
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificates, private)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let handle = spawn(move || {
        let (stream, _) = listener.accept()?;
        let mut tls = StreamOwned::new(ServerConnection::new(Arc::new(config)).map_err(io::Error::other)?, stream);
        let mut buffer = [u8::MIN; REQUEST_BUFFER];
        let received = tls.read(&mut buffer)?;
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")?;
        tls.flush().map(|()| received)
    });
    Ok((port, handle))
}


fn fetch_over_tls(ca_pem: &str, certificate: &str, key: &str) -> Result<(bool, Result<usize, io::Error>), TestError> {
    let (port, server) = serve_tls_once(certificate, key)?;
    let agent = provider_agent(Some(ca_pem.as_bytes()))?;
    let target = Request::builder().uri(format!("https://{LOCALHOST_NAME}:{port}/")).body(Vec::new())?;
    let reached = http_call(&agent, target).is_ok();
    let served = server.join().map_err(|_| "server thread panicked")?;
    Ok((reached, served))
}


#[test]
fn the_provider_certificate_is_checked_against_the_configured_ca() -> TestResult {
    let generated = generate_simple_self_signed(vec![LOCALHOST_NAME.to_owned()])?;
    let (certificate, key) = (generated.cert.pem(), generated.signing_key.serialize_pem());
    let (trusted, served) = fetch_over_tls(&certificate, &certificate, &key)?;
    assert!(trusted);
    assert!(served.is_ok());
    let stranger = generate_simple_self_signed(vec![LOCALHOST_NAME.to_owned()])?;
    let (refused, _) = fetch_over_tls(&stranger.cert.pem(), &certificate, &key)?;
    assert!(!refused);
    Ok(())
}


#[test]
fn a_missing_or_invalid_ca_file_is_a_startup_error() -> TestResult {
    let dir = tempdir()?;
    let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    assert!(provider_agent(Some(broken.as_bytes())).is_err());
    let missing = OidcFiles {
        config: dir.path().join("oidc.yaml"),
        ca_file: Some(dir.path().join("missing.pem")),
        secret_file: dir.path().join("oidc.secret"),
    };
    fs::write(&missing.config, CONFIG_TEXT)?;
    private_file(&missing.secret_file, b"secret")?;
    assert!(matches!(load_oidc(&missing, &builtin_catalog()), Err(StartupError::Io(_))));
    assert!(provider_agent(None).is_ok());
    Ok(())
}


fn panicking_verify(_password: &str, _stored: &str) -> Result<bool, AuthError> {
    let zero = std::hint::black_box(u32::MIN);
    Ok(1 / zero == 0)
}


fn failing_verify(_password: &str, _stored: &str) -> Result<bool, AuthError> {
    Err(AuthError::Decrypt)
}


async fn login_with(adjust: impl FnOnce(ApiState) -> Result<ApiState, TestError>) -> Result<(StatusCode, Fixture), TestError> {
    let fx = fixture_with(adjust)?;
    let response = send(&fx.router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    Ok((response.status(), fx))
}


async fn audited_refusal(adjust: impl FnOnce(ApiState) -> Result<ApiState, TestError>, expected: StatusCode) -> TestResult {
    let (status, fx) = login_with(adjust).await?;
    assert_eq!(status, expected);
    assert!(has_reason(&fx, "auth.login", "internal_error")?);
    assert!(fx.dir.path().exists());
    Ok(())
}


#[tokio::test]
async fn a_failing_verification_is_audited() -> TestResult {
    audited_refusal(
        |state| {
            Ok(ApiState {
                verify: failing_verify,
                ..state
            })
        },
        StatusCode::UNAUTHORIZED,
    )
    .await
}


#[tokio::test]
async fn a_panicking_verification_is_audited() -> TestResult {
    audited_refusal(
        |state| {
            Ok(ApiState {
                verify: panicking_verify,
                ..state
            })
        },
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await
}


#[tokio::test]
async fn a_closed_hashing_gate_is_audited() -> TestResult {
    audited_refusal(
        |state| {
            state.hashing.close();
            Ok(state)
        },
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await
}


#[tokio::test]
async fn a_login_token_still_opens_a_session() -> TestResult {
    let fx = fixture()?;
    let token = http::login_token(&fx.router).await?;
    assert_eq!(call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(), StatusCode::OK);
    Ok(())
}


fn silent_audit_fixture() -> Result<Fixture, TestError> {
    let runtime = mock_runtime(&TokenCell::default())?;
    fixture_with(move |state| {
        Ok(ApiState {
            audit: new_log(fs::File::open("/dev/null")?, GENESIS_HASH, sync_file),
            oidc: ArcSwapOption::from_pointee(runtime),
            ..state
        })
    })
}


#[tokio::test]
async fn an_audit_failure_on_a_refusal_fails_closed() -> TestResult {
    let fx = silent_audit_fixture()?;
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let malformed = callback_flow(&fx.state, "id-1", peer, None, None).await;
    assert!(matches!(malformed, Err(ApiError::Internal)));
    let provider_error = CallbackQuery {
        state: None,
        code: None,
        error: Some("access_denied".to_owned()),
    };
    let refused = callback_flow(&fx.state, "id-2", peer, None, Some(provider_error)).await;
    assert!(matches!(refused, Err(ApiError::Internal)));
    {
        let runtime = fx.state.oidc.load_full().ok_or("no oidc")?;
        let mut pending = runtime.pending.lock().map_err(|_| "poisoned")?;
        (0..PENDING_MAX).for_each(|index| {
            pending.insert(
                format!("key-{index}"),
                PendingLogin {
                    nonce: "n".to_owned(),
                    verifier: SecretString::from("v"),
                    created_at: OffsetDateTime::now_utc(),
                    source: "other".to_owned(),
                },
            );
        });
    }
    let full = start_flow(&fx.state, "id-4", peer).await;
    assert!(matches!(full, Err(ApiError::Internal)));
    (0..SOURCE_MAX_FAILURES).for_each(|_| count_callback_failure(&fx.state, "id-3", FIXTURE_SOURCE));
    let attempts = fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.clone();
    assert!(attempts
        .get(&source_key(FIXTURE_SOURCE))
        .is_some_and(|entry| entry.locked_until.is_some()));
    Ok(())
}


#[tokio::test]
async fn one_source_cannot_fill_the_pending_table() -> TestResult {
    let (fx, _) = oidc_fixture()?;
    {
        let runtime = fx.state.oidc.load_full().ok_or("no oidc")?;
        let mut pending = runtime.pending.lock().map_err(|_| "poisoned")?;
        (0..PENDING_PER_SOURCE_MAX).for_each(|index| {
            pending.insert(
                format!("key-{index}"),
                PendingLogin {
                    nonce: "n".to_owned(),
                    verifier: SecretString::from("v"),
                    created_at: OffsetDateTime::now_utc(),
                    source: "127.0.0.1".to_owned(),
                },
            );
        });
    }
    let full = start_flow(&fx.state, "id-1", IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    assert!(matches!(full, Err(ApiError::TooManyRequests)));
    assert!(has_reason(&fx, "auth.login", "too_many_pending")?);
    let other = start_flow(
        &fx.state,
        "id-2",
        IpAddr::V4(Ipv4Addr::LOCALHOST.to_bits().wrapping_add(OTHER_HOST).into()),
    )
    .await;
    assert!(other.is_ok());
    Ok(())
}


#[tokio::test]
async fn an_oidc_account_deleted_from_the_file_is_dropped_unless_a_callback_made_it() -> TestResult {
    let (fx, cell) = oidc_fixture()?;
    let token = oidc_token(&fx, &cell).await?;
    let ghost = core_auth::model::Account {
        username: "oidc:ghost".to_owned(),
        password_hash: core_auth::oidc::EXTERNAL_PASSWORD_HASH.to_owned(),
        roles: RoleSet::new(),
        totp: None,
        sessions_valid_after: None,
    };
    {
        let mut auth = fx.state.auth.lock().map_err(|_| "poisoned")?;
        auth.accounts.insert("oidc:ghost".to_owned(), ghost);
        refresh_accounts(&fx.state, &mut auth)?;
        assert!(auth.accounts.contains_key("oidc:user-1"));
        assert!(!auth.accounts.contains_key("oidc:ghost"));
    }
    assert_eq!(call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(), StatusCode::OK);
    Ok(())
}
