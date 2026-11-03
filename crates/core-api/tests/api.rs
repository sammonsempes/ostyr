#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/http.rs"]
mod http;
#[path = "support/logging.rs"]
mod logging;
#[path = "support/types.rs"]
mod types;


use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode};
use core_api::example::{example_document, PING_REPLY};
use core_api::failure::{auth_failure, error_parts};
use core_api::middleware::{admit_source, count_request, rate_key, SECURITY_HEADERS};
use core_api::model::Window;
use core_api::model::{ApiError, ApiState};
use core_api::routes::{admit_login, commit_login, core_access, BODY_LIMIT_BYTES};
use core_api::state::{prune_attempts, MAX_CONCURRENT_HASHES, RATE_MAX_REQUESTS, RATE_WINDOW_SECONDS};
use core_audit::log::{new_log, sync_file};
use core_audit::model::GENESIS_HASH;
use core_audit::verify::verify;
use core_auth::error::AuthError;
use core_auth::limiter::{FAILURE_WINDOW_SECONDS, LOCKOUT_SECONDS};
use core_auth::model::Attempts;
use core_auth::random::os_random;
use core_auth::service::LoginRequest;
use core_auth::session::create_session;
use fixture::{fixture, fixture_with, PASSWORD, READER};
use http::{audit_lines, body_json, call, client, login_body, login_token, request, send, send_from};
use logging::capture_dispatch;
use secrecy::SecretString;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;
use time::OffsetDateTime;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use types::{TestError, TestResult};


const GENERATED_ID_CHARS: usize = 32;


const TOO_LONG_ID_CHARS: usize = 65;


const FAILURES_BEFORE_LOCK: usize = 5;


const EXTRA_REQUESTS: usize = 10;


const EXPECTED_EVENTS: usize = 3;


const OTHER_SOURCE: u8 = 2;


const AUDIT_SIZE_LIMIT: u64 = 600;


fn failing_random(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


fn broken_random(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        random: failing_random,
        ..state
    })
}


fn read_only_audit(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        audit: new_log(File::open("/dev/null")?, GENESIS_HASH, sync_file),
        ..state
    })
}


fn short_sync(file: &mut File) -> io::Result<()> {
    if file.metadata()?.len() > AUDIT_SIZE_LIMIT {
        Err(io::Error::other("audit device full"))
    } else {
        Ok(())
    }
}


fn two_record_audit(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        audit: new_log(tempfile::tempfile()?, GENESIS_HASH, short_sync),
        store_path: PathBuf::from("/nonexistent-directory/accounts.json"),
        ..state
    })
}


fn unwritable_store(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        store_path: PathBuf::from("/nonexistent-directory/accounts.json"),
        ..state
    })
}


#[tokio::test]
async fn health_is_public_and_hardened() -> TestResult {
    let fx = fixture()?;
    assert!(fx.dir.path().exists());
    let response = call(&fx.router, "GET", "/health", None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    SECURITY_HEADERS
        .iter()
        .for_each(|(name, value)| assert_eq!(response.headers().get(name), Some(value)));
    let id = response.headers().get("x-request-id").ok_or("no request id")?.to_str()?.to_owned();
    assert_eq!(id.len(), GENERATED_ID_CHARS);
    assert_eq!(body_json(response).await?, json!({ "status": "ok" }));
    Ok(())
}


#[tokio::test]
async fn request_ids_are_propagated_or_replaced() -> TestResult {
    let fx = fixture()?;
    let valid = send(&fx.router, request("GET", "/health", None, Body::empty())?).await?;
    assert!(valid.headers().contains_key("x-request-id"));
    let long_id = "a".repeat(TOO_LONG_ID_CHARS);
    let invalid_bytes = HeaderValue::from_bytes(b"\xff\xfe")?;
    let propagated = [("trace-42_A", true), ("bad id", false), ("", false), (long_id.as_str(), false)];
    for (sent, kept) in propagated {
        let mut built = request("GET", "/health", None, Body::empty())?;
        built.headers_mut().insert("x-request-id", HeaderValue::from_str(sent)?);
        let response = send(&fx.router, built).await?;
        let received = response.headers().get("x-request-id").ok_or("no request id")?.to_str()?.to_owned();
        assert_eq!(received == sent, kept);
    }
    let mut binary = request("GET", "/health", None, Body::empty())?;
    binary.headers_mut().insert("x-request-id", invalid_bytes);
    let response = send(&fx.router, binary).await?;
    assert_eq!(response.headers().get("x-request-id").ok_or("no request id")?.len(), GENERATED_ID_CHARS);
    Ok(())
}


#[tokio::test]
async fn request_id_failure_is_a_generic_error_with_headers() -> TestResult {
    let fx = fixture_with(broken_random)?;
    let response = call(&fx.router, "GET", "/health", None).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers().get("x-request-id"), Some(&HeaderValue::from_static("unavailable")));
    assert!(response.headers().contains_key("strict-transport-security"));
    let mut identified = request("GET", "/health", None, Body::empty())?;
    identified.headers_mut().insert("x-request-id", HeaderValue::from_static("given"));
    assert_eq!(send(&fx.router, identified).await?.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn login_me_logout_cycle() -> TestResult {
    let fx = fixture()?;
    let token = login_token(&fx.router).await?;
    let me = call(&fx.router, "GET", "/auth/me", Some(&token)).await?;
    assert_eq!(me.status(), StatusCode::OK);
    assert_eq!(
        body_json(me).await?,
        json!({ "username": READER, "roles": ["reader"], "mfa_enrolled": false })
    );
    let stored = fs::read_to_string(&fx.config.accounts_store)?;
    assert!(stored.contains(READER));
    assert_eq!(
        call(&fx.router, "POST", "/auth/logout", Some(&token)).await?.status(),
        StatusCode::NO_CONTENT
    );
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
async fn me_for_a_vanished_account_is_unauthorised() -> TestResult {
    let fx = fixture()?;
    let token = login_token(&fx.router).await?;
    fx.state.auth.lock().map_err(|_| "poisoned")?.accounts.remove(READER);
    assert_eq!(
        call(&fx.router, "GET", "/auth/me", Some(&token)).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}


#[tokio::test]
async fn bad_credentials_look_alike_and_lock_out() -> TestResult {
    let fx = fixture()?;
    let wrong = send(
        &fx.router,
        request("POST", "/auth/login", None, login_body(READER, "wrong password here"))?,
    )
    .await?;
    let unknown = send(&fx.router, request("POST", "/auth/login", None, login_body("nobody", PASSWORD))?).await?;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    let wrong_body = body_json(wrong).await?;
    assert_eq!(wrong_body, body_json(unknown).await?);
    assert_eq!(
        wrong_body,
        json!({ "error": { "code": "invalid_credentials", "message": "invalid credentials" } })
    );
    for _ in 1..FAILURES_BEFORE_LOCK {
        send(
            &fx.router,
            request("POST", "/auth/login", None, login_body(READER, "still wrong password"))?,
        )
        .await?;
    }
    for _ in 0..FAILURES_BEFORE_LOCK {
        send(
            &fx.router,
            request("POST", "/auth/login", None, login_body("nobody", "still wrong password"))?,
        )
        .await?;
    }
    let locked = send(&fx.router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    let unknown_after = send(&fx.router, request("POST", "/auth/login", None, login_body("nobody", PASSWORD))?).await?;
    assert_eq!(locked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_after.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(locked).await?, wrong_body);
    assert_eq!(body_json(unknown_after).await?, wrong_body);
    let locked_records = audit_lines(&fx)?
        .into_iter()
        .filter(|line| line.pointer("/parameters/reason") == Some(&json!("locked")))
        .count();
    assert_eq!(locked_records, 1);
    Ok(())
}


#[tokio::test]
async fn malformed_login_bodies_are_bad_requests() -> TestResult {
    let fx = fixture()?;
    let bodies = ["not json", r#"{"username":"a","password":"b","extra":1}"#, r#"{"username":"a"}"#];
    for body in bodies {
        let response = send(&fx.router, request("POST", "/auth/login", None, Body::from(body))?).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(response).await?.pointer("/error/code"), Some(&json!("bad_request")));
    }
    let broken = Body::from_stream(tokio_stream::iter(vec![Ok(Bytes::from("{")), Err(io::Error::other("connection reset"))]));
    let response = send(&fx.router, request("POST", "/auth/login", None, broken)?).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}


#[tokio::test]
async fn oversized_bodies_are_refused() -> TestResult {
    let fx = fixture()?;
    let sized = Body::from(vec![b'a'; BODY_LIMIT_BYTES + 1]);
    let response = send(&fx.router, request("POST", "/auth/login", None, sized)?).await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_json(response).await?.pointer("/error/code"), Some(&json!("payload_too_large")));
    let chunk = Bytes::from(vec![b'a'; BODY_LIMIT_BYTES]);
    let streamed = Body::from_stream(tokio_stream::iter(vec![Ok::<_, io::Error>(chunk.clone()), Ok(chunk)]));
    let chunked = send(&fx.router, request("POST", "/auth/login", None, streamed)?).await?;
    assert_eq!(chunked.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}


#[tokio::test]
async fn deny_by_default_and_permission_checks() -> TestResult {
    let fx = fixture()?;
    let anonymous = [
        ("GET", "/auth/me"),
        ("POST", "/auth/logout"),
        ("GET", "/example/events"),
        ("GET", "/example/secret"),
        ("GET", "/nowhere"),
        ("PUT", "/auth/me"),
        ("HEAD", "/health"),
    ];
    for (method, path) in anonymous {
        let response = call(&fx.router, method, path, None).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    let forged = call(&fx.router, "GET", "/auth/me", Some("forged-token")).await?;
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(forged).await?,
        json!({ "error": { "code": "unauthorized", "message": "authentication is required" } })
    );
    let token = login_token(&fx.router).await?;
    let allowed = [
        ("GET", "/example/events", StatusCode::OK),
        ("POST", "/example/change", StatusCode::OK),
        ("GET", "/example/secret", StatusCode::FORBIDDEN),
        ("GET", "/nowhere", StatusCode::FORBIDDEN),
        ("PUT", "/auth/me", StatusCode::FORBIDDEN),
    ];
    for (method, path, expected) in allowed {
        let response = call(&fx.router, method, path, Some(&token)).await?;
        assert_eq!(response.status(), expected, "{method} {path}");
    }
    Ok(())
}


#[tokio::test]
async fn rate_limit_is_per_source() -> TestResult {
    let fx = fixture()?;
    let total = usize::try_from(RATE_MAX_REQUESTS)? + EXTRA_REQUESTS;
    let mut statuses = Vec::new();
    for _ in 0..total {
        statuses.push(call(&fx.router, "GET", "/health", None).await?.status());
    }
    assert_eq!(statuses.first(), Some(&StatusCode::OK));
    assert_eq!(statuses.last(), Some(&StatusCode::TOO_MANY_REQUESTS));
    let limited = call(&fx.router, "GET", "/health", None).await?;
    assert!(limited.headers().contains_key("x-content-type-options"));
    assert_eq!(body_json(limited).await?.pointer("/error/code"), Some(&json!("too_many_requests")));
    let other = send_from(&fx.router, client(OTHER_SOURCE), request("GET", "/health", None, Body::empty())?).await?;
    assert_eq!(other.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test]
async fn openapi_documents_every_route() -> TestResult {
    let fx = fixture()?;
    let response = call(&fx.router, "GET", "/openapi.json", None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let document = body_json(response).await?;
    assert!(document
        .get("openapi")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|version| version.starts_with('3')));
    assert_eq!(document.pointer("/info/title"), Some(&json!("example API")));
    assert!(document.pointer("/components/securitySchemes/bearer").is_some());
    let documented: BTreeSet<String> = document
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .ok_or("no paths")?
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .into_iter()
                .flat_map(|methods| methods.keys().map(|method| format!("{} {path}", method.to_uppercase())))
                .collect::<Vec<_>>()
        })
        .collect();
    let routed: BTreeSet<String> = core_access().into_keys().chain(["GET /example/ping".to_owned()]).collect();
    assert_eq!(documented, routed);
    Ok(())
}


#[tokio::test]
async fn cors_is_closed() -> TestResult {
    let fx = fixture()?;
    let mut preflight = request("OPTIONS", "/auth/me", None, Body::empty())?;
    preflight.headers_mut().insert("origin", HeaderValue::from_static("https://evil.example"));
    preflight
        .headers_mut()
        .insert("access-control-request-method", HeaderValue::from_static("GET"));
    let response = send(&fx.router, preflight).await?;
    assert!(response.headers().keys().all(|name| !name.as_str().starts_with("access-control-")));
    let mut cross = request("GET", "/health", None, Body::empty())?;
    cross.headers_mut().insert("origin", HeaderValue::from_static("https://evil.example"));
    let simple = send(&fx.router, cross).await?;
    assert!(!simple.headers().contains_key("access-control-allow-origin"));
    Ok(())
}


#[tokio::test]
async fn audit_records_changes_sensitive_reads_and_denials() -> TestResult {
    let fx = fixture()?;
    let token = login_token(&fx.router).await?;
    let mut change = request("POST", "/example/change", Some(&token), Body::empty())?;
    change.headers_mut().insert("x-request-id", HeaderValue::from_static("req-change-1"));
    send(&fx.router, change).await?;
    call(&fx.router, "GET", "/auth/me", Some(&token)).await?;
    call(&fx.router, "GET", "/example/secret", Some(&token)).await?;
    call(&fx.router, "GET", "/example/events", Some(&token)).await?;
    call(&fx.router, "GET", "/health", None).await?;
    call(&fx.router, "GET", "/auth/me", None).await?;
    send(&fx.router, request("POST", "/auth/login", None, Body::from("nonsense"))?).await?;
    let lines = audit_lines(&fx)?;
    let api: Vec<(String, String, String)> = lines
        .iter()
        .filter(|line| line.get("action") == Some(&json!("api.request")))
        .map(|line| {
            let text = |name: &str| line.get(name).and_then(serde_json::Value::as_str).unwrap_or("").to_owned();
            (text("target"), text("actor_id"), text("outcome"))
        })
        .collect();
    let expected = [
        ("POST /auth/login", "anonymous", "success"),
        ("POST /example/change", READER, "success"),
        ("GET /auth/me", READER, "success"),
        ("GET /example/secret", READER, "denied"),
        ("GET /auth/me", "anonymous", "denied"),
        ("POST /auth/login", "anonymous", "failure"),
    ]
    .map(|(target, actor, outcome)| (target.to_owned(), actor.to_owned(), outcome.to_owned()));
    assert_eq!(api, expected);
    let change_record = lines
        .iter()
        .find(|line| line.get("target") == Some(&json!("POST /example/change")))
        .ok_or("no change record")?;
    assert_eq!(change_record.get("request_id"), Some(&json!("req-change-1")));
    assert_eq!(change_record.get("tenant"), Some(&json!("acme")));
    assert_eq!(change_record.get("module"), Some(&json!("example")));
    let text = fs::read_to_string(&fx.config.audit_log)?;
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains(&token));
    let report = verify(BufReader::new(File::open(&fx.config.audit_log)?), None)?;
    assert_eq!(report.records, lines.len());
    Ok(())
}


#[tokio::test]
async fn audit_failures_fail_closed() -> TestResult {
    let fx = fixture_with(read_only_audit)?;
    assert_eq!(call(&fx.router, "GET", "/health", None).await?.status(), StatusCode::OK);
    let login = send(&fx.router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    assert_eq!(login.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body_json(login).await?.pointer("/error/code"), Some(&json!("internal_error")));
    let token = {
        let mut auth = fx.state.auth.lock().map_err(|_| "poisoned")?;
        create_session(&mut auth.sessions, READER, OffsetDateTime::now_utc(), os_random)?
    };
    let sensitive = call(&fx.router, "GET", "/auth/me", Some(secrecy::ExposeSecret::expose_secret(&token))).await?;
    assert_eq!(sensitive.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let logout = call(&fx.router, "POST", "/auth/logout", Some(secrecy::ExposeSecret::expose_secret(&token))).await?;
    assert_eq!(logout.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}


#[tokio::test]
async fn a_failed_store_save_discards_the_session() -> TestResult {
    let fx = fixture_with(unwritable_store)?;
    let response = send(&fx.router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await?.pointer("/error/code"), Some(&json!("invalid_credentials")));
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.sessions.is_empty());
    let reasons: Vec<String> = audit_lines(&fx)?
        .iter()
        .filter(|line| line.get("action") == Some(&json!("auth.login")))
        .filter_map(|line| line.pointer("/parameters/reason").and_then(serde_json::Value::as_str).map(str::to_owned))
        .collect();
    assert_eq!(reasons, ["internal_error"]);
    Ok(())
}


#[tokio::test]
async fn a_failed_store_save_and_a_failed_audit_still_refuse_the_login() -> TestResult {
    let fx = fixture_with(two_record_audit)?;
    let response = send(&fx.router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.sessions.is_empty());
    Ok(())
}


#[tokio::test]
async fn request_logs_carry_the_constant_fields() -> TestResult {
    let log_dir = tempfile::tempdir()?;
    let log_path = log_dir.path().join("platform.log");
    let dispatch = capture_dispatch(BoxMakeWriter::new(Mutex::new(File::create(&log_path)?)));
    let fx = fixture_with(|state| Ok(ApiState { dispatch, ..state }))?;
    let mut identified = request("GET", "/health", None, Body::empty())?;
    identified.headers_mut().insert("x-request-id", HeaderValue::from_static("log-1"));
    send(&fx.router, identified).await?;
    send(&fx.router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    call(&fx.router, "GET", "/auth/me", None).await?;
    let text = fs::read_to_string(&log_path)?;
    assert!(!text.contains(PASSWORD));
    let events: Vec<serde_json::Value> = text.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
    let first = events.first().ok_or("no log line")?;
    assert_eq!(first.get("module"), Some(&json!("example")));
    assert_eq!(first.get("tenant"), Some(&json!("acme")));
    assert_eq!(first.get("request_id"), Some(&json!("log-1")));
    assert_eq!(first.get("result"), Some(&json!("success")));
    assert!(first.get("duration_ms").is_some_and(serde_json::Value::is_number));
    let results: Vec<&str> = events
        .iter()
        .filter_map(|event| event.get("result").and_then(serde_json::Value::as_str))
        .collect();
    assert_eq!(results, ["success", "success", "denied"]);
    assert_eq!(events.len(), EXPECTED_EVENTS);
    Ok(())
}


#[test]
fn every_error_has_a_stable_status_and_code() -> TestResult {
    let cases = [
        (ApiError::BadRequest, StatusCode::BAD_REQUEST),
        (ApiError::Unauthorized, StatusCode::UNAUTHORIZED),
        (ApiError::InvalidCredentials, StatusCode::UNAUTHORIZED),
        (ApiError::MfaRequired, StatusCode::UNAUTHORIZED),
        (ApiError::MfaInvalid, StatusCode::UNAUTHORIZED),
        (ApiError::MfaEnrolmentRequired, StatusCode::FORBIDDEN),
        (ApiError::Forbidden, StatusCode::FORBIDDEN),
        (ApiError::PayloadTooLarge, StatusCode::PAYLOAD_TOO_LARGE),
        (ApiError::TooManyRequests, StatusCode::TOO_MANY_REQUESTS),
        (ApiError::Internal, StatusCode::INTERNAL_SERVER_ERROR),
    ];
    cases.iter().for_each(|(error, status)| assert_eq!(error_parts(error).0, *status));
    let codes: BTreeSet<&str> = cases.iter().map(|(error, _)| error_parts(error).1).collect();
    assert_eq!(codes.len(), cases.len());
    Ok(())
}


#[test]
fn auth_errors_map_to_api_errors() -> TestResult {
    let until = OffsetDateTime::UNIX_EPOCH;
    let cases = [
        (AuthError::InvalidCredentials, ApiError::InvalidCredentials),
        (AuthError::SessionInvalid, ApiError::Unauthorized),
        (AuthError::PermissionDenied, ApiError::Forbidden),
        (AuthError::MfaRequired, ApiError::MfaRequired),
        (AuthError::MfaInvalid, ApiError::MfaInvalid),
        (AuthError::MfaEnrolmentRequired, ApiError::MfaEnrolmentRequired),
        (AuthError::Locked { until }, ApiError::TooManyRequests),
        (AuthError::Decrypt, ApiError::Internal),
        (AuthError::Io(io::Error::other("disk")), ApiError::Internal),
    ];
    cases.iter().for_each(|(error, expected)| assert_eq!(auth_failure(error), *expected));
    Ok(())
}


const SOURCE_A: u8 = 1;


const SOURCE_B: u8 = 2;


const SOURCE_C: u8 = 3;


const SOURCE_D: u8 = 4;


const SOURCE_E: u8 = 5;


const SMALL_TABLE: usize = 2;


const TWO_KEYS: usize = 2;


const ROTATION_ATTEMPTS: usize = 25;


const SOURCE_LOCKOUT_FAILURES: usize = 20;


const CLIENT_PORT: u16 = 40_000;


const STALE_ENTRIES: usize = 5;


const RECENT_SECONDS: i64 = 10;


const SEQUENCE_LENGTH: usize = 21;


fn failing_verify(_password: &str, _stored: &str) -> Result<bool, AuthError> {
    Err(AuthError::Decrypt)
}


fn panicking_verify(_password: &str, _stored: &str) -> Result<bool, AuthError> {
    let zero = std::hint::black_box(u32::MIN);
    Ok(1 / zero == 0)
}


fn failing_hash(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        verify: failing_verify,
        ..state
    })
}


fn panicking_hash(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        verify: panicking_verify,
        ..state
    })
}


fn closed_gate(state: ApiState) -> Result<ApiState, TestError> {
    state.hashing.close();
    Ok(state)
}


fn small_attempt_table(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState { max_attempts: 1, ..state })
}


fn two_key_attempt_table(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        max_attempts: TWO_KEYS,
        ..state
    })
}


fn small_source_table(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        max_sources: SMALL_TABLE,
        ..state
    })
}


fn login_request(username: &str) -> LoginRequest {
    LoginRequest {
        username: username.to_owned(),
        password: SecretString::from(PASSWORD),
        totp_code: None,
        source: "127.0.0.1".to_owned(),
    }
}


async fn login_status(fixture: &fixture::Fixture, offset: u8, password: &str) -> Result<StatusCode, TestError> {
    let response = send_from(
        &fixture.router,
        client(offset),
        request("POST", "/auth/login", None, login_body(READER, password))?,
    )
    .await?;
    Ok(response.status())
}


async fn login_status_of(router: &axum::Router, offset: u8) -> Result<StatusCode, TestError> {
    let response = send_from(
        router,
        client(offset),
        request("POST", "/auth/login", None, login_body(READER, PASSWORD))?,
    )
    .await?;
    Ok(response.status())
}


#[tokio::test]
async fn a_failing_verification_refuses_the_login_without_a_session() -> TestResult {
    let fx = fixture_with(failing_hash)?;
    let response = send(&fx.router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await?.pointer("/error/code"), Some(&json!("invalid_credentials")));
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.sessions.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_panicking_verification_is_an_internal_error() -> TestResult {
    let fx = fixture_with(panicking_hash)?;
    assert_eq!(login_status(&fx, 1, PASSWORD).await?, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(fx.state.hashing.available_permits(), MAX_CONCURRENT_HASHES);
    Ok(())
}


#[tokio::test]
async fn a_closed_hashing_gate_is_an_internal_error() -> TestResult {
    let fx = fixture_with(closed_gate)?;
    assert_eq!(login_status(&fx, 1, PASSWORD).await?, StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}


#[tokio::test]
async fn concurrent_logins_all_succeed_and_release_the_gate() -> TestResult {
    let fx = fixture()?;
    assert!(fx.dir.path().exists());
    let (first, second, third, fourth, fifth) = tokio::join!(
        login_status_of(&fx.router, SOURCE_A),
        login_status_of(&fx.router, SOURCE_B),
        login_status_of(&fx.router, SOURCE_C),
        login_status_of(&fx.router, SOURCE_D),
        login_status_of(&fx.router, SOURCE_E),
    );
    for status in [first, second, third, fourth, fifth] {
        assert_eq!(status?, StatusCode::OK);
    }
    assert_eq!(fx.state.hashing.available_permits(), MAX_CONCURRENT_HASHES);
    Ok(())
}


#[tokio::test]
async fn a_changed_hash_or_failed_verdict_fails_closed() -> TestResult {
    let fx = fixture()?;
    let stale = commit_login(&fx.state, "id-1", &login_request(READER), "not the stored hash", Some(true));
    assert!(stale.is_err());
    let unverified = commit_login(&fx.state, "id-2", &login_request(READER), "not the stored hash", None);
    assert!(unverified.is_err());
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.sessions.is_empty());
    Ok(())
}


#[test]
fn pruning_keeps_only_locked_or_recent_entries() -> TestResult {
    let now = OffsetDateTime::now_utc();
    let old = now - time::Duration::seconds(FAILURE_WINDOW_SECONDS + 1);
    let recent = now - time::Duration::seconds(RECENT_SECONDS);
    let mut attempts: core_auth::types::AttemptMap = [
        (
            "stale".to_owned(),
            Attempts {
                failures: vec![old],
                locked_until: None,
            },
        ),
        ("empty".to_owned(), Attempts::default()),
        (
            "expired-lock".to_owned(),
            Attempts {
                failures: vec![],
                locked_until: Some(old),
            },
        ),
        (
            "recent".to_owned(),
            Attempts {
                failures: vec![old, recent],
                locked_until: None,
            },
        ),
        (
            "locked".to_owned(),
            Attempts {
                failures: vec![],
                locked_until: Some(now + time::Duration::seconds(LOCKOUT_SECONDS)),
            },
        ),
    ]
    .into_iter()
    .collect();
    prune_attempts(&mut attempts, now);
    assert_eq!(attempts.keys().map(String::as_str).collect::<Vec<_>>(), ["locked", "recent"]);
    Ok(())
}


#[tokio::test]
async fn a_full_failure_table_refuses_new_sources_until_entries_expire() -> TestResult {
    let fx = fixture_with(two_key_attempt_table)?;
    assert_eq!(login_status(&fx, 1, "wrong password here").await?, StatusCode::UNAUTHORIZED);
    assert_eq!(login_status(&fx, 1, "wrong password here").await?, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(login_status(&fx, SOURCE_B, PASSWORD).await?, StatusCode::TOO_MANY_REQUESTS);
    {
        let mut auth = fx.state.auth.lock().map_err(|_| "poisoned")?;
        auth.attempts.clear();
        (0..STALE_ENTRIES).for_each(|index| {
            auth.attempts.insert(
                format!("account:old-{index}"),
                Attempts {
                    failures: vec![OffsetDateTime::UNIX_EPOCH],
                    locked_until: None,
                },
            );
        });
    }
    assert_eq!(login_status(&fx, SOURCE_C, PASSWORD).await?, StatusCode::OK);
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.is_empty());
    Ok(())
}


#[tokio::test]
async fn the_source_table_refuses_new_sources_only_and_idle_sources_expire() -> TestResult {
    let fx = fixture_with(small_source_table)?;
    let (first, second, third) = (client(SOURCE_A).ip(), client(SOURCE_B).ip(), client(SOURCE_C).ip());
    assert!(admit_source(&fx.state, first));
    assert!(admit_source(&fx.state, second));
    assert!(!admit_source(&fx.state, third));
    assert!(admit_source(&fx.state, first));
    assert!(admit_source(&fx.state, second));
    assert_eq!(fx.state.limiter.lock().map_err(|_| "poisoned")?.len(), SMALL_TABLE);
    {
        let mut table = fx.state.limiter.lock().map_err(|_| "poisoned")?;
        table.insert(
            rate_key(first),
            Window {
                started: OffsetDateTime::UNIX_EPOCH,
                count: RATE_MAX_REQUESTS,
            },
        );
    }
    assert!(admit_source(&fx.state, third));
    assert!(fx.state.limiter.lock().map_err(|_| "poisoned")?.len() <= SMALL_TABLE);
    Ok(())
}


#[tokio::test]
async fn a_known_source_over_its_quota_stays_refused_in_a_full_table() -> TestResult {
    let fx = fixture_with(small_source_table)?;
    let first = client(SOURCE_A).ip();
    let results: Vec<bool> = (0..=RATE_MAX_REQUESTS).map(|_| admit_source(&fx.state, first)).collect();
    assert_eq!(results.iter().filter(|admitted| **admitted).count(), usize::try_from(RATE_MAX_REQUESTS)?);
    assert_eq!(results.last(), Some(&false));
    let window = *fx
        .state
        .limiter
        .lock()
        .map_err(|_| "poisoned")?
        .get(&rate_key(first))
        .ok_or("no window")?;
    assert!(OffsetDateTime::now_utc() - window.started < time::Duration::seconds(RATE_WINDOW_SECONDS));
    Ok(())
}


#[tokio::test]
async fn rotating_inside_one_64_bit_prefix_still_trips_the_source_lockout() -> TestResult {
    let fx = fixture()?;
    let mut statuses = Vec::new();
    for host in 1..=ROTATION_ATTEMPTS {
        let source = SocketAddr::new(format!("2001:db8:1:2::{host:x}").parse()?, CLIENT_PORT);
        let body = login_body(&format!("random-name-{host}"), "wrong password here");
        statuses.push(send_from(&fx.router, source, request("POST", "/auth/login", None, body)?).await?.status());
    }
    let (before, after) = statuses.split_at(SOURCE_LOCKOUT_FAILURES);
    assert!(before.iter().all(|status| *status == StatusCode::UNAUTHORIZED));
    assert!(after.iter().all(|status| *status == StatusCode::TOO_MANY_REQUESTS));
    let keys: Vec<String> = fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.keys().cloned().collect();
    assert_eq!(keys, ["source:2001:db8:1:2::".to_owned()]);
    Ok(())
}


fn full_table_with_failing_hash(state: ApiState) -> Result<ApiState, TestError> {
    Ok(ApiState {
        max_attempts: 1,
        verify: panicking_verify,
        ..state
    })
}


#[tokio::test]
async fn a_refused_login_costs_no_password_hashing() -> TestResult {
    let fx = fixture_with(full_table_with_failing_hash)?;
    fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.insert(
        "source:203.0.113.9".to_owned(),
        Attempts {
            failures: vec![OffsetDateTime::now_utc()],
            locked_until: None,
        },
    );
    assert_eq!(login_status(&fx, SOURCE_B, PASSWORD).await?, StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}


#[test]
fn ipv6_sources_share_one_bucket_per_64_bit_prefix() -> TestResult {
    let first: IpAddr = "2001:db8:1:2::1".parse()?;
    let same_prefix: IpAddr = "2001:db8:1:2:ffff::9".parse()?;
    let other_prefix: IpAddr = "2001:db8:1:3::1".parse()?;
    let v4: IpAddr = "192.0.2.7".parse()?;
    assert_eq!(rate_key(first), rate_key(same_prefix));
    assert_ne!(rate_key(first), rate_key(other_prefix));
    assert_eq!(rate_key(v4), v4);
    Ok(())
}


#[test]
fn an_expired_window_restarts_its_count() -> TestResult {
    let now = OffsetDateTime::now_utc();
    let mut spent = Window {
        started: OffsetDateTime::UNIX_EPOCH,
        count: RATE_MAX_REQUESTS,
    };
    assert!(count_request(&mut spent, now));
    assert_eq!((spent.started, spent.count), (now, 1));
    let mut full = Window {
        started: now,
        count: RATE_MAX_REQUESTS,
    };
    assert!(!count_request(&mut full, now));
    assert_eq!(full.count, RATE_MAX_REQUESTS);
    Ok(())
}


#[tokio::test]
async fn the_example_module_answers_a_permitted_session() -> TestResult {
    let fx = fixture()?;
    let token = login_token(&fx.router).await?;
    let response = call(&fx.router, "GET", "/example/ping", Some(&token)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), BODY_LIMIT_BYTES).await?;
    assert_eq!(bytes, PING_REPLY.as_bytes());
    assert!(serde_json::to_value(example_document())?.pointer("/paths/~1example~1ping/get").is_some());
    Ok(())
}


fn mapped_and_plain_keys() -> Result<(IpAddr, IpAddr, IpAddr), TestError> {
    Ok(("::ffff:192.0.2.1".parse()?, "::ffff:198.51.100.7".parse()?, "192.0.2.1".parse()?))
}


#[test]
fn an_ipv4_mapped_address_is_keyed_as_its_ipv4_address() -> TestResult {
    let (first, second, plain) = mapped_and_plain_keys()?;
    assert_eq!(rate_key(first), plain);
    assert_eq!(rate_key(second), "198.51.100.7".parse::<IpAddr>()?);
    assert_ne!(rate_key(first), rate_key(second));
    Ok(())
}


fn locked_for_a_while() -> Attempts {
    Attempts {
        failures: Vec::new(),
        locked_until: Some(OffsetDateTime::now_utc() + time::Duration::seconds(LOCKOUT_SECONDS)),
    }
}


#[tokio::test]
async fn a_locked_source_is_refused_without_hashing_but_an_account_lock_is_not() -> TestResult {
    let fx = fixture_with(panicking_hash)?;
    let mut request = login_request(READER);
    request.source = "203.0.113.50".to_owned();
    assert!(admit_login(&fx.state, "id-admit", &request).is_ok());
    fx.state
        .auth
        .lock()
        .map_err(|_| "poisoned")?
        .attempts
        .insert("source:203.0.113.50".to_owned(), locked_for_a_while());
    assert!(matches!(admit_login(&fx.state, "id-admit", &request), Err(ApiError::TooManyRequests)));
    assert_eq!(login_status(&fx, SOURCE_A, PASSWORD).await?, StatusCode::INTERNAL_SERVER_ERROR);
    {
        let mut auth = fx.state.auth.lock().map_err(|_| "poisoned")?;
        auth.attempts.clear();
        auth.attempts.insert(format!("account:{READER}"), locked_for_a_while());
    }
    assert!(admit_login(&fx.state, "id-admit", &request).is_ok());
    Ok(())
}


#[tokio::test]
async fn a_lock_on_an_unknown_account_name_is_ignored_before_hashing() -> TestResult {
    let fx = fixture()?;
    fx.state
        .auth
        .lock()
        .map_err(|_| "poisoned")?
        .attempts
        .insert("account:nobody".to_owned(), locked_for_a_while());
    assert!(admit_login(&fx.state, "id-admit", &login_request("nobody")).is_ok());
    Ok(())
}


#[tokio::test]
async fn commit_login_repeats_the_full_table_check() -> TestResult {
    let fx = fixture_with(small_attempt_table)?;
    fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.insert(
        "source:203.0.113.9".to_owned(),
        Attempts {
            failures: vec![OffsetDateTime::now_utc()],
            locked_until: None,
        },
    );
    let stored = core_api::routes::stored_hash(&fx.state, READER);
    let refused = commit_login(&fx.state, "id-3", &login_request(READER), &stored, Some(true));
    assert!(matches!(refused, Err(ApiError::TooManyRequests)));
    Ok(())
}


#[tokio::test]
async fn in_flight_logins_cannot_grow_the_failure_table_past_its_cap() -> TestResult {
    let fx = fixture_with(small_attempt_table)?;
    let (first, second, third, fourth, fifth) = tokio::join!(
        wrong_login_status(&fx.router, SOURCE_A),
        wrong_login_status(&fx.router, SOURCE_B),
        wrong_login_status(&fx.router, SOURCE_C),
        wrong_login_status(&fx.router, SOURCE_D),
        wrong_login_status(&fx.router, SOURCE_E),
    );
    let statuses = [first?, second?, third?, fourth?, fifth?];
    assert!(statuses
        .iter()
        .all(|status| *status == StatusCode::UNAUTHORIZED || *status == StatusCode::TOO_MANY_REQUESTS));
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.len() <= 1);
    Ok(())
}


async fn wrong_login_status(router: &axum::Router, offset: u8) -> Result<StatusCode, TestError> {
    let body = login_body(&format!("stranger-{offset}"), "wrong password here");
    Ok(send_from(router, client(offset), request("POST", "/auth/login", None, body)?)
        .await?
        .status())
}


#[tokio::test]
async fn an_existing_account_needs_room_for_both_of_its_failure_keys() -> TestResult {
    let fx = fixture_with(two_key_attempt_table)?;
    fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.insert(
        "source:203.0.113.9".to_owned(),
        Attempts {
            failures: vec![OffsetDateTime::now_utc()],
            locked_until: None,
        },
    );
    let mut known = login_request(READER);
    known.source = "198.51.100.1".to_owned();
    assert!(matches!(admit_login(&fx.state, "id-room", &known), Err(ApiError::TooManyRequests)));
    let mut unknown = login_request("stranger");
    unknown.source = "198.51.100.1".to_owned();
    assert!(matches!(admit_login(&fx.state, "id-room", &unknown), Err(ApiError::TooManyRequests)));
    Ok(())
}


async fn status_sequence(router: &axum::Router, offset: u8, username: &str) -> Result<Vec<StatusCode>, TestError> {
    let mut statuses = Vec::new();
    for _ in 0..SEQUENCE_LENGTH {
        let body = login_body(username, "wrong password here");
        statuses.push(
            send_from(router, client(offset), request("POST", "/auth/login", None, body)?)
                .await?
                .status(),
        );
    }
    Ok(statuses)
}


#[tokio::test]
async fn a_real_name_and_an_unknown_name_give_identical_status_sequences_from_one_source() -> TestResult {
    let fx = fixture()?;
    let real = status_sequence(&fx.router, 1, READER).await?;
    let unknown = status_sequence(&fx.router, OTHER_SOURCE, "nobody").await?;
    assert_eq!(real, unknown);
    assert_eq!(real.last(), Some(&StatusCode::TOO_MANY_REQUESTS));
    assert_eq!(real.first(), Some(&StatusCode::UNAUTHORIZED));
    Ok(())
}


async fn wrong_reader_status(router: &axum::Router, offset: u8) -> Result<StatusCode, TestError> {
    let body = login_body(READER, "wrong password here");
    Ok(send_from(router, client(offset), request("POST", "/auth/login", None, body)?)
        .await?
        .status())
}


#[tokio::test]
async fn in_flight_logins_for_an_existing_account_cannot_grow_the_table_past_its_cap() -> TestResult {
    let fx = fixture_with(two_key_attempt_table)?;
    let (first, second, third, fourth, fifth) = tokio::join!(
        wrong_reader_status(&fx.router, SOURCE_A),
        wrong_reader_status(&fx.router, SOURCE_B),
        wrong_reader_status(&fx.router, SOURCE_C),
        wrong_reader_status(&fx.router, SOURCE_D),
        wrong_reader_status(&fx.router, SOURCE_E),
    );
    let statuses = [first?, second?, third?, fourth?, fifth?];
    assert!(statuses.contains(&StatusCode::UNAUTHORIZED));
    assert!(fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.len() <= TWO_KEYS);
    Ok(())
}


#[tokio::test]
async fn a_login_refused_for_a_lock_is_audited_as_denied_locked() -> TestResult {
    let fx = fixture()?;
    fx.state
        .auth
        .lock()
        .map_err(|_| "poisoned")?
        .attempts
        .insert(format!("account:{READER}"), locked_for_a_while());
    assert_eq!(login_status(&fx, SOURCE_A, PASSWORD).await?, StatusCode::UNAUTHORIZED);
    let denied: Vec<serde_json::Value> = audit_lines(&fx)?
        .into_iter()
        .filter(|line| line.get("action") == Some(&json!("auth.login")))
        .collect();
    assert_eq!(denied.len(), 1);
    let line = denied.first().ok_or("no record")?;
    assert_eq!(line.get("outcome"), Some(&json!("denied")));
    assert_eq!(line.pointer("/parameters/reason"), Some(&json!("locked")));
    Ok(())
}


#[tokio::test]
async fn a_failing_audit_on_a_locked_refusal_fails_closed() -> TestResult {
    let fx = fixture_with(read_only_audit)?;
    fx.state
        .auth
        .lock()
        .map_err(|_| "poisoned")?
        .attempts
        .insert("source:203.0.113.50".to_owned(), locked_for_a_while());
    let mut request = login_request("stranger");
    request.source = "203.0.113.50".to_owned();
    assert!(matches!(admit_login(&fx.state, "id-audit", &request), Err(ApiError::Internal)));
    Ok(())
}


const FILLED_TABLE: usize = 5;


fn filler_attempts(auth: &mut core_auth::service::State, count: usize) {
    (0..count).for_each(|index| {
        auth.attempts.insert(
            format!("source:198.51.100.{index}"),
            Attempts {
                failures: vec![OffsetDateTime::now_utc()],
                locked_until: None,
            },
        );
    });
}


async fn three_step_statuses(username: &str) -> Result<Vec<StatusCode>, TestError> {
    let fx = fixture_with(|state| {
        Ok(ApiState {
            max_attempts: FILLED_TABLE,
            ..state
        })
    })?;
    let mut statuses = Vec::new();
    let first = send_from(
        &fx.router,
        client(SOURCE_A),
        request("POST", "/auth/login", None, login_body(username, "wrong password here"))?,
    )
    .await?;
    statuses.push(first.status());
    {
        let mut auth = fx.state.auth.lock().map_err(|_| "poisoned")?;
        let present = auth.attempts.len();
        filler_attempts(&mut auth, FILLED_TABLE - present);
    }
    let retry = send_from(
        &fx.router,
        client(SOURCE_A),
        request("POST", "/auth/login", None, login_body(username, "wrong password here"))?,
    )
    .await?;
    statuses.push(retry.status());
    Ok(statuses)
}


#[tokio::test]
async fn a_full_table_answers_a_real_and_an_unknown_name_alike_after_one_failure() -> TestResult {
    let real = three_step_statuses(READER).await?;
    let unknown = three_step_statuses("nobody").await?;
    assert_eq!(real, unknown);
    assert_eq!(real.first(), Some(&StatusCode::UNAUTHORIZED));
    Ok(())
}


#[tokio::test]
async fn a_locked_account_login_logs_no_warning() -> TestResult {
    let log_dir = tempfile::tempdir()?;
    let log_path = log_dir.path().join("platform.log");
    let dispatch = capture_dispatch(BoxMakeWriter::new(Mutex::new(File::create(&log_path)?)));
    let fx = fixture_with(|state| Ok(ApiState { dispatch, ..state }))?;
    fx.state
        .auth
        .lock()
        .map_err(|_| "poisoned")?
        .attempts
        .insert(format!("account:{READER}"), locked_for_a_while());
    assert_eq!(login_status(&fx, SOURCE_A, PASSWORD).await?, StatusCode::UNAUTHORIZED);
    let text = fs::read_to_string(&log_path)?;
    assert!(!text.contains("WARN"), "{text}");
    assert!(!text.contains("dummy verification"), "{text}");
    Ok(())
}
