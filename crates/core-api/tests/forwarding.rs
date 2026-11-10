#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/http.rs"]
mod http;
#[path = "support/types.rs"]
mod types;


use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use core_api::config::{forwarders, MAX_TRUSTED_FORWARDERS};
use core_api::middleware::{client_source, forwarded_address, forwarded_for, forwarded_node};
use core_api::model::ApiError;
use core_config::load::load_module;
use core_config::model::ModuleConfig;
use fixture::{fixture, Fixture, PASSWORD, READER};
use http::{audit_lines, body_json, call, client, login_body, login_token, request, send, send_from};
use ipnet::IpNet;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use types::{TestError, TestResult};


const FORWARDER_OFFSET: u8 = 1;


const LOCKOUT_FAILURES: usize = 20;


const FORWARDER_NETWORK: &str = "127.0.0.0/24";


const SOURCE_A: &str = "198.51.100.7";


const SOURCE_B: &str = "198.51.100.8";


const MAPPED_PORT: u16 = 4000;


const IGNORED_HEADERS: u64 = 2;


const VALID_ENTRIES: usize = 2;


fn trust(fx: &Fixture, entries: &[&str]) -> Result<(), TestError> {
    let networks = entries.iter().map(|entry| entry.parse::<IpNet>()).collect::<Result<Vec<_>, _>>()?;
    fx.state.forwarders.store(Arc::new(networks));
    Ok(())
}


fn with_headers(path: &str, headers: &[&str]) -> Result<Request<Body>, TestError> {
    let mut built = request("GET", path, None, Body::empty())?;
    headers.iter().try_for_each(|value| -> Result<(), TestError> {
        built.headers_mut().append("forwarded", HeaderValue::from_str(value)?);
        Ok(())
    })?;
    Ok(built)
}


async fn login_forwarded(fx: &Fixture, source: &str, username: &str, password: &str) -> Result<StatusCode, TestError> {
    let mut built = request("POST", "/auth/login", None, login_body(username, password))?;
    built.headers_mut().insert("forwarded", HeaderValue::from_str(&format!("for={source}"))?);
    Ok(send_from(&fx.router, client(FORWARDER_OFFSET), built).await?.status())
}


fn limiter_keys(fx: &Fixture) -> Result<Vec<String>, TestError> {
    Ok(fx.state.limiter.lock().map_err(|_| "poisoned")?.keys().map(ToString::to_string).collect())
}


fn record_of(fx: &Fixture) -> Result<serde_json::Value, TestError> {
    assert!(fx.dir.path().join("audit.log").exists());
    Ok(audit_lines(fx)?
        .into_iter()
        .find(|line| line.get("action") == Some(&serde_json::json!("api.request")))
        .ok_or("no record")?)
}


#[tokio::test]
async fn a_forwarding_header_from_an_untrusted_peer_is_ignored_and_counted() -> TestResult {
    let fx = fixture()?;
    let plain = send_from(&fx.router, client(FORWARDER_OFFSET), with_headers("/health", &["for=203.0.113.9"])?).await?;
    assert_eq!(plain.status(), StatusCode::OK);
    let mut spoofed = request("GET", "/health", None, Body::empty())?;
    spoofed.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    send_from(&fx.router, client(FORWARDER_OFFSET), spoofed).await?;
    send(&fx.router, request("GET", "/health", None, Body::empty())?).await?;
    let token = login_token(&fx.router).await?;
    assert_eq!(call(&fx.router, "GET", "/example/ping", Some(&token)).await?.status(), StatusCode::OK);
    assert_eq!(fx.state.ignored_forwarding.load(Ordering::Relaxed), IGNORED_HEADERS);
    assert_eq!(limiter_keys(&fx)?, ["127.0.0.2".to_owned()]);
    Ok(())
}


#[tokio::test]
async fn a_trusted_forwarder_keys_the_rate_limit_on_the_forwarded_address() -> TestResult {
    let fx = fixture()?;
    trust(&fx, &[FORWARDER_NETWORK])?;
    send_from(
        &fx.router,
        client(FORWARDER_OFFSET),
        with_headers("/health", &["for=198.51.100.7;proto=https"])?,
    )
    .await?;
    send_from(
        &fx.router,
        client(FORWARDER_OFFSET),
        with_headers("/health", &["For=\"[2001:db8:1:2::9]\""])?,
    )
    .await?;
    send_from(&fx.router, client(FORWARDER_OFFSET), with_headers("/health", &["for=\"198.51.100.9\""])?).await?;
    assert_eq!(
        limiter_keys(&fx)?,
        ["198.51.100.7".to_owned(), "198.51.100.9".to_owned(), "2001:db8:1:2::".to_owned()]
    );
    assert_eq!(fx.state.ignored_forwarding.load(Ordering::Relaxed), 0);
    Ok(())
}


#[tokio::test]
async fn one_locked_forwarded_source_does_not_lock_another() -> TestResult {
    let fx = fixture()?;
    trust(&fx, &[FORWARDER_NETWORK])?;
    let mut statuses = Vec::new();
    for _ in 0..=LOCKOUT_FAILURES {
        statuses.push(login_forwarded(&fx, SOURCE_A, "somebody-else", "wrong password here").await?);
    }
    let (before, after) = statuses.split_at(LOCKOUT_FAILURES);
    assert!(before.iter().all(|status| *status == StatusCode::UNAUTHORIZED));
    assert!(after.iter().all(|status| *status == StatusCode::TOO_MANY_REQUESTS));
    assert_eq!(login_forwarded(&fx, SOURCE_A, READER, PASSWORD).await?, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(login_forwarded(&fx, SOURCE_B, READER, PASSWORD).await?, StatusCode::OK);
    let keys: Vec<String> = fx.state.auth.lock().map_err(|_| "poisoned")?.attempts.keys().cloned().collect();
    assert!(keys.contains(&format!("source:{SOURCE_A}")));
    assert!(!keys.iter().any(|key| key.contains("127.0.0.2")));
    Ok(())
}


#[tokio::test]
async fn every_malformed_header_from_a_trusted_forwarder_is_refused_before_authentication() -> TestResult {
    let fx = fixture()?;
    trust(&fx, &["127.0.0.0/8"])?;
    let cases: Vec<&[&str]> = vec![
        &[],
        &["for=198.51.100.7", "for=198.51.100.8"],
        &["for=198.51.100.7, for=198.51.100.8"],
        &["for=198.51.100.7;for=198.51.100.8"],
        &["for=\"_hidden\""],
        &["for=unknown"],
        &["for=198.51.100.7:4711"],
        &["for=\"[2001:db8::1]:4711\""],
        &["for=example.com"],
        &["by=198.51.100.7"],
        &["198.51.100.7"],
        &["for=2001:db8::1"],
        &["for=0198.051.100.7"],
        &["for="],
        &["for=198.51.100.7;proto"],
        &["for=198.51.100.7;"],
        &["for =198.51.100.7"],
        &["for= 198.51.100.7"],
        &["for=198.51.100.7 "],
        &["for=[2001:db8::1]"],
    ];
    for headers in cases {
        let response = send_from(&fx.router, client(FORWARDER_OFFSET), with_headers("/auth/me", headers)?).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{headers:?}");
        let body = body_json(response).await?;
        assert_eq!(body.pointer("/error/code"), Some(&serde_json::json!("bad_request")));
    }
    let mut binary = request("GET", "/auth/me", None, Body::empty())?;
    binary.headers_mut().insert("forwarded", HeaderValue::from_bytes(b"for=\xff")?);
    let refused = send_from(&fx.router, client(FORWARDER_OFFSET), binary).await?;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(limiter_keys(&fx)?.is_empty());
    Ok(())
}


#[test]
fn the_strict_parsers_refuse_loose_pairs_and_unquoted_brackets() -> TestResult {
    assert!(forwarded_for("for=198.51.100.7;proto=https").is_some());
    assert!(forwarded_for("for=\"[2001:db8::1]\"").is_some());
    assert!(forwarded_for("for=198.51.100.7;proto").is_none());
    assert!(forwarded_for("for = 198.51.100.7").is_none());
    assert!(forwarded_node("[2001:db8::1]").is_none());
    assert!(forwarded_node("\"198.51.100.7\"").is_some());
    Ok(())
}


#[tokio::test]
async fn x_forwarded_for_is_never_read_even_from_a_trusted_forwarder() -> TestResult {
    let fx = fixture()?;
    trust(&fx, &["127.0.0.0/8"])?;
    let mut built = request("GET", "/health", None, Body::empty())?;
    built.headers_mut().insert("x-forwarded-for", HeaderValue::from_static(SOURCE_A));
    assert!(forwarded_address(built.headers()).is_none());
    let response = send_from(&fx.router, client(FORWARDER_OFFSET), built).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}


#[tokio::test]
async fn the_audit_records_the_forwarded_source_and_the_forwarder() -> TestResult {
    let fx = fixture()?;
    trust(&fx, &["127.0.0.0/8"])?;
    send_from(
        &fx.router,
        client(FORWARDER_OFFSET),
        with_headers("/auth/me", &["for=\"[2001:db8:1:2::9]\""])?,
    )
    .await?;
    let forwarded = record_of(&fx)?;
    assert_eq!(forwarded.pointer("/parameters/source"), Some(&serde_json::json!("2001:db8:1:2::")));
    assert_eq!(forwarded.pointer("/parameters/forwarded_by"), Some(&serde_json::json!("127.0.0.2")));
    let direct = fixture()?;
    send_from(&direct.router, client(FORWARDER_OFFSET), request("GET", "/auth/me", None, Body::empty())?).await?;
    let untouched = record_of(&direct)?;
    assert_eq!(untouched.pointer("/parameters/source"), Some(&serde_json::json!("127.0.0.2")));
    assert!(untouched.pointer("/parameters/forwarded_by").is_none());
    Ok(())
}


#[test]
fn a_mapped_ipv4_peer_matches_an_ipv4_network_and_the_port_is_kept() -> TestResult {
    let fx = fixture()?;
    trust(&fx, &["127.0.0.0/8"])?;
    let peer = SocketAddr::new("::ffff:127.0.0.1".parse::<IpAddr>()?, MAPPED_PORT);
    let built = with_headers("/health", &["for=198.51.100.7"])?;
    let source = client_source(&fx.state, peer, built.headers()).map_err(|_| "refused")?;
    assert_eq!(source.address, SocketAddr::new(SOURCE_A.parse()?, MAPPED_PORT));
    assert_eq!(source.forwarded_by, Some(peer.ip()));
    let refused = client_source(&fx.state, peer, with_headers("/health", &[])?.headers());
    assert!(matches!(refused, Err(ApiError::BadRequest)));
    Ok(())
}


fn module_with(setting: Option<&str>) -> Result<ModuleConfig, TestError> {
    let line = setting.map_or(String::new(), |value| format!("settings:\n  trusted_forwarders: \"{value}\"\n"));
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("module.yaml");
    fs::write(&path, format!("name: example\nversion: 1.0.0\nlisten: \"127.0.0.1:0\"\n{line}"))?;
    Ok(load_module(&path)?)
}


fn list_of(count: usize) -> String {
    (0..count).map(|index| format!("10.0.0.{index}")).collect::<Vec<_>>().join(",")
}


#[test]
fn the_setting_defaults_to_empty_and_reads_addresses_and_networks() -> TestResult {
    assert!(forwarders(&module_with(None)?)?.is_empty());
    assert!(forwarders(&module_with(Some(" "))?)?.is_empty());
    let parsed = forwarders(&module_with(Some("10.0.0.1, 192.168.0.0/16 ,2001:db8::/48,::1"))?)?;
    let expected: Vec<IpNet> = ["10.0.0.1/32", "192.168.0.0/16", "2001:db8::/48", "::1/128"]
        .iter()
        .map(|text| text.parse())
        .collect::<Result<_, _>>()?;
    assert_eq!(parsed, expected);
    Ok(())
}


#[test]
fn a_bad_entry_an_empty_entry_or_too_many_entries_are_refused() -> TestResult {
    let bad = forwarders(&module_with(Some("10.0.0.1,not-an-address"))?);
    assert!(bad.is_err_and(|error| error.to_string().contains("not-an-address")));
    assert!(forwarders(&module_with(Some("10.0.0.1,,10.0.0.2"))?).is_err());
    assert!(forwarders(&module_with(Some("10.0.0.0/33"))?).is_err());
    ["0.0.0.0/0", "::/0", "10.0.0.0/15", "10.0.0.0/8", "2001:db8::/47", "2001:db8::/32"]
        .iter()
        .try_for_each(|entry| -> TestResult {
            let refused = forwarders(&module_with(Some(&format!("10.0.0.1,{entry}")))?);
            assert!(refused.is_err_and(|error| error.to_string().contains(entry) && error.to_string().contains("minimum prefix")));
            Ok(())
        })?;
    assert_eq!(forwarders(&module_with(Some("10.0.0.0/16,2001:db8:1::/48"))?)?.len(), VALID_ENTRIES);
    let refused = forwarders(&module_with(Some(&list_of(MAX_TRUSTED_FORWARDERS + 1)))?);
    assert!(refused.is_err_and(|error| error.to_string().contains("must be between 0 and")));
    assert_eq!(
        forwarders(&module_with(Some(&list_of(MAX_TRUSTED_FORWARDERS)))?)?.len(),
        MAX_TRUSTED_FORWARDERS
    );
    Ok(())
}


#[tokio::test]
async fn the_health_route_shows_the_ignored_forwarding_counter() -> TestResult {
    let fx = fixture()?;
    send_from(&fx.router, client(FORWARDER_OFFSET), with_headers("/health", &["for=203.0.113.9"])?).await?;
    let health = send(&fx.router, request("GET", "/health", None, Body::empty())?).await?;
    assert_eq!(body_json(health).await?.pointer("/ignored_forwarding"), Some(&serde_json::json!(1)));
    Ok(())
}
