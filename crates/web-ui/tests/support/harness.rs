use crate::stub::{start_stub, Mode, Stub};
use crate::types::TestError;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use core_auth::random::os_random;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use web_ui::client::build_client;
use web_ui::model::{ApiSection, WebLimits, WebState};
use web_ui::routes::build_router;
use web_ui::server::new_state;
use web_ui::types::Random;


pub const CONNECTIONS: usize = 4;


pub const BODY_LIMIT: usize = 4_194_304;


pub const CLIENT_PORT: u16 = 40_000;


pub const API_TIMEOUT: u64 = 5;


pub const LOOPBACK_FIRST: u8 = 127;


pub const LIMITS: WebLimits = WebLimits {
    max_sessions: 2,
    session_seconds: 100,
    form_timeout: Duration::from_secs(5),
    form_bytes: 512,
    login_max: 10,
    login_window_seconds: 60,
    max_sources: 2,
};


pub struct Harness {
    pub router: Router,
    pub state: Arc<WebState>,
    pub stub: Stub,
    pub clock: Arc<AtomicU64>,
}


#[derive(Default)]
pub struct Req {
    pub post: bool,
    pub path: String,
    pub cookies: Vec<String>,
    pub language: Option<String>,
    pub body: Option<String>,
    pub source: u8,
}


pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}


pub async fn harness_custom(mode: Mode, random: Random, limits: WebLimits) -> Result<Harness, TestError> {
    let stub = start_stub(mode).await?;
    let client = build_client(&ApiSection {
        base_url: format!("http://{}/", stub.address),
        ca: None,
        timeout_seconds: API_TIMEOUT,
        max_connections: CONNECTIONS,
    })?;
    let clock = Arc::new(AtomicU64::new(0));
    let ticking = clock.clone();
    let state = Arc::new(new_state(client, limits, Box::new(move || ticking.load(Ordering::SeqCst)), random));
    Ok(Harness {
        router: build_router(state.clone()),
        state,
        stub,
        clock,
    })
}


pub async fn harness(mode: Mode) -> Result<Harness, TestError> {
    harness_custom(mode, os_random, LIMITS).await
}


pub fn get(path: &str) -> Req {
    Req {
        path: path.to_owned(),
        source: 1,
        ..Req::default()
    }
}


pub fn get_with(path: &str, session: &str) -> Req {
    Req {
        cookies: vec![format!("__Host-ostyr_session={session}")],
        ..get(path)
    }
}


pub fn post_form(path: &str, cookies: Vec<String>, body: &str) -> Req {
    Req {
        post: true,
        cookies,
        body: Some(body.to_owned()),
        ..get(path)
    }
}


pub async fn fire_body(router: &Router, request: Req, body: Body) -> Result<Reply, TestError> {
    let mut builder = Request::builder()
        .method(if request.post { "POST" } else { "GET" })
        .uri(&request.path)
        .header("content-type", "application/x-www-form-urlencoded");
    if !request.cookies.is_empty() {
        builder = builder.header("cookie", request.cookies.join("; "));
    }
    if let Some(language) = &request.language {
        builder = builder.header("accept-language", language);
    }
    let mut built = builder.body(body)?;
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(LOOPBACK_FIRST, 0, 0, request.source)), CLIENT_PORT);
    built.extensions_mut().insert(ConnectInfo(peer));
    let response = router.clone().oneshot(built).await?;
    let (parts, response_body) = response.into_parts();
    let bytes = to_bytes(response_body, BODY_LIMIT).await?;
    Ok(Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}


pub async fn fire(harness: &Harness, request: Req) -> Result<Reply, TestError> {
    let body = request.body.clone().map_or_else(Body::empty, Body::from);
    fire_body(&harness.router, request, body).await
}


pub fn set_cookie_of(reply: &Reply, name: &str) -> Option<String> {
    reply
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|line| line.starts_with(&format!("{name}=")))
        .map(str::to_owned)
}


pub fn cookie_value_of(set_cookie: &str) -> Option<String> {
    set_cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
}


pub fn location_of(reply: &Reply) -> Option<String> {
    reply.headers.get("location").and_then(|value| value.to_str().ok()).map(str::to_owned)
}


pub fn csrf_in(body: &str) -> Option<String> {
    let marker = "name=\"csrf\" value=\"";
    let start = body.find(marker)? + marker.len();
    let rest = body.get(start..)?;
    rest.find('"').and_then(|end| rest.get(..end)).map(str::to_owned)
}


pub async fn login_csrf(harness: &Harness) -> Result<String, TestError> {
    let reply = fire(harness, get("/login")).await?;
    let cookie = set_cookie_of(&reply, "__Host-ostyr_login").ok_or("no login cookie")?;
    Ok(cookie_value_of(&cookie).ok_or("no login cookie value")?)
}


pub fn login_body(csrf: &str, username: &str, password: &str) -> String {
    format!("csrf={csrf}&username={username}&password={password}&totp_code=")
}


pub async fn post_login(harness: &Harness, username: &str, password: &str) -> Result<Reply, TestError> {
    let csrf = login_csrf(harness).await?;
    fire(
        harness,
        post_form(
            "/login",
            vec![format!("__Host-ostyr_login={csrf}")],
            &login_body(&csrf, username, password),
        ),
    )
    .await
}


pub async fn sign_in(harness: &Harness) -> Result<String, TestError> {
    let reply = post_login(harness, "alice", "secret").await?;
    let cookie = set_cookie_of(&reply, "__Host-ostyr_session").ok_or("no session cookie")?;
    Ok(cookie_value_of(&cookie).ok_or("no session value")?)
}
