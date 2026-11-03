use crate::fixture::{Fixture, PASSWORD, READER};
use crate::types::TestError;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, Response};
use axum::Router;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::ServiceExt;


pub const CLIENT_PORT: u16 = 40_000;


pub const BODY_READ_LIMIT: usize = 1_048_576;


pub fn client(offset: u8) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(u32::from(Ipv4Addr::LOCALHOST) + u32::from(offset))),
        CLIENT_PORT,
    )
}


pub fn request(method: &str, path: &str, token: Option<&str>, body: Body) -> Result<Request<Body>, TestError> {
    let mut builder = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(value) = token {
        builder = builder.header("authorization", format!("Bearer {value}"));
    }
    Ok(builder.body(body)?)
}


pub async fn send_from(router: &Router, source: SocketAddr, mut request: Request<Body>) -> Result<Response<Body>, TestError> {
    request.extensions_mut().insert(ConnectInfo(source));
    Ok(router.clone().oneshot(request).await?)
}


pub async fn send(router: &Router, request: Request<Body>) -> Result<Response<Body>, TestError> {
    send_from(router, client(1), request).await
}


pub async fn call(router: &Router, method: &str, path: &str, token: Option<&str>) -> Result<Response<Body>, TestError> {
    send(router, request(method, path, token, Body::empty())?).await
}


pub async fn body_json(response: Response<Body>) -> Result<serde_json::Value, TestError> {
    let bytes = to_bytes(response.into_body(), BODY_READ_LIMIT).await?;
    Ok(serde_json::from_slice(&bytes)?)
}


pub fn login_body(username: &str, password: &str) -> Body {
    Body::from(serde_json::json!({ "username": username, "password": password }).to_string())
}


pub async fn login_token(router: &Router) -> Result<String, TestError> {
    let response = send(router, request("POST", "/auth/login", None, login_body(READER, PASSWORD))?).await?;
    let json = body_json(response).await?;
    Ok(json.get("token").and_then(serde_json::Value::as_str).ok_or("no token")?.to_owned())
}


pub fn audit_lines(fixture: &Fixture) -> Result<Vec<serde_json::Value>, TestError> {
    fs::read_to_string(&fixture.config.audit_log)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}
