use crate::fixture::PASSWORD;
use crate::types::TestError;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, Response};
use axum::Router;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tower::ServiceExt;


pub const CLIENT_PORT: u16 = 40_000;


pub const BODY_READ_LIMIT: usize = 1_048_576;


pub fn source() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), CLIENT_PORT)
}


pub async fn call(router: &Router, method: &str, path: &str, token: Option<&str>, body: Body) -> Result<Response<Body>, TestError> {
    let mut builder = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(value) = token {
        builder = builder.header("authorization", format!("Bearer {value}"));
    }
    let mut request = builder.body(body)?;
    request.extensions_mut().insert(ConnectInfo(source()));
    Ok(router.clone().oneshot(request).await?)
}


pub async fn get(router: &Router, path: &str, token: Option<&str>) -> Result<Response<Body>, TestError> {
    call(router, "GET", path, token, Body::empty()).await
}


pub async fn body_json(response: Response<Body>) -> Result<serde_json::Value, TestError> {
    let bytes = to_bytes(response.into_body(), BODY_READ_LIMIT).await?;
    Ok(serde_json::from_slice(&bytes)?)
}


pub async fn login(router: &Router, user: &str) -> Result<String, TestError> {
    let body = Body::from(serde_json::json!({ "username": user, "password": PASSWORD }).to_string());
    let response = call(router, "POST", "/auth/login", None, body).await?;
    let json = body_json(response).await?;
    Ok(json.get("token").and_then(serde_json::Value::as_str).ok_or("no token")?.to_owned())
}
