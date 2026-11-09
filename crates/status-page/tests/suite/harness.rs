use crate::types::Clock;
use axum::body::{to_bytes, Body};
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use status_page::limiter::new_state;
use status_page::model::{PageSettings, PageState, PeerIp, Snapshot};
use status_page::settings::shared_settings;
use status_page::snapshot::{etag_of, publish};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tower::ServiceExt;


pub const TENANT: &str = "acme";


pub const BODY_LIMIT: usize = 1_048_576;


pub const PEER: &str = "192.0.2.10";


pub fn peer(text: &str) -> Result<IpAddr, std::net::AddrParseError> {
    text.parse()
}


pub fn small_settings(rate_per_second: u32, burst: u32, max_sources: usize) -> PageSettings {
    PageSettings {
        rate_per_second,
        burst,
        max_sources,
        ..PageSettings::default()
    }
}


pub fn snapshot(tenant: &str, label: &str) -> Snapshot {
    let html = format!("<html>{label}</html>");
    let json = format!("{{\"label\":\"{label}\"}}");
    Snapshot {
        tenant: tenant.to_owned(),
        etag: etag_of(&json, &html),
        html,
        json,
    }
}


pub fn state_with(settings: PageSettings) -> (Arc<PageState>, Clock) {
    let clock: Clock = Arc::new(AtomicU64::new(0));
    let reader = Arc::clone(&clock);
    let state = new_state(
        TENANT.to_owned(),
        shared_settings(settings),
        Box::new(move || reader.load(Ordering::SeqCst)),
    );
    (Arc::new(state), clock)
}


pub fn published_state(settings: PageSettings, label: &str) -> Result<(Arc<PageState>, Clock), Box<dyn std::error::Error>> {
    let (state, clock) = state_with(settings);
    publish(&state, snapshot(TENANT, label))?;
    Ok((state, clock))
}


pub fn request(method: &str, path: &str, source: Option<&str>, headers: &[(&str, &str)]) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let builder = headers
        .iter()
        .fold(Request::builder().method(method).uri(path), |builder, (name, value)| {
            builder.header(*name, *value)
        });
    let mut request = builder.body(Body::empty())?;
    if let Some(text) = source {
        request.extensions_mut().insert(PeerIp(peer(text)?));
    }
    Ok(request)
}


pub async fn call(router: &Router, request: Request<Body>) -> Result<Response<Body>, Box<dyn std::error::Error>> {
    Ok(router.clone().oneshot(request).await?)
}


pub async fn get_status(router: &Router, path: &str, source: &str) -> Result<StatusCode, Box<dyn std::error::Error>> {
    Ok(call(router, request("GET", path, Some(source), &[])?).await?.status())
}


pub async fn text_of(response: Response<Body>) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(to_bytes(response.into_body(), BODY_LIMIT).await?.to_vec())?)
}


pub fn header_of<'a>(response: &'a Response<Body>, name: &str) -> Option<&'a str> {
    response.headers().get(name).and_then(|value| value.to_str().ok())
}
