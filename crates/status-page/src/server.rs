use crate::limiter::admit;
use crate::model::{Admission, PageSettings, PeerIp, Snapshot};
use crate::types::SharedState;
use axum::extract::{Request, State};
use axum::http::header::{
    HeaderMap, HeaderName, HeaderValue, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ETAG, IF_NONE_MATCH, REFERRER_POLICY,
    RETRY_AFTER, TRANSFER_ENCODING, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;


pub const HTML_TYPE: &str = "text/html; charset=utf-8";


pub const JSON_TYPE: &str = "application/json";


pub const TEXT_TYPE: &str = "text/plain; charset=utf-8";


pub const CONTENT_SECURITY_POLICY_VALUE: &str = "default-src 'none'";


pub const NOT_FOUND_BODY: &str = "not found";


pub const NOT_ALLOWED_BODY: &str = "method not allowed";


pub const UNAVAILABLE_BODY: &str = "status page not published yet";


pub const LIMITED_BODY: &str = "too many requests";


pub const BODY_REFUSED_BODY: &str = "request body refused";


pub const NO_PEER_BODY: &str = "peer unknown";


pub const NO_STORE: &str = "no-store";


pub const NOT_MODIFIED_CONTROL_PREFIX: &str = "public, max-age=";


pub fn text_response(status: StatusCode, body: &'static str) -> Response {
    (status, [(CONTENT_TYPE, TEXT_TYPE)], body).into_response()
}


pub async fn not_found() -> Response {
    text_response(StatusCode::NOT_FOUND, NOT_FOUND_BODY)
}


pub async fn not_allowed() -> Response {
    text_response(StatusCode::METHOD_NOT_ALLOWED, NOT_ALLOWED_BODY)
}


/// True when `If-None-Match` names the current tag (a list, weak tags and `*` included).
pub fn tag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == etag)
}


/// Answers from the one snapshot loaded here; 503 before the first publish.
pub fn respond(state: &SharedState, headers: &HeaderMap, content_type: &'static str, pick: fn(&Snapshot) -> &str) -> Response {
    match state.snapshot.load_full() {
        None => text_response(StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE_BODY),
        Some(snapshot) => {
            let tag = HeaderValue::from_str(&snapshot.etag);
            match tag {
                Ok(value) if tag_matches(headers, &snapshot.etag) => (StatusCode::NOT_MODIFIED, [(ETAG, value)]).into_response(),
                Ok(value) => (
                    StatusCode::OK,
                    [(ETAG, value)],
                    [(CONTENT_TYPE, content_type)],
                    pick(&snapshot).to_owned(),
                )
                    .into_response(),
                Err(error) => {
                    tracing::error!(%error, "snapshot tag is not a header value");
                    text_response(StatusCode::INTERNAL_SERVER_ERROR, UNAVAILABLE_BODY)
                }
            }
        }
    }
}


pub async fn page_html(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    respond(&state, &headers, HTML_TYPE, |snapshot| snapshot.html.as_str())
}


pub async fn page_json(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    respond(&state, &headers, JSON_TYPE, |snapshot| snapshot.json.as_str())
}


/// A body is never accepted: any `Content-Length` other than 0, or any `Transfer-Encoding`, is refused.
pub fn has_body(headers: &HeaderMap) -> bool {
    headers.get_all(CONTENT_LENGTH).iter().any(|value| value != "0") || headers.contains_key(TRANSFER_ENCODING)
}


pub fn limited(retry_after_seconds: u64) -> Response {
    let mut response = text_response(StatusCode::TOO_MANY_REQUESTS, LIMITED_BODY);
    response.headers_mut().insert(RETRY_AFTER, HeaderValue::from(retry_after_seconds));
    response
}


/// The refusal for this request, if any: the rate limit comes first, before anything else is looked at.
pub fn refusal(state: &SharedState, settings: &PageSettings, request: &Request) -> Option<Response> {
    match request.extensions().get::<PeerIp>() {
        None => Some(text_response(StatusCode::BAD_REQUEST, NO_PEER_BODY)),
        Some(PeerIp(peer)) => match admit(state, *peer, settings) {
            Admission::Limited { retry_after_seconds } => Some(limited(retry_after_seconds)),
            Admission::Allowed => has_body(request.headers()).then(|| text_response(StatusCode::BAD_REQUEST, BODY_REFUSED_BODY)),
        },
    }
}


pub fn fixed_headers() -> Vec<(HeaderName, HeaderValue)> {
    vec![
        (CONTENT_SECURITY_POLICY, HeaderValue::from_static(CONTENT_SECURITY_POLICY_VALUE)),
        (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
        (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
    ]
}


/// Adds the security headers and the cache policy to every response, refusals included.
pub fn add_headers(response: &mut Response, settings: &PageSettings) {
    let cacheable = response.status() == StatusCode::OK || response.status() == StatusCode::NOT_MODIFIED;
    let control = if cacheable {
        HeaderValue::from_str(&format!("{NOT_MODIFIED_CONTROL_PREFIX}{}", settings.cache_max_age_seconds))
            .unwrap_or(HeaderValue::from_static(NO_STORE))
    } else {
        HeaderValue::from_static(NO_STORE)
    };
    let headers = response.headers_mut();
    fixed_headers().into_iter().for_each(|(name, value)| {
        headers.insert(name, value);
    });
    headers.insert(CACHE_CONTROL, control);
}


/// The first layer: one settings snapshot per request, rate limit, body refusal, then the route.
pub async fn guard(State(state): State<SharedState>, request: Request, next: Next) -> Response {
    let settings = state.settings.load_full();
    let mut response = match refusal(&state, &settings, &request) {
        Some(refused) => refused,
        None => next.run(request).await,
    };
    add_headers(&mut response, &settings);
    response
}


/// Exactly two routes; nothing here reads a file or a store.
pub fn status_router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(page_html))
        .route("/status.json", get(page_json))
        .fallback(not_found)
        .method_not_allowed_fallback(not_allowed)
        .layer(from_fn_with_state(state.clone(), guard))
        .with_state(state)
}
