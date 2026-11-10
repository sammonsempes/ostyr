use crate::api::{get_alert, list_alerts, login, logout, valid_cursor, valid_id};
use crate::error::{ApiFailure, FormRefusal, SessionError};
use crate::model::{ApiClient, Language, Opened, Principal, WebLimits, WebState};
use crate::pages::{alert_page, alerts_page, error_page, login_page, STYLESHEET};
use crate::session::{
    admit_login, clear_cookie, cookie_value, create_session, csrf_matches, drop_session, find_session, new_secret, set_cookie, LANGUAGE_COOKIE,
    LANGUAGE_COOKIE_SECONDS, LOGIN_COOKIE, LOGIN_COOKIE_SECONDS, SESSION_COOKIE,
};
use crate::types::{Form, Refused, SharedWeb};
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::header::{
    HeaderName, HeaderValue, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, LOCATION, REFERRER_POLICY, SET_COOKIE, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use maud::Markup;
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use tokio::time::timeout;
use url::form_urlencoded;


pub const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";


pub const SECURITY_HEADERS: [(HeaderName, HeaderValue); 6] = [
    (STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains")),
    (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
    (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
    (CACHE_CONTROL, HeaderValue::from_static("no-store")),
    (CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP)),
    (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
];


pub const HTML_TYPE: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");


pub const CSS_TYPE: HeaderValue = HeaderValue::from_static("text/css; charset=utf-8");


pub const MAX_LIMIT: u32 = 100;


pub const DEFAULT_WEIGHT: f32 = 1.0;


pub const NO_WEIGHT: f32 = 0.0;


pub const FALLBACK_LANGUAGE: Language = Language::English;


pub async fn harden(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    SECURITY_HEADERS.iter().for_each(|(name, value)| {
        response.headers_mut().insert(name.clone(), value.clone());
    });
    response
}


pub fn language_from_code(code: &str) -> Option<Language> {
    match code {
        "en" => Some(Language::English),
        "fr" => Some(Language::French),
        _ => None,
    }
}


/// The supported language with the highest `q`, the first listed on a tie; `q=0` and malformed weights exclude a tag.
pub fn accept_language(value: &str) -> Option<Language> {
    value
        .split(',')
        .filter_map(|entry| {
            let mut parts = entry.split(';');
            let tag = parts.next()?.trim().split('-').next()?.to_ascii_lowercase();
            let weight = parts
                .next()
                .map_or(Some(DEFAULT_WEIGHT), |parameter| parameter.trim().strip_prefix("q=")?.parse::<f32>().ok())?;
            language_from_code(&tag).filter(|_| weight > NO_WEIGHT).map(|language| (language, weight))
        })
        .min_by(|left, right| right.1.total_cmp(&left.1))
        .map(|(language, _)| language)
}


/// The explicit choice (cookie) first, then `Accept-Language`, then English.
pub fn language_of(headers: &HeaderMap) -> Language {
    cookie_value(headers, LANGUAGE_COOKIE)
        .and_then(|code| language_from_code(&code))
        .or_else(|| {
            headers
                .get(axum::http::header::ACCEPT_LANGUAGE)
                .and_then(|value| value.to_str().ok())
                .and_then(accept_language)
        })
        .unwrap_or(FALLBACK_LANGUAGE)
}


pub fn cookie_header(cookie: &str) -> HeaderValue {
    HeaderValue::from_str(cookie).unwrap_or_else(|error| {
        tracing::error!(%error, "a cookie is not a valid header value");
        HeaderValue::from_static("")
    })
}


pub fn html_response(status: StatusCode, markup: &Markup, cookies: &[String]) -> Response {
    let mut response = (status, [(CONTENT_TYPE, HTML_TYPE)], markup.0.clone()).into_response();
    cookies.iter().for_each(|cookie| {
        response.headers_mut().append(SET_COOKIE, cookie_header(cookie));
    });
    response
}


/// A fixed target only: nothing from the request ever reaches `Location`.
pub fn redirect(location: &'static str, cookies: &[String]) -> Response {
    let mut response = (StatusCode::SEE_OTHER, [(LOCATION, HeaderValue::from_static(location))]).into_response();
    cookies.iter().for_each(|cookie| {
        response.headers_mut().append(SET_COOKIE, cookie_header(cookie));
    });
    response
}


pub fn refusal(language: Language, csrf: Option<&str>, status: StatusCode, key: &str) -> Response {
    html_response(status, &error_page(language, csrf, key), &[])
}


pub fn require(accepted: bool, language: Language, status: StatusCode, key: &str) -> Result<(), Refused> {
    if accepted {
        Ok(())
    } else {
        Err(Box::new(refusal(language, None, status, key)))
    }
}


pub fn merge(result: Result<Response, Refused>) -> Response {
    result.unwrap_or_else(|refused| *refused)
}


pub fn form_refusal(language: Language, reason: FormRefusal) -> Response {
    match reason {
        FormRefusal::Timeout => refusal(language, None, StatusCode::REQUEST_TIMEOUT, "error_bad_request"),
        FormRefusal::TooLarge => refusal(language, None, StatusCode::PAYLOAD_TOO_LARGE, "error_bad_request"),
        FormRefusal::Malformed => refusal(language, None, StatusCode::BAD_REQUEST, "error_bad_request"),
    }
}


pub fn session_refusal(language: Language, failure: &SessionError) -> Response {
    tracing::error!(%failure, "cannot open a session");
    match failure {
        SessionError::Full => refusal(language, None, StatusCode::SERVICE_UNAVAILABLE, "error_full"),
        SessionError::Random(_) => refusal(language, None, StatusCode::INTERNAL_SERVER_ERROR, "error_generic"),
    }
}


/// A page for a failed API call: our own text per class, never the API's.
pub fn api_refusal(language: Language, csrf: Option<&str>, failure: &ApiFailure) -> Response {
    tracing::warn!(%failure, "API call failed");
    match failure {
        ApiFailure::Unauthorized | ApiFailure::Forbidden => refusal(language, csrf, StatusCode::FORBIDDEN, "error_forbidden"),
        ApiFailure::NotFound => refusal(language, csrf, StatusCode::NOT_FOUND, "error_not_found"),
        ApiFailure::Throttled => refusal(language, csrf, StatusCode::TOO_MANY_REQUESTS, "error_throttled"),
        ApiFailure::BadRequest => refusal(language, csrf, StatusCode::BAD_REQUEST, "error_bad_request"),
        ApiFailure::Unavailable(_) | ApiFailure::Status(_) | ApiFailure::TooLarge | ApiFailure::Malformed(_) | ApiFailure::Json(_) => {
            refusal(language, csrf, StatusCode::BAD_GATEWAY, "error_unavailable")
        }
    }
}


/// An API `401` ends the session here too, whatever its cause.
pub fn api_failure(state: &WebState, principal: &Principal, language: Language, failure: &ApiFailure) -> Response {
    match failure {
        ApiFailure::Unauthorized => {
            drop_session(state, &principal.key);
            redirect("/login", &[clear_cookie(SESSION_COOKIE)])
        }
        other => api_refusal(language, Some(&principal.csrf), other),
    }
}


/// At most `form_bytes` within `form_timeout`, so a slow or endless body cannot hold the handler.
pub async fn read_form(body: Body, limits: &WebLimits) -> Result<Form, FormRefusal> {
    let bytes = timeout(limits.form_timeout, to_bytes(body, limits.form_bytes))
        .await
        .map_err(|_elapsed| FormRefusal::Timeout)?
        .map_err(|_refused| FormRefusal::TooLarge)?;
    Ok(form_urlencoded::parse(&bytes).into_owned().collect())
}


pub fn current_principal(state: &WebState, headers: &HeaderMap) -> Result<Principal, Refused> {
    find_session(state, headers).ok_or_else(|| Box::new(redirect("/login", &[])))
}


pub async fn index() -> Response {
    redirect("/alerts", &[])
}


pub async fn stylesheet() -> Response {
    (StatusCode::OK, [(CONTENT_TYPE, CSS_TYPE)], STYLESHEET).into_response()
}


pub async fn not_found(headers: HeaderMap) -> Response {
    refusal(language_of(&headers), None, StatusCode::NOT_FOUND, "error_not_found")
}


/// The switch token is the session's CSRF token, or the login cookie's value on the sign-in page.
pub fn switch_token_valid(state: &WebState, headers: &HeaderMap, form: &Form) -> bool {
    find_session(state, headers).is_some_and(|principal| csrf_matches(&principal.csrf, field(form, "csrf"))) || login_csrf_valid(headers, form)
}


pub async fn submit_language(state: &WebState, code: &str, headers: &HeaderMap, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    let form = read_form(body, &state.limits)
        .await
        .map_err(|reason| Box::new(form_refusal(language, reason)))?;
    require(switch_token_valid(state, headers, &form), language, StatusCode::FORBIDDEN, "error_csrf")?;
    require(language_from_code(code).is_some(), language, StatusCode::NOT_FOUND, "error_not_found")?;
    Ok(redirect("/alerts", &[set_cookie(LANGUAGE_COOKIE, code, LANGUAGE_COOKIE_SECONDS)]))
}


pub async fn switch_language(State(state): State<SharedWeb>, Path(code): Path<String>, headers: HeaderMap, body: Body) -> Response {
    merge(submit_language(&state, &code, &headers, body).await)
}


pub async fn login_form(State(state): State<SharedWeb>, headers: HeaderMap) -> Response {
    let language = language_of(&headers);
    match new_secret(state.random) {
        Ok(csrf) => html_response(
            StatusCode::OK,
            &login_page(language, &csrf, false),
            &[set_cookie(LOGIN_COOKIE, &csrf, LOGIN_COOKIE_SECONDS)],
        ),
        Err(failure) => session_refusal(language, &failure),
    }
}


/// Login CSRF is the double-submit of a `__Host-` cookie: both values must be present, non-empty and equal.
pub fn login_csrf_valid(headers: &HeaderMap, form: &Form) -> bool {
    cookie_value(headers, LOGIN_COOKIE)
        .zip(form.get("csrf"))
        .is_some_and(|(cookie, field)| !cookie.is_empty() && csrf_matches(&cookie, field))
}


pub const MAX_USERNAME_BYTES: usize = 256;


pub const MAX_PASSWORD_BYTES: usize = 1024;


pub const MAX_TOTP_BYTES: usize = 16;


pub fn field<'form>(form: &'form Form, name: &str) -> &'form str {
    form.get(name).map_or("", String::as_str)
}


pub fn credentials_shaped(username: &str, password: &str, totp: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME_BYTES
        && !password.is_empty()
        && password.len() <= MAX_PASSWORD_BYTES
        && totp.len() <= MAX_TOTP_BYTES
}


/// Ends sessions at the API for the tokens the UI just dropped; a failure is logged and never blocks the caller.
pub async fn end_remote(client: &ApiClient, source: IpAddr, tokens: &[SecretString]) {
    for token in tokens {
        logout(client, source, token)
            .await
            .unwrap_or_else(|failure| tracing::warn!(%failure, "the API did not confirm the logout of a dropped session"));
    }
}


/// Replaces the presented session by a new one; every token the UI drops, or cannot keep, is ended at the API.
pub async fn open_session(
    state: &WebState,
    client: &ApiClient,
    source: IpAddr,
    headers: &HeaderMap,
    username: &str,
    token: SecretString,
) -> Result<Opened, Refused> {
    let language = language_of(headers);
    let previous: Vec<SecretString> = find_session(state, headers)
        .into_iter()
        .inspect(|found| drop_session(state, &found.key))
        .map(|found| found.token)
        .collect();
    let spare = token.clone();
    match create_session(state, username, token) {
        Ok(opened) => {
            end_remote(client, source, &previous).await;
            end_remote(client, source, &opened.evicted).await;
            Ok(opened)
        }
        Err(failure) => {
            end_remote(client, source, &previous).await;
            end_remote(client, source, &[spare]).await;
            Err(Box::new(session_refusal(language, &failure)))
        }
    }
}


pub async fn submit_login(state: &WebState, source: IpAddr, headers: &HeaderMap, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    require(admit_login(state, source), language, StatusCode::TOO_MANY_REQUESTS, "error_throttled")?;
    let form = read_form(body, &state.limits)
        .await
        .map_err(|reason| Box::new(form_refusal(language, reason)))?;
    require(login_csrf_valid(headers, &form), language, StatusCode::FORBIDDEN, "error_csrf")?;
    let (username, password, totp) = (field(&form, "username"), field(&form, "password"), field(&form, "totp_code"));
    let client = state.api.load_full();
    let outcome = if credentials_shaped(username, password, totp) {
        login(&client, source, username, password, Some(totp).filter(|code| !code.is_empty())).await
    } else {
        Err(ApiFailure::Unauthorized)
    };
    match outcome {
        Ok(token) => {
            let opened = open_session(state, &client, source, headers, username, token).await?;
            Ok(redirect(
                "/alerts",
                &[
                    set_cookie(SESSION_COOKIE, &opened.id, state.limits.session_seconds),
                    clear_cookie(LOGIN_COOKIE),
                ],
            ))
        }
        Err(ApiFailure::Unauthorized) => Ok(html_response(
            StatusCode::UNAUTHORIZED,
            &login_page(language, field(&form, "csrf"), true),
            &[],
        )),
        Err(failure) => Err(Box::new(api_refusal(language, None, &failure))),
    }
}


pub async fn login_submit(State(state): State<SharedWeb>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, body: Body) -> Response {
    merge(submit_login(&state, peer.ip(), &headers, body).await)
}


pub async fn submit_logout(state: &WebState, source: IpAddr, headers: &HeaderMap, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let form = read_form(body, &state.limits)
        .await
        .map_err(|reason| Box::new(form_refusal(language, reason)))?;
    require(
        csrf_matches(&principal.csrf, field(&form, "csrf")),
        language,
        StatusCode::FORBIDDEN,
        "error_csrf",
    )?;
    let client = state.api.load_full();
    logout(&client, source, &principal.token)
        .await
        .unwrap_or_else(|failure| tracing::warn!(%failure, "the API did not confirm the logout"));
    drop_session(state, &principal.key);
    Ok(redirect("/login", &[clear_cookie(SESSION_COOKIE)]))
}


pub async fn logout_submit(State(state): State<SharedWeb>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, body: Body) -> Response {
    merge(submit_logout(&state, peer.ip(), &headers, body).await)
}


pub fn parse_limit(query: &BTreeMap<String, String>) -> Result<Option<u32>, FormRefusal> {
    query
        .get("limit")
        .map(|text| {
            text.parse::<u32>()
                .ok()
                .filter(|limit| (1..=MAX_LIMIT).contains(limit))
                .ok_or(FormRefusal::Malformed)
        })
        .transpose()
}


pub fn parse_cursor(query: &BTreeMap<String, String>) -> Result<Option<&str>, FormRefusal> {
    query
        .get("cursor")
        .map(|text| Some(text.as_str()).filter(|cursor| valid_cursor(cursor)).ok_or(FormRefusal::Malformed))
        .transpose()
}


pub async fn show_alerts_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let cursor = parse_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let limit = parse_limit(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let page = list_alerts(&client, source, &principal.token, cursor, limit)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &alerts_page(language, &principal.csrf, &page), &[]))
}


pub async fn show_alerts(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_alerts_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_alert_page(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    require(valid_id(id), language, StatusCode::NOT_FOUND, "error_not_found")?;
    let client = state.api.load_full();
    let alert = get_alert(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &alert_page(language, &principal.csrf, &alert), &[]))
}


pub async fn show_alert(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    merge(show_alert_page(&state, peer.ip(), &headers, &id).await)
}


pub fn build_router(state: SharedWeb) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/style.css", get(stylesheet))
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", post(logout_submit))
        .route("/alerts", get(show_alerts))
        .route("/alerts/{id}", get(show_alert))
        .route("/language/{code}", post(switch_language))
        .fallback(not_found)
        .layer(from_fn(harden))
        .with_state(state)
}
