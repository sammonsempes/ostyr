use crate::api::{
    cert_filter, checked_observable, get_alert, get_asset, get_attack, get_case, get_cert, get_dhcp, get_grc, get_oncall_alert, get_posture,
    get_risk_entity, get_shell_session, get_state_asset, get_vuln_asset, list_alerts, list_assets, list_attack, list_case_links,
    list_case_observables, list_cases, list_certs, list_findings, list_grc, list_groups, list_oncall, list_risk, list_shell_sessions, list_states,
    list_vulns, login, logout, parse_dhcp_address, parse_dhcp_mac, parse_dhcp_time, parse_dhcp_window, post_alert_triage, post_case_action,
    post_case_comment, post_case_link, post_case_observable, probe_dhcp, probe_posture, risk_kind, shell_open_filter, valid_asset_cursor,
    valid_case_id, valid_cert_cursor, valid_cursor, valid_hunt_cursor, valid_id, valid_shell_cursor, valid_shell_filter_requester,
    valid_shell_reference, valid_state_cursor, valid_state_id, valid_vuln_cursor, verdict_filter, MAX_COMMENT_CHARS, MAX_NOTE_CHARS,
    MAX_OBSERVABLE_CHARS, MAX_SOURCE_CHARS, RUN_CHANGED_KEY, SECONDS_PER_DAY, VERDICT_DEFAULT,
};
use crate::error::{ApiFailure, FormRefusal, SessionError};
use crate::model::{
    ApiClient, CaseDetailView, CommentView, DhcpQuery, Language, LinksPanel, ObservablesPanel, Opened, Principal, ShellQuery, WebLimits, WebState,
};
use crate::pages::{
    alert_page, alerts_page, asset_page, assets_page, attack_page, attack_report_page, case_page, case_page_all, case_page_full, case_page_with,
    cases_page, cert_page, certs_page, comment_unloaded_page, compliance_asset_page, compliance_page, dhcp_page, error_page, grc_page,
    grc_report_page, groups_page, hunts_page, login_page, oncall_alert_page, oncall_page, posture_changed_page, posture_form_page, posture_page,
    posture_too_large_page, risk_entity_page, risk_page, shell_detail_page, shell_page, vuln_asset_page, vulns_page, STYLESHEET,
};
use crate::session::{
    admit_login, clear_cookie, cookie_value, create_session, csrf_matches, drop_session, find_session, new_secret, set_cookie, LANGUAGE_COOKIE,
    LANGUAGE_COOKIE_SECONDS, LOGIN_COOKIE, LOGIN_COOKIE_SECONDS, SESSION_COOKIE,
};
use crate::strings::{checked_action, checked_triage_status};
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


pub fn require_signed(accepted: bool, language: Language, csrf: &str, status: StatusCode, key: &str) -> Result<(), Refused> {
    if accepted {
        Ok(())
    } else {
        Err(Box::new(refusal(language, Some(csrf), status, key)))
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


/// A fixed class name per failure, safe to log: never the URL, the status text or an API value.
pub fn failure_class(failure: &ApiFailure) -> &'static str {
    match failure {
        ApiFailure::Unauthorized => "unauthorized",
        ApiFailure::Forbidden => "forbidden",
        ApiFailure::NotFound => "not_found",
        ApiFailure::Throttled => "throttled",
        ApiFailure::BadRequest => "bad_request",
        ApiFailure::Unavailable(_) => "unavailable",
        ApiFailure::Handshake(_) => "handshake",
        ApiFailure::Conflict(_) => "conflict",
        ApiFailure::Unreadable => "unreadable",
        ApiFailure::Status(_) => "status",
        ApiFailure::TooLarge => "too_large",
        ApiFailure::Malformed(_) => "malformed",
        ApiFailure::Json { .. } => "json",
    }
}


/// A page for a failed API call: our own text per class, never the API's.
pub fn api_refusal(language: Language, csrf: Option<&str>, failure: &ApiFailure) -> Response {
    let class = failure_class(failure);
    tracing::warn!(class, "API call failed");
    match failure {
        ApiFailure::Unauthorized | ApiFailure::Forbidden => refusal(language, csrf, StatusCode::FORBIDDEN, "error_forbidden"),
        ApiFailure::NotFound => refusal(language, csrf, StatusCode::NOT_FOUND, "error_not_found"),
        ApiFailure::Throttled => refusal(language, csrf, StatusCode::TOO_MANY_REQUESTS, "error_throttled"),
        ApiFailure::BadRequest => refusal(language, csrf, StatusCode::BAD_REQUEST, "error_bad_request"),
        ApiFailure::Conflict(key) => refusal(language, csrf, StatusCode::CONFLICT, key),
        ApiFailure::Unreadable => refusal(language, csrf, StatusCode::UNPROCESSABLE_ENTITY, "oncall_unreadable"),
        ApiFailure::Unavailable(_)
        | ApiFailure::Handshake(_)
        | ApiFailure::Status(_)
        | ApiFailure::TooLarge
        | ApiFailure::Malformed(_)
        | ApiFailure::Json { .. } => refusal(language, csrf, StatusCode::BAD_GATEWAY, "error_unavailable"),
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
            .unwrap_or_else(|failure| tracing::warn!(class = failure_class(&failure), "the API did not confirm the logout of a dropped session"));
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
        .unwrap_or_else(|failure| tracing::warn!(class = failure_class(&failure), "the API did not confirm the logout"));
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


pub async fn show_cases_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let cursor = parse_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let limit = parse_limit(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let page = list_cases(&client, source, &principal.token, cursor, limit)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &cases_page(language, &principal.csrf, &page, limit), &[]))
}


pub async fn show_cases(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_cases_page(&state, peer.ip(), &headers, &query).await)
}


pub fn parse_links_cursor(query: &BTreeMap<String, String>) -> Result<Option<&str>, FormRefusal> {
    query
        .get("links_cursor")
        .map(|text| Some(text.as_str()).filter(|cursor| valid_cursor(cursor)).ok_or(FormRefusal::Malformed))
        .transpose()
}


/// The panel of the linked alerts: a `401` ends the session, any other failure is our unavailable text and the case page still renders.
pub async fn load_links(
    state: &WebState,
    client: &ApiClient,
    source: IpAddr,
    principal: &Principal,
    language: Language,
    (id, cursor): (&str, Option<&str>),
) -> Result<LinksPanel, Refused> {
    match list_case_links(client, source, &principal.token, id, cursor).await {
        Ok(page) => Ok(LinksPanel::Shown(page)),
        Err(ApiFailure::Unauthorized) => Err(Box::new(api_failure(state, principal, language, &ApiFailure::Unauthorized))),
        Err(failure) => {
            let class = failure_class(&failure);
            tracing::warn!(class, "the linked alerts could not be read");
            Ok(LinksPanel::Unavailable)
        }
    }
}


pub async fn show_case_page(
    state: &WebState,
    source: IpAddr,
    headers: &HeaderMap,
    id: &str,
    query: &BTreeMap<String, String>,
) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    require(valid_case_id(id), language, StatusCode::NOT_FOUND, "error_not_found")?;
    let cursor = parse_links_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let case = get_case(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    let panel = load_links(state, &client, source, &principal, language, (id, cursor)).await?;
    let observables = load_observables(state, &client, source, &principal, language, id).await?;
    Ok(html_response(
        StatusCode::OK,
        &case_page_all(language, &principal.csrf, &case, None, (&panel, &observables, false)),
        &[],
    ))
}


pub async fn show_case(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_case_page(&state, peer.ip(), &headers, &id, &query).await)
}


pub fn parse_asset_cursor(query: &BTreeMap<String, String>) -> Result<Option<&str>, FormRefusal> {
    query
        .get("cursor")
        .map(|text| {
            Some(text.as_str())
                .filter(|cursor| valid_asset_cursor(cursor))
                .ok_or(FormRefusal::Malformed)
        })
        .transpose()
}


pub async fn show_assets_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let cursor = parse_asset_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let limit = parse_limit(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let page = list_assets(&client, source, &principal.token, cursor, limit)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &assets_page(language, &principal.csrf, &page, limit), &[]))
}


pub async fn show_assets(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_assets_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_asset_page(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let asset = get_asset(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &asset_page(language, &principal.csrf, &asset), &[]))
}


pub async fn show_asset(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    merge(show_asset_page(&state, peer.ip(), &headers, &id).await)
}


/// The risk module answers `503` when a computation passes its deadline: our own retry text, never the API's.
pub fn risk_failure(state: &WebState, principal: &Principal, language: Language, failure: &ApiFailure) -> Response {
    match failure {
        ApiFailure::Status(status) if *status == StatusCode::SERVICE_UNAVAILABLE.as_u16() => {
            tracing::warn!(class = failure_class(failure), "risk computation unavailable");
            refusal(language, Some(&principal.csrf), StatusCode::SERVICE_UNAVAILABLE, "risk_busy")
        }
        other => api_failure(state, principal, language, other),
    }
}


pub fn parse_risk_kind(query: &BTreeMap<String, String>) -> Result<Option<&'static str>, FormRefusal> {
    query.get("kind").map(|text| risk_kind(text).ok_or(FormRefusal::Malformed)).transpose()
}


pub async fn show_risk_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let kind = parse_risk_kind(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let list = list_risk(&client, source, &principal.token, kind)
        .await
        .map_err(|failure| Box::new(risk_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &risk_page(language, &principal.csrf, &list), &[]))
}


pub async fn show_risk(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_risk_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_risk_entity_page(state: &WebState, source: IpAddr, headers: &HeaderMap, kind: &str, id: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let detail = get_risk_entity(&client, source, &principal.token, kind, id)
        .await
        .map_err(|failure| Box::new(risk_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &risk_entity_page(language, &principal.csrf, &detail), &[]))
}


pub async fn show_risk_entity(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, String)>,
) -> Response {
    merge(show_risk_entity_page(&state, peer.ip(), &headers, &kind, &id).await)
}


pub fn parse_cert_filter(query: &BTreeMap<String, String>) -> Result<&'static str, FormRefusal> {
    query
        .get("expiring")
        .map_or(Ok("all"), |text| cert_filter(text).ok_or(FormRefusal::Malformed))
}


pub fn parse_cert_cursor(query: &BTreeMap<String, String>) -> Result<Option<&str>, FormRefusal> {
    query
        .get("cursor")
        .map(|text| {
            Some(text.as_str())
                .filter(|cursor| valid_cert_cursor(cursor))
                .ok_or(FormRefusal::Malformed)
        })
        .transpose()
}


/// The cut-off is the injected wall clock plus a fixed number of days: the browser never supplies a time.
pub fn expiring_before(wall: i64, filter: &str) -> Option<i64> {
    filter
        .parse::<i64>()
        .ok()
        .map(|days| wall.saturating_add(days.saturating_mul(SECONDS_PER_DAY)))
}


pub async fn show_certs_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let filter = parse_cert_filter(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let cursor = parse_cert_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let list = list_certs(&client, source, &principal.token, cursor, expiring_before((state.wall)(), filter))
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &certs_page(language, &principal.csrf, &list, filter), &[]))
}


pub async fn show_certs(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_certs_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_cert_page(state: &WebState, source: IpAddr, headers: &HeaderMap, fingerprint: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let detail = get_cert(&client, source, &principal.token, fingerprint)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &cert_page(language, &principal.csrf, &detail), &[]))
}


pub async fn show_cert(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(fingerprint): Path<String>,
) -> Response {
    merge(show_cert_page(&state, peer.ip(), &headers, &fingerprint).await)
}


pub fn parse_hunt_cursor(query: &BTreeMap<String, String>) -> Result<Option<&str>, FormRefusal> {
    query
        .get("cursor")
        .map(|text| {
            Some(text.as_str())
                .filter(|cursor| valid_hunt_cursor(cursor))
                .ok_or(FormRefusal::Malformed)
        })
        .transpose()
}


pub async fn show_groups_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    require(query.is_empty(), language, StatusCode::BAD_REQUEST, "error_bad_request")?;
    let client = state.api.load_full();
    let list = list_groups(&client, source, &principal.token)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &groups_page(language, &principal.csrf, &list), &[]))
}


pub async fn show_groups(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_groups_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_hunts_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let cursor = parse_hunt_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let list = list_findings(&client, source, &principal.token, cursor)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &hunts_page(language, &principal.csrf, &list), &[]))
}


pub async fn show_hunts(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_hunts_page(&state, peer.ip(), &headers, &query).await)
}


/// The verdict from its fixed set (`fail` when absent), an empty baseline as none, any other baseline inside the API's grammar.
pub fn parse_state_filter(query: &BTreeMap<String, String>) -> Result<(&'static str, Option<&str>), FormRefusal> {
    let verdict = query
        .get("verdict")
        .map_or(Some(VERDICT_DEFAULT), |text| verdict_filter(text))
        .ok_or(FormRefusal::Malformed)?;
    let baseline = query
        .get("baseline")
        .map(String::as_str)
        .filter(|name| !name.is_empty())
        .map_or(Ok(None), |name| valid_state_id(name).then_some(Some(name)).ok_or(FormRefusal::Malformed))?;
    Ok((verdict, baseline))
}


pub fn parse_state_cursor(query: &BTreeMap<String, String>) -> Result<Option<&str>, FormRefusal> {
    query
        .get("cursor")
        .map(|text| {
            Some(text.as_str())
                .filter(|cursor| valid_state_cursor(cursor))
                .ok_or(FormRefusal::Malformed)
        })
        .transpose()
}


pub async fn show_compliance_page(
    state: &WebState,
    source: IpAddr,
    headers: &HeaderMap,
    query: &BTreeMap<String, String>,
) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let (verdict, baseline) = parse_state_filter(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let cursor = parse_state_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let list = list_states(&client, source, &principal.token, verdict, baseline, cursor)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(
        StatusCode::OK,
        &compliance_page(language, &principal.csrf, &list, verdict, baseline),
        &[],
    ))
}


pub async fn show_compliance(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_compliance_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_compliance_asset_page(state: &WebState, source: IpAddr, headers: &HeaderMap, asset: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let detail = get_state_asset(&client, source, &principal.token, asset)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(
        StatusCode::OK,
        &compliance_asset_page(language, &principal.csrf, asset, &detail),
        &[],
    ))
}


pub async fn show_compliance_asset(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(asset): Path<String>,
) -> Response {
    merge(show_compliance_asset_page(&state, peer.ip(), &headers, &asset).await)
}


pub fn parse_vuln_cursor(query: &BTreeMap<String, String>) -> Result<Option<&str>, FormRefusal> {
    query
        .get("cursor")
        .map(|text| {
            Some(text.as_str())
                .filter(|cursor| valid_vuln_cursor(cursor))
                .ok_or(FormRefusal::Malformed)
        })
        .transpose()
}


pub async fn show_vulns_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let cursor = parse_vuln_cursor(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let list = list_vulns(&client, source, &principal.token, cursor)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &vulns_page(language, &principal.csrf, &list), &[]))
}


pub async fn show_vulns(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_vulns_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_vuln_asset_page(state: &WebState, source: IpAddr, headers: &HeaderMap, asset: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let detail = get_vuln_asset(&client, source, &principal.token, asset)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(
        StatusCode::OK,
        &vuln_asset_page(language, &principal.csrf, asset, &detail),
        &[],
    ))
}


pub async fn show_vuln_asset(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(asset): Path<String>,
) -> Response {
    merge(show_vuln_asset_page(&state, peer.ip(), &headers, &asset).await)
}


pub async fn show_oncall_page(state: &WebState, source: IpAddr, headers: &HeaderMap) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let list = list_oncall(&client, source, &principal.token)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &oncall_page(language, &principal.csrf, &list), &[]))
}


pub async fn show_oncall(State(state): State<SharedWeb>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    merge(show_oncall_page(&state, peer.ip(), &headers).await)
}


pub async fn show_oncall_alert_page(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let alert = get_oncall_alert(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &oncall_alert_page(language, &principal.csrf, &alert), &[]))
}


pub async fn show_oncall_alert(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    merge(show_oncall_alert_page(&state, peer.ip(), &headers, &id).await)
}


pub fn parse_report_framework(query: &BTreeMap<String, String>) -> Option<&str> {
    query.get("framework").map(String::as_str).filter(|name| !name.is_empty())
}


pub async fn show_grc_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let framework = parse_report_framework(query);
    let client = state.api.load_full();
    let list = list_grc(&client, source, &principal.token, framework)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &grc_page(language, &principal.csrf, &list, framework), &[]))
}


pub async fn show_grc(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_grc_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_grc_report_page(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let report = get_grc(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &grc_report_page(language, &principal.csrf, &report), &[]))
}


pub async fn show_grc_report(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    merge(show_grc_report_page(&state, peer.ip(), &headers, &id).await)
}


pub async fn show_attack_page(state: &WebState, source: IpAddr, headers: &HeaderMap) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let list = list_attack(&client, source, &principal.token)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &attack_page(language, &principal.csrf, &list), &[]))
}


pub async fn show_attack(State(state): State<SharedWeb>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap) -> Response {
    merge(show_attack_page(&state, peer.ip(), &headers).await)
}


pub async fn show_attack_report_page(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let report = get_attack(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(
        StatusCode::OK,
        &attack_report_page(language, &principal.csrf, &report),
        &[],
    ))
}


pub async fn show_attack_report(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    merge(show_attack_report_page(&state, peer.ip(), &headers, &id).await)
}


pub const COMMENT_FORM_BYTES: usize = MAX_COMMENT_CHARS * FORM_BYTES_PER_CHAR + FORM_OVERHEAD_BYTES;


pub const FORM_BYTES_PER_CHAR: usize = 12;


pub const FORM_OVERHEAD_BYTES: usize = 1024;


/// A comment of the API's cap of four-byte characters must fit the form, so this route reads more than `form_bytes`, still bounded.
pub fn comment_limits(limits: &WebLimits) -> WebLimits {
    WebLimits {
        form_bytes: limits.form_bytes.max(COMMENT_FORM_BYTES),
        ..*limits
    }
}


/// The session, the form and the CSRF token, in that order and before anything else; the form is returned for the fields.
pub async fn write_request(state: &WebState, headers: &HeaderMap, body: Body, limits: &WebLimits) -> Result<(Principal, Form), Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let form = read_form(body, limits).await.map_err(|reason| Box::new(form_refusal(language, reason)))?;
    require(
        csrf_matches(&principal.csrf, field(&form, "csrf")),
        language,
        StatusCode::FORBIDDEN,
        "error_csrf",
    )?;
    Ok((principal, form))
}


pub async fn submit_case_action(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    let (principal, form) = write_request(state, headers, body, &state.limits).await?;
    let resolution = form.get("resolution").map(String::as_str).filter(|value| !value.is_empty());
    let (action, fixed_resolution) = checked_action(field(&form, "action"), resolution)
        .ok_or_else(|| Box::new(refusal(language, Some(&principal.csrf), StatusCode::BAD_REQUEST, "error_bad_request")))?;
    let client = state.api.load_full();
    let case = post_case_action(&client, source, &principal.token, id, action, fixed_resolution)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &case_page(language, &principal.csrf, &case), &[]))
}


pub async fn case_action_submit(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    merge(submit_case_action(&state, peer.ip(), &headers, &id, body).await)
}


/// The characters a textarea counts: a browser sends a line break as CRLF, which the user sees and the `maxlength` counts as one.
pub fn browser_chars(text: &str) -> usize {
    text.chars().count() - text.matches("\r\n").count()
}


pub fn comment_shaped(text: &str) -> bool {
    !text.is_empty() && browser_chars(text) <= MAX_COMMENT_CHARS
}


pub async fn submit_case_comment(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    let (principal, form) = write_request(state, headers, body, &comment_limits(&state.limits)).await?;
    let text = field(&form, "text");
    require_signed(
        comment_shaped(text),
        language,
        &principal.csrf,
        StatusCode::BAD_REQUEST,
        "error_bad_request",
    )?;
    let client = state.api.load_full();
    let stored = post_case_comment(&client, source, &principal.token, id, text)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    let reread = get_case(&client, source, &principal.token, id).await;
    Ok(comment_answer(state, &principal, language, id, &stored, &reread))
}


/// The page after a stored comment: the case when it was read again, else the stored comment and our own fixed text; a `401` ends the session.
pub fn comment_answer(
    state: &WebState,
    principal: &Principal,
    language: Language,
    id: &str,
    stored: &CommentView,
    reread: &Result<CaseDetailView, ApiFailure>,
) -> Response {
    match reread {
        Ok(case) => html_response(StatusCode::OK, &case_page_with(language, &principal.csrf, case, Some(stored)), &[]),
        Err(ApiFailure::Unauthorized) => {
            tracing::warn!("the case re-read after a comment was refused with 401");
            drop_session(state, &principal.key);
            let page = comment_unloaded_page(language, None, stored, "/login", "comment_signin", "login_submit");
            html_response(StatusCode::OK, &page, &[clear_cookie(SESSION_COOKIE)])
        }
        Err(failure) => {
            let class = failure_class(failure);
            tracing::warn!(class, "the case re-read after a comment failed");
            let page = comment_unloaded_page(
                language,
                Some(&principal.csrf),
                stored,
                &format!("/cases/{id}"),
                "comment_unloaded",
                "case_reload",
            );
            html_response(StatusCode::OK, &page, &[])
        }
    }
}


pub async fn case_comment_submit(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    merge(submit_case_comment(&state, peer.ip(), &headers, &id, body).await)
}


/// The note of the form: an empty textarea is no note, at most `MAX_NOTE_CHARS` characters otherwise; `None` is a refusal.
pub fn triage_note(form: &Form) -> Option<Option<&str>> {
    let note = field(form, "note");
    Some(note)
        .filter(|text| browser_chars(text) <= MAX_NOTE_CHARS)
        .map(|text| Some(text).filter(|kept| !kept.is_empty()))
}


/// The version of the form: absent while the alert is new, else ASCII digits of an integer from 1; `None` is a refusal.
pub fn triage_version(form: &Form) -> Option<Option<i64>> {
    form.get("version").map_or(Some(None), |text| {
        Some(text)
            .filter(|digits| !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit()))
            .and_then(|digits| digits.parse::<i64>().ok())
            .filter(|read| *read >= 1)
            .map(Some)
    })
}


pub async fn submit_alert_triage(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    let (principal, form) = write_request(state, headers, body, &comment_limits(&state.limits)).await?;
    let bad_request = || Box::new(refusal(language, Some(&principal.csrf), StatusCode::BAD_REQUEST, "error_bad_request"));
    let status = checked_triage_status(field(&form, "status")).ok_or_else(bad_request)?;
    let note = triage_note(&form).ok_or_else(bad_request)?;
    let version = triage_version(&form).ok_or_else(bad_request)?;
    let client = state.api.load_full();
    post_alert_triage(&client, source, &principal.token, id, status, note, version)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    let alert = get_alert(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(StatusCode::OK, &alert_page(language, &principal.csrf, &alert), &[]))
}


pub async fn alert_triage_submit(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    merge(submit_alert_triage(&state, peer.ip(), &headers, &id, body).await)
}


pub async fn submit_case_link(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    let (principal, form) = write_request(state, headers, body, &state.limits).await?;
    require_signed(
        valid_id(field(&form, "alert_id")),
        language,
        &principal.csrf,
        StatusCode::BAD_REQUEST,
        "error_bad_request",
    )?;
    let client = state.api.load_full();
    post_case_link(&client, source, &principal.token, id, field(&form, "alert_id"))
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    let case = get_case(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    let panel = load_links(state, &client, source, &principal, language, (id, None)).await?;
    Ok(html_response(
        StatusCode::OK,
        &case_page_full(language, &principal.csrf, &case, None, &panel),
        &[],
    ))
}


pub async fn case_link_submit(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    merge(submit_case_link(&state, peer.ip(), &headers, &id, body).await)
}


/// The observables panel: a `401` ends the session, any other failure is our unavailable text and the case page still renders.
pub async fn load_observables(
    state: &WebState,
    client: &ApiClient,
    source: IpAddr,
    principal: &Principal,
    language: Language,
    id: &str,
) -> Result<ObservablesPanel, Refused> {
    match list_case_observables(client, source, &principal.token, id).await {
        Ok(list) => Ok(ObservablesPanel::Shown(list)),
        Err(ApiFailure::Unauthorized) => Err(Box::new(api_failure(state, principal, language, &ApiFailure::Unauthorized))),
        Err(ApiFailure::TooLarge) => {
            tracing::warn!(class = "observables_too_large", "The observables answer is over the body cap");
            Ok(ObservablesPanel::TooLarge)
        }
        Err(failure) => {
            let class = failure_class(&failure);
            tracing::warn!(class, "the observables could not be read");
            Ok(ObservablesPanel::Unavailable)
        }
    }
}


pub const OBSERVABLE_FORM_BYTES: usize = (MAX_OBSERVABLE_CHARS + MAX_SOURCE_CHARS) * FORM_BYTES_PER_CHAR + FORM_OVERHEAD_BYTES;


/// A value and a source of the API's caps, four-byte characters percent-encoded, must fit the form.
pub fn observable_limits(limits: &WebLimits) -> WebLimits {
    WebLimits {
        form_bytes: limits.form_bytes.max(OBSERVABLE_FORM_BYTES),
        ..*limits
    }
}


/// Session, form and CSRF first; then the four selects and the two texts against the fixed tables and shapes; then the API.
pub async fn submit_case_observable(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str, body: Body) -> Result<Response, Refused> {
    let language = language_of(headers);
    let (principal, form) = write_request(state, headers, body, &observable_limits(&state.limits)).await?;
    let fields = checked_observable(
        (field(&form, "kind"), field(&form, "tlp"), field(&form, "pap"), field(&form, "ioc")),
        (field(&form, "value"), field(&form, "source")),
    )
    .ok_or_else(|| Box::new(refusal(language, Some(&principal.csrf), StatusCode::BAD_REQUEST, "error_bad_request")))?;
    let client = state.api.load_full();
    let already = post_case_observable(&client, source, &principal.token, id, &fields)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    let case = get_case(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    let observables = load_observables(state, &client, source, &principal, language, id).await?;
    Ok(html_response(
        StatusCode::OK,
        &case_page_all(language, &principal.csrf, &case, None, (&LinksPanel::Absent, &observables, already)),
        &[],
    ))
}


pub async fn case_observable_submit(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    merge(submit_case_observable(&state, peer.ip(), &headers, &id, body).await)
}


pub fn build_router(state: SharedWeb) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/style.css", get(stylesheet))
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", post(logout_submit))
        .route("/alerts", get(show_alerts))
        .route("/alerts/{id}", get(show_alert))
        .route("/cases", get(show_cases))
        .route("/cases/{id}", get(show_case))
        .route("/assets", get(show_assets))
        .route("/assets/{id}", get(show_asset))
        .route("/risk", get(show_risk))
        .route("/risk/{kind}/{id}", get(show_risk_entity))
        .route("/certificates", get(show_certs))
        .route("/certificates/{fingerprint}", get(show_cert))
        .route("/alert-groups", get(show_groups))
        .route("/hunts", get(show_hunts))
        .route("/compliance", get(show_compliance))
        .route("/compliance/{asset}", get(show_compliance_asset))
        .route("/dhcp", get(show_dhcp))
        .route("/posture", get(show_posture_form))
        .route("/posture/{account}", get(show_posture))
        .route("/remote-shell", get(show_shell))
        .route("/remote-shell/{id}", get(show_shell_session))
        .route("/vulnerabilities", get(show_vulns))
        .route("/vulnerabilities/{asset}", get(show_vuln_asset))
        .route("/oncall", get(show_oncall))
        .route("/oncall/{id}", get(show_oncall_alert))
        .route("/grc", get(show_grc))
        .route("/grc/{id}", get(show_grc_report))
        .route("/attack-paths", get(show_attack))
        .route("/attack-paths/{id}", get(show_attack_report))
        .route("/alerts/{id}/triage", post(alert_triage_submit))
        .route("/cases/{id}/action", post(case_action_submit))
        .route("/cases/{id}/comment", post(case_comment_submit))
        .route("/cases/{id}/alerts", post(case_link_submit))
        .route("/cases/{id}/observables", post(case_observable_submit))
        .route("/language/{code}", post(switch_language))
        .fallback(not_found)
        .layer(from_fn(harden))
        .with_state(state)
}


/// The lookup the browser asked for: `address` and `at` are the first form, `mac`, `from` and `to` the second; nothing else is read, and a value outside the API's grammar is refused before any call.
pub fn parse_dhcp_query(query: &BTreeMap<String, String>) -> Result<Option<DhcpQuery>, FormRefusal> {
    let value = |name: &str| query.get(name).map(String::as_str);
    let at_form = ["address", "at"].iter().any(|name| query.contains_key(*name));
    let mac_form = ["mac", "from", "to"].iter().any(|name| query.contains_key(*name));
    match (at_form, mac_form) {
        (false, false) => Ok(None),
        (true, false) => parse_dhcp_address(value("address"))
            .zip(parse_dhcp_time(value("at")))
            .map(|(address, at)| Some(DhcpQuery::At { address, at }))
            .ok_or(FormRefusal::Malformed),
        (false, true) => parse_dhcp_mac(value("mac"))
            .zip(parse_dhcp_window(value("from"), value("to")))
            .map(|(mac, (from, to))| Some(DhcpQuery::Mac { mac, from, to }))
            .ok_or(FormRefusal::Malformed),
        (true, true) => Err(FormRefusal::Malformed),
    }
}


pub async fn show_dhcp_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let checked = parse_dhcp_query(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let found = match &checked {
        Some(lookup) => Some(
            get_dhcp(&client, source, &principal.token, lookup)
                .await
                .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?,
        ),
        None => {
            probe_dhcp(&client, source, &principal.token)
                .await
                .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
            None
        }
    };
    Ok(html_response(StatusCode::OK, &dhcp_page(language, &principal.csrf, found.as_ref()), &[]))
}


/// The 409 `run_changed` and a page over the body cap are pages with a link to the first page; every other failure is the generic one.
pub fn posture_failure(state: &WebState, principal: &Principal, language: Language, account: &str, failure: &ApiFailure) -> Response {
    match failure {
        ApiFailure::Conflict(key) if *key == RUN_CHANGED_KEY => {
            html_response(StatusCode::CONFLICT, &posture_changed_page(language, &principal.csrf, account), &[])
        }
        ApiFailure::TooLarge => {
            tracing::warn!(class = "posture_page_too_large", "Posture page over the body cap");
            html_response(StatusCode::BAD_GATEWAY, &posture_too_large_page(language, &principal.csrf, account), &[])
        }
        other => api_failure(state, principal, language, other),
    }
}


/// One findings page: the account and the cursor are checked inside `get_posture`, before any API call.
pub async fn show_posture_page(
    state: &WebState,
    source: IpAddr,
    headers: &HeaderMap,
    account: &str,
    cursor: Option<&str>,
) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let view = get_posture(&client, source, &principal.token, account, cursor)
        .await
        .map_err(|failure| Box::new(posture_failure(state, &principal, language, account, &failure)))?;
    Ok(html_response(
        StatusCode::OK,
        &posture_page(language, &principal.csrf, account, &view),
        &[],
    ))
}


/// `GET /posture`: with `account` the first findings page, without it the form after one permission probe; nothing else is read.
pub async fn show_posture_form_page(
    state: &WebState,
    source: IpAddr,
    headers: &HeaderMap,
    query: &BTreeMap<String, String>,
) -> Result<Response, Refused> {
    match query.get("account") {
        Some(account) => show_posture_page(state, source, headers, account, None).await,
        None => {
            let language = language_of(headers);
            let principal = current_principal(state, headers)?;
            let client = state.api.load_full();
            probe_posture(&client, source, &principal.token)
                .await
                .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
            Ok(html_response(StatusCode::OK, &posture_form_page(language, &principal.csrf), &[]))
        }
    }
}


pub async fn show_posture_form(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_posture_form_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_posture(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_posture_page(&state, peer.ip(), &headers, &account, query.get("cursor").map(String::as_str)).await)
}


/// A filter text: absent or empty is no filter, any other must pass `valid`.
pub fn shell_filter(query: &BTreeMap<String, String>, name: &str, valid: fn(&str) -> bool) -> Result<Option<String>, FormRefusal> {
    query
        .get(name)
        .filter(|text| !text.is_empty())
        .map_or(Ok(None), |text| valid(text).then(|| Some(text.clone())).ok_or(FormRefusal::Malformed))
}


/// The register query the browser asked for: `asset`, `requester`, `open` and `cursor`, each inside the API's grammar, nothing else is read.
pub fn parse_shell_query(query: &BTreeMap<String, String>) -> Result<ShellQuery, FormRefusal> {
    let open = query
        .get("open")
        .map_or(Some(None), |text| shell_open_filter(text))
        .ok_or(FormRefusal::Malformed)?;
    let cursor = query
        .get("cursor")
        .map(|text| valid_shell_cursor(text).then(|| text.clone()).ok_or(FormRefusal::Malformed))
        .transpose()?;
    Ok(ShellQuery {
        asset: shell_filter(query, "asset", valid_shell_reference)?,
        requester: shell_filter(query, "requester", valid_shell_filter_requester)?,
        open,
        cursor,
    })
}


pub async fn show_shell_page(state: &WebState, source: IpAddr, headers: &HeaderMap, query: &BTreeMap<String, String>) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let checked = parse_shell_query(query).map_err(|reason| Box::new(form_refusal(language, reason)))?;
    let client = state.api.load_full();
    let list = list_shell_sessions(&client, source, &principal.token, &checked)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(
        StatusCode::OK,
        &shell_page(language, &principal.csrf, &list, &checked),
        &[],
    ))
}


pub async fn show_shell(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_shell_page(&state, peer.ip(), &headers, &query).await)
}


pub async fn show_shell_session_page(state: &WebState, source: IpAddr, headers: &HeaderMap, id: &str) -> Result<Response, Refused> {
    let language = language_of(headers);
    let principal = current_principal(state, headers)?;
    let client = state.api.load_full();
    let session = get_shell_session(&client, source, &principal.token, id)
        .await
        .map_err(|failure| Box::new(api_failure(state, &principal, language, &failure)))?;
    Ok(html_response(
        StatusCode::OK,
        &shell_detail_page(language, &principal.csrf, &session),
        &[],
    ))
}


pub async fn show_shell_session(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    merge(show_shell_session_page(&state, peer.ip(), &headers, &id).await)
}


pub async fn show_dhcp(
    State(state): State<SharedWeb>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    merge(show_dhcp_page(&state, peer.ip(), &headers, &query).await)
}
