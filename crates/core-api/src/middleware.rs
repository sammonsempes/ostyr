use crate::failure::{auth_failure, error_response};
use crate::model::{ApiError, ApiState, Authenticated, Decision, Exchange, Limits, RequestId, Requirement, Window};
use crate::routes::{route_key, BODY_LIMIT_BYTES};
use crate::state::{lock_auth, refresh_accounts, session_revoked};
use crate::types::SharedState;
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::header::{
    HeaderName, AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;
use core_audit::error::AuditError;
use core_audit::log::append_declared;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_auth::error::AuthError;
use core_auth::random::random_array;
use core_auth::service::{authorize, ANONYMOUS_ACTOR};
use core_auth::session::{revoke_session, validate_session};
use core_auth::types::{RandomFn, RoleCatalog};
use core_config::reload::bounded_value;
use data_encoding::HEXLOWER;
use http_body_util::LengthLimitError;
use secrecy::SecretString;
use std::error::Error;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::PoisonError;
use std::time::Instant;
use time::{Duration, OffsetDateTime};


pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");


pub const REQUEST_ID_MAX_LENGTH: usize = 64;


pub const REQUEST_ID_BYTES: usize = 16;


pub const IPV6_HOST_BITS: u32 = 64;


pub const UNAVAILABLE_ID: &str = "unavailable";


pub const UNMATCHED_ROUTE: &str = "unmatched";


pub const BEARER_PREFIX: &[u8] = b"Bearer ";


pub const ACTION_REQUEST: &str = "api.request";


pub const REQUEST_DECLARED_KEYS: [&str; 2] = ["source", "status"];


pub const LOG_TARGET: &str = "core_api::request";


pub const DENIED_STATUSES: [StatusCode; 2] = [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN];


pub const SECURITY_HEADERS: [(HeaderName, HeaderValue); 6] = [
    (STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains")),
    (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
    (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
    (CACHE_CONTROL, HeaderValue::from_static("no-store")),
    (
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    ),
    (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
];


pub fn is_valid_request_id(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= REQUEST_ID_MAX_LENGTH
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}


pub fn request_id(headers: &HeaderMap, random: RandomFn) -> Result<String, AuthError> {
    match headers
        .get(REQUEST_ID_HEADER)
        .map(HeaderValue::as_bytes)
        .filter(|bytes| is_valid_request_id(bytes))
    {
        Some(bytes) => Ok(String::from_utf8_lossy(bytes).into_owned()),
        None => random_array::<REQUEST_ID_BYTES>(random).map(|bytes| HEXLOWER.encode(&bytes)),
    }
}


pub fn decorate(headers: &mut HeaderMap, request_id: &str) {
    SECURITY_HEADERS.iter().for_each(|(name, value)| {
        headers.insert(name.clone(), value.clone());
    });
    HeaderValue::from_str(request_id).into_iter().for_each(|value| {
        headers.insert(REQUEST_ID_HEADER, value);
    });
}


pub fn result_label(status: StatusCode) -> &'static str {
    if status == StatusCode::TOO_MANY_REQUESTS {
        "rate_limited"
    } else if DENIED_STATUSES.contains(&status) {
        "denied"
    } else if status.is_success() {
        "success"
    } else {
        "failure"
    }
}


pub fn log_request(app: &ApiState, id: &str, method: &str, path: &str, source: IpAddr, status: StatusCode, elapsed: std::time::Duration) {
    let identity = app.identity.load();
    let (module, tenant) = (identity.module.as_str(), identity.tenant.as_str());
    let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let (result, code) = (result_label(status), status.as_u16());
    tracing::dispatcher::with_default(&app.dispatch, || {
        tracing::info!(target: LOG_TARGET, module, tenant, request_id = id, duration_ms, result, method, path, status = code, source = %source, "request");
    });
}


pub async fn edge(State(app): State<SharedState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, mut request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let (id, mut response) = match request_id(request.headers(), app.random) {
        Ok(id) => {
            request.extensions_mut().insert(RequestId(id.clone()));
            let response = next.run(request).await;
            (id, response)
        }
        Err(error) => {
            tracing::warn!(%error, "request id generation failed");
            (UNAVAILABLE_ID.to_owned(), error_response(&ApiError::Internal))
        }
    };
    decorate(response.headers_mut(), &id);
    log_request(&app, &id, &method, &path, peer.ip(), response.status(), started.elapsed());
    response
}


pub fn rate_key(source: IpAddr) -> IpAddr {
    let canonical = source.to_canonical();
    match canonical {
        IpAddr::V4(_) => canonical,
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from((u128::from(address) >> IPV6_HOST_BITS) << IPV6_HOST_BITS)),
    }
}


pub fn window_open(window: &Window, now: OffsetDateTime, limits: &Limits) -> bool {
    now - window.started < Duration::seconds(limits.rate_window_seconds)
}


pub fn count_request(window: &mut Window, now: OffsetDateTime, limits: &Limits) -> bool {
    if !window_open(window, now, limits) {
        *window = Window { started: now, count: 0 };
    }
    window.count < limits.rate_max_requests && {
        window.count += 1;
        true
    }
}


pub fn admit_source(app: &ApiState, source: IpAddr) -> bool {
    let now = (app.clock)();
    let limits = app.limits.load_full();
    let mut table = app.limiter.lock().unwrap_or_else(PoisonError::into_inner);
    if table.len() >= limits.max_sources {
        table.retain(|_, window| window_open(window, now, &limits));
    }
    let key = rate_key(source);
    let known = table.contains_key(&key);
    if known || table.len() < limits.max_sources {
        count_request(table.entry(key).or_insert(Window { started: now, count: 0 }), now, &limits)
    } else {
        false
    }
}


pub async fn limit(State(app): State<SharedState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, request: Request, next: Next) -> Response {
    if admit_source(&app, peer.ip()) {
        next.run(request).await
    } else {
        error_response(&ApiError::TooManyRequests)
    }
}


pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(BEARER_PREFIX))
        .map(|token| String::from_utf8_lossy(token).into_owned())
}


pub fn route_of(request: &Request) -> String {
    let path = request.extensions().get::<MatchedPath>().map_or(UNMATCHED_ROUTE, MatchedPath::as_str);
    route_key(request.method().as_str(), path)
}


pub fn admit(actor: &str, session: Option<Authenticated>) -> Decision {
    Decision {
        actor: actor.to_owned(),
        session,
        error: None,
    }
}


pub fn deny(actor: &str, error: ApiError) -> Decision {
    Decision {
        actor: actor.to_owned(),
        session: None,
        error: Some(error),
    }
}


pub fn check_requirement(
    auth: &mut core_auth::service::State,
    catalog: &RoleCatalog,
    requirement: Option<&Requirement>,
    token: &str,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    match requirement {
        Some(Requirement::Session) => Ok(()),
        Some(Requirement::Permission(permission)) => authorize(auth, catalog, token, now, permission)
            .map(|_| ())
            .map_err(|failure| auth_failure(&failure)),
        _ => Err(ApiError::Forbidden),
    }
}


pub fn authenticate(app: &ApiState, requirement: Option<&Requirement>, token: String, now: OffsetDateTime) -> Decision {
    let mut auth = lock_auth(app);
    match validate_session(&mut auth.sessions, &token, now) {
        Err(_) => deny(ANONYMOUS_ACTOR, ApiError::Unauthorized),
        Ok(user) => match refresh_accounts(app, &mut auth) {
            Err(_) => deny(&user, ApiError::Unauthorized),
            Ok(()) if session_revoked(&auth, &token) => {
                revoke_session(&mut auth.sessions, &token);
                deny(&user, ApiError::Unauthorized)
            }
            Ok(()) => {
                let allowed = check_requirement(&mut auth, &app.catalog, requirement, &token, now);
                Decision {
                    actor: user.clone(),
                    session: allowed.is_ok().then(|| Authenticated {
                        user,
                        token: SecretString::from(token),
                    }),
                    error: allowed.err(),
                }
            }
        },
    }
}


pub fn decide(app: &ApiState, requirement: Option<&Requirement>, presented: Option<String>, now: OffsetDateTime) -> Decision {
    match (requirement, presented) {
        (Some(Requirement::Public), _) => admit(ANONYMOUS_ACTOR, None),
        (_, None) => deny(ANONYMOUS_ACTOR, ApiError::Unauthorized),
        (required, Some(token)) => authenticate(app, required, token, now),
    }
}


pub fn needs_audit(exchange: &Exchange) -> bool {
    exchange.state_changing || exchange.sensitive || DENIED_STATUSES.contains(&exchange.status)
}


pub fn exchange_outcome(status: StatusCode) -> Outcome {
    if DENIED_STATUSES.contains(&status) {
        Outcome::Denied
    } else if status.is_success() {
        Outcome::Success
    } else {
        Outcome::Failure
    }
}


pub fn audit_exchange(app: &ApiState, exchange: &Exchange) -> Result<(), AuditError> {
    if needs_audit(exchange) {
        let identity = app.identity.load();
        append_declared(
            &app.audit,
            NewEntry {
                timestamp: (app.clock)(),
                actor: Actor {
                    kind: ActorKind::User,
                    id: exchange.actor.clone(),
                },
                tenant: identity.tenant.clone(),
                module: identity.module.clone(),
                action: ACTION_REQUEST.to_owned(),
                target: exchange.route.clone(),
                outcome: exchange_outcome(exchange.status),
                request_id: exchange.request_id.clone(),
                justification: None,
                parameters: [
                    ("source".to_owned(), bounded_value(&exchange.source)),
                    ("status".to_owned(), exchange.status.as_u16().to_string()),
                ]
                .into_iter()
                .collect(),
            },
            &REQUEST_DECLARED_KEYS,
        )
        .map(|_| ())
    } else {
        Ok(())
    }
}


pub async fn guard(
    State(app): State<SharedState>,
    Extension(id): Extension<RequestId>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let route = route_of(&request);
    let rule = app.access.get(&route);
    let decision = decide(&app, rule.map(|found| &found.requirement), bearer_token(request.headers()), (app.clock)());
    let state_changing = !request.method().is_safe();
    let response = match decision.error {
        Some(error) => error_response(&error),
        None => {
            decision.session.into_iter().for_each(|session| {
                request.extensions_mut().insert(session);
            });
            next.run(request).await
        }
    };
    let exchange = Exchange {
        request_id: id.0,
        actor: decision.actor,
        route,
        state_changing,
        sensitive: rule.is_some_and(|found| found.sensitive),
        source: rate_key(peer.ip()).to_string(),
        status: response.status(),
    };
    match audit_exchange(&app, &exchange) {
        Ok(()) => response,
        Err(error) => {
            tracing::error!(%error, "audit append failed, request answered with an error");
            error_response(&ApiError::Internal)
        }
    }
}


pub fn body_failure(error: &axum::Error) -> ApiError {
    if error.source().is_some_and(|cause| cause.is::<LengthLimitError>()) {
        ApiError::PayloadTooLarge
    } else {
        ApiError::BadRequest
    }
}


pub async fn body_deadline(State(app): State<SharedState>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(app.limits.load().body_read_timeout, to_bytes(body, BODY_LIMIT_BYTES)).await {
        Err(_) => error_response(&ApiError::RequestTimeout),
        Ok(Err(error)) => error_response(&body_failure(&error)),
        Ok(Ok(bytes)) => next.run(Request::from_parts(parts, Body::from(bytes))).await,
    }
}
