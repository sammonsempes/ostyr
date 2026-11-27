use crate::failure::{auth_failure, error_response};
use crate::model::{
    AdmittedSender, ApiError, ApiIdentity, ApiState, Authenticated, ClientSource, Decision, DetachedPool, Exchange, ForwardedBy, Limits, RequestId,
    Requirement, Rule, SenderSlot, Window,
};
use crate::routes::{route_key, BODY_LIMIT_BYTES};
use crate::server::admit_connection;
use crate::state::{
    lock_auth, refresh_accounts, session_revoked, MAX_DETACHED_PER_SOURCE, MAX_DETACHED_READS_PER_SOURCE, MAX_TRACE_DECODES_PER_SENDER,
};
use crate::types::{ConnectionTable, DetachedPermit, SenderPermit, SharedState};
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::header::{
    HeaderName, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_SECURITY_POLICY, CONTENT_TYPE, FORWARDED, REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
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
use core_auth::webauthn::holds_unknown_role;
use core_config::reload::{bounded_text, bounded_value};
use data_encoding::HEXLOWER;
use http_body_util::LengthLimitError;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Instant;
use time::{Duration, OffsetDateTime};
use tracing::instrument::WithSubscriber;


pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");


pub const REQUEST_ID_MAX_LENGTH: usize = 64;


pub const REQUEST_ID_BYTES: usize = 16;


pub const IPV6_HOST_BITS: u32 = 64;


pub const UNAVAILABLE_ID: &str = "unavailable";


pub const UNMATCHED_ROUTE: &str = "unmatched";


pub const OTHER_METHOD: &str = "OTHER";


pub const KNOWN_METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];


pub const BEARER_PREFIX: &[u8] = b"Bearer ";


/// Length of an ingest token in characters: 32 random bytes in lower-case hex.
pub const SENDER_TOKEN_LENGTH: usize = 64;


pub const SENDER_CONTENT_TYPE: &[u8] = b"application/x-protobuf";


pub const SENDER_ENCODING_IDENTITY: &[u8] = b"identity";


pub const SENDER_ACTOR_PREFIX: &str = "sender:";


pub const ACTION_REQUEST: &str = "api.request";


pub const REQUEST_DECLARED_KEYS: [&str; 4] = ["source", "status", "forwarded_by", "reason"];


pub const REASON_UNKNOWN_ROLE: &str = "unknown_role";


pub const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");


pub const FORWARDED_ELEMENT: &str = "for";


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


/// Longest request path or method written whole to the request log line; the rest is cut with a visible marker.
pub const MAX_LOGGED_PATH_CHARS: usize = 512;


pub fn log_request(
    app: &ApiState,
    identity: &ApiIdentity,
    (id, raw_method, raw_path): (&str, &str, &str),
    source: IpAddr,
    status: StatusCode,
    elapsed: std::time::Duration,
) {
    let (module, tenant) = (identity.module.as_str(), identity.tenant.as_str());
    let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let (result, code) = (result_label(status), status.as_u16());
    let request_id = id;
    let path = bounded_text(raw_path, MAX_LOGGED_PATH_CHARS, "path");
    let method = bounded_text(raw_method, MAX_LOGGED_PATH_CHARS, "method");
    tracing::dispatcher::with_default(&app.dispatch, || {
        tracing::info!(target: LOG_TARGET, module, tenant, request_id, duration_ms, result, method, path, status = code, source = %source, "request");
    });
}


/// The address in one `Forwarded: for=<ip>` header: exactly one header, no list, exactly one `for` pair, an IPv4 or bracketed IPv6 literal without port.
pub fn forwarded_address(headers: &HeaderMap) -> Option<IpAddr> {
    match headers.get_all(FORWARDED).iter().collect::<Vec<_>>().as_slice() {
        [value] => value.to_str().ok().filter(|text| !text.contains(',')).and_then(forwarded_for),
        _ => None,
    }
}


pub fn forwarded_for(text: &str) -> Option<IpAddr> {
    let pairs = text.split(';').map(|pair| pair.split_once('=')).collect::<Option<Vec<_>>>()?;
    match pairs
        .into_iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(FORWARDED_ELEMENT))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [(_, node)] => forwarded_node(node),
        _ => None,
    }
}


/// An IPv4 literal (quotes optional) or a quoted bracketed IPv6 literal; a port, a name, `unknown`, `_obfuscated` and whitespace all fail the parse.
pub fn forwarded_node(node: &str) -> Option<IpAddr> {
    let quoted = node.strip_prefix('"').and_then(|inner| inner.strip_suffix('"'));
    let parsed = match quoted.and_then(|inner| inner.strip_prefix('[')).and_then(|inner| inner.strip_suffix(']')) {
        Some(inner) => inner.parse::<Ipv6Addr>().map(IpAddr::V6),
        None => quoted.unwrap_or(node).parse::<Ipv4Addr>().map(IpAddr::V4),
    };
    parsed.inspect_err(|error| tracing::debug!(%error, "malformed Forwarded address")).ok()
}


/// Counts an ignored forwarding header and warns when the count is a power of two (1, 2, 4, 8, ...), so the log stays bounded.
pub fn note_ignored_forwarding(app: &ApiState) -> u64 {
    let count = app.ignored_forwarding.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if count.is_power_of_two() {
        tracing::dispatcher::with_default(&app.dispatch, || {
            tracing::warn!(count, "forwarding headers from an untrusted peer ignored");
        });
    }
    count
}


/// The source of a request: the TCP peer, unless the peer is a trusted forwarder, which must then name the client (else 400, never its own address).
pub fn client_source(app: &ApiState, peer: SocketAddr, headers: &HeaderMap) -> Result<ClientSource, ApiError> {
    let canonical = peer.ip().to_canonical();
    if app.forwarders.load().iter().any(|network| network.contains(&canonical)) {
        forwarded_address(headers)
            .map(|address| ClientSource {
                address: SocketAddr::new(address, peer.port()),
                forwarded_by: Some(peer.ip()),
            })
            .ok_or(ApiError::BadRequest)
    } else {
        if headers.contains_key(FORWARDED) || headers.contains_key(X_FORWARDED_FOR) {
            note_ignored_forwarding(app);
        }
        Ok(ClientSource {
            address: peer,
            forwarded_by: None,
        })
    }
}


pub async fn edge(State(app): State<SharedState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, mut request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let (id, source, mut response) = match (request_id(request.headers(), app.random), client_source(&app, peer, request.headers())) {
        (Ok(id), Ok(client)) => {
            request.extensions_mut().insert(RequestId(id.clone()));
            request.extensions_mut().insert(ConnectInfo(client.address));
            client.forwarded_by.into_iter().for_each(|forwarder| {
                request.extensions_mut().insert(ForwardedBy(forwarder));
            });
            let response = next.run(request).await;
            (id, client.address, response)
        }
        (Ok(id), Err(error)) => (id, peer, error_response(&error)),
        (Err(error), _) => {
            tracing::warn!(%error, "request id generation failed");
            (UNAVAILABLE_ID.to_owned(), peer, error_response(&ApiError::Internal))
        }
    };
    decorate(response.headers_mut(), &id);
    let admitted = response
        .extensions()
        .get::<Arc<ApiIdentity>>()
        .cloned()
        .unwrap_or_else(|| app.identity.load_full());
    log_request(&app, &admitted, (&id, &method, &path), source.ip(), response.status(), started.elapsed());
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
    let method = request.method().as_str();
    let known = if KNOWN_METHODS.contains(&method) { method } else { OTHER_METHOD };
    route_key(known, path)
}


pub fn admit(actor: &str, session: Option<Authenticated>) -> Decision {
    Decision {
        actor: actor.to_owned(),
        session,
        error: None,
        identity: None,
        reason: None,
    }
}


pub fn deny(actor: &str, error: ApiError) -> Decision {
    Decision {
        actor: actor.to_owned(),
        session: None,
        error: Some(error),
        identity: None,
        reason: None,
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


/// A session whose account holds a role the catalog in use lacks: refused with the audited reason, never served with the remaining permissions.
pub fn deny_unknown_role(user: &str) -> Decision {
    Decision {
        reason: Some(REASON_UNKNOWN_ROLE),
        ..deny(user, ApiError::Unauthorized)
    }
}


pub fn authenticate(app: &ApiState, requirement: Option<&Requirement>, token: String, now: OffsetDateTime) -> Decision {
    authenticate_under(app, &app.catalog.load_full(), requirement, token, now)
}


/// `authenticate` under one catalog snapshot, used for the unknown-role check and the permission check alike.
pub fn authenticate_under(app: &ApiState, catalog: &RoleCatalog, requirement: Option<&Requirement>, token: String, now: OffsetDateTime) -> Decision {
    let mut auth = lock_auth(app);
    match validate_session(&mut auth.sessions, &token, now) {
        Err(_) => deny(ANONYMOUS_ACTOR, ApiError::Unauthorized),
        Ok(user) => match refresh_accounts(app, &mut auth) {
            Err(_) => deny(&user, ApiError::Unauthorized),
            Ok(()) if session_revoked(&auth, &token) => {
                revoke_session(&mut auth.sessions, &token);
                deny(&user, ApiError::Unauthorized)
            }
            Ok(()) if holds_unknown_role(&auth.accounts, catalog, &user) => {
                revoke_session(&mut auth.sessions, &token);
                deny_unknown_role(&user)
            }
            Ok(()) => {
                let allowed = check_requirement(&mut auth, catalog, requirement, &token, now);
                Decision {
                    actor: user.clone(),
                    session: allowed.is_ok().then(|| Authenticated {
                        user,
                        token: SecretString::from(token),
                    }),
                    error: allowed.err(),
                    identity: Some(app.identity.load_full()),
                    reason: None,
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
        let identity = &exchange.identity;
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
                .chain(exchange.forwarded_by.iter().map(|by| ("forwarded_by".to_owned(), bounded_value(by))))
                .chain(exchange.reason.iter().map(|reason| ("reason".to_owned(), (*reason).to_owned())))
                .collect(),
            },
            &REQUEST_DECLARED_KEYS,
        )
        .map(|_| ())
    } else {
        Ok(())
    }
}


/// Appends the exchange record for `response` and answers 500 instead when the append fails.
pub fn audit_response(app: &ApiState, template: Exchange, response: Response) -> Response {
    let exchange = Exchange {
        status: response.status(),
        ..template
    };
    match audit_exchange(app, &exchange) {
        Ok(()) => response,
        Err(error) => {
            tracing::error!(%error, "audit append failed, request answered with an error");
            error_response(&ApiError::Internal)
        }
    }
}


/// The digest of the ingest token in `headers`: exactly one `Authorization` header, `Bearer ` and 64 lower-case hex characters, else `None`.
pub fn sender_digest(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .as_bytes()
            .strip_prefix(BEARER_PREFIX)
            .filter(|token| token.len() == SENDER_TOKEN_LENGTH && token.iter().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
            .map(|token| HEXLOWER.encode(&Sha256::digest(token))),
        _ => None,
    }
}


/// `Content-Type` exactly `application/x-protobuf` and `Content-Encoding` absent or `identity`, each at most once.
pub fn sender_media_ok(headers: &HeaderMap) -> bool {
    let mut types = headers.get_all(CONTENT_TYPE).iter();
    let mut encodings = headers.get_all(CONTENT_ENCODING).iter();
    let type_ok = matches!((types.next(), types.next()), (Some(value), None) if value.as_bytes() == SENDER_CONTENT_TYPE);
    let encoding_ok = match (encodings.next(), encodings.next()) {
        (None, None) => true,
        (Some(value), None) => value.as_bytes() == SENDER_ENCODING_IDENTITY,
        _ => false,
    };
    type_ok && encoding_ok
}


/// Takes the sender's slot then a global permit of the decode pool, never queueing; `None` when either is full.
pub fn admit_sender(app: &ApiState, name: &str) -> Option<SenderPermit> {
    let taken = {
        let mut table = app.sender_slots.lock().unwrap_or_else(PoisonError::into_inner);
        let held = table.get(name).copied().unwrap_or(0);
        (held < MAX_TRACE_DECODES_PER_SENDER)
            .then(|| table.insert(name.to_owned(), held + 1))
            .is_some()
    };
    taken
        .then(|| SenderSlot {
            table: app.sender_slots.clone(),
            name: name.to_owned(),
        })
        .and_then(|slot| {
            app.sender_pool
                .permits
                .clone()
                .try_acquire_owned()
                .inspect_err(|error| tracing::debug!(%error, "decode pool full"))
                .ok()
                .map(|permit| (slot, permit))
        })
}


/// Counts a refused sender request and warns when the count is a power of two; never the token or its digest.
pub fn note_sender_refused(app: &ApiState) -> u64 {
    let count = count_refusal(&app.sender_refused);
    if count.is_power_of_two() {
        tracing::dispatcher::with_default(&app.dispatch, || {
            tracing::warn!(count, "sender requests refused");
        });
    }
    count
}


/// Admission of an ingest sender on headers only, before any body byte: token (401), media type (415), slots (429).
pub fn sender_decision(app: &ApiState, headers: &HeaderMap) -> (Decision, Option<AdmittedSender>) {
    let name = sender_digest(headers).and_then(|digest| app.senders.load().get(&digest).cloned());
    let actor = name
        .as_ref()
        .map_or_else(|| ANONYMOUS_ACTOR.to_owned(), |found| format!("{SENDER_ACTOR_PREFIX}{found}"));
    let outcome = match name {
        None => Err(ApiError::Unauthorized),
        Some(_) if !sender_media_ok(headers) => Err(ApiError::UnsupportedMediaType),
        Some(found) => admit_sender(app, &found)
            .map(|permit| AdmittedSender {
                name: found,
                permit: Arc::new(permit),
            })
            .ok_or(ApiError::SenderBusy),
    };
    match outcome {
        Ok(sender) => (admit(&actor, None), Some(sender)),
        Err(error) => {
            note_sender_refused(app);
            (deny(&actor, error), None)
        }
    }
}


/// A request under a session or a permission runs detached, whatever its method (T769, T883); public routes (login, OIDC) never do.
pub fn detaches(rule: Option<&Rule>) -> bool {
    matches!(
        rule.map(|found| &found.requirement),
        Some(Requirement::Session | Requirement::Permission(_))
    )
}


/// Takes the per-source slot then a global permit of `pool`, never queueing; `None` when either is full.
pub fn admit_in(pool: &DetachedPool, sources: &ConnectionTable, per_source: usize, source: IpAddr) -> Option<DetachedPermit> {
    admit_connection(sources, source, per_source).and_then(|slot| {
        pool.permits
            .clone()
            .try_acquire_owned()
            .inspect_err(|error| tracing::debug!(%error, "detached pool full"))
            .ok()
            .map(|permit| (permit, slot))
    })
}


/// Takes a slot of the detached writes.
pub fn admit_detached(app: &ApiState, source: IpAddr) -> Option<DetachedPermit> {
    admit_in(&app.detached, &app.detached_sources, MAX_DETACHED_PER_SOURCE, source)
}


/// Takes a slot of the detached reads, a pool and a per-source table apart from the writes.
pub fn admit_detached_read(app: &ApiState, source: IpAddr) -> Option<DetachedPermit> {
    admit_in(&app.detached_reads, &app.detached_read_sources, MAX_DETACHED_READS_PER_SOURCE, source)
}


/// Counts a refusal and returns the count.
pub fn count_refusal(counter: &AtomicU64) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed).saturating_add(1)
}


/// Counts a refused detached write and warns when the count is a power of two, so the log stays bounded.
pub fn note_detached_refused(app: &ApiState) -> u64 {
    let count = count_refusal(&app.detached_refused);
    if count.is_power_of_two() {
        tracing::dispatcher::with_default(&app.dispatch, || {
            tracing::warn!(count, "detached write pool full, request refused");
        });
    }
    count
}


/// Counts a refused detached read and warns when the count is a power of two.
pub fn note_detached_read_refused(app: &ApiState) -> u64 {
    let count = count_refusal(&app.detached_reads_refused);
    if count.is_power_of_two() {
        tracing::dispatcher::with_default(&app.dispatch, || {
            tracing::warn!(count, "detached read pool full, request refused");
        });
    }
    count
}


/// Runs the handler in its own task and audits the result there, so a client that leaves never cancels the work between its commit and its record.
pub async fn complete_write(app: SharedState, request: Request, next: Next, template: Exchange, _permit: DetachedPermit) -> Response {
    let response = tokio::spawn(next.run(request).with_current_subscriber()).await.unwrap_or_else(|_| {
        tracing::error!("write handler task failed");
        error_response(&ApiError::Internal)
    });
    audit_response(&app, template, response)
}


/// Admits the request to its detached pool (writes or reads), or answers 503 `busy` with one audited record.
pub async fn run_detached(app: SharedState, request: Request, next: Next, template: Exchange, source: IpAddr) -> Response {
    let admitted = if template.state_changing {
        admit_detached(&app, source)
    } else {
        admit_detached_read(&app, source)
    };
    match admitted {
        None => {
            if template.state_changing {
                note_detached_refused(&app);
            } else {
                note_detached_read_refused(&app);
            }
            audit_response(&app, template, error_response(&ApiError::Busy))
        }
        Some(permit) => tokio::spawn(complete_write(app, request, next, template, permit).with_current_subscriber())
            .await
            .unwrap_or_else(|_| {
                tracing::error!("detached write task failed");
                error_response(&ApiError::Internal)
            }),
    }
}


/// Waits until every detached write has written its record; false when `timeout` passes first (those writes are cancelled with the runtime).
pub async fn drain_detached(app: &ApiState, timeout: std::time::Duration) -> bool {
    let all = app.detached.permits.clone().acquire_many_owned(app.detached.size);
    let drained = tokio::time::timeout(timeout, all).await.is_ok();
    if !drained {
        tracing::warn!("detached writes still running at shutdown");
    }
    drained
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
    let (decision, sender) = match rule.map(|found| &found.requirement) {
        Some(Requirement::Sender(_)) => sender_decision(&app, request.headers()),
        requirement => (decide(&app, requirement, bearer_token(request.headers()), (app.clock)()), None),
    };
    let identity = decision.identity.clone().unwrap_or_else(|| app.identity.load_full());
    let state_changing = !request.method().is_safe();
    let detach = detaches(rule);
    let forwarded_by = request.extensions().get::<ForwardedBy>().map(|found| found.0);
    let template = Exchange {
        request_id: id.0,
        actor: decision.actor,
        route,
        state_changing,
        sensitive: rule.is_some_and(|found| found.sensitive),
        source: rate_key(peer.ip()).to_string(),
        forwarded_by: forwarded_by.map(|by| by.to_string()),
        status: StatusCode::OK,
        identity: identity.clone(),
        reason: decision.reason,
    };
    let mut answered = match decision.error {
        Some(error) => audit_response(&app, template, error_response(&error)),
        None => {
            request.extensions_mut().insert(identity.clone());
            sender.into_iter().for_each(|admitted| {
                request.extensions_mut().insert(admitted);
            });
            decision.session.into_iter().for_each(|session| {
                request.extensions_mut().insert(session);
            });
            if detach {
                match buffer_body(&app, request, BODY_LIMIT_BYTES).await {
                    Ok(buffered) => run_detached(app.clone(), buffered, next, template, peer.ip()).await,
                    Err(refusal) => audit_response(&app, template, error_response(&refusal)),
                }
            } else {
                audit_response(&app, template, next.run(request).await)
            }
        }
    };
    answered.extensions_mut().insert(identity);
    answered
}


pub fn body_failure(error: &axum::Error) -> ApiError {
    if error.source().is_some_and(|cause| cause.is::<LengthLimitError>()) {
        ApiError::PayloadTooLarge
    } else {
        ApiError::BadRequest
    }
}


/// Reads the whole body within the body read timeout, so a detached slot is never held by a slow body; the error is the refusal to send.
pub async fn buffer_body(app: &ApiState, request: Request, limit: usize) -> Result<Request, ApiError> {
    let (parts, body) = request.into_parts();
    match tokio::time::timeout(app.limits.load().body_read_timeout, to_bytes(body, limit)).await {
        Err(_) => Err(ApiError::RequestTimeout),
        Ok(Err(error)) => Err(body_failure(&error)),
        Ok(Ok(bytes)) => Ok(Request::from_parts(parts, Body::from(bytes))),
    }
}


/// The body limit of the matched route: its `Sender` ceiling, else `BODY_LIMIT_BYTES`.
pub fn body_limit(app: &ApiState, request: &Request) -> usize {
    match app.access.get(&route_of(request)).map(|found| &found.requirement) {
        Some(Requirement::Sender(ceiling)) => *ceiling,
        _ => BODY_LIMIT_BYTES,
    }
}


pub async fn body_deadline(State(app): State<SharedState>, request: Request, next: Next) -> Response {
    let limit = body_limit(&app, &request);
    match buffer_body(&app, request, limit).await {
        Ok(buffered) => next.run(buffered).await,
        Err(refusal) => error_response(&refusal),
    }
}
