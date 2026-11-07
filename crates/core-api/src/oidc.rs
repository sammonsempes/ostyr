use crate::error::StartupError;
use crate::failure::{auth_failure, reply};
use crate::middleware::rate_key;
use crate::model::{ApiError, ApiState, CallbackQuery, LoginReply, OidcFiles, OidcRuntime, RequestId, StartReply};
use crate::routes::{REASON_LOCKED, REASON_TABLE_FULL, TOKEN_TYPE};
use crate::state::{auth_context, lock_auth, remember_callback_account};
use crate::types::SharedState;
use axum::extract::rejection::QueryRejection;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use core_audit::log::check_private;
use core_audit::model::Outcome;
use core_auth::error::OidcDenial;
use core_auth::limiter::{record_failure, source_key, SOURCE_MAX_FAILURES};
use core_auth::model::PendingLogin;
use core_auth::oidc::{
    audit_denial, begin_login, fetch_identity, http_call, new_agent, parse_oidc_config, prune_pending, settle_identity, take_pending, Callback,
    Identity, KeyRefreshGate, OidcContext, HTTP_TIMEOUT_SECONDS, OIDC_TARGET, PENDING_MAX, PENDING_TTL_SECONDS,
};
use core_auth::service::{log_lockout, record, ACTION_LOGIN, ANONYMOUS_ACTOR};
use core_auth::session::{hash_token, session_owner};
use core_auth::types::{PendingMap, RoleCatalog};
use openidconnect::url::Url;
use rustls::crypto::ring::default_provider;
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use secrecy::{ExposeSecret, SecretString};
use std::fs::{read_to_string, File};
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::task::spawn_blocking;
use ureq::{Agent, AgentBuilder};


/// Pending logins one folded source may hold at once.
pub const PENDING_PER_SOURCE_MAX: usize = 16;


pub const BINDING_COOKIE: &str = "__Host-oidc_binding";


pub const BINDING_ATTRIBUTES: &str = "HttpOnly; Secure; SameSite=Lax; Path=/";


pub const CLEAR_BINDING_COOKIE: HeaderValue = HeaderValue::from_static("__Host-oidc_binding=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");


pub const REASON_BAD_REQUEST: &str = "bad_request";


pub const REASON_BAD_BINDING: &str = "bad_binding";


pub const SCOPE_SOURCE: &str = "source";


pub fn binding_of(state: &str) -> String {
    hash_token(&format!("binding:{state}"))
}


pub fn binding_cookie(headers: &HeaderMap) -> Option<String> {
    let prefix = format!("{BINDING_COOKIE}=");
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|text| text.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(prefix.as_str()).map(str::to_owned))
}


pub fn read_secret(path: &Path) -> Result<SecretString, io::Error> {
    let mut file = File::open(path)?;
    check_private(&file).map_err(io::Error::other)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(SecretString::from(text.trim_end().to_owned()))
}


pub fn trust_roots(path: &Path) -> Result<RootCertStore, StartupError> {
    let mut roots = RootCertStore::empty();
    CertificateDer::pem_file_iter(path)?.try_for_each(|certificate| -> Result<(), StartupError> { Ok(roots.add(certificate?)?) })?;
    Ok(roots)
}


pub fn provider_agent(ca_file: Option<&Path>) -> Result<Agent, StartupError> {
    match ca_file {
        None => Ok(new_agent()),
        Some(path) => {
            let tls = ClientConfig::builder_with_provider(Arc::new(default_provider()))
                .with_protocol_versions(&[&TLS13, &TLS12])?
                .with_root_certificates(trust_roots(path)?)
                .with_no_client_auth();
            Ok(AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
                .tls_config(Arc::new(tls))
                .build())
        }
    }
}


pub fn load_oidc(files: &OidcFiles, catalog: &RoleCatalog) -> Result<OidcRuntime, StartupError> {
    let config = parse_oidc_config(&read_to_string(&files.config)?, &files.config.display().to_string(), catalog)?;
    let agent = provider_agent(files.ca_file.as_deref())?;
    let secret_file = files.secret_file.clone();
    Ok(OidcRuntime {
        config,
        http: Box::new(move |request| http_call(&agent, request)),
        resolve: Box::new(move |_| read_secret(&secret_file)),
        pending: Mutex::new(PendingMap::new()),
        refresh: KeyRefreshGate::default(),
    })
}


pub fn oidc_runtime(app: &ApiState) -> Result<&OidcRuntime, ApiError> {
    app.oidc.as_ref().ok_or(ApiError::Internal)
}


pub fn oidc_context(runtime: &OidcRuntime) -> OidcContext<'_> {
    OidcContext {
        config: &runtime.config,
        http: &*runtime.http,
        resolve: &*runtime.resolve,
        refresh: &runtime.refresh,
    }
}


pub fn store_pending(app: &ApiState, runtime: &OidcRuntime, request_id: &str, source: &str, fresh: PendingMap) -> Result<(), ApiError> {
    let now = (app.clock)();
    let mut pending = runtime.pending.lock().unwrap_or_else(PoisonError::into_inner);
    prune_pending(&mut pending, now);
    let from_source = pending.values().filter(|login| login.source == source).count();
    if pending.len() >= PENDING_MAX || from_source >= PENDING_PER_SOURCE_MAX {
        let context = auth_context(app, request_id, &app.verify);
        Err(audit_denial(&context, now, ANONYMOUS_ACTOR, OidcDenial::TooManyPending, source)
            .map_or_else(|failure| auth_failure(&failure), |()| ApiError::TooManyRequests))
    } else {
        pending.extend(fresh);
        Ok(())
    }
}


pub fn begin(app: &ApiState, request_id: &str, source: &str) -> Result<String, ApiError> {
    let runtime = oidc_runtime(app)?;
    let context = auth_context(app, request_id, &app.verify);
    store_pending(app, runtime, request_id, source, PendingMap::new())?;
    let mut fresh = PendingMap::new();
    let location = begin_login(&context, &oidc_context(runtime), &mut fresh, (app.clock)(), source).map_err(|failure| auth_failure(&failure))?;
    store_pending(app, runtime, request_id, source, fresh)?;
    Ok(location)
}


pub fn start_response(location: &str) -> Result<Response, ApiError> {
    let url = Url::parse(location).map_err(|error| {
        tracing::error!(%error, "authorization URL is invalid");
        ApiError::Internal
    })?;
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .ok_or(ApiError::Internal)?;
    let cookie = format!(
        "{BINDING_COOKIE}={}; {BINDING_ATTRIBUTES}; Max-Age={PENDING_TTL_SECONDS}",
        binding_of(&state)
    );
    Ok((
        StatusCode::OK,
        [(SET_COOKIE, cookie)],
        Json(StartReply {
            authorization_url: location.to_owned(),
        }),
    )
        .into_response())
}


pub async fn start_flow(app: &SharedState, request_id: &str, peer: IpAddr) -> Result<Response, ApiError> {
    let (worker, id, source) = (app.clone(), request_id.to_owned(), rate_key(peer).to_string());
    let location = spawn_blocking(move || begin(&worker, &id, &source)).await.map_err(|error| {
        tracing::error!(%error, "OIDC start task failed");
        ApiError::Internal
    })??;
    start_response(&location)
}


#[utoipa::path(
    get,
    path = "/auth/oidc/start",
    responses(
        (status = 200, description = "The authorization URL; the browser binding cookie is set", body = StartReply),
        (status = 429, description = "Too many requests or too many pending logins", body = crate::model::ErrorBody),
        (status = 502, description = "The identity provider is unavailable", body = crate::model::ErrorBody)
    )
)]
pub async fn start_endpoint(
    State(app): State<SharedState>,
    Extension(request_id): Extension<RequestId>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
) -> Response {
    reply(start_flow(&app, &request_id.0, peer.ip()).await)
}


pub fn refusal(app: &ApiState, request_id: &str, source: &str, reason: &str, outcome: Outcome, error: ApiError) -> ApiError {
    tracing::warn!(reason, "OIDC callback refused");
    let context = auth_context(app, request_id, &app.verify);
    let parameters = [("reason", reason.to_owned()), ("source", source.to_owned())];
    record(&context, (app.clock)(), ANONYMOUS_ACTOR, ACTION_LOGIN, OIDC_TARGET, outcome, &parameters)
        .map_or_else(|failure| auth_failure(&failure), |()| error)
}


pub fn deny(app: &ApiState, request_id: &str, source: &str, denial: OidcDenial) -> ApiError {
    let context = auth_context(app, request_id, &app.verify);
    audit_denial(&context, (app.clock)(), ANONYMOUS_ACTOR, denial, source)
        .map_or_else(|failure| auth_failure(&failure), |()| ApiError::InvalidCredentials)
}


pub fn admit_callback(app: &ApiState, request_id: &str, source: &str) -> Result<(), ApiError> {
    let mut auth = lock_auth(app);
    let full = crate::routes::check_table_room(app, &mut auth, source).is_err();
    let reason = if crate::routes::is_locked(app, &auth, source) {
        Some(REASON_LOCKED)
    } else {
        full.then_some(REASON_TABLE_FULL)
    };
    reason.map_or(Ok(()), |found| {
        Err(refusal(app, request_id, source, found, Outcome::Denied, ApiError::TooManyRequests))
    })
}


pub fn parse_callback(
    app: &ApiState,
    request_id: &str,
    source: &str,
    binding: Option<String>,
    query: Option<CallbackQuery>,
) -> Result<Callback, ApiError> {
    match query {
        Some(CallbackQuery { error: Some(_), .. }) => Err(deny(app, request_id, source, OidcDenial::Provider)),
        Some(CallbackQuery {
            state: Some(state),
            code: Some(code),
            ..
        }) => {
            if binding.as_deref() == Some(binding_of(&state).as_str()) {
                Ok(Callback {
                    state,
                    code,
                    source: source.to_owned(),
                })
            } else {
                Err(refusal(
                    app,
                    request_id,
                    source,
                    REASON_BAD_BINDING,
                    Outcome::Denied,
                    ApiError::InvalidCredentials,
                ))
            }
        }
        _ => Err(refusal(
            app,
            request_id,
            source,
            REASON_BAD_REQUEST,
            Outcome::Failure,
            ApiError::BadRequest,
        )),
    }
}


pub fn take_login(app: &ApiState, request_id: &str, callback: &Callback) -> Result<PendingLogin, ApiError> {
    let runtime = oidc_runtime(app)?;
    let mut pending = runtime.pending.lock().unwrap_or_else(PoisonError::into_inner);
    take_pending(&mut pending, &callback.state, (app.clock)()).map_err(|denial| deny(app, request_id, &callback.source, denial))
}


pub fn fetch(app: &ApiState, login: PendingLogin, code: &SecretString) -> Result<Identity, OidcDenial> {
    let runtime = app.oidc.as_ref().ok_or(OidcDenial::Provider)?;
    fetch_identity(&oidc_context(runtime), login, code)
}


pub async fn fetch_off_worker(app: &SharedState, request_id: &str, login: PendingLogin, callback: &Callback) -> Result<Identity, ApiError> {
    let (worker, code) = (app.clone(), callback.code.clone());
    spawn_blocking(move || fetch(&worker, login, &code))
        .await
        .unwrap_or_else(|error| {
            tracing::error!(%error, "OIDC exchange task failed");
            Err(OidcDenial::Provider)
        })
        .map_err(|denial| deny(app, request_id, &callback.source, denial))
}


pub fn settle(app: &ApiState, request_id: &str, identity: &Identity, callback: &Callback) -> Result<SecretString, ApiError> {
    let runtime = oidc_runtime(app)?;
    let mut auth = lock_auth(app);
    let context = auth_context(app, request_id, &app.verify);
    let token =
        settle_identity(&mut auth, &context, &oidc_context(runtime), (app.clock)(), identity, callback).map_err(|failure| auth_failure(&failure))?;
    session_owner(&auth.sessions, token.expose_secret())
        .iter()
        .for_each(|username| remember_callback_account(app, username));
    Ok(token)
}


pub fn count_callback_failure(app: &ApiState, request_id: &str, source: &str) {
    let now = (app.clock)();
    let mut auth = lock_auth(app);
    if crate::routes::check_table_room(app, &mut auth, source).is_ok() {
        let context = auth_context(app, request_id, &app.verify);
        record_failure(&mut auth.attempts, &source_key(source), SOURCE_MAX_FAILURES, now)
            .into_iter()
            .for_each(|until| {
                log_lockout(&context, now, ANONYMOUS_ACTOR, source, SCOPE_SOURCE, until)
                    .inspect_err(|error| tracing::error!(%error, "lockout audit record failed"))
                    .ok();
            });
    }
}


pub async fn run_callback(
    app: &SharedState,
    request_id: &str,
    source: &str,
    binding: Option<String>,
    query: Option<CallbackQuery>,
) -> Result<SecretString, ApiError> {
    let callback = parse_callback(app, request_id, source, binding, query)?;
    let login = take_login(app, request_id, &callback)?;
    let identity = fetch_off_worker(app, request_id, login, &callback).await?;
    settle(app, request_id, &identity, &callback)
}


pub async fn callback_flow(
    app: &SharedState,
    request_id: &str,
    peer: IpAddr,
    binding: Option<String>,
    query: Option<CallbackQuery>,
) -> Result<Response, ApiError> {
    let source = rate_key(peer).to_string();
    admit_callback(app, request_id, &source)?;
    run_callback(app, request_id, &source, binding, query)
        .await
        .inspect_err(|_| count_callback_failure(app, request_id, &source))
        .map(|token| {
            Json(LoginReply {
                token: token.expose_secret().to_owned(),
                token_type: TOKEN_TYPE.to_owned(),
            })
            .into_response()
        })
}


pub fn callback_query(query: Result<Query<CallbackQuery>, QueryRejection>) -> Option<CallbackQuery> {
    query
        .map(|Query(parsed)| parsed)
        .inspect_err(|error| tracing::warn!(%error, "OIDC callback query rejected"))
        .ok()
}


#[utoipa::path(
    get,
    path = "/auth/oidc/callback",
    params(
        ("state" = Option<String>, Query, description = "The state returned by the provider"),
        ("code" = Option<String>, Query, description = "The authorization code"),
        ("error" = Option<String>, Query, description = "A provider error code")
    ),
    responses(
        (status = 200, description = "A session token", body = LoginReply),
        (status = 400, description = "Malformed request", body = crate::model::ErrorBody),
        (status = 401, description = "Login refused", body = crate::model::ErrorBody),
        (status = 429, description = "Too many requests or source locked", body = crate::model::ErrorBody)
    )
)]
pub async fn callback_endpoint(
    State(app): State<SharedState>,
    Extension(request_id): Extension<RequestId>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
    let mut response = reply(callback_flow(&app, &request_id.0, peer.ip(), binding_cookie(&headers), callback_query(query)).await);
    response.headers_mut().insert(SET_COOKIE, CLEAR_BINDING_COOKIE);
    response
}
