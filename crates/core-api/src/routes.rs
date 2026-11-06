use crate::failure::{auth_failure, reply};
use crate::middleware::{body_deadline, edge, guard, limit, rate_key};
use crate::model::{
    ApiError, ApiState, Authenticated, ErrorBody, ErrorDetail, HealthReply, LoginBody, LoginReply, MeReply, RequestId, Requirement, Rule, StartReply,
};
use crate::oidc::{callback_endpoint, start_endpoint};
use crate::state::{auth_context, lock_auth, memory_only_accounts, prune_attempts, refresh_accounts};
use crate::types::{AccessTable, SharedState};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use core_audit::model::Outcome;
use core_auth::error::AuthError;
use core_auth::limiter::{locked_until, source_key};
use core_auth::service::{
    audit_name, login as core_login, record, revoke_token, Context, LoginRequest, State as AuthState, ACTION_LOGIN, DUMMY_HASH,
};
use core_auth::session::revoke_session;
use core_auth::store::update_store_file;
use secrecy::{ExposeSecret, SecretString};
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use time::OffsetDateTime;
use tokio::task::spawn_blocking;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{Components, OpenApi as OpenApiDocument};
use utoipa::OpenApi;


pub const BODY_LIMIT_BYTES: usize = 16_384;


pub const REASON_LOCKED: &str = "locked";


pub const REASON_TABLE_FULL: &str = "table_full";


pub const REASON_INTERNAL: &str = "internal_error";


pub const HEALTH_STATUS: &str = "ok";


pub const TOKEN_TYPE: &str = "Bearer";


pub const BEARER_SCHEME: &str = "bearer";


pub const PUBLIC_RULE: Rule = Rule {
    requirement: Requirement::Public,
    sensitive: false,
};


#[derive(OpenApi)]
#[openapi(
    paths(
        health_endpoint,
        openapi_endpoint,
        login_endpoint,
        logout_endpoint,
        me_endpoint,
        crate::oidc::start_endpoint,
        crate::oidc::callback_endpoint
    ),
    components(schemas(HealthReply, LoginBody, LoginReply, MeReply, ErrorBody, ErrorDetail, StartReply))
)]
pub struct ApiDoc;


pub fn route_key(method: &str, path: &str) -> String {
    format!("{method} {path}")
}


pub fn core_access() -> AccessTable {
    [
        (route_key("GET", "/health"), PUBLIC_RULE),
        (route_key("GET", "/openapi.json"), PUBLIC_RULE),
        (route_key("POST", "/auth/login"), PUBLIC_RULE),
        (
            route_key("GET", "/auth/oidc/start"),
            Rule {
                requirement: Requirement::Public,
                sensitive: true,
            },
        ),
        (route_key("GET", "/auth/oidc/callback"), PUBLIC_RULE),
        (
            route_key("POST", "/auth/logout"),
            Rule {
                requirement: Requirement::Session,
                sensitive: false,
            },
        ),
        (
            route_key("GET", "/auth/me"),
            Rule {
                requirement: Requirement::Session,
                sensitive: true,
            },
        ),
    ]
    .into_iter()
    .collect()
}


pub fn openapi_document(module: &str) -> OpenApiDocument {
    let mut document = ApiDoc::openapi();
    document.info.title = format!("{module} API");
    document.components.get_or_insert_with(Components::new).add_security_scheme(
        BEARER_SCHEME,
        SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
    );
    document
}


pub fn build_router(state: SharedState, extra: Router<SharedState>) -> Router {
    Router::new()
        .route("/health", get(health_endpoint))
        .route("/openapi.json", get(openapi_endpoint))
        .route("/auth/login", post(login_endpoint))
        .route("/auth/logout", post(logout_endpoint))
        .route("/auth/me", get(me_endpoint))
        .merge(oidc_router(&state))
        .merge(extra)
        .layer(from_fn_with_state(state.clone(), body_deadline))
        .layer(from_fn_with_state(state.clone(), guard))
        .layer(from_fn_with_state(state.clone(), limit))
        .layer(from_fn_with_state(state.clone(), edge))
        .with_state(state)
}


pub fn oidc_router(state: &ApiState) -> Router<SharedState> {
    let router = Router::new();
    if state.oidc.is_some() {
        router
            .route("/auth/oidc/start", get(start_endpoint))
            .route("/auth/oidc/callback", get(callback_endpoint))
    } else {
        router
    }
}


#[utoipa::path(
    get,
    path = "/health",
    responses((status = 200, description = "The service is up", body = HealthReply))
)]
pub async fn health_endpoint() -> Json<HealthReply> {
    Json(HealthReply {
        status: HEALTH_STATUS.to_owned(),
    })
}


#[utoipa::path(
    get,
    path = "/openapi.json",
    responses((status = 200, description = "This OpenAPI 3 document"))
)]
pub async fn openapi_endpoint(State(app): State<SharedState>) -> Json<serde_json::Value> {
    Json(app.document.clone())
}


pub fn login_request(body: LoginBody, source: IpAddr) -> LoginRequest {
    LoginRequest {
        username: body.username,
        password: body.password,
        totp_code: body.totp_code,
        source: rate_key(source).to_string(),
    }
}


pub fn persist_login(
    app: &ApiState,
    auth: &mut AuthState,
    context: &Context<File>,
    now: OffsetDateTime,
    request: &LoginRequest,
) -> Result<LoginReply, ApiError> {
    let updated = update_store_file(&app.store_path, app.random, |accounts, credentials| {
        let external = memory_only_accounts(&auth.accounts, accounts);
        auth.accounts = std::mem::take(accounts);
        auth.accounts.extend(external.clone());
        auth.credentials = std::mem::take(credentials);
        let token = core_login(auth, context, now, request)?;
        accounts.clone_from(&auth.accounts);
        external.keys().for_each(|name| {
            accounts.remove(name);
        });
        credentials.clone_from(&auth.credentials);
        Ok(token)
    })
    .map_err(|failure| auth_failure(&failure))?;
    let token = updated.value;
    match updated.saved {
        Ok(()) => Ok(LoginReply {
            token: token.expose_secret().to_owned(),
            token_type: TOKEN_TYPE.to_owned(),
        }),
        Err(error) => {
            tracing::warn!(%error, "account store save failed after login, session discarded");
            revoke_session(&mut auth.sessions, token.expose_secret());
            let parameters = [("reason", "internal_error".to_owned()), ("source", request.source.clone())];
            record(
                context,
                now,
                &request.username,
                ACTION_LOGIN,
                &request.username,
                Outcome::Failure,
                &parameters,
            )
            .inspect_err(|failure| tracing::error!(error = %failure, "internal_error audit record failed"))
            .ok();
            Err(ApiError::InvalidCredentials)
        }
    }
}


pub fn stored_hash(app: &ApiState, username: &str) -> String {
    let mut auth = lock_auth(app);
    refresh_accounts(app, &mut auth);
    auth.accounts
        .get(username)
        .map_or_else(|| DUMMY_HASH.to_owned(), |account| account.password_hash.clone())
}


pub async fn verify_off_worker(app: &ApiState, password: &SecretString, stored: &str) -> Result<Option<bool>, ApiError> {
    let permit = app.hashing.clone().acquire_owned().await.map_err(|error| {
        tracing::error!(%error, "password hashing gate closed");
        ApiError::Internal
    })?;
    let (verify, secret, hash) = (app.verify, password.clone(), stored.to_owned());
    let joined = spawn_blocking(move || {
        let held = permit;
        let verdict = verify(secret.expose_secret(), &hash);
        drop(held);
        verdict
    })
    .await;
    match joined {
        Ok(Ok(verdict)) => Ok(Some(verdict)),
        Ok(Err(error)) => {
            tracing::warn!(%error, "password verification failed internally");
            Ok(None)
        }
        Err(error) => {
            tracing::error!(%error, "password verification task failed");
            Err(ApiError::Internal)
        }
    }
}


pub fn needed_room(auth: &AuthState, source: &str) -> usize {
    1 + usize::from(!auth.attempts.contains_key(&source_key(source)))
}


pub fn check_table_room(app: &ApiState, auth: &mut AuthState, source: &str) -> Result<(), ApiError> {
    prune_attempts(&mut auth.attempts, (app.clock)());
    if auth.attempts.len() + needed_room(auth, source) > app.max_attempts {
        tracing::warn!("failure tracking table is full, login refused");
        Err(ApiError::TooManyRequests)
    } else {
        Ok(())
    }
}


pub fn is_locked(app: &ApiState, auth: &AuthState, source: &str) -> bool {
    let now = (app.clock)();
    locked_until(&auth.attempts, &source_key(source), now).is_some()
}


pub fn refuse_login(app: &ApiState, auth: &AuthState, request_id: &str, request: &LoginRequest, reason: &str) -> ApiError {
    refuse_with(app, auth, request_id, request, reason, (Outcome::Denied, ApiError::TooManyRequests))
}


pub fn refuse_internal(app: &ApiState, request_id: &str, request: &LoginRequest, error: ApiError) -> ApiError {
    let auth = lock_auth(app);
    refuse_with(app, &auth, request_id, request, REASON_INTERNAL, (Outcome::Failure, error))
}


pub fn refuse_with(
    app: &ApiState,
    auth: &AuthState,
    request_id: &str,
    request: &LoginRequest,
    reason: &str,
    (outcome, error): (Outcome, ApiError),
) -> ApiError {
    tracing::warn!(reason, "login refused");
    let context = auth_context(app, request_id, &app.verify);
    let audit_user = audit_name(&auth.accounts, &request.username);
    let parameters = [("reason", reason.to_owned()), ("source", request.source.clone())];
    record(&context, (app.clock)(), &audit_user, ACTION_LOGIN, &audit_user, outcome, &parameters)
        .map_or_else(|failure| auth_failure(&failure), |()| error)
}


pub fn admit_login(app: &ApiState, request_id: &str, request: &LoginRequest) -> Result<(), ApiError> {
    let mut auth = lock_auth(app);
    let full = check_table_room(app, &mut auth, &request.source).is_err();
    let reason = if is_locked(app, &auth, &request.source) {
        Some(REASON_LOCKED)
    } else {
        full.then_some(REASON_TABLE_FULL)
    };
    reason.map_or(Ok(()), |found| Err(refuse_login(app, &auth, request_id, request, found)))
}


pub fn commit_login(app: &ApiState, request_id: &str, request: &LoginRequest, stored: &str, verdict: Option<bool>) -> Result<Response, ApiError> {
    let now = (app.clock)();
    let verify = |_: &str, current: &str| {
        if current == stored {
            verdict.ok_or(AuthError::InvalidCredentials)
        } else {
            Ok(false)
        }
    };
    let mut auth = lock_auth(app);
    check_table_room(app, &mut auth, &request.source).map_err(|_| refuse_login(app, &auth, request_id, request, REASON_TABLE_FULL))?;
    let context = auth_context(app, request_id, &verify);
    persist_login(app, &mut auth, &context, now, request).map(|granted| Json(granted).into_response())
}


pub async fn login_flow(app: &ApiState, request_id: &str, source: IpAddr, bytes: Bytes) -> Result<Response, ApiError> {
    let parsed: LoginBody = serde_json::from_slice(&bytes).map_err(|_| ApiError::BadRequest)?;
    let request = login_request(parsed, source);
    admit_login(app, request_id, &request)?;
    let stored = stored_hash(app, &request.username);
    let verdict = verify_off_worker(app, &request.password, &stored)
        .await
        .map_err(|error| refuse_internal(app, request_id, &request, error))?;
    commit_login(app, request_id, &request, &stored, verdict)
}


#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginBody,
    responses(
        (status = 200, description = "A session token", body = LoginReply),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Invalid credentials or second factor", body = ErrorBody),
        (status = 403, description = "Second factor enrolment required", body = ErrorBody),
        (status = 408, description = "Request body not received in time", body = ErrorBody),
        (status = 413, description = "Request body too large", body = ErrorBody),
        (status = 429, description = "Too many requests or source locked", body = ErrorBody)
    )
)]
pub async fn login_endpoint(
    State(app): State<SharedState>,
    Extension(request_id): Extension<RequestId>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    reply(login_flow(&app, &request_id.0, peer.ip(), body).await)
}


pub fn logout_flow(app: &ApiState, request_id: &str, session: &Authenticated) -> Result<Response, ApiError> {
    let now = (app.clock)();
    let mut auth = lock_auth(app);
    let context = auth_context(app, request_id, &app.verify);
    let token = session.token.expose_secret();
    revoke_token(&mut auth, &context, now, token, token)
        .map(|()| StatusCode::NO_CONTENT.into_response())
        .map_err(|failure| auth_failure(&failure))
}


#[utoipa::path(
    post,
    path = "/auth/logout",
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The session is revoked"),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn logout_endpoint(
    State(app): State<SharedState>,
    Extension(request_id): Extension<RequestId>,
    Extension(session): Extension<Authenticated>,
) -> Response {
    reply(logout_flow(&app, &request_id.0, &session))
}


pub fn profile(app: &ApiState, user: &str) -> Result<Response, ApiError> {
    lock_auth(app)
        .accounts
        .get(user)
        .map(|account| {
            Json(MeReply {
                username: account.username.clone(),
                roles: account.roles.iter().cloned().collect(),
                mfa_enrolled: account.totp.is_some(),
            })
            .into_response()
        })
        .ok_or(ApiError::Unauthorized)
}


#[utoipa::path(
    get,
    path = "/auth/me",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The authenticated account", body = MeReply),
        (status = 401, description = "No valid session", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
pub async fn me_endpoint(State(app): State<SharedState>, Extension(session): Extension<Authenticated>) -> Response {
    reply(profile(&app, &session.user))
}
