use crate::failure::{auth_failure, reply};
use crate::middleware::{edge, guard, limit};
use crate::model::{
    ApiError, ApiState, Authenticated, ErrorBody, ErrorDetail, HealthReply, LoginBody, LoginReply, MeReply, RequestId, Requirement, Rule,
};
use crate::state::{auth_context, lock_auth};
use crate::types::{AccessTable, SharedState};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use core_audit::model::Outcome;
use core_auth::service::{login as core_login, record, revoke_token, Context, LoginRequest, State as AuthState, ACTION_LOGIN};
use core_auth::session::revoke_session;
use core_auth::store::save_accounts_file;
use secrecy::{ExposeSecret, SecretString};
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use time::OffsetDateTime;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{Components, OpenApi as OpenApiDocument};
use utoipa::OpenApi;


pub const BODY_LIMIT_BYTES: usize = 16_384;


pub const HEALTH_STATUS: &str = "ok";


pub const TOKEN_TYPE: &str = "Bearer";


pub const BEARER_SCHEME: &str = "bearer";


pub const PUBLIC_RULE: Rule = Rule {
    requirement: Requirement::Public,
    sensitive: false,
};


#[derive(OpenApi)]
#[openapi(
    paths(health_endpoint, openapi_endpoint, login_endpoint, logout_endpoint, me_endpoint),
    components(schemas(HealthReply, LoginBody, LoginReply, MeReply, ErrorBody, ErrorDetail))
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
        .merge(extra)
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(from_fn_with_state(state.clone(), guard))
        .layer(from_fn_with_state(state.clone(), limit))
        .layer(from_fn_with_state(state.clone(), edge))
        .with_state(state)
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


pub fn body_failure(rejection: &BytesRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge
    } else {
        ApiError::BadRequest
    }
}


pub fn login_request(body: LoginBody, source: IpAddr) -> LoginRequest {
    LoginRequest {
        username: body.username,
        password: body.password,
        totp_code: body.totp_code,
        source: source.to_string(),
    }
}


pub fn persist_login(
    app: &ApiState,
    auth: &mut AuthState,
    context: &Context<File>,
    now: OffsetDateTime,
    request: &LoginRequest,
    token: &SecretString,
) -> Result<LoginReply, ApiError> {
    match save_accounts_file(&app.store_path, &auth.accounts, app.random) {
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


pub fn login_flow(app: &ApiState, request_id: &str, source: IpAddr, body: Result<Bytes, BytesRejection>) -> Result<Response, ApiError> {
    let bytes = body.map_err(|rejection| body_failure(&rejection))?;
    let parsed: LoginBody = serde_json::from_slice(&bytes).map_err(|_| ApiError::BadRequest)?;
    let request = login_request(parsed, source);
    let now = (app.clock)();
    let mut auth = lock_auth(app);
    let context = auth_context(app, request_id);
    let token = core_login(&mut auth, &context, now, &request).map_err(|failure| auth_failure(&failure))?;
    persist_login(app, &mut auth, &context, now, &request, &token).map(|granted| Json(granted).into_response())
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
        (status = 413, description = "Request body too large", body = ErrorBody),
        (status = 429, description = "Too many requests or account locked", body = ErrorBody)
    )
)]
pub async fn login_endpoint(
    State(app): State<SharedState>,
    Extension(request_id): Extension<RequestId>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    reply(login_flow(&app, &request_id.0, peer.ip(), body))
}


pub fn logout_flow(app: &ApiState, request_id: &str, session: &Authenticated) -> Result<Response, ApiError> {
    let now = (app.clock)();
    let mut auth = lock_auth(app);
    let context = auth_context(app, request_id);
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
