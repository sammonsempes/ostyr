use crate::error::{AuthError, OidcDenial};
use crate::model::{Account, PendingLogin};
use crate::random::random_array;
use crate::rbac::check_roles;
use crate::service::{check_username, join_roles, record, Context, State, ACTION_LOGIN, ANONYMOUS_ACTOR, OIDC_PREFIX};
use crate::session::{create_session, hash_token, revoke_user_sessions};
use crate::types::{GroupRoleMap, HttpFn, OidcClient, PendingMap, RandomFn, ResolveFn, RoleCatalog, RoleSet};
use core_audit::model::Outcome;
use core_config::parse::parse_document;
use core_config::secret::SecretRef;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreJwsSigningAlgorithm, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken, HttpRequest, HttpResponse, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, SyncHttpClient, TokenResponse,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::io::{self, Write};
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};


pub const ACTION_OIDC_MAP: &str = "authz.oidc.map";


pub const OIDC_TARGET: &str = "oidc";


pub const EXTERNAL_PASSWORD_HASH: &str = "!external";


pub const DEFAULT_GROUPS_CLAIM: &str = "groups";


pub const PENDING_TTL_SECONDS: i64 = 600;


pub const PENDING_MAX: usize = 1024;


pub const STATE_BYTES: usize = 32;


pub const HTTP_TIMEOUT_SECONDS: u64 = 10;


pub const ALLOWED_ALGORITHMS: [CoreJwsSigningAlgorithm; 2] =
    [CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, CoreJwsSigningAlgorithm::EcdsaP256Sha256];


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretRef,
    pub redirect_url: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub role_map: GroupRoleMap,
}


pub struct OidcContext<'a> {
    pub config: &'a OidcConfig,
    pub http: HttpFn<'a>,
    pub resolve: ResolveFn<'a>,
}


#[derive(Debug)]
pub struct Callback {
    pub state: String,
    pub code: SecretString,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub groups: BTreeSet<String>,
}


pub fn default_groups_claim() -> String {
    DEFAULT_GROUPS_CLAIM.to_owned()
}


pub fn parse_oidc_config(text: &str, file: &str, catalog: &RoleCatalog) -> Result<OidcConfig, AuthError> {
    let config: OidcConfig = parse_document(text, file)?;
    config.role_map.values().try_for_each(|roles| check_roles(catalog, roles))?;
    Ok(config)
}


pub fn new_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(StdDuration::from_secs(HTTP_TIMEOUT_SECONDS))
        .build()
}


pub fn http_call(agent: &ureq::Agent, request: HttpRequest) -> Result<HttpResponse, io::Error> {
    agent.call(request).map_err(io::Error::other)
}


pub fn provider_error<Cause: Display>(cause: Cause) -> OidcDenial {
    tracing::warn!(%cause, "identity provider exchange failed");
    OidcDenial::Provider
}


pub fn build_client(oidc: &OidcContext) -> Result<OidcClient, OidcDenial> {
    let secret = (oidc.resolve)(&oidc.config.client_secret).map_err(provider_error)?;
    let issuer = IssuerUrl::new(oidc.config.issuer.clone()).map_err(provider_error)?;
    let redirect = RedirectUrl::new(oidc.config.redirect_url.clone()).map_err(provider_error)?;
    let metadata = CoreProviderMetadata::discover(&issuer, &oidc.http).map_err(provider_error)?;
    Ok(CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(oidc.config.client_id.clone()),
        Some(ClientSecret::new(secret.expose_secret().to_owned())),
    )
    .set_redirect_uri(redirect))
}


pub fn random_text(random: RandomFn) -> Result<String, AuthError> {
    Ok(HEXLOWER.encode(&random_array::<STATE_BYTES>(random)?))
}


pub fn prune_pending(pending: &mut PendingMap, now: OffsetDateTime) {
    pending.retain(|_, login| now - login.created_at < Duration::seconds(PENDING_TTL_SECONDS));
}


pub fn begin_login(oidc: &OidcContext, pending: &mut PendingMap, now: OffsetDateTime, random: RandomFn) -> Result<String, AuthError> {
    prune_pending(pending, now);
    if pending.len() >= PENDING_MAX {
        Err(OidcDenial::TooManyPending)?;
    }
    let seed = random_text(random)?;
    let state = hash_token(&format!("state:{seed}"));
    let nonce = hash_token(&format!("nonce:{seed}"));
    let verifier = hash_token(&format!("verifier:{seed}"));
    let client = build_client(oidc)?;
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.clone()));
    let request = client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        {
            let own_state = state.clone();
            move || CsrfToken::new(own_state)
        },
        {
            let own_nonce = nonce.clone();
            move || Nonce::new(own_nonce)
        },
    );
    let (url, _, _) = oidc
        .config
        .scopes
        .iter()
        .fold(request, |built, scope| built.add_scope(Scope::new(scope.clone())))
        .set_pkce_challenge(challenge)
        .url();
    pending.insert(
        hash_token(&state),
        PendingLogin {
            nonce,
            verifier: SecretString::from(verifier),
            created_at: now,
        },
    );
    Ok(url.to_string())
}


pub fn claims_denial(error: ClaimsVerificationError) -> OidcDenial {
    tracing::warn!(%error, "ID token rejected");
    match error {
        ClaimsVerificationError::Expired(_) => OidcDenial::Expired,
        ClaimsVerificationError::InvalidAudience(_) => OidcDenial::WrongAudience,
        ClaimsVerificationError::InvalidIssuer(_) => OidcDenial::WrongIssuer,
        ClaimsVerificationError::InvalidNonce(_) => OidcDenial::BadNonce,
        ClaimsVerificationError::SignatureVerification(_) => OidcDenial::BadSignature,
        _ => OidcDenial::InvalidToken,
    }
}


pub fn denial_reason(denial: OidcDenial) -> &'static str {
    match denial {
        OidcDenial::BadState => "bad_state",
        OidcDenial::Provider => "provider_error",
        OidcDenial::MissingIdToken => "missing_id_token",
        OidcDenial::Expired => "expired",
        OidcDenial::WrongAudience => "wrong_audience",
        OidcDenial::WrongIssuer => "wrong_issuer",
        OidcDenial::BadNonce => "bad_nonce",
        OidcDenial::BadSignature => "bad_signature",
        OidcDenial::InvalidToken => "invalid_token",
        OidcDenial::InvalidSubject => "invalid_subject",
        OidcDenial::Unmapped => "unmapped",
        OidcDenial::TooManyPending => "too_many_pending",
    }
}


pub fn groups_of(payload: &Value, claim: &str) -> BTreeSet<String> {
    match payload.get(claim) {
        Some(Value::Array(items)) => items.iter().filter_map(|item| item.as_str().map(str::to_owned)).collect(),
        Some(Value::Object(entries)) => entries.keys().cloned().collect(),
        _ => BTreeSet::new(),
    }
}


pub fn payload_of(text: &str) -> Result<Value, OidcDenial> {
    let segment = text.split('.').nth(1).ok_or(OidcDenial::InvalidToken)?;
    let bytes = BASE64URL_NOPAD.decode(segment.as_bytes()).map_err(provider_error)?;
    serde_json::from_slice(&bytes).map_err(provider_error)
}


pub fn take_pending(pending: &mut PendingMap, state: &str, now: OffsetDateTime) -> Result<PendingLogin, OidcDenial> {
    pending
        .remove(&hash_token(state))
        .filter(|login| now - login.created_at < Duration::seconds(PENDING_TTL_SECONDS))
        .ok_or(OidcDenial::BadState)
}


pub fn fetch_identity(oidc: &OidcContext, login: PendingLogin, code: &SecretString) -> Result<Identity, OidcDenial> {
    let client = build_client(oidc)?;
    let response = client
        .exchange_code(AuthorizationCode::new(code.expose_secret().to_owned()))
        .map_err(provider_error)?
        .set_pkce_verifier(PkceCodeVerifier::new(login.verifier.expose_secret().to_owned()))
        .request(&oidc.http)
        .map_err(provider_error)?;
    let token = response.id_token().ok_or(OidcDenial::MissingIdToken)?;
    let verifier = client.id_token_verifier().set_allowed_algs(ALLOWED_ALGORITHMS);
    let claims = token.claims(&verifier, &Nonce::new(login.nonce)).map_err(claims_denial)?;
    let subject = claims.subject().to_string();
    payload_of(&token.to_string()).map(|payload| Identity {
        subject,
        groups: groups_of(&payload, &oidc.config.groups_claim),
    })
}


pub fn map_roles(config: &OidcConfig, groups: &BTreeSet<String>) -> RoleSet {
    groups.iter().filter_map(|group| config.role_map.get(group)).flatten().cloned().collect()
}


pub fn upsert_external(state: &mut State, username: &str, roles: RoleSet) {
    let changed = state.accounts.get(username).is_none_or(|account| account.roles != roles);
    if changed {
        revoke_user_sessions(&mut state.sessions, username);
    }
    state.accounts.insert(
        username.to_owned(),
        Account {
            username: username.to_owned(),
            password_hash: EXTERNAL_PASSWORD_HASH.to_owned(),
            roles,
            totp: None,
        },
    );
}


pub fn record_denial<Output: Write>(
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    denial: OidcDenial,
    callback: &Callback,
) -> Result<AuthError, AuthError> {
    let outcome = if denial == OidcDenial::Unmapped {
        Outcome::Denied
    } else {
        Outcome::Failure
    };
    let parameters = [("reason", denial_reason(denial).to_owned()), ("source", callback.source.clone())];
    record(context, now, actor, ACTION_LOGIN, OIDC_TARGET, outcome, &parameters)?;
    Ok(AuthError::InvalidCredentials)
}


pub fn grant_external<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    username: &str,
    roles: RoleSet,
    callback: &Callback,
) -> Result<SecretString, AuthError> {
    let mut working = state.clone();
    upsert_external(&mut working, username, roles);
    match create_session(&mut working.sessions, username, now, context.random) {
        Ok(token) => {
            let parameters = [("method", "oidc".to_owned()), ("source", callback.source.clone())];
            record(context, now, username, ACTION_LOGIN, OIDC_TARGET, Outcome::Success, &parameters)?;
            state.accounts = working.accounts;
            state.sessions = working.sessions;
            Ok(token)
        }
        Err(error) => {
            tracing::error!(%error, "OIDC session creation failed");
            Err(record_denial(context, now, username, OidcDenial::Provider, callback)?)
        }
    }
}


pub fn settle_identity<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    oidc: &OidcContext,
    now: OffsetDateTime,
    identity: &Identity,
    callback: &Callback,
) -> Result<SecretString, AuthError> {
    let username = format!("{OIDC_PREFIX}{}", identity.subject);
    if check_username(&identity.subject).is_err() {
        Err(record_denial(context, now, ANONYMOUS_ACTOR, OidcDenial::InvalidSubject, callback)?)
    } else {
        let roles = map_roles(oidc.config, &identity.groups);
        let mapping = [("roles", join_roles(&roles)), ("groups", identity.groups.len().to_string())];
        if roles.is_empty() {
            record(context, now, &username, ACTION_OIDC_MAP, &username, Outcome::Denied, &mapping)?;
            Err(record_denial(context, now, &username, OidcDenial::Unmapped, callback)?)
        } else {
            record(context, now, &username, ACTION_OIDC_MAP, &username, Outcome::Success, &mapping)?;
            grant_external(state, context, now, &username, roles, callback)
        }
    }
}


pub fn complete_login<Output: Write>(
    state: &mut State,
    pending: &mut PendingMap,
    context: &Context<Output>,
    oidc: &OidcContext,
    now: OffsetDateTime,
    callback: &Callback,
) -> Result<SecretString, AuthError> {
    match take_pending(pending, &callback.state, now).and_then(|login| fetch_identity(oidc, login, &callback.code)) {
        Ok(identity) => settle_identity(state, context, oidc, now, &identity, callback),
        Err(denial) => Err(record_denial(context, now, ANONYMOUS_ACTOR, denial, callback)?),
    }
}
