//! WebAuthn credentials of local accounts: registration, second factor and passwordless passkey login (spec sections 12 and 15).

use crate::error::AuthError;
use crate::limiter::{account_key, clear_failures, locked_until, record_failure, source_key};
use crate::model::{Challenge, ChallengeKind, CredentialInfo, Located, Prepared, StoredCredential};
use crate::oidc::EXTERNAL_PASSWORD_HASH;
use crate::random::random_array;
use crate::rbac::{requires_mfa, webauthn_required};
use crate::service::{
    audit_name, count_failure, denial_error, finish, login_gate, record, record_denial, refuse_locked, require, resolve_actor, transact,
    verify_account_password, Context, Denial, LoginRequest, State, ACTION_LOGIN, ANONYMOUS_ACTOR,
};
use crate::session::create_session;
use crate::types::{Parameters, RandomFn, RoleCatalog, RoleSet};
use core_audit::model::Outcome;
use core_config::parse::parse_document;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use secrecy::SecretString;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Write;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, Passkey, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Webauthn, WebauthnBuilder, WebauthnError,
};


pub const CHALLENGE_SECONDS: i64 = 300;


pub const CHALLENGE_MAX: usize = 1024;


pub const ANONYMOUS_CHALLENGE_MAX: usize = 256;


pub const PASSKEY_START_MAX: usize = 20;


pub const PASSKEY_START_KEY: &str = "passkey_start";


pub const CHALLENGE_ID_BYTES: usize = 16;


pub const NAME_MAX_CHARS: usize = 64;


pub const UUID_BYTES: usize = 16;


pub const BITS_PER_BYTE: u32 = 8;


pub const USER_HANDLE_DOMAIN: &str = "ostyr-webauthn-user:";


pub const METHOD_WEBAUTHN: &str = "webauthn";


pub const METHOD_PASSKEY: &str = "passkey";


pub const ACTION_REGISTER_START: &str = "auth.webauthn.register_start";


pub const ACTION_REGISTER: &str = "auth.webauthn.register";


pub const ACTION_LOGIN_START: &str = "auth.webauthn.login_start";


pub const ACTION_RENAME: &str = "auth.webauthn.rename";


pub const ACTION_REMOVE: &str = "auth.webauthn.remove";


#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}


#[derive(Debug)]
pub struct Assertion {
    pub challenge_id: String,
    pub response: PublicKeyCredential,
    pub source: String,
}


#[derive(Debug)]
pub struct RegistrationRequest {
    pub username: String,
    pub challenge_id: String,
    pub name: String,
    pub response: RegisterPublicKeyCredential,
}


pub fn parse_webauthn_config(text: &str, file: &str) -> Result<WebauthnConfig, AuthError> {
    Ok(parse_document(text, file)?)
}


pub fn build_webauthn(config: &WebauthnConfig) -> Result<Webauthn, AuthError> {
    let origin = Url::parse(&config.rp_origin)?;
    Ok(WebauthnBuilder::new(&config.rp_id, &origin)?.rp_name(&config.rp_name).build()?)
}


pub fn encode_id(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}


/// The stable user handle of an account: the first 16 bytes of a domain-separated SHA-256 of its name.
pub fn user_uuid(username: &str) -> Uuid {
    let digest = Sha256::digest(format!("{USER_HANDLE_DOMAIN}{username}").as_bytes());
    Uuid::from_u128(
        digest
            .iter()
            .take(UUID_BYTES)
            .fold(u128::MIN, |accumulated, byte| (accumulated << BITS_PER_BYTE) | u128::from(*byte)),
    )
}


pub fn check_name(name: &str) -> Result<(), AuthError> {
    if name.is_empty() || name.chars().count() > NAME_MAX_CHARS || name.chars().any(char::is_control) {
        Err(AuthError::InvalidCredentialName)
    } else {
        Ok(())
    }
}


pub fn is_fresh(challenge: &Challenge, now: OffsetDateTime) -> bool {
    now - challenge.created_at < Duration::seconds(CHALLENGE_SECONDS)
}


pub fn issue_challenge(
    state: &mut State,
    now: OffsetDateTime,
    random: RandomFn,
    (actor, user): (&str, &str),
    kind: ChallengeKind,
) -> Result<String, AuthError> {
    state.challenges.retain(|_, challenge| is_fresh(challenge, now));
    let anonymous = state
        .challenges
        .values()
        .filter(|pending| matches!(pending.kind, ChallengeKind::Passwordless(_)))
        .count();
    let crowded = match kind {
        ChallengeKind::Passwordless(_) => anonymous >= ANONYMOUS_CHALLENGE_MAX,
        _ => state.challenges.len() >= CHALLENGE_MAX,
    };
    if crowded {
        Err(AuthError::TooManyChallenges)
    } else {
        let identifier = HEXLOWER.encode(&random_array::<CHALLENGE_ID_BYTES>(random)?);
        state.challenges.insert(
            identifier.clone(),
            Challenge {
                actor: actor.to_owned(),
                user: user.to_owned(),
                created_at: now,
                kind,
            },
        );
        Ok(identifier)
    }
}


/// Removes the challenge whatever happens next, so it can be answered once only.
pub fn take_challenge(state: &mut State, now: OffsetDateTime, identifier: &str) -> Result<Challenge, AuthError> {
    let challenge = state.challenges.remove(identifier).ok_or(AuthError::ChallengeInvalid)?;
    if is_fresh(&challenge, now) {
        Ok(challenge)
    } else {
        Err(AuthError::ChallengeExpired)
    }
}


pub fn passkeys_of(state: &State, username: &str) -> Vec<Passkey> {
    state
        .credentials
        .get(username)
        .into_iter()
        .flatten()
        .map(|credential| credential.passkey.clone())
        .collect()
}


/// Passkeys belong to local accounts: an identity provider owns the roles of an external account and could not revoke a passkey.
pub fn require_local(state: &State, username: &str) -> Result<(), AuthError> {
    let account = state.accounts.get(username).ok_or(AuthError::NoSuchAccount)?;
    if account.password_hash == EXTERNAL_PASSWORD_HASH {
        Err(AuthError::ExternalAccount)
    } else {
        Ok(())
    }
}


pub fn begin_registration(
    working: &mut State,
    context: &Context<impl Write>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    (actor, username): (&str, &str),
) -> Result<(String, CreationChallengeResponse), AuthError> {
    require_local(working, username)?;
    let excluded = passkeys_of(working, username).iter().map(|passkey| passkey.cred_id().clone()).collect();
    let (options, registration) = webauthn.start_passkey_registration(user_uuid(username), username, username, Some(excluded))?;
    let identifier = issue_challenge(working, now, context.random, (actor, username), ChallengeKind::Registration(registration))?;
    Ok((identifier, options))
}


/// Starts the registration of a credential for `username`; allowed for the account itself and for `users.manage`.
pub fn register_start<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    token: &str,
    username: &str,
) -> Result<(String, CreationChallengeResponse), AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_REGISTER_START,
        |after| audit_name(&after.accounts, username),
        |working, acting| {
            require(acting, acting.manager || acting.actor == username)
                .and_then(|()| begin_registration(working, context, webauthn, now, (&acting.actor, username)))
                .map(|started| (started, Vec::new()))
        },
    )
}


pub fn registration_state(challenge: Challenge, actor: &str, username: &str) -> Result<PasskeyRegistration, AuthError> {
    match challenge.kind {
        ChallengeKind::Registration(registration) if challenge.actor == actor && challenge.user == username => Ok(registration),
        _ => Err(AuthError::ChallengeInvalid),
    }
}


pub fn complete_registration(
    working: &mut State,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    actor: &str,
    request: &RegistrationRequest,
) -> Result<(String, Parameters), AuthError> {
    check_name(&request.name)?;
    require_local(working, &request.username)?;
    let challenge = take_challenge(working, now, &request.challenge_id)?;
    let registration = registration_state(challenge, actor, &request.username)?;
    let passkey = webauthn.finish_passkey_registration(&request.response, &registration)?;
    let identifier = encode_id(passkey.cred_id());
    if working.credentials.values().flatten().any(|credential| credential.id == identifier) {
        Err(AuthError::CredentialExists)
    } else {
        working.credentials.entry(request.username.clone()).or_default().push(StoredCredential {
            username: request.username.clone(),
            id: identifier.clone(),
            name: request.name.clone(),
            created_at: now.unix_timestamp(),
            last_used: None,
            passkey,
        });
        Ok((identifier.clone(), vec![("credential", identifier), ("name", request.name.clone())]))
    }
}


/// Finishes a registration started by the same actor for the same account and returns the credential id.
pub fn register_finish<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    token: &str,
    request: &RegistrationRequest,
) -> Result<String, AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_REGISTER,
        |after| audit_name(&after.accounts, &request.username),
        |working, acting| {
            require(acting, acting.manager || acting.actor == request.username)
                .and_then(|()| complete_registration(working, webauthn, now, &acting.actor, request))
        },
    )
}


pub fn credential_info(credential: &StoredCredential) -> CredentialInfo {
    CredentialInfo {
        id: credential.id.clone(),
        name: credential.name.clone(),
        created_at: credential.created_at,
        last_used: credential.last_used,
    }
}


pub fn list_credentials(
    state: &mut State,
    catalog: &RoleCatalog,
    now: OffsetDateTime,
    token: &str,
    username: &str,
) -> Result<Vec<CredentialInfo>, AuthError> {
    let acting = resolve_actor(state, catalog, token, now);
    require(&acting, acting.manager || acting.actor == username)?;
    Ok(state.credentials.get(username).into_iter().flatten().map(credential_info).collect())
}


pub fn rename_in(working: &mut State, username: &str, identifier: &str, name: &str) -> Result<Parameters, AuthError> {
    check_name(name)?;
    let credential = working
        .credentials
        .get_mut(username)
        .into_iter()
        .flatten()
        .find(|credential| credential.id == identifier)
        .ok_or(AuthError::UnknownCredential)?;
    credential.name = name.to_owned();
    Ok(vec![("credential", identifier.to_owned()), ("name", name.to_owned())])
}


pub fn rename_credential<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    (username, identifier, name): (&str, &str, &str),
) -> Result<(), AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_RENAME,
        |after| audit_name(&after.accounts, username),
        |working, acting| {
            require(acting, acting.manager || acting.actor == username)
                .and_then(|()| rename_in(working, username, identifier, name))
                .map(|parameters| ((), parameters))
        },
    )
}


/// An account that needs a second factor keeps one: a WebAuthn-only role keeps a credential, any other privileged role keeps TOTP or a credential.
pub fn last_factor_blocked(catalog: &RoleCatalog, roles: &RoleSet, has_totp: bool, remaining: usize) -> bool {
    remaining == 0 && (webauthn_required(catalog, roles) || (requires_mfa(catalog, roles) && !has_totp))
}


pub fn remove_in(working: &mut State, catalog: &RoleCatalog, username: &str, identifier: &str) -> Result<Parameters, AuthError> {
    let account = working.accounts.get(username).ok_or(AuthError::NoSuchAccount)?;
    let credentials = working.credentials.get_mut(username).ok_or(AuthError::UnknownCredential)?;
    let remaining = credentials.iter().filter(|credential| credential.id != identifier).count();
    if remaining == credentials.len() {
        Err(AuthError::UnknownCredential)
    } else if last_factor_blocked(catalog, &account.roles, account.totp.is_some(), remaining) {
        Err(AuthError::LastFactor)
    } else {
        credentials.retain(|credential| credential.id != identifier);
        Ok(vec![("credential", identifier.to_owned()), ("remaining", remaining.to_string())])
    }
}


pub fn remove_credential<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    (username, identifier): (&str, &str),
) -> Result<(), AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_REMOVE,
        |after| audit_name(&after.accounts, username),
        |working, acting| {
            require(acting, acting.manager || acting.actor == username)
                .and_then(|()| remove_in(working, context.catalog, username, identifier))
                .map(|parameters| ((), parameters))
        },
    )
}


pub fn second_factor_challenge<Output: Write>(
    working: &mut State,
    context: &Context<Output>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    request: &LoginRequest,
) -> Result<Result<(String, RequestChallengeResponse), Denial>, AuthError> {
    let password_ok = verify_account_password(&working.accounts, context, &request.username, &request.password)?;
    let passkeys = passkeys_of(working, &request.username);
    match (working.accounts.contains_key(&request.username), password_ok) {
        (false, _) => Ok(Err(Denial::UnknownUser)),
        (true, false) => Ok(Err(Denial::BadPassword)),
        (true, true) if passkeys.is_empty() => Ok(Err(Denial::MfaNotEnrolled)),
        (true, true) => {
            let (options, authentication) = webauthn.start_passkey_authentication(&passkeys)?;
            let kind = ChallengeKind::SecondFactor(authentication);
            let identifier = issue_challenge(working, now, context.random, (&request.username, &request.username), kind)?;
            Ok(Ok((identifier, options)))
        }
    }
}


/// Checks the password and, when the account holds credentials, issues the challenge of the second factor.
pub fn webauthn_login_start<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    request: &LoginRequest,
) -> Result<(String, RequestChallengeResponse), AuthError> {
    let audit_user = audit_name(&state.accounts, &request.username);
    login_gate(state, context, now, &audit_user, request)?;
    let mut working = state.clone();
    let outcome = second_factor_challenge(&mut working, context, webauthn, now, request).unwrap_or_else(|error| {
        tracing::warn!(%error, "WebAuthn challenge could not be issued");
        Err(Denial::Internal)
    });
    match outcome {
        Ok(started) => {
            let parameters = [("source", request.source.clone())];
            record(context, now, &audit_user, ACTION_LOGIN_START, &audit_user, Outcome::Success, &parameters)?;
            state.challenges = working.challenges;
            Ok(started)
        }
        Err(denial) => {
            record_denial(state, context, now, &audit_user, request, denial)?;
            Err(denial_error(denial))
        }
    }
}


/// Starts a passwordless login: no account is named, the authenticator offers its discoverable credential.
pub fn passkey_login_start<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    source: &str,
) -> Result<(String, RequestChallengeResponse), AuthError> {
    let start_key = source_key(&format!("{PASSKEY_START_KEY}:{source}"));
    let locked = locked_until(&state.attempts, &source_key(source), now).or_else(|| locked_until(&state.attempts, &start_key, now));
    match locked {
        Some(until) => {
            refuse_locked(context, now, ANONYMOUS_ACTOR, source)?;
            Err(AuthError::Locked { until })
        }
        None => {
            let mut working = state.clone();
            record_failure(&mut working.attempts, &start_key, PASSKEY_START_MAX, now);
            let started = webauthn
                .start_discoverable_authentication()
                .map_err(AuthError::from)
                .and_then(|(options, discoverable)| {
                    let kind = ChallengeKind::Passwordless(discoverable);
                    issue_challenge(&mut working, now, context.random, (ANONYMOUS_ACTOR, ANONYMOUS_ACTOR), kind)
                        .map(|identifier| (identifier, options))
                });
            let reply = finish(
                context,
                now,
                ANONYMOUS_ACTOR,
                ACTION_LOGIN_START,
                ANONYMOUS_ACTOR,
                started.map(|value| (value, vec![("source", source.to_owned())])),
            )?;
            state.challenges = working.challenges;
            state.attempts = working.attempts;
            Ok(reply)
        }
    }
}


pub fn locate(working: &State, webauthn: &Webauthn, challenge: Challenge, response: &PublicKeyCredential) -> Result<Located, AuthError> {
    match challenge.kind {
        ChallengeKind::SecondFactor(authentication) => require_local(working, &challenge.user).map(|()| Located {
            user: challenge.user,
            prepared: Prepared::SecondFactor(authentication),
        }),
        ChallengeKind::Passwordless(discoverable) => {
            let (handle, credential_id) = webauthn.identify_discoverable_authentication(response)?;
            let identifier = encode_id(credential_id);
            let stored = working
                .credentials
                .values()
                .flatten()
                .find(|credential| credential.id == identifier && user_uuid(&credential.username) == handle)
                .ok_or(AuthError::UnknownCredential)?;
            require_local(working, &stored.username)?;
            Ok(Located {
                user: stored.username.clone(),
                prepared: Prepared::Passwordless(discoverable, Box::new(stored.passkey.clone())),
            })
        }
        ChallengeKind::Registration(_) => Err(AuthError::ChallengeInvalid),
    }
}


pub fn classify(error: WebauthnError) -> AuthError {
    match error {
        WebauthnError::CredentialPossibleCompromise => AuthError::CounterRegression,
        other => AuthError::Webauthn(other),
    }
}


pub fn check_assertion(webauthn: &Webauthn, located: &Located, response: &PublicKeyCredential) -> Result<AuthenticationResult, AuthError> {
    match &located.prepared {
        Prepared::SecondFactor(authentication) => webauthn.finish_passkey_authentication(response, authentication),
        Prepared::Passwordless(discoverable, passkey) => {
            webauthn.finish_discoverable_authentication_v2(response, discoverable.clone(), passkey.as_ref())
        }
    }
    .map_err(classify)
}


pub fn refusal_reason(error: &AuthError) -> &'static str {
    match error {
        AuthError::ChallengeExpired => "challenge_expired",
        AuthError::ChallengeInvalid => "bad_challenge",
        AuthError::UnknownCredential => "unknown_credential",
        AuthError::ExternalAccount => "external_account",
        AuthError::CounterRegression => "counter_regression",
        _ => "assertion_invalid",
    }
}


/// Every refusal of an assertion is audited with its precise reason and answered as `invalid credentials`.
pub fn refuse_assertion<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    source: &str,
    (user, reason): (Option<&str>, &str),
) -> Result<SecretString, AuthError> {
    let username = user.unwrap_or(ANONYMOUS_ACTOR);
    let audit_user = user.map_or_else(|| ANONYMOUS_ACTOR.to_owned(), |name| audit_name(&state.accounts, name));
    let parameters = [("reason", reason.to_owned()), ("source", source.to_owned())];
    record(context, now, &audit_user, ACTION_LOGIN, &audit_user, Outcome::Failure, &parameters)?;
    count_failure(state, context, now, &audit_user, username, source, true)?;
    Err(AuthError::InvalidCredentials)
}


pub fn method_of(prepared: &Prepared) -> &'static str {
    match prepared {
        Prepared::SecondFactor(_) => METHOD_WEBAUTHN,
        Prepared::Passwordless(..) => METHOD_PASSKEY,
    }
}


pub fn apply_result(working: &mut State, username: &str, result: &AuthenticationResult, now: OffsetDateTime) {
    let identifier = encode_id(result.cred_id());
    working
        .credentials
        .get_mut(username)
        .into_iter()
        .flatten()
        .filter(|credential| credential.id == identifier)
        .for_each(|credential| {
            credential.passkey.update_credential(result);
            credential.last_used = Some(now.unix_timestamp());
        });
}


pub fn grant_assertion<Output: Write>(
    state: &mut State,
    mut working: State,
    context: &Context<Output>,
    now: OffsetDateTime,
    (source, located, result): (&str, &Located, &AuthenticationResult),
) -> Result<SecretString, AuthError> {
    apply_result(&mut working, &located.user, result, now);
    match create_session(&mut working.sessions, &located.user, now, context.random) {
        Ok(token) => {
            let parameters = [("source", source.to_owned()), ("method", method_of(&located.prepared).to_owned())];
            record(context, now, &located.user, ACTION_LOGIN, &located.user, Outcome::Success, &parameters)?;
            state.sessions = working.sessions;
            state.credentials = working.credentials;
            clear_failures(&mut state.attempts, &account_key(&located.user));
            Ok(token)
        }
        Err(error) => {
            tracing::warn!(%error, "session creation failed after the assertion was accepted");
            refuse_assertion(state, context, now, source, (Some(&located.user), "internal_error"))
        }
    }
}


pub fn settle_assertion<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    assertion: &Assertion,
) -> Result<SecretString, AuthError> {
    let mut working = state.clone();
    let located =
        take_challenge(&mut working, now, &assertion.challenge_id).and_then(|challenge| locate(&working, webauthn, challenge, &assertion.response));
    state.challenges = working.challenges.clone();
    match located {
        Err(error) => refuse_assertion(state, context, now, &assertion.source, (None, refusal_reason(&error))),
        Ok(found) => match check_assertion(webauthn, &found, &assertion.response) {
            Err(error) => refuse_assertion(state, context, now, &assertion.source, (Some(&found.user), refusal_reason(&error))),
            Ok(result) => grant_assertion(state, working, context, now, (&assertion.source, &found, &result)),
        },
    }
}


/// Finishes a second-factor or a passwordless login; the challenge is consumed even when the assertion is refused.
pub fn webauthn_login_finish<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: &Webauthn,
    now: OffsetDateTime,
    assertion: &Assertion,
) -> Result<SecretString, AuthError> {
    match locked_until(&state.attempts, &source_key(&assertion.source), now) {
        Some(until) => {
            refuse_locked(context, now, ANONYMOUS_ACTOR, &assertion.source)?;
            Err(AuthError::Locked { until })
        }
        None => settle_assertion(state, context, webauthn, now, assertion),
    }
}
