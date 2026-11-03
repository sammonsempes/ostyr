use crate::error::AuthError;
use crate::limiter::{account_key, clear_failures, locked_until, record_failure, source_key, ACCOUNT_MAX_FAILURES, SOURCE_MAX_FAILURES};
use crate::model::{Account, TotpEnrolment};
use crate::password::{hash_password, verify_password};
use crate::policy::check_password;
use crate::rbac::{check_roles, is_allowed, requires_mfa};
use crate::secretbox::{open_secret, seal_secret};
use crate::session::{create_session, revoke_session, revoke_user_sessions, validate_session};
use crate::totp::{consume_backup_code, hash_backup_code, new_backup_codes, new_secret, secret_text, verify_code};
use crate::types::{AccountMap, AttemptMap, CompromisedSet, RandomFn, RoleCatalog, RoleSet, SessionMap, StoreKey};
use core_audit::log::{append, AuditLog};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;
use time::OffsetDateTime;


pub const MODULE_NAME: &str = "core-auth";


pub const DUMMY_PASSWORD: &str = "dummy password for constant work";


pub const ACTION_LOGIN: &str = "auth.login";


pub const ACTION_LOCKOUT: &str = "auth.lockout";


pub const ACTION_ACCOUNT_CREATE: &str = "auth.account.create";


pub const ACTION_MFA_ENROL: &str = "auth.mfa.enrol";


pub const ACTION_ROLE_CHANGE: &str = "authz.role.change";


pub const ACTION_SESSION_REVOKE: &str = "auth.session.revoke";


pub const ACTION_SESSION_REVOKE_ALL: &str = "auth.session.revoke_all";


pub struct Context<'a, Output> {
    pub audit: &'a AuditLog<Output>,
    pub random: RandomFn,
    pub key: &'a StoreKey,
    pub compromised: &'a CompromisedSet,
    pub catalog: &'a RoleCatalog,
    pub tenant: &'a str,
    pub request_id: &'a str,
}


#[derive(Debug, Default)]
pub struct State {
    pub accounts: AccountMap,
    pub sessions: SessionMap,
    pub attempts: AttemptMap,
}


#[derive(Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: SecretString,
    pub totp_code: Option<SecretString>,
    pub source: String,
}


#[derive(Debug)]
pub struct Enrolment {
    pub secret: SecretString,
    pub backup_codes: Vec<SecretString>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    UnknownUser,
    BadPassword,
    MfaNotEnrolled,
    MfaMissing,
    MfaInvalid,
}


pub fn denial_reason(denial: Denial) -> &'static str {
    match denial {
        Denial::UnknownUser => "unknown_user",
        Denial::BadPassword => "bad_password",
        Denial::MfaNotEnrolled => "mfa_not_enrolled",
        Denial::MfaMissing => "mfa_missing",
        Denial::MfaInvalid => "mfa_invalid",
    }
}


pub fn denial_error(denial: Denial) -> AuthError {
    match denial {
        Denial::UnknownUser | Denial::BadPassword => AuthError::InvalidCredentials,
        Denial::MfaNotEnrolled => AuthError::MfaEnrolmentRequired,
        Denial::MfaMissing => AuthError::MfaRequired,
        Denial::MfaInvalid => AuthError::MfaInvalid,
    }
}


pub fn counts_as_failure(denial: Denial) -> bool {
    !matches!(denial, Denial::MfaNotEnrolled | Denial::MfaMissing)
}


pub fn denial_outcome(denial: Denial) -> Outcome {
    if counts_as_failure(denial) {
        Outcome::Failure
    } else {
        Outcome::Denied
    }
}


pub fn record<Output: Write>(
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    action: &str,
    target: &str,
    outcome: Outcome,
    parameters: &[(&str, String)],
) -> Result<(), AuthError> {
    append(
        context.audit,
        NewEntry {
            timestamp: now,
            actor: Actor {
                kind: ActorKind::User,
                id: actor.to_owned(),
            },
            tenant: context.tenant.to_owned(),
            module: MODULE_NAME.to_owned(),
            action: action.to_owned(),
            target: target.to_owned(),
            outcome,
            request_id: context.request_id.to_owned(),
            justification: None,
            parameters: parameters.iter().map(|(name, value)| ((*name).to_owned(), value.clone())).collect(),
        },
    )?;
    Ok(())
}


pub fn check_username(username: &str) -> Result<(), AuthError> {
    if username.is_empty() || username.chars().any(|character| character.is_whitespace() || character.is_control()) {
        Err(AuthError::InvalidUsername)
    } else {
        Ok(())
    }
}


pub fn prepare_account<Output: Write>(
    state: &State,
    context: &Context<Output>,
    username: &str,
    password: &SecretString,
    roles: RoleSet,
) -> Result<Account, AuthError> {
    check_username(username)?;
    check_roles(context.catalog, &roles)?;
    if state.accounts.contains_key(username) {
        Err(AuthError::AccountExists)
    } else {
        check_password(password.expose_secret(), context.compromised)?;
        Ok(Account {
            username: username.to_owned(),
            password_hash: hash_password(password.expose_secret(), context.random)?,
            roles,
            totp: None,
        })
    }
}


pub fn create_account<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    username: &str,
    password: &SecretString,
    roles: RoleSet,
) -> Result<(), AuthError> {
    match prepare_account(state, context, username, password, roles) {
        Ok(account) => {
            let joined = account.roles.iter().cloned().collect::<Vec<_>>().join(",");
            state.accounts.insert(username.to_owned(), account);
            record(
                context,
                now,
                actor,
                ACTION_ACCOUNT_CREATE,
                username,
                Outcome::Success,
                &[("roles", joined)],
            )
        }
        Err(error) => {
            record(
                context,
                now,
                actor,
                ACTION_ACCOUNT_CREATE,
                username,
                Outcome::Failure,
                &[("reason", error.to_string())],
            )?;
            Err(error)
        }
    }
}


pub fn enrol_totp<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    username: &str,
) -> Result<Enrolment, AuthError> {
    let account = state.accounts.get_mut(username).ok_or(AuthError::NoSuchAccount)?;
    let secret = new_secret(context.random)?;
    let codes = new_backup_codes(context.random)?;
    account.totp = Some(TotpEnrolment {
        encrypted_secret: seal_secret(context.key, username, &secret, context.random)?,
        last_step: 0,
        backup_code_hashes: codes.iter().map(|code| hash_backup_code(code)).collect(),
    });
    record(
        context,
        now,
        actor,
        ACTION_MFA_ENROL,
        username,
        Outcome::Success,
        &[("method", "totp".to_owned())],
    )?;
    Ok(Enrolment {
        secret: SecretString::from(secret_text(&secret)),
        backup_codes: codes.into_iter().map(SecretString::from).collect(),
    })
}


pub fn change_roles<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    username: &str,
    roles: RoleSet,
) -> Result<(), AuthError> {
    check_roles(context.catalog, &roles)?;
    let account = state.accounts.get_mut(username).ok_or(AuthError::NoSuchAccount)?;
    let before = account.roles.iter().cloned().collect::<Vec<_>>().join(",");
    let after = roles.iter().cloned().collect::<Vec<_>>().join(",");
    account.roles = roles;
    let revoked = revoke_user_sessions(&mut state.sessions, username);
    record(
        context,
        now,
        actor,
        ACTION_ROLE_CHANGE,
        username,
        Outcome::Success,
        &[("before", before), ("after", after), ("revoked_sessions", revoked.to_string())],
    )
}


pub fn revoke_token<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    token: &str,
) -> Result<(), AuthError> {
    let user = revoke_session(&mut state.sessions, token).ok_or(AuthError::SessionInvalid)?;
    record(context, now, actor, ACTION_SESSION_REVOKE, &user, Outcome::Success, &[])
}


pub fn revoke_all_sessions<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    username: &str,
) -> Result<usize, AuthError> {
    let revoked = revoke_user_sessions(&mut state.sessions, username);
    record(
        context,
        now,
        actor,
        ACTION_SESSION_REVOKE_ALL,
        username,
        Outcome::Success,
        &[("count", revoked.to_string())],
    )?;
    Ok(revoked)
}


pub fn authorize(state: &mut State, catalog: &RoleCatalog, token: &str, now: OffsetDateTime, permission: &str) -> Result<String, AuthError> {
    let user = validate_session(&mut state.sessions, token, now)?;
    let roles = state.accounts.get(&user).map(|account| &account.roles).ok_or(AuthError::SessionInvalid)?;
    is_allowed(catalog, roles, permission).then_some(user).ok_or(AuthError::PermissionDenied)
}


pub fn verify_factor(
    enrolment: &mut TotpEnrolment,
    key: &StoreKey,
    username: &str,
    code: &str,
    now: OffsetDateTime,
) -> Result<Option<Denial>, AuthError> {
    let secret = open_secret(key, username, &enrolment.encrypted_secret)?;
    let used = match verify_code(&secret, code, now, enrolment.last_step)? {
        Some(step) => {
            enrolment.last_step = step;
            true
        }
        None => consume_backup_code(enrolment, code),
    };
    Ok((!used).then_some(Denial::MfaInvalid))
}


pub fn second_factor(account: &mut Account, key: &StoreKey, request: &LoginRequest, now: OffsetDateTime) -> Result<Option<Denial>, AuthError> {
    let role_needs_mfa = requires_mfa(&account.roles);
    match (account.totp.as_mut(), request.totp_code.as_ref()) {
        (None, _) => Ok(role_needs_mfa.then_some(Denial::MfaNotEnrolled)),
        (Some(_), None) => Ok(Some(Denial::MfaMissing)),
        (Some(enrolment), Some(code)) => verify_factor(enrolment, key, &request.username, code.expose_secret(), now),
    }
}


pub fn check_factors<Output: Write>(
    accounts: &mut AccountMap,
    context: &Context<Output>,
    request: &LoginRequest,
    now: OffsetDateTime,
) -> Result<Option<Denial>, AuthError> {
    let stored = accounts.get_mut(&request.username);
    let hash = match &stored {
        Some(account) => account.password_hash.clone(),
        None => hash_password(DUMMY_PASSWORD, context.random)?,
    };
    let password_ok = verify_password(request.password.expose_secret(), &hash)?;
    match stored {
        None => Ok(Some(Denial::UnknownUser)),
        Some(account) if password_ok => second_factor(account, context.key, request, now),
        Some(_) => Ok(Some(Denial::BadPassword)),
    }
}


pub fn log_lockout<Output: Write>(
    context: &Context<Output>,
    now: OffsetDateTime,
    request: &LoginRequest,
    scope: &str,
    until: OffsetDateTime,
) -> Result<(), AuthError> {
    record(
        context,
        now,
        &request.username,
        ACTION_LOCKOUT,
        &request.username,
        Outcome::Denied,
        &[
            ("scope", scope.to_owned()),
            ("source", request.source.clone()),
            ("until", until.unix_timestamp().to_string()),
        ],
    )
}


pub fn register_failure<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    request: &LoginRequest,
) -> Result<(), AuthError> {
    let account_lock = record_failure(&mut state.attempts, &account_key(&request.username), ACCOUNT_MAX_FAILURES, now);
    let source_lock = record_failure(&mut state.attempts, &source_key(&request.source), SOURCE_MAX_FAILURES, now);
    [("account", account_lock), ("source", source_lock)]
        .into_iter()
        .try_for_each(|(scope, lock)| lock.map_or(Ok(()), |until| log_lockout(context, now, request, scope, until)))
}


pub fn deny_login<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    request: &LoginRequest,
    denial: Denial,
) -> Result<SecretString, AuthError> {
    let parameters = [("reason", denial_reason(denial).to_owned()), ("source", request.source.clone())];
    record(
        context,
        now,
        &request.username,
        ACTION_LOGIN,
        &request.username,
        denial_outcome(denial),
        &parameters,
    )?;
    if counts_as_failure(denial) {
        register_failure(state, context, now, request)?;
    }
    Err(denial_error(denial))
}


pub fn grant_login<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    request: &LoginRequest,
) -> Result<SecretString, AuthError> {
    clear_failures(&mut state.attempts, &account_key(&request.username));
    let token = create_session(&mut state.sessions, &request.username, now, context.random)?;
    record(
        context,
        now,
        &request.username,
        ACTION_LOGIN,
        &request.username,
        Outcome::Success,
        &[("source", request.source.clone())],
    )?;
    Ok(token)
}


pub fn login<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    request: &LoginRequest,
) -> Result<SecretString, AuthError> {
    let lock = locked_until(&state.attempts, &account_key(&request.username), now)
        .or_else(|| locked_until(&state.attempts, &source_key(&request.source), now));
    match lock {
        Some(until) => {
            let parameters = [("reason", "locked".to_owned()), ("source", request.source.clone())];
            record(
                context,
                now,
                &request.username,
                ACTION_LOGIN,
                &request.username,
                Outcome::Denied,
                &parameters,
            )?;
            Err(AuthError::Locked { until })
        }
        None => match check_factors(&mut state.accounts, context, request, now)? {
            None => grant_login(state, context, now, request),
            Some(denial) => deny_login(state, context, now, request, denial),
        },
    }
}
