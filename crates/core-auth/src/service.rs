use crate::error::AuthError;
use crate::limiter::{account_key, clear_failures, locked_until, record_failure, source_key, ACCOUNT_MAX_FAILURES, SOURCE_MAX_FAILURES};
use crate::model::{Account, TotpEnrolment};
use crate::password::hash_password;
use crate::policy::check_password;
use crate::rbac::{check_roles, is_allowed, requires_mfa, PERMISSION_USERS_MANAGE, ROLE_ADMINISTRATOR};
use crate::secretbox::{open_secret, seal_secret};
use crate::session::{create_session, hash_token, revoke_session, revoke_user_sessions, session_owner, validate_session};
use crate::totp::{consume_backup_code, hash_backup_code, new_backup_codes, new_secret, secret_text, verify_code};
use crate::types::{AccountMap, AttemptMap, CompromisedSet, Parameters, RandomFn, RoleCatalog, RoleSet, SessionMap, StoreKey, VerifyFn};
use core_audit::log::{append, AuditLog};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use secrecy::{ExposeSecret, SecretString};
use std::io::Write;
use time::OffsetDateTime;


pub const MODULE_NAME: &str = "core-auth";


pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$eLn8npymZcp+LqjaHar7Ww$YLEZoBh9Xv6kwPHZD3zecktBgdrvag7/CXQCA6uy/Ws";


pub const ANONYMOUS_ACTOR: &str = "anonymous";


pub const BOOTSTRAP_ACTOR: &str = "bootstrap";


pub const SYSTEM_ACTOR: &str = "system";


pub const ENROLMENT_SOURCE: &str = "enrolment";


pub const UNKNOWN_PREFIX: &str = "unknown:";


pub const UNKNOWN_HEX_CHARS: usize = 12;


pub const UNKNOWN_SESSION: &str = "unknown session";


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
    pub verify: VerifyFn<'a>,
    pub key: &'a StoreKey,
    pub compromised: &'a CompromisedSet,
    pub catalog: &'a RoleCatalog,
    pub tenant: &'a str,
    pub request_id: &'a str,
}


#[derive(Debug, Default, Clone, PartialEq, Eq)]
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


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acting {
    pub actor: String,
    pub authenticated: bool,
    pub manager: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    UnknownUser,
    BadPassword,
    MfaNotEnrolled,
    MfaMissing,
    MfaInvalid,
    Internal,
}


pub fn denial_reason(denial: Denial) -> &'static str {
    match denial {
        Denial::UnknownUser => "unknown_user",
        Denial::BadPassword => "bad_password",
        Denial::MfaNotEnrolled => "mfa_not_enrolled",
        Denial::MfaMissing => "mfa_missing",
        Denial::MfaInvalid => "mfa_invalid",
        Denial::Internal => "internal_error",
    }
}


pub fn denial_error(denial: Denial) -> AuthError {
    match denial {
        Denial::UnknownUser | Denial::BadPassword | Denial::Internal => AuthError::InvalidCredentials,
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


pub fn pseudonym(username: &str) -> String {
    format!(
        "{UNKNOWN_PREFIX}{}",
        hash_token(username).chars().take(UNKNOWN_HEX_CHARS).collect::<String>()
    )
}


pub fn audit_name(accounts: &AccountMap, username: &str) -> String {
    if accounts.contains_key(username) {
        username.to_owned()
    } else {
        pseudonym(username)
    }
}


pub fn resolve_actor(state: &mut State, catalog: &RoleCatalog, token: &str, now: OffsetDateTime) -> Acting {
    match validate_session(&mut state.sessions, token, now) {
        Ok(user) => {
            let manager = state
                .accounts
                .get(&user)
                .is_some_and(|account| is_allowed(catalog, &account.roles, PERMISSION_USERS_MANAGE));
            Acting {
                actor: user,
                authenticated: true,
                manager,
            }
        }
        Err(_) => Acting {
            actor: ANONYMOUS_ACTOR.to_owned(),
            authenticated: false,
            manager: false,
        },
    }
}


pub fn require(acting: &Acting, allowed: bool) -> Result<(), AuthError> {
    if !acting.authenticated {
        Err(AuthError::SessionInvalid)
    } else if allowed {
        Ok(())
    } else {
        Err(AuthError::PermissionDenied)
    }
}


pub fn failure_outcome(error: &AuthError) -> Outcome {
    if matches!(error, AuthError::PermissionDenied | AuthError::SessionInvalid) {
        Outcome::Denied
    } else {
        Outcome::Failure
    }
}


pub fn finish<Output: Write, Value>(
    context: &Context<Output>,
    now: OffsetDateTime,
    actor: &str,
    action: &str,
    target: &str,
    result: Result<(Value, Parameters), AuthError>,
) -> Result<Value, AuthError> {
    match result {
        Ok((value, parameters)) => record(context, now, actor, action, target, Outcome::Success, &parameters).map(|()| value),
        Err(error) => {
            record(
                context,
                now,
                actor,
                action,
                target,
                failure_outcome(&error),
                &[("reason", error.to_string())],
            )?;
            Err(error)
        }
    }
}


pub fn is_reserved(username: &str) -> bool {
    let lowered = username.to_lowercase();
    [ANONYMOUS_ACTOR, BOOTSTRAP_ACTOR, SYSTEM_ACTOR].contains(&lowered.as_str()) || lowered.starts_with(UNKNOWN_PREFIX)
}


pub fn transact<Output: Write, Value>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    action: &str,
    target: impl Fn(&State) -> String,
    operation: impl FnOnce(&mut State, &Acting) -> Result<(Value, Parameters), AuthError>,
) -> Result<Value, AuthError> {
    let mut working = state.clone();
    let acting = resolve_actor(&mut working, context.catalog, token, now);
    let result = operation(&mut working, &acting);
    let outcome = finish(context, now, &acting.actor, action, &target(&working), result);
    state.attempts = working.attempts;
    if outcome.is_ok() {
        state.accounts = working.accounts;
        state.sessions = working.sessions;
    }
    outcome
}


pub fn check_username(username: &str) -> Result<(), AuthError> {
    if username.is_empty() || username.chars().any(|character| character.is_whitespace() || character.is_control()) || is_reserved(username) {
        Err(AuthError::InvalidUsername)
    } else {
        Ok(())
    }
}


pub fn join_roles(roles: &RoleSet) -> String {
    roles.iter().cloned().collect::<Vec<_>>().join(",")
}


pub fn insert_account<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    username: &str,
    password: &SecretString,
    roles: RoleSet,
) -> Result<Parameters, AuthError> {
    check_username(username)?;
    check_roles(context.catalog, &roles)?;
    if state.accounts.contains_key(username) {
        Err(AuthError::AccountExists)
    } else {
        check_password(password.expose_secret(), context.compromised)?;
        let joined = join_roles(&roles);
        state.accounts.insert(
            username.to_owned(),
            Account {
                username: username.to_owned(),
                password_hash: hash_password(password.expose_secret(), context.random)?,
                roles,
                totp: None,
            },
        );
        Ok(vec![("roles", joined)])
    }
}


pub fn create_account<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    username: &str,
    password: &SecretString,
    roles: RoleSet,
) -> Result<(), AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_ACCOUNT_CREATE,
        |after| audit_name(&after.accounts, username),
        |working, acting| {
            require(acting, acting.manager)
                .and_then(|()| insert_account(working, context, username, password, roles))
                .map(|parameters| ((), parameters))
        },
    )
}


pub fn new_enrolment<Output: Write>(context: &Context<Output>, username: &str) -> Result<(TotpEnrolment, Enrolment), AuthError> {
    let secret = new_secret(context.random)?;
    let codes = new_backup_codes(context.random)?;
    let stored = TotpEnrolment {
        encrypted_secret: seal_secret(context.key, username, &secret, context.random)?,
        last_step: 0,
        backup_code_hashes: codes.iter().map(|code| hash_backup_code(code)).collect(),
    };
    let shown = Enrolment {
        secret: SecretString::from(secret_text(&secret)),
        backup_codes: codes.into_iter().map(SecretString::from).collect(),
    };
    Ok((stored, shown))
}


pub fn enrol_account<Output: Write>(account: &mut Account, context: &Context<Output>, username: &str) -> Result<(Enrolment, Parameters), AuthError> {
    let (stored, shown) = new_enrolment(context, username)?;
    account.totp = Some(stored);
    Ok((shown, vec![("method", "totp".to_owned())]))
}


pub fn bootstrap_administrator<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    username: &str,
    password: &SecretString,
) -> Result<Enrolment, AuthError> {
    let mut working = state.clone();
    let created = if working.accounts.is_empty() {
        insert_account(&mut working, context, username, password, RoleSet::from([ROLE_ADMINISTRATOR.to_owned()]))
    } else {
        Err(AuthError::AlreadyBootstrapped)
    };
    let target = audit_name(&working.accounts, username);
    finish(
        context,
        now,
        BOOTSTRAP_ACTOR,
        ACTION_ACCOUNT_CREATE,
        &target,
        created.map(|parameters| ((), parameters)),
    )?;
    let enrolled = working
        .accounts
        .get_mut(username)
        .ok_or(AuthError::NoSuchAccount)
        .and_then(|account| enrol_account(account, context, username));
    let shown = finish(context, now, BOOTSTRAP_ACTOR, ACTION_MFA_ENROL, &target, enrolled)?;
    state.accounts = working.accounts;
    Ok(shown)
}


pub fn check_current_code<Output: Write>(
    attempts: &mut AttemptMap,
    context: &Context<Output>,
    now: OffsetDateTime,
    existing: &mut TotpEnrolment,
    username: &str,
    code: &SecretString,
) -> Result<(), AuthError> {
    let key = account_key(username);
    match locked_until(attempts, &key, now) {
        Some(until) => Err(AuthError::Locked { until }),
        None => match verify_factor(existing, context.key, username, code.expose_secret(), now)? {
            None => Ok(()),
            Some(denial) => {
                record_failure(attempts, &key, ACCOUNT_MAX_FAILURES, now)
                    .map_or(Ok(()), |until| log_lockout(context, now, username, ENROLMENT_SOURCE, "account", until))?;
                Err(denial_error(denial))
            }
        },
    }
}


pub fn replace_enrolment<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    acting: &Acting,
    username: &str,
    current_code: Option<&SecretString>,
) -> Result<(Enrolment, Parameters), AuthError> {
    let account = state.accounts.get_mut(username).ok_or(AuthError::NoSuchAccount)?;
    let proof = match (account.totp.as_mut(), acting.manager, current_code) {
        (Some(_), false, None) => Err(AuthError::MfaRequired),
        (Some(existing), false, Some(code)) => check_current_code(&mut state.attempts, context, now, existing, username, code),
        _ => Ok(()),
    };
    proof.and_then(|()| enrol_account(account, context, username))
}


pub fn enrol_totp<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    username: &str,
    current_code: Option<&SecretString>,
) -> Result<Enrolment, AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_MFA_ENROL,
        |after| audit_name(&after.accounts, username),
        |working, acting| {
            require(acting, acting.manager || acting.actor == username)
                .and_then(|()| replace_enrolment(working, context, now, acting, username, current_code))
        },
    )
}


pub fn apply_roles(state: &mut State, catalog: &RoleCatalog, username: &str, roles: RoleSet) -> Result<Parameters, AuthError> {
    check_roles(catalog, &roles)?;
    let account = state.accounts.get_mut(username).ok_or(AuthError::NoSuchAccount)?;
    let before = join_roles(&account.roles);
    let after = join_roles(&roles);
    account.roles = roles;
    let revoked = revoke_user_sessions(&mut state.sessions, username);
    Ok(vec![("before", before), ("after", after), ("revoked_sessions", revoked.to_string())])
}


pub fn change_roles<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    username: &str,
    roles: RoleSet,
) -> Result<(), AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_ROLE_CHANGE,
        |after| audit_name(&after.accounts, username),
        |working, acting| {
            require(acting, acting.manager)
                .and_then(|()| apply_roles(working, context.catalog, username, roles))
                .map(|parameters| ((), parameters))
        },
    )
}


pub fn revoke_token<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    target_token: &str,
) -> Result<(), AuthError> {
    let owner = session_owner(&state.sessions, target_token);
    transact(
        state,
        context,
        now,
        token,
        ACTION_SESSION_REVOKE,
        |_| owner.clone().unwrap_or_else(|| UNKNOWN_SESSION.to_owned()),
        |working, acting| {
            require(acting, acting.manager || owner.as_deref() == Some(acting.actor.as_str()))
                .and_then(|()| revoke_session(&mut working.sessions, target_token).ok_or(AuthError::SessionInvalid))
                .map(|_| ((), Vec::new()))
        },
    )
}


pub fn revoke_all_sessions<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
    username: &str,
) -> Result<usize, AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_SESSION_REVOKE_ALL,
        |after| audit_name(&after.accounts, username),
        |working, acting| {
            require(acting, acting.manager || acting.actor == username).map(|()| {
                let revoked = revoke_user_sessions(&mut working.sessions, username);
                (revoked, vec![("count", revoked.to_string())])
            })
        },
    )
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


pub fn second_factor(
    account: &mut Account,
    catalog: &RoleCatalog,
    key: &StoreKey,
    request: &LoginRequest,
    now: OffsetDateTime,
) -> Result<Option<Denial>, AuthError> {
    let role_needs_mfa = requires_mfa(catalog, &account.roles);
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
    let hash = stored
        .as_ref()
        .map_or_else(|| DUMMY_HASH.to_owned(), |account| account.password_hash.clone());
    let password_ok = (context.verify)(request.password.expose_secret(), &hash)?;
    match stored {
        None => Ok(Some(Denial::UnknownUser)),
        Some(account) if password_ok => second_factor(account, context.catalog, context.key, request, now),
        Some(_) => Ok(Some(Denial::BadPassword)),
    }
}


pub fn log_lockout<Output: Write>(
    context: &Context<Output>,
    now: OffsetDateTime,
    audit_user: &str,
    source: &str,
    scope: &str,
    until: OffsetDateTime,
) -> Result<(), AuthError> {
    record(
        context,
        now,
        audit_user,
        ACTION_LOCKOUT,
        audit_user,
        Outcome::Denied,
        &[
            ("scope", scope.to_owned()),
            ("source", source.to_owned()),
            ("until", until.unix_timestamp().to_string()),
        ],
    )
}


pub fn register_failure<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    audit_user: &str,
    request: &LoginRequest,
) -> Result<(), AuthError> {
    let account_lock = state
        .accounts
        .contains_key(&request.username)
        .then(|| record_failure(&mut state.attempts, &account_key(&request.username), ACCOUNT_MAX_FAILURES, now))
        .flatten();
    let source_lock = record_failure(&mut state.attempts, &source_key(&request.source), SOURCE_MAX_FAILURES, now);
    [("account", account_lock), ("source", source_lock)]
        .into_iter()
        .try_for_each(|(scope, lock)| lock.map_or(Ok(()), |until| log_lockout(context, now, audit_user, &request.source, scope, until)))
}


pub fn deny_login<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    audit_user: &str,
    request: &LoginRequest,
    denial: Denial,
) -> Result<SecretString, AuthError> {
    let parameters = [("reason", denial_reason(denial).to_owned()), ("source", request.source.clone())];
    record(context, now, audit_user, ACTION_LOGIN, audit_user, denial_outcome(denial), &parameters)?;
    if counts_as_failure(denial) {
        register_failure(state, context, now, audit_user, request)?;
    }
    Err(denial_error(denial))
}


pub fn factors_denial<Output: Write>(
    accounts: &mut AccountMap,
    context: &Context<Output>,
    request: &LoginRequest,
    now: OffsetDateTime,
) -> Option<Denial> {
    check_factors(accounts, context, request, now).unwrap_or_else(|error| {
        tracing::warn!(%error, "login verification failed internally");
        Some(Denial::Internal)
    })
}


pub fn grant_login<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    audit_user: &str,
    request: &LoginRequest,
) -> Result<SecretString, AuthError> {
    let mut sessions = state.sessions.clone();
    match create_session(&mut sessions, &request.username, now, context.random) {
        Ok(token) => {
            record(
                context,
                now,
                &request.username,
                ACTION_LOGIN,
                &request.username,
                Outcome::Success,
                &[("source", request.source.clone())],
            )?;
            state.sessions = sessions;
            clear_failures(&mut state.attempts, &account_key(&request.username));
            Ok(token)
        }
        Err(error) => {
            tracing::warn!(%error, "session creation failed after the factors were accepted");
            deny_login(state, context, now, audit_user, request, Denial::Internal)
        }
    }
}


pub fn login<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    request: &LoginRequest,
) -> Result<SecretString, AuthError> {
    let audit_user = audit_name(&state.accounts, &request.username);
    let lock = locked_until(&state.attempts, &account_key(&request.username), now)
        .or_else(|| locked_until(&state.attempts, &source_key(&request.source), now));
    match lock {
        Some(until) => {
            let parameters = [("reason", "locked".to_owned()), ("source", request.source.clone())];
            record(context, now, &audit_user, ACTION_LOGIN, &audit_user, Outcome::Denied, &parameters)?;
            Err(AuthError::Locked { until })
        }
        None => {
            let mut accounts = state.accounts.clone();
            match factors_denial(&mut accounts, context, request, now) {
                None => {
                    let granted = grant_login(state, context, now, &audit_user, request);
                    if granted.is_ok() {
                        state.accounts = accounts;
                    }
                    granted
                }
                Some(denial) => deny_login(state, context, now, &audit_user, request, denial),
            }
        }
    }
}
