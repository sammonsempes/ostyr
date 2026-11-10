#[path = "support/types.rs"]
mod types;


use core_auth::error::AuthError;
use core_auth::limiter::{
    account_key, clear_failures, locked_until, record_failure, source_key, ACCOUNT_MAX_FAILURES, FAILURE_WINDOW_SECONDS, LOCKOUT_SECONDS,
    SOURCE_MAX_FAILURES,
};
use core_auth::model::Account;
use core_auth::random::os_random;
use core_auth::rbac::{
    builtin_catalog, check_roles, is_allowed, load_catalog, requires_mfa, PERMISSION_ALERTS_READ, PERMISSION_ALERTS_TRIAGE, PERMISSION_AUDIT_READ,
    PERMISSION_CASES_READ, PERMISSION_CONFIG_MANAGE, PERMISSION_EVENTS_READ, PERMISSION_RESPONSE_EXECUTE, PERMISSION_USERS_MANAGE,
    ROLE_ADMINISTRATOR, ROLE_ANALYST, ROLE_AUDITOR, ROLE_READER, ROLE_RESPONDER,
};
use core_auth::session::{
    create_session, hash_token, is_revoked, mark_sessions_revoked, revocation_marker, revoke_session, revoke_user_sessions, validate_session,
    SESSION_ABSOLUTE_SECONDS, SESSION_IDLE_SECONDS,
};
use core_auth::types::{AccountMap, AttemptMap, RoleSet, SessionMap};
use secrecy::ExposeSecret;
use time::{Duration, OffsetDateTime};
use types::TestResult;


const TWO_SESSIONS: usize = 2;


const BASE_TIME: i64 = 1_700_000_000;


const TOKEN_HEX_LENGTH: usize = 64;


const REFRESH_INTERVAL_SECONDS: i64 = 800;


fn at(offset: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(BASE_TIME + offset)
}


fn roles(names: &[&str]) -> RoleSet {
    names.iter().map(|name| (*name).to_owned()).collect()
}


fn failing_random(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


#[test]
fn built_in_roles_have_the_expected_permissions() -> TestResult {
    let catalog = builtin_catalog();
    let matrix = [
        (ROLE_READER, [true, false, false, false, false, false, false, false]),
        (ROLE_ANALYST, [true, true, true, false, false, false, false, true]),
        (ROLE_RESPONDER, [true, true, true, true, false, false, false, true]),
        (ROLE_ADMINISTRATOR, [true, true, true, true, false, true, true, true]),
        (ROLE_AUDITOR, [true, true, false, false, true, false, false, true]),
    ];
    let permissions = [
        PERMISSION_EVENTS_READ,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_TRIAGE,
        PERMISSION_RESPONSE_EXECUTE,
        PERMISSION_AUDIT_READ,
        PERMISSION_USERS_MANAGE,
        PERMISSION_CONFIG_MANAGE,
        PERMISSION_CASES_READ,
    ];
    matrix.iter().for_each(|(role, expected)| {
        permissions
            .iter()
            .zip(expected)
            .for_each(|(permission, allowed)| assert_eq!(is_allowed(&catalog, &roles(&[role]), permission), *allowed, "{role} {permission}"));
    });
    Ok(())
}


#[test]
fn access_is_denied_by_default() -> TestResult {
    let catalog = builtin_catalog();
    assert!(!is_allowed(&catalog, &RoleSet::new(), PERMISSION_EVENTS_READ));
    assert!(!is_allowed(&catalog, &roles(&["ghost"]), PERMISSION_EVENTS_READ));
    assert!(!is_allowed(&catalog, &roles(&[ROLE_ADMINISTRATOR]), "unknown.permission"));
    assert!(!is_allowed(&catalog, &roles(&[ROLE_ADMINISTRATOR]), ""));
    Ok(())
}


#[test]
fn several_roles_add_their_permissions() -> TestResult {
    let catalog = builtin_catalog();
    let both = roles(&[ROLE_READER, ROLE_AUDITOR]);
    assert!(is_allowed(&catalog, &both, PERMISSION_AUDIT_READ));
    assert!(!is_allowed(&catalog, &both, PERMISSION_USERS_MANAGE));
    Ok(())
}


#[test]
fn custom_roles_are_data() -> TestResult {
    let text = r#"[{"name":"hunter","permissions":["events.read","hunt.run"]}]"#;
    let catalog = load_catalog(text.as_bytes())?;
    assert!(is_allowed(&catalog, &roles(&["hunter"]), "hunt.run"));
    assert!(!is_allowed(&catalog, &roles(&["hunter"]), PERMISSION_AUDIT_READ));
    assert!(is_allowed(&catalog, &roles(&[ROLE_READER]), PERMISSION_EVENTS_READ));
    check_roles(&catalog, &roles(&["hunter", ROLE_READER]))?;
    Ok(())
}


#[test]
fn custom_roles_cannot_redefine_built_ins() -> TestResult {
    let text = r#"[{"name":"administrator","permissions":[]}]"#;
    assert!(matches!(load_catalog(text.as_bytes()), Err(AuthError::BuiltInRole(name)) if name == ROLE_ADMINISTRATOR));
    Ok(())
}


#[test]
fn malformed_role_data_is_refused() -> TestResult {
    assert!(matches!(load_catalog("[{".as_bytes()), Err(AuthError::Format(_))));
    assert!(matches!(
        load_catalog(r#"[{"name":"x","permissions":[],"extra":1}]"#.as_bytes()),
        Err(AuthError::Format(_))
    ));
    Ok(())
}


#[test]
fn unknown_roles_are_refused() -> TestResult {
    let catalog = builtin_catalog();
    assert!(matches!(check_roles(&catalog, &roles(&["ghost"])), Err(AuthError::UnknownRole(name)) if name == "ghost"));
    Ok(())
}


#[test]
fn mfa_follows_privileged_permissions_not_role_names() -> TestResult {
    let text = r#"[
        {"name":"ops","permissions":["config.manage"]},
        {"name":"keeper","permissions":["roles.manage"]},
        {"name":"exporter","permissions":["audit.export"]},
        {"name":"people","permissions":["users.manage"]},
        {"name":"viewer","permissions":["events.read"]}
    ]"#;
    let catalog = load_catalog(text.as_bytes())?;
    assert!(requires_mfa(&catalog, &roles(&[ROLE_READER, ROLE_ADMINISTRATOR])));
    ["ops", "keeper", "exporter", "people"]
        .iter()
        .for_each(|name| assert!(requires_mfa(&catalog, &roles(&[ROLE_READER, name])), "{name}"));
    assert!(!requires_mfa(&catalog, &roles(&[ROLE_RESPONDER, ROLE_AUDITOR, "viewer"])));
    assert!(!requires_mfa(&catalog, &roles(&["ghost"])));
    assert!(!requires_mfa(&catalog, &RoleSet::new()));
    Ok(())
}


#[test]
fn sessions_store_only_the_token_hash() -> TestResult {
    let mut sessions = SessionMap::new();
    let token = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    let secret = token.expose_secret();
    assert_eq!(secret.len(), TOKEN_HEX_LENGTH);
    assert!(sessions.contains_key(&hash_token(secret)));
    assert!(sessions.keys().all(|key| key != secret));
    assert_eq!(validate_session(&mut sessions, secret, at(1)?)?, "alice");
    assert!(matches!(
        create_session(&mut sessions, "alice", at(0)?, failing_random),
        Err(AuthError::Random(_))
    ));
    Ok(())
}


#[test]
fn tokens_are_unique() -> TestResult {
    let mut sessions = SessionMap::new();
    let first = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    let second = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    assert_ne!(first.expose_secret(), second.expose_secret());
    assert_eq!(sessions.len(), TWO_SESSIONS);
    Ok(())
}


#[test]
fn idle_expiry_is_exact() -> TestResult {
    let mut sessions = SessionMap::new();
    let token = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    assert_eq!(
        validate_session(&mut sessions, token.expose_secret(), at(SESSION_IDLE_SECONDS - 1)?)?,
        "alice"
    );
    let last_seen = SESSION_IDLE_SECONDS - 1;
    assert!(matches!(
        validate_session(&mut sessions, token.expose_secret(), at(last_seen + SESSION_IDLE_SECONDS)?),
        Err(AuthError::SessionInvalid)
    ));
    assert!(sessions.is_empty());
    Ok(())
}


#[test]
fn activity_extends_the_idle_timer_until_the_absolute_limit() -> TestResult {
    let mut sessions = SessionMap::new();
    let token = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    let mut elapsed = 0;
    while elapsed + REFRESH_INTERVAL_SECONDS < SESSION_ABSOLUTE_SECONDS {
        elapsed += REFRESH_INTERVAL_SECONDS;
        assert_eq!(validate_session(&mut sessions, token.expose_secret(), at(elapsed)?)?, "alice");
    }
    assert!(matches!(
        validate_session(&mut sessions, token.expose_secret(), at(SESSION_ABSOLUTE_SECONDS)?),
        Err(AuthError::SessionInvalid)
    ));
    Ok(())
}


#[test]
fn revocation_is_immediate() -> TestResult {
    let mut sessions = SessionMap::new();
    let token = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    assert_eq!(revoke_session(&mut sessions, token.expose_secret()), Some("alice".to_owned()));
    assert!(matches!(
        validate_session(&mut sessions, token.expose_secret(), at(1)?),
        Err(AuthError::SessionInvalid)
    ));
    assert_eq!(revoke_session(&mut sessions, token.expose_secret()), None);
    Ok(())
}


#[test]
fn all_sessions_of_a_user_are_revoked_at_once() -> TestResult {
    let mut sessions = SessionMap::new();
    let first = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    let second = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    let other = create_session(&mut sessions, "bob", at(0)?, os_random)?;
    assert_eq!(revoke_user_sessions(&mut sessions, "alice"), TWO_SESSIONS);
    assert!(validate_session(&mut sessions, first.expose_secret(), at(1)?).is_err());
    assert!(validate_session(&mut sessions, second.expose_secret(), at(1)?).is_err());
    assert_eq!(validate_session(&mut sessions, other.expose_secret(), at(1)?)?, "bob");
    assert_eq!(revoke_user_sessions(&mut sessions, "alice"), 0);
    Ok(())
}


#[test]
fn lockout_starts_at_the_threshold() -> TestResult {
    let mut attempts = AttemptMap::new();
    let key = account_key("alice");
    (0..ACCOUNT_MAX_FAILURES - 1).try_for_each(|_| {
        assert_eq!(record_failure(&mut attempts, &key, ACCOUNT_MAX_FAILURES, at(0)?), None);
        Ok::<(), time::error::ComponentRange>(())
    })?;
    assert_eq!(locked_until(&attempts, &key, at(0)?), None);
    let until = record_failure(&mut attempts, &key, ACCOUNT_MAX_FAILURES, at(0)?);
    assert_eq!(until, Some(at(LOCKOUT_SECONDS)?));
    assert_eq!(locked_until(&attempts, &key, at(LOCKOUT_SECONDS - 1)?), until);
    assert_eq!(locked_until(&attempts, &key, at(LOCKOUT_SECONDS)?), None);
    assert_eq!(locked_until(&attempts, &account_key("bob"), at(0)?), None);
    Ok(())
}


#[test]
fn old_failures_leave_the_window() -> TestResult {
    let mut attempts = AttemptMap::new();
    let key = source_key("10.0.0.1");
    (0..SOURCE_MAX_FAILURES - 1).try_for_each(|_| {
        record_failure(&mut attempts, &key, SOURCE_MAX_FAILURES, at(0)?);
        Ok::<(), time::error::ComponentRange>(())
    })?;
    assert_eq!(
        record_failure(&mut attempts, &key, SOURCE_MAX_FAILURES, at(FAILURE_WINDOW_SECONDS)?),
        None
    );
    let entry = attempts.get(&key).ok_or("missing entry")?;
    assert_eq!(entry.failures.len(), 1);
    assert_eq!(entry.failures.first(), Some(&at(FAILURE_WINDOW_SECONDS)?));
    Ok(())
}


#[test]
fn clearing_forgets_failures_and_keys_are_scoped() -> TestResult {
    let mut attempts = AttemptMap::new();
    record_failure(&mut attempts, &account_key("alice"), ACCOUNT_MAX_FAILURES, at(0)?);
    assert_ne!(account_key("alice"), source_key("alice"));
    clear_failures(&mut attempts, &account_key("alice"));
    assert!(attempts.is_empty());
    assert_eq!(Duration::seconds(LOCKOUT_SECONDS), Duration::seconds(FAILURE_WINDOW_SECONDS));
    Ok(())
}


#[test]
fn a_session_at_or_before_the_marker_is_revoked() -> TestResult {
    let mut sessions = SessionMap::new();
    let token = create_session(&mut sessions, "alice", at(0)?, os_random)?;
    let session = sessions.get(&hash_token(token.expose_secret())).ok_or("no session")?;
    let mut accounts = AccountMap::new();
    assert!(!is_revoked(&accounts, session));
    accounts.insert(
        "alice".to_owned(),
        Account {
            username: "alice".to_owned(),
            password_hash: "h".to_owned(),
            roles: RoleSet::new(),
            totp: None,
            sessions_valid_after: None,
        },
    );
    assert!(!is_revoked(&accounts, session));
    mark_sessions_revoked(&mut accounts, "ghost", at(0)?);
    assert!(!is_revoked(&accounts, session));
    assert!(!accounts.contains_key("ghost"));
    mark_sessions_revoked(&mut accounts, "oidc:sub", at(0)?);
    assert_eq!(
        accounts.get("oidc:sub").and_then(|account| account.sessions_valid_after),
        Some(revocation_marker(at(0)?))
    );
    mark_sessions_revoked(&mut accounts, "oidc:sub", at(1)?);
    assert_eq!(
        accounts.get("oidc:sub").and_then(|account| account.sessions_valid_after),
        Some(revocation_marker(at(1)?))
    );
    mark_sessions_revoked(&mut accounts, "alice", at(0)?);
    assert!(is_revoked(&accounts, session));
    mark_sessions_revoked(&mut accounts, "alice", at(-1)?);
    assert!(!is_revoked(&accounts, session));
    Ok(())
}


#[test]
fn an_out_of_range_time_saturates_the_marker() -> TestResult {
    assert_eq!(
        revocation_marker(OffsetDateTime::new_utc(time::Date::MAX, time::Time::MIDNIGHT)),
        i64::MAX
    );
    assert!(revocation_marker(at(0)?) < i64::MAX);
    Ok(())
}
