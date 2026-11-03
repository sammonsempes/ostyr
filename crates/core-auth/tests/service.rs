#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/types.rs"]
mod types;


use core_audit::log::{genesis_log, AuditLog};
use core_audit::verify::verify;
use core_auth::error::AuthError;
use core_auth::limiter::{ACCOUNT_MAX_FAILURES, LOCKOUT_SECONDS, SOURCE_MAX_FAILURES};
use core_auth::password::{verify_password, ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM};
use core_auth::random::os_random;
use core_auth::rbac::{
    builtin_catalog, load_catalog, PERMISSION_EVENTS_READ, PERMISSION_RESPONSE_EXECUTE, ROLE_ADMINISTRATOR, ROLE_ANALYST, ROLE_READER,
};
use core_auth::service::{
    authorize, bootstrap_administrator, change_roles, create_account, enrol_totp, login, revoke_all_sessions, revoke_token, Context, LoginRequest,
    State, DUMMY_HASH,
};
use core_auth::store::save_accounts;
use core_auth::totp::{code_for_step, TOTP_STEP_SECONDS};
use core_auth::types::{CompromisedSet, RoleCatalog, RoleSet, StoreKey};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use failing_writer::FailingWriter;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use time::OffsetDateTime;
use types::TestResult;


const PSEUDONYM_CHARS: usize = 12;


const PERMISSION_DENIALS: usize = 7;


const PLUS_TWO: i64 = 2;


const PLUS_THREE: i64 = 3;


const PLUS_FOUR: i64 = 4;


const PLUS_FIVE: i64 = 5;


const PLUS_SIX: i64 = 6;


const PLUS_SEVEN: i64 = 7;


const KEY_FILL: u8 = 9;


const BASE_TIME: i64 = 1_700_000_010;


const KEY_LENGTH: usize = 32;


const GOOD_PASSWORD: &str = "correct horse battery";


const SECOND_PASSWORD: &str = "another long passphrase";


const SOURCE: &str = "10.0.0.7";


const SECRET_LENGTH: usize = 20;


const BACKUP_LENGTH: usize = 10;


const NONCE_LENGTH: usize = 12;


const SALT_LENGTH: usize = 16;


const TOKEN_LENGTH: usize = 32;


const STEP_SKEW_SECONDS: i64 = 60;


struct Fixture<Output> {
    audit: AuditLog<Output>,
    key: StoreKey,
    compromised: CompromisedSet,
    catalog: RoleCatalog,
}


fn fixture() -> Fixture<Vec<u8>> {
    fixture_over(Vec::new())
}


fn fixture_over<Output: std::io::Write>(output: Output) -> Fixture<Output> {
    Fixture {
        audit: genesis_log(output),
        key: SecretSlice::from(vec![KEY_FILL; KEY_LENGTH]),
        compromised: ["password1234".to_owned()].into(),
        catalog: builtin_catalog(),
    }
}


fn context<'a, Output>(fixture: &'a Fixture<Output>) -> Context<'a, Output> {
    context_with(fixture, os_random)
}


fn context_with<'a, Output>(fixture: &'a Fixture<Output>, random: core_auth::types::RandomFn) -> Context<'a, Output> {
    Context {
        audit: &fixture.audit,
        random,
        verify: &verify_password,
        key: &fixture.key,
        compromised: &fixture.compromised,
        catalog: &fixture.catalog,
        tenant: "tenant-a",
        request_id: "request-1",
    }
}


fn at(offset: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(BASE_TIME + offset)
}


fn roles(names: &[&str]) -> RoleSet {
    names.iter().map(|name| (*name).to_owned()).collect()
}


fn audit_text(fixture: &Fixture<Vec<u8>>) -> Result<String, Box<dyn std::error::Error>> {
    let state = fixture.audit.state.lock().map_err(|_| "poisoned")?;
    verify(state.writer.as_slice(), None)?;
    Ok(String::from_utf8(state.writer.clone())?)
}


fn request(user: &str, password: &str, code: Option<&str>, source: &str) -> LoginRequest {
    LoginRequest {
        username: user.to_owned(),
        password: SecretString::from(password),
        totp_code: code.map(SecretString::from),
        source: source.to_owned(),
    }
}


fn with_user(fixture: &Fixture<Vec<u8>>, user: &str, user_roles: &[&str]) -> Result<(State, String), Box<dyn std::error::Error>> {
    let mut state = State::default();
    let admin = bootstrap(fixture, &mut state)?;
    create_account(
        &mut state,
        &context(fixture),
        at(0)?,
        &admin,
        user,
        &SecretString::from(GOOD_PASSWORD),
        roles(user_roles),
    )?;
    Ok((state, admin))
}


fn bootstrap(fixture: &Fixture<Vec<u8>>, state: &mut State) -> Result<String, Box<dyn std::error::Error>> {
    let ctx = context(fixture);
    let enrolment = bootstrap_administrator(state, &ctx, at(0)?, "admin", &SecretString::from(SECOND_PASSWORD))?;
    let code = current_code(&enrolment.secret, 0)?;
    let token = login(state, &ctx, at(0)?, &request("admin", SECOND_PASSWORD, Some(&code), "10.9.9.9"))?;
    Ok(token.expose_secret().to_owned())
}


fn current_code(secret: &SecretString, offset: i64) -> Result<String, Box<dyn std::error::Error>> {
    let raw = BASE32_NOPAD.decode(secret.expose_secret().as_bytes())?;
    let seconds = u64::try_from(BASE_TIME + offset)?;
    Ok(code_for_step(&raw, seconds / TOTP_STEP_SECONDS))
}


fn fail_on_secret(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    if buffer.len() == SECRET_LENGTH {
        Err(getrandom::Error::UNSUPPORTED)
    } else {
        os_random(buffer)
    }
}


fn fail_on_backup(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    if buffer.len() == BACKUP_LENGTH {
        Err(getrandom::Error::UNSUPPORTED)
    } else {
        os_random(buffer)
    }
}


fn fail_on_nonce(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    if buffer.len() == NONCE_LENGTH {
        Err(getrandom::Error::UNSUPPORTED)
    } else {
        os_random(buffer)
    }
}


fn fail_on_salt(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    if buffer.len() == SALT_LENGTH {
        Err(getrandom::Error::UNSUPPORTED)
    } else {
        os_random(buffer)
    }
}


#[test]
fn account_creation_is_audited() -> TestResult {
    let fixture = fixture();
    let (state, _) = with_user(&fixture, "alice", &[ROLE_ANALYST])?;
    assert!(state.accounts.contains_key("alice"));
    let text = audit_text(&fixture)?;
    assert!(text.contains("auth.account.create"));
    assert!(text.contains("\"roles\":\"analyst\""));
    assert!(!text.contains(GOOD_PASSWORD));
    Ok(())
}


#[test]
fn account_creation_rejections_are_audited() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let good = SecretString::from(GOOD_PASSWORD);
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "alice", &good, roles(&[])),
        Err(AuthError::AccountExists)
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "", &good, roles(&[])),
        Err(AuthError::InvalidUsername)
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "a b", &good, roles(&[])),
        Err(AuthError::InvalidUsername)
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "a\u{7}b", &good, roles(&[])),
        Err(AuthError::InvalidUsername)
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "bob", &good, roles(&["ghost"])),
        Err(AuthError::UnknownRole(_))
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "bob", &SecretString::from("short"), roles(&[])),
        Err(AuthError::Policy(_))
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "bob", &SecretString::from("Password1234"), roles(&[])),
        Err(AuthError::Policy(_))
    ));
    assert!(!state.accounts.contains_key("bob"));
    let text = audit_text(&fixture)?;
    assert!(text.contains("password is shorter"));
    assert!(text.contains("compromised"));
    assert!(!text.contains("Password1234"));
    Ok(())
}


#[test]
fn salt_failure_aborts_account_creation() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context_with(&fixture, fail_on_salt);
    let result = create_account(&mut state, &ctx, at(0)?, &admin, "bob", &SecretString::from(GOOD_PASSWORD), roles(&[]));
    assert!(matches!(result, Err(AuthError::Random(_))));
    assert!(!state.accounts.contains_key("bob"));
    Ok(())
}


#[test]
fn login_succeeds_and_session_authorises() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let token = login(&mut state, &ctx, at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    let user = authorize(&mut state, &fixture.catalog, token.expose_secret(), at(PLUS_TWO)?, PERMISSION_EVENTS_READ)?;
    assert_eq!(user, "alice");
    assert!(matches!(
        authorize(
            &mut state,
            &fixture.catalog,
            token.expose_secret(),
            at(PLUS_THREE)?,
            PERMISSION_RESPONSE_EXECUTE
        ),
        Err(AuthError::PermissionDenied)
    ));
    let text = audit_text(&fixture)?;
    assert!(text.contains("\"action\":\"auth.login\"") && text.contains("\"outcome\":\"success\""));
    assert!(!text.contains(token.expose_secret()));
    Ok(())
}


#[test]
fn wrong_password_and_unknown_user_look_alike() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let wrong = login(&mut state, &ctx, at(1)?, &request("alice", "wrong password here", None, SOURCE));
    let unknown = login(&mut state, &ctx, at(PLUS_TWO)?, &request("nobody", GOOD_PASSWORD, None, SOURCE));
    assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
    assert!(matches!(unknown, Err(AuthError::InvalidCredentials)));
    let text = audit_text(&fixture)?;
    assert!(text.contains("bad_password") && text.contains("unknown_user"));
    assert!(!text.contains("wrong password here"));
    Ok(())
}


#[test]
fn every_login_path_costs_one_password_verification() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let calls = Cell::new(usize::MIN);
    let seen = RefCell::new(Vec::new());
    let counting = |password: &str, stored: &str| {
        calls.set(calls.get() + 1);
        seen.borrow_mut().push(stored.to_owned());
        verify_password(password, stored)
    };
    let ctx = Context {
        verify: &counting,
        ..context(&fixture)
    };
    let alice_hash = state.accounts.get("alice").ok_or("no alice")?.password_hash.clone();
    let paths = [("nobody", GOOD_PASSWORD), ("alice", "wrong password here"), ("alice", GOOD_PASSWORD)];
    paths.iter().try_for_each(|(user, password)| {
        calls.set(0);
        let attempt = login(&mut state, &ctx, at(1)?, &request(user, password, None, SOURCE));
        assert_eq!(attempt.is_ok(), *user == "alice" && *password == GOOD_PASSWORD);
        assert_eq!(calls.get(), 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let hashes = seen.borrow();
    assert_eq!(hashes.first().map(String::as_str), Some(DUMMY_HASH));
    assert_eq!(hashes.get(1), Some(&alice_hash));
    Ok(())
}


#[test]
fn dummy_hash_uses_the_production_parameters() -> TestResult {
    assert!(DUMMY_HASH.contains(&format!("m={ARGON2_MEMORY_KIB},t={ARGON2_ITERATIONS},p={ARGON2_PARALLELISM}")));
    assert!(DUMMY_HASH.starts_with("$argon2id$"));
    assert!(verify_password("dummy password for constant work", DUMMY_HASH)?);
    Ok(())
}


fn failing_verify(_password: &str, _stored: &str) -> Result<bool, AuthError> {
    Err(AuthError::Decrypt)
}


#[test]
fn verification_failure_is_reported_for_unknown_users() -> TestResult {
    let fixture = fixture();
    let mut state = State::default();
    let ctx = Context {
        verify: &failing_verify,
        ..context(&fixture)
    };
    assert!(matches!(
        login(&mut state, &ctx, at(1)?, &request("nobody", GOOD_PASSWORD, None, SOURCE)),
        Err(AuthError::Decrypt)
    ));
    Ok(())
}


#[test]
fn custom_privileged_role_requires_mfa_without_the_administrator_name() -> TestResult {
    let mut fixture = fixture();
    fixture.catalog = load_catalog(r#"[{"name":"ops","permissions":["config.manage"]},{"name":"viewer","permissions":["events.read"]}]"#.as_bytes())?;
    let (mut state, admin) = with_user(&fixture, "olga", &["ops"])?;
    let ctx = context(&fixture);
    assert!(matches!(
        login(&mut state, &ctx, at(1)?, &request("olga", GOOD_PASSWORD, None, SOURCE)),
        Err(AuthError::MfaEnrolmentRequired)
    ));
    create_account(
        &mut state,
        &ctx,
        at(1)?,
        &admin,
        "vera",
        &SecretString::from(GOOD_PASSWORD),
        roles(&["viewer"]),
    )?;
    login(&mut state, &ctx, at(PLUS_TWO)?, &request("vera", GOOD_PASSWORD, None, SOURCE))?;
    Ok(())
}


#[test]
fn unknown_usernames_are_audited_as_a_pseudonym() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let typed = "TypedPassword!9";
    (0..ACCOUNT_MAX_FAILURES).for_each(|_| {
        assert!(login(
            &mut state,
            &ctx,
            at(1).unwrap_or(OffsetDateTime::UNIX_EPOCH),
            &request(typed, GOOD_PASSWORD, None, SOURCE)
        )
        .is_err());
    });
    let text = audit_text(&fixture)?;
    assert!(!text.contains(typed));
    let digest = HEXLOWER.encode(&Sha256::digest(typed.as_bytes()));
    let prefix: String = digest.chars().take(PSEUDONYM_CHARS).collect();
    assert!(text.contains(&format!("unknown:{prefix}")));
    assert!(text.contains("auth.lockout"));
    Ok(())
}


#[test]
fn every_failed_operation_is_audited() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    assert!(matches!(
        change_roles(&mut state, &ctx, at(1)?, &admin, "alice", roles(&["ghost"])),
        Err(AuthError::UnknownRole(_))
    ));
    assert!(matches!(
        change_roles(&mut state, &ctx, at(1)?, &admin, "ghost", roles(&[])),
        Err(AuthError::NoSuchAccount)
    ));
    assert!(matches!(
        enrol_totp(&mut state, &ctx, at(1)?, &admin, "ghost", None),
        Err(AuthError::NoSuchAccount)
    ));
    assert!(matches!(
        revoke_token(&mut state, &ctx, at(1)?, &admin, "no such token"),
        Err(AuthError::SessionInvalid)
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(1)?, &admin, "alice", &SecretString::from(GOOD_PASSWORD), roles(&[])),
        Err(AuthError::AccountExists)
    ));
    let text = audit_text(&fixture)?;
    ["authz.role.change", "auth.mfa.enrol", "auth.account.create"].iter().for_each(|action| {
        let failures = text
            .lines()
            .filter(|line| line.contains(action) && line.contains("\"outcome\":\"failure\""))
            .count();
        assert!(failures >= 1, "no failure record for {action}");
    });
    assert!(text
        .lines()
        .any(|line| line.contains("auth.session.revoke\"") && line.contains("\"outcome\":\"denied\"")));
    assert!(!text.contains("\"target\":\"ghost\""));
    Ok(())
}


#[test]
fn unauthorised_callers_are_denied_and_audited() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let good = SecretString::from(GOOD_PASSWORD);
    create_account(&mut state, &ctx, at(1)?, &admin, "bob", &good, roles(&[ROLE_READER]))?;
    let alice = login(&mut state, &ctx, at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    let bob = login(&mut state, &ctx, at(1)?, &request("bob", GOOD_PASSWORD, None, SOURCE))?;
    let token = alice.expose_secret();
    assert!(matches!(
        create_account(&mut state, &ctx, at(PLUS_TWO)?, token, "eve", &good, roles(&[ROLE_ADMINISTRATOR])),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        change_roles(&mut state, &ctx, at(PLUS_TWO)?, token, "alice", roles(&[ROLE_ADMINISTRATOR])),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        enrol_totp(&mut state, &ctx, at(PLUS_TWO)?, token, "bob", None),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        revoke_token(&mut state, &ctx, at(PLUS_TWO)?, token, bob.expose_secret()),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        revoke_token(&mut state, &ctx, at(PLUS_TWO)?, token, "unknown token"),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        revoke_all_sessions(&mut state, &ctx, at(PLUS_TWO)?, token, "bob"),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(PLUS_TWO)?, "bogus", "eve", &good, roles(&[])),
        Err(AuthError::SessionInvalid)
    ));
    assert!(!state.accounts.contains_key("eve"));
    assert_eq!(
        state.accounts.get("alice").map(|account| account.roles.clone()),
        Some(roles(&[ROLE_READER]))
    );
    let text = audit_text(&fixture)?;
    assert!(text.contains("anonymous"));
    assert!(text.lines().filter(|line| line.contains("\"outcome\":\"denied\"")).count() >= PERMISSION_DENIALS);
    revoke_token(&mut state, &ctx, at(PLUS_THREE)?, token, token)?;
    assert!(matches!(
        authorize(&mut state, &fixture.catalog, token, at(PLUS_FOUR)?, PERMISSION_EVENTS_READ),
        Err(AuthError::SessionInvalid)
    ));
    let second = login(&mut state, &ctx, at(PLUS_FIVE)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    assert_eq!(revoke_all_sessions(&mut state, &ctx, at(PLUS_SIX)?, second.expose_secret(), "alice")?, 1);
    Ok(())
}


#[test]
fn re_enrolment_needs_the_current_code_or_the_manage_permission() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let alice = login(&mut state, &ctx, at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    let token = alice.expose_secret();
    let first = enrol_totp(&mut state, &ctx, at(1)?, token, "alice", None)?;
    assert!(matches!(
        enrol_totp(&mut state, &ctx, at(PLUS_TWO)?, token, "alice", None),
        Err(AuthError::MfaRequired)
    ));
    let wrong = SecretString::from("000000");
    assert!(matches!(
        enrol_totp(&mut state, &ctx, at(PLUS_TWO)?, token, "alice", Some(&wrong)),
        Err(AuthError::MfaInvalid)
    ));
    let code = SecretString::from(current_code(&first.secret, PLUS_TWO)?);
    let second = enrol_totp(&mut state, &ctx, at(PLUS_TWO)?, token, "alice", Some(&code))?;
    assert_ne!(first.secret.expose_secret(), second.secret.expose_secret());
    let third = enrol_totp(&mut state, &ctx, at(PLUS_THREE)?, &admin, "alice", None)?;
    assert_ne!(second.secret.expose_secret(), third.secret.expose_secret());
    Ok(())
}


#[test]
fn bootstrap_is_possible_only_on_an_empty_store() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let result = bootstrap_administrator(&mut state, &context(&fixture), at(1)?, "mallory", &SecretString::from(GOOD_PASSWORD));
    assert!(matches!(result, Err(AuthError::AlreadyBootstrapped)));
    assert!(!state.accounts.contains_key("mallory"));
    assert!(audit_text(&fixture)?.contains("\"outcome\":\"failure\""));
    Ok(())
}


#[test]
fn administrator_needs_enrolment_then_totp() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    let ctx = context(&fixture);
    assert!(matches!(
        login(&mut state, &ctx, at(1)?, &request("root", GOOD_PASSWORD, None, SOURCE)),
        Err(AuthError::MfaEnrolmentRequired)
    ));
    let enrolment = enrol_totp(&mut state, &ctx, at(PLUS_TWO)?, &admin, "root", None)?;
    assert!(matches!(
        login(&mut state, &ctx, at(PLUS_THREE)?, &request("root", GOOD_PASSWORD, None, SOURCE)),
        Err(AuthError::MfaRequired)
    ));
    let wrong = login(&mut state, &ctx, at(PLUS_FOUR)?, &request("root", GOOD_PASSWORD, Some("000000"), SOURCE));
    assert!(matches!(wrong, Err(AuthError::MfaInvalid)));
    let code = current_code(&enrolment.secret, PLUS_FIVE)?;
    let token = login(&mut state, &ctx, at(PLUS_FIVE)?, &request("root", GOOD_PASSWORD, Some(&code), SOURCE))?;
    assert_eq!(
        authorize(
            &mut state,
            &fixture.catalog,
            token.expose_secret(),
            at(PLUS_SIX)?,
            PERMISSION_RESPONSE_EXECUTE
        )?,
        "root"
    );
    let replay = login(&mut state, &ctx, at(PLUS_SEVEN)?, &request("root", GOOD_PASSWORD, Some(&code), SOURCE));
    assert!(matches!(replay, Err(AuthError::MfaInvalid)));
    let text = audit_text(&fixture)?;
    assert!(text.contains("mfa_not_enrolled") && text.contains("mfa_missing") && text.contains("mfa_invalid"));
    assert!(text.contains("auth.mfa.enrol"));
    assert!(!text.contains(&code) && !text.contains(enrolment.secret.expose_secret()));
    Ok(())
}


#[test]
fn clock_skew_beyond_the_window_is_refused() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    let ctx = context(&fixture);
    let enrolment = enrol_totp(&mut state, &ctx, at(0)?, &admin, "root", None)?;
    let stale = current_code(&enrolment.secret, -STEP_SKEW_SECONDS)?;
    let result = login(&mut state, &ctx, at(1)?, &request("root", GOOD_PASSWORD, Some(&stale), SOURCE));
    assert!(matches!(result, Err(AuthError::MfaInvalid)));
    Ok(())
}


#[test]
fn backup_codes_log_in_once() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    let ctx = context(&fixture);
    let enrolment = enrol_totp(&mut state, &ctx, at(0)?, &admin, "root", None)?;
    let backup = enrolment.backup_codes.first().ok_or("no backup code")?.expose_secret();
    login(&mut state, &ctx, at(1)?, &request("root", GOOD_PASSWORD, Some(backup), SOURCE))?;
    let again = login(&mut state, &ctx, at(PLUS_TWO)?, &request("root", GOOD_PASSWORD, Some(backup), SOURCE));
    assert!(matches!(again, Err(AuthError::MfaInvalid)));
    Ok(())
}


#[test]
fn enrolled_non_administrators_must_use_their_second_factor() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_ANALYST])?;
    let ctx = context(&fixture);
    let enrolment = enrol_totp(&mut state, &ctx, at(0)?, &admin, "alice", None)?;
    assert!(matches!(
        login(&mut state, &ctx, at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE)),
        Err(AuthError::MfaRequired)
    ));
    let code = current_code(&enrolment.secret, PLUS_TWO)?;
    login(&mut state, &ctx, at(PLUS_TWO)?, &request("alice", GOOD_PASSWORD, Some(&code), SOURCE))?;
    Ok(())
}


#[test]
fn stored_totp_secret_is_encrypted() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    let enrolment = enrol_totp(&mut state, &context(&fixture), at(0)?, &admin, "root", None)?;
    let mut stored = Vec::new();
    save_accounts(&mut stored, &state.accounts)?;
    let text = String::from_utf8(stored)?;
    let secret = enrolment.secret.expose_secret();
    assert!(!text.contains(secret));
    assert!(!text.contains(GOOD_PASSWORD));
    assert!(enrolment.backup_codes.iter().all(|code| !text.contains(code.expose_secret())));
    Ok(())
}


#[test]
fn enrolment_failures_are_reported() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    assert!(matches!(
        enrol_totp(&mut state, &context(&fixture), at(0)?, &admin, "ghost", None),
        Err(AuthError::NoSuchAccount)
    ));
    assert!(matches!(
        enrol_totp(&mut state, &context_with(&fixture, fail_on_secret), at(0)?, &admin, "root", None),
        Err(AuthError::Random(_))
    ));
    assert!(matches!(
        enrol_totp(&mut state, &context_with(&fixture, fail_on_backup), at(0)?, &admin, "root", None),
        Err(AuthError::Random(_))
    ));
    assert!(matches!(
        enrol_totp(&mut state, &context_with(&fixture, fail_on_nonce), at(0)?, &admin, "root", None),
        Err(AuthError::Random(_))
    ));
    let bad_key = Fixture {
        key: SecretSlice::from(vec![KEY_FILL]),
        ..fixture_over(Vec::new())
    };
    assert!(matches!(
        enrol_totp(&mut state, &context(&bad_key), at(0)?, &admin, "root", None),
        Err(AuthError::InvalidKey)
    ));
    Ok(())
}


#[test]
fn corrupted_totp_secret_is_reported() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    let ctx = context(&fixture);
    enrol_totp(&mut state, &ctx, at(0)?, &admin, "root", None)?;
    state
        .accounts
        .get_mut("root")
        .and_then(|account| account.totp.as_mut())
        .ok_or("no totp")?
        .encrypted_secret = "AAAA".to_owned();
    let result = login(&mut state, &ctx, at(1)?, &request("root", GOOD_PASSWORD, Some("123456"), SOURCE));
    assert!(matches!(result, Err(AuthError::Decrypt)));
    Ok(())
}


#[test]
fn repeated_failures_lock_the_account_and_are_audited() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    (0..ACCOUNT_MAX_FAILURES).try_for_each(|attempt| {
        let result = login(
            &mut state,
            &ctx,
            at(1)?,
            &request("alice", "wrong password here", None, &format!("10.0.1.{attempt}")),
        );
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let locked = login(&mut state, &ctx, at(PLUS_TWO)?, &request("alice", GOOD_PASSWORD, None, SOURCE));
    assert!(matches!(locked, Err(AuthError::Locked { until }) if until == at(1 + LOCKOUT_SECONDS).unwrap_or(until)));
    let text = audit_text(&fixture)?;
    assert!(text.contains("auth.lockout") && text.contains("\"scope\":\"account\""));
    assert!(text.contains("\"reason\":\"locked\""));
    login(&mut state, &ctx, at(1 + LOCKOUT_SECONDS)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    Ok(())
}


#[test]
fn brute_force_from_one_source_is_locked_out_by_source() -> TestResult {
    let fixture = fixture();
    let mut state = State::default();
    let ctx = context(&fixture);
    (0..SOURCE_MAX_FAILURES).try_for_each(|attempt| {
        let user = format!("user{attempt}");
        let result = login(&mut state, &ctx, at(1)?, &request(&user, "wrong password here", None, SOURCE));
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let blocked = login(&mut state, &ctx, at(PLUS_TWO)?, &request("fresh", GOOD_PASSWORD, None, SOURCE));
    assert!(matches!(blocked, Err(AuthError::Locked { .. })));
    assert!(audit_text(&fixture)?.contains("\"scope\":\"source\""));
    Ok(())
}


#[test]
fn success_resets_the_failure_counter() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    (0..ACCOUNT_MAX_FAILURES - 1).try_for_each(|_| {
        login(&mut state, &ctx, at(1)?, &request("alice", "wrong password here", None, SOURCE))
            .map(|_| ())
            .or(Ok::<(), Box<dyn std::error::Error>>(()))
    })?;
    login(&mut state, &ctx, at(PLUS_TWO)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    (0..ACCOUNT_MAX_FAILURES - 1).try_for_each(|_| {
        login(&mut state, &ctx, at(PLUS_THREE)?, &request("alice", "wrong password here", None, SOURCE))
            .map(|_| ())
            .or(Ok::<(), Box<dyn std::error::Error>>(()))
    })?;
    login(&mut state, &ctx, at(PLUS_FOUR)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    Ok(())
}


#[test]
fn role_change_revokes_sessions_and_is_audited() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let token = login(&mut state, &ctx, at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    change_roles(&mut state, &ctx, at(PLUS_TWO)?, &admin, "alice", roles(&[ROLE_ANALYST]))?;
    assert!(matches!(
        authorize(
            &mut state,
            &fixture.catalog,
            token.expose_secret(),
            at(PLUS_THREE)?,
            PERMISSION_EVENTS_READ
        ),
        Err(AuthError::SessionInvalid)
    ));
    let text = audit_text(&fixture)?;
    assert!(text.contains("authz.role.change") && text.contains("\"before\":\"reader\"") && text.contains("\"after\":\"analyst\""));
    assert!(matches!(
        change_roles(&mut state, &ctx, at(PLUS_FOUR)?, &admin, "alice", roles(&["ghost"])),
        Err(AuthError::UnknownRole(_))
    ));
    assert!(matches!(
        change_roles(&mut state, &ctx, at(PLUS_FOUR)?, &admin, "ghost", roles(&[])),
        Err(AuthError::NoSuchAccount)
    ));
    Ok(())
}


#[test]
fn revocation_is_audited() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let ctx = context(&fixture);
    let first = login(&mut state, &ctx, at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    let second = login(&mut state, &ctx, at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    revoke_token(&mut state, &ctx, at(PLUS_TWO)?, &admin, first.expose_secret())?;
    assert!(matches!(
        revoke_token(&mut state, &ctx, at(PLUS_TWO)?, &admin, first.expose_secret()),
        Err(AuthError::SessionInvalid)
    ));
    assert_eq!(revoke_all_sessions(&mut state, &ctx, at(PLUS_THREE)?, &admin, "alice")?, 1);
    assert!(matches!(
        authorize(
            &mut state,
            &fixture.catalog,
            second.expose_secret(),
            at(PLUS_FOUR)?,
            PERMISSION_EVENTS_READ
        ),
        Err(AuthError::SessionInvalid)
    ));
    let text = audit_text(&fixture)?;
    assert!(text.contains("auth.session.revoke\"") && text.contains("auth.session.revoke_all"));
    assert!(!text.contains(first.expose_secret()) && !text.contains(second.expose_secret()));
    Ok(())
}


#[test]
fn sessions_of_deleted_accounts_are_invalid() -> TestResult {
    let fixture = fixture();
    let (mut state, _) = with_user(&fixture, "alice", &[ROLE_READER])?;
    let token = login(&mut state, &context(&fixture), at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    state.accounts.clear();
    assert!(matches!(
        authorize(&mut state, &fixture.catalog, token.expose_secret(), at(PLUS_TWO)?, PERMISSION_EVENTS_READ),
        Err(AuthError::SessionInvalid)
    ));
    Ok(())
}


#[test]
fn secrets_never_reach_debug_or_display_output() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    let ctx = context(&fixture);
    let enrolment = enrol_totp(&mut state, &ctx, at(0)?, &admin, "root", None)?;
    let code = current_code(&enrolment.secret, 1)?;
    let login_request = request("root", GOOD_PASSWORD, Some(&code), SOURCE);
    let token = login(&mut state, &ctx, at(1)?, &login_request)?;
    let rendered = format!("{login_request:?} {enrolment:?} {state:?} {token:?} {:?}", fixture.key);
    [GOOD_PASSWORD, enrolment.secret.expose_secret(), token.expose_secret(), &code]
        .iter()
        .for_each(|secret| assert!(!rendered.contains(secret), "leaked {secret}"));
    assert!(enrolment.backup_codes.iter().all(|backup| !rendered.contains(backup.expose_secret())));
    let errors = [
        AuthError::InvalidCredentials,
        AuthError::MfaInvalid,
        AuthError::Decrypt,
        AuthError::Locked { until: at(0)? },
    ];
    errors
        .iter()
        .for_each(|error| assert!(!format!("{error} {error:?}").contains(GOOD_PASSWORD)));
    assert!(!audit_text(&fixture)?.contains(&code));
    Ok(())
}


#[test]
fn audit_failures_stop_every_operation() -> TestResult {
    let healthy = fixture();
    let (mut state, admin) = with_user(&healthy, "alice", &[ROLE_READER])?;
    let broken = fixture_over(FailingWriter {
        fail_write: true,
        fail_flush: false,
    });
    let ctx = context(&broken);
    let good = SecretString::from(GOOD_PASSWORD);
    assert!(matches!(
        create_account(&mut state, &ctx, at(0)?, &admin, "bob", &good, roles(&[])),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(0)?, &admin, "", &good, roles(&[])),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        create_account(&mut state, &ctx, at(0)?, "bogus", "carol", &good, roles(&[])),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        change_roles(&mut state, &ctx, at(0)?, &admin, "alice", roles(&[])),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        revoke_all_sessions(&mut state, &ctx, at(0)?, &admin, "alice"),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        login(&mut state, &ctx, at(0)?, &request("alice", GOOD_PASSWORD, None, SOURCE)),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        login(&mut state, &ctx, at(0)?, &request("alice", SECOND_PASSWORD, None, SOURCE)),
        Err(AuthError::Audit(_))
    ));
    let token = login(&mut state, &context(&healthy), at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE))?;
    assert!(matches!(
        revoke_token(&mut state, &ctx, at(1)?, &admin, token.expose_secret()),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        enrol_totp(&mut state, &ctx, at(0)?, &admin, "alice", None),
        Err(AuthError::Audit(_))
    ));
    assert!(matches!(
        enrol_totp(&mut state, &ctx, at(0)?, &admin, "ghost", None),
        Err(AuthError::Audit(_))
    ));
    let mut empty = State::default();
    assert!(matches!(
        bootstrap_administrator(&mut empty, &ctx, at(0)?, "root", &good),
        Err(AuthError::Audit(_))
    ));
    Ok(())
}


#[test]
fn bootstrap_enrolment_audit_failure_is_reported() -> TestResult {
    let selective = fixture_over(SelectiveWriter { needle: "auth.mfa.enrol" });
    let mut state = State::default();
    let result = bootstrap_administrator(&mut state, &context(&selective), at(0)?, "root", &SecretString::from(GOOD_PASSWORD));
    assert!(matches!(result, Err(AuthError::Audit(_))));
    Ok(())
}


#[test]
fn lockout_audit_failure_is_reported() -> TestResult {
    let healthy = fixture();
    let (mut state, _) = with_user(&healthy, "alice", &[ROLE_READER])?;
    let broken = fixture_over(FailingWriter {
        fail_write: true,
        fail_flush: false,
    });
    let ctx = context(&broken);
    let result = (0..ACCOUNT_MAX_FAILURES)
        .map(|_| {
            login(
                &mut state,
                &ctx,
                at(1).unwrap_or(OffsetDateTime::UNIX_EPOCH),
                &request("alice", SECOND_PASSWORD, None, SOURCE),
            )
        })
        .collect::<Vec<_>>();
    assert!(result.iter().all(|outcome| matches!(outcome, Err(AuthError::Audit(_)))));
    Ok(())
}


struct SelectiveWriter {
    needle: &'static str,
}


impl std::io::Write for SelectiveWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if String::from_utf8_lossy(buffer).contains(self.needle) {
            Err(std::io::Error::other("injected selective failure"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn fail_on_token(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    if buffer.len() == TOKEN_LENGTH {
        Err(getrandom::Error::UNSUPPORTED)
    } else {
        os_random(buffer)
    }
}


#[test]
fn lockout_record_failure_is_reported() -> TestResult {
    let healthy = fixture();
    let (mut state, _) = with_user(&healthy, "alice", &[ROLE_READER])?;
    let selective = fixture_over(SelectiveWriter { needle: "auth.lockout" });
    let ctx = context(&selective);
    let moment = at(1)?;
    let outcomes = (0..ACCOUNT_MAX_FAILURES)
        .map(|_| login(&mut state, &ctx, moment, &request("alice", SECOND_PASSWORD, None, SOURCE)))
        .collect::<Vec<_>>();
    assert!(matches!(outcomes.last(), Some(Err(AuthError::Audit(_)))));
    Ok(())
}


#[test]
fn locked_login_audit_failure_and_token_failure_are_reported() -> TestResult {
    let healthy = fixture();
    let (mut state, _) = with_user(&healthy, "alice", &[ROLE_READER])?;
    let token_failure = login(
        &mut state,
        &context_with(&healthy, fail_on_token),
        at(1)?,
        &request("alice", GOOD_PASSWORD, None, SOURCE),
    );
    assert!(matches!(token_failure, Err(AuthError::Random(_))));
    (0..ACCOUNT_MAX_FAILURES).for_each(|_| {
        login(
            &mut state,
            &context(&healthy),
            at(1).unwrap_or(OffsetDateTime::UNIX_EPOCH),
            &request("alice", SECOND_PASSWORD, None, SOURCE),
        )
        .map_or_else(|_| (), |_| ());
    });
    let broken = fixture_over(FailingWriter {
        fail_write: true,
        fail_flush: false,
    });
    let locked = login(&mut state, &context(&broken), at(1)?, &request("alice", GOOD_PASSWORD, None, SOURCE));
    assert!(matches!(locked, Err(AuthError::Audit(_))));
    Ok(())
}


#[test]
fn corrupted_password_hash_and_clock_before_epoch_are_reported() -> TestResult {
    let fixture = fixture();
    let (mut state, admin) = with_user(&fixture, "root", &[ROLE_ADMINISTRATOR])?;
    let ctx = context(&fixture);
    enrol_totp(&mut state, &ctx, at(0)?, &admin, "root", None)?;
    let before_epoch = OffsetDateTime::from_unix_timestamp(-1)?;
    let early = login(&mut state, &ctx, before_epoch, &request("root", GOOD_PASSWORD, Some("123456"), SOURCE));
    assert!(matches!(early, Err(AuthError::ClockBeforeEpoch)));
    state.accounts.get_mut("root").ok_or("no account")?.password_hash = "garbage".to_owned();
    let corrupted = login(&mut state, &ctx, at(1)?, &request("root", GOOD_PASSWORD, None, SOURCE));
    assert!(matches!(corrupted, Err(AuthError::Hash(_))));
    Ok(())
}
