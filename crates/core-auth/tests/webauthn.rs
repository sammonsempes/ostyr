#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/soft.rs"]
mod soft;
#[path = "support/types.rs"]
mod types;


use core_audit::log::{genesis_log, AuditLog};
use core_audit::verify::verify;
use core_auth::cli::{apply_command, apply_command_with, run, totp_now};
use core_auth::error::AuthError;
use core_auth::limiter::{ACCOUNT_MAX_FAILURES, SOURCE_MAX_FAILURES};
use core_auth::password::verify_password;
use core_auth::random::os_random;
use core_auth::rbac::{builtin_catalog, load_catalog, webauthn_required, ROLE_ADMINISTRATOR, ROLE_READER};
use core_auth::service::{bootstrap_administrator, create_account, enrol_totp, login, Context, LoginRequest, State};
use core_auth::session::TOKEN_BYTES;
use core_auth::store::{
    load_accounts, load_accounts_file, load_store, load_store_file, save_accounts, save_accounts_file, save_store, save_store_file, STORE_VERSION,
};
use core_auth::totp::{code_for_step, TOTP_STEP_SECONDS};
use core_auth::types::{CompromisedSet, RandomFn, RoleCatalog, RoleSet, StoreKey};
use core_auth::webauthn::{
    build_webauthn, check_name, list_credentials, parse_webauthn_config, passkey_login_start, register_finish, register_start, remove_credential,
    rename_credential, user_uuid, webauthn_login_finish, webauthn_login_start, Assertion, RegistrationRequest, WebauthnConfig, CHALLENGE_ID_BYTES,
    CHALLENGE_MAX, CHALLENGE_SECONDS, NAME_MAX_CHARS,
};
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use failing_writer::FailingWriter;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde_json::{json, Value};
use soft::{assert_with, discoverable_assertion, edited, origin, register_with, set_at, soft_passkey, SoftResult};
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::Webauthn;


const BASE_TIME: i64 = 1_700_000_010;


const GOOD_PASSWORD: &str = "correct horse battery";


const ADMIN_PASSWORD: &str = "another long passphrase";


const SOURCE: &str = "10.0.0.7";


const OTHER_SOURCE: &str = "10.0.0.8";


const ORIGIN: &str = "https://ostyr.example";


const RP_ID: &str = "ostyr.example";


const KEY_FILL: u8 = 9;


const KEY_LENGTH: usize = 32;


const PLUS_ONE: i64 = 1;


const PLUS_TWO: i64 = 2;


const PLUS_THREE: i64 = 3;


const LATE: i64 = CHALLENGE_SECONDS + 1;


const HIGH_COUNTER: u64 = 1000;


struct Fixture<Output> {
    audit: AuditLog<Output>,
    key: StoreKey,
    compromised: CompromisedSet,
    catalog: RoleCatalog,
    webauthn: Webauthn,
}


fn config(rp_id: &str, rp_origin: &str) -> WebauthnConfig {
    WebauthnConfig {
        rp_id: rp_id.to_owned(),
        rp_origin: rp_origin.to_owned(),
        rp_name: "Ostyr".to_owned(),
    }
}


fn webauthn_for(rp_id: &str, rp_origin: &str) -> SoftResult<Webauthn> {
    Ok(build_webauthn(&config(rp_id, rp_origin))?)
}


fn fixture_over<Output: std::io::Write>(output: Output, catalog: RoleCatalog) -> SoftResult<Fixture<Output>> {
    Ok(Fixture {
        audit: genesis_log(output),
        key: SecretSlice::from(vec![KEY_FILL; KEY_LENGTH]),
        compromised: CompromisedSet::new(),
        catalog,
        webauthn: webauthn_for(RP_ID, ORIGIN)?,
    })
}


fn fixture() -> SoftResult<Fixture<Vec<u8>>> {
    fixture_over(Vec::new(), builtin_catalog())
}


fn strict_catalog() -> SoftResult<RoleCatalog> {
    let text = r#"[{"name":"breakglass","permissions":["users.manage","policy.webauthn_required"]}]"#;
    Ok(load_catalog(text.as_bytes())?)
}


fn context<'a, Output>(fixture: &'a Fixture<Output>) -> Context<'a, Output> {
    context_with(fixture, os_random, &verify_password)
}


fn context_with<'a, Output>(
    fixture: &'a Fixture<Output>,
    random: RandomFn,
    verify: &'a dyn Fn(&str, &str) -> Result<bool, AuthError>,
) -> Context<'a, Output> {
    Context {
        audit: &fixture.audit,
        random,
        verify,
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


fn request(user: &str, password: &str, source: &str) -> LoginRequest {
    LoginRequest {
        username: user.to_owned(),
        password: SecretString::from(password),
        totp_code: None,
        source: source.to_owned(),
    }
}


fn audit_text(fixture: &Fixture<Vec<u8>>) -> SoftResult<String> {
    let state = fixture.audit.state.lock().map_err(|_| "poisoned")?;
    verify(state.writer.as_slice(), None)?;
    Ok(String::from_utf8(state.writer.clone())?)
}


fn fail_on_length(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    if buffer.len() == TOKEN_BYTES {
        Err(getrandom::Error::UNSUPPORTED)
    } else {
        os_random(buffer)
    }
}


fn fail_on_challenge(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    if buffer.len() == CHALLENGE_ID_BYTES {
        Err(getrandom::Error::UNSUPPORTED)
    } else {
        os_random(buffer)
    }
}


fn failing_verify(_password: &str, _hash: &str) -> Result<bool, AuthError> {
    Err(AuthError::InvalidCredentials)
}


fn broken_fixture() -> SoftResult<Fixture<FailingWriter>> {
    fixture_over(
        FailingWriter {
            fail_write: true,
            fail_flush: false,
        },
        builtin_catalog(),
    )
}


fn current_code(secret: &SecretString) -> SoftResult<String> {
    let raw = BASE32_NOPAD.decode(secret.expose_secret().as_bytes())?;
    Ok(code_for_step(&raw, u64::try_from(BASE_TIME)? / TOTP_STEP_SECONDS))
}


struct World {
    state: State,
    admin: String,
    admin_secret: SecretString,
}


fn world(fixture: &Fixture<Vec<u8>>) -> SoftResult<World> {
    let ctx = context(fixture);
    let mut state = State::default();
    let enrolment = bootstrap_administrator(&mut state, &ctx, at(0)?, "admin", &SecretString::from(ADMIN_PASSWORD))?;
    let mut with_code = request("admin", ADMIN_PASSWORD, "10.9.9.9");
    with_code.totp_code = Some(SecretString::from(current_code(&enrolment.secret)?));
    let token = login(&mut state, &ctx, at(0)?, &with_code)?;
    let start = at(0)?;
    ["alice", "bob"].iter().try_for_each(|name| {
        create_account(
            &mut state,
            &ctx,
            start,
            token.expose_secret(),
            name,
            &SecretString::from(GOOD_PASSWORD),
            roles(&[ROLE_READER]),
        )
    })?;
    Ok(World {
        state,
        admin: token.expose_secret().to_owned(),
        admin_secret: enrolment.secret,
    })
}


fn token_for(fixture: &Fixture<Vec<u8>>, world: &mut World, user: &str, offset: i64) -> SoftResult<String> {
    let ctx = context(fixture);
    let token = login(&mut world.state, &ctx, at(offset)?, &request(user, GOOD_PASSWORD, "10.9.9.1"))?;
    Ok(token.expose_secret().to_owned())
}


fn register(
    fixture: &Fixture<Vec<u8>>,
    state: &mut State,
    soft: &mut SoftPasskey,
    (token, user, name): (&str, &str, &str),
    offset: i64,
) -> SoftResult<String> {
    let ctx = context(fixture);
    let (challenge, options) = register_start(state, &ctx, &fixture.webauthn, at(offset)?, token, user)?;
    let response = register_with(soft, &origin(ORIGIN)?, options)?;
    let finished = RegistrationRequest {
        username: user.to_owned(),
        challenge_id: challenge,
        name: name.to_owned(),
        response,
    };
    Ok(register_finish(state, &ctx, &fixture.webauthn, at(offset)?, token, &finished)?)
}


fn second_factor(
    fixture: &Fixture<Vec<u8>>,
    state: &mut State,
    soft: &mut SoftPasskey,
    (user, source): (&str, &str),
    offset: i64,
) -> SoftResult<String> {
    let ctx = context(fixture);
    let (challenge, options) = webauthn_login_start(state, &ctx, &fixture.webauthn, at(offset)?, &request(user, GOOD_PASSWORD, source))?;
    let response = assert_with(soft, &origin(ORIGIN)?, options)?;
    let assertion = Assertion {
        challenge_id: challenge,
        response,
        source: source.to_owned(),
    };
    Ok(webauthn_login_finish(state, &ctx, &fixture.webauthn, at(offset)?, &assertion)?
        .expose_secret()
        .to_owned())
}


fn passkey_login(
    fixture: &Fixture<Vec<u8>>,
    state: &mut State,
    soft: &mut SoftPasskey,
    (credential, user, source): (&str, &str, &str),
    offset: i64,
) -> SoftResult<String> {
    let ctx = context(fixture);
    let (challenge, options) = passkey_login_start(state, &ctx, &fixture.webauthn, at(offset)?, source)?;
    let handle = BASE64URL_NOPAD.encode(user_uuid(user).as_bytes());
    let response = discoverable_assertion(soft, &origin(ORIGIN)?, options, (credential, Some(&handle)))?;
    let assertion = Assertion {
        challenge_id: challenge,
        response,
        source: source.to_owned(),
    };
    Ok(webauthn_login_finish(state, &ctx, &fixture.webauthn, at(offset)?, &assertion)?
        .expose_secret()
        .to_owned())
}


fn invalid(result: Result<impl std::fmt::Debug, AuthError>) -> bool {
    matches!(result, Err(AuthError::InvalidCredentials))
}


#[test]
fn configuration_is_parsed_strictly_and_checked() -> TestResult {
    let parsed = parse_webauthn_config(
        "rp_id: ostyr.example\nrp_origin: https://ostyr.example\nrp_name: Ostyr\n",
        "webauthn.yaml",
    )?;
    assert_eq!(parsed.rp_id, RP_ID);
    build_webauthn(&parsed)?;
    assert!(matches!(
        parse_webauthn_config("rp_id: a\nrp_origin: b\nrp_name: c\nextra: d\n", "webauthn.yaml"),
        Err(AuthError::Config(_))
    ));
    assert!(matches!(build_webauthn(&config(RP_ID, "not a url")), Err(AuthError::InvalidUrl(_))));
    assert!(matches!(build_webauthn(&config("other.example", ORIGIN)), Err(AuthError::Webauthn(_))));
    Ok(())
}


#[test]
fn a_user_registers_lists_renames_and_removes_credentials() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    let first = register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let second = register(&fx, &mut world.state, &mut soft, (&alice, "alice", "phone"), PLUS_TWO)?;
    assert_ne!(first, second);
    let listed = list_credentials(&mut world.state, &fx.catalog, at(PLUS_TWO)?, &alice, "alice")?;
    assert_eq!(listed.iter().map(|info| info.name.as_str()).collect::<Vec<_>>(), ["laptop", "phone"]);
    assert!(listed
        .iter()
        .all(|info| info.last_used.is_none() && info.created_at == BASE_TIME + PLUS_TWO));
    let ctx = context(&fx);
    rename_credential(&mut world.state, &ctx, at(PLUS_THREE)?, &alice, ("alice", &first, "work laptop"))?;
    remove_credential(&mut world.state, &ctx, at(PLUS_THREE)?, &alice, ("alice", &second))?;
    let after = list_credentials(&mut world.state, &fx.catalog, at(PLUS_THREE)?, &alice, "alice")?;
    assert_eq!(after.iter().map(|info| info.name.as_str()).collect::<Vec<_>>(), ["work laptop"]);
    let text = audit_text(&fx)?;
    ["register_start", "webauthn.register\"", "webauthn.rename", "webauthn.remove"]
        .iter()
        .for_each(|needle| assert!(text.contains(needle), "{needle}"));
    Ok(())
}


#[test]
fn registration_and_management_obey_the_boundary() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let ctx = context(&fx);
    let mut soft = soft_passkey();
    assert!(matches!(
        register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "bob"),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, "no-such-token", "alice"),
        Err(AuthError::SessionInvalid)
    ));
    assert!(matches!(
        register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &world.admin, "nobody"),
        Err(AuthError::NoSuchAccount)
    ));
    let id = register(&fx, &mut world.state, &mut soft, (&world.admin.clone(), "bob", "managed"), PLUS_TWO)?;
    assert!(matches!(
        list_credentials(&mut world.state, &fx.catalog, at(PLUS_TWO)?, &alice, "bob"),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        rename_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &alice, ("bob", &id, "x")),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &alice, ("bob", &id)),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        rename_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("bob", "missing", "x")),
        Err(AuthError::UnknownCredential)
    ));
    assert!(matches!(
        rename_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("bob", &id, "")),
        Err(AuthError::InvalidCredentialName)
    ));
    assert!(matches!(
        remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("bob", "missing")),
        Err(AuthError::UnknownCredential)
    ));
    assert!(matches!(
        remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("alice", "missing")),
        Err(AuthError::UnknownCredential)
    ));
    assert!(matches!(
        remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("nobody", "missing")),
        Err(AuthError::NoSuchAccount)
    ));
    assert!(audit_text(&fx)?.contains("\"outcome\":\"denied\""));
    Ok(())
}


#[test]
fn credential_names_are_bounded() -> TestResult {
    assert!(check_name("laptop").is_ok());
    assert!(check_name(&"a".repeat(NAME_MAX_CHARS)).is_ok());
    assert!(check_name("").is_err());
    assert!(check_name(&"a".repeat(NAME_MAX_CHARS + 1)).is_err());
    assert!(check_name("bad\nname").is_err());
    Ok(())
}


#[test]
fn registration_challenges_are_single_use_bound_and_expire() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let ctx = context(&fx);
    let mut soft = soft_passkey();
    let page = origin(ORIGIN)?;
    let (challenge, options) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "alice")?;
    let response = register_with(&mut soft, &page, options)?;
    let build = |name: &str| RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: challenge.clone(),
        name: name.to_owned(),
        response: response.clone(),
    };
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &build("")),
        Err(AuthError::InvalidCredentialName)
    ));
    register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &build("first"))?;
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &build("again")),
        Err(AuthError::ChallengeInvalid)
    ));
    let (late, late_options) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "alice")?;
    let late_response = register_with(&mut soft, &page, late_options)?;
    let late_request = RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: late,
        name: "late".to_owned(),
        response: late_response,
    };
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO + LATE)?, &alice, &late_request),
        Err(AuthError::ChallengeExpired)
    ));
    let (bound, bound_options) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &world.admin, "alice")?;
    let bound_response = register_with(&mut soft, &page, bound_options)?;
    let bound_request = RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: bound,
        name: "bound".to_owned(),
        response: bound_response,
    };
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &bound_request),
        Err(AuthError::ChallengeInvalid)
    ));
    let (other_user, other_options) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &world.admin, "alice")?;
    let other_response = register_with(&mut soft, &page, other_options)?;
    let other_request = RegistrationRequest {
        username: "bob".to_owned(),
        challenge_id: other_user,
        name: "other".to_owned(),
        response: other_response,
    };
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &world.admin, &other_request),
        Err(AuthError::ChallengeInvalid)
    ));
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &other_request),
        Err(AuthError::PermissionDenied)
    ));
    let text = audit_text(&fx)?;
    assert!(text.contains("the WebAuthn challenge has expired"));
    Ok(())
}


#[test]
fn a_registration_challenge_cannot_finish_a_login() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    let credential = register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    let (challenge, _) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "alice")?;
    let (_, login_options) = passkey_login_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, SOURCE)?;
    let response = discoverable_assertion(&mut soft, &origin(ORIGIN)?, login_options, (&credential, None))?;
    let assertion = Assertion {
        challenge_id: challenge,
        response,
        source: SOURCE.to_owned(),
    };
    assert!(invalid(webauthn_login_finish(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_TWO)?,
        &assertion
    )));
    assert!(audit_text(&fx)?.contains("\"reason\":\"bad_challenge\""));
    Ok(())
}


#[test]
fn a_challenge_of_another_kind_cannot_finish_a_registration() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    let (second_factor_challenge, _) = webauthn_login_start(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_TWO)?,
        &request("alice", GOOD_PASSWORD, SOURCE),
    )?;
    let (_, options) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "alice")?;
    let response = register_with(&mut soft, &origin(ORIGIN)?, options)?;
    let wrong = RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: second_factor_challenge,
        name: "x".to_owned(),
        response,
    };
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &wrong),
        Err(AuthError::ChallengeInvalid)
    ));
    Ok(())
}


#[test]
fn a_wrong_origin_or_relying_party_id_is_refused() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let ctx = context(&fx);
    let mut soft = soft_passkey();
    let (challenge, options) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "alice")?;
    let response = register_with(&mut soft, &origin("https://evil.ostyr.example")?, options)?;
    let wrong_origin = RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: challenge,
        name: "evil".to_owned(),
        response,
    };
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &wrong_origin),
        Err(AuthError::Webauthn(_))
    ));
    let (challenge_b, options_b) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "alice")?;
    let response_b = register_with(&mut soft, &origin(ORIGIN)?, options_b)?;
    let other_id = webauthn_for("example", "https://example")?;
    let wrong_rp = RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: challenge_b,
        name: "rp".to_owned(),
        response: response_b,
    };
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &other_id, at(PLUS_TWO)?, &alice, &wrong_rp),
        Err(AuthError::Webauthn(_))
    ));
    assert!(world.state.credentials.values().all(Vec::is_empty));
    Ok(())
}


#[test]
fn a_credential_id_registered_elsewhere_is_refused() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let ctx = context(&fx);
    let mut soft = soft_passkey();
    let (challenge, options) = register_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, "alice")?;
    let response = register_with(&mut soft, &origin(ORIGIN)?, options)?;
    let finishing = RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: challenge,
        name: "laptop".to_owned(),
        response,
    };
    let mut rehearsal = world.state.clone();
    register_finish(&mut rehearsal, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &finishing)?;
    let copied = rehearsal.credentials.get("alice").cloned().ok_or("no credential")?;
    world.state.credentials.insert("bob".to_owned(), copied);
    assert!(matches!(
        register_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &alice, &finishing),
        Err(AuthError::CredentialExists)
    ));
    Ok(())
}


#[test]
fn a_second_factor_round_trip_logs_in_and_records_use() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let session = second_factor(&fx, &mut world.state, &mut soft, ("alice", SOURCE), PLUS_THREE)?;
    assert!(!session.is_empty());
    let listed = list_credentials(&mut world.state, &fx.catalog, at(PLUS_THREE)?, &session, "alice")?;
    assert_eq!(listed.first().and_then(|info| info.last_used), Some(BASE_TIME + PLUS_THREE));
    second_factor(&fx, &mut world.state, &mut soft, ("alice", SOURCE), PLUS_THREE)?;
    let text = audit_text(&fx)?;
    assert!(text.contains("\"method\":\"webauthn\""));
    assert!(text.contains("auth.webauthn.login_start"));
    Ok(())
}


#[test]
fn a_replayed_or_late_assertion_is_refused() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    let page = origin(ORIGIN)?;
    let (challenge, options) = webauthn_login_start(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, SOURCE),
    )?;
    let response = assert_with(&mut soft, &page, options)?;
    let assertion = Assertion {
        challenge_id: challenge,
        response,
        source: SOURCE.to_owned(),
    };
    webauthn_login_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_THREE)?, &assertion)?;
    assert!(invalid(webauthn_login_finish(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &assertion
    )));
    let (late, late_options) = webauthn_login_start(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, SOURCE),
    )?;
    let late_assertion = Assertion {
        challenge_id: late,
        response: assert_with(&mut soft, &page, late_options)?,
        source: SOURCE.to_owned(),
    };
    assert!(invalid(webauthn_login_finish(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE + LATE)?,
        &late_assertion
    )));
    let text = audit_text(&fx)?;
    assert!(text.contains("\"reason\":\"bad_challenge\""));
    assert!(text.contains("\"reason\":\"challenge_expired\""));
    Ok(())
}


#[test]
fn a_counter_that_goes_backwards_is_refused_and_audited() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    second_factor(&fx, &mut world.state, &mut soft, ("alice", SOURCE), PLUS_THREE)?;
    let stored = world
        .state
        .credentials
        .get("alice")
        .and_then(|list| list.first())
        .ok_or("no credential")?
        .clone();
    let raised = edited(&stored, "/passkey/cred/counter", json!(HIGH_COUNTER))?;
    world.state.credentials.insert("alice".to_owned(), vec![raised]);
    let outcome = second_factor(&fx, &mut world.state, &mut soft, ("alice", SOURCE), PLUS_THREE);
    assert!(outcome.is_err());
    let text = audit_text(&fx)?;
    assert!(text.contains("\"reason\":\"counter_regression\""));
    assert!(world
        .state
        .credentials
        .get("alice")
        .and_then(|list| list.first())
        .is_some_and(|credential| {
            serde_json::to_value(credential).is_ok_and(|value| value.pointer("/passkey/cred/counter") == Some(&json!(HIGH_COUNTER)))
        }));
    Ok(())
}


#[test]
fn the_credential_of_another_account_is_refused() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let bob = token_for(&fx, &mut world, "bob", PLUS_ONE)?;
    let mut alice_key = soft_passkey();
    let mut bob_key = soft_passkey();
    register(&fx, &mut world.state, &mut alice_key, (&alice, "alice", "laptop"), PLUS_TWO)?;
    register(&fx, &mut world.state, &mut bob_key, (&bob, "bob", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    let (challenge, options) = webauthn_login_start(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, SOURCE),
    )?;
    let bob_id = world
        .state
        .credentials
        .get("bob")
        .and_then(|list| list.first())
        .ok_or("no credential")?
        .id
        .clone();
    let forged = discoverable_assertion(&mut bob_key, &origin(ORIGIN)?, options, (&bob_id, None))?;
    let assertion = Assertion {
        challenge_id: challenge,
        response: forged,
        source: SOURCE.to_owned(),
    };
    assert!(invalid(webauthn_login_finish(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &assertion
    )));
    assert!(audit_text(&fx)?.contains("\"reason\":\"assertion_invalid\""));
    Ok(())
}


#[test]
fn starting_the_second_factor_does_not_reveal_accounts() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    let now = at(PLUS_THREE)?;
    let start =
        |state: &mut State, user: &str, password: &str| webauthn_login_start(state, &ctx, &fx.webauthn, now, &request(user, password, SOURCE));
    assert!(invalid(start(&mut world.state, "alice", "wrong password here")));
    assert!(invalid(start(&mut world.state, "nobody", "wrong password here")));
    assert!(matches!(
        start(&mut world.state, "bob", GOOD_PASSWORD),
        Err(AuthError::MfaEnrolmentRequired)
    ));
    let text = audit_text(&fx)?;
    assert!(text.contains("\"reason\":\"bad_password\""));
    assert!(text.contains("\"reason\":\"unknown_user\""));
    assert!(text.contains("\"reason\":\"mfa_not_enrolled\""));
    assert!(text.contains("unknown:"));
    assert!(!text.contains("nobody"));
    Ok(())
}


#[test]
fn start_failures_are_internal_denials() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let broken_verify = context_with(&fx, os_random, &failing_verify);
    assert!(invalid(webauthn_login_start(
        &mut world.state,
        &broken_verify,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, SOURCE)
    )));
    let broken_random = context_with(&fx, fail_on_challenge, &verify_password);
    assert!(invalid(webauthn_login_start(
        &mut world.state,
        &broken_random,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, SOURCE)
    )));
    assert!(audit_text(&fx)?.contains("\"reason\":\"internal_error\""));
    Ok(())
}


#[test]
fn failures_lock_the_source_and_the_account() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    (0..ACCOUNT_MAX_FAILURES).try_for_each(|_| {
        let (challenge, _) = webauthn_login_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_THREE)?, &request("alice", GOOD_PASSWORD, SOURCE))?;
        let garbage = Assertion {
            challenge_id: challenge,
            response: serde_json::from_value(json!({"id":"AA","rawId":"AA","response":{"authenticatorData":"AA","clientDataJSON":"AA","signature":"AA"},"type":"public-key","extensions":{}}))?,
            source: SOURCE.to_owned(),
        };
        assert!(invalid(webauthn_login_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_THREE)?, &garbage)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let locked_account = webauthn_login_start(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, OTHER_SOURCE),
    );
    assert!(invalid(locked_account));
    let now = at(PLUS_THREE)?;
    let locked_out = (0..SOURCE_MAX_FAILURES)
        .filter(|_| {
            matches!(
                webauthn_login_start(&mut world.state, &ctx, &fx.webauthn, now, &request("nobody", GOOD_PASSWORD, SOURCE)),
                Err(AuthError::Locked { .. })
            )
        })
        .count();
    assert!(locked_out > 0);
    assert!(matches!(
        webauthn_login_start(
            &mut world.state,
            &ctx,
            &fx.webauthn,
            at(PLUS_THREE)?,
            &request("nobody", GOOD_PASSWORD, SOURCE)
        ),
        Err(AuthError::Locked { .. })
    ));
    assert!(matches!(
        passkey_login_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_THREE)?, SOURCE),
        Err(AuthError::Locked { .. })
    ));
    let (challenge, options) = passkey_login_start(&mut world.state, &ctx, &fx.webauthn, at(PLUS_THREE)?, "10.1.1.1")?;
    let listed_id = world
        .state
        .credentials
        .get("alice")
        .and_then(|list| list.first())
        .map(|credential| credential.id.clone());
    let response = assert_with(
        &mut soft,
        &origin(ORIGIN)?,
        edited(&options, "/publicKey/allowCredentials", json!([{"type":"public-key","id": listed_id}]))?,
    )?;
    let locked = Assertion {
        challenge_id: challenge,
        response,
        source: SOURCE.to_owned(),
    };
    assert!(matches!(
        webauthn_login_finish(&mut world.state, &ctx, &fx.webauthn, at(PLUS_THREE)?, &locked),
        Err(AuthError::Locked { .. })
    ));
    let text = audit_text(&fx)?;
    assert!(text.contains("\"reason\":\"locked\""));
    assert!(text.contains("auth.lockout"));
    Ok(())
}


#[test]
fn a_passkey_logs_in_without_a_password() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let admin = world.admin.clone();
    let mut soft = soft_passkey();
    let credential = register(&fx, &mut world.state, &mut soft, (&admin, "admin", "yubikey"), PLUS_ONE)?;
    let session = passkey_login(&fx, &mut world.state, &mut soft, (&credential, "admin", SOURCE), PLUS_TWO)?;
    assert!(!session.is_empty());
    let text = audit_text(&fx)?;
    assert!(text.contains("\"method\":\"passkey\""));
    assert!(world.state.sessions.len() > 1);
    assert!(!world.admin_secret.expose_secret().is_empty());
    Ok(())
}


#[test]
fn passkey_assertions_are_checked_against_the_stored_credential() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    let credential = register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    let page = origin(ORIGIN)?;
    let attempt = |state: &mut State, key: &mut SoftPasskey, credential_id: &str, user_handle: Option<&str>| -> SoftResult<AuthError> {
        let (challenge, options) = passkey_login_start(state, &ctx, &fx.webauthn, at(PLUS_THREE)?, SOURCE)?;
        let response = discoverable_assertion(key, &page, options, (credential_id, user_handle))?;
        let assertion = Assertion {
            challenge_id: challenge,
            response,
            source: SOURCE.to_owned(),
        };
        webauthn_login_finish(state, &ctx, &fx.webauthn, at(PLUS_THREE)?, &assertion)
            .err()
            .ok_or_else(|| "accepted".into())
    };
    let other_handle = BASE64URL_NOPAD.encode(user_uuid("bob").as_bytes());
    assert!(matches!(
        attempt(&mut world.state, &mut soft, &credential, None)?,
        AuthError::InvalidCredentials
    ));
    assert!(matches!(
        attempt(&mut world.state, &mut soft, &credential, Some(&other_handle))?,
        AuthError::InvalidCredentials
    ));
    assert!(matches!(
        attempt(&mut world.state, &mut soft, &credential, Some("AAAA"))?,
        AuthError::InvalidCredentials
    ));
    let mut spare = soft_passkey();
    let spare_id = register(&fx, &mut world.state, &mut spare, (&alice, "alice", "spare"), PLUS_TWO)?;
    remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &alice, ("alice", &spare_id))?;
    let own_handle = BASE64URL_NOPAD.encode(user_uuid("alice").as_bytes());
    assert!(matches!(
        attempt(&mut world.state, &mut spare, &spare_id, Some(&own_handle))?,
        AuthError::InvalidCredentials
    ));
    let text = audit_text(&fx)?;
    assert!(text.contains("\"reason\":\"unknown_credential\""));
    assert!(text.contains("\"reason\":\"assertion_invalid\""));
    let session = passkey_login(&fx, &mut world.state, &mut soft, (&credential, "alice", SOURCE), PLUS_THREE)?;
    assert!(!session.is_empty());
    Ok(())
}


#[test]
fn a_second_factor_challenge_cannot_be_used_after_it_was_replaced_and_challenges_are_capped() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let ctx = context(&fx);
    let start = at(0)?;
    (0..CHALLENGE_MAX).try_for_each(|_| passkey_login_start(&mut world.state, &ctx, &fx.webauthn, start, SOURCE).map(|_| ()))?;
    assert!(matches!(
        passkey_login_start(&mut world.state, &ctx, &fx.webauthn, at(0)?, SOURCE),
        Err(AuthError::TooManyChallenges)
    ));
    assert!(passkey_login_start(&mut world.state, &ctx, &fx.webauthn, at(LATE)?, SOURCE).is_ok());
    assert_eq!(world.state.challenges.len(), 1);
    assert!(matches!(
        passkey_login_start(
            &mut world.state,
            &context_with(&fx, fail_on_challenge, &verify_password),
            &fx.webauthn,
            at(LATE)?,
            SOURCE
        ),
        Err(AuthError::Random(_))
    ));
    Ok(())
}


#[test]
fn a_session_failure_after_a_valid_assertion_is_an_internal_denial() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let alice = token_for(&fx, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx = context(&fx);
    let (challenge, options) = webauthn_login_start(
        &mut world.state,
        &ctx,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, SOURCE),
    )?;
    let assertion = Assertion {
        challenge_id: challenge,
        response: assert_with(&mut soft, &origin(ORIGIN)?, options)?,
        source: SOURCE.to_owned(),
    };
    let no_session = context_with(&fx, fail_on_length, &verify_password);
    assert!(invalid(webauthn_login_finish(
        &mut world.state,
        &no_session,
        &fx.webauthn,
        at(PLUS_THREE)?,
        &assertion
    )));
    assert!(audit_text(&fx)?.contains("\"reason\":\"internal_error\""));
    Ok(())
}


#[test]
fn a_failing_audit_fails_every_operation_closed() -> TestResult {
    let healthy = fixture()?;
    let mut world = world(&healthy)?;
    let alice = token_for(&healthy, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    let credential = register(&healthy, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let ctx_ok = context(&healthy);
    let (challenge, options) = webauthn_login_start(
        &mut world.state,
        &ctx_ok,
        &healthy.webauthn,
        at(PLUS_THREE)?,
        &request("alice", GOOD_PASSWORD, SOURCE),
    )?;
    let assertion = Assertion {
        challenge_id: challenge,
        response: assert_with(&mut soft, &origin(ORIGIN)?, options)?,
        source: SOURCE.to_owned(),
    };
    let (registration, reg_options) = register_start(&mut world.state, &ctx_ok, &healthy.webauthn, at(PLUS_THREE)?, &alice, "alice")?;
    let registering = RegistrationRequest {
        username: "alice".to_owned(),
        challenge_id: registration,
        name: "second".to_owned(),
        response: register_with(&mut soft, &origin(ORIGIN)?, reg_options)?,
    };
    let before = world.state.sessions.len();
    let broken = broken_fixture()?;
    let ctx = context(&broken);
    let bad_audit = |outcome: Result<(), AuthError>| matches!(outcome, Err(AuthError::Audit(_)));
    assert!(bad_audit(
        register_start(&mut world.state, &ctx, &broken.webauthn, at(PLUS_THREE)?, &alice, "alice").map(|_| ())
    ));
    assert!(bad_audit(
        register_finish(&mut world.state, &ctx, &broken.webauthn, at(PLUS_THREE)?, &alice, &registering).map(|_| ())
    ));
    assert!(bad_audit(rename_credential(
        &mut world.state,
        &ctx,
        at(PLUS_THREE)?,
        &alice,
        ("alice", &credential, "x")
    )));
    assert!(bad_audit(remove_credential(
        &mut world.state,
        &ctx,
        at(PLUS_THREE)?,
        &alice,
        ("alice", &credential)
    )));
    assert!(bad_audit(
        webauthn_login_finish(&mut world.state, &ctx, &broken.webauthn, at(PLUS_THREE)?, &assertion).map(|_| ())
    ));
    assert_eq!(world.state.sessions.len(), before);
    assert_eq!(world.state.credentials.get("alice").map(Vec::len), Some(1));
    Ok(())
}


#[test]
fn audit_failures_are_reported_by_the_login_starts_and_refusals() -> TestResult {
    let healthy = fixture()?;
    let mut world = world(&healthy)?;
    let alice = token_for(&healthy, &mut world, "alice", PLUS_ONE)?;
    let mut soft = soft_passkey();
    register(&healthy, &mut world.state, &mut soft, (&alice, "alice", "laptop"), PLUS_TWO)?;
    let broken = broken_fixture()?;
    let ctx = context(&broken);
    let audit_error = |outcome: Result<(), AuthError>| matches!(outcome, Err(AuthError::Audit(_)));
    assert!(audit_error(
        webauthn_login_start(
            &mut world.state,
            &ctx,
            &broken.webauthn,
            at(PLUS_THREE)?,
            &request("alice", GOOD_PASSWORD, SOURCE)
        )
        .map(|_| ())
    ));
    assert!(audit_error(
        webauthn_login_start(
            &mut world.state,
            &ctx,
            &broken.webauthn,
            at(PLUS_THREE)?,
            &request("alice", "wrong password", SOURCE)
        )
        .map(|_| ())
    ));
    assert!(audit_error(
        passkey_login_start(&mut world.state, &ctx, &broken.webauthn, at(PLUS_THREE)?, SOURCE).map(|_| ())
    ));
    let garbage = Assertion {
        challenge_id: "missing".to_owned(),
        response: serde_json::from_value(
            json!({"id":"AA","rawId":"AA","response":{"authenticatorData":"AA","clientDataJSON":"AA","signature":"AA"},"type":"public-key","extensions":{}}),
        )?,
        source: SOURCE.to_owned(),
    };
    assert!(audit_error(
        webauthn_login_finish(&mut world.state, &ctx, &broken.webauthn, at(PLUS_THREE)?, &garbage).map(|_| ())
    ));
    let healthy_ctx = context(&healthy);
    let now = at(PLUS_THREE)?;
    (0..SOURCE_MAX_FAILURES).for_each(|_| {
        assert!(invalid(webauthn_login_finish(
            &mut world.state,
            &healthy_ctx,
            &healthy.webauthn,
            now,
            &garbage
        )));
    });
    assert!(audit_error(
        webauthn_login_finish(&mut world.state, &ctx, &broken.webauthn, at(PLUS_THREE)?, &garbage).map(|_| ())
    ));
    assert!(audit_error(
        passkey_login_start(&mut world.state, &ctx, &broken.webauthn, at(PLUS_THREE)?, SOURCE).map(|_| ())
    ));
    assert!(audit_error(
        webauthn_login_start(
            &mut world.state,
            &ctx,
            &broken.webauthn,
            at(PLUS_THREE)?,
            &request("alice", GOOD_PASSWORD, SOURCE)
        )
        .map(|_| ())
    ));
    Ok(())
}


#[test]
fn webauthn_required_roles_reject_totp() -> TestResult {
    let fx = fixture_over(Vec::new(), strict_catalog()?)?;
    let ctx = context(&fx);
    let mut world = world(&fx)?;
    assert!(webauthn_required(&fx.catalog, &roles(&["breakglass"])));
    assert!(!webauthn_required(&fx.catalog, &roles(&[ROLE_ADMINISTRATOR])));
    create_account(
        &mut world.state,
        &ctx,
        at(PLUS_ONE)?,
        &world.admin,
        "glass",
        &SecretString::from(GOOD_PASSWORD),
        roles(&["breakglass"]),
    )?;
    let enrolment = enrol_totp(&mut world.state, &ctx, at(PLUS_ONE)?, &world.admin, "glass", None)?;
    let mut with_code = request("glass", GOOD_PASSWORD, SOURCE);
    with_code.totp_code = Some(SecretString::from(current_code(&enrolment.secret)?));
    assert!(matches!(
        login(&mut world.state, &ctx, at(0)?, &with_code),
        Err(AuthError::WebauthnRequired)
    ));
    assert!(audit_text(&fx)?.contains("\"reason\":\"webauthn_required\""));
    let glass_token = world.admin.clone();
    let mut soft = soft_passkey();
    register(&fx, &mut world.state, &mut soft, (&glass_token, "glass", "key"), PLUS_ONE)?;
    let session = second_factor(&fx, &mut world.state, &mut soft, ("glass", SOURCE), PLUS_TWO)?;
    assert!(!session.is_empty());
    let id = world
        .state
        .credentials
        .get("glass")
        .and_then(|list| list.first())
        .ok_or("no credential")?
        .id
        .clone();
    assert!(matches!(
        remove_credential(&mut world.state, &ctx, at(PLUS_THREE)?, &world.admin, ("glass", &id)),
        Err(AuthError::LastFactor)
    ));
    Ok(())
}


#[test]
fn the_last_factor_of_an_account_that_needs_one_cannot_be_removed() -> TestResult {
    let fx = fixture()?;
    let ctx = context(&fx);
    let mut world = world(&fx)?;
    create_account(
        &mut world.state,
        &ctx,
        at(PLUS_ONE)?,
        &world.admin,
        "ops",
        &SecretString::from(GOOD_PASSWORD),
        roles(&[ROLE_ADMINISTRATOR]),
    )?;
    let mut soft = soft_passkey();
    let first = register(&fx, &mut world.state, &mut soft, (&world.admin.clone(), "ops", "key one"), PLUS_ONE)?;
    let second = register(&fx, &mut world.state, &mut soft, (&world.admin.clone(), "ops", "key two"), PLUS_ONE)?;
    remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("ops", &first))?;
    assert!(matches!(
        remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("ops", &second)),
        Err(AuthError::LastFactor)
    ));
    enrol_totp(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, "ops", None)?;
    remove_credential(&mut world.state, &ctx, at(PLUS_TWO)?, &world.admin, ("ops", &second))?;
    assert!(audit_text(&fx)?.contains("the last second factor"));
    Ok(())
}


const VERSION_ONE: &str = r#"{"version":1,"accounts":[{"username":"alice","password_hash":"x","roles":["reader"],"totp":null}]}"#;


const OWNER_ONLY: u32 = 0o600;


fn registered(fixture: &Fixture<Vec<u8>>) -> SoftResult<State> {
    let mut world = world(fixture)?;
    let alice = token_for(fixture, &mut world, "alice", PLUS_ONE)?;
    register(fixture, &mut world.state, &mut soft_passkey(), (&alice, "alice", "laptop"), PLUS_TWO)?;
    Ok(world.state)
}


#[test]
fn credentials_round_trip_through_the_store() -> TestResult {
    let state = registered(&fixture()?)?;
    let mut bytes = Vec::new();
    save_store(&mut bytes, &state.accounts, &state.credentials)?;
    let text = String::from_utf8(bytes.clone())?;
    assert!(text.contains("\"version\": 2"));
    assert!(text.contains("\"credentials\""));
    let (accounts, credentials) = load_store(bytes.as_slice())?;
    assert_eq!(accounts, state.accounts);
    assert_eq!(credentials.get("alice").map(Vec::len), Some(1));
    assert_eq!(
        credentials
            .get("alice")
            .and_then(|list| list.first())
            .map(|credential| credential.name.as_str()),
        Some("laptop")
    );
    Ok(())
}


#[test]
fn a_version_one_store_migrates_and_is_rewritten_as_version_two() -> TestResult {
    let (accounts, credentials) = load_store(VERSION_ONE.as_bytes())?;
    assert_eq!(accounts.len(), 1);
    assert!(credentials.is_empty());
    assert_eq!(load_accounts(VERSION_ONE.as_bytes())?.len(), 1);
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    fs::write(&path, VERSION_ONE)?;
    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(OWNER_ONLY))?;
    let loaded = load_accounts_file(&path)?;
    save_accounts_file(&path, &loaded, os_random)?;
    assert!(fs::read_to_string(&path)?.contains(&format!("\"version\": {STORE_VERSION}")));
    Ok(())
}


#[test]
fn stored_credentials_are_validated() -> TestResult {
    let state = registered(&fixture()?)?;
    let mut bytes = Vec::new();
    save_store(&mut bytes, &state.accounts, &state.credentials)?;
    let document: Value = serde_json::from_slice(&bytes)?;
    let mut orphan = document.clone();
    set_at(&mut orphan, "/accounts", json!([]))?;
    assert!(matches!(load_store(orphan.to_string().as_bytes()), Err(AuthError::OrphanCredential(_))));
    let mut old = document.clone();
    set_at(&mut old, "/version", json!(1))?;
    assert!(matches!(
        load_store(old.to_string().as_bytes()),
        Err(AuthError::UnsupportedVersion { found: 1 })
    ));
    let mut unknown = document;
    set_at(&mut unknown, "/credentials/0", json!({"extra": true}))?;
    assert!(matches!(load_store(unknown.to_string().as_bytes()), Err(AuthError::Format(_))));
    let mut accounts_only = Vec::new();
    save_accounts(&mut accounts_only, &state.accounts)?;
    assert_eq!(load_store(accounts_only.as_slice())?.1.len(), 0);
    Ok(())
}


#[test]
fn saving_accounts_keeps_the_credentials_of_the_remaining_accounts() -> TestResult {
    let state = registered(&fixture()?)?;
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    save_store_file(&path, &state.accounts, &state.credentials, os_random)?;
    save_accounts_file(&path, &state.accounts, os_random)?;
    assert_eq!(load_store_file(&path)?.1.get("alice").map(Vec::len), Some(1));
    let mut remaining = state.accounts.clone();
    remaining.remove("alice");
    save_accounts_file(&path, &remaining, os_random)?;
    assert!(load_store_file(&path)?.1.is_empty());
    Ok(())
}


const REPLY_PARTS: usize = 3;


const READ_ONLY_DIRECTORY: u32 = 0o500;


const WRITABLE_DIRECTORY: u32 = 0o700;


fn exec(state: &mut State, fixture: &Fixture<Vec<u8>>, store: &Path, text: &str) -> Result<String, AuthError> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let now = OffsetDateTime::from_unix_timestamp(BASE_TIME + PLUS_TWO).map_err(|error| AuthError::Usage(error.to_string()))?;
    apply_command_with(state, &context(fixture), Some(&fixture.webauthn), now, (store, &words))
}


fn json_after(reply: &str) -> SoftResult<(String, String)> {
    let mut parts = reply.splitn(REPLY_PARTS, ' ');
    parts.next();
    let identifier = parts.next().ok_or("no identifier")?.to_owned();
    Ok((identifier, parts.next().ok_or("no json")?.to_owned()))
}


#[test]
fn the_tool_drives_registration_and_both_logins_from_json() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let directory = tempdir()?;
    let store = directory.path().join("accounts.json");
    let mut soft = soft_passkey();
    let page = origin(ORIGIN)?;
    let admin = world.admin.clone();
    exec(
        &mut world.state,
        &fx,
        &store,
        &format!("create {admin} carol {GOOD_PASSWORD_WORD} reader"),
    )?;
    let (challenge, options) = json_after(&exec(&mut world.state, &fx, &store, &format!("wa-register-start {admin} carol"))?)?;
    let response = serde_json::to_string(&register_with(&mut soft, &page, serde_json::from_str(&options)?)?)?;
    let registered = exec(
        &mut world.state,
        &fx,
        &store,
        &format!("wa-register-finish {admin} carol {challenge} laptop {response}"),
    )?;
    let credential = registered.strip_prefix("ok ").ok_or("no credential")?.to_owned();
    assert!(exec(&mut world.state, &fx, &store, &format!("wa-list {admin} carol"))?.contains("laptop"));
    assert_eq!(
        exec(&mut world.state, &fx, &store, &format!("wa-rename {admin} carol {credential} renamed"))?,
        "ok"
    );
    assert!(exec(&mut world.state, &fx, &store, &format!("wa-list {admin} carol"))?.contains("renamed"));
    assert!(load_store_file(&store)?.1.contains_key("carol"));
    let (second, second_options) = json_after(&exec(
        &mut world.state,
        &fx,
        &store,
        &format!("wa-login-start carol {GOOD_PASSWORD_WORD} {SOURCE}"),
    )?)?;
    let proof = serde_json::to_string(&assert_with(&mut soft, &page, serde_json::from_str(&second_options)?)?)?;
    let logged = exec(&mut world.state, &fx, &store, &format!("wa-login-finish {second} {SOURCE} {proof}"))?;
    assert!(logged.starts_with("ok "));
    assert!(exec(&mut world.state, &fx, &store, &format!("wa-list {admin} carol"))?.contains("renamed"));
    let (passkey, passkey_options) = json_after(&exec(&mut world.state, &fx, &store, &format!("passkey-start {SOURCE}"))?)?;
    let handle = BASE64URL_NOPAD.encode(user_uuid("carol").as_bytes());
    let discovered = discoverable_assertion(&mut soft, &page, serde_json::from_str(&passkey_options)?, (&credential, Some(&handle)))?;
    let passwordless = exec(
        &mut world.state,
        &fx,
        &store,
        &format!("wa-login-finish {passkey} {SOURCE} {}", serde_json::to_string(&discovered)?),
    )?;
    assert!(passwordless.starts_with("ok "));
    assert_eq!(
        exec(&mut world.state, &fx, &store, &format!("wa-remove {admin} carol {credential}"))?,
        "ok"
    );
    assert!(!load_store_file(&store)?.1.contains_key("carol"));
    assert!(matches!(
        exec(
            &mut world.state,
            &fx,
            &store,
            &format!("wa-register-finish {admin} carol {challenge} laptop not-json")
        ),
        Err(AuthError::Format(_))
    ));
    assert!(matches!(exec(&mut world.state, &fx, &store, "wa-nothing"), Err(AuthError::Usage(_))));
    Ok(())
}


const GOOD_PASSWORD_WORD: &str = "correct-horse-battery";


#[test]
fn the_tool_refuses_webauthn_without_a_configuration() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let directory = tempdir()?;
    let store = directory.path().join("accounts.json");
    let words = ["passkey-start", SOURCE];
    let now = at(PLUS_ONE)?;
    assert!(matches!(
        apply_command(&mut world.state, &context(&fx), now, &store, &words),
        Err(AuthError::WebauthnNotConfigured)
    ));
    Ok(())
}


#[test]
fn a_login_whose_store_save_fails_returns_no_session() -> TestResult {
    let fx = fixture()?;
    let mut world = world(&fx)?;
    let directory = tempdir()?;
    let locked = directory.path().join("store");
    fs::create_dir(&locked)?;
    let store = locked.join("accounts.json");
    let mut soft = soft_passkey();
    let page = origin(ORIGIN)?;
    let admin = world.admin.clone();
    exec(
        &mut world.state,
        &fx,
        &store,
        &format!("create {admin} carol {GOOD_PASSWORD_WORD} reader"),
    )?;
    let (challenge, options) = json_after(&exec(&mut world.state, &fx, &store, &format!("wa-register-start {admin} carol"))?)?;
    let response = serde_json::to_string(&register_with(&mut soft, &page, serde_json::from_str(&options)?)?)?;
    exec(
        &mut world.state,
        &fx,
        &store,
        &format!("wa-register-finish {admin} carol {challenge} laptop {response}"),
    )?;
    let (second, second_options) = json_after(&exec(
        &mut world.state,
        &fx,
        &store,
        &format!("wa-login-start carol {GOOD_PASSWORD_WORD} {SOURCE}"),
    )?)?;
    let proof = serde_json::to_string(&assert_with(&mut soft, &page, serde_json::from_str(&second_options)?)?)?;
    let sessions = world.state.sessions.len();
    fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(READ_ONLY_DIRECTORY))?;
    let refused = exec(&mut world.state, &fx, &store, &format!("wa-login-finish {second} {SOURCE} {proof}"));
    let password_login = exec(&mut world.state, &fx, &store, &format!("login carol {GOOD_PASSWORD_WORD} {SOURCE}"));
    let unsaved = exec(&mut world.state, &fx, &store, &format!("wa-rename {admin} carol missing renamed"));
    let unsaved_removal = exec(&mut world.state, &fx, &store, &format!("create {admin} dave {GOOD_PASSWORD_WORD} reader"));
    fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(WRITABLE_DIRECTORY))?;
    assert!(matches!(refused, Err(AuthError::InvalidCredentials)));
    assert!(matches!(password_login, Err(AuthError::InvalidCredentials)));
    assert!(matches!(unsaved, Err(AuthError::UnknownCredential)));
    assert!(matches!(unsaved_removal, Err(AuthError::Io(_))));
    assert_eq!(world.state.sessions.len(), sessions);
    let text = audit_text(&fx)?;
    assert!(text.contains("internal_error"));
    assert!(text.contains("auth.session.revoke"));
    Ok(())
}


#[test]
fn the_tool_reads_the_webauthn_configuration_file() -> TestResult {
    let directory = tempdir()?;
    let write = |name: &str, content: &[u8]| -> SoftResult<String> {
        let path = directory.path().join(name);
        fs::write(&path, content)?;
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(OWNER_ONLY))?;
        Ok(path.display().to_string())
    };
    let key = write("key", &[KEY_FILL; KEY_LENGTH])?;
    let words = write("words", b"password1234\n")?;
    let good = write(
        "webauthn.yaml",
        b"rp_id: ostyr.example\nrp_origin: https://ostyr.example\nrp_name: Ostyr\n",
    )?;
    let bad = write("bad.yaml", b"rp_id: ostyr.example\n")?;
    let arguments = |config: Option<&str>| -> Vec<String> {
        let base = [
            directory.path().join("accounts.json").display().to_string(),
            directory.path().join("audit.log").display().to_string(),
            key.clone(),
            words.clone(),
        ];
        base.into_iter().chain(config.map(str::to_owned)).collect()
    };
    let fixed = || OffsetDateTime::from_unix_timestamp(BASE_TIME).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let mut output = Vec::new();
    run(
        &arguments(Some(&good)),
        "passkey-start 10.0.0.1\nwa-list nothing alice\n".as_bytes(),
        &mut output,
        fixed,
        os_random,
    )?;
    let text = String::from_utf8(output)?;
    assert!(text.starts_with("ok "));
    assert!(text.contains("error session is invalid or expired"));
    let mut plain = Vec::new();
    run(&arguments(None), "passkey-start 10.0.0.1\n".as_bytes(), &mut plain, fixed, os_random)?;
    assert!(String::from_utf8(plain)?.contains("error WebAuthn is not configured"));
    let mut unused = Vec::new();
    assert!(matches!(run(&[], "".as_bytes(), &mut unused, fixed, os_random), Err(AuthError::Usage(_))));
    assert!(run(&arguments(Some(&bad)), "".as_bytes(), Vec::new(), fixed, os_random).is_err());
    assert!(run(
        &arguments(Some("/nonexistent/webauthn.yaml")),
        "".as_bytes(),
        Vec::new(),
        fixed,
        os_random
    )
    .is_err());
    Ok(())
}


const PATTERN_BYTE: u8 = 7;


const SECRET_BYTES: usize = 20;


fn constant_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    buffer.fill(PATTERN_BYTE);
    Ok(())
}


#[test]
fn the_tool_loads_custom_roles_from_a_file() -> TestResult {
    let directory = tempdir()?;
    let write = |name: &str, content: &[u8]| -> SoftResult<String> {
        let path = directory.path().join(name);
        fs::write(&path, content)?;
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(OWNER_ONLY))?;
        Ok(path.display().to_string())
    };
    let key = write("key", &[KEY_FILL; KEY_LENGTH])?;
    let words = write("words", b"password1234\n")?;
    let webauthn = write(
        "webauthn.yaml",
        b"rp_id: ostyr.example\nrp_origin: https://ostyr.example\nrp_name: Ostyr\n",
    )?;
    let roles_file = write(
        "roles.json",
        br#"[{"name":"breakglass","permissions":["users.manage","policy.webauthn_required"]}]"#,
    )?;
    let store = directory.path().join("accounts.json").display().to_string();
    let audit = directory.path().join("audit.log").display().to_string();
    let arguments = |roles: &str| {
        vec![
            store.clone(),
            audit.clone(),
            key.clone(),
            words.clone(),
            webauthn.clone(),
            roles.to_owned(),
        ]
    };
    let fixed = || OffsetDateTime::from_unix_timestamp(BASE_TIME).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let mut first = Vec::new();
    run(
        &arguments(&roles_file),
        "bootstrap root correct-horse-battery\n".as_bytes(),
        &mut first,
        fixed,
        constant_random,
    )?;
    let secret = BASE32_NOPAD.encode(&[PATTERN_BYTE; SECRET_BYTES]);
    let code = totp_now(&secret, fixed())?;
    let token = "07".repeat(KEY_LENGTH);
    let script = format!("login root correct-horse-battery 10.0.0.1 {code}\ncreate {token} glass correct-horse-battery breakglass\n");
    let mut second = Vec::new();
    run(&arguments(&roles_file), script.as_bytes(), &mut second, fixed, constant_random)?;
    assert!(String::from_utf8(second)?.ends_with("ok\n"));
    assert!(run(&arguments("/nonexistent/roles.json"), "".as_bytes(), Vec::new(), fixed, os_random).is_err());
    Ok(())
}
