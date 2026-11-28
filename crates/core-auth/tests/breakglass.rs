#![cfg(unix)]
#[path = "support/soft.rs"]
mod soft;
#[path = "support/types.rs"]
mod types;


use core_audit::log::{genesis_log, AuditLog};
use core_audit::verify::verify;
use core_auth::breakglass::{breakglass_status, shell_inert, BREAKGLASS_TARGET};
use core_auth::cli::{apply_command_with, run};
use core_auth::error::{AuthError, RolesError};
use core_auth::password::verify_password;
use core_auth::random::os_random;
use core_auth::rbac::{break_glass, break_glass_roles, builtin_catalog, load_catalog, POLICY_BREAK_GLASS, ROLE_ADMINISTRATOR, ROLE_READER};
use core_auth::service::{bootstrap_administrator, change_roles, create_account, login, Context, LoginRequest, State, DECLARED_KEYS};
use core_auth::store::update_store_file;
use core_auth::totp::{code_for_step, TOTP_STEP_SECONDS};
use core_auth::types::{CompromisedSet, RoleCatalog, RoleSet, StoreKey};
use core_auth::webauthn::{
    build_webauthn, passkey_login_start, register_finish, register_start, remove_credential, rename_credential, user_uuid, webauthn_login_finish,
    Assertion, RegistrationRequest, WebauthnConfig,
};
use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use soft::{discoverable_assertion, origin, register_with, soft_passkey, SoftResult};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::Webauthn;


const BASE_TIME: i64 = 1_700_000_010;


const GOOD_PASSWORD: &str = "correct horse battery";


const ADMIN_PASSWORD: &str = "another long passphrase";


const ORIGIN: &str = "https://ostyr.example";


const RP_ID: &str = "ostyr.example";


const KEY_FILL: u8 = 9;


const KEY_LENGTH: usize = 32;


const PLUS_ONE: i64 = 1;


const PLUS_TWO: i64 = 2;


const WRONG_PASSWORDS: usize = 8;


const SOURCES: usize = 4;


const LOCK_ROUNDS: usize = 2;


const GRANT_AND_REVOKE: usize = 2;


const MANAGER_REFUSALS: usize = 4;


const SELF_STEPS: usize = 3;


const LISTED_ACCOUNTS: usize = 2;


const PASSKEY_LOGIN_RECORDS: usize = 2;


const OWNER_ONLY: u32 = 0o600;


const GLASS_ROLES: &str = r#"[{"name":"glass","permissions":["events.read","policy.break_glass","policy.webauthn_required"]}]"#;


const LOGIN_ACTION: &str = "\"action\":\"auth.login\"";


const MARKER: &str = "\"break_glass\":\"true\"";


struct Fixture {
    audit: AuditLog<Vec<u8>>,
    key: StoreKey,
    compromised: CompromisedSet,
    catalog: RoleCatalog,
    webauthn: Webauthn,
}


fn fixture(catalog: RoleCatalog) -> SoftResult<Fixture> {
    Ok(Fixture {
        audit: genesis_log(Vec::new()),
        key: SecretSlice::from(vec![KEY_FILL; KEY_LENGTH]),
        compromised: CompromisedSet::new(),
        catalog,
        webauthn: build_webauthn(&WebauthnConfig {
            rp_id: RP_ID.to_owned(),
            rp_origin: ORIGIN.to_owned(),
            rp_name: "Ostyr".to_owned(),
        })?,
    })
}


fn glass_fixture() -> SoftResult<Fixture> {
    fixture(load_catalog(GLASS_ROLES.as_bytes())?)
}


fn context(fixture: &Fixture) -> Context<'_, Vec<u8>> {
    Context {
        audit: &fixture.audit,
        random: os_random,
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


fn request(user: &str, password: &str, source: &str) -> LoginRequest {
    LoginRequest {
        username: user.to_owned(),
        password: SecretString::from(password),
        totp_code: None,
        source: source.to_owned(),
    }
}


fn audit_text(fixture: &Fixture) -> SoftResult<String> {
    let state = fixture.audit.state.lock().map_err(|_| "poisoned")?;
    verify(state.writer.as_slice(), None)?;
    Ok(String::from_utf8(state.writer.clone())?)
}


fn lines_with(fixture: &Fixture, needles: &[&str]) -> SoftResult<usize> {
    Ok(audit_text(fixture)?
        .lines()
        .filter(|line| needles.iter().all(|needle| line.contains(needle)))
        .count())
}


struct World {
    state: State,
    admin: String,
}


fn world(fixture: &Fixture) -> SoftResult<World> {
    let ctx = context(fixture);
    let mut state = State::default();
    let enrolment = bootstrap_administrator(&mut state, &ctx, at(0)?, "admin", &SecretString::from(ADMIN_PASSWORD))?;
    let raw = BASE32_NOPAD.decode(enrolment.secret.expose_secret().as_bytes())?;
    let mut with_code = request("admin", ADMIN_PASSWORD, "10.9.9.9");
    with_code.totp_code = Some(SecretString::from(code_for_step(&raw, u64::try_from(BASE_TIME)? / TOTP_STEP_SECONDS)));
    let token = login(&mut state, &ctx, at(0)?, &with_code)?;
    Ok(World {
        state,
        admin: token.expose_secret().to_owned(),
    })
}


fn register(fixture: &Fixture, state: &mut State, soft: &mut SoftPasskey, (token, user, name): (&str, &str, &str)) -> SoftResult<String> {
    let ctx = context(fixture);
    let (challenge, options) = register_start(state, &ctx, &fixture.webauthn, at(PLUS_ONE)?, token, user)?;
    let response = register_with(soft, &origin(ORIGIN)?, options)?;
    let finished = RegistrationRequest {
        username: user.to_owned(),
        challenge_id: challenge,
        name: name.to_owned(),
        response,
    };
    Ok(register_finish(state, &ctx, &fixture.webauthn, at(PLUS_ONE)?, token, &finished)?)
}


fn passkey_login(fixture: &Fixture, state: &mut State, soft: &mut SoftPasskey, (credential, user, source): (&str, &str, &str)) -> SoftResult<String> {
    let ctx = context(fixture);
    let (challenge, options) = passkey_login_start(state, &ctx, &fixture.webauthn, at(PLUS_TWO)?, source)?;
    let handle = BASE64URL_NOPAD.encode(user_uuid(user).as_bytes());
    let response = discoverable_assertion(soft, &origin(ORIGIN)?, options, (credential, Some(&handle)))?;
    let assertion = Assertion {
        challenge_id: challenge,
        response,
        source: source.to_owned(),
    };
    Ok(webauthn_login_finish(state, &ctx, &fixture.webauthn, at(PLUS_TWO)?, &assertion)?
        .expose_secret()
        .to_owned())
}


struct Glass {
    world: World,
    soft: SoftPasskey,
    credential: String,
    session: String,
}


fn glass_world(fixture: &Fixture, name: &str) -> SoftResult<Glass> {
    let ctx = context(fixture);
    let mut world = world(fixture)?;
    let password = SecretString::from(GOOD_PASSWORD);
    create_account(
        &mut world.state,
        &ctx,
        at(PLUS_ONE)?,
        &world.admin,
        name,
        &password,
        roles(&[ROLE_READER]),
    )?;
    let own = login(&mut world.state, &ctx, at(PLUS_ONE)?, &request(name, GOOD_PASSWORD, "10.9.9.1"))?;
    let mut soft = soft_passkey();
    let credential = register(fixture, &mut world.state, &mut soft, (own.expose_secret(), name, "key"))?;
    change_roles(&mut world.state, &ctx, at(PLUS_ONE)?, &world.admin, name, roles(&["glass"]))?;
    let session = passkey_login(fixture, &mut world.state, &mut soft, (&credential, name, "10.9.9.2"))?;
    Ok(Glass {
        world,
        soft,
        credential,
        session,
    })
}


#[test]
fn a_break_glass_role_needs_webauthn_in_every_catalog_load() -> TestResult {
    let alone = r#"[{"name":"glass","permissions":["policy.break_glass"]}]"#;
    assert!(matches!(
        load_catalog(alone.as_bytes()),
        Err(AuthError::Roles(RolesError::BreakGlassWithoutWebauthn(name))) if name == "glass"
    ));
    let beside = r#"[{"name":"ok","permissions":["events.read"]},{"name":"glass","permissions":["users.manage","policy.break_glass"]}]"#;
    assert!(matches!(
        load_catalog(beside.as_bytes()),
        Err(AuthError::Roles(RolesError::BreakGlassWithoutWebauthn(_)))
    ));
    let catalog = load_catalog(GLASS_ROLES.as_bytes())?;
    assert!(break_glass(&catalog, &roles(&["glass"])));
    assert!(!break_glass(&catalog, &roles(&[ROLE_ADMINISTRATOR, ROLE_READER, "missing"])));
    assert_eq!(break_glass_roles(&catalog, &roles(&["glass", ROLE_READER, "missing"])), roles(&["glass"]));
    assert!(builtin_catalog().values().all(|permissions| !permissions.contains(POLICY_BREAK_GLASS)));
    assert!(DECLARED_KEYS.contains(&"break_glass") && DECLARED_KEYS.contains(&"break_glass_change"));
    Ok(())
}


#[test]
fn the_catalog_of_the_tool_is_refused_when_a_break_glass_role_lacks_webauthn() -> TestResult {
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
    let bad = write("bad.json", br#"[{"name":"glass","permissions":["policy.break_glass"]}]"#)?;
    let store = directory.path().join("accounts.json").display().to_string();
    let audit = directory.path().join("audit.log").display().to_string();
    let arguments = vec![store, audit, key, words, webauthn, bad];
    let fixed = || OffsetDateTime::from_unix_timestamp(BASE_TIME).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let outcome = run(&arguments, "".as_bytes(), Vec::new(), fixed, os_random);
    assert!(matches!(outcome, Err(AuthError::Roles(RolesError::BreakGlassWithoutWebauthn(_)))));
    Ok(())
}


#[test]
fn the_tool_reads_the_roles_file_through_the_bounded_regular_file_reader() -> TestResult {
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
    let fifo = directory.path().join("roles.fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    let big = write("big.json", &vec![b' '; usize::try_from(core_auth::rbac::MAX_ROLES_FILE_BYTES)? + 1])?;
    let store = directory.path().join("accounts.json").display().to_string();
    let audit = directory.path().join("audit.log").display().to_string();
    let fixed = || OffsetDateTime::from_unix_timestamp(BASE_TIME).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    [fifo.display().to_string(), big].iter().try_for_each(|roles_file| -> TestResult {
        let arguments = vec![
            store.clone(),
            audit.clone(),
            key.clone(),
            words.clone(),
            webauthn.clone(),
            roles_file.clone(),
        ];
        assert!(matches!(
            run(&arguments, "".as_bytes(), Vec::new(), fixed, os_random),
            Err(AuthError::Config(_))
        ));
        Ok(())
    })
}


#[test]
fn every_record_about_a_break_glass_account_carries_the_marker() -> TestResult {
    let fx = glass_fixture()?;
    let ctx = context(&fx);
    let mut glass = glass_world(&fx, "glass")?;
    let grant = audit_text(&fx)?;
    assert!(grant
        .lines()
        .any(|line| line.contains("authz.role.change") && line.contains(MARKER) && line.contains("\"break_glass_change\":\"grant\"")));
    assert_eq!(
        lines_with(&fx, &["auth.login", "\"outcome\":\"success\"", MARKER, "\"method\":\"passkey\""])?,
        1
    );
    assert_eq!(lines_with(&fx, &["auth.webauthn.login_start", MARKER])?, 0);
    let before = lines_with(&fx, &[LOGIN_ACTION, MARKER])?;
    (0..WRONG_PASSWORDS).try_for_each(|i| -> TestResult {
        let source = format!("10.1.0.{}", i % SOURCES);
        let outcome = login(
            &mut glass.world.state,
            &ctx,
            at(PLUS_TWO)?,
            &request("glass", "wrong password here", &source),
        );
        assert!(matches!(outcome, Err(AuthError::InvalidCredentials)));
        Ok(())
    })?;
    assert_eq!(lines_with(&fx, &[LOGIN_ACTION, MARKER])?, before + WRONG_PASSWORDS);
    assert!(lines_with(&fx, &["auth.lockout", MARKER, "\"scope\":\"account\""])? >= 1);
    let unknown = login(
        &mut glass.world.state,
        &ctx,
        at(PLUS_TWO)?,
        &request("nobody", "wrong password here", "10.1.1.1"),
    );
    assert!(matches!(unknown, Err(AuthError::InvalidCredentials)));
    assert_eq!(lines_with(&fx, &["unknown:", MARKER])?, 0);
    let again = passkey_login(&fx, &mut glass.world.state, &mut glass.soft, (&glass.credential, "glass", "10.9.9.3"))?;
    assert!(!again.is_empty());
    change_roles(
        &mut glass.world.state,
        &ctx,
        at(PLUS_TWO)?,
        &glass.world.admin,
        "glass",
        roles(&[ROLE_READER]),
    )?;
    assert!(audit_text(&fx)?
        .lines()
        .any(|line| line.contains("authz.role.change") && line.contains(MARKER) && line.contains("\"break_glass_change\":\"revoke\"")));
    assert_eq!(lines_with(&fx, &["authz.role.change", "\"break_glass_change\""])?, GRANT_AND_REVOKE);
    Ok(())
}


#[test]
fn a_locked_break_glass_account_still_logs_in_by_passkey_from_an_unlocked_source() -> TestResult {
    let fx = glass_fixture()?;
    let ctx = context(&fx);
    let mut glass = glass_world(&fx, "glass")?;
    (0..SOURCES * LOCK_ROUNDS).try_for_each(|i| -> TestResult {
        let source = format!("10.2.0.{i}");
        assert!(login(
            &mut glass.world.state,
            &ctx,
            at(PLUS_TWO)?,
            &request("glass", "wrong password here", &source)
        )
        .is_err());
        Ok(())
    })?;
    let locked = login(&mut glass.world.state, &ctx, at(PLUS_TWO)?, &request("glass", GOOD_PASSWORD, "10.2.9.9"));
    assert!(matches!(locked, Err(AuthError::InvalidCredentials)));
    let session = passkey_login(&fx, &mut glass.world.state, &mut glass.soft, (&glass.credential, "glass", "10.2.8.8"))?;
    assert_eq!(session.len(), glass.session.len());
    assert!(lines_with(&fx, &["auth.lockout", MARKER])? >= 1);
    Ok(())
}


#[test]
fn only_the_account_itself_manages_the_passkeys_of_a_break_glass_account() -> TestResult {
    let fx = glass_fixture()?;
    let ctx = context(&fx);
    let mut glass = glass_world(&fx, "glass")?;
    let admin = glass.world.admin.clone();
    let denied = |outcome: Result<(), AuthError>| matches!(outcome, Err(AuthError::PermissionDenied));
    let (challenge, options) = register_start(&mut glass.world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &glass.session, "glass")?;
    assert!(matches!(
        register_start(&mut glass.world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &admin, "glass"),
        Err(AuthError::PermissionDenied)
    ));
    let mut second = soft_passkey();
    let response = register_with(&mut second, &origin(ORIGIN)?, options)?;
    let finished = RegistrationRequest {
        username: "glass".to_owned(),
        challenge_id: challenge,
        name: "second".to_owned(),
        response,
    };
    assert!(matches!(
        register_finish(&mut glass.world.state, &ctx, &fx.webauthn, at(PLUS_TWO)?, &admin, &finished),
        Err(AuthError::PermissionDenied)
    ));
    assert!(denied(rename_credential(
        &mut glass.world.state,
        &ctx,
        at(PLUS_TWO)?,
        &admin,
        ("glass", &glass.credential, "renamed")
    )));
    assert!(denied(remove_credential(
        &mut glass.world.state,
        &ctx,
        at(PLUS_TWO)?,
        &admin,
        ("glass", &glass.credential)
    )));
    assert!(lines_with(&fx, &["auth.webauthn", "\"outcome\":\"denied\"", MARKER])? >= MANAGER_REFUSALS);
    rename_credential(
        &mut glass.world.state,
        &ctx,
        at(PLUS_TWO)?,
        &glass.session,
        ("glass", &glass.credential, "renamed"),
    )?;
    assert!(matches!(
        remove_credential(&mut glass.world.state, &ctx, at(PLUS_TWO)?, &glass.session, ("glass", &glass.credential)),
        Err(AuthError::LastFactor)
    ));
    let added = register(&fx, &mut glass.world.state, &mut second, (&glass.session, "glass", "second"))?;
    remove_credential(&mut glass.world.state, &ctx, at(PLUS_TWO)?, &glass.session, ("glass", &added))?;
    assert!(lines_with(&fx, &["auth.webauthn", "\"outcome\":\"success\"", MARKER])? >= SELF_STEPS);
    Ok(())
}


#[test]
fn nobody_grants_themselves_a_break_glass_role() -> TestResult {
    let fx = glass_fixture()?;
    let ctx = context(&fx);
    let mut world = world(&fx)?;
    let admin = world.admin.clone();
    let own = change_roles(
        &mut world.state,
        &ctx,
        at(PLUS_ONE)?,
        &admin,
        "admin",
        roles(&[ROLE_ADMINISTRATOR, "glass"]),
    );
    assert!(matches!(own, Err(AuthError::PermissionDenied)));
    assert!(world.state.accounts.get("admin").is_some_and(|account| !account.roles.contains("glass")));
    assert_eq!(lines_with(&fx, &["authz.role.change", "\"outcome\":\"denied\""])?, 1);
    create_account(
        &mut world.state,
        &ctx,
        at(PLUS_ONE)?,
        &admin,
        "other",
        &SecretString::from(GOOD_PASSWORD),
        roles(&[ROLE_READER]),
    )?;
    change_roles(&mut world.state, &ctx, at(PLUS_ONE)?, &admin, "other", roles(&["glass"]))?;
    assert_eq!(lines_with(&fx, &["authz.role.change", MARKER, "\"break_glass_change\":\"grant\""])?, 1);
    create_account(
        &mut world.state,
        &ctx,
        at(PLUS_ONE)?,
        &admin,
        "direct",
        &SecretString::from(GOOD_PASSWORD),
        roles(&["glass"]),
    )?;
    assert_eq!(lines_with(&fx, &["auth.account.create", MARKER, "\"break_glass_change\":\"grant\""])?, 1);
    change_roles(&mut world.state, &ctx, at(PLUS_ONE)?, &admin, "admin", roles(&[ROLE_ADMINISTRATOR]))?;
    Ok(())
}


#[test]
fn a_role_change_that_keeps_break_glass_marks_without_a_change() -> TestResult {
    let fx = fixture(load_catalog(
        r#"[{"name":"glass","permissions":["policy.break_glass","policy.webauthn_required"]},{"name":"glass2","permissions":["policy.break_glass","policy.webauthn_required"]}]"#.as_bytes(),
    )?)?;
    let ctx = context(&fx);
    let mut world = world(&fx)?;
    let admin = world.admin.clone();
    create_account(
        &mut world.state,
        &ctx,
        at(PLUS_ONE)?,
        &admin,
        "pair",
        &SecretString::from(GOOD_PASSWORD),
        roles(&["glass"]),
    )?;
    change_roles(&mut world.state, &ctx, at(PLUS_ONE)?, &admin, "pair", roles(&["glass", "glass2"]))?;
    assert_eq!(lines_with(&fx, &["authz.role.change", MARKER])?, 1);
    assert_eq!(lines_with(&fx, &["authz.role.change", "break_glass_change"])?, 0);
    Ok(())
}


fn seed_store(store: &Path, state: &State) -> TestResult {
    update_store_file(store, os_random, |accounts, credentials| {
        accounts.clone_from(&state.accounts);
        credentials.clone_from(&state.credentials);
        Ok(())
    })?
    .saved?;
    Ok(())
}


#[test]
fn shell_inert_names_keep_only_safe_bytes() -> TestResult {
    assert_eq!(shell_inert("x';id;'"), "x%27%3Bid%3B%27");
    assert_eq!(shell_inert("a.b_c~d-e%f"), "a.b_c~d-e%25f");
    assert!(shell_inert("é")
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "%".contains(character)));
    Ok(())
}


#[test]
fn breakglass_status_lists_accounts_without_secrets_and_audits_the_count() -> TestResult {
    let fx = glass_fixture()?;
    let ctx = context(&fx);
    let mut glass = glass_world(&fx, "glass")?;
    let admin = glass.world.admin.clone();
    let password = SecretString::from(GOOD_PASSWORD);
    create_account(
        &mut glass.world.state,
        &ctx,
        at(PLUS_TWO)?,
        &admin,
        "x';id;'",
        &password,
        roles(&["glass"]),
    )?;
    let lines = breakglass_status(&mut glass.world.state, &ctx, at(PLUS_TWO)?, &admin)?;
    assert_eq!(lines.len(), LISTED_ACCOUNTS);
    assert!(lines.iter().any(|line| line == "glass 1 1700000012"));
    assert!(lines.iter().any(|line| line == "x%27%3Bid%3B%27 0 never no_passkey"));
    assert!(matches!(
        breakglass_status(&mut glass.world.state, &ctx, at(PLUS_TWO)?, &glass.session),
        Err(AuthError::PermissionDenied)
    ));
    assert!(matches!(
        breakglass_status(&mut glass.world.state, &ctx, at(PLUS_TWO)?, "no-such-session"),
        Err(AuthError::SessionInvalid)
    ));
    let text = audit_text(&fx)?;
    assert!(text
        .lines()
        .any(|line| line.contains("auth.breakglass.status") && line.contains("\"count\":\"2\"") && line.contains(BREAKGLASS_TARGET)));
    assert!(!text
        .lines()
        .any(|line| line.contains("auth.breakglass.status") && line.contains(&glass.credential)));
    Ok(())
}


#[test]
fn the_tool_prints_the_status_and_leaves_the_store_alone() -> TestResult {
    let fx = glass_fixture()?;
    let ctx = context(&fx);
    let mut glass = glass_world(&fx, "glass")?;
    let directory = tempdir()?;
    let store = directory.path().join("accounts.json");
    seed_store(&store, &glass.world.state)?;
    let before = fs::read(&store)?;
    let admin = glass.world.admin.clone();
    let words = ["breakglass-status", admin.as_str()];
    let reply = apply_command_with(&mut glass.world.state, &ctx, Some(&fx.webauthn), at(PLUS_TWO)?, (&store, &words))?;
    assert_eq!(reply, "glass 1 1700000012");
    assert_eq!(fs::read(&store)?, before);
    Ok(())
}


fn record_count(fixture: &Fixture) -> SoftResult<usize> {
    Ok(audit_text(fixture)?.lines().count())
}


#[test]
fn a_break_glass_operation_writes_exactly_one_record_per_step() -> TestResult {
    let fx = glass_fixture()?;
    let ctx = context(&fx);
    let mut glass = glass_world(&fx, "glass")?;
    let before = record_count(&fx)?;
    let credential = glass.credential.clone();
    passkey_login(&fx, &mut glass.world.state, &mut glass.soft, (&credential, "glass", "10.9.9.4"))?;
    assert_eq!(record_count(&fx)?, before + PASSKEY_LOGIN_RECORDS);
    let admin = glass.world.admin.clone();
    let after_login = record_count(&fx)?;
    change_roles(&mut glass.world.state, &ctx, at(PLUS_TWO)?, &admin, "glass", roles(&[ROLE_READER]))?;
    assert_eq!(record_count(&fx)?, after_login + 1);
    let before_refused = record_count(&fx)?;
    assert!(login(
        &mut glass.world.state,
        &ctx,
        at(PLUS_TWO)?,
        &request("glass", "wrong password here", "10.9.9.5")
    )
    .is_err());
    assert_eq!(record_count(&fx)?, before_refused + 1);
    Ok(())
}
