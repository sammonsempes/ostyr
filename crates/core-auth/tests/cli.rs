#[path = "support/failing_reader.rs"]
mod failing_reader;
#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/types.rs"]
mod types;


#[cfg(unix)]
use core_audit::error::AuditError;
#[cfg(unix)]
use core_audit::log::{genesis_log, AuditLog};
use core_audit::verify::verify;
#[cfg(unix)]
use core_auth::cli::apply_command;
#[cfg(unix)]
use core_auth::cli::read_key_file;
use core_auth::cli::{parse_roles, run, totp_now};
use core_auth::error::AuthError;
#[cfg(unix)]
use core_auth::password::verify_password;
use core_auth::random::os_random;
#[cfg(unix)]
use core_auth::rbac::builtin_catalog;
#[cfg(unix)]
use core_auth::service::Context;
#[cfg(unix)]
use core_auth::service::State;
#[cfg(unix)]
use core_auth::session::hash_token;
#[cfg(unix)]
use core_auth::store::{load_accounts_file, update_store_file};
#[cfg(unix)]
use core_auth::types::{CompromisedSet, RoleCatalog, StoreKey};
use data_encoding::BASE32_NOPAD;
use failing_reader::FailingReader;
use failing_writer::FailingWriter;
#[cfg(unix)]
use secrecy::SecretSlice;
use std::fs::{self, OpenOptions};
use std::io::BufReader;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(unix)]
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const KEY_FILL: u8 = 5;


const SECRET_BYTES: usize = 20;


const ENROLMENTS: usize = 2;


#[cfg(unix)]
const GROUP_READABLE: u32 = 0o640;


const HEX_PER_BYTE: usize = 2;


#[cfg(unix)]
const FAILED_COMMANDS: usize = 2;


#[cfg(unix)]
const WRITE_BUDGET: usize = 100;


#[cfg(unix)]
const TOTP_STEP: u64 = 30;


#[cfg(unix)]
const READ_ONLY_DIRECTORY: u32 = 0o500;


const CODE_DIGITS: usize = 6;


const KEY_PATH: usize = 2;


const WORDS_PATH: usize = 3;


const BASE_TIME: i64 = 1_700_000_010;


const KEY_LENGTH: usize = 32;


#[cfg(unix)]
const MODE_MASK: u32 = 0o777;


const OWNER_ONLY: u32 = 0o600;


const PASSWORD: &str = "correct-horse-battery";


const RFC_SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";


const PATTERN_BYTE: u8 = 7;


const BRUTE_FORCE: usize = 6;


#[cfg(unix)]
const REVOCATIONS: usize = 2;


struct Workspace {
    directory: TempDir,
}


fn fixed_clock() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(BASE_TIME).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}


fn workspace() -> Result<Workspace, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    write_key(directory.path(), vec![KEY_FILL; KEY_LENGTH], OWNER_ONLY)?;
    fs::write(directory.path().join("bad-words"), "password1234\n")?;
    Ok(Workspace { directory })
}


#[cfg(unix)]
fn write_key(directory: &Path, bytes: Vec<u8>, mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    let key = directory.join("key");
    fs::write(&key, bytes)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(mode))?;
    Ok(())
}


#[cfg(not(unix))]
fn write_key(directory: &Path, bytes: Vec<u8>, _mode: u32) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(directory.join("key"), bytes)?;
    Ok(())
}


fn paths(workspace: &Workspace) -> Vec<String> {
    paths_in(workspace.directory.path())
}


fn paths_in(directory: &Path) -> Vec<String> {
    ["accounts.json", "audit.log", "key", "bad-words"]
        .iter()
        .map(|name| directory.join(name).display().to_string())
        .collect()
}


fn replaced(all: &[String], index: usize, value: String) -> Vec<String> {
    all.iter()
        .enumerate()
        .map(|(position, path)| if position == index { value.clone() } else { path.clone() })
        .collect()
}


fn session(workspace: &Workspace, script: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    run(&paths(workspace), script.as_bytes(), &mut output, fixed_clock, os_random)?;
    Ok(String::from_utf8(output)?)
}


fn constant_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    buffer.fill(PATTERN_BYTE);
    Ok(())
}


fn word_after<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    text.lines().find_map(|line| line.strip_prefix(label)).map(str::trim)
}


#[test]
fn full_administrator_flow() -> TestResult {
    let space = workspace()?;
    let setup = session(&space, &format!("bootstrap root {PASSWORD}\nlogin root {PASSWORD} 10.0.0.1\n"))?;
    let secret = word_after(&setup, "secret ").ok_or("no secret")?.to_owned();
    assert!(setup.contains("error a second factor is required"));
    let code = session(&space, &format!("totp {secret}\n"))?.trim().to_owned();
    let done = session(&space, &format!("login root {PASSWORD} 10.0.0.1 {code}\n"))?;
    let token = word_after(&done, "ok ").ok_or("no token")?.to_owned();
    assert_eq!(token.len(), KEY_LENGTH * HEX_PER_BYTE);
    let store = fs::read_to_string(space.directory.path().join("accounts.json"))?;
    let audit = fs::read_to_string(space.directory.path().join("audit.log"))?;
    [PASSWORD, secret.as_str(), code.as_str(), token.as_str()].iter().for_each(|value| {
        assert!(!store.contains(value));
        assert!(!audit.contains(value));
    });
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(space.directory.path().join("accounts.json"))?.permissions().mode() & MODE_MASK,
        OWNER_ONLY
    );
    assert!(verify(audit.as_bytes(), None)?.records > 0);
    Ok(())
}


#[test]
fn brute_force_is_locked_and_audited() -> TestResult {
    let space = workspace()?;
    session(&space, &format!("bootstrap root {PASSWORD}\n"))?;
    let mut script = String::new();
    script.push_str(&"login root wrong-password-here 10.0.0.2\n".repeat(BRUTE_FORCE));
    script.push_str(&format!("login root {PASSWORD} 10.0.0.2\n"));
    let output = session(&space, &script)?;
    assert!(!output.contains("error too many failures"));
    assert!(!output.contains("token"));
    assert!(output.lines().last().is_some_and(|line| line.contains("invalid credentials")));
    assert!(fs::read_to_string(space.directory.path().join("audit.log"))?.contains("auth.lockout"));
    Ok(())
}


fn constant_session(workspace: &Workspace, script: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    run(&paths(workspace), script.as_bytes(), &mut output, fixed_clock, constant_random)?;
    Ok(String::from_utf8(output)?)
}


#[test]
fn every_command_replies() -> TestResult {
    let space = workspace()?;
    constant_session(&space, &format!("bootstrap root {PASSWORD}\n"))?;
    let secret = BASE32_NOPAD.encode(&[PATTERN_BYTE; SECRET_BYTES]);
    let code = totp_now(&secret, fixed_clock())?;
    let token = "07".repeat(KEY_LENGTH);
    let script = format!(
        "login root {PASSWORD} src {code}\ncreate {token} alice {PASSWORD} reader\nenrol {token} alice\nenrol {token} alice 000000\nroles {token} alice analyst\n\
         revoke-all {token} alice\ncheck {token}\nrevoke {token} {token}\ncheck {token}\nbogus\ntotp !!!\n"
    );
    let output = constant_session(&space, &script)?;
    assert!(output.contains(&format!("ok {token}")));
    assert!(output.contains("allowed root"));
    assert!(output.contains("revoked 0"));
    assert!(output.contains("error session is invalid or expired"));
    assert!(output.contains("error invalid command: unknown command"));
    assert!(output.contains("error invalid command: secret is not base32"));
    assert!(output.matches("secret ").count() >= ENROLMENTS);
    Ok(())
}


#[test]
fn roles_are_parsed_and_totp_is_computed() -> TestResult {
    assert_eq!(parse_roles("a,,b").len(), HEX_PER_BYTE);
    assert!(parse_roles("").is_empty());
    assert_eq!(
        totp_now(RFC_SECRET_BASE32, OffsetDateTime::from_unix_timestamp(BASE_TIME)?)?.len(),
        CODE_DIGITS
    );
    assert!(matches!(totp_now("!!!", fixed_clock()), Err(AuthError::Usage(_))));
    assert!(matches!(
        totp_now(RFC_SECRET_BASE32, OffsetDateTime::from_unix_timestamp(-1)?),
        Err(AuthError::ClockBeforeEpoch)
    ));
    Ok(())
}


#[test]
fn key_files_must_be_private_and_exactly_32_bytes() -> TestResult {
    let space = workspace()?;
    let mut output = Vec::new();
    [
        (vec![KEY_FILL; KEY_LENGTH + 1], OWNER_ONLY),
        (vec![KEY_FILL; KEY_LENGTH - 1], OWNER_ONLY),
        (Vec::new(), OWNER_ONLY),
    ]
    .into_iter()
    .try_for_each(|(bytes, mode)| {
        write_key(space.directory.path(), bytes, mode)?;
        let result = run(&paths(&space), "".as_bytes(), &mut output, fixed_clock, os_random);
        assert!(matches!(result, Err(AuthError::InvalidKey)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    #[cfg(unix)]
    {
        write_key(space.directory.path(), vec![KEY_FILL; KEY_LENGTH], GROUP_READABLE)?;
        let loose = run(&paths(&space), "".as_bytes(), &mut output, fixed_clock, os_random);
        assert!(matches!(loose, Err(AuthError::KeyFile(AuditError::InsecurePermissions { .. }))));
        assert!(!space.directory.path().join("audit.log").exists());
    }
    Ok(())
}


#[test]
#[cfg(unix)]
fn a_fifo_at_the_key_path_is_refused_without_blocking() -> TestResult {
    let space = workspace()?;
    let fifo = space.directory.path().join("key.fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    let result = read_key_file(&fifo.to_string_lossy());
    assert!(matches!(result, Err(AuthError::Io(_))));
    Ok(())
}


#[test]
fn bad_arguments_and_files_are_reported() -> TestResult {
    let space = workspace()?;
    let mut output = Vec::new();
    let missing_arguments = run(&[], "".as_bytes(), &mut output, fixed_clock, os_random);
    assert!(matches!(missing_arguments, Err(AuthError::Usage(_))));
    let missing_key = replaced(&paths(&space), KEY_PATH, space.directory.path().join("absent-key").display().to_string());
    assert!(matches!(
        run(&missing_key, "".as_bytes(), &mut output, fixed_clock, os_random),
        Err(AuthError::Io(_))
    ));
    let missing_list = replaced(
        &paths(&space),
        WORDS_PATH,
        space.directory.path().join("absent-list").display().to_string(),
    );
    assert!(matches!(
        run(&missing_list, "".as_bytes(), &mut output, fixed_clock, os_random),
        Err(AuthError::Io(_))
    ));
    let bad_audit = replaced(
        &paths(&space),
        1,
        space.directory.path().join("no-dir").join("audit.log").display().to_string(),
    );
    assert!(matches!(
        run(&bad_audit, "".as_bytes(), &mut output, fixed_clock, os_random),
        Err(AuthError::Audit(_))
    ));
    let bad_store = replaced(
        &paths(&space),
        0,
        space.directory.path().join("no-dir").join("accounts.json").display().to_string(),
    );
    assert!(matches!(
        run(&bad_store, "bogus\n".as_bytes(), &mut output, fixed_clock, os_random),
        Err(AuthError::Io(_))
    ));
    Ok(())
}


#[test]
fn input_and_output_failures_are_reported() -> TestResult {
    let space = workspace()?;
    let broken_input = run(&paths(&space), BufReader::new(FailingReader), Vec::new(), fixed_clock, os_random);
    assert!(matches!(broken_input, Err(AuthError::Io(_))));
    let broken_output = FailingWriter {
        fail_write: true,
        fail_flush: false,
    };
    assert!(matches!(
        run(&paths(&space), "bogus\n".as_bytes(), broken_output, fixed_clock, os_random),
        Err(AuthError::Io(_))
    ));
    let unused: PathBuf = Path::new("unused").to_path_buf();
    assert!(unused.is_relative());
    Ok(())
}


#[test]
fn a_malformed_store_stops_the_tool() -> TestResult {
    let space = workspace()?;
    let store = space.directory.path().join("accounts.json");
    fs::write(&store, "garbage")?;
    #[cfg(unix)]
    fs::set_permissions(&store, fs::Permissions::from_mode(OWNER_ONLY))?;
    assert!(session(&space, "bogus\n").is_err());
    Ok(())
}


const CHILD_ENV: &str = "CORE_AUTH_LOCK_CHILD";


const BLOCKED_MILLISECONDS: u64 = 600;


#[test]
fn lock_child_process() -> TestResult {
    match std::env::var(CHILD_ENV) {
        Ok(directory) => {
            let mut output = Vec::new();
            run(
                &paths_in(Path::new(&directory)),
                format!("bootstrap root {PASSWORD}\n").as_bytes(),
                &mut output,
                fixed_clock,
                os_random,
            )?;
            Ok(())
        }
        Err(_) => Ok(()),
    }
}


#[test]
fn concurrent_runs_wait_for_the_store_lock() -> TestResult {
    let space = workspace()?;
    let lock_path = space.directory.path().join("accounts.json.lock");
    let held = OpenOptions::new().write(true).create(true).truncate(false).open(&lock_path)?;
    held.lock()?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", "lock_child_process", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, space.directory.path())
        .spawn()?;
    std::thread::sleep(Duration::from_millis(BLOCKED_MILLISECONDS));
    assert!(child.try_wait()?.is_none());
    assert!(!space.directory.path().join("accounts.json").exists());
    assert!(!space.directory.path().join("audit.log").exists());
    held.unlock()?;
    assert!(child.wait()?.success());
    assert!(space.directory.path().join("accounts.json").exists());
    Ok(())
}


#[test]
#[cfg(unix)]
fn the_lock_file_is_private_and_a_failed_command_does_not_rewrite_the_store() -> TestResult {
    let space = workspace()?;
    constant_session(&space, &format!("bootstrap root {PASSWORD}\n"))?;
    let store = space.directory.path().join("accounts.json");
    let lock_mode = fs::metadata(space.directory.path().join("accounts.json.lock"))?.permissions().mode() & MODE_MASK;
    assert_eq!(lock_mode, OWNER_ONLY);
    let before = fs::metadata(&store)?.ino();
    let output = session(&space, "bogus\nroles 00 root reader\n")?;
    assert_eq!(output.matches("error ").count(), FAILED_COMMANDS);
    assert_eq!(fs::metadata(&store)?.ino(), before);
    session(&space, "totp GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\ncheck 00\n")?;
    assert_eq!(fs::metadata(&store)?.ino(), before);
    let secret = BASE32_NOPAD.encode(&[PATTERN_BYTE; SECRET_BYTES]);
    let code = totp_now(&secret, fixed_clock())?;
    let logged = constant_session(&space, &format!("login root {PASSWORD} 10.0.0.1 {code}\n"))?;
    assert!(logged.starts_with("ok "));
    assert_ne!(fs::metadata(&store)?.ino(), before);
    Ok(())
}


#[test]
#[cfg(unix)]
fn a_login_whose_store_save_fails_returns_no_session() -> TestResult {
    let fixture = fixture();
    let directory = tempdir()?;
    let store_directory = directory.path().join("store");
    fs::create_dir(&store_directory)?;
    let store = store_directory.join("accounts.json");
    let context = working(&fixture);
    let mut state = State::default();
    let enrolment = apply_command(&mut state, &context, fixed_clock(), &store, &["bootstrap", "root", PASSWORD])?;
    let secret = word_after(&enrolment, "secret ").ok_or("no secret")?.to_owned();
    let first_code = totp_now(&secret, fixed_clock())?;
    let first = apply_command(
        &mut state,
        &context,
        fixed_clock(),
        &store,
        &["login", "root", PASSWORD, "10.0.0.1", first_code.as_str()],
    )?;
    let token = word_after(&first, "ok ").ok_or("no token")?.to_owned();
    let later = fixed_clock() + Duration::from_secs(TOTP_STEP);
    let code = totp_now(&secret, later)?;
    let login = ["login", "root", PASSWORD, "10.0.0.1", code.as_str()];
    fs::set_permissions(&store_directory, fs::Permissions::from_mode(READ_ONLY_DIRECTORY))?;
    let unsaved = apply_command(
        &mut state,
        &context,
        later,
        &store,
        &["create", token.as_str(), "alice", PASSWORD, "reader"],
    );
    let refused = apply_command(&mut state, &context, later, &store, &login);
    let sessions_after_refusal = state.sessions.len();
    let replayed = apply_command(&mut state, &context, later, &store, &login);
    let shown = apply_command(&mut state, &context, later, &store, &["totp", secret.as_str()])?;
    fs::set_permissions(&store_directory, fs::Permissions::from_mode(MODE_MASK))?;
    assert_eq!(shown.len(), CODE_DIGITS);
    assert!(matches!(refused, Err(AuthError::InvalidCredentials)));
    assert!(matches!(replayed, Err(AuthError::InvalidCredentials)));
    assert!(matches!(unsaved, Err(AuthError::Io(_))));
    assert_eq!(sessions_after_refusal, 1);
    assert!(state.sessions.contains_key(&hash_token(&token)));
    let guard = fixture.audit_ok.state.lock().map_err(|error| error.to_string())?;
    let audit = String::from_utf8(guard.writer.clone())?;
    assert!(audit.contains("internal_error"));
    assert!(audit.contains("auth.session.revoke"));
    Ok(())
}


#[cfg(unix)]
struct Fixture {
    audit_ok: AuditLog<Vec<u8>>,
    audit_broken: AuditLog<FailingWriter>,
    key: StoreKey,
    compromised: CompromisedSet,
    catalog: RoleCatalog,
}


#[cfg(unix)]
fn fixture() -> Fixture {
    Fixture {
        audit_ok: genesis_log(Vec::new()),
        audit_broken: genesis_log(FailingWriter {
            fail_write: true,
            fail_flush: false,
        }),
        key: SecretSlice::from(vec![KEY_FILL; KEY_LENGTH]),
        compromised: CompromisedSet::new(),
        catalog: builtin_catalog(),
    }
}


#[cfg(unix)]
fn working<'a>(fixture: &'a Fixture) -> Context<'a, Vec<u8>> {
    Context {
        audit: &fixture.audit_ok,
        random: os_random,
        verify: &verify_password,
        key: &fixture.key,
        compromised: &fixture.compromised,
        catalog: &fixture.catalog,
        tenant: "default",
        request_id: "cli",
    }
}


#[cfg(unix)]
fn broken<'a>(fixture: &'a Fixture) -> Context<'a, FailingWriter> {
    Context {
        audit: &fixture.audit_broken,
        random: os_random,
        verify: &verify_password,
        key: &fixture.key,
        compromised: &fixture.compromised,
        catalog: &fixture.catalog,
        tenant: "default",
        request_id: "cli",
    }
}


#[cfg(unix)]
fn same_file(path: &Path, content: &[u8], inode: u64) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(fs::read(path)? == content && fs::metadata(path)?.ino() == inode)
}


#[cfg(unix)]
struct BudgetWriter {
    writes_left: Arc<AtomicUsize>,
}


#[cfg(unix)]
impl Write for BudgetWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let allowed = self
            .writes_left
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1));
        allowed.map(|_| buffer.len()).map_err(|_| std::io::Error::other("write budget spent"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[test]
#[cfg(unix)]
fn a_failing_audit_after_an_unsaved_login_is_reported() -> TestResult {
    let fixture = fixture();
    let writes_left = Arc::new(AtomicUsize::new(WRITE_BUDGET));
    let audit = genesis_log(BudgetWriter {
        writes_left: Arc::clone(&writes_left),
    });
    let context = Context {
        audit: &audit,
        random: os_random,
        verify: &verify_password,
        key: &fixture.key,
        compromised: &fixture.compromised,
        catalog: &fixture.catalog,
        tenant: "default",
        request_id: "cli",
    };
    let directory = tempdir()?;
    let store_directory = directory.path().join("store");
    fs::create_dir(&store_directory)?;
    let store = store_directory.join("accounts.json");
    let mut state = State::default();
    let enrolment = apply_command(&mut state, &context, fixed_clock(), &store, &["bootstrap", "root", PASSWORD])?;
    let secret = word_after(&enrolment, "secret ").ok_or("no secret")?.to_owned();
    let code = totp_now(&secret, fixed_clock())?;
    fs::set_permissions(&store_directory, fs::Permissions::from_mode(READ_ONLY_DIRECTORY))?;
    let later = fixed_clock() + Duration::from_secs(TOTP_STEP);
    let later_code = totp_now(&secret, later)?;
    let accepted = apply_command(
        &mut state,
        &context,
        fixed_clock(),
        &store,
        &["login", "root", PASSWORD, "10.0.0.1", code.as_str()],
    );
    writes_left.store(1, Ordering::SeqCst);
    let unaudited = apply_command(
        &mut state,
        &context,
        later,
        &store,
        &["login", "root", PASSWORD, "10.0.0.1", later_code.as_str()],
    );
    fs::set_permissions(&store_directory, fs::Permissions::from_mode(MODE_MASK))?;
    assert!(matches!(accepted, Err(AuthError::InvalidCredentials)));
    assert!(matches!(unaudited, Err(AuthError::Audit(_))));
    Ok(())
}


#[test]
#[cfg(unix)]
fn a_failing_audit_append_leaves_the_store_untouched() -> TestResult {
    let fixture = fixture();
    let directory = tempdir()?;
    let store = directory.path().join("accounts.json");
    let mut state = State::default();
    let denied = apply_command(&mut state, &broken(&fixture), fixed_clock(), &store, &["bootstrap", "root", PASSWORD]);
    assert!(matches!(denied, Err(AuthError::Audit(_))));
    assert!(!store.exists());
    assert!(state.accounts.is_empty());
    let ok_context = working(&fixture);
    let enrolment = apply_command(&mut state, &ok_context, fixed_clock(), &store, &["bootstrap", "root", PASSWORD])?;
    let secret = word_after(&enrolment, "secret ").ok_or("no secret")?.to_owned();
    assert!(store.exists());
    let code = totp_now(&secret, fixed_clock())?;
    let logged = apply_command(
        &mut state,
        &ok_context,
        fixed_clock(),
        &store,
        &["login", "root", PASSWORD, "10.0.0.1", &code],
    )?;
    let token = word_after(&logged, "ok ").ok_or("no token")?.to_owned();
    let before_content = fs::read(&store)?;
    let before_inode = fs::metadata(&store)?.ino();
    let mutation = ["create", token.as_str(), "bob", "another-long-passphrase", "reader"];
    let refused = apply_command(&mut state, &broken(&fixture), fixed_clock(), &store, &mutation);
    assert!(matches!(refused, Err(AuthError::Audit(_))));
    assert!(same_file(&store, &before_content, before_inode)?);
    assert!(!state.accounts.contains_key("bob"));
    let accepted = apply_command(&mut state, &ok_context, fixed_clock(), &store, &mutation)?;
    assert_eq!(accepted, "ok");
    assert!(!same_file(&store, &before_content, before_inode)?);
    Ok(())
}


#[test]
#[cfg(unix)]
fn a_loose_key_file_error_names_the_key_file() -> TestResult {
    let space = workspace()?;
    write_key(space.directory.path(), vec![KEY_FILL; KEY_LENGTH], GROUP_READABLE)?;
    let result = run(&paths(&space), "".as_bytes(), Vec::new(), fixed_clock, os_random);
    assert!(result.err().ok_or("accepted")?.to_string().starts_with("key file rejected"));
    Ok(())
}


#[test]
#[cfg(unix)]
fn a_command_keeps_changes_another_writer_made_to_the_file() -> TestResult {
    let fixture = fixture();
    let directory = tempdir()?;
    let store = directory.path().join("accounts.json");
    let context = working(&fixture);
    let mut state = State::default();
    let enrolment = apply_command(&mut state, &context, fixed_clock(), &store, &["bootstrap", "root", PASSWORD])?;
    let secret = word_after(&enrolment, "secret ").ok_or("no secret")?.to_owned();
    let code = totp_now(&secret, fixed_clock())?;
    let logged = apply_command(
        &mut state,
        &context,
        fixed_clock(),
        &store,
        &["login", "root", PASSWORD, "10.0.0.1", code.as_str()],
    )?;
    let token = word_after(&logged, "ok ").ok_or("no token")?.to_owned();
    update_store_file(&store, os_random, |accounts, _| {
        let mut outsider = accounts.get("root").ok_or(AuthError::Usage("no root".to_owned()))?.clone();
        outsider.username = "outsider".to_owned();
        outsider.roles = ["reader".to_owned()].into();
        accounts.insert("outsider".to_owned(), outsider);
        Ok(())
    })?
    .saved?;
    apply_command(
        &mut state,
        &context,
        fixed_clock(),
        &store,
        &["create", token.as_str(), "bob", "another-long-passphrase", "reader"],
    )?;
    let stored = load_accounts_file(&store)?;
    assert!(stored.contains_key("outsider"));
    assert!(stored.contains_key("bob"));
    let listed = apply_command(&mut state, &context, fixed_clock(), &store, &["check", token.as_str()])?;
    assert!(listed.starts_with("allowed"));
    assert!(state.accounts.contains_key("outsider"));
    Ok(())
}


#[test]
#[cfg(unix)]
fn revoke_all_on_an_absent_oidc_name_writes_a_stub_and_audits_the_clear_target() -> TestResult {
    let space = workspace()?;
    constant_session(&space, &format!("bootstrap root {PASSWORD}\n"))?;
    let secret = BASE32_NOPAD.encode(&[PATTERN_BYTE; SECRET_BYTES]);
    let code = totp_now(&secret, fixed_clock())?;
    let token = "07".repeat(KEY_LENGTH);
    let script = format!("login root {PASSWORD} src {code}\nrevoke-all {token} oidc:absent-sub\nrevoke-all {token} ghost\n");
    let output = constant_session(&space, &script)?;
    assert!(output.matches("revoked 0").count() >= REVOCATIONS, "{output}");
    let stored = load_accounts_file(&space.directory.path().join("accounts.json"))?;
    let stub = stored.get("oidc:absent-sub").ok_or("stub missing")?;
    assert!(stub.sessions_valid_after.is_some());
    assert!(stub.roles.is_empty());
    assert_eq!(stub.password_hash, "!external");
    assert!(!stored.contains_key("ghost"));
    let audit = fs::read_to_string(space.directory.path().join("audit.log"))?;
    assert!(audit.contains("oidc:absent-sub"));
    assert!(!audit.contains("ghost"));
    assert!(audit.contains("unknown:"));
    Ok(())
}
