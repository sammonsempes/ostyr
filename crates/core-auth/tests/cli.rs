#[path = "support/failing_reader.rs"]
mod failing_reader;
#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/types.rs"]
mod types;


use core_audit::verify::verify;
use core_auth::cli::{parse_roles, run, totp_now};
use core_auth::error::AuthError;
use core_auth::random::os_random;
use failing_reader::FailingReader;
use failing_writer::FailingWriter;
use std::fs;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use types::TestResult;


const KEY_FILL: u8 = 5;


const HEX_PER_BYTE: usize = 2;


const CODE_DIGITS: usize = 6;


const KEY_PATH: usize = 2;


const WORDS_PATH: usize = 3;


const BASE_TIME: i64 = 1_700_000_010;


const KEY_LENGTH: usize = 32;


const MODE_MASK: u32 = 0o777;


const OWNER_ONLY: u32 = 0o600;


const PASSWORD: &str = "correct-horse-battery";


const RFC_SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";


const PATTERN_BYTE: u8 = 7;


const BRUTE_FORCE: usize = 6;


struct Workspace {
    directory: TempDir,
}


fn fixed_clock() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(BASE_TIME).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}


fn workspace() -> Result<Workspace, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    fs::write(directory.path().join("key"), vec![KEY_FILL; KEY_LENGTH])?;
    fs::write(directory.path().join("bad-words"), "password1234\n")?;
    Ok(Workspace { directory })
}


fn paths(workspace: &Workspace) -> Vec<String> {
    ["accounts.json", "audit.log", "key", "bad-words"]
        .iter()
        .map(|name| workspace.directory.path().join(name).display().to_string())
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
    let setup = session(
        &space,
        &format!("create root {PASSWORD} administrator\nenrol root\nlogin root {PASSWORD} 10.0.0.1\n"),
    )?;
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
    let mut script = format!("create alice {PASSWORD} reader\n");
    script.push_str(&"login alice wrong-password-here 10.0.0.2\n".repeat(BRUTE_FORCE));
    script.push_str(&format!("login alice {PASSWORD} 10.0.0.2\n"));
    let output = session(&space, &script)?;
    assert!(output.contains("error too many failures"));
    assert!(fs::read_to_string(space.directory.path().join("audit.log"))?.contains("auth.lockout"));
    Ok(())
}


#[test]
fn every_command_replies() -> TestResult {
    let space = workspace()?;
    let setup = session(&space, &format!("create alice {PASSWORD} reader\nlogin alice {PASSWORD} src\n"))?;
    let token = word_after(&setup, "ok ").ok_or("no token")?.to_owned();
    let script = format!("check {token}\nroles alice analyst\ncheck {token}\nrevoke-all alice\nbogus\ntotp !!!\n");
    let output = session(&space, &script)?;
    assert!(output.contains("error session is invalid or expired"));
    assert!(output.contains("revoked 0"));
    assert!(output.contains("error invalid command: unknown command"));
    assert!(output.contains("error invalid command: secret is not base32"));
    let same_process = session(&space, &format!("login alice {PASSWORD} src\n"))?;
    let fresh = word_after(&same_process, "ok ").ok_or("no token")?;
    let checked = session(&space, &format!("login alice {PASSWORD} src\nroles alice reader\nrevoke-all alice\n"))?;
    assert!(checked.contains("revoked") && !fresh.is_empty());
    Ok(())
}


#[test]
fn check_allows_a_live_session() -> TestResult {
    let space = workspace()?;
    let mut output = Vec::new();
    let script = format!(
        "create alice {PASSWORD} reader\nlogin alice {PASSWORD} src\ncheck {}\n",
        "07".repeat(KEY_LENGTH)
    );
    run(&paths(&space), script.as_bytes(), &mut output, fixed_clock, constant_random)?;
    assert!(String::from_utf8(output)?.contains("allowed alice"));
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
    fs::set_permissions(&store, fs::Permissions::from_mode(OWNER_ONLY))?;
    assert!(session(&space, "bogus\n").is_err());
    Ok(())
}
