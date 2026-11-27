#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use agent_channel::spool_dirs::accept_any_entries;
use agent_windows::error::RunError;
use agent_windows::model::{RunEnd, RunRequest};
use agent_windows::serve::{error_line, exit_code, install_logging, start, start_site, wait_or_stop, ServeError, StartError, EXIT_ROUND_CAP};
use agent_windows::settings::SettingsError;
use agent_windows::types::InterruptWait;
use std::fs;
use std::future::{pending, ready};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::channel;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const OWNER_ONLY: u32 = 0o700;


const OPEN_TO_ALL: u32 = 0o777;


const DEFENDER_AND_WINGET_LINES: usize = 2;


const TWO_ROUNDS: u64 = 2;


const GOOD: &str = "audit_file: audit-log\n";


struct Site {
    state: PathBuf,
    spool: PathBuf,
}


fn empty_output(_request: &RunRequest<'_>, _sink: &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError> {
    Ok(RunEnd::Done)
}


fn instantly(_seconds: u64) -> Duration {
    Duration::ZERO
}


fn site(root: &Path, settings: Option<&str>) -> Result<Site, Box<dyn std::error::Error>> {
    let state = root.join("state");
    let spool_dir = root.join("spool");
    [&state, &spool_dir].iter().try_for_each(|directory| {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(OWNER_ONLY))
    })?;
    settings.map_or(Ok(()), |text| fs::write(state.join("settings.yaml"), text))?;
    Ok(Site {
        state,
        spool: spool_dir.join("spool"),
    })
}


fn refused_start(settings: Option<&str>) -> Result<StartError, Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let made = site(root.path(), settings)?;
    Ok(start_site(&made.state, &made.spool, accept_any_entries)
        .err()
        .ok_or("the start was accepted")?)
}


#[test]
fn a_good_site_starts_and_the_audit_file_is_made() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), Some(GOOD))?;
    start_site(&made.state, &made.spool, accept_any_entries)?;
    assert!(made.state.join("audit-log").is_file());
    Ok(())
}


#[test]
fn every_refusal_at_the_start_is_named() -> TestResult {
    assert!(matches!(refused_start(None)?, StartError::Read(_)));
    assert!(matches!(
        refused_start(Some("batch: 7\n"))?,
        StartError::Invalid(SettingsError::NoAuditFile)
    ));
    assert!(matches!(
        refused_start(Some("audit_file: nul\n"))?,
        StartError::Invalid(SettingsError::BadAuditFile)
    ));
    assert!(matches!(
        refused_start(Some("audit_file: audit\nbatch: 0\n"))?,
        StartError::Invalid(SettingsError::Range { field: "batch" })
    ));
    assert!(matches!(refused_start(Some("audit_file: 'x'\n"))?, StartError::Read(_)));
    Ok(())
}


#[test]
fn an_audit_name_that_is_a_directory_is_refused() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), Some(GOOD))?;
    fs::create_dir(made.state.join("audit-log"))?;
    assert!(matches!(
        start_site(&made.state, &made.spool, accept_any_entries).err(),
        Some(StartError::Audit(_))
    ));
    Ok(())
}


#[test]
fn a_state_directory_open_to_all_or_missing_is_refused() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), Some(GOOD))?;
    fs::set_permissions(&made.state, fs::Permissions::from_mode(OPEN_TO_ALL))?;
    assert!(matches!(
        start_site(&made.state, &made.spool, accept_any_entries).err(),
        Some(StartError::StateDir(_))
    ));
    assert!(matches!(
        start_site(&root.path().join("absent"), &made.spool, accept_any_entries).err(),
        Some(StartError::StateDir(_))
    ));
    Ok(())
}


#[test]
fn a_state_directory_that_is_a_link_is_refused() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), Some(GOOD))?;
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&made.state, &link)?;
    assert!(matches!(
        start_site(&link, &made.spool, accept_any_entries).err(),
        Some(StartError::StateDir(_))
    ));
    Ok(())
}


#[test]
fn a_spool_directory_open_to_all_is_refused() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), Some(GOOD))?;
    let parent = made.spool.parent().ok_or("no parent")?;
    fs::set_permissions(parent, fs::Permissions::from_mode(OPEN_TO_ALL))?;
    assert!(matches!(
        start_site(&made.state, &made.spool, accept_any_entries).err(),
        Some(StartError::SpoolDir(_))
    ));
    Ok(())
}


struct Ran {
    made: Site,
    _root: tempfile::TempDir,
    result: Result<(), ServeError>,
}


fn at_cap(settings: Option<&str>, interrupt: InterruptWait) -> Result<Ran, Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let made = site(root.path(), settings)?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let result = runtime.block_on(start(
        &made.state,
        &made.spool,
        TWO_ROUNDS,
        empty_output,
        instantly,
        accept_any_entries,
        interrupt,
    ));
    Ok(Ran { made, _root: root, result })
}


#[test]
fn the_round_cap_is_a_named_error_with_its_own_exit_code() -> TestResult {
    let ran = at_cap(Some(GOOD), Box::pin(pending()))?;
    let (made, result) = (&ran.made, &ran.result);
    assert!(matches!(result, Err(ServeError::RoundCap)));
    assert_eq!(exit_code(result), ExitCode::from(EXIT_ROUND_CAP));
    let spooled = fs::read_to_string(&made.spool)?;
    assert_eq!(spooled.lines().count(), DEFENDER_AND_WINGET_LINES, "{spooled}");
    assert!(spooled.contains("defender_unavailable"), "{spooled}");
    assert!(spooled.contains("windowsapps_unreadable"), "{spooled}");
    Ok(())
}


#[test]
fn a_failed_round_is_logged_and_retried_until_the_cap() -> TestResult {
    let root = tempdir()?;
    let made = site(root.path(), Some(GOOD))?;
    fs::create_dir(&made.spool)?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let result = runtime.block_on(start(
        &made.state,
        &made.spool,
        TWO_ROUNDS,
        empty_output,
        instantly,
        accept_any_entries,
        Box::pin(pending()),
    ));
    assert!(matches!(result, Err(ServeError::RoundCap)));
    Ok(())
}


#[test]
fn an_interrupt_ends_the_rounds_cleanly() -> TestResult {
    let Ran { result, made, _root } = at_cap(Some(GOOD), Box::pin(ready(Ok(()))))?;
    assert!(result.is_ok());
    assert_eq!(exit_code(&result), ExitCode::SUCCESS);
    let spooled = fs::read_to_string(&made.spool)?;
    assert_eq!(
        spooled.lines().count(),
        DEFENDER_AND_WINGET_LINES,
        "the round in flight finished its spool write: {spooled}"
    );
    Ok(())
}


#[test]
fn a_failing_interrupt_wait_is_named() -> TestResult {
    let Ran { result, .. } = at_cap(Some(GOOD), Box::pin(ready(Err(io::Error::other("no signal")))))?;
    assert!(matches!(result, Err(ServeError::Interrupt(_))));
    assert_eq!(exit_code(&result), ExitCode::FAILURE);
    Ok(())
}


#[test]
fn a_bad_start_is_a_start_error_in_one_line() -> TestResult {
    let Ran { result, .. } = at_cap(None, Box::pin(pending()))?;
    let error = result.err().ok_or("started")?;
    assert!(matches!(error, ServeError::Start(StartError::Read(_))));
    let line = error_line(&error);
    assert!(line.starts_with("cannot start: settings file refused"), "{line}");
    assert!(!line.contains('\n'));
    Ok(())
}


#[test]
fn the_wait_ends_at_once_on_a_message_or_a_dropped_sender_and_not_on_a_timeout() -> TestResult {
    let (sender, receiver) = channel::<()>();
    assert!(!wait_or_stop(&receiver, instantly, 1));
    sender.send(())?;
    assert!(wait_or_stop(&receiver, instantly, 1));
    drop(sender);
    assert!(wait_or_stop(&receiver, instantly, 1));
    Ok(())
}


#[test]
fn logging_installs_once() -> TestResult {
    let first = install_logging();
    let second = install_logging();
    assert!(first.is_ok());
    assert!(matches!(second, Err(ServeError::Logging(_))));
    Ok(())
}
