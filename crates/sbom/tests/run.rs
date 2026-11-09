#![cfg(unix)]

#[path = "common/types.rs"]
mod types;


use sbom::error::{RunError, SbomError, SettingsError, TargetError};
use sbom::model::Stderr;
use sbom::run::{
    child_environment, drain_stderr, generate, generate_with, outcome, reserve_helpers, run_job, spawn_thread, stderr_excerpt, stderr_summary,
};
use sbom::settings::{SyftSettings, Target};
use sbom::types::{Helpers, Job};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SendError};
use std::sync::Arc;
use tempfile::TempDir;
use types::TestResult;


const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/syft-debian.cdx.json");


const FIXTURE_COMPONENTS: usize = 7;


const SCRIPT_MODE: u32 = 0o755;


const DEADLINE_MILLIS: u64 = 200;


const LONG_DEADLINE_MILLIS: u64 = 60_000;


const MAX_STDOUT: usize = 1_048_576;


const SMALL_STDOUT: usize = 100;


const MAX_COMPONENTS: usize = 5;


const STDERR_CAP: usize = 1000;


const FLOOD_BYTES: &str = "5000000";


const EXIT_CODE: i32 = 3;


const LONG_STDERR: usize = 1000;


const DOUBLE_STDERR: usize = 2000;


const DOUBLE_EXCERPT: usize = 512;


fn fake_syft(dir: &TempDir, body: &str) -> io::Result<PathBuf> {
    let path = dir.path().join("syft");
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(SCRIPT_MODE))?;
    Ok(path)
}


fn settings(dir: &TempDir, binary: PathBuf, deadline_millis: u64) -> SyftSettings {
    SyftSettings {
        binary,
        work_dir: dir.path().to_path_buf(),
        deadline_millis,
        max_stdout_bytes: MAX_STDOUT,
        max_components: MAX_COMPONENTS * MAX_COMPONENTS,
        max_stderr_bytes: STDERR_CAP,
        helper_grace_millis: GRACE_MILLIS,
        max_live_helpers: LIVE_HELPERS,
    }
}


fn target() -> Target {
    Target::Directory(PathBuf::from("/srv/tree"))
}


const TEXT_FILE_BUSY: i32 = 26;


const BUSY_RETRIES: usize = 20;


fn run_once(settings: &SyftSettings) -> Result<sbom::model::Sbom, RunError> {
    generate(settings, &fresh_helpers(), &target(), "tenant-a", "web:1.0")
}


fn fresh_helpers() -> Helpers {
    Arc::new(AtomicUsize::new(0))
}


const GRACE_MILLIS: u64 = 200;


const LIVE_HELPERS: usize = 8;


fn run(settings: &SyftSettings) -> Result<sbom::model::Sbom, RunError> {
    (0..BUSY_RETRIES).fold(run_once(settings), |result, _| match result {
        Err(RunError::Io(error)) if error.raw_os_error() == Some(TEXT_FILE_BUSY) => run_once(settings),
        other => other,
    })
}


#[test]
fn good_run_parses_fixture_and_carries_scope() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("cat '{FIXTURE}'"))?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    assert_eq!(sbom.components.len(), FIXTURE_COMPONENTS);
    assert_eq!(sbom.tenant, "tenant-a");
    assert_eq!(sbom.artefact, "web:1.0");
    Ok(())
}


#[test]
fn arguments_are_separate_and_typed() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "printf '{\"components\":[{\"name\":\"%s\"}]}' \"$*\"")?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    let name = sbom.components.first().map(|component| component.name.as_str());
    assert_eq!(name, Some("scan -o cyclonedx-json dir:/srv/tree"));
    Ok(())
}


#[test]
fn environment_is_cleared_and_explicit() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "printf '{\"components\":[{\"name\":\"%s\"}]}' \"$(env | sort | tr '\\n' ' ')\"")?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    let seen = sbom
        .components
        .first()
        .map(|component| component.name.to_lowercase())
        .ok_or("no component")?;
    assert!(seen.contains("syft_check_for_app_update=false"));
    assert!(seen.contains("home="));
    assert!(!seen.contains("proxy"));
    assert!(!seen.contains("cargo"));
    Ok(())
}


#[test]
fn environment_names_are_fixed() -> TestResult {
    let names: Vec<String> = child_environment(Path::new("/w/h")).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, ["HOME", "XDG_CACHE_HOME", "SYFT_CACHE_DIR", "TMPDIR", "SYFT_CHECK_FOR_APP_UPDATE"]);
    Ok(())
}


#[test]
fn oversized_output_is_too_large() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("cat '{FIXTURE}'"))?;
    let mut limited = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    limited.max_stdout_bytes = SMALL_STDOUT;
    let result = run(&limited);
    assert!(matches!(result, Err(RunError::Sbom(SbomError::TooLarge { .. }))));
    Ok(())
}


#[test]
fn endless_output_stops_at_the_component_cap() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "printf '{\"components\":['\nexec yes '{\"name\":\"a\"},'")?;
    let mut limited = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    limited.max_components = MAX_COMPONENTS;
    let result = run(&limited);
    assert!(matches!(result, Err(RunError::Sbom(SbomError::TooMany { .. }))));
    Ok(())
}


#[test]
fn silent_hang_is_killed_at_the_deadline() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "exec sleep 3600")?;
    let result = run(&settings(&dir, binary, DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::TimedOut)));
    Ok(())
}


#[test]
fn background_holder_of_the_pipe_dies_with_the_group() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "sleep 3600 &\nwait")?;
    let result = run(&settings(&dir, binary, DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::TimedOut)));
    Ok(())
}


#[test]
fn non_zero_exit_is_typed() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("cat '{FIXTURE}'\nexit {EXIT_CODE}"))?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Failed { code: Some(EXIT_CODE), .. })));
    Ok(())
}


#[test]
fn garbage_output_is_a_parse_error() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "echo nonsense")?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Sbom(_))));
    Ok(())
}


#[test]
fn stderr_flood_is_drained_and_capped() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("yes noise | head -c {FLOOD_BYTES} >&2\ncat '{FIXTURE}'"))?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    assert_eq!(sbom.components.len(), FIXTURE_COMPONENTS);
    Ok(())
}


#[test]
fn drain_keeps_the_cap_and_counts_the_rest() -> TestResult {
    let data = vec![b'x'; DOUBLE_STDERR];
    let drained = drain_stderr(data.as_slice(), STDERR_CAP)?;
    assert_eq!(drained.kept.len(), STDERR_CAP);
    assert_eq!(drained.total, u64::try_from(DOUBLE_STDERR)?);
    Ok(())
}


#[test]
fn excerpt_is_bounded_and_escaped() -> TestResult {
    let mut kept = b"line\nnext\x1b[31m".to_vec();
    kept.extend(vec![b'y'; LONG_STDERR]);
    let excerpt = stderr_excerpt(&Stderr { kept, total: 0 });
    assert!(excerpt.starts_with("line\\nnext\\u{1b}[31m"));
    assert!(excerpt.len() <= DOUBLE_EXCERPT);
    Ok(())
}


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}


#[test]
fn drain_reports_a_read_failure() -> TestResult {
    assert!(drain_stderr(Failing, STDERR_CAP).is_err());
    Ok(())
}


#[test]
fn refused_targets_never_spawn() -> TestResult {
    let dir = TempDir::new()?;
    let absent = dir.path().join("absent");
    let configured = settings(&dir, absent, LONG_DEADLINE_MILLIS);
    let helpers = fresh_helpers();
    let relative = generate(&configured, &helpers, &Target::Directory(PathBuf::from("tree")), "t", "a");
    assert!(matches!(relative, Err(RunError::Target(TargetError::Relative))));
    let dash = generate(&configured, &helpers, &Target::OciArchive(PathBuf::from("-x")), "t", "a");
    assert!(matches!(dash, Err(RunError::Target(TargetError::LeadingDash))));
    let control = generate(&configured, &helpers, &Target::DockerArchive(PathBuf::from("/a\nb")), "t", "a");
    assert!(matches!(control, Err(RunError::Target(TargetError::Control))));
    Ok(())
}


#[test]
fn invalid_settings_are_refused() -> TestResult {
    let dir = TempDir::new()?;
    let mut bad = settings(&dir, PathBuf::from("syft"), LONG_DEADLINE_MILLIS);
    bad.binary = PathBuf::from("relative-syft");
    assert!(matches!(run(&bad), Err(RunError::Settings(SettingsError::Invalid("binary")))));
    Ok(())
}


#[test]
fn binary_must_exist_and_be_a_regular_file() -> TestResult {
    let dir = TempDir::new()?;
    let missing = run(&settings(&dir, dir.path().join("absent"), LONG_DEADLINE_MILLIS));
    assert!(matches!(missing, Err(RunError::Io(_))));
    let directory = run(&settings(&dir, dir.path().to_path_buf(), LONG_DEADLINE_MILLIS));
    assert!(matches!(directory, Err(RunError::NotRegular)));
    Ok(())
}


#[test]
fn non_executable_binary_fails_to_spawn() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("plain");
    fs::write(&path, "x")?;
    let result = run(&settings(&dir, path, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Io(_))));
    Ok(())
}


#[test]
fn missing_work_directory_is_an_io_error() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "exit 0")?;
    let mut configured = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    configured.work_dir = dir.path().join("no-such-dir");
    assert!(matches!(run(&configured), Err(RunError::Io(_))));
    Ok(())
}


const HOLDER_LIVE_HELPERS: usize = 2;


#[test]
fn setsid_holder_of_the_pipes_cannot_stall_the_run_or_pile_up_helpers() -> TestResult {
    let dir = TempDir::new()?;
    let pid_file = dir.path().join("holder.pid");
    let binary = fake_syft(&dir, &format!("setsid sleep 3600 &\necho $! > '{}'\nexec sleep 3600", pid_file.display()))?;
    let mut limited = settings(&dir, binary, DEADLINE_MILLIS);
    limited.max_live_helpers = HOLDER_LIVE_HELPERS;
    let helpers = fresh_helpers();
    let first = generate(&limited, &helpers, &target(), "t", "a");
    assert!(matches!(first, Err(RunError::TimedOut)));
    assert_eq!(helpers.load(Ordering::SeqCst), HOLDER_LIVE_HELPERS);
    let second = generate(&limited, &helpers, &target(), "t", "a");
    assert!(matches!(second, Err(RunError::Busy)));
    let holder = fs::read_to_string(&pid_file)?;
    let killed = Command::new("kill").arg(holder.trim()).status()?;
    assert!(killed.success());
    Ok(())
}


#[test]
fn helper_slots_are_reserved_and_released() -> TestResult {
    let helpers = fresh_helpers();
    let slots = reserve_helpers(&helpers, HOLDER_LIVE_HELPERS).ok_or("no slots")?;
    assert_eq!(helpers.load(Ordering::SeqCst), HOLDER_LIVE_HELPERS);
    assert!(reserve_helpers(&helpers, HOLDER_LIVE_HELPERS).is_none());
    drop(slots);
    assert_eq!(helpers.load(Ordering::SeqCst), 0);
    assert!(reserve_helpers(&helpers, HOLDER_LIVE_HELPERS).is_some());
    Ok(())
}


#[test]
fn failing_exit_with_empty_output_keeps_the_code_and_the_parse_error() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("exit {EXIT_CODE}"))?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(matches!(
        result,
        Err(RunError::Failed {
            code: Some(EXIT_CODE),
            source: Some(SbomError::Json(_))
        })
    ));
    Ok(())
}


#[test]
fn outcome_priorities() -> TestResult {
    let failed = ExitStatus::from_raw(EXIT_CODE << EXIT_SHIFT);
    let clean = ExitStatus::from_raw(0);
    let unreadable = || Ok(Err(SbomError::Read(io::Error::from(io::ErrorKind::BrokenPipe))));
    assert!(matches!(
        outcome(false, Err(RecvTimeoutError::Disconnected), clean),
        Err(RunError::TimedOut)
    ));
    assert!(matches!(outcome(true, unreadable(), failed), Err(RunError::TimedOut)));
    assert!(matches!(
        outcome(false, unreadable(), failed),
        Err(RunError::Failed {
            code: Some(EXIT_CODE),
            source: Some(_)
        })
    ));
    assert!(matches!(outcome(false, unreadable(), clean), Err(RunError::Sbom(SbomError::Read(_)))));
    let too_large = Ok(Err(SbomError::TooLarge { max: 1 }));
    assert!(matches!(
        outcome(false, too_large, failed),
        Err(RunError::Sbom(SbomError::TooLarge { .. }))
    ));
    Ok(())
}


const EXIT_SHIFT: i32 = 8;


const STDERR_TOTAL: u64 = 5;


#[test]
fn stderr_summary_covers_every_case() -> TestResult {
    let kept = Ok(Ok(Stderr {
        kept: b"oops\n".to_vec(),
        total: STDERR_TOTAL,
    }));
    assert_eq!(stderr_summary(&kept), "5 bytes, excerpt `oops\\n`");
    let broken = Ok(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
    assert!(stderr_summary(&broken).starts_with("unreadable"));
    assert!(stderr_summary(&Err(RecvTimeoutError::Timeout)).contains("held open"));
    Ok(())
}


const PID_POLLS: usize = 200;


const PID_POLL_MILLIS: u64 = 10;


fn wait_for_pid_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let found = (0..PID_POLLS).find_map(|_| match fs::read_to_string(path) {
        Ok(text) if text.ends_with('\n') => Some(text),
        _ => {
            std::thread::sleep(std::time::Duration::from_millis(PID_POLL_MILLIS));
            None
        }
    });
    Ok(found.ok_or("no pid file")?.trim().to_owned())
}


fn process_exists(pid: &str) -> bool {
    Path::new("/proc").join(pid).exists()
}


#[test]
fn child_that_left_the_group_is_killed_by_pid_at_the_deadline() -> TestResult {
    let dir = TempDir::new()?;
    let pid_file = dir.path().join("child.pid");
    let body = format!(
        "exec perl -e 'setpgrp(0, getpgrp(getppid())); open(F, \">{}\"); print F \"$$\\n\"; close F; sleep 3600'",
        pid_file.display()
    );
    let binary = fake_syft(&dir, &body)?;
    let result = run(&settings(&dir, binary, DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::TimedOut)));
    assert!(!process_exists(&wait_for_pid_file(&pid_file)?));
    Ok(())
}


#[test]
fn child_that_left_the_group_and_closed_its_pipes_is_killed_by_pid() -> TestResult {
    let dir = TempDir::new()?;
    let pid_file = dir.path().join("child.pid");
    let body = format!(
        "exec perl -e 'setpgrp(0, getpgrp(getppid())); open(F, \">{}\"); print F \"$$\\n\"; close F; close STDOUT; close STDERR; sleep 3600'",
        pid_file.display()
    );
    let binary = fake_syft(&dir, &body)?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Sbom(_))));
    assert!(!process_exists(&wait_for_pid_file(&pid_file)?));
    Ok(())
}


#[test]
fn complete_document_with_a_lingering_child_is_killed_and_reported() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("cat '{FIXTURE}'\nexec 1>&-\nexec 2>&-\nexec sleep 3600"))?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Failed { code: None, source: None })));
    Ok(())
}


fn failing_after(allowed: usize) -> impl FnMut(Job) -> io::Result<()> {
    let mut started = 0;
    move |job| {
        started += 1;
        match started <= allowed {
            true => spawn_thread(job),
            false => Err(io::Error::from(io::ErrorKind::OutOfMemory)),
        }
    }
}


#[test]
fn failed_helper_spawn_kills_the_child_and_returns_the_error() -> TestResult {
    let scope = ("t", "a");
    let outcomes = (0..HELPERS_STARTED).map(|allowed| -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let binary = fake_syft(&dir, "exec sleep 3600")?;
        let configured = settings(&dir, binary, LONG_DEADLINE_MILLIS);
        let result = generate_with(failing_after(allowed), &configured, &fresh_helpers(), &target(), scope);
        assert!(matches!(result, Err(RunError::Io(_))));
        Ok(())
    });
    outcomes.collect::<Result<Vec<()>, _>>()?;
    Ok(())
}


const HELPERS_STARTED: usize = 3;


#[test]
fn abandoned_helper_results_are_logged_not_lost() -> TestResult {
    let lost = RunError::from(SendError(1));
    assert!(matches!(lost, RunError::Abandoned));
    run_job(Box::new(|| Err(RunError::Abandoned)));
    run_job(Box::new(|| Ok(())));
    spawn_thread(Box::new(|| Ok(())))?;
    Ok(())
}
