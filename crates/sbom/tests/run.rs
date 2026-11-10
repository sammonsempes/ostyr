#![cfg(unix)]

#[path = "common/types.rs"]
mod types;


use rustix::process::Pid;
use sbom::error::{ResourceKind, RunError, SbomError, SettingsError, TargetError};
use sbom::model::{Stderr, Verdict, WatchPlan};
use sbom::run::{
    check_archive, child_environment, classify, disk_exceeded, disk_verdict, drain_stderr, entry_bytes, exceeded_limit, generate, generate_with,
    kill_then, outcome, reserve_helpers, run_job, spawn_thread, stderr_excerpt, stderr_summary, watch_plan, watchdog,
};
use sbom::settings::{SyftSettings, Target};
use sbom::types::{Helpers, Job};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{RecvTimeoutError, SendError};
use std::sync::Arc;
use std::time::Duration;
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


const DRAIN_MANY: usize = 100_000;


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
        max_memory_bytes: MEMORY_LIMIT,
        max_file_bytes: FILE_LIMIT,
        max_archive_bytes: ARCHIVE_LIMIT,
        max_run_disk_bytes: DISK_LIMIT,
        max_run_entries: ENTRY_LIMIT,
        disk_poll_millis: POLL_MILLIS,
        prlimit_binary: PathBuf::from(PRLIMIT),
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


const MEMORY_LIMIT: u64 = 1_073_741_824;


const DISK_LIMIT: u64 = 1_048_576;


const ENTRY_LIMIT: usize = 1000;


const POLL_MILLIS: u64 = 10;


const PRLIMIT: &str = "/usr/bin/prlimit";


const FILE_LIMIT: u64 = 1_048_576;


const ARCHIVE_LIMIT: u64 = 1_048_576;


const SMALL_ARCHIVE_LIMIT: u64 = 1000;


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
    let drained = drain_stderr(&mut data.as_slice(), STDERR_CAP)?;
    assert_eq!(drained.kept.len(), STDERR_CAP);
    assert_eq!(drained.total, u64::try_from(DOUBLE_STDERR)?);
    let mut ordered = vec![b'a'; STDERR_CAP];
    ordered.extend(vec![b'z'; STDERR_CAP]);
    let tail = drain_stderr(&mut ordered.as_slice(), STDERR_CAP)?;
    assert_eq!(tail.kept, vec![b'z'; STDERR_CAP]);
    assert_eq!(tail.total, u64::try_from(DOUBLE_STDERR)?);
    let many_chunks = vec![b'q'; DRAIN_MANY];
    assert_eq!(drain_stderr(&mut many_chunks.as_slice(), STDERR_CAP)?.total, u64::try_from(DRAIN_MANY)?);
    Ok(())
}


#[test]
fn excerpt_is_bounded_and_escaped() -> TestResult {
    let mut kept = vec![b'y'; LONG_STDERR];
    kept.extend(b"line\nnext\x1b[31m");
    let excerpt = stderr_excerpt(&Stderr { kept, total: 0 });
    assert!(excerpt.ends_with("line\\nnext\\u{1b}[31m"));
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
    assert!(drain_stderr(&mut Failing, STDERR_CAP).is_err());
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
fn non_executable_binary_fails_to_run_and_non_executable_prlimit_fails_to_spawn() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("plain");
    fs::write(&path, "x")?;
    let unusable = run(&settings(&dir, path.clone(), LONG_DEADLINE_MILLIS));
    assert!(matches!(unusable, Err(RunError::Failed { code: Some(_), .. })), "{unusable:?}");
    let binary = fake_syft(&dir, "exit 0")?;
    let mut configured = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    configured.prlimit_binary = path;
    assert!(matches!(run(&configured), Err(RunError::Io(_))));
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


const HOLDER_ATTEMPTS: usize = 20;


fn kill_holder(pid_file: &Path) -> TestResult {
    let holder = fs::read_to_string(pid_file)?;
    Command::new("kill").arg(holder.trim()).status()?;
    Ok(())
}


fn holder_attempt(limited: &SyftSettings, pid_file: &Path) -> Result<Option<Helpers>, Box<dyn std::error::Error>> {
    if pid_file.exists() {
        fs::remove_file(pid_file)?;
    }
    let helpers = fresh_helpers();
    let first = generate(limited, &helpers, &target(), "t", "a");
    let held = matches!(first, Err(RunError::TimedOut)) && helpers.load(Ordering::SeqCst) == HOLDER_LIVE_HELPERS;
    if !held && pid_file.exists() {
        kill_holder(pid_file)?;
    }
    Ok(held.then_some(helpers))
}


#[test]
fn setsid_holder_of_the_pipes_cannot_stall_the_run_or_pile_up_helpers() -> TestResult {
    let dir = TempDir::new()?;
    let pid_file = dir.path().join("holder.pid");
    let binary = fake_syft(&dir, &format!("setsid sleep 3600 &\necho $! > '{}'\nexec sleep 3600", pid_file.display()))?;
    let mut limited = settings(&dir, binary, DEADLINE_MILLIS);
    limited.max_live_helpers = HOLDER_LIVE_HELPERS;
    let held = (0..HOLDER_ATTEMPTS).try_fold(None, |found, _| match found {
        Some(helpers) => Ok::<_, Box<dyn std::error::Error>>(Some(helpers)),
        None => holder_attempt(&limited, &pid_file),
    })?;
    let helpers = held.ok_or("the holder never outlived the deadline")?;
    let second = generate(&limited, &helpers, &target(), "t", "a");
    assert!(matches!(second, Err(RunError::Busy)));
    kill_holder(&pid_file)?;
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


const KIBIBYTES: u64 = 1024;


const BIG_ALLOCATION: &str = "3000000000";


const ARCHIVE_BYTES: usize = 2000;


const XFSZ_SIGNAL: i32 = 25;


const EXIT_ONE_STATUS: i32 = 256;


fn work_dir_leftovers(dir: &TempDir) -> io::Result<usize> {
    Ok(fs::read_dir(dir.path())?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("syft-"))
        .count())
}


#[test]
fn the_child_runs_under_the_configured_address_space_limit() -> TestResult {
    let dir = TempDir::new()?;
    let body = "printf '{\"components\":[{\"name\":\"%s\"}]}' \"$(ulimit -v)\"";
    let binary = fake_syft(&dir, body)?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    let name = sbom.components.first().map(|component| component.name.clone());
    assert_eq!(name, Some((MEMORY_LIMIT / KIBIBYTES).to_string()));
    Ok(())
}


#[test]
fn allocating_past_the_limit_is_a_typed_memory_error_and_the_home_is_removed() -> TestResult {
    let dir = TempDir::new()?;
    let body = format!("head -c {BIG_ALLOCATION} /dev/zero | tr '\\0' x | tail -n 1");
    let binary = fake_syft(&dir, &body)?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(
        matches!(
            result,
            Err(RunError::ResourceLimit {
                kind: ResourceKind::Memory,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(work_dir_leftovers(&dir)?, 0);
    Ok(())
}


#[test]
fn writing_past_the_limit_is_a_typed_file_error_and_the_home_is_removed() -> TestResult {
    let dir = TempDir::new()?;
    let body = "exec dd if=/dev/zero of=\"$HOME/big\" bs=1M count=8";
    let binary = fake_syft(&dir, body)?;
    let mut limited = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    limited.max_run_disk_bytes = HUGE_DISK;
    let result = run(&limited);
    assert!(
        matches!(
            result,
            Err(RunError::ResourceLimit {
                kind: ResourceKind::FileSize,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(work_dir_leftovers(&dir)?, 0);
    Ok(())
}


#[test]
fn archives_are_checked_on_the_opened_handle() -> TestResult {
    let dir = TempDir::new()?;
    let archive = dir.path().join("image.tar");
    fs::write(&archive, vec![b'a'; ARCHIVE_BYTES])?;
    let oversize = check_archive(&Target::OciArchive(archive.clone()), SMALL_ARCHIVE_LIMIT);
    assert!(matches!(
        oversize,
        Err(RunError::ResourceLimit {
            kind: ResourceKind::Archive,
            ..
        })
    ));
    assert!(check_archive(&Target::DockerArchive(archive.clone()), u64::try_from(ARCHIVE_BYTES)?).is_ok());
    assert!(check_archive(&Target::Directory(archive), 0).is_ok());
    assert!(matches!(
        check_archive(&Target::OciArchive(dir.path().to_path_buf()), 1),
        Err(RunError::NotRegular)
    ));
    let fifo = dir.path().join("pipe.tar");
    rustix::fs::mknodat(rustix::fs::CWD, &fifo, rustix::fs::FileType::Fifo, rustix::fs::Mode::RUSR, 0)?;
    assert!(matches!(check_archive(&Target::DockerArchive(fifo), 1), Err(RunError::NotRegular)));
    assert!(matches!(
        check_archive(&Target::OciArchive(dir.path().join("absent")), 1),
        Err(RunError::Io(_))
    ));
    Ok(())
}


#[test]
fn an_oversize_archive_never_spawns() -> TestResult {
    let dir = TempDir::new()?;
    let archive = dir.path().join("image.tar");
    fs::File::create(&archive)?.set_len(ARCHIVE_LIMIT + 1)?;
    let binary = fake_syft(&dir, "exit 0")?;
    let result = generate(
        &settings(&dir, binary, LONG_DEADLINE_MILLIS),
        &fresh_helpers(),
        &Target::OciArchive(archive),
        "t",
        "a",
    );
    assert!(matches!(
        result,
        Err(RunError::ResourceLimit {
            kind: ResourceKind::Archive,
            ..
        })
    ));
    assert_eq!(work_dir_leftovers(&dir)?, 0);
    Ok(())
}


#[test]
fn limit_classification() -> TestResult {
    let ok = ExitStatus::from_raw(0);
    let failed = ExitStatus::from_raw(EXIT_ONE_STATUS);
    let xfsz = ExitStatus::from_raw(XFSZ_SIGNAL);
    assert_eq!(exceeded_limit(ok, b"out of memory"), None);
    assert_eq!(exceeded_limit(xfsz, b""), Some(ResourceKind::FileSize));
    assert_eq!(exceeded_limit(failed, b"write: File too large"), Some(ResourceKind::FileSize));
    assert_eq!(exceeded_limit(failed, b"fatal error: runtime: Out Of Memory"), Some(ResourceKind::Memory));
    assert_eq!(exceeded_limit(failed, b"mmap: cannot allocate memory"), Some(ResourceKind::Memory));
    assert_eq!(
        exceeded_limit(failed, b"fatal error: failed to reserve page summary memory"),
        Some(ResourceKind::Memory)
    );
    assert_eq!(
        exceeded_limit(failed, b"runtime: allocating heap arena failed"),
        Some(ResourceKind::Memory)
    );
    assert_eq!(exceeded_limit(failed, b"something else"), None);
    assert!(matches!(
        classify(Err(RunError::TimedOut), Some(ResourceKind::Memory)),
        Err(RunError::TimedOut)
    ));
    assert!(matches!(
        classify(Err(RunError::Abandoned), Some(ResourceKind::Memory)),
        Err(RunError::ResourceLimit {
            kind: ResourceKind::Memory,
            ..
        })
    ));
    assert!(matches!(classify(Err(RunError::Abandoned), None), Err(RunError::Abandoned)));
    Ok(())
}


const WRITE_STEPS: &str = "for i in 1 2 3 4; do dd if=/dev/zero of=\"$TMPDIR/f$i\" bs=1k count=512 2>/dev/null; done\nexec sleep 3600";


const MANY_FILES: &str = "for i in 1 2 3 4 5 6; do : > \"$TMPDIR/f$i\"; done\nexec sleep 3600";


const SMALL_ENTRY_LIMIT: usize = 3;


const BIG_FILE_BYTES: usize = 600_000;


const KILL_SIGNAL: i32 = 9;


const TICKS: u64 = 3;


const TINY_DISK: u64 = 1000;


const HUGE_DISK: u64 = 1_099_511_627_776;


const TWO_ENTRIES: usize = 2;


const THREE_TICKS_MILLIS: u64 = 25;


const SHORT_MILLIS: u64 = 5;


const TICK: Duration = Duration::from_millis(POLL_MILLIS);


fn plan(home: &Path, ticks: u64, max_bytes: u64, max_entries: usize) -> WatchPlan {
    WatchPlan {
        home: home.to_path_buf(),
        tick: TICK,
        ticks,
        max_bytes,
        max_entries,
    }
}


fn sleeper() -> io::Result<Child> {
    Command::new("sleep").arg("3600").spawn()
}


fn killed(mut child: Child) -> TestResult {
    assert_eq!(child.wait()?.signal(), Some(KILL_SIGNAL));
    Ok(())
}


fn killed_by_hand(mut child: Child) -> TestResult {
    child.kill()?;
    child.wait()?;
    Ok(())
}


#[test]
fn writing_past_the_disk_bound_is_a_typed_disk_error_and_the_home_is_removed() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, WRITE_STEPS)?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(
        matches!(
            result,
            Err(RunError::ResourceLimit {
                kind: ResourceKind::Disk,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(work_dir_leftovers(&dir)?, 0);
    Ok(())
}


#[test]
fn too_many_entries_in_the_home_is_a_typed_disk_error() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, MANY_FILES)?;
    let mut limited = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    limited.max_run_entries = SMALL_ENTRY_LIMIT;
    let result = run(&limited);
    assert!(
        matches!(
            result,
            Err(RunError::ResourceLimit {
                kind: ResourceKind::Disk,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(work_dir_leftovers(&dir)?, 0);
    Ok(())
}


#[test]
fn the_child_temporary_directory_is_its_private_home() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "printf '{\"components\":[{\"name\":\"%s\"}]}' \"$TMPDIR\"")?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    let name = sbom.components.first().map(|component| component.name.clone()).ok_or("no component")?;
    assert!(name.starts_with(&format!("{}/syft-", dir.path().display())), "{name}");
    Ok(())
}


#[test]
fn the_limits_are_in_force_from_the_first_instruction() -> TestResult {
    let dir = TempDir::new()?;
    let body = "printf '{\"components\":[{\"name\":\"%s\"}]}' \"$(ulimit -v)\"";
    let binary = fake_syft(&dir, body)?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    let name = sbom.components.first().map(|component| component.name.clone());
    assert_eq!(name, Some((MEMORY_LIMIT / KIBIBYTES).to_string()));
    Ok(())
}


#[test]
fn only_the_kept_tail_of_stderr_classifies_a_failure() -> TestResult {
    let dir = TempDir::new()?;
    let early = fake_syft(&dir, "echo 'out of memory' >&2\nyes noise | head -c 5000 >&2\nexit 1")?;
    let ignored = run(&settings(&dir, early, LONG_DEADLINE_MILLIS));
    assert!(matches!(ignored, Err(RunError::Failed { code: Some(1), .. })), "{ignored:?}");
    let late = fake_syft(&dir, "yes noise | head -c 5000 >&2\necho 'failed to reserve' >&2\nexit 1")?;
    let found = run(&settings(&dir, late, LONG_DEADLINE_MILLIS));
    assert!(
        matches!(
            found,
            Err(RunError::ResourceLimit {
                kind: ResourceKind::Memory,
                ..
            })
        ),
        "{found:?}"
    );
    Ok(())
}


#[test]
fn a_missing_or_irregular_prlimit_refuses_the_run() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "exit 0")?;
    let mut configured = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    configured.prlimit_binary = dir.path().join("absent");
    assert!(matches!(run(&configured), Err(RunError::Io(_))));
    configured.prlimit_binary = dir.path().to_path_buf();
    assert!(matches!(run(&configured), Err(RunError::NotRegular)));
    assert_eq!(work_dir_leftovers(&dir)?, 0);
    Ok(())
}


#[test]
fn the_walk_measures_blocks_and_entries_and_stops_at_the_cap() -> TestResult {
    let dir = TempDir::new()?;
    fs::write(dir.path().join("big"), vec![b'a'; BIG_FILE_BYTES])?;
    assert!(disk_exceeded(dir.path(), TINY_DISK, ENTRY_LIMIT)?);
    assert!(!disk_exceeded(dir.path(), HUGE_DISK, ENTRY_LIMIT)?);
    assert!(!disk_exceeded(dir.path(), HUGE_DISK, TWO_ENTRIES)?);
    assert!(disk_exceeded(dir.path(), HUGE_DISK, 1)?);
    assert!(matches!(
        disk_exceeded(&dir.path().join("big").join("under"), 1, 1),
        Err(RunError::Walk(_))
    ));
    Ok(())
}


#[test]
fn a_vanished_entry_counts_as_nothing_and_other_walk_errors_are_typed() -> TestResult {
    let dir = TempDir::new()?;
    let file = dir.path().join("file");
    fs::write(&file, "x")?;
    let vanished = walkdir::WalkDir::new(dir.path().join("absent")).into_iter().next().ok_or("no entry")?;
    assert_eq!(entry_bytes(vanished)?, 0);
    let broken = walkdir::WalkDir::new(file.join("under")).into_iter().next().ok_or("no entry")?;
    assert!(matches!(entry_bytes(broken), Err(RunError::Walk(_))));
    let present = walkdir::WalkDir::new(&file).into_iter().next().ok_or("no entry")?;
    assert!(entry_bytes(present)? > 0);
    Ok(())
}


#[test]
fn the_watchdog_decides_on_close_disk_overrun_and_ticks_out() -> TestResult {
    let dir = TempDir::new()?;
    let (closed_sender, closed_receiver) = mpsc::channel::<()>();
    drop(closed_sender);
    let finished = sleeper()?;
    let finished_verdict = watchdog(
        Pid::from_child(&finished),
        &closed_receiver,
        &plan(dir.path(), TICKS, DISK_LIMIT, ENTRY_LIMIT),
    )?;
    assert_eq!(finished_verdict, Verdict::Finished);
    killed_by_hand(finished)?;
    let (_held_sender, held_receiver) = mpsc::channel::<()>();
    let timed_out = sleeper()?;
    let timed_out_verdict = watchdog(
        Pid::from_child(&timed_out),
        &held_receiver,
        &plan(dir.path(), TICKS, DISK_LIMIT, ENTRY_LIMIT),
    )?;
    assert_eq!(timed_out_verdict, Verdict::TimedOut);
    killed(timed_out)?;
    fs::write(dir.path().join("big"), vec![b'a'; BIG_FILE_BYTES])?;
    let full = sleeper()?;
    let full_verdict = watchdog(Pid::from_child(&full), &held_receiver, &plan(dir.path(), TICKS, TINY_DISK, ENTRY_LIMIT))?;
    assert_eq!(full_verdict, Verdict::DiskFull);
    killed(full)?;
    let broken = sleeper()?;
    let under = dir.path().join("big").join("under");
    let failed = watchdog(Pid::from_child(&broken), &held_receiver, &plan(&under, TICKS, DISK_LIMIT, ENTRY_LIMIT));
    assert!(matches!(failed, Err(RunError::Walk(_))));
    killed(broken)
}


#[test]
fn killing_a_reaped_pid_is_an_error() -> TestResult {
    let mut child = Command::new("true").spawn()?;
    let pid = Pid::from_child(&child);
    child.wait()?;
    assert!(matches!(kill_then(pid, Ok(Verdict::Finished)), Err(RunError::Signal(_))));
    Ok(())
}


#[test]
fn the_watch_schedule_covers_the_deadline_with_ticks_no_longer_than_it() -> TestResult {
    let dir = TempDir::new()?;
    let mut configured = settings(&dir, PathBuf::from("/bin/true"), LONG_DEADLINE_MILLIS);
    configured.disk_poll_millis = POLL_MILLIS;
    configured.deadline_millis = THREE_TICKS_MILLIS;
    let spread = watch_plan(&configured, dir.path());
    assert_eq!((spread.tick, spread.ticks), (TICK, TICKS));
    assert_eq!((spread.max_bytes, spread.max_entries), (DISK_LIMIT, ENTRY_LIMIT));
    configured.deadline_millis = SHORT_MILLIS;
    let short = watch_plan(&configured, dir.path());
    assert_eq!((short.tick, short.ticks), (Duration::from_millis(SHORT_MILLIS), 1));
    configured.deadline_millis = 0;
    assert_eq!(watch_plan(&configured, dir.path()).ticks, 0);
    Ok(())
}


#[test]
fn a_disk_overrun_replaces_the_result_and_keeps_it_as_the_cause() -> TestResult {
    let replaced = disk_verdict(Verdict::DiskFull, Err(RunError::Abandoned));
    assert!(matches!(
        &replaced,
        Err(RunError::ResourceLimit { kind: ResourceKind::Disk, cause: Some(inner) }) if matches!(inner.as_ref(), RunError::Abandoned)
    ));
    assert!(matches!(disk_verdict(Verdict::Finished, Err(RunError::Busy)), Err(RunError::Busy)));
    assert!(matches!(
        disk_verdict(Verdict::TimedOut, Err(RunError::TimedOut)),
        Err(RunError::TimedOut)
    ));
    Ok(())
}
