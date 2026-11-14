//! Runs gitleaks on one directory under a deadline and parses its report (Unix only: process groups, `O_NOFOLLOW`).

use crate::error::ReportError;
use crate::model::{Limits, Report, ScanScope};
use crate::report::parse_report;
use rustix::process::{kill_process, kill_process_group, Pid, Signal};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use thiserror::Error;
use tracing::debug;


pub const MAX_PATH_BYTES: usize = 4096;


pub const MIN_TIMEOUT_SECONDS: u64 = 1;


pub const MAX_TIMEOUT_SECONDS: u64 = 3600;


pub const MILLIS_PER_SECOND: u64 = 1000;


pub const REAP_POLLS: u64 = 100;


pub const DIR_PREFIX: &str = "secret-scan-";


pub const REPORT_NAME: &str = "report.json";


pub const NEW_PROCESS_GROUP: i32 = 0;


/// Where and how the child runs; `expired` is asked at every poll with the private directory (production: `never_expired`).
pub struct RunSettings {
    pub prlimit: PathBuf,
    pub work_dir: PathBuf,
    pub max_memory_bytes: u64,
    pub max_file_bytes: u64,
    pub poll_millis: u64,
    pub expected_uid: u32,
    pub expired: fn(&Path) -> bool,
}


/// Tenant and scan scope of one run, copied into the report.
#[derive(Debug, Clone, Copy)]
pub struct ScanTarget<'a> {
    pub tenant: &'a str,
    pub scope_id: &'a str,
    pub scope: &'a ScanScope,
}


#[derive(Debug, Error)]
pub enum ScanError {
    #[error("scan timed out")]
    TimedOut,
    #[error("gitleaks failed with code {0:?}")]
    Failed(Option<i32>),
    #[error("gitleaks hit a resource limit")]
    ResourceLimit,
    #[error("refused scan path: {0}")]
    BadPath(&'static str),
    #[error("program must be an absolute path")]
    BadProgram,
    #[error("timeout must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds")]
    BadTimeout,
    #[error("report is not a regular file")]
    ReportNotRegular,
    #[error("report is not owned by the caller")]
    ReportForeign,
    #[error("timed-out child could not be reaped")]
    Unreaped,
    #[error("report: {0}")]
    Report(#[from] ReportError),
    #[error("scan i/o: {0}")]
    Io(#[from] io::Error),
}


/// The production deadline test: never early, the tick count alone ends the run.
pub fn never_expired(_dir: &Path) -> bool {
    false
}


/// Settings for production: the caller's own uid owns the report, the deadline is the tick count.
pub fn run_settings(prlimit: PathBuf, work_dir: PathBuf, max_memory_bytes: u64, max_file_bytes: u64, poll_millis: u64) -> RunSettings {
    RunSettings {
        prlimit,
        work_dir,
        max_memory_bytes,
        max_file_bytes,
        poll_millis,
        expected_uid: rustix::process::geteuid().as_raw(),
        expired: never_expired,
    }
}


fn ensure(ok: bool, error: ScanError) -> Result<(), ScanError> {
    ok.then_some(()).ok_or(error)
}


/// The gitleaks arguments for one directory scan; the report goes to a file, nothing to stdout.
pub fn scan_arguments(path: &Path, report_path: &Path) -> Vec<OsString> {
    let flags = ["--report-format", "json", "--report-path"];
    let tail = ["--no-banner", "--redact=0", "--exit-code", "0"];
    std::iter::once(OsString::from("dir"))
        .chain(std::iter::once(path.as_os_str().to_owned()))
        .chain(flags.iter().map(OsString::from))
        .chain(std::iter::once(report_path.as_os_str().to_owned()))
        .chain(tail.iter().map(OsString::from))
        .collect()
}


/// Absolute, normalised, no component starting with `-`, at most `MAX_PATH_BYTES`, an existing directory.
pub fn check_path(path: &Path) -> Result<(), ScanError> {
    ensure(path.is_absolute(), ScanError::BadPath("not absolute"))?;
    ensure(path.as_os_str().len() <= MAX_PATH_BYTES, ScanError::BadPath("too long"))?;
    ensure(
        path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        ScanError::BadPath("not normalised"),
    )?;
    ensure(
        path.components().all(|part| !part.as_os_str().as_encoded_bytes().starts_with(b"-")),
        ScanError::BadPath("component starts with a dash"),
    )?;
    ensure(path.is_dir(), ScanError::BadPath("not a directory"))
}


/// The only variables the child sees: a private home and temporary directory.
pub fn child_environment(home: &Path) -> Vec<(&'static str, OsString)> {
    ["HOME", "TMPDIR"].into_iter().map(|name| (name, home.as_os_str().to_owned())).collect()
}


/// Kills the child by pid and its group; a missing group is expected and only logged.
pub fn kill_all(pid: Pid) -> Result<(), rustix::io::Errno> {
    let _group = kill_process_group(pid, Signal::KILL).inspect_err(|error| debug!(error = ?error, "no process group to kill"));
    kill_process(pid, Signal::KILL)
}


fn spawn_gitleaks(program: &Path, path: &Path, report_path: &Path, home: &Path, run: &RunSettings) -> io::Result<Child> {
    let mut command = Command::new(&run.prlimit);
    command
        .arg(format!("--as={}", run.max_memory_bytes))
        .arg(format!("--fsize={}", run.max_file_bytes))
        .arg("--")
        .arg(program)
        .args(scan_arguments(path, report_path))
        .env_clear()
        .envs(child_environment(home))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(NEW_PROCESS_GROUP);
    command.spawn()
}


/// Polls the child up to `ticks` times; `None` when it still runs after the last poll or when `expired` says so.
pub fn wait_child(child: &mut Child, ticks: u64, expired: fn(&Path) -> bool, run: &RunSettings, home: &Path) -> io::Result<Option<ExitStatus>> {
    (0..ticks)
        .find_map(|_| match child.try_wait() {
            Ok(None) if expired(home) => Some(Ok(None)),
            Ok(None) => {
                thread::sleep(Duration::from_millis(run.poll_millis));
                None
            }
            other => Some(other),
        })
        .unwrap_or(Ok(None))
}


fn stop_child(child: &mut Child, run: &RunSettings, home: &Path) -> Result<(), ScanError> {
    kill_all(Pid::from_child(child)).map_err(io::Error::from)?;
    let reaped = wait_child(child, REAP_POLLS, never_expired, run, home)?.is_some();
    ensure(reaped, ScanError::Unreaped)
}


/// A success is exit 0; a death by SIGXFSZ is the file-size limit; anything else is `Failed`.
pub fn check_exit(status: ExitStatus) -> Result<(), ScanError> {
    match (status.success(), status.signal()) {
        (true, _) => Ok(()),
        (false, Some(libc::SIGXFSZ)) => Err(ScanError::ResourceLimit),
        _ => Err(ScanError::Failed(status.code())),
    }
}


/// Opens the report with `O_NOFOLLOW | O_NONBLOCK`, checks the opened handle (regular file, owner) and parses that same handle.
pub fn read_report(report_path: &Path, target: &ScanTarget, limits: &Limits, expected_uid: u32) -> Result<Report, ScanError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(report_path)?;
    let metadata = file.metadata()?;
    ensure(metadata.is_file(), ScanError::ReportNotRegular)?;
    ensure(metadata.uid() == expected_uid, ScanError::ReportForeign)?;
    Ok(parse_report(file, limits, target.tenant, target.scope_id, target.scope)?)
}


/// `scan_directory` with the deadline given as a number of polls; the private directory is removed on drop.
pub fn scan_with_ticks(
    program: &Path,
    path: &Path,
    target: &ScanTarget,
    limits: &Limits,
    ticks: u64,
    run: &RunSettings,
) -> Result<Report, ScanError> {
    ensure(program.is_absolute(), ScanError::BadProgram)?;
    check_path(path)?;
    let dir: TempDir = tempfile::Builder::new().prefix(DIR_PREFIX).tempdir_in(&run.work_dir)?;
    let report_path = dir.path().join(REPORT_NAME);
    let mut child = spawn_gitleaks(program, path, &report_path, dir.path(), run)?;
    match wait_child(&mut child, ticks, run.expired, run, dir.path())? {
        None => stop_child(&mut child, run, dir.path()).and(Err(ScanError::TimedOut)),
        Some(status) => {
            check_exit(status)?;
            read_report(&report_path, target, limits, run.expected_uid)
        }
    }
}


/// Runs gitleaks (`program`, absolute) on `path` for at most `timeout_seconds` (1 to 3 600) and parses the report for the target tenant and scope.
pub fn scan_directory(
    program: &Path,
    path: &Path,
    target: &ScanTarget,
    limits: &Limits,
    timeout_seconds: u64,
    run: &RunSettings,
) -> Result<Report, ScanError> {
    ensure(
        (MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds),
        ScanError::BadTimeout,
    )?;
    let ticks = timeout_seconds.saturating_mul(MILLIS_PER_SECOND).div_ceil(run.poll_millis.max(1));
    scan_with_ticks(program, path, target, limits, ticks, run)
}
