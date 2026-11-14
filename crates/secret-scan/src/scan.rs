//! Runs gitleaks on one directory under a deadline and parses its report (Unix only: process groups, `O_NOFOLLOW`).

use crate::copy::{
    check_limits, check_work_dir_name, copy_tree, counts_of, create_private, data_path, no_hook, original_path, run_path, write_ignore, CopyLimits,
    GROUP_OTHER_WRITE, IGNORE_FILE_NAME,
};
use crate::error::ReportError;
use crate::model::{Limits, Report, ScanScope};
use crate::report::parse_report_mapped;
use rustix::process::{kill_process, kill_process_group, Pid, Signal};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::debug;


pub const MAX_PATH_BYTES: usize = 4096;


pub const MIN_TIMEOUT_SECONDS: u64 = 1;


pub const MAX_TIMEOUT_SECONDS: u64 = 3600;


pub const MILLIS_PER_SECOND: u64 = 1000;


pub const REAP_POLLS: u64 = 1000;


pub const MIN_POLL_MILLIS: u64 = 1;


pub const MAX_POLL_MILLIS: u64 = 1000;


pub const REPORT_NAME: &str = "report.json";


pub const IGNORE_NAME: &str = "ignore";


pub const NEW_PROCESS_GROUP: i32 = 0;


pub const HARDLINK_SYSCTL: &str = "/proc/sys/fs/protected_hardlinks";


pub const SYSCTL_BYTES: u64 = 16;


/// Where and how the child runs; `expired` is asked at every poll with the private directory (production: `never_expired`).
pub struct RunSettings {
    pub prlimit: PathBuf,
    pub rules: PathBuf,
    pub work_dir: PathBuf,
    pub hardlink_sysctl: PathBuf,
    pub max_memory_bytes: u64,
    pub max_file_bytes: u64,
    pub poll_millis: u64,
    pub expected_uid: u32,
    pub rules_uid: u32,
    pub work_uid: u32,
    pub expired: fn(&Path) -> bool,
    pub copy: CopyLimits,
    pub before_open: fn(&Path),
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
    #[error("refused run settings: {0}")]
    BadSettings(&'static str),
    #[error("refused rules file: {0}")]
    BadRules(&'static str),
    #[error("the scanned tree holds a .gitleaksignore")]
    IgnoreFileInTree,
    #[error("copy limit reached: {0}")]
    CopyLimit(&'static str),
    #[error("an entry name uses the reserved scan prefix")]
    NameClash,
    #[error("fs.protected_hardlinks is not 1")]
    HardlinksUnprotected,
    #[error("{0} findings exceed the limit")]
    TooManyFindings(usize),
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
pub fn run_settings(
    prlimit: PathBuf,
    rules: PathBuf,
    work_dir: PathBuf,
    max_memory_bytes: u64,
    max_file_bytes: u64,
    poll_millis: u64,
) -> RunSettings {
    RunSettings {
        prlimit,
        rules,
        work_dir,
        hardlink_sysctl: PathBuf::from(HARDLINK_SYSCTL),
        max_memory_bytes,
        max_file_bytes,
        poll_millis,
        expected_uid: rustix::process::geteuid().as_raw(),
        rules_uid: rustix::process::geteuid().as_raw(),
        work_uid: rustix::process::geteuid().as_raw(),
        expired: never_expired,
        copy: CopyLimits::default(),
        before_open: no_hook,
    }
}


pub fn ensure(ok: bool, error: ScanError) -> Result<(), ScanError> {
    ok.then_some(()).ok_or(error)
}


/// The launcher is an absolute path (never searched in `PATH`) and the poll interval is 1 to 1 000 ms.
pub fn check_settings(run: &RunSettings) -> Result<(), ScanError> {
    ensure(run.prlimit.is_absolute(), ScanError::BadSettings("prlimit is not absolute"))?;
    ensure(
        (MIN_POLL_MILLIS..=MAX_POLL_MILLIS).contains(&run.poll_millis),
        ScanError::BadSettings("poll_millis out of range"),
    )?;
    check_work_dir_name(&run.work_dir)?;
    check_limits(&run.copy)
}


/// Refuses to run unless the kernel refuses hard links to files the caller does not own, read as a file at the start of every scan.
pub fn check_hardlinks(sysctl: &Path) -> Result<(), ScanError> {
    let mut text = String::new();
    std::fs::File::open(sysctl)?.take(SYSCTL_BYTES).read_to_string(&mut text)?;
    ensure(text.trim() == "1", ScanError::HardlinksUnprotected)
}


/// The gitleaks arguments for one scan: report to a file, and the caller's rules and empty ignore file, never the tree's.
pub fn scan_arguments(path: &Path, report_path: &Path, rules: &Path, ignore_path: &Path) -> Vec<OsString> {
    let flags = ["--report-format", "json", "--report-path"];
    let tail = ["--no-banner", "--redact=0", "--exit-code", "0", "--config"];
    std::iter::once(OsString::from("dir"))
        .chain(std::iter::once(path.as_os_str().to_owned()))
        .chain(flags.iter().map(OsString::from))
        .chain(std::iter::once(report_path.as_os_str().to_owned()))
        .chain(tail.iter().map(OsString::from))
        .chain(std::iter::once(rules.as_os_str().to_owned()))
        .chain(std::iter::once(OsString::from("--gitleaks-ignore-path")))
        .chain(std::iter::once(ignore_path.as_os_str().to_owned()))
        .chain(std::iter::once(OsString::from("--ignore-gitleaks-allow")))
        .collect()
}


/// The rules file: absolute, opened without following a symlink, a regular file of the caller, not writable by group or others.
pub fn check_rules(rules: &Path, expected_uid: u32) -> Result<(), ScanError> {
    ensure(rules.is_absolute(), ScanError::BadRules("not absolute"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(rules)?;
    let metadata = file.metadata()?;
    ensure(metadata.is_file(), ScanError::BadRules("not a regular file"))?;
    ensure(metadata.uid() == expected_uid, ScanError::BadRules("not owned by the caller"))?;
    ensure(
        metadata.mode() & GROUP_OTHER_WRITE == 0,
        ScanError::BadRules("writable by group or others"),
    )
}


/// gitleaks always reads `<tree>/.gitleaksignore` and no flag turns it off, so a tree that holds one is refused.
pub fn check_no_ignore_file(path: &Path) -> Result<(), ScanError> {
    match path.join(IGNORE_FILE_NAME).symlink_metadata() {
        Ok(_) => Err(ScanError::IgnoreFileInTree),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ScanError::Io(error)),
    }
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
    ensure(path.to_str().is_some(), ScanError::BadPath("not UTF-8"))?;
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


/// Kills whatever is left of the child's process group after the child exited; an empty group is the normal case and only logged.
pub fn kill_group_after_exit(pid: Pid) {
    let _group = kill_process_group(pid, Signal::KILL).inspect_err(|error| debug!(error = ?error, "no process group left"));
}


fn spawn_gitleaks(program: &Path, arguments: &[OsString], home: &Path, run: &RunSettings) -> io::Result<Child> {
    let mut command = Command::new(&run.prlimit);
    command
        .arg(format!("--as={}", run.max_memory_bytes))
        .arg(format!("--fsize={}", run.max_file_bytes))
        .arg("--")
        .arg(program)
        .args(arguments)
        .current_dir(home)
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
pub fn read_report(
    report_path: &Path,
    target: &ScanTarget,
    limits: &Limits,
    expected_uid: u32,
    map_path: &dyn Fn(&str) -> String,
) -> Result<Report, ScanError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(report_path)?;
    let metadata = file.metadata()?;
    ensure(metadata.is_file(), ScanError::ReportNotRegular)?;
    ensure(metadata.uid() == expected_uid, ScanError::ReportForeign)?;
    Ok(parse_report_mapped(file, limits, target.tenant, target.scope_id, target.scope, map_path)?)
}


/// What one gitleaks run scans, where it keeps its files, and how reported paths are mapped.
pub struct Pass<'a> {
    pub scan_path: &'a Path,
    pub pass_dir: PathBuf,
    pub map_path: &'a dyn Fn(&str) -> String,
}


/// One gitleaks run with its own private directory `pass_dir`; the report is parsed with `map_path`.
pub fn run_pass(program: &Path, pass: &Pass, target: &ScanTarget, limits: &Limits, ticks: u64, run: &RunSettings) -> Result<Report, ScanError> {
    let Pass {
        scan_path,
        pass_dir,
        map_path,
    } = pass;
    check_no_ignore_file(scan_path)?;
    let report_path = pass_dir.join(REPORT_NAME);
    let ignore_path = pass_dir.join(IGNORE_NAME);
    let arguments = scan_arguments(scan_path, &report_path, &run.rules, &ignore_path);
    let mut child = spawn_gitleaks(program, &arguments, pass_dir, run)?;
    let pid = Pid::from_child(&child);
    let waited = wait_child(&mut child, ticks, run.expired, run, pass_dir)?;
    match waited {
        None => stop_child(&mut child, run, pass_dir).and(Err(ScanError::TimedOut)),
        Some(status) => {
            kill_group_after_exit(pid);
            check_exit(status)?;
            check_no_ignore_file(scan_path)?;
            read_report(&report_path, target, limits, run.expected_uid, map_path)
        }
    }
}


/// `scan_directory` with the deadline in polls: the tree is copied into a private root-owned directory through held handles and the copy is scanned.
pub fn scan_with_ticks(
    program: &Path,
    path: &Path,
    target: &ScanTarget,
    limits: &Limits,
    ticks: u64,
    run: &RunSettings,
) -> Result<Report, ScanError> {
    ensure(program.is_absolute(), ScanError::BadProgram)?;
    check_settings(run)?;
    check_hardlinks(&run.hardlink_sysctl)?;
    check_path(path)?;
    check_rules(&run.rules, run.rules_uid)?;
    let private = create_private(&run.work_dir, run.work_uid)?;
    let started = Instant::now();
    let budget = Duration::from_millis(ticks.saturating_mul(run.poll_millis));
    let expired = || started.elapsed() >= budget || (run.expired)(&private.path);
    let summary = copy_tree(path, &private, &run.copy, run.before_open, &expired)?;
    write_ignore(&private)?;
    let data = data_path(&private);
    let map_path = |file: &str| original_path(file, &data, path, &summary.renamed);
    let pass = Pass {
        scan_path: &data,
        pass_dir: run_path(&private),
        map_path: &map_path,
    };
    let copy = counts_of(&summary);
    run_pass(program, &pass, target, limits, ticks, run).map(|report| Report { copy, ..report })
}


/// Runs gitleaks (`program`, absolute) on `path` for at most `timeout_seconds` (1 to 3 600) per run and parses the report for the target tenant and scope.
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
    check_settings(run)?;
    let ticks = timeout_seconds.saturating_mul(MILLIS_PER_SECOND).div_ceil(run.poll_millis);
    scan_with_ticks(program, path, target, limits, ticks, run)
}
