//! Runs gitleaks on one directory under a deadline and parses its report (Unix only: process groups, `O_NOFOLLOW`).

use crate::allow::{checked_rules, read_rules};
use crate::copy::{
    check_limits, copy_tree, counts_of, create_private, data_path, no_hook, original_path, run_path, write_file, write_ignore, CopyLimits,
    IGNORE_FILE_NAME, TREE_DIR,
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


pub const CONFIG_NAME: &str = "config.toml";


pub const NEW_PROCESS_GROUP: i32 = 0;


pub const NAMESPACE_FLAGS: [&str; 5] = ["--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts", "--unshare-cgroup"];


pub const LIBRARY_DIRS: [&str; 3] = ["/usr", "/lib", "/lib64"];


pub const HARDLINK_SYSCTL: &str = "/proc/sys/fs/protected_hardlinks";


pub const SYSCTL_BYTES: u64 = 16;


pub const FUSE_CONF: &str = "/etc/fuse.conf";


pub const FUSE_CONF_BYTES: u64 = 65536;


pub const FUSE_SYS_ADMIN: &str = "/sys/module/fuse/parameters/allow_sys_admin_access";


pub const FUSE_SYS_ADMIN_BYTES: u64 = 16;


pub const FUSE_ALLOW_OTHER: &[u8] = b"user_allow_other";


/// Where and how the child runs; `expired` is asked at every poll with the private directory (production: `never_expired`).
pub struct RunSettings {
    pub prlimit: PathBuf,
    pub bwrap: PathBuf,
    pub rules: PathBuf,
    pub work_dir: PathBuf,
    pub hardlink_sysctl: PathBuf,
    pub fuse_conf: PathBuf,
    pub fuse_sys_admin: PathBuf,
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
    #[error("the sandbox launcher is missing: nothing was scanned")]
    NoSandbox,
    #[error("refused rules file key: {0}")]
    BadRulesKey(String),
    #[error("the scanned tree holds a .gitleaksignore")]
    IgnoreFileInTree,
    #[error("copy limit reached: {0}")]
    CopyLimit(&'static str),
    #[error("an entry name uses the reserved scan prefix")]
    NameClash,
    #[error("fs.protected_hardlinks is not 1")]
    HardlinksUnprotected,
    #[error("fuse.conf allows other users to share FUSE mounts: a stopped daemon would hang the copy")]
    FuseAllowOther,
    #[error("fuse allow_sys_admin_access is not N: root could be blocked by a user's stopped FUSE daemon")]
    FuseSysAdminAccess,
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
    bwrap: PathBuf,
    rules: PathBuf,
    work_dir: PathBuf,
    max_memory_bytes: u64,
    max_file_bytes: u64,
    poll_millis: u64,
) -> RunSettings {
    RunSettings {
        prlimit,
        bwrap,
        rules,
        work_dir,
        hardlink_sysctl: PathBuf::from(HARDLINK_SYSCTL),
        fuse_conf: PathBuf::from(FUSE_CONF),
        fuse_sys_admin: PathBuf::from(FUSE_SYS_ADMIN),
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
    ensure(run.bwrap.is_absolute(), ScanError::BadSettings("bwrap is not absolute"))?;
    ensure(
        (MIN_POLL_MILLIS..=MAX_POLL_MILLIS).contains(&run.poll_millis),
        ScanError::BadSettings("poll_millis out of range"),
    )?;
    check_limits(&run.copy)
}


/// Refuses to run unless the kernel refuses hard links to files the caller does not own, read as a file at the start of every scan.
pub fn check_hardlinks(sysctl: &Path) -> Result<(), ScanError> {
    let mut text = String::new();
    std::fs::File::open(sysctl)?.take(SYSCTL_BYTES).read_to_string(&mut text)?;
    ensure(text.trim() == "1", ScanError::HardlinksUnprotected)
}


/// Refuses to run when `fuse.conf` holds an uncommented `user_allow_other`: the kernel then lets root read a user's FUSE mount, and a stopped daemon blocks it.
pub fn check_fuse(conf: &Path) -> Result<(), ScanError> {
    match std::fs::File::open(conf) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(FUSE_CONF_BYTES + 1).read_to_end(&mut bytes)?;
            ensure(bytes.len() as u64 <= FUSE_CONF_BYTES, ScanError::BadSettings("fuse.conf is too large"))?;
            ensure(
                !bytes
                    .split(|byte| *byte == b'\n')
                    .any(|line| line.trim_ascii().starts_with(FUSE_ALLOW_OTHER)),
                ScanError::FuseAllowOther,
            )
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ScanError::Io(error)),
    }
}


/// Refuses to run unless the fuse module parameter `allow_sys_admin_access` is `N` (a missing file means no fuse module, accepted).
pub fn check_fuse_sys_admin(parameter: &Path) -> Result<(), ScanError> {
    match std::fs::File::open(parameter) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(FUSE_SYS_ADMIN_BYTES + 1).read_to_end(&mut bytes)?;
            ensure(
                bytes.len() as u64 <= FUSE_SYS_ADMIN_BYTES && bytes.trim_ascii() == b"N",
                ScanError::FuseSysAdminAccess,
            )
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ScanError::Io(error)),
    }
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


/// The sandbox launcher must exist as a file: a missing one is a fixed error and never a fallback to scanning the copy at its private path.
pub fn check_bwrap(bwrap: &Path) -> Result<(), ScanError> {
    let found = std::fs::metadata(bwrap)
        .inspect_err(|error| debug!(error = ?error, "sandbox launcher not found"))
        .is_ok_and(|metadata| metadata.is_file());
    ensure(found, ScanError::NoSandbox)
}


/// The system directories that exist on this host among `candidates`: bound read-only into the sandbox, nothing else of the host is.
pub fn library_dirs(candidates: &[&str]) -> Vec<PathBuf> {
    candidates.iter().map(PathBuf::from).filter(|dir| dir.exists()).collect()
}


/// The ancestors of `original` below `/`, outermost first: they exist inside the sandbox only, as empty directories of its own tmpfs root.
pub fn sandbox_ancestors(original: &Path) -> Vec<&Path> {
    let mut ancestors: Vec<&Path> = original.ancestors().skip(1).filter(|ancestor| ancestor.parent().is_some()).collect();
    ancestors.reverse();
    ancestors
}


/// The bwrap arguments up to the program: an own `tmpfs` root, only the system directories and the program bound read-only, the copy at the original path.
pub fn bwrap_arguments(program: &Path, libraries: &[PathBuf], copy: &Path, original: &Path, run_dir: &Path) -> Vec<OsString> {
    let os = |text: &str| OsString::from(text);
    let path = |value: &Path| value.as_os_str().to_owned();
    let read_only = |source: &Path, target: &Path| [os("--ro-bind"), path(source), path(target)];
    [os("--tmpfs"), os("/"), os("--cap-drop"), os("ALL")]
        .into_iter()
        .chain(sandbox_ancestors(original).into_iter().flat_map(|ancestor| [os("--dir"), path(ancestor)]))
        .chain(libraries.iter().flat_map(|library| read_only(library, library)))
        .chain([os("--dev"), os("/dev"), os("--proc"), os("/proc")])
        .chain(read_only(program, program))
        .chain(read_only(copy, original))
        .chain([os("--bind"), path(run_dir), path(run_dir)])
        .chain(NAMESPACE_FLAGS.iter().chain(["--die-with-parent", "--"].iter()).map(|flag| os(flag)))
        .collect()
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


fn spawn_gitleaks(program: &Path, sandbox: &[OsString], arguments: &[OsString], home: &Path, run: &RunSettings) -> io::Result<Child> {
    let mut command = Command::new(&run.prlimit);
    command
        .arg(format!("--as={}", run.max_memory_bytes))
        .arg(format!("--fsize={}", run.max_file_bytes))
        .arg("--")
        .arg(&run.bwrap)
        .args(sandbox)
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


/// What one gitleaks run scans: the private `copy` seen at the `original` path, where it keeps its files, and how reported paths are mapped.
pub struct Pass<'a> {
    pub copy: PathBuf,
    pub original: &'a Path,
    pub pass_dir: PathBuf,
    pub config: PathBuf,
    pub map_path: &'a dyn Fn(&str) -> String,
}


/// One gitleaks run inside the sandbox, with its own private directory `pass_dir`; the report is parsed with `map_path`.
pub fn run_pass(program: &Path, pass: &Pass, target: &ScanTarget, limits: &Limits, ticks: u64, run: &RunSettings) -> Result<Report, ScanError> {
    let Pass {
        copy,
        original,
        pass_dir,
        config,
        map_path,
    } = pass;
    check_no_ignore_file(copy)?;
    let report_path = pass_dir.join(REPORT_NAME);
    let ignore_path = pass_dir.join(IGNORE_NAME);
    let arguments = scan_arguments(original, &report_path, config, &ignore_path);
    let libraries = library_dirs(&LIBRARY_DIRS);
    let sandbox = bwrap_arguments(program, &libraries, copy, original, pass_dir);
    let mut child = spawn_gitleaks(program, &sandbox, &arguments, pass_dir, run)?;
    let pid = Pid::from_child(&child);
    let waited = wait_child(&mut child, ticks, run.expired, run, pass_dir)?;
    match waited {
        None => stop_child(&mut child, run, pass_dir).and(Err(ScanError::TimedOut)),
        Some(status) => {
            kill_group_after_exit(pid);
            check_exit(status)?;
            check_no_ignore_file(copy)?;
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
    check_fuse(&run.fuse_conf)?;
    check_fuse_sys_admin(&run.fuse_sys_admin)?;
    check_path(path)?;
    check_bwrap(&run.bwrap)?;
    let rules = read_rules(&run.rules, run.rules_uid)?;
    checked_rules(&rules)?;
    let private = create_private(&run.work_dir, run.work_uid)?;
    let started = Instant::now();
    let budget = Duration::from_millis(ticks.saturating_mul(run.poll_millis));
    let expired = || started.elapsed() >= budget || (run.expired)(&private.path);
    let summary = copy_tree(path, &private, &run.copy, run.before_open, &expired)?;
    write_ignore(&private)?;
    write_file(&private.run, CONFIG_NAME, rules.as_bytes())?;
    let map_path = |file: &str| original_path(file, path, &summary.renamed);
    let pass = Pass {
        copy: data_path(&private).join(TREE_DIR),
        original: path,
        pass_dir: run_path(&private),
        config: run_path(&private).join(CONFIG_NAME),
        map_path: &map_path,
    };
    let report = run_pass(program, &pass, target, limits, ticks, run)?;
    Ok(Report {
        copy: counts_of(&summary),
        ..report
    })
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
