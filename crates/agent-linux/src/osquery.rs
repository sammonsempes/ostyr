use crate::error::{OsqueryError, SensorError};
use crate::model::{
    CommandSpec, OsqueryEnv, OsquerySettings, QueryRows, MOUNT_PATH, NSENTER_PATH, OSQUERYI_PATH, PRLIMIT_PATH, UMOUNT_PATH, UNSHARE_PATH,
};
use crate::types::{ChildKillFn, ReleaseFn, RowBuilderFn};
use crate::updates::child_environment;
use core_config::trusted_dir::{open_trusted_dir, TrustedDirError};
use rustix::fs::{flock, fstat, fstatfs, mkdirat, open, openat, FileType, FlockOperation, Mode, OFlags, PROC_SUPER_MAGIC};
use rustix::io::Errno;
use serde::de::IgnoredAny;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;


pub const MAX_QUERY_BYTES: usize = 16_384;


pub const MAX_OSQUERY_OUTPUT_BYTES: u64 = 8_388_608;


pub const MAX_ROWS: usize = 10_000;


pub const MAX_ROW_BYTES: usize = 1_048_576;


pub const MAX_COLUMNS: usize = 256;


pub const MAX_VALUE_BYTES: usize = 65_536;


pub const LOGGER_DIR_NAME: &str = "osquery-logs";


pub const GROUP_OTHER_ANY: u32 = 0o077;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const LOGGER_PATH_FLAG: &str = "--logger_path=";


pub const AS_LIMIT_FLAG: &str = "--as=";


pub const CPU_LIMIT_FLAG: &str = "--cpu=";


pub const FSIZE_LIMIT_FLAG: &str = "--fsize=";


pub const CORE_LIMIT_FLAG: &str = "--core=1";


pub const LOCK_FILE_NAME: &str = "osquery.lock";


pub const LOCK_POLL_MILLISECONDS: u64 = 50;


pub const LOCK_POLLS_PER_SECOND: u64 = 20;


pub const TEMP_DIR_NAME: &str = "osquery-tmp";


pub const NAMESPACE_FILE_NAME: &str = "namespace";


pub const MOUNT_NAMESPACE_FLAG: &str = "--mount=";


pub const WORKING_DIR_FLAG: &str = "--wd=";


pub const PRIVATE_PROPAGATION_FLAG: &str = "--propagation=private";


pub const SETUP_DEADLINE_SECONDS: u64 = 10;


pub const MAX_SETUP_OUTPUT_BYTES: u64 = 4_096;


pub const SQLITE_FULL_EXIT: i32 = 13;


pub const TEMP_DIR_VARIABLE: &str = "TMPDIR";


pub const SQLITE_TEMP_DIR_VARIABLE: &str = "SQLITE_TMPDIR";


pub const TOOL_PATHS: [&str; 6] = [PRLIMIT_PATH, UNSHARE_PATH, NSENTER_PATH, MOUNT_PATH, UMOUNT_PATH, OSQUERYI_PATH];


pub const END_OF_OPTIONS: &str = "--";


/// Every osqueryi argument before the logger path and the query: read-only, no extension, no event, no configuration, no table that reaches the network (the cloud metadata address included) or copies files out.
pub const FIXED_ARGUMENTS: [&str; 6] = [
    "--json",
    "--disable_extensions",
    "--disable_events",
    "--config_path=/dev/null",
    "--disable_tables=curl,curl_certificate,carves,ec2_instance_metadata,ec2_instance_tags,azure_instance_metadata,azure_instance_tags,ycloud_instance_metadata",
    "--logger_plugin=filesystem",
];


const FILE_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::NONBLOCK);


const ANCHOR_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


const CREATE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY);


const REOPEN_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::CLOEXEC).union(OFlags::NONBLOCK).union(OFlags::NOCTTY);


const PROC_FD_DIR: &str = "/proc/self/fd";


const LOCK_NOT_REGULAR: &str = "lock file is not a regular file";


const NAMESPACE_NOT_REGULAR: &str = "namespace file is not a regular file";


const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


/// Why a query is refused before any run: empty, too long, a NUL, or a first character osquery would read as a flag or a shell command.
pub fn query_fault(query: &str) -> Option<&'static str> {
    if query.trim().is_empty() {
        Some("query is empty")
    } else if query.len() > MAX_QUERY_BYTES {
        Some("query is too long")
    } else if query.contains('\0') {
        Some("query holds a NUL")
    } else if query.starts_with(['-', '.']) {
        Some("query starts like a flag or a shell command")
    } else {
        None
    }
}


pub fn check_query(query: &str) -> Result<(), OsqueryError> {
    query_fault(query).map_or(Ok(()), |reason| Err(OsqueryError::BadQuery(reason)))
}


pub fn errno_error(errno: Errno) -> OsqueryError {
    OsqueryError::Spawn(io::Error::from(errno).kind())
}


pub fn dir_error(error: TrustedDirError) -> OsqueryError {
    match error {
        TrustedDirError::Refused(reason) => OsqueryError::Untrusted(reason),
        TrustedDirError::Io(source) => OsqueryError::Spawn(source.kind()),
    }
}


/// Why the program file is not trusted: not a regular file, not owned by the trusted user, or writable by group or others.
pub fn program_fault(mode: u32, owner: u32, trusted_uid: u32) -> Option<&'static str> {
    if FileType::from_raw_mode(mode) != FileType::RegularFile {
        Some("program is not a regular file")
    } else if owner != trusted_uid {
        Some("program is not owned by the trusted user")
    } else if mode & GROUP_OTHER_WRITE != 0 {
        Some("program is writable by group or others")
    } else {
        None
    }
}


/// Why a private directory (logger, temp) is not trusted: owned by another user, or open to group or others.
pub fn logger_dir_fault(mode: u32, owner: u32, trusted_uid: u32) -> Option<&'static str> {
    if owner != trusted_uid {
        Some("private directory is not owned by the trusted user")
    } else if mode & GROUP_OTHER_ANY != 0 {
        Some("private directory is open to group or others")
    } else {
        None
    }
}


/// Judges one regular file through handles: every ancestor owned by the trusted user and closed to others, no symlink on the way, the file regular.
pub fn check_file(path: &Path, trusted_uid: u32) -> Result<(), OsqueryError> {
    let parent = path.parent().ok_or(OsqueryError::Untrusted("program has no directory"))?;
    let name = path.file_name().ok_or(OsqueryError::Untrusted("program has no name"))?;
    let directory = open_trusted_dir(parent, trusted_uid).map_err(dir_error)?;
    let file = openat(&directory, name, FILE_FLAGS, Mode::empty()).map_err(errno_error)?;
    let stat = fstat(&file).map_err(errno_error)?;
    program_fault(stat.st_mode, stat.st_uid, trusted_uid).map_or(Ok(()), |reason| Err(OsqueryError::Untrusted(reason)))
}


/// Judges the program: its directory is trusted and the file the name resolves to is judged by `check_file`; the name may be a symlink (osqueryi is).
pub fn check_program(path: &Path, trusted_uid: u32) -> Result<(), OsqueryError> {
    let parent = path.parent().ok_or(OsqueryError::Untrusted("program has no directory"))?;
    path.file_name().ok_or(OsqueryError::Untrusted("program has no name"))?;
    open_trusted_dir(parent, trusted_uid).map_err(dir_error)?;
    let resolved = std::fs::canonicalize(path).map_err(|error| OsqueryError::Spawn(error.kind()))?;
    check_file(&resolved, trusted_uid)
}


/// Makes a private directory `name` under the trusted state directory (mode 0700) or accepts an existing one only if it is ours and closed.
pub fn prepare_private_dir(state_dir: &Path, name: &str, trusted_uid: u32) -> Result<PathBuf, OsqueryError> {
    let parent = open_trusted_dir(state_dir, trusted_uid).map_err(dir_error)?;
    mkdirat(&parent, name, Mode::RWXU)
        .or_else(|errno| (errno == Errno::EXIST).then_some(()).ok_or(errno))
        .map_err(errno_error)?;
    let directory = openat(&parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(errno_error)?;
    let stat = fstat(&directory).map_err(errno_error)?;
    logger_dir_fault(stat.st_mode, stat.st_uid, trusted_uid).map_or_else(|| Ok(state_dir.join(name)), |reason| Err(OsqueryError::Untrusted(reason)))
}


/// Why the lock file is not trusted: not a regular file, owned by another user, or open to group or others.
pub fn lock_fault(mode: u32, owner: u32, trusted_uid: u32) -> Option<&'static str> {
    if FileType::from_raw_mode(mode) != FileType::RegularFile {
        Some("lock file is not a regular file")
    } else if owner != trusted_uid {
        Some("lock file is not owned by the trusted user")
    } else if mode & GROUP_OTHER_ANY != 0 {
        Some("lock file is open to group or others")
    } else {
        None
    }
}


/// Opens `name` under `directory` without running any driver `open` on a node that is not a regular file: anchored with `O_PATH | O_NOFOLLOW`, judged by `fstat`, a regular file reopened through `/proc/self/fd`, a free name created with `O_CREAT | O_EXCL` (0600).
pub fn open_regular(directory: &OwnedFd, name: &str, not_regular: &'static str) -> Result<OwnedFd, OsqueryError> {
    match openat(directory, name, ANCHOR_FLAGS, Mode::empty()) {
        Ok(anchor) => reopen_regular(&anchor, not_regular),
        Err(Errno::NOENT) => openat(directory, name, CREATE_FLAGS, Mode::RUSR | Mode::WUSR).map_err(errno_error),
        Err(errno) => Err(errno_error(errno)),
    }
}


/// Judges an `O_PATH` anchor (a device, a FIFO, a socket or a link is `Untrusted`) and reopens the regular file it pins through the procfs directory handle.
pub fn reopen_regular(anchor: &OwnedFd, not_regular: &'static str) -> Result<OwnedFd, OsqueryError> {
    let stat = fstat(anchor).map_err(errno_error)?;
    (FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile)
        .then_some(())
        .ok_or(OsqueryError::Untrusted(not_regular))?;
    let proc_dir = open_procfs_dir(Path::new(PROC_FD_DIR), not_regular)?;
    let file = openat(&proc_dir, anchor.as_raw_fd().to_string(), REOPEN_FLAGS, Mode::empty()).map_err(errno_error)?;
    let reopened = fstat(&file).map_err(errno_error)?;
    same_identity((stat.st_dev, stat.st_ino), (reopened.st_dev, reopened.st_ino), not_regular).map(|()| file)
}


/// Opens a directory (no driver `open` runs on a directory) and accepts it only on procfs: a forged `/proc` (a root-only mount) could point `fd/N` at a device.
pub fn open_procfs_dir(path: &Path, not_regular: &'static str) -> Result<OwnedFd, OsqueryError> {
    let directory = open(path, DIRECTORY_FLAGS, Mode::empty()).map_err(errno_error)?;
    let filesystem = fstatfs(&directory).map_err(errno_error)?;
    (filesystem.f_type == PROC_SUPER_MAGIC)
        .then_some(directory)
        .ok_or(OsqueryError::Untrusted(not_regular))
}


/// The handle got back from `/proc/self/fd` must be the file the anchor pinned (a forged `/proc` would hand back another one).
pub fn same_identity(anchor: (u64, u64), reopened: (u64, u64), not_regular: &'static str) -> Result<(), OsqueryError> {
    (anchor == reopened).then_some(()).ok_or(OsqueryError::Untrusted(not_regular))
}


/// Opens the lock file (0600, never through a symlink) under the trusted state directory and judges the handle it got, not the path.
pub fn open_lock_file(state_dir: &Path, trusted_uid: u32) -> Result<OwnedFd, OsqueryError> {
    let parent = open_trusted_dir(state_dir, trusted_uid).map_err(dir_error)?;
    let file = open_regular(&parent, LOCK_FILE_NAME, LOCK_NOT_REGULAR)?;
    let stat = fstat(&file).map_err(errno_error)?;
    lock_fault(stat.st_mode, stat.st_uid, trusted_uid).map_or(Ok(file), |reason| Err(OsqueryError::Untrusted(reason)))
}


/// Takes the exclusive lock of an open lock file, polling `attempts` more times at a fixed interval; `Busy` once they are spent.
pub async fn lock_exclusive(file: &OwnedFd, attempts: u64) -> Result<(), OsqueryError> {
    let mut waited = 0;
    let mut outcome = flock(file, FlockOperation::NonBlockingLockExclusive);
    while outcome == Err(Errno::WOULDBLOCK) && waited < attempts {
        sleep(Duration::from_millis(LOCK_POLL_MILLISECONDS)).await;
        outcome = flock(file, FlockOperation::NonBlockingLockExclusive);
        waited += 1;
    }
    match outcome {
        Ok(()) => Ok(()),
        Err(Errno::WOULDBLOCK) => Err(OsqueryError::Busy),
        Err(errno) => Err(errno_error(errno)),
    }
}


/// Takes the one-query-at-a-time lock of the state directory; the lock lives as long as the returned handle.
pub async fn lock_state(state_dir: &Path, trusted_uid: u32, deadline_seconds: u64) -> Result<OwnedFd, OsqueryError> {
    let file = open_lock_file(state_dir, trusted_uid)?;
    lock_exclusive(&file, deadline_seconds.saturating_mul(LOCK_POLLS_PER_SECOND)).await?;
    Ok(file)
}


pub fn prepare_logger_dir(state_dir: &Path, trusted_uid: u32) -> Result<PathBuf, OsqueryError> {
    prepare_private_dir(state_dir, LOGGER_DIR_NAME, trusted_uid)
}


pub fn prepare_temp_dir(state_dir: &Path, trusted_uid: u32) -> Result<PathBuf, OsqueryError> {
    prepare_private_dir(state_dir, TEMP_DIR_NAME, trusted_uid)
}


/// The programs a run executes, all `const`s: judged before every run.
pub fn tool_paths() -> Vec<PathBuf> {
    TOOL_PATHS.into_iter().map(PathBuf::from).collect()
}


/// The command of one query: `nsenter` enters the private mount namespace (working directory the tmpfs), `prlimit` binds address space, CPU time, file size and core size from the first instruction, then `osqueryi` with separate arguments and the query last; `TMPDIR` and `SQLITE_TMPDIR` are the tmpfs. Every program is a `const`.
pub fn query_spec(settings: &OsquerySettings, ns_file: &str, temp_dir: &str, logger_dir: &str, query: &str) -> CommandSpec {
    let limits = [
        format!("{AS_LIMIT_FLAG}{}", settings.max_memory_bytes),
        format!("{CPU_LIMIT_FLAG}{}", settings.deadline_seconds),
        format!("{FSIZE_LIMIT_FLAG}{}", settings.max_temp_bytes),
        CORE_LIMIT_FLAG.to_owned(),
        END_OF_OPTIONS.to_owned(),
    ];
    CommandSpec {
        program: PathBuf::from(NSENTER_PATH),
        arguments: [
            format!("{MOUNT_NAMESPACE_FLAG}{ns_file}"),
            format!("{WORKING_DIR_FLAG}{temp_dir}"),
            END_OF_OPTIONS.to_owned(),
            PRLIMIT_PATH.to_owned(),
        ]
        .into_iter()
        .chain(limits)
        .chain([OSQUERYI_PATH.to_owned()])
        .chain(FIXED_ARGUMENTS.iter().map(|argument| (*argument).to_owned()))
        .chain([format!("{LOGGER_PATH_FLAG}{logger_dir}"), query.to_owned()])
        .map(OsString::from)
        .collect(),
        environment: Some(
            child_environment()
                .into_iter()
                .chain([
                    (TEMP_DIR_VARIABLE.to_owned(), temp_dir.to_owned()),
                    (SQLITE_TEMP_DIR_VARIABLE.to_owned(), temp_dir.to_owned()),
                ])
                .collect(),
        ),
        accepted_codes: vec![0],
        max_output: MAX_OSQUERY_OUTPUT_BYTES,
    }
}


/// One preparation or cleanup command: a program and separate arguments, no output expected.
pub fn plain_spec(program: &Path, arguments: &[String]) -> CommandSpec {
    CommandSpec {
        program: program.to_path_buf(),
        arguments: arguments.iter().map(OsString::from).collect(),
        environment: Some(child_environment()),
        accepted_codes: vec![0],
        max_output: MAX_SETUP_OUTPUT_BYTES,
    }
}


/// The tmpfs mount options: an explicit total size, no device nodes, no setuid files.
pub fn tmpfs_options(settings: &OsquerySettings) -> String {
    format!("size={},mode=1777,nosuid,nodev", settings.max_temp_total_bytes)
}


/// The preparation steps, in order: the private directory is made a private mount point of its own (the kernel refuses to keep a namespace on a file of a shared mount), then a new private mount namespace kept alive by `ns_file` holding one size-capped tmpfs on that directory; nothing is mounted over `/tmp`, `/var/tmp` or `/usr/tmp`.
pub fn setup_steps(settings: &OsquerySettings, temp_dir: &str, ns_file: &str) -> Vec<(&'static str, CommandSpec)> {
    let mount = Path::new(MOUNT_PATH);
    let self_bind = plain_spec(mount, &["--bind".to_owned(), temp_dir.to_owned(), temp_dir.to_owned()]);
    let make_private = plain_spec(mount, &["--make-private".to_owned(), temp_dir.to_owned()]);
    let create = plain_spec(
        Path::new(UNSHARE_PATH),
        &[
            format!("{MOUNT_NAMESPACE_FLAG}{ns_file}"),
            PRIVATE_PROPAGATION_FLAG.to_owned(),
            END_OF_OPTIONS.to_owned(),
            MOUNT_PATH.to_owned(),
            "-t".to_owned(),
            "tmpfs".to_owned(),
            "-o".to_owned(),
            tmpfs_options(settings),
            "tmpfs".to_owned(),
            temp_dir.to_owned(),
        ],
    );
    vec![("self-bind", self_bind), ("make-private", make_private), ("namespace", create)]
}


/// Runs `program path` with the cleared environment and no output, waiting at most `polls` intervals; a slow or failing program is an error.
pub fn bounded_status(program: &Path, path: &Path, polls: u64, interval: Duration) -> io::Result<()> {
    let mut child = Command::new(program)
        .arg(path)
        .env_clear()
        .envs(child_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let finished = (0..polls).find_map(|_| {
        child.try_wait().transpose().or_else(|| {
            std::thread::sleep(interval);
            None
        })
    });
    match finished {
        Some(status) => status?.success().then_some(()).ok_or_else(|| io::Error::other("umount failed")),
        None => {
            reap_killed(&mut child, Child::kill, polls, interval)?;
            Err(io::Error::other("umount timed out"))
        }
    }
}


/// Waits for a child at most `polls` intervals; `None` when it is still running.
pub fn wait_bounded(child: &mut Child, polls: u64, interval: Duration) -> Option<io::Result<ExitStatus>> {
    (0..polls).find_map(|_| {
        child.try_wait().transpose().or_else(|| {
            std::thread::sleep(interval);
            None
        })
    })
}


/// Kills a child and waits for it at most `polls` intervals, so a failed kill leaves no zombie and a stuck child no hang; a kill failure or a child not reaped is logged and returned.
pub fn reap_killed(child: &mut Child, kill: ChildKillFn, polls: u64, interval: Duration) -> io::Result<()> {
    let killed = kill(child);
    let waited = wait_bounded(child, polls, interval);
    killed.as_ref().err().iter().for_each(|error| log_kill_failure(error));
    warn_unreaped(waited.is_none());
    killed?;
    waited.map_or_else(|| Err(io::Error::other("umount not reaped")), |status| status.map(|_status| ()))
}


/// Warns when the killed release step is still not reaped.
pub fn warn_unreaped(unreaped: bool) {
    if unreaped {
        tracing::warn!("umount not reaped");
    }
}


/// Logs that the release step could not be killed.
pub fn log_kill_failure(error: &io::Error) {
    let reason = error.to_string();
    tracing::warn!(reason, "umount not killed");
}


/// Runs `umount` on one path through the `const` program, with the cleared environment and the step deadline.
pub fn umount_path(path: &Path) -> io::Result<()> {
    bounded_status(
        Path::new(UMOUNT_PATH),
        path,
        SETUP_DEADLINE_SECONDS * LOCK_POLLS_PER_SECOND,
        Duration::from_millis(LOCK_POLL_MILLISECONDS),
    )
}


/// Drops each mount in order and returns how many could not be dropped (each is logged at debug level).
pub fn release_mounts(targets: &[PathBuf], release: ReleaseFn) -> usize {
    targets
        .iter()
        .filter(|target| {
            release(target).map_or_else(
                |error| {
                    tracing::debug!(%error, "mount not dropped");
                    true
                },
                |()| false,
            )
        })
        .count()
}


/// Holds the namespace file and the temp directory; dropping it drops their mounts, so an early `?` or a cancelled future leaves no tmpfs mounted.
#[derive(Debug)]
pub struct NamespaceGuard {
    pub release: ReleaseFn,
    pub targets: Vec<PathBuf>,
}


impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        warn_left_behind(release_mounts(&self.targets, self.release));
    }
}


/// Warns when some mounts could not be dropped.
pub fn warn_left_behind(failed: usize) {
    if failed > 0 {
        tracing::warn!(failed, "osquery mounts may be left behind");
    }
}


/// Runs the release off the async workers (`umount` is waited for synchronously) and returns how many mounts stayed; a lost task counts them all. The blocking task owns a clone of the lock and drops it after the last `umount`, so a cancelled caller cannot free the lock under a release still running.
pub async fn release_off_runtime(release: ReleaseFn, targets: Vec<PathBuf>, lock: Arc<OwnedFd>) -> usize {
    let total = targets.len();
    tokio::task::spawn_blocking(move || {
        let failed = release_mounts(&targets, release);
        drop(lock);
        failed
    })
    .await
    .unwrap_or_else(|error| {
        let reason = error.to_string();
        tracing::warn!(reason, "osquery release task lost");
        total
    })
}


/// Runs the preparation steps in order; the first failure ends the run as `Sandbox` naming the step and keeping the cause.
pub async fn run_setup(env: &OsqueryEnv, steps: Vec<(&'static str, CommandSpec)>) -> Result<(), OsqueryError> {
    for (step, spec) in steps {
        (env.run)(spec, Duration::from_secs(SETUP_DEADLINE_SECONDS))
            .await
            .map_err(|error| OsqueryError::Sandbox {
                step,
                source: Box::new(osquery_error_of(error)),
            })?;
    }
    Ok(())
}


/// Creates the file that keeps the private mount namespace alive, inside the private directory, through its handle.
pub fn prepare_namespace_file(temp_dir: &Path) -> Result<PathBuf, OsqueryError> {
    let directory = open(temp_dir, DIRECTORY_FLAGS, Mode::empty()).map_err(errno_error)?;
    open_regular(&directory, NAMESPACE_FILE_NAME, NAMESPACE_NOT_REGULAR).map(|_file| temp_dir.join(NAMESPACE_FILE_NAME))
}


pub fn osquery_error_of(error: SensorError) -> OsqueryError {
    match error {
        SensorError::Timeout => OsqueryError::Deadline,
        SensorError::TooLarge(_) => OsqueryError::TooLarge,
        SensorError::Io(source) => OsqueryError::Spawn(source.kind()),
        SensorError::Exit(Some(SQLITE_FULL_EXIT)) => OsqueryError::ResourceLimit,
        SensorError::Exit(Some(code)) => OsqueryError::Exit(code),
        SensorError::Exit(None) => OsqueryError::ResourceLimit,
        SensorError::Utf8(_) | SensorError::Parse => OsqueryError::NotJson { line: 0, column: 0 },
    }
}


/// Position only: the parser's message can repeat output bytes.
pub fn not_json(error: serde_json::Error) -> OsqueryError {
    OsqueryError::NotJson {
        line: error.line(),
        column: error.column(),
    }
}


/// A control character other than a line break or a tab: it would reach a terminal or a log unchanged.
pub fn has_control(text: &str) -> bool {
    text.chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}


pub fn text_within_bounds(text: &str) -> bool {
    text.len() <= MAX_VALUE_BYTES && !has_control(text)
}


pub fn row_within_bounds(row: &BTreeMap<String, String>) -> bool {
    row.len() <= MAX_COLUMNS && row.iter().all(|(column, value)| text_within_bounds(column) && text_within_bounds(value))
}


/// One row, or `None` when it breaks a bound or is not an object of strings: refused alone, the caller counts it.
pub fn row_of(raw: &str) -> Option<BTreeMap<String, String>> {
    (raw.len() <= MAX_ROW_BYTES)
        .then(|| serde_json::from_str::<BTreeMap<String, String>>(raw).ok())
        .flatten()
        .filter(row_within_bounds)
}


/// The production row builder: it counts nothing.
pub fn build_row(raw: &str, _calls: &mut usize) -> Option<BTreeMap<String, String>> {
    row_of(raw)
}


/// The rows of osquery's JSON array. The elements are counted without being stored (`IgnoredAny` is zero-sized) before any row is built.
pub fn rows_from_output(output: &[u8]) -> Result<QueryRows, OsqueryError> {
    rows_with_builder(output, build_row, &mut 0)
}


/// `rows_from_output` with the row builder injected, so a test can show that the count bound is applied before any row is built.
pub fn rows_with_builder(output: &[u8], build: RowBuilderFn, calls: &mut usize) -> Result<QueryRows, OsqueryError> {
    let count = serde_json::from_slice::<Vec<IgnoredAny>>(output).map_err(not_json)?.len();
    (count <= MAX_ROWS).then_some(()).ok_or(OsqueryError::TooLarge)?;
    let raws = serde_json::from_slice::<Vec<&RawValue>>(output).map_err(not_json)?;
    let built: Vec<Option<BTreeMap<String, String>>> = raws.iter().map(|raw| build(raw.get(), calls)).collect();
    let refused_rows = built.iter().filter(|row| row.is_none()).count();
    Ok(QueryRows {
        rows: built.into_iter().flatten().collect(),
        refused_rows,
    })
}


/// The path as text for a command line argument: a non-UTF-8 private directory is refused rather than spelled differently.
pub fn path_text(path: &Path) -> Result<&str, OsqueryError> {
    path.to_str().ok_or(OsqueryError::Untrusted("private directory is not UTF-8"))
}


/// The query inside the prepared namespace: the rows of its output, bounded.
pub async fn run_in_namespace(
    env: &OsqueryEnv,
    settings: &OsquerySettings,
    temp_dir: &str,
    ns_file: &str,
    logger_dir: &str,
    query: &str,
) -> Result<QueryRows, OsqueryError> {
    run_setup(env, setup_steps(settings, temp_dir, ns_file)).await?;
    let spec = query_spec(settings, ns_file, temp_dir, logger_dir, query);
    let output = (env.run)(spec, Duration::from_secs(settings.deadline_seconds))
        .await
        .map_err(osquery_error_of)?;
    rows_from_output(&output)
}


/// Runs one query with `osqueryi` and returns its rows; every program (a `const`) and the private directories are judged before the run, the temp space is one size-capped tmpfs in a private mount namespace dropped by a guard, the output is bounded after it; one query at a time per state directory (an exclusive `flock` held for the whole run, a second query waits up to its deadline then fails `Busy`).
pub async fn run_query(env: &OsqueryEnv, settings: &OsquerySettings, query: &str) -> Result<QueryRows, OsqueryError> {
    check_query(query)?;
    env.tools.iter().try_for_each(|program| check_program(program, env.trusted_uid))?;
    let lock = Arc::new(lock_state(&env.state_dir, env.trusted_uid, settings.deadline_seconds).await?);
    let logger_dir = prepare_logger_dir(&env.state_dir, env.trusted_uid)?;
    let logger_text = path_text(&logger_dir)?;
    let temp_dir = prepare_temp_dir(&env.state_dir, env.trusted_uid)?;
    let temp_text = path_text(&temp_dir)?;
    let ns_file = prepare_namespace_file(&temp_dir)?;
    let ns_text = path_text(&ns_file)?;
    let mut guard = NamespaceGuard {
        release: env.release,
        targets: vec![ns_file.clone(), temp_dir.clone()],
    };
    release_off_runtime(guard.release, guard.targets.clone(), Arc::clone(&lock)).await;
    let outcome = run_in_namespace(env, settings, temp_text, ns_text, logger_text, query).await;
    warn_left_behind(release_off_runtime(guard.release, std::mem::take(&mut guard.targets), Arc::clone(&lock)).await);
    outcome
}
