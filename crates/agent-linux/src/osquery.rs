use crate::error::{OsqueryError, SensorError};
use crate::model::{CommandSpec, OsqueryEnv, OsquerySettings, QueryRows};
use crate::types::RowBuilderFn;
use crate::updates::child_environment;
use core_config::trusted_dir::{open_trusted_dir, TrustedDirError};
use rustix::fs::{fstat, mkdirat, open, openat, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::de::IgnoredAny;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;


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


pub const TEMP_DIR_NAME: &str = "osquery-tmp";


pub const NAMESPACE_FILE_NAME: &str = "namespace";


pub const NOFILE_LIMIT_FLAG: &str = "--nofile=";


pub const MAX_OPEN_FILES: u64 = 256;


pub const MOUNT_NAMESPACE_FLAG: &str = "--mount=";


pub const WORKING_DIR_FLAG: &str = "--wd=";


pub const PRIVATE_PROPAGATION_FLAG: &str = "--propagation=private";


pub const TMPFS_PATH: &str = "/tmp";


pub const BIND_PATHS: [&str; 2] = ["/var/tmp", "/usr/tmp"];


pub const SETUP_DEADLINE_SECONDS: u64 = 10;


pub const MAX_SETUP_OUTPUT_BYTES: u64 = 4_096;


pub const SQLITE_FULL_EXIT: i32 = 13;


pub const TEMP_DIR_VARIABLE: &str = "TMPDIR";


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


const NAMESPACE_FILE_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::CREATE).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


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


pub fn prepare_logger_dir(state_dir: &Path, trusted_uid: u32) -> Result<PathBuf, OsqueryError> {
    prepare_private_dir(state_dir, LOGGER_DIR_NAME, trusted_uid)
}


pub fn prepare_temp_dir(state_dir: &Path, trusted_uid: u32) -> Result<PathBuf, OsqueryError> {
    prepare_private_dir(state_dir, TEMP_DIR_NAME, trusted_uid)
}


/// The command of one query: `nsenter` enters the private mount namespace (working directory the tmpfs), `prlimit` binds address space, CPU time, file size, open files and core size from the first instruction, then `osqueryi` (the checked path, as is) with separate arguments and the query last; `TMPDIR` is the tmpfs.
pub fn query_spec(settings: &OsquerySettings, ns_file: &str, logger_dir: &str, query: &str) -> CommandSpec {
    let limits = [
        format!("{AS_LIMIT_FLAG}{}", settings.max_memory_bytes),
        format!("{CPU_LIMIT_FLAG}{}", settings.deadline_seconds),
        format!("{FSIZE_LIMIT_FLAG}{}", settings.max_temp_bytes),
        format!("{NOFILE_LIMIT_FLAG}{MAX_OPEN_FILES}:{MAX_OPEN_FILES}"),
        CORE_LIMIT_FLAG.to_owned(),
        END_OF_OPTIONS.to_owned(),
    ];
    CommandSpec {
        program: settings.nsenter_path.clone(),
        arguments: [
            format!("{MOUNT_NAMESPACE_FLAG}{ns_file}"),
            format!("{WORKING_DIR_FLAG}{TMPFS_PATH}"),
            END_OF_OPTIONS.to_owned(),
        ]
        .into_iter()
        .map(OsString::from)
        .chain([settings.prlimit_path.clone().into_os_string()])
        .chain(limits.into_iter().map(OsString::from))
        .chain([settings.path.clone().into_os_string()])
        .chain(FIXED_ARGUMENTS.iter().map(OsString::from))
        .chain(
            [format!("{LOGGER_PATH_FLAG}{logger_dir}"), query.to_owned()]
                .into_iter()
                .map(OsString::from),
        )
        .collect(),
        environment: Some(
            child_environment()
                .into_iter()
                .chain([(TEMP_DIR_VARIABLE.to_owned(), TMPFS_PATH.to_owned())])
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


/// The preparation steps, in order: the private directory is made a private mount point of its own (the kernel refuses to keep a namespace on a file of a shared mount), then a new private mount namespace kept alive by `ns_file` holding one size-capped tmpfs on `/tmp`, then that same tmpfs bind-mounted over each other temp path in `binds`.
pub fn setup_steps(settings: &OsquerySettings, temp_dir: &str, ns_file: &str, binds: &[&str]) -> Vec<(&'static str, CommandSpec)> {
    let namespace = format!("{MOUNT_NAMESPACE_FLAG}{ns_file}");
    let mount = settings.mount_path.to_string_lossy().into_owned();
    let self_bind = plain_spec(&settings.mount_path, &["--bind".to_owned(), temp_dir.to_owned(), temp_dir.to_owned()]);
    let make_private = plain_spec(&settings.mount_path, &["--make-private".to_owned(), temp_dir.to_owned()]);
    let create = plain_spec(
        &settings.unshare_path,
        &[
            namespace.clone(),
            PRIVATE_PROPAGATION_FLAG.to_owned(),
            END_OF_OPTIONS.to_owned(),
            mount.clone(),
            "-t".to_owned(),
            "tmpfs".to_owned(),
            "-o".to_owned(),
            tmpfs_options(settings),
            "tmpfs".to_owned(),
            TMPFS_PATH.to_owned(),
        ],
    );
    let bind_steps = binds.iter().map(|target| {
        let arguments = [
            namespace.clone(),
            END_OF_OPTIONS.to_owned(),
            mount.clone(),
            "--bind".to_owned(),
            TMPFS_PATH.to_owned(),
            (*target).to_owned(),
        ];
        ("bind", plain_spec(&settings.nsenter_path, &arguments))
    });
    [("self-bind", self_bind), ("make-private", make_private), ("namespace", create)]
        .into_iter()
        .chain(bind_steps)
        .collect()
}


/// The temp paths SQLite falls back to that exist on this host.
pub fn present_binds() -> Vec<&'static str> {
    BIND_PATHS.into_iter().filter(|path| Path::new(path).exists()).collect()
}


/// Drops the namespace file's mount, then the directory's own; only logged, since nothing is mounted when nothing was left over.
pub async fn release_namespace(env: &OsqueryEnv, settings: &OsquerySettings, temp_dir: &str, ns_file: &str) {
    for target in [ns_file, temp_dir] {
        let spec = plain_spec(&settings.umount_path, &[target.to_owned()]);
        let outcome = (env.run)(spec, Duration::from_secs(SETUP_DEADLINE_SECONDS)).await;
        outcome.map_or_else(|error| tracing::debug!(%error, "mount not dropped"), |_| ());
    }
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
    openat(&directory, NAMESPACE_FILE_NAME, NAMESPACE_FILE_FLAGS, Mode::RUSR | Mode::WUSR).map_err(errno_error)?;
    Ok(temp_dir.join(NAMESPACE_FILE_NAME))
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
    run_setup(env, setup_steps(settings, temp_dir, ns_file, &present_binds())).await?;
    let spec = query_spec(settings, ns_file, logger_dir, query);
    let output = (env.run)(spec, Duration::from_secs(settings.deadline_seconds))
        .await
        .map_err(osquery_error_of)?;
    rows_from_output(&output)
}


/// Runs one query with `osqueryi` and returns its rows; every program and the private directories are judged before the run, the temp space is one size-capped tmpfs in a private mount namespace dropped after the run, the output is bounded after it.
pub async fn run_query(env: &OsqueryEnv, settings: &OsquerySettings, query: &str) -> Result<QueryRows, OsqueryError> {
    check_query(query)?;
    [
        &settings.prlimit_path,
        &settings.unshare_path,
        &settings.nsenter_path,
        &settings.mount_path,
        &settings.umount_path,
        &settings.path,
    ]
    .into_iter()
    .try_for_each(|program| check_program(program, env.trusted_uid))?;
    let logger_dir = prepare_logger_dir(&env.state_dir, env.trusted_uid)?;
    let logger_text = path_text(&logger_dir)?;
    let temp_dir = prepare_temp_dir(&env.state_dir, env.trusted_uid)?;
    let temp_text = path_text(&temp_dir)?;
    let ns_file = prepare_namespace_file(&temp_dir)?;
    let ns_text = path_text(&ns_file)?;
    release_namespace(env, settings, temp_text, ns_text).await;
    let result = run_in_namespace(env, settings, temp_text, ns_text, logger_text, query).await;
    release_namespace(env, settings, temp_text, ns_text).await;
    result
}
