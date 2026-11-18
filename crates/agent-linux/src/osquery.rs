use crate::error::{OsqueryError, SensorError};
use crate::model::{CommandSpec, OsqueryEnv, OsquerySettings, QueryRows};
use crate::updates::child_environment;
use core_config::trusted_dir::{open_trusted_dir, TrustedDirError};
use rustix::fs::{fstat, mkdirat, openat, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::de::IgnoredAny;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;


pub const MAX_QUERY_BYTES: usize = 16_384;


pub const MAX_OSQUERY_OUTPUT_BYTES: u64 = 8_388_608;


pub const MAX_ROWS: usize = 10_000;


pub const MAX_ROW_BYTES: usize = 1_048_576;


pub const MAX_COLUMNS: usize = 256;


pub const MAX_VALUE_BYTES: usize = 65_536;


pub const SIGNAL_EXIT: i32 = -1;


pub const LOGGER_DIR_NAME: &str = "osquery-logs";


pub const GROUP_OTHER_ANY: u32 = 0o077;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const LOGGER_PATH_FLAG: &str = "--logger_path=";


/// Every argument before the logger path and the query: read-only, no extension, no event, no configuration, no table that reaches the network or copies files out.
pub const FIXED_ARGUMENTS: [&str; 6] = [
    "--json",
    "--disable_extensions",
    "--disable_events",
    "--config_path=/dev/null",
    "--disable_tables=curl,curl_certificate,carves",
    "--logger_plugin=filesystem",
];


const FILE_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::NONBLOCK);


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


/// Why the logger directory is not trusted: owned by another user, or open to group or others.
pub fn logger_dir_fault(mode: u32, owner: u32, trusted_uid: u32) -> Option<&'static str> {
    if owner != trusted_uid {
        Some("logger directory is not owned by the trusted user")
    } else if mode & GROUP_OTHER_ANY != 0 {
        Some("logger directory is open to group or others")
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


/// Makes the private logger directory under the trusted state directory (mode 0700) or accepts an existing one only if it is ours and closed.
pub fn prepare_logger_dir(state_dir: &Path, trusted_uid: u32) -> Result<PathBuf, OsqueryError> {
    let parent = open_trusted_dir(state_dir, trusted_uid).map_err(dir_error)?;
    mkdirat(&parent, LOGGER_DIR_NAME, Mode::RWXU)
        .or_else(|errno| (errno == Errno::EXIST).then_some(()).ok_or(errno))
        .map_err(errno_error)?;
    let directory = openat(&parent, LOGGER_DIR_NAME, DIRECTORY_FLAGS, Mode::empty()).map_err(errno_error)?;
    let stat = fstat(&directory).map_err(errno_error)?;
    logger_dir_fault(stat.st_mode, stat.st_uid, trusted_uid)
        .map_or_else(|| Ok(state_dir.join(LOGGER_DIR_NAME)), |reason| Err(OsqueryError::Untrusted(reason)))
}


/// The command of one query: separate arguments, a cleared environment, the query last as a single argument.
pub fn query_spec(settings: &OsquerySettings, logger_dir: &str, query: &str) -> CommandSpec {
    CommandSpec {
        program: settings.path.clone(),
        arguments: FIXED_ARGUMENTS
            .iter()
            .map(|argument| (*argument).to_owned())
            .chain([format!("{LOGGER_PATH_FLAG}{logger_dir}"), query.to_owned()])
            .collect(),
        environment: Some(child_environment()),
        accepted_codes: vec![0],
        max_output: MAX_OSQUERY_OUTPUT_BYTES,
    }
}


pub fn osquery_error_of(error: SensorError) -> OsqueryError {
    match error {
        SensorError::Timeout => OsqueryError::Deadline,
        SensorError::TooLarge(_) => OsqueryError::TooLarge,
        SensorError::Io(source) => OsqueryError::Spawn(source.kind()),
        SensorError::Exit(code) => OsqueryError::Exit(code.unwrap_or(SIGNAL_EXIT)),
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


/// The rows of osquery's JSON array. The elements are counted without being stored (`IgnoredAny` is zero-sized) before any row is built.
pub fn rows_from_output(output: &[u8]) -> Result<QueryRows, OsqueryError> {
    let count = serde_json::from_slice::<Vec<IgnoredAny>>(output).map_err(not_json)?.len();
    (count <= MAX_ROWS).then_some(()).ok_or(OsqueryError::TooLarge)?;
    let raws = serde_json::from_slice::<Vec<&RawValue>>(output).map_err(not_json)?;
    let built: Vec<Option<BTreeMap<String, String>>> = raws.iter().map(|raw| row_of(raw.get())).collect();
    let refused_rows = built.iter().filter(|row| row.is_none()).count();
    Ok(QueryRows {
        rows: built.into_iter().flatten().collect(),
        refused_rows,
    })
}


/// Runs one query with `osqueryi` and returns its rows; the program and the logger directory are judged before the run, the output is bounded after it.
pub async fn run_query(env: &OsqueryEnv, settings: &OsquerySettings, query: &str) -> Result<QueryRows, OsqueryError> {
    check_query(query)?;
    check_program(&settings.path, env.trusted_uid)?;
    let logger_dir = prepare_logger_dir(&env.state_dir, env.trusted_uid)?;
    let logger_text = logger_dir.to_str().ok_or(OsqueryError::Untrusted("logger directory is not UTF-8"))?;
    let spec = query_spec(settings, logger_text, query);
    let output = (env.run)(spec, Duration::from_secs(settings.deadline_seconds))
        .await
        .map_err(osquery_error_of)?;
    rows_from_output(&output)
}
