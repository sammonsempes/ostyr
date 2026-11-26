use std::io;
use std::path::PathBuf;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("input or output failed: {0}")]
    Io(#[from] io::Error),
    #[error("{} is larger than {} bytes", .0.display(), .1)]
    TooLarge(PathBuf, u64),
}


#[derive(Debug, Error)]
pub enum SensorError {
    #[error("the command could not run: {0}")]
    Io(#[from] io::Error),
    #[error("the command did not finish in time")]
    Timeout,
    #[error("the command wrote more than {0} bytes")]
    TooLarge(u64),
    #[error("the command failed with status {0:?}")]
    Exit(Option<i32>),
    #[error("the command output is not UTF-8")]
    Utf8(#[source] std::str::Utf8Error),
    #[error("the command output is not what systemctl show prints")]
    Parse,
}


#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum StateDirReason {
    #[error("the cursor path has no directory")]
    NoDirectory,
    #[error("the directory is missing")]
    Missing,
    #[error("the path is not a directory, or is a symlink")]
    NotDirectory,
    #[error("the directory is owned by neither the agent user nor root")]
    WrongOwner,
    #[error("the directory is writable by group or others")]
    Writable,
}


#[derive(Debug, Error)]
pub enum SourceError {
    #[error("input or output failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error(transparent)]
    Audit(#[from] core_audit::error::AuditError),
    #[error(transparent)]
    Watch(#[from] core_config::error::WatchError),
    #[error(transparent)]
    App(#[from] agent_channel::error::AppError),
    #[error(transparent)]
    Export(#[from] core_export::error::ExportError),
    #[error("the export file could not be read: {0}")]
    Undrained(#[source] Box<SourceError>),
    #[error("state directory of {} is refused: {}", .0.display(), .1)]
    StateDir(PathBuf, StateDirReason),
    #[error("the background poll failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("settings out of range: {0}")]
    Settings(String),
    #[error("{} is not a regular file", .0.display())]
    NotRegular(PathBuf),
    #[error("run counter file {} is not a decimal number below the maximum", .0.display())]
    Counter(PathBuf),
    #[error("cursor file {} does not hold `<dev> <ino> <offset>`", .0.display())]
    Cursor(PathBuf),
}


#[derive(Debug, Error)]
pub enum IsolationError {
    #[error("nft could not run: {0}")]
    Io(#[from] io::Error),
    #[error("nft did not finish in time")]
    Timeout,
    #[error("nft wrote more than {0} bytes")]
    TooLarge(u64),
    #[error("nft failed with status {code:?}: {stderr}")]
    Exit { code: Option<i32>, stderr: String },
    #[error("nft output is not UTF-8")]
    Utf8(#[source] std::str::Utf8Error),
    #[error("nft output is not a table listing: {0}")]
    Json(#[from] serde_json::Error),
    #[error("isolation needs at least one endpoint")]
    NoEndpoints,
    #[error("isolation would cut the agent's own channel: an endpoint of the agent file is not a listed isolation endpoint")]
    ChannelNotListed,
    #[error("the table is not the one that was applied: {0}")]
    Mismatch(String),
    #[error(transparent)]
    State(#[from] SourceError),
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error(transparent)]
    Audit(#[from] core_audit::error::AuditError),
    #[error(transparent)]
    App(#[from] agent_channel::error::AppError),
    #[error("settings out of range: {0}")]
    Settings(String),
    #[error("unknown action, expected isolate, release or status")]
    Usage,
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum OsqueryError {
    #[error("the query is refused: {0}")]
    BadQuery(&'static str),
    #[error("a path osquery needs is refused: {0}")]
    Untrusted(&'static str),
    #[error("osquery could not start: {0:?}")]
    Spawn(io::ErrorKind),
    #[error("osquery did not finish in time")]
    Deadline,
    #[error("osquery wrote more than the allowed output or rows")]
    TooLarge,
    #[error("osquery was stopped by a limit (memory, CPU time, temp file size or temp space) or by a signal")]
    ResourceLimit,
    #[error("the private temp space could not be prepared at step {step}")]
    Sandbox {
        step: &'static str,
        #[source]
        source: Box<OsqueryError>,
    },
    #[error("another osquery query holds the sandbox and did not finish within the deadline")]
    Busy,
    #[error("osquery failed with status {0}")]
    Exit(i32),
    #[error("osquery output is not a JSON array at line {line} column {column}")]
    NotJson { line: usize, column: usize },
}


/// Why a FIM plan was refused; a fixed reason, never the text of a file.
#[derive(Debug, Error)]
pub enum FimError {
    #[error("the role table is not UTF-8")]
    TableNotUtf8,
    #[error("planted.tsv is not UTF-8")]
    PlantedNotUtf8,
    #[error("the role table is refused: {0}")]
    Table(#[source] linux_fim::error::TableError),
    #[error("the role is empty")]
    EmptyRole,
    #[error("the table has no role of that name")]
    NoRole,
    #[error("planted.tsv is refused: {0}")]
    Planted(#[source] linux_fim::error::CliError),
    #[error("planted.tsv entry {entry} names a path the role does not declare")]
    Undeclared { entry: usize },
    #[error("planted.tsv entry {entry} repeats the path of an earlier entry")]
    Duplicate { entry: usize },
}


#[derive(Debug, Error)]
pub enum ServeError {
    #[error("usage: ostyr-agent-linux <config.yaml>")]
    Usage,
    #[error(transparent)]
    Run(#[from] SourceError),
}
