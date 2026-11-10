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
    #[error("the command output is not UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
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
    #[error("{} is not an absolute path", .0.display())]
    NotAbsolute(PathBuf),
    #[error("the background poll failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("settings out of range: {0}")]
    Settings(String),
    #[error("{} is not a regular file", .0.display())]
    NotRegular(PathBuf),
    #[error("cursor file {} does not hold `<dev> <ino> <offset>`", .0.display())]
    Cursor(PathBuf),
}
