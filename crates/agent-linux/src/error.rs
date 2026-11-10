use std::io;
use std::path::PathBuf;
use thiserror::Error;


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
    #[error("state directory of {} is missing or writable by group or others", .0.display())]
    StateDir(PathBuf),
    #[error("the background poll failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("settings out of range: {0}")]
    Settings(String),
    #[error("{} is not a regular file", .0.display())]
    NotRegular(PathBuf),
    #[error("cursor file {} does not hold `<dev> <ino> <offset>`", .0.display())]
    Cursor(PathBuf),
}
