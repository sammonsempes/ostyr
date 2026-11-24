use core_audit::error::AuditError;
use core_config::error::{ConfigError, WatchError};
use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("invalid settings: {0}")]
    Invalid(String),
    #[error("`listen` is read at start only, restart the relay to change it")]
    ListenChanged,
    #[error("max_connections {max} needs {needed} file descriptors, the soft limit RLIMIT_NOFILE is {soft}")]
    Descriptors { max: usize, needed: u64, soft: u64 },
    #[error(transparent)]
    Config(#[from] ConfigError),
}


#[derive(Debug, Error)]
pub enum RelayError {
    #[error("usage: ostyr-relay <relay.yaml> <audit-file>")]
    Usage,
    #[error("refusing to run as root: use an unprivileged user with CAP_NET_BIND_SERVICE")]
    Root,
    #[error("settings: {0}")]
    Settings(#[from] SettingsError),
    #[error("audit: {0}")]
    Audit(#[from] AuditError),
    #[error("watch: {0}")]
    Watch(#[from] WatchError),
    #[error("the audit file is held by another relay: {0}")]
    AuditLocked(#[source] io::Error),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}
