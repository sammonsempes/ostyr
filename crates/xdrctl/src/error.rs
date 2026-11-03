use core_audit::error::AuditError;
use core_config::error::{ApplyError, ConfigError};
use std::io;
use std::path::PathBuf;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum ClientError {
    #[error("cannot read the CA file {path}: {source}")]
    CaFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("transport failed: {0}")]
    Transport(#[from] ureq::Error),
    #[error("invalid request: {0}")]
    Request(#[from] ureq::http::Error),
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("the server address must start with https://")]
    InsecureServer,
    #[error("no server address: pass --server or log in first")]
    NoServer,
    #[error("no user configuration directory: pass --config-dir")]
    NoConfigDir,
    #[error("not logged in: run `xdrctl login`")]
    NotLoggedIn,
    #[error("session file {path}: {source}")]
    Session {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("session file {path} is unreadable: {source}")]
    SessionFormat {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("the server refused the request ({status}): {code}: {message}")]
    Refused { status: u16, code: String, message: String },
    #[error("unexpected reply from the server (status {status})")]
    BadReply {
        status: u16,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot read the input: {0}")]
    Input(#[source] io::Error),
    #[error("cannot write the output: {0}")]
    Output(#[from] io::Error),
    #[error("cannot encode the output: {0}")]
    Encode(#[from] serde_json::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{path}: {source}")]
    Directory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Apply(#[from] ApplyError),
    #[error("apply cancelled")]
    Cancelled,
}
