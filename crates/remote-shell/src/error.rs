use core_config::error::ConfigError;
use serde_json::Error as JsonError;
use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum PolicyError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: invalid `{field}`")]
    Invalid { file: String, field: &'static str },
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("usage: shell_decide <policy.yaml> <case.json>")]
    Usage,
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: invalid case")]
    Case {
        file: String,
        #[source]
        source: JsonError,
    },
    #[error("cannot write the result")]
    Write(#[from] io::Error),
}
