use std::io;
use thiserror::Error;


/// A `line` and `column` of 0 mean the parser gave no position.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{file}: cannot access: {source}")]
    Io {
        file: String,
        #[source]
        source: io::Error,
    },
    #[error("{file}:{line}:{column}: at `{field_path}`: {message}")]
    Parse {
        file: String,
        line: u64,
        column: u64,
        field_path: String,
        message: String,
        #[source]
        source: Box<serde_saphyr::Error>,
    },
}
