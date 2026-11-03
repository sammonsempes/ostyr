use crate::types::LineNumber;
use std::io;
use std::str::Utf8Error;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum NormaliseError {
    #[error("invalid JSON: {0}")]
    Syntax(#[source] serde_json::Error),
    #[error("unexpected event shape: {0}")]
    Schema(#[source] serde_json::Error),
    #[error("the event has no `{0}` argument")]
    MissingField(&'static str),
    #[error("the line is longer than {max} bytes")]
    TooLong { max: u64 },
    #[error("the line is not valid UTF-8: {0}")]
    Utf8(#[from] Utf8Error),
    #[error("cannot serialise the ECS event: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}


#[derive(Debug, Error)]
#[error("line {line}: {error}")]
pub struct LineError {
    pub line: LineNumber,
    #[source]
    pub error: NormaliseError,
}
