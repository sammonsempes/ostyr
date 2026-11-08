use crate::types::LineNumber;
use std::io;
use std::num::ParseIntError;
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


#[derive(Debug, Error)]
pub enum SysmonError {
    #[error("the event is longer than {max} bytes")]
    TooLong { max: usize },
    #[error("the event has more than {max} fields")]
    TooManyFields { max: usize },
    #[error("a field name or value is longer than {max} bytes")]
    FieldTooLong { max: usize },
    #[error("invalid XML: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("invalid XML text: {0}")]
    Encoding(#[from] quick_xml::encoding::EncodingError),
    #[error("unknown XML entity `{0}`")]
    UnknownEntity(String),
    #[error("invalid JSON: {0}")]
    Json(#[source] serde_json::Error),
    #[error("the event has no `{0}`")]
    MissingField(&'static str),
    #[error("`{0}` is not an unsigned number")]
    BadEventId(String),
    #[error("the JSON field `{0}` is not a scalar")]
    BadValue(String),
    #[error("`{field}` is not a valid number: {source}")]
    BadNumber {
        field: String,
        #[source]
        source: ParseIntError,
    },
    #[error("invalid event time: {0}")]
    BadTime(#[source] time::error::Parse),
    #[error("a Hashes entry has no `=`")]
    BadHashes,
}
