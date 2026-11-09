use core_config::error::ConfigError;
use core_config::parse::{describe_error, position_of, ROOT_FIELD_PATH};
use serde::de::Error as _;
use sigma_sql::error::SigmaError;
use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error(transparent)]
    Sigma(#[from] sigma_sql::error::SigmaError),
    #[error("{file}: {source}")]
    InFile {
        file: String,
        #[source]
        source: Box<CorrelationError>,
    },
    #[error("correlation rule {rule}: unsupported construct {construct}")]
    Unsupported { rule: String, construct: String },
    #[error("correlation rule {rule}: invalid {field}: {reason}")]
    Invalid { rule: String, field: String, reason: String },
    #[error("correlation rule {rule}: cannot read the document: {source}")]
    Schema {
        rule: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("correlation rule {rule}: unknown rule reference {reference}")]
    UnknownReference { rule: String, reference: String },
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error("duplicate rule identifier {0}")]
    Duplicate(String),
    #[error("event has no @timestamp string")]
    MissingTimestamp,
    #[error("event @timestamp {value:?} is not RFC 3339: {source}")]
    BadTimestamp {
        value: String,
        #[source]
        source: time::error::Parse,
    },
    #[error("checkpoint {path} is corrupt: {source}")]
    CorruptCheckpoint {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("checkpoint {path} has version {found}, expected {expected}")]
    CheckpointVersion { path: String, found: u32, expected: u32 },
    #[error("checkpoint {path}: {source}")]
    CheckpointIo {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("cannot serialise: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("cannot write: {0}")]
    Output(#[from] io::Error),
}


/// A YAML parse error of the Sigma parser becomes a fixed error class, since its text can quote the rule document.
pub fn redacted(error: SigmaError) -> CorrelationError {
    match error {
        SigmaError::Yaml(yaml) => {
            let (line, column) = position_of(yaml.location());
            let message = describe_error(&yaml);
            CorrelationError::Config(ConfigError::Parse {
                file: String::new(),
                line,
                column,
                field_path: ROOT_FIELD_PATH.to_string(),
                message: message.clone(),
                source: Box::new(serde_saphyr::Error::custom(message)),
            })
        }
        other => CorrelationError::Sigma(other),
    }
}
