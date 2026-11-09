use core_config::error::ConfigError;
use core_config::parse::{describe_error, describe_path, position_of, ROOT_FIELD_PATH};
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
    #[error("correlation rule {rule}: invalid document at `{field_path}`: {class}")]
    Schema { rule: String, field_path: String, class: String },
    #[error("correlation rule {rule}: unknown rule reference")]
    UnknownReference { rule: String },
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


pub const SCHEMA_CLASSES: &[(&str, &str)] = &[
    ("invalid type", "invalid type"),
    ("invalid value", "invalid value"),
    ("unknown field", "unknown field"),
    ("missing field", "missing field"),
    ("invalid length", "invalid length"),
];


pub const UNKNOWN_SCHEMA_CLASS: &str = "invalid document";


/// A schema error of the typed rule struct becomes a field path and a fixed class, since its text quotes the offending value.
pub fn schema_error(rule: &str, error: &serde_path_to_error::Error<serde_json::Error>) -> CorrelationError {
    let message = error.inner().to_string();
    let class = SCHEMA_CLASSES
        .iter()
        .find(|(prefix, _)| message.starts_with(prefix))
        .map_or(UNKNOWN_SCHEMA_CLASS, |(_, fixed)| fixed);
    CorrelationError::Schema {
        rule: rule.to_string(),
        field_path: describe_path(error.path(), message.starts_with("unknown field")),
        class: class.to_string(),
    }
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
