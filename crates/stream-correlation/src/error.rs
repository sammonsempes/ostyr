use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error(transparent)]
    Sigma(#[from] sigma_sql::error::SigmaError),
    #[error("cannot parse the YAML: {0}")]
    Yaml(#[from] serde_saphyr::Error),
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
