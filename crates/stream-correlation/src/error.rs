use core_config::error::ConfigError;
use core_config::parse::{describe_error, describe_path, position_of, shown_key, ROOT_FIELD_PATH};
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


pub const HIDDEN_IDENTIFIER: &str = "<identifier>";


pub const FIXED_CONSTRUCTS: &[(&str, &str)] = &[
    ("top-level key", "top-level key"),
    ("conflicting modifiers", "conflicting modifiers"),
    ("windash", "windash with a non-string matcher"),
];


fn fixed_construct(construct: String) -> String {
    let fixed = FIXED_CONSTRUCTS
        .iter()
        .find_map(|(prefix, fixed)| construct.starts_with(prefix).then_some(*fixed));
    fixed.map_or(construct, str::to_string)
}


/// Keeps the variant and the rule title of a Sigma error but drops every key, modifier and selection name that is not a schema identifier.
pub fn scrubbed(error: SigmaError) -> SigmaError {
    match error {
        SigmaError::Unsupported { rule, construct } => SigmaError::Unsupported {
            rule,
            construct: fixed_construct(construct),
        },
        SigmaError::UnknownModifier { rule, field, modifier } => SigmaError::UnknownModifier {
            rule,
            field: shown_key(&field),
            modifier: shown_key(&modifier),
        },
        SigmaError::UnmappedField { rule, field, category } => SigmaError::UnmappedField {
            rule,
            field: shown_key(&field),
            category,
        },
        SigmaError::MissingSelection { rule, name } => SigmaError::MissingSelection {
            rule,
            name: shown_key(&name),
        },
        SigmaError::BadValue { rule, field, reason } => SigmaError::BadValue {
            rule,
            field: shown_key(&field),
            reason,
        },
        SigmaError::BadIdentifier(_) => SigmaError::BadIdentifier(HIDDEN_IDENTIFIER.to_string()),
        other => other,
    }
}


/// A Sigma error of the rule parser or compiler becomes a fixed class: a YAML error loses its quoted text, the others their document keys.
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
        other => CorrelationError::Sigma(scrubbed(other)),
    }
}
