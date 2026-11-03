use thiserror::Error;


#[derive(Debug, Error)]
pub enum SigmaError {
    #[error("cannot parse the YAML: {0}")]
    Yaml(#[from] serde_saphyr::Error),
    #[error("rule {rule}: unsupported construct {construct}")]
    Unsupported { rule: String, construct: String },
    #[error("rule {rule}: unknown or unsupported modifier {modifier} on {field}")]
    UnknownModifier { rule: String, field: String, modifier: String },
    #[error("rule {rule}: field {field} has no mapping for category {category}")]
    UnmappedField { rule: String, field: String, category: String },
    #[error("rule {rule}: bad condition: {reason}")]
    BadCondition { rule: String, reason: String },
    #[error("rule {rule}: no selection named {name}")]
    MissingSelection { rule: String, name: String },
    #[error("rule {rule}: bad value for {field}: {reason}")]
    BadValue { rule: String, field: String, reason: String },
    #[error("bad identifier {0:?}")]
    BadIdentifier(String),
    #[error("cannot read {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("cannot write output: {0}")]
    Output(#[from] std::io::Error),
    #[error("usage: sigma2sql <mapping.yaml> <table> <rule.yml>...")]
    Usage,
}
