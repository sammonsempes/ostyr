use crate::model::CaseStatus;
use crate::template::CaseField;
use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("action `{action}` is not allowed while the case is {status:?}")]
    NotAllowed { status: CaseStatus, action: &'static str },
    #[error("closing a case needs a resolution")]
    ResolutionRequired,
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlaError {
    #[error("`{field}` is {value}, allowed range is {min} to {max}")]
    OutOfRange { field: &'static str, value: u32, min: u32, max: u32 },
}


#[derive(Debug, Error)]
pub enum SlaLoadError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] SlaError),
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum TemplateError {
    #[error("more than {max} templates")]
    TooManyTemplates { max: usize },
    #[error("a template has an empty name")]
    EmptyName,
    #[error("template `{0}` is defined twice")]
    DuplicateName(String),
    #[error("template `{template}` has more than {max} tasks")]
    TooManyTasks { template: String, max: usize },
    #[error("template `{0}` has a task with an empty title")]
    EmptyTaskTitle(String),
    #[error("template `{template}`: a task is due in {hours} hours, the maximum is {max}")]
    DueOutOfRange { template: String, hours: u32, max: u32 },
}


#[derive(Debug, Error)]
pub enum TemplateLoadError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] TemplateError),
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum CreateError {
    #[error("mandatory fields missing: {0:?}")]
    MissingFields(Vec<CaseField>),
    #[error("case type `{0}` is not allowed by the template")]
    TypeNotAllowed(String),
}


#[derive(Debug, Error)]
pub enum CaseStoreError {
    #[error("database: {0}")]
    Pg(#[from] core_pg::error::PgError),
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error("case tenant differs from the scope")]
    TenantMismatch,
    #[error("a new case is `new` and holds no observable, comment or history")]
    NotNew,
    #[error("field `{field}` is empty")]
    FieldEmpty { field: &'static str },
    #[error("field `{field}` exceeds {limit}")]
    FieldTooLong { field: &'static str, limit: usize },
    #[error("field `{field}` holds a NUL character")]
    NulByte { field: &'static str },
    #[error("`{field}` holds more than {limit} entries")]
    TooMany { field: &'static str, limit: usize },
    #[error("time `{field}` must not be negative")]
    BadTime { field: &'static str },
    #[error("alert id must be 64 lowercase hexadecimal characters")]
    BadAlertId,
    #[error("page size must be between 1 and {limit}")]
    BadPageSize { limit: usize },
    #[error("case not found")]
    NotFound,
    #[error("alert not found in this tenant")]
    AlertNotFound,
    #[error("a case with this id exists")]
    Exists,
    #[error("the case changed since it was read")]
    Conflict,
    #[error("`{what}` is full at {limit}")]
    Full { what: &'static str, limit: usize },
    #[error("the store returned a malformed value in column {column}")]
    BadRow { column: usize },
    #[error("column {column} is not a number")]
    BadNumber {
        column: usize,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("a stored label is unknown")]
    BadLabels(#[source] serde_json::Error),
    #[error("a stored document is malformed")]
    BadDocument(#[source] serde_json::Error),
}
