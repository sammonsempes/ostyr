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
