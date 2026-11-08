use core_config::error::ConfigError;
use std::io;
use std::num::ParseIntError;
use std::time::Duration;
use thiserror::Error;


#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConnectorError {
    #[error("connector failed: {0}")]
    Failed(String),
    #[error("connector took {elapsed:?}, the deadline is {deadline:?}")]
    Timeout { elapsed: Duration, deadline: Duration },
    #[error("no such compensation in the catalogue")]
    UnknownCompensation,
}


#[derive(Debug, Error)]
pub enum ExprError {
    #[error("forbidden syntax `{0}`: only `{{{{ expression }}}}` is allowed")]
    Forbidden(String),
    #[error("expression is {length} bytes long, the limit is {max}")]
    TooLong { length: usize, max: usize },
    #[error("expression nests brackets {depth} levels deep, the limit is {max}")]
    TooNested { depth: usize, max: usize },
    #[error("expression has {operators} operators, the limit is {max}")]
    TooComplex { operators: usize, max: usize },
    #[error("cannot start the expression worker: {0}")]
    Worker(#[from] io::Error),
    #[error("the expression worker panicked")]
    WorkerPanicked,
    #[error("expression refused: {0}")]
    Engine(#[from] minijinja::Error),
    #[error("value cannot be converted: {0}")]
    Convert(#[from] serde_json::Error),
}


#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Problem {
    #[error("{path}: unknown action `{action}` of connector `{connector}`")]
    UnknownAction { path: String, connector: String, action: String },
    #[error("{path}: action `{action}` lacks the parameter `{param}`")]
    MissingParam { path: String, action: String, param: String },
    #[error("{path}: action `{action}` has no parameter `{param}`")]
    UnknownParam { path: String, action: String, param: String },
    #[error("{path}: parameter `{param}`: {message}")]
    ParamType { path: String, param: String, message: String },
    #[error("{path}: destructive action `{action}` has no compensation")]
    MissingCompensation { path: String, action: String },
    #[error("{path}: action `{action}` compensates with unknown `{compensate}`")]
    UnknownCompensation { path: String, action: String, compensate: String },
    #[error("on_error is missing: a failure must page someone")]
    MissingOnError,
    #[error("steps is empty")]
    EmptySteps,
    #[error("the name is empty")]
    EmptyName,
    #[error("nesting deeper than {0} levels")]
    TooDeep(usize),
    #[error("{path}: parameter `{param}` is a breaker target and must be a bare `{{{{ alert.<entity> }}}}` or a literal")]
    BreakerTargetNotEntity { path: String, param: String },
    #[error("{path}: {message}")]
    BadExpression { path: String, message: String },
    #[error("{path}: {reason}")]
    MalformedStep { path: String, reason: String },
    #[error("trigger key `{0}` must start with `alert.`")]
    BadTrigger(String),
    #[error("catalogue entry `{entry}`: {reason}")]
    BadCatalogue { entry: String, reason: String },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentProblems {
    pub document: String,
    pub problems: Vec<Problem>,
}


pub fn describe(documents: &[DocumentProblems]) -> String {
    documents
        .iter()
        .flat_map(|found| found.problems.iter().map(|problem| format!("{}: {problem}", found.document)))
        .collect::<Vec<_>>()
        .join("; ")
}


#[derive(Debug, Error)]
#[error("{}", describe(.0))]
pub struct ValidationError(pub Vec<DocumentProblems>);


#[derive(Debug, Error)]
pub enum PlaybookError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] ValidationError),
}


#[derive(Debug, Error)]
pub enum CommandError {
    #[error("usage: {0}")]
    Usage(&'static str),
    #[error("unknown playbook `{0}`")]
    UnknownPlaybook(String),
    #[error("cannot read the alert: {0}")]
    Io(#[from] io::Error),
    #[error("the alert is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not a number: {0}")]
    Number(#[from] ParseIntError),
    #[error(transparent)]
    Invalid(#[from] ValidationError),
}
