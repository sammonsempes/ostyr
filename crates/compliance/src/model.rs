use crate::types::Row;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    Anssi,
    DisaStig,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkRef {
    pub framework: Framework,
    pub reference: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expectation {
    RowCount(usize),
    ColumnEquals { column: String, value: String },
    ColumnMatches { column: String, pattern: String },
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    pub action: String,
    #[serde(default)]
    pub enabled: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    pub query: String,
    pub expect: Expectation,
    pub severity: Severity,
    #[serde(default)]
    pub frameworks: Vec<FrameworkRef>,
    #[serde(default)]
    pub correction: Option<Correction>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub version: u32,
    pub name: String,
    pub controls: Vec<Control>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Device(String),
    Tag(String),
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub control: String,
    pub scope: Scope,
    pub owner: String,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionFile {
    pub exceptions: Vec<Exception>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub device: String,
    pub tags: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail { offending: Vec<Row>, total: usize },
    Error { reason: String },
    Excepted { owner: String, reason: String },
}
