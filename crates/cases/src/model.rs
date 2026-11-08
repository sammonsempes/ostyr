use serde::{Deserialize, Serialize};


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
pub enum CaseStatus {
    New,
    InProgress,
    Closed,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    TruePositive,
    FalsePositive,
    Benign,
    Duplicate,
    Other,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Todo,
    InProgress,
    Done,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAction {
    Created,
    Started,
    Completed,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskLogEntry {
    pub at: i64,
    pub actor: String,
    pub action: TaskAction,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub title: String,
    pub status: TaskStatus,
    pub due: Option<i64>,
    pub log: Vec<TaskLogEntry>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservableKind {
    Ip,
    Domain,
    Url,
    Hash,
    Email,
    Filename,
    Other,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tlp {
    Clear,
    Green,
    Amber,
    AmberStrict,
    Red,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pap {
    Clear,
    Green,
    Amber,
    Red,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocStatus {
    NotIoc,
    Suspected,
    Confirmed,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observable {
    pub kind: ObservableKind,
    pub value: String,
    pub tlp: Tlp,
    pub pap: Pap,
    pub ioc: IocStatus,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    pub author: String,
    pub at: i64,
    pub text: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseEventKind {
    Started,
    Closed,
    Reopened,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseEvent {
    pub kind: CaseEventKind,
    pub at: i64,
    pub actor: String,
    pub from: CaseStatus,
    pub to: CaseStatus,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub tenant: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub status: CaseStatus,
    pub resolution: Option<Resolution>,
    pub assignee: Option<String>,
    pub template: Option<String>,
    pub case_type: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub tasks: Vec<Task>,
    pub observables: Vec<Observable>,
    pub comments: Vec<Comment>,
    pub history: Vec<CaseEvent>,
}
