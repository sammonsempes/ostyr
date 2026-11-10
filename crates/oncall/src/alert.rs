use chrono::{DateTime, Utc};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Open,
    Acknowledged,
    Escalated,
    Resolved,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleState {
    pub phase: Phase,
    pub level: u32,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Acknowledge,
    Escalate { to_level: u32 },
    Resolve,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub id: i64,
    pub fingerprint: String,
    pub state: LifecycleState,
    pub occurrences: i64,
    pub version: i64,
    pub opened_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub alert: Alert,
    pub created: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    OtherTenant,
    SenderFailed,
    InvalidMessage,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    Failed { reason: FailureReason },
}


/// A bound value; the tenant is bound as `$1` by the executor, these start at `$2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Int(i64),
    Text(String),
    OptText(Option<String>),
    Time(Option<DateTime<Utc>>),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    Int(i64),
    Text(String),
    Time(Option<DateTime<Utc>>),
    Bool(bool),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub sql: &'static str,
    pub params: Vec<Param>,
}
