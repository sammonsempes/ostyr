use crate::types::{ConnectorFn, MonotonicFn, ParamMap};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Simulate,
    Enforce,
    #[serde(rename = "dry-run")]
    DryRun,
    #[serde(rename = "approval-required")]
    ApprovalRequired,
}


#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Step {
    #[serde(rename = "if")]
    pub condition: Option<String>,
    pub then: Vec<Step>,
    #[serde(rename = "else")]
    pub otherwise: Vec<Step>,
    pub connector: Option<String>,
    pub action: Option<String>,
    pub params: ParamMap,
    pub compensate: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Playbook {
    pub name: String,
    pub version: u64,
    pub mode: Mode,
    #[serde(default)]
    pub trigger: ParamMap,
    #[serde(default)]
    pub variables: ParamMap,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub on_error: Vec<Step>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    String,
    Integer,
    Boolean,
    Ip,
    Domain,
    Duration,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    #[serde(rename = "type")]
    pub kind: ParamType,
    #[serde(default)]
    pub optional: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerKind {
    IsolateEndpoint,
    DisableAccount,
    BlockIp,
    BlockDomain,
    RmmScript,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakerBinding {
    pub kind: BreakerKind,
    pub target: String,
    #[serde(default)]
    pub duration: Option<String>,
    #[serde(default)]
    pub machines: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueEntry {
    #[serde(default)]
    pub connector: Option<String>,
    pub action: String,
    #[serde(default)]
    pub params: BTreeMap<String, ParamSpec>,
    #[serde(default)]
    pub compensate: Option<String>,
    #[serde(default)]
    pub destructive: bool,
    #[serde(default)]
    pub breaker: Option<BreakerBinding>,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalogue {
    pub actions: Vec<CatalogueEntry>,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    #[serde(default)]
    pub tags: Vec<String>,
}


/// Platform data standing in for the CMDB: the tags of every known host and account.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    #[serde(default)]
    pub hosts: BTreeMap<String, Asset>,
    #[serde(default)]
    pub accounts: BTreeMap<String, Asset>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionOutcome {
    True,
    False,
    Failed(String),
}


#[derive(Debug, Clone, PartialEq)]
pub enum TraceEvent {
    Trigger {
        matched: bool,
        mismatches: Vec<String>,
    },
    Condition {
        path: String,
        expression: String,
        outcome: ConditionOutcome,
    },
    Action {
        path: String,
        connector: Option<String>,
        action: String,
        params: ParamMap,
        verdict: Option<String>,
    },
    Rejected {
        path: String,
        action: String,
        reason: String,
    },
    Approval {
        path: String,
        params: ParamMap,
        granted: bool,
    },
    NotRun {
        path: String,
        step: String,
    },
    UnknownAsset {
        path: String,
        id: String,
    },
    Halted {
        path: String,
    },
    Failure {
        path: String,
        action: String,
    },
    ActionFailed {
        path: String,
        action: String,
        reason: String,
    },
    Compensation {
        action: String,
        compensates: String,
    },
    ErrorHandler,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Trace {
    pub playbook: String,
    pub version: u64,
    pub mode: Mode,
    pub events: Vec<TraceEvent>,
}


#[derive(Debug, Clone, PartialEq)]
pub struct SimulationInput {
    pub tenant: String,
    pub request_id: String,
    pub alert: serde_json::Value,
    pub fleet_size: u64,
    pub isolated_now: u64,
    pub fail_action: Option<usize>,
    pub approvals: Vec<String>,
}


/// An action that failed; `took_effect` is true when the connector succeeded too late, so the action must still be undone.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub event: TraceEvent,
    pub took_effect: bool,
}


/// What a connector is asked to do; `deadline` is the time the run allows it.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorCall {
    pub tenant: String,
    pub request_id: String,
    pub connector: Option<String>,
    pub action: String,
    pub params: ParamMap,
    pub deadline: Duration,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorResult {
    pub summary: String,
}


/// The real run's injected world: the connector, a monotonic clock and the per-action deadline.
#[derive(Clone, Copy)]
pub struct Executor<'a> {
    pub connector: &'a ConnectorFn,
    pub clock: &'a MonotonicFn,
    pub deadline: Duration,
}
