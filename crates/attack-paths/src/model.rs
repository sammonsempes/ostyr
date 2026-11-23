use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};


pub const MAX_NODES: usize = 10_000;


pub const MAX_EDGES: usize = 100_000;


pub const MAX_NODE_ID_BYTES: usize = 128;


pub const MAX_DEPTH: usize = 16;


pub const MAX_PATHS: usize = 100_000;


pub const MAX_TAGS: usize = 1_000;


pub const MAX_SEARCH_STEPS: usize = 10_000_000;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Workstation,
    User,
    Group,
    Server,
    DomainController,
    AdCs,
    BackupServer,
    Hypervisor,
    SecretsVault,
    CloudRole,
    Internet,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    MemberOf,
    AdminTo,
    HasSessionOn,
    Exploitable,
    ExposedToInternet,
    CanAssume,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    #[serde(default)]
    pub critical: bool,
    #[serde(default)]
    pub entry_point: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub relation: Relation,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Path {
    pub nodes: Vec<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_depth: usize,
    pub max_paths: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathSet {
    pub paths: Vec<Path>,
    pub truncated: bool,
    pub budget_reached: bool,
    pub unsearched: Vec<Unsearched>,
}


/// The bound that ended the search of an entry before it was complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    StepBudget,
    PathCap,
}


impl Display for StopReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(match self {
            Self::StepBudget => "step_budget",
            Self::PathCap => "path_cap",
        })
    }
}


/// An entry whose search was cut by a bound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Unsearched {
    pub id: String,
    pub reason: StopReason,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChokePoint {
    pub node: String,
    pub paths_through: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRef {
    pub from: String,
    pub to: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub edge: EdgeRef,
    pub paths_closed: usize,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tags {
    #[serde(default)]
    pub critical: Vec<String>,
}
