use crate::types::{AttributeMap, KeyMap, ObservedMap, VersionMap};
use serde::{Deserialize, Serialize};
use std::fmt;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Workstation,
    Server,
    VirtualMachine,
    Container,
    NetworkDevice,
    Printer,
    Iot,
    CloudResource,
    SaasApplication,
    ServiceAccount,
    Certificate,
    Software,
    Licence,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Ordered,
    InService,
    InMaintenance,
    Retired,
    Destroyed,
}


/// Declaration order is the matching priority: the derived `Ord` sorts a `KeyMap` from the strongest key to the weakest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKey {
    SerialNumber,
    Mac,
    CloudId,
    Name,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    DependsOn,
    RunsOn,
    MemberOf,
}


impl fmt::Display for IdentityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            IdentityKey::SerialNumber => "serial_number",
            IdentityKey::Mac => "mac",
            IdentityKey::CloudId => "cloud_id",
            IdentityKey::Name => "name",
        })
    }
}


impl fmt::Display for Criticality {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Criticality::Low => "low",
            Criticality::Medium => "medium",
            Criticality::High => "high",
            Criticality::Critical => "critical",
        })
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub value: String,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub id: String,
    pub kind: AssetKind,
    pub lifecycle: Lifecycle,
    pub keys: KeyMap,
    pub attributes: AttributeMap,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub from: String,
    pub kind: RelationKind,
    pub to: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub source: String,
    pub kind: AssetKind,
    pub keys: KeyMap,
    pub attributes: ObservedMap,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    TookObserved,
    KeptCurrent,
    Undecided,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub asset: String,
    pub attribute: String,
    pub current: Attribute,
    pub observed: Attribute,
    pub resolution: Resolution,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Created { asset: String },
    Reappeared { asset: String, lifecycle: Lifecycle },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub inventory: Vec<Asset>,
    pub conflicts: Vec<Conflict>,
    pub events: Vec<Event>,
}


/// A conflict refused because its asset already held `max_open_conflicts` open ones from the same observed source; no value is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedConflict {
    pub asset: String,
    pub attribute: String,
    pub observed_source: String,
}


/// A conflict the store already held open with the same values, so nothing was written for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateConflict {
    pub asset: String,
    pub attribute: String,
    pub observed_source: String,
}


/// What one apply answered: the refused conflicts and the duplicates of open ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub refused: Vec<RefusedConflict>,
    pub duplicates: Vec<DuplicateConflict>,
}


/// A stored reconciliation: `outcome.conflicts` holds only the conflicts newly written; the refused and the duplicates of open ones are listed apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub outcome: Outcome,
    pub refused_conflicts: Vec<RefusedConflict>,
    pub duplicate_conflicts: Vec<DuplicateConflict>,
}


/// Assets as stored, with the version each had when read (the optimistic concurrency token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub assets: Vec<Asset>,
    pub versions: VersionMap,
}


/// Read and retry bounds of the store; `Default` gives the production values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub page_size: usize,
    pub max_assets: usize,
    pub max_child_rows: usize,
    pub max_attempts: usize,
    pub max_open_conflicts: usize,
    pub max_open_key_conflicts: usize,
}


pub const DEFAULT_PAGE_SIZE: usize = 500;


pub const DEFAULT_MAX_ASSETS: usize = 10_000;


pub const DEFAULT_MAX_CHILD_ROWS: usize = 200_000;


pub const DEFAULT_MAX_ATTEMPTS: usize = 3;


pub const DEFAULT_MAX_OPEN_CONFLICTS: usize = 1_000;


pub const DEFAULT_MAX_OPEN_KEY_CONFLICTS: usize = 64;


impl Default for Limits {
    fn default() -> Self {
        Limits {
            page_size: DEFAULT_PAGE_SIZE,
            max_assets: DEFAULT_MAX_ASSETS,
            max_child_rows: DEFAULT_MAX_CHILD_ROWS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            max_open_conflicts: DEFAULT_MAX_OPEN_CONFLICTS,
            max_open_key_conflicts: DEFAULT_MAX_OPEN_KEY_CONFLICTS,
        }
    }
}
