use crate::types::{AttributeMap, KeyMap, ObservedMap};
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
