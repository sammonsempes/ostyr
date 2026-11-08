//! Data model: OSV records, inventory packages and match results.

use crate::types::UnmatchedCounts;
use rpm_version::Evr;
use serde::Deserialize;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Debian,
    Rpm,
    SemVer,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<Event>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AffectedPackage {
    pub ecosystem: String,
    pub name: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Affected {
    pub package: AffectedPackage,
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub versions: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OsvRecord {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub affected: Vec<Affected>,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub package: String,
    pub installed_version: String,
    pub ecosystem: String,
    pub record_id: String,
    pub cve_aliases: Vec<String>,
    pub fixed_version: Option<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnmatchedReason {
    UnknownEcosystem,
    UnparsableVersion,
    UnparsableRecordVersion,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unmatched {
    pub package: Package,
    pub record_id: Option<String>,
    pub reason: UnmatchedReason,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MatchReport {
    pub findings: Vec<Finding>,
    pub unmatched: Vec<Unmatched>,
    pub unmatched_counts: UnmatchedCounts,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParsedVersion {
    Debian(debversion::Version),
    Rpm(Evr<'static>),
    SemVer(semver::Version),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Introduced,
    Fixed,
    LastAffected,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEvent {
    pub kind: EventKind,
    pub text: String,
    pub version: Option<ParsedVersion>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Affected { fixed: Option<String> },
    NotAffected,
}
