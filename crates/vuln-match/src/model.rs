//! Data model: OSV records, inventory packages and match results.

use crate::types::UnmatchedCounts;
use rpm_version::Evr;
use serde::Deserialize;
use std::collections::BTreeMap;


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


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}


#[derive(Debug, Clone, PartialEq)]
pub struct ScoredFinding {
    pub finding: Finding,
    pub cvss: f64,
    pub epss: f64,
    pub kev: bool,
    pub criticality: Criticality,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EolEntry {
    pub product: String,
    pub cycle: String,
    pub end_date: time::Date,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EolTable {
    #[serde(default)]
    pub entries: Vec<EolEntry>,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EolFinding {
    pub package: String,
    pub installed_version: String,
    pub ecosystem: String,
    pub cycle: String,
    pub end_date: time::Date,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSettings {
    pub sha256: String,
    #[serde(default)]
    pub prefix_licences: BTreeMap<String, String>,
    #[serde(default)]
    pub allowed_licences: Vec<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedLimits {
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: u64,
    pub ratio_floor_bytes: u64,
    pub max_retained_items: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalHeader {
    pub flags: u16,
    pub method: u16,
    pub compressed: usize,
    pub name_len: usize,
    pub extra_len: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedRecord {
    pub record: OsvRecord,
    pub licence: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeedReport {
    pub records: Vec<LoadedRecord>,
    pub bad_entries: usize,
    pub dropped_by_licence: usize,
    pub retained_items: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanState {
    pub report: FeedReport,
    pub total: u64,
    pub entries: usize,
    pub done: bool,
}
