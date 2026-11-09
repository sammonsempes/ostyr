//! Data model: device, update records, inventory and parse outcomes.

use crate::types::SkipCounts;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub tenant: String,
    pub device_id: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_lines: usize,
    pub max_line_bytes: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub tenant: String,
    pub device_id: String,
    pub package: String,
    pub architecture: String,
    pub installed_version: Option<String>,
    pub candidate_version: String,
    pub origin: Option<String>,
    pub security: bool,
    pub advisory_id: Option<String>,
    pub severity: Option<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    Malformed,
    ControlCharacters,
    LineTooLong,
    UnparsableVersion,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub updates: Vec<Update>,
    pub skipped: SkipCounts,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<Item> {
    Ignored,
    Record(Item),
    Skipped(SkipReason),
    Stop,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned<Item> {
    pub records: Vec<Item>,
    pub skipped: SkipCounts,
}
