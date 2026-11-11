use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;


/// One trigger of the zone; a domain with `wildcard` also gets its `*.` subdomains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub owner: String,
    pub wildcard: bool,
    pub rdata: String,
    pub action: &'static str,
    pub confidence: u8,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SkipReason {
    #[error("unsupported IOC type")]
    UnsupportedType,
    #[error("expired")]
    Expired,
    #[error("TLP not allowed")]
    Tlp,
    #[error("confidence below the minimum")]
    LowConfidence,
    #[error("allowlisted")]
    Allowlisted,
    #[error("not a valid trigger name")]
    InvalidName,
    #[error("duplicate trigger")]
    Duplicate,
    #[error("malformed line")]
    MalformedLine,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct RunSummary {
    pub published: BTreeMap<&'static str, u64>,
    pub skipped: BTreeMap<&'static str, u64>,
    pub dropped_by_cap: u64,
    pub source_bad_rows: u64,
    pub records: u64,
    pub serial: u32,
}


/// How the Unbound control command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStatus {
    Success,
    Failed(Option<i32>),
    TimedOut,
}


/// What a zone reload needs: the command runner, the audit sink and who is acting.
pub struct Reloader<'a> {
    pub runner: &'a crate::types::RunnerFn<'a>,
    pub audit: &'a core_config::types::SharedAuditFn,
    pub context: &'a core_config::reload::ReloadContext,
}
