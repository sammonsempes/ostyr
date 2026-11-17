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


/// The sinkhole page as served: the status and the HTML bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    pub status: u16,
    pub html: String,
}


/// Open connections in all and per source key, under one lock so the caps are checked and taken together.
#[derive(Debug, Default)]
pub struct Admission {
    pub total: usize,
    pub sources: std::collections::BTreeMap<std::net::IpAddr, usize>,
}


/// Shared by the accept loop and every connection: the admission table and the counters reported once per interval.
#[derive(Debug, Default)]
pub struct ServeState {
    pub admission: std::sync::Arc<std::sync::Mutex<Admission>>,
    pub refused: std::sync::atomic::AtomicU64,
    pub cut: std::sync::atomic::AtomicU64,
    pub failed: std::sync::atomic::AtomicU64,
    pub reported_at: std::sync::Mutex<Option<tokio::time::Instant>>,
}


/// Releases the connection's slot when dropped.
#[derive(Debug)]
pub struct ConnectionGuard {
    pub admission: std::sync::Arc<std::sync::Mutex<Admission>>,
    pub key: std::net::IpAddr,
}


/// How a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionClass {
    Closed,
    Failed,
    Deadline,
}
