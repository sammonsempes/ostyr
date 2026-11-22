use crate::types::Row;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    Anssi,
    DisaStig,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkRef {
    pub framework: Framework,
    pub reference: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expectation {
    RowCount(usize),
    ColumnEquals { column: String, value: String },
    ColumnMatches { column: String, pattern: String },
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    pub action: String,
    #[serde(default)]
    pub enabled: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: String,
    pub query: String,
    pub expect: Expectation,
    pub severity: Severity,
    #[serde(default)]
    pub frameworks: Vec<FrameworkRef>,
    #[serde(default)]
    pub correction: Option<Correction>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub version: u32,
    pub tenant: String,
    pub name: String,
    #[serde(default)]
    pub actions: Vec<String>,
    pub controls: Vec<Control>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Device(String),
    Tag(String),
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub control: String,
    pub scope: Scope,
    pub owner: String,
    pub reason: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionFile {
    pub exceptions: Vec<Exception>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub device: String,
    pub tags: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail { offending: Vec<Row>, total: usize },
    Error { reason: String },
    Excepted { owner: String, reason: String },
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub tenant: String,
    #[serde(default = "default_dry_run")]
    pub dry_run: bool,
    pub max_devices: usize,
    pub max_corrections_per_device: usize,
}


fn default_dry_run() -> bool {
    true
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceVerdicts {
    pub tenant: String,
    pub target: Target,
    pub verdicts: Vec<(String, Verdict)>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrectionRequest {
    pub control: String,
    pub device: String,
    pub action: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferReason {
    DeviceCapReached,
    DeviceCorrectionCapReached,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredCorrection {
    pub request: CorrectionRequest,
    pub reason: DeferReason,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub tenant: String,
    pub dry_run: bool,
    pub requests: Vec<CorrectionRequest>,
    pub would_run: Vec<CorrectionRequest>,
    pub deferred: Vec<DeferredCorrection>,
}


/// A control that failed on an asset, with the time of its first failure in the current run of failures (kept by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftFinding {
    pub tenant: String,
    pub baseline: String,
    pub control: String,
    pub title: String,
    pub severity: Severity,
    pub asset: String,
    pub first_failed_micros: u64,
    pub verdict: Verdict,
}


/// A failed control with the time its current run of failures began, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedAt {
    pub baseline: String,
    pub control: String,
    pub asset: String,
    pub first_failed_micros: u64,
}


/// The result of one recorded run: the failures to alert on, the entries skipped for their grammar and those refused for lack of room.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordOutcome {
    pub failed: Vec<FailedAt>,
    pub skipped_invalid: usize,
    pub refused_no_room: usize,
}


/// Counts of one indicator computation; integers only, so they can go to a log or a source text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndicatorCounts {
    pub assets: u64,
    pub excepted_only: u64,
    pub excepted_rows: u64,
    pub error_rows: u64,
    pub stale_rows: u64,
    pub future_rows: u64,
    pub missing: u64,
    pub unlisted_rows: u64,
    pub rows: u64,
}


/// One GRC indicator value, in the shape `grc::inputs::parse_indicators` reads.
#[derive(Debug, Clone, PartialEq)]
pub struct IndicatorRow {
    pub tenant: String,
    pub name: String,
    pub value: f64,
    pub observed_at: OffsetDateTime,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq)]
pub struct IndicatorOutcome {
    pub row: Option<IndicatorRow>,
    pub counts: IndicatorCounts,
}
