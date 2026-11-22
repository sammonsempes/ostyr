/// One directory entry; times are Unix seconds, `None` when the attribute is absent, 0 or "never".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub dn: String,
    pub classes: Vec<String>,
    pub account: Option<String>,
    pub uac: u32,
    pub spns: Vec<String>,
    pub member_of: Vec<String>,
    pub pwd_last_set: Option<i64>,
    pub last_logon: Option<i64>,
    pub sid: Option<String>,
    pub gaps: Vec<Gap>,
}


/// Values of one list that could not be kept: refused ones are dropped, a list over its count keeps none (`over_limit`); `dropped` counts both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub field: &'static str,
    pub dropped: usize,
    pub over_limit: bool,
}


/// A global bound that was reached: `observed` is a lower bound for the size (the read stops one byte past the limit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundHit {
    pub bound: &'static str,
    pub observed: u64,
    pub limit: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub entries: Vec<Entry>,
    pub unreadable: Vec<Unreadable>,
    pub bounds: Vec<BoundHit>,
}


/// An entry set aside, named by position, field, fixed reason and a DN digest; `group_risk`: its SID is a privileged group's or unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    pub index: usize,
    pub field: &'static str,
    pub reason: &'static str,
    pub dn_digest: String,
    pub group_risk: bool,
    pub account: Option<String>,
    pub sid: Option<String>,
}


/// Ordered from the least to the most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    Kerberoastable,
    NoPreauth,
    UnconstrainedDelegation,
    KrbtgtPasswordAge,
    PrivilegedGroupSize,
    InactivePrivileged,
    UnreadableObject,
    PrivilegedGroupUnreadable,
    IncompleteCheck,
    DroppedValues,
    AssessmentIncomplete,
}


/// `reason` and `fix` are fixed texts, `detail` is built from field names and numbers only; `object` is the distinguished name, already refused if it held an unsafe character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub check: Check,
    pub object: String,
    pub reason: &'static str,
    pub fix: &'static str,
    pub detail: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub score: Option<u32>,
}


/// The raw elements of a JSON array, or its length when it is above the bound.
pub enum Items<'a> {
    Within(Vec<&'a serde_json::value::RawValue>),
    Over(usize),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thresholds {
    pub krbtgt_max_age_days: u32,
    pub privileged_max_members: usize,
    pub inactive_days: u32,
}


/// A snapshot with the capture time its exporter wrote (`None` for a bare array, or a refused text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub snapshot: Snapshot,
    pub captured: Option<String>,
}


/// Why the indicator emits nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BoundHit,
    NoCaptureTime,
    BadCaptureTime,
    CaptureInFuture,
    CaptureTooOld,
    NoDomain,
    NoDomainObject,
    NoAdministrator,
}


/// Integers only: nothing read from the directory reaches the indicator as text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndicatorCounts {
    pub entries: usize,
    pub accounts: usize,
    pub inactive: usize,
    pub never_logged: usize,
    pub future: usize,
    pub unreadable: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logon {
    Never,
    Future,
    Stale,
    Fresh,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndicatorRow {
    pub tenant: String,
    pub name: &'static str,
    pub value: usize,
    pub observed_at: String,
    pub source: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndicatorOutcome {
    Row(IndicatorRow),
    Refused { refusal: Refusal, entries: usize },
}
