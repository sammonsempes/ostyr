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
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub entries: Vec<Entry>,
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
}


/// `reason` and `fix` are fixed texts; `object` is the distinguished name, already refused if it held an unsafe character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: Check,
    pub severity: Severity,
    pub object: String,
    pub reason: &'static str,
    pub fix: &'static str,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub score: u32,
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
