use core_pg::scope::TenantScope;
use std::collections::BTreeMap;


/// Declared from the least to the most serious: the derived order picks the status a repeated identity keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Muted,
    Manual,
    Fail,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Unknown,
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Fatal,
    Other,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Unparsable,
    BadField,
    Duplicate,
    ForeignAccount,
}


/// One finding: identity fields are ASCII allowlisted, `uid` is the raw finding uid, `title` and `detail` are escaped cut text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub uid: String,
    pub check_id: String,
    pub status: Status,
    pub severity: Severity,
    pub provider: String,
    pub account: String,
    pub region: String,
    pub resource_uid: String,
    pub resource_type: String,
    pub time_unix: i64,
    pub title: String,
    pub detail: String,
}


/// `refused_by_status` counts each `bad_field` finding whose `status_code` was readable, so a refused FAIL stays visible.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skipped {
    pub unparsable: usize,
    pub bad_field: usize,
    pub duplicate: usize,
    pub foreign_account: usize,
    pub refused_by_status: BTreeMap<Status, usize>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Findings {
    pub tenant: TenantScope,
    pub account: String,
    pub items: Vec<Finding>,
    pub skipped: Skipped,
}
