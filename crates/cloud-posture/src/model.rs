use core_pg::scope::TenantScope;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Fail,
    Manual,
    Muted,
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


/// One finding: identity fields are ASCII allowlisted, `uid`, `title` and `detail` are escaped display text.
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


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skipped {
    pub unparsable: usize,
    pub bad_field: usize,
    pub duplicate: usize,
    pub foreign_account: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Findings {
    pub tenant: TenantScope,
    pub account: String,
    pub items: Vec<Finding>,
    pub skipped: Skipped,
}
