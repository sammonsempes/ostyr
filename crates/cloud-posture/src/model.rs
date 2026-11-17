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


/// One finding: identity fields are ASCII allowlisted, `uid` is the raw finding uid, `title` and `detail` are raw text cut on a character boundary, `title_cut` and `detail_cut` the bytes left out (escape with `shown`).
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
    pub title_cut: usize,
    pub detail: String,
    pub detail_cut: usize,
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


/// One declared Kubernetes cluster; `kubeconfig_file` is relative to `tenant_directory` and opened beneath it; `context` is the account Prowler reports, so it is unique inside a declarations file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    pub name: String,
    pub tenant_directory: std::path::PathBuf,
    pub kubeconfig_file: std::path::PathBuf,
    pub context: String,
}


/// One tenant's declarations: the clusters that run and the indexes of the entries refused.
#[derive(Debug)]
pub struct Declarations {
    pub tenant: TenantScope,
    pub clusters: Vec<Cluster>,
    pub refused: Vec<usize>,
}


/// Which kubeconfig check refused the file, never its path or content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KubeconfigFault {
    Unreadable,
    NotRegular,
    Symlink,
    Linked,
    Mode,
    Owner,
}
