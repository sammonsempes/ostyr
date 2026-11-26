use crate::types::Digest;
use core_pg::scope::TenantScope;
use std::collections::{BTreeMap, HashMap};


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
    TooLarge,
    Bytes,
    Shape,
    TooMany,
    Exec,
    AuthProvider,
    FilePath,
    ProxyUrl,
}


/// The findings of one run that the store accepts: one per identity, the refusals counted by status.
#[derive(Debug, Default)]
pub struct Admitted<'a> {
    pub kept: Vec<&'a Finding>,
    pub positions: HashMap<Digest, usize>,
    pub duplicate: usize,
    pub refused: BTreeMap<Status, usize>,
}


/// What `replace_run` stored: the rows written and the findings the store itself refused or merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOutcome {
    pub stored: usize,
    pub store_refused: usize,
    pub duplicate: usize,
}


/// The run row of one account: the last stored run (`run_id` and `finished_micros` are `None` while no run was ever stored) and the last refused one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunHeader {
    pub run_id: Option<String>,
    pub finished_micros: Option<i64>,
    pub items: u64,
    pub unparsable: u64,
    pub bad_field: u64,
    pub duplicate: u64,
    pub foreign_account: u64,
    pub refused_pass: u64,
    pub refused_muted: u64,
    pub refused_manual: u64,
    pub refused_fail: u64,
    pub store_refused: u64,
    pub refused_micros: Option<i64>,
    pub refused_items: u64,
}


/// One page of an account's findings: the run header, the findings that pass the serving check, the rows skipped, and the cursor of the next page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingsPage {
    pub run: Option<RunHeader>,
    pub items: Vec<Finding>,
    pub unservable: usize,
    pub next: Option<String>,
}


/// A parsed cursor: the run it belongs to (`run_id` and its finish time) and the key of the last row served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCursor {
    pub run_id: String,
    pub finished_micros: i64,
    pub rank: i16,
    pub identity: String,
}
