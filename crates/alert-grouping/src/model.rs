use crate::types::OpenGroups;
use alerts::model::Severity;
use serde::Deserialize;
use std::collections::BTreeSet;


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupKey {
    pub tenant: String,
    pub rule_id: String,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
}


/// `alert_count` and `duplicates` are exact; `alert_ids` holds the first ids only and `omitted` says some are left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub key: GroupKey,
    pub representative: String,
    pub alert_ids: Vec<String>,
    pub omitted: bool,
    pub alert_count: u64,
    pub duplicates: u64,
    pub first_micros: u64,
    pub last_micros: u64,
    pub max_severity: Severity,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupLimits {
    pub window_micros: u64,
    pub max_alerts: usize,
    pub max_groups: usize,
    pub max_alerts_per_group: usize,
}


#[derive(Debug, Clone)]
pub struct Work<'alerts> {
    pub group: Group,
    pub sequence: u64,
    pub seen: BTreeSet<Vec<&'alerts str>>,
}


#[derive(Debug, Default)]
pub struct Progress<'alerts> {
    pub open: OpenGroups<'alerts>,
    pub finished: Vec<Work<'alerts>>,
    pub next_sequence: u64,
}
