use crate::types::{RunGetFn, RunListFn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct RunsBackend {
    pub list: RunListFn,
    pub get: RunGetFn,
}


/// One page request: the run sequence number to continue below, and the size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunPage {
    pub after: Option<i64>,
    pub size: usize,
}


/// A run as the store holds it, without its trace; `seq` is the keyset position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunMeta {
    pub id: String,
    pub alert_id: String,
    pub playbook: String,
    pub mode: String,
    pub outcome: String,
    pub steps: u64,
    pub created: i64,
    pub seq: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunList {
    pub runs: Vec<RunMeta>,
    pub next: Option<i64>,
}


#[derive(Debug, Clone, PartialEq)]
pub struct RunDetail {
    pub meta: RunMeta,
    pub trace: Value,
}


/// `GET /playbooks/runs` query: both values are checked by hand so a bad one is a stable 400; any other key is a 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Cursor returned by the previous page, decimal digits.
    pub cursor: Option<String>,
    /// Number of runs, 1 to 100, default 50.
    pub limit: Option<String>,
}


/// `GET /playbooks/runs/{id}` takes no query: any parameter is a 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoQuery {}


/// One stored dry run of a playbook over an alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RunItem {
    pub id: String,
    pub alert_id: String,
    pub playbook: String,
    pub mode: String,
    pub outcome: String,
    pub steps: u64,
    /// Unix seconds.
    pub created: i64,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RunListView {
    pub items: Vec<RunItem>,
    pub next_cursor: Option<String>,
}


/// A run with its trace: events carry parameter names and kinds, never values.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct RunDetailView {
    #[serde(flatten)]
    pub run: RunItem,
    pub trace: Value,
}
