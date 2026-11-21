use crate::types::ReadFn;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST route reads through: injected, so a test serves the route from memory.
#[derive(Clone)]
pub struct PostureBackend {
    pub read: ReadFn,
}


/// `GET /posture/accounts/{account}/findings` query: every value is checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ReadQuery {
    /// Opaque cursor from `next_cursor`, percent-encoded.
    pub cursor: Option<String>,
    /// Page size, 1 to 500, default 50.
    pub limit: Option<String>,
}


/// The run row: counts and times as integers (microseconds since the epoch), `run_id` and `finished_micros` absent while only a refusal was stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RunView {
    pub run_id: Option<String>,
    pub finished_micros: Option<i64>,
    pub refused_micros: Option<i64>,
    pub refused_items: u64,
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
    pub refusal_pending: bool,
}


/// `uid`, `title` and `detail` are escaped (ASCII graphic and space only): a cut text ends with `\[N bytes cut]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct FindingView {
    pub uid: String,
    pub check_id: String,
    pub status: String,
    pub severity: String,
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


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PostureView {
    pub run: Option<RunView>,
    pub unservable: usize,
    pub items: Vec<FindingView>,
    pub next_cursor: Option<String>,
}
