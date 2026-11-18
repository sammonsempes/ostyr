use crate::store::FindingPage;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// `GET /hunts/findings` query: both values are checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Opaque cursor from `next_cursor`.
    pub cursor: Option<String>,
    /// Page size, 1 to 500, default 50.
    pub limit: Option<String>,
}


/// A checked page request: rows strictly after `after` (window end, pack id), at most `size`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingsQuery {
    pub after: (i64, String),
    pub size: i64,
}


/// What the store gave for one request: the page and the count of rows that are never listed.
#[derive(Debug, PartialEq, Eq)]
pub struct FindingsReply {
    pub page: FindingPage,
    pub oversized: i64,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct FindingView {
    pub pack_id: String,
    pub window_start: String,
    pub window_end: String,
    pub matches: i64,
    pub max_matches: i64,
}


/// Rows with a pack id over 64 bytes: `count` is cut at the report cap and `capped` tells it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct OversizedView {
    pub count: i64,
    pub capped: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct FindingsView {
    pub items: Vec<FindingView>,
    pub skipped: usize,
    pub oversized: OversizedView,
    pub next_cursor: Option<String>,
}
