use crate::types::{GetFn, ListFn};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct SessionsBackend {
    pub list: ListFn,
    pub get: GetFn,
}


/// `GET /remote-shell/sessions` query: every value is checked by hand so a bad one is a stable 400; an unknown key is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Asset reference; percent-encode `/`.
    pub asset: Option<String>,
    /// Requester subject; percent-encode `+`, `|`, `/`, `=`.
    pub requester: Option<String>,
    /// Exactly `true` (open sessions only) or `false`.
    pub open: Option<String>,
    /// Opaque cursor from `next_cursor`, percent-encoded.
    pub cursor: Option<String>,
    /// Page size, 1 to 200, default 50.
    pub limit: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionView {
    pub session_id: String,
    pub requester: String,
    pub asset: String,
    pub ticket: String,
    pub opened_at: String,
    pub closed_at: Option<String>,
    pub close_reason: Option<String>,
    pub recording_frames: Option<i64>,
    pub recording_hash: Option<String>,
    pub recording_bytes: Option<i64>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SessionsListView {
    pub items: Vec<SessionView>,
    pub skipped: usize,
    pub next_cursor: Option<String>,
}
