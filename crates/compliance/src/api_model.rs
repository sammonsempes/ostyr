use crate::types::{AssetFn, ListFn};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct StateBackend {
    pub list: ListFn,
    pub asset: AssetFn,
}


/// `GET /compliance/state` query: every value is checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// `fail` (default), `error`, `excepted`, `pass` or `all`.
    pub verdict: Option<String>,
    /// Only this baseline.
    pub baseline: Option<String>,
    /// Opaque cursor from `next_cursor`.
    pub cursor: Option<String>,
    /// Page size, 1 to 500, default 50.
    pub limit: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct StateView {
    pub baseline: String,
    pub control: String,
    pub asset: String,
    pub verdict: String,
    pub first_failed: Option<String>,
    pub last_seen: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct StateListView {
    pub items: Vec<StateView>,
    pub skipped: usize,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssetView {
    pub items: Vec<StateView>,
    pub skipped: usize,
    pub truncated: bool,
}
