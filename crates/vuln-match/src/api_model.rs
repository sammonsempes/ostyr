use crate::types::{AssetFn, ListFn};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct FindingsBackend {
    pub list: ListFn,
    pub asset: AssetFn,
}


/// `GET /vulnerabilities/findings` query: every value is checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Opaque cursor from `next_cursor`, percent-encoded.
    pub cursor: Option<String>,
    /// Page size, 1 to 500, default 50.
    pub limit: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct FindingView {
    pub asset: String,
    pub ecosystem: String,
    pub package: String,
    pub record_id: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub cvss: f64,
    pub epss: f64,
    pub kev: bool,
    pub priority: u32,
    pub first_seen: String,
    pub last_seen: String,
}


#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct FindingsListView {
    pub items: Vec<FindingView>,
    pub skipped: usize,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AssetView {
    pub items: Vec<FindingView>,
    pub skipped: usize,
    pub truncated: bool,
}
