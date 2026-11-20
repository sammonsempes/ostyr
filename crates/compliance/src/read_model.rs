//! Data of the read side: a page request, the stored rows and the pages answered.

use crate::types::StateKey;


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateFilter {
    pub verdict: Option<String>,
    pub baseline: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest {
    pub filter: StateFilter,
    pub cursor: Option<StateKey>,
    pub limit: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredState {
    pub baseline: String,
    pub control: String,
    pub asset: String,
    pub verdict: String,
    pub first_failed_micros: Option<i64>,
    pub last_seen_micros: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePage {
    pub rows: Vec<StoredState>,
    pub skipped: usize,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetResults {
    pub rows: Vec<StoredState>,
    pub skipped: usize,
    pub truncated: bool,
}
