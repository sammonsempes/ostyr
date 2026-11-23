use crate::types::{ApplyFn, GetFn, ListFn, NowFn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct OncallBackend {
    pub list: ListFn,
    pub get: GetFn,
    pub apply: ApplyFn,
    pub clock: NowFn,
}


/// `GET /oncall/alerts` query: the limit is checked by hand so a bad one is a stable 400, and any other key is refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Number of alerts, 1 to 1000, default 50.
    pub limit: Option<String>,
}


/// A value no key can hold: deserialising it always fails.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum NoField {}


/// The body of an acknowledge or resolve: the empty JSON object only; any key and a JSON array are refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = Object)]
pub struct ChangeRequest(pub BTreeMap<String, NoField>);


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AlertView {
    pub id: i64,
    pub fingerprint: String,
    /// `open`, `acknowledged`, `escalated` or `resolved`.
    pub state: String,
    pub level: u32,
    pub occurrences: i64,
    pub opened_at: String,
    pub acknowledged_at: Option<String>,
    pub resolved_at: Option<String>,
}


/// `skipped` counts the stored rows that could not be shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AlertListView {
    pub items: Vec<AlertView>,
    pub skipped: usize,
}
