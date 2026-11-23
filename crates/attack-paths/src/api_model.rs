use crate::types::{GetFn, ListFn};
use core_api::model::ApiIdentity;
use core_api::types::SharedState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct AttackPathsBackend {
    pub list: ListFn,
    pub get: GetFn,
}


/// `GET /attack-paths/reports` query: the limit is checked by hand so a bad one is a stable 400; any other key is a 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Number of reports, 1 to 100, default 50.
    pub limit: Option<String>,
}


/// `GET /attack-paths/reports/{id}` takes no query: any parameter is a 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoQuery {}


/// Metadata of one stored report; the body is read with `GET /attack-paths/reports/{id}`. The incompleteness fields are always present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ReportItem {
    pub id: i64,
    /// SHA-256 of the input graph, lowercase hexadecimal.
    pub graph_digest: String,
    /// UTC second the report was generated, RFC 3339.
    pub generated: String,
    /// SHA-256 of the stored body, lowercase hexadecimal.
    pub digest: String,
    pub bytes: u64,
    /// The path search stopped at its path cap: the paths are not all of them.
    pub truncated: bool,
    /// The step budget ended the search.
    pub budget_reached: bool,
    /// Entries whose search was not completed, named in the body.
    pub unsearched_count: u64,
    /// Unix seconds.
    pub stored_at: i64,
}


/// The newest reports first, at most `limit` of them: there is no cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ReportListView {
    pub items: Vec<ReportItem>,
}


/// What a read handler knows about the caller, owned so the read can run detached from the connection.
#[derive(Clone)]
pub struct Caller {
    pub app: SharedState,
    pub identity: Arc<ApiIdentity>,
    pub request_id: String,
    pub user: Option<String>,
}
