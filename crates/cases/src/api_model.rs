use crate::stored::CaseSummary;
use crate::types::{DetailGetFn, SummaryListFn};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct CasesBackend {
    pub list: SummaryListFn,
    pub get: DetailGetFn,
}


/// `GET /cases` query: both values are checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Opaque cursor from `next_cursor`.
    pub cursor: Option<String>,
    /// Page size, 1 to 100, default 50.
    pub limit: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CaseListView {
    pub items: Vec<CaseSummary>,
    pub next_cursor: Option<String>,
}
