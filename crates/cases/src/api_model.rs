use crate::model::Resolution;
use crate::stored::CaseSummary;
use crate::types::{ActFn, ClockFn, CommentFn, DetailGetFn, SummaryListFn};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct CasesBackend {
    pub list: SummaryListFn,
    pub get: DetailGetFn,
    pub act: ActFn,
    pub comment: CommentFn,
    pub clock: ClockFn,
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


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionName {
    Start,
    Close,
    Reopen,
}


/// `POST /cases/{id}/actions` body; the actor and the tenant come from the session, never from here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub action: ActionName,
    /// Required to close, refused with any other action.
    pub resolution: Option<Resolution>,
}


/// `POST /cases/{id}/comments` body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentRequest {
    pub text: String,
}
