use crate::model::{Case, CaseEvent, CaseStatus, Comment, Observable, Resolution, Severity, Task};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;


/// A case as read, with the version an update must present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub case: Case,
    pub version: i64,
}


/// Keyset position (created_at, id) of the last case of a page; it carries no tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseCursor {
    pub created_at: i64,
    pub id: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasePage {
    pub after: Option<CaseCursor>,
    pub size: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseList {
    pub cases: Vec<Stored>,
    pub next: Option<CaseCursor>,
}


#[derive(Debug, Deserialize)]
pub struct Labels {
    pub severity: Severity,
    pub status: CaseStatus,
    pub resolution: Option<Resolution>,
}


#[derive(Debug, Deserialize)]
pub struct Parts {
    pub tasks: Vec<Task>,
    pub observables: Vec<Observable>,
    pub comments: Vec<Comment>,
    pub history: Vec<CaseEvent>,
}


/// How many entries each growing list of a case holds, so a response never carries the lists themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CaseCounts {
    pub tasks: usize,
    pub observables: usize,
    pub comments: usize,
    pub history: usize,
    pub alerts: usize,
}


/// A case without its comments, observables and history; times are unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CaseSummary {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub status: CaseStatus,
    pub assignee: Option<String>,
    pub case_type: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: i64,
    pub counts: CaseCounts,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CaseDetail {
    #[serde(flatten)]
    pub summary: CaseSummary,
    pub description: Option<String>,
    pub resolution: Option<Resolution>,
    pub template: Option<String>,
    #[schema(value_type = Vec<Object>)]
    pub tasks: Vec<Task>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryList {
    pub summaries: Vec<CaseSummary>,
    pub next: Option<CaseCursor>,
}


/// Keyset by alert id: `after` is the last alert id of the previous page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPage {
    pub after: Option<String>,
    pub size: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkList {
    pub alerts: Vec<AlertLinkItem>,
    pub next: Option<String>,
}


/// One alert linked to a case; the alert itself is read through the alerts API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AlertLink {
    pub alert_id: String,
}


/// A listed link: who linked the alert and when, `None` for a link written before the attribution columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AlertLinkItem {
    pub alert_id: String,
    pub linked_by: Option<String>,
    pub linked_at: Option<i64>,
}
