use crate::model::{Case, CaseEvent, CaseStatus, Comment, Observable, Resolution, Severity, Task};
use serde::Deserialize;


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
