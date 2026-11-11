use crate::error::StoreError;
use crate::types::{ClockFn, GetFn, ListFn, TriageFn};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;
use tokio_postgres::Client;
use utoipa::{IntoParams, ToSchema};


pub const SEVERITY_COLUMN: usize = 3;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}


impl Display for Severity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        let name = match self {
            Severity::Informational => "informational",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        formatter.write_str(name)
    }
}


impl FromStr for Severity {
    type Err = StoreError;

    fn from_str(text: &str) -> Result<Self, StoreError> {
        match text {
            "informational" => Ok(Severity::Informational),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(StoreError::BadRow { column: SEVERITY_COLUMN }),
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TriageStatus {
    Acknowledged,
    Closed,
}


impl Display for TriageStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        let name = match self {
            TriageStatus::Acknowledged => "acknowledged",
            TriageStatus::Closed => "closed",
        };
        formatter.write_str(name)
    }
}


impl FromStr for TriageStatus {
    type Err = StoreError;

    fn from_str(text: &str) -> Result<Self, StoreError> {
        match text {
            "acknowledged" => Ok(TriageStatus::Acknowledged),
            "closed" => Ok(TriageStatus::Closed),
            _ => Err(StoreError::BadRow { column: 0 }),
        }
    }
}


/// What a caller asks for: no row means the alert is new; `now` is caller-supplied microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageChange {
    pub status: TriageStatus,
    pub actor: String,
    pub note: Option<String>,
    pub now: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triage {
    pub status: TriageStatus,
    pub actor: String,
    pub note: Option<String>,
    pub updated_at: u64,
    pub version: i64,
}


/// An alert with its triage, read in one lease; no triage means the alert is new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertDetail {
    pub alert: Alert,
    pub triage: Option<Triage>,
}


/// The event summary as stored: `text` is cut at `MAX_SUMMARY_BYTES` when `truncated`, and `original_bytes` is the uncut size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub text: String,
    pub truncated: bool,
    pub original_bytes: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub tenant: String,
    pub rule_id: String,
    pub rule_title: String,
    pub severity: Severity,
    pub event_time: String,
    pub created_micros: u64,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
    pub event_ids: Vec<String>,
    pub summary: Summary,
}


/// Keyset position (created, id) of the last alert of a page; it carries no tenant and is never trusted for one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub created_micros: u64,
    pub id: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub after: Option<Cursor>,
    pub size: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertPage {
    pub alerts: Vec<Alert>,
    pub next: Option<Cursor>,
}


/// What the REST routes read through: injected, so a test serves the routes from memory.
#[derive(Clone)]
pub struct Backend {
    pub list: ListFn,
    pub get: GetFn,
    pub triage: TriageFn,
    pub clock: ClockFn,
}


/// One database connection for one request, with its statement deadline; the permit is released when the lease is dropped.
pub struct Lease {
    pub client: Client,
    pub deadline: Duration,
    pub permit: OwnedSemaphorePermit,
}


/// `GET /alerts` query: both values are checked by hand so a bad one is a stable 400.
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
pub struct AlertView {
    pub id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub severity: String,
    pub event_time: String,
    pub created: String,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
    pub event_ids: Vec<String>,
    #[schema(value_type = Object)]
    pub summary: serde_json::Value,
    pub summary_truncated: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AlertListView {
    pub items: Vec<AlertView>,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct TriageView {
    pub status: String,
    pub actor: String,
    pub note: Option<String>,
    pub updated_at: String,
    pub version: i64,
}


/// `GET /alerts/{id}`: the alert as listed plus its triage (`null` while the alert is new).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AlertDetailView {
    #[serde(flatten)]
    pub alert: AlertView,
    pub triage: Option<TriageView>,
}


/// `POST /alerts/{id}/triage` body; the actor and the tenant come from the session, never from here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TriageRequest {
    pub status: TriageStatus,
    /// At most 2048 characters, no NUL.
    pub note: Option<String>,
    /// The version read from the detail; absent while the alert has no triage.
    pub version: Option<i64>,
}
