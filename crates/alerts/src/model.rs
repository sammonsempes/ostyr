use crate::error::StoreError;
use crate::types::{GetFn, ListFn};
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
