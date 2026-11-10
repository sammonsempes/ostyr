use crate::error::StoreError;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;


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
