#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub tenant: String,
    pub at: i64,
    pub ok: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Impact {
    Outage,
    Degraded,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    pub tenant: String,
    pub start: i64,
    pub end: i64,
    pub impact: Impact,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceWindow {
    pub tenant: String,
    pub start: i64,
    pub end: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Period {
    pub tenant: String,
    pub start: i64,
    pub end: i64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_results: usize,
    pub max_incidents: usize,
    pub max_windows: usize,
    pub max_gap_seconds: i64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorBudget {
    pub allowed_seconds: i64,
    pub consumed_seconds: i64,
    pub remaining_seconds: i64,
    pub exhausted: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Totals {
    pub excluded_seconds: i64,
    pub unknown_seconds: i64,
    pub down_seconds: i64,
    pub up_seconds: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlaFigure {
    pub up_seconds: i64,
    pub down_seconds: i64,
    pub unknown_seconds: i64,
    pub excluded_seconds: i64,
    pub availability_ppm: Option<u32>,
    pub budget: ErrorBudget,
    pub ignored: usize,
    pub method: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInput {
    pub tenant: String,
    pub name: String,
    pub objective_ppm: u32,
    pub figure: SlaFigure,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportLimits {
    pub max_services: usize,
    pub max_name_bytes: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReportLine {
    pub name: String,
    pub objective_percent: String,
    pub availability_percent: Option<String>,
    pub budget_used_seconds: i64,
    pub budget_allowed_seconds: i64,
    pub down_seconds: i64,
    pub unknown_seconds: i64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct ReportTotals {
    pub services: usize,
    pub budget_used_seconds: i64,
    pub down_seconds: i64,
    pub unknown_seconds: i64,
}


#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Report {
    pub tenant: String,
    pub start: i64,
    pub end: i64,
    pub lines: Vec<ReportLine>,
    pub totals: ReportTotals,
}
