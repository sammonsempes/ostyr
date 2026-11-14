use crate::error::GrcError;
use crate::model::{ControlStatus, Report};
use crate::risk::{Action, ActionStatus, Register, Risk, Treatment};
use core_pg::scope::{tenant_of, tenant_scope};
use time::Date;


pub const LOW_MAX: u8 = 4;


pub const MEDIUM_MAX: u8 = 9;


pub const HIGH_MAX: u8 = 16;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}


#[derive(Debug, Clone, PartialEq)]
pub struct ActionResult {
    pub id: String,
    pub status: ActionStatus,
    pub due: Date,
    pub overdue: bool,
}


#[derive(Debug, Clone, PartialEq)]
pub struct RiskResult {
    pub id: String,
    pub score: u8,
    pub level: RiskLevel,
    pub gap: bool,
    pub uncovered: bool,
    pub review_overdue: bool,
    pub actions: Vec<ActionResult>,
}


#[derive(Debug, Clone, PartialEq)]
pub struct RiskReport {
    pub tenant: String,
    pub risks: Vec<RiskResult>,
}


/// Fixed bands: 1-4 low, 5-9 medium, 10-16 high, 17 and above (20-25 in practice) critical.
pub fn risk_level(score: u8) -> RiskLevel {
    if score <= LOW_MAX {
        RiskLevel::Low
    } else if score <= MEDIUM_MAX {
        RiskLevel::Medium
    } else if score <= HIGH_MAX {
        RiskLevel::High
    } else {
        RiskLevel::Critical
    }
}


/// Fail closed: anything but `Compliant`, and a control missing from the report, is a gap.
pub fn has_gap(risk: &Risk, report: &Report) -> bool {
    risk.controls.iter().any(|control| {
        report
            .results
            .iter()
            .find(|result| &result.control == control)
            .is_none_or(|result| result.status != ControlStatus::Compliant)
    })
}


/// An action is overdue when it is not done and its due date is before today; due today is not overdue.
pub fn action_result(action: &Action, today: Date) -> ActionResult {
    ActionResult {
        id: action.id.clone(),
        status: action.status,
        due: action.due,
        overdue: action.due < today && action.status != ActionStatus::Done,
    }
}


pub fn risk_result(risk: &Risk, actions: &[Action], report: &Report, today: Date) -> RiskResult {
    let score = risk.likelihood * risk.impact;
    let gap = has_gap(risk, report);
    let own_actions: Vec<ActionResult> = actions
        .iter()
        .filter(|action| action.risk == risk.id)
        .map(|action| action_result(action, today))
        .collect();
    let pending = own_actions.iter().any(|action| action.status != ActionStatus::Done);
    RiskResult {
        id: risk.id.clone(),
        score,
        level: risk_level(score),
        gap,
        uncovered: gap && risk.treatment == Treatment::Mitigate && !pending,
        review_overdue: risk.review_by < today,
        actions: own_actions,
    }
}


/// The register and the report must belong to the same tenant.
pub fn evaluate_risks(register: &Register, report: &Report, today: Date) -> Result<RiskReport, GrcError> {
    let scope = tenant_scope(&register.tenant)?;
    let expected = tenant_of(&scope);
    if expected == report.tenant {
        Ok(RiskReport {
            tenant: expected.to_owned(),
            risks: register
                .risks
                .iter()
                .map(|risk| risk_result(risk, &register.actions, report, today))
                .collect(),
        })
    } else {
        Err(GrcError::TenantMismatch)
    }
}
