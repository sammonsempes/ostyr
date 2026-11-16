use crate::error::GrcError;
use crate::model::{ControlResult, ControlStatus, Framework, Report};
use crate::render::{action_status_name, status_name};
use crate::risk::{ActionStatus, Register};
use crate::risk_eval::action_result;
use serde::Serialize;
use time::Date;


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusCounts {
    pub compliant: usize,
    pub partially_compliant: usize,
    pub non_compliant: usize,
    pub not_assessable: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlRow {
    pub id: String,
    pub title: String,
    pub status: String,
    pub evidence_digest: Option<String>,
    pub evidence_time: Option<i64>,
    pub risks: Vec<String>,
    pub open_actions: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub control: String,
    pub title: String,
    pub status: String,
    pub risks: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanItem {
    pub control: String,
    pub risk: String,
    pub action: String,
    pub title: String,
    pub owner: String,
    pub status: String,
    pub due: String,
    pub overdue: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComplianceReport {
    pub tenant: String,
    pub framework: String,
    pub version: u32,
    pub generated: String,
    pub counts: StatusCounts,
    pub controls: Vec<ControlRow>,
    pub gaps: Vec<Gap>,
    pub plan: Vec<PlanItem>,
}


fn count(report: &Report, status: ControlStatus) -> usize {
    report.results.iter().filter(|result| result.status == status).count()
}


/// Ids of the risks that name the control, sorted.
pub fn linked_risks(register: &Register, control: &str) -> Vec<String> {
    let mut ids: Vec<String> = register
        .risks
        .iter()
        .filter(|risk| risk.controls.iter().any(|named| named == control))
        .map(|risk| risk.id.clone())
        .collect();
    ids.sort();
    ids
}


/// Actions not done of the risks that name the control, sorted by risk then action id.
pub fn open_actions(register: &Register, control: &str, today: Date) -> Vec<PlanItem> {
    let mut items: Vec<PlanItem> = linked_risks(register, control)
        .iter()
        .flat_map(|risk| {
            register
                .actions
                .iter()
                .filter(move |action| &action.risk == risk && action.status != ActionStatus::Done)
                .map(move |action| {
                    let result = action_result(action, today);
                    PlanItem {
                        control: control.to_owned(),
                        risk: risk.clone(),
                        action: action.id.clone(),
                        title: action.title.clone(),
                        owner: action.owner.clone(),
                        status: action_status_name(result.status).to_owned(),
                        due: result.due.to_string(),
                        overdue: result.overdue,
                    }
                })
        })
        .collect();
    items.sort_by(|left, right| (&left.risk, &left.action).cmp(&(&right.risk, &right.action)));
    items
}


fn title_of(framework: &Framework, control: &str) -> String {
    framework
        .controls
        .iter()
        .find(|candidate| candidate.id == control)
        .map_or_else(String::new, |found| found.title.clone())
}


fn control_row(framework: &Framework, register: &Register, result: &ControlResult, today: Date) -> ControlRow {
    ControlRow {
        id: result.control.clone(),
        title: title_of(framework, &result.control),
        status: status_name(result.status).to_owned(),
        evidence_digest: result.evidence.as_ref().map(|evidence| evidence.sha256.clone()),
        evidence_time: result.evidence.as_ref().map(|evidence| evidence.observed_at),
        risks: linked_risks(register, &result.control),
        open_actions: open_actions(register, &result.control, today)
            .into_iter()
            .map(|item| item.action)
            .collect(),
    }
}


/// Same inputs, same report: controls in report order, risks and actions by id. The register must belong to the report's tenant.
pub fn build_report(framework: &Framework, report: &Report, register: &Register, generated: Date) -> Result<ComplianceReport, GrcError> {
    if register.tenant == report.tenant {
        let controls: Vec<ControlRow> = report
            .results
            .iter()
            .map(|result| control_row(framework, register, result, generated))
            .collect();
        let not_compliant: Vec<&ControlRow> = report
            .results
            .iter()
            .zip(&controls)
            .filter(|(result, _)| result.status != ControlStatus::Compliant)
            .map(|(_, row)| row)
            .collect();
        Ok(ComplianceReport {
            tenant: report.tenant.clone(),
            framework: report.framework.clone(),
            version: report.version,
            generated: generated.to_string(),
            counts: StatusCounts {
                compliant: count(report, ControlStatus::Compliant),
                partially_compliant: count(report, ControlStatus::PartiallyCompliant),
                non_compliant: count(report, ControlStatus::NonCompliant),
                not_assessable: count(report, ControlStatus::NotAssessable),
            },
            gaps: not_compliant
                .iter()
                .map(|row| Gap {
                    control: row.id.clone(),
                    title: row.title.clone(),
                    status: row.status.clone(),
                    risks: row.risks.clone(),
                })
                .collect(),
            plan: not_compliant.iter().flat_map(|row| open_actions(register, &row.id, generated)).collect(),
            controls,
        })
    } else {
        Err(GrcError::TenantMismatch)
    }
}
