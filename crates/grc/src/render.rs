use crate::model::{ControlStatus, Report};
use crate::risk::ActionStatus;
use crate::risk_eval::{RiskLevel, RiskReport, RiskResult};
use std::io::Write;


pub const NO_EVIDENCE: &str = "-";


pub fn status_name(status: ControlStatus) -> &'static str {
    match status {
        ControlStatus::Compliant => "compliant",
        ControlStatus::PartiallyCompliant => "partially compliant",
        ControlStatus::NonCompliant => "non compliant",
        ControlStatus::NotAssessable => "not assessable",
    }
}


/// One header line, then one tab-separated line per control: id, status, evidence digest or `-`.
pub fn write_report(out: &mut impl Write, report: &Report) -> std::io::Result<()> {
    writeln!(out, "{}\t{}\t{}", report.tenant, report.framework, report.version)?;
    report.results.iter().try_for_each(|result| {
        let digest = result.evidence.as_ref().map_or(NO_EVIDENCE, |evidence| evidence.sha256.as_str());
        writeln!(out, "{}\t{}\t{}", result.control, status_name(result.status), digest)
    })
}


pub fn level_name(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}


pub fn action_status_name(status: ActionStatus) -> &'static str {
    match status {
        ActionStatus::Open => "open",
        ActionStatus::InProgress => "in progress",
        ActionStatus::Done => "done",
    }
}


/// One line per risk (id, level, score, gap, uncovered, review overdue), then one indented line per action.
pub fn write_risks(out: &mut dyn Write, report: &RiskReport) -> std::io::Result<()> {
    report.risks.iter().try_for_each(|risk| {
        let level = level_name(risk.level);
        let RiskResult {
            id,
            score,
            gap,
            uncovered,
            review_overdue,
            ..
        } = risk;
        writeln!(
            out,
            "risk\t{id}\t{level}\tscore={score}\tgap={gap}\tuncovered={uncovered}\treview_overdue={review_overdue}"
        )?;
        risk.actions.iter().try_for_each(|action| {
            let status = action_status_name(action.status);
            writeln!(out, "  action\t{}\t{status}\tdue={}\toverdue={}", action.id, action.due, action.overdue)
        })
    })
}
