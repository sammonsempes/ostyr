use crate::model::{Finding, Report};


/// One output line per finding: only fixed texts and the DN, which the snapshot reader refused if it held an unsafe character.
pub fn format_finding(found: &Finding) -> String {
    format!(
        "{:?} {:?} {} | {} | fix: {}",
        found.severity, found.check, found.object, found.reason, found.fix
    )
}


pub fn format_report(report: &Report) -> Vec<String> {
    let mut lines: Vec<String> = report.findings.iter().map(format_finding).collect();
    lines.push(format!("score={} findings={}", report.score, report.findings.len()));
    lines
}
