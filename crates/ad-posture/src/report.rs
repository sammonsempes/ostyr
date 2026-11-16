use crate::model::{Finding, Report};
use serde_json::json;


/// One JSON object per finding: a DN is a JSON string, so it cannot forge a field or a line.
pub fn format_finding(found: &Finding) -> String {
    json!({
        "severity": format!("{:?}", found.severity),
        "check": format!("{:?}", found.check),
        "object": found.object,
        "reason": found.reason,
        "fix": found.fix,
        "detail": found.detail,
    })
    .to_string()
}


/// The findings one at a time (nothing is collected), then a final `{"score":..,"findings":..}` line.
pub fn report_lines(report: &Report) -> impl Iterator<Item = String> + '_ {
    report.findings.iter().map(format_finding).chain(std::iter::once(
        json!({"score": report.score, "findings": report.findings.len()}).to_string(),
    ))
}
