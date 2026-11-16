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
    })
    .to_string()
}


/// The findings, then a final `{"score":..,"findings":..}` line.
pub fn format_report(report: &Report) -> Vec<String> {
    let mut lines: Vec<String> = report.findings.iter().map(format_finding).collect();
    lines.push(json!({"score": report.score, "findings": report.findings.len()}).to_string());
    lines
}
