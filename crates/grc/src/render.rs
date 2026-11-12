use crate::model::{ControlStatus, Report};
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
