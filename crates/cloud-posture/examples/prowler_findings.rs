//! Usage: `prowler_findings <ocsf.json> <tenant> <account>`. Prints the counts and one escaped line per FAIL finding.
use cloud_posture::limits::Limits;
use cloud_posture::model::{Finding, Findings, Severity, Status};
use cloud_posture::prowler::parse_prowler_ocsf;
use core_pg::scope::tenant_of;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};


const ACCOUNT_ARGUMENT: usize = 2;


fn tally<Key: Ord + Copy>(findings: &[Finding], key_of: fn(&Finding) -> Key) -> BTreeMap<Key, usize> {
    findings.iter().fold(BTreeMap::new(), |mut counts, finding| {
        *counts.entry(key_of(finding)).or_insert(0) += 1;
        counts
    })
}


fn status_key(finding: &Finding) -> Status {
    finding.status
}


fn severity_key(finding: &Finding) -> Severity {
    finding.severity
}


fn fail_line(finding: &Finding) -> String {
    format!(
        "FAIL {:?} check={} provider={} account={} region={} resource={} type={} time={} title={} detail={}",
        finding.severity,
        finding.check_id,
        finding.provider,
        finding.account,
        finding.region,
        finding.resource_uid,
        finding.resource_type,
        finding.time_unix,
        finding.title,
        finding.detail
    )
}


fn summary(parsed: &Findings) -> String {
    format!(
        "tenant={} account={} findings={} by_status={:?} by_severity={:?} skipped={:?}",
        tenant_of(&parsed.tenant),
        parsed.account,
        parsed.items.len(),
        tally(&parsed.items, status_key),
        tally(&parsed.items, severity_key),
        parsed.skipped
    )
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let path = arguments.first().ok_or("missing ocsf.json")?;
    let tenant = arguments.get(1).ok_or("missing tenant")?;
    let account = arguments.get(ACCOUNT_ARGUMENT).ok_or("missing account")?;
    let parsed = parse_prowler_ocsf(File::open(path)?, tenant, account, &Limits::default())?;
    let mut out = stdout();
    writeln!(out, "{}", summary(&parsed))?;
    parsed
        .items
        .iter()
        .filter(|finding| finding.status == Status::Fail)
        .try_for_each(|finding| writeln!(out, "{}", fail_line(finding)))?;
    Ok(())
}
