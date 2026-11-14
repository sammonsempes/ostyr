use crate::model::Finding;
use crate::text::{escaped_whole, shown};


/// One output line per FAIL finding: every text field is escaped, then Debug-quoted, so no text can forge a `name=` field.
pub fn fail_line(finding: &Finding) -> String {
    format!(
        "FAIL {:?} uid={:?} check={:?} provider={:?} account={:?} region={:?} resource={:?} type={:?} time={} title={:?} detail={:?}",
        finding.severity,
        escaped_whole(&finding.uid),
        finding.check_id,
        finding.provider,
        finding.account,
        finding.region,
        finding.resource_uid,
        finding.resource_type,
        finding.time_unix,
        shown(&finding.title, finding.title_cut),
        shown(&finding.detail, finding.detail_cut)
    )
}
