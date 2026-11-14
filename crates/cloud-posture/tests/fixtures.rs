#[path = "common/types.rs"]
mod types;


use cloud_posture::limits::Limits;
use cloud_posture::model::{Severity, Skipped, Status};
use cloud_posture::prowler::parse_prowler_ocsf;
use std::collections::BTreeMap;
use std::fs::File;
use types::TestResult;


const FIXTURE: &str = "tests/fixtures/prowler-k3s-ocsf.json";


const CLUSTER: &str = "default";


const FINDINGS: usize = 317;


const PASSED: usize = 278;


const FAILED: usize = 37;


const MANUAL: usize = 2;


const HIGH: usize = 315;


const CRITICAL: usize = 2;


const CLUSTER_WIDE: usize = 291;


const KUBE_SYSTEM: usize = 23;


const KUBE_PUBLIC: usize = 3;


const FINDING_TIME: i64 = 1_794_648_552;


#[test]
fn the_live_prowler_kubernetes_capture_is_parsed_with_its_counts() -> TestResult {
    let parsed = parse_prowler_ocsf(File::open(FIXTURE)?, "lab", CLUSTER, &Limits::default())?;
    assert_eq!(parsed.items.len(), FINDINGS);
    assert_eq!(parsed.skipped, Skipped::default());
    let by_status = |wanted: Status| parsed.items.iter().filter(|finding| finding.status == wanted).count();
    assert_eq!(
        (
            by_status(Status::Pass),
            by_status(Status::Fail),
            by_status(Status::Manual),
            by_status(Status::Muted)
        ),
        (PASSED, FAILED, MANUAL, 0)
    );
    let by_severity = |wanted: Severity| parsed.items.iter().filter(|finding| finding.severity == wanted).count();
    assert_eq!((by_severity(Severity::High), by_severity(Severity::Critical)), (HIGH, CRITICAL));
    let regions = parsed.items.iter().fold(BTreeMap::new(), |mut counts: BTreeMap<&str, usize>, finding| {
        *counts.entry(finding.region.as_str()).or_insert(0) += 1;
        counts
    });
    assert_eq!(regions.get("cluster-wide"), Some(&CLUSTER_WIDE));
    assert_eq!(regions.get("kube-system"), Some(&KUBE_SYSTEM));
    assert_eq!(regions.get("kube-public"), Some(&KUBE_PUBLIC));
    assert!(parsed
        .items
        .iter()
        .all(|finding| finding.provider == "kubernetes" && finding.account == CLUSTER && finding.time_unix == FINDING_TIME));
    assert!(parsed.items.iter().all(|finding| finding.title.len() <= Limits::default().max_text_bytes));
    Ok(())
}


#[test]
fn the_live_capture_belongs_to_one_account_only() -> TestResult {
    let parsed = parse_prowler_ocsf(File::open(FIXTURE)?, "lab", "another-cluster", &Limits::default())?;
    assert!(parsed.items.is_empty());
    assert_eq!(parsed.skipped.foreign_account, FINDINGS);
    Ok(())
}
