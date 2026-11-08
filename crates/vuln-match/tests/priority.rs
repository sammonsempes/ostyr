#[path = "common/types.rs"]
mod types;


use std::collections::BTreeSet;
use types::TestResult;
use vuln_match::model::{Criticality, Finding, ScoredFinding};
use vuln_match::priority::{priority_of, rank};
use vuln_match::rematch::kev_rematch;


const ZERO: f64 = 0.0;


const ONE: f64 = 1.0;


const FIVE: f64 = 5.0;


const NINE: f64 = 9.0;


const TEN: f64 = 10.0;


const HALF: f64 = 0.5;


const TENTH: f64 = 0.1;


const OUT_OF_RANGE_CVSS: f64 = 99.0;


const NEGATIVE: f64 = -1.0;


const POINTS_FIVE: u32 = 500;


const POINTS_THOUSAND: u32 = 1000;


const POINTS_TWO_THOUSAND: u32 = 2000;


const POINTS_THREE_THOUSAND: u32 = 3000;


const POINTS_MAX_NON_KEV: u32 = 8000;


const POINTS_KEV_ONLY: u32 = 10_000;


fn scored(record: &str, aliases: &[&str], cvss: f64, epss: f64, kev: bool, criticality: Criticality) -> ScoredFinding {
    ScoredFinding {
        finding: Finding {
            package: "pkg".into(),
            installed_version: "1".into(),
            ecosystem: "Debian".into(),
            record_id: record.into(),
            cve_aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            fixed_version: None,
        },
        cvss,
        epss,
        kev,
        criticality,
    }
}


#[test]
fn priority_table() -> TestResult {
    let table = [
        (ZERO, ZERO, false, Criticality::Low, 0),
        (FIVE, ZERO, false, Criticality::Low, POINTS_FIVE),
        (FIVE, HALF, false, Criticality::Low, POINTS_THOUSAND),
        (FIVE, HALF, false, Criticality::Medium, POINTS_TWO_THOUSAND),
        (FIVE, HALF, false, Criticality::High, POINTS_THREE_THOUSAND),
        (TEN, ONE, false, Criticality::Critical, POINTS_MAX_NON_KEV),
        (ZERO, ZERO, true, Criticality::Low, POINTS_KEV_ONLY),
        (f64::NAN, f64::NAN, false, Criticality::Low, 0),
        (OUT_OF_RANGE_CVSS, NINE, false, Criticality::Low, POINTS_TWO_THOUSAND),
        (NEGATIVE, NEGATIVE, false, Criticality::Low, 0),
    ];

    table.iter().for_each(|(cvss, epss, kev, criticality, expected)| {
        assert_eq!(priority_of(&scored("A", &[], *cvss, *epss, *kev, *criticality)), *expected);
    });
    Ok(())
}


#[test]
fn kev_overrides_higher_cvss() -> TestResult {
    let kev_low = scored("KEV", &[], ONE, ZERO, true, Criticality::Low);
    let critical = scored("CRIT", &[], TEN, ONE, false, Criticality::Critical);
    assert!(priority_of(&kev_low) > priority_of(&critical));
    let ranked = rank(vec![critical.clone(), kev_low.clone()]);
    assert_eq!(ranked, vec![kev_low, critical]);
    Ok(())
}


#[test]
fn rank_is_deterministic_on_ties() -> TestResult {
    let first = scored("A", &[], FIVE, TENTH, false, Criticality::Low);
    let second = scored("B", &[], FIVE, TENTH, false, Criticality::Low);
    assert_eq!(rank(vec![second.clone(), first.clone()]), vec![first.clone(), second.clone()]);
    assert_eq!(rank(vec![first.clone(), second.clone()]), vec![first, second]);
    Ok(())
}


#[test]
fn kev_rematch_flags_only_new_matches() -> TestResult {
    let by_alias = scored("DSA-1", &["CVE-2024-1"], FIVE, ZERO, false, Criticality::Low);
    let by_id = scored("CVE-2024-2", &[], NINE, ZERO, false, Criticality::Low);
    let already = scored("DSA-3", &["CVE-2024-1"], NINE, ZERO, true, Criticality::Low);
    let other = scored("DSA-4", &["CVE-2024-9"], NINE, ZERO, false, Criticality::Low);
    let new_ids: BTreeSet<String> = ["CVE-2024-1", "CVE-2024-2"].iter().map(|id| id.to_string()).collect();
    let result = kev_rematch(&[by_alias.clone(), by_id.clone(), already, other], &new_ids);
    let expected = rank(vec![ScoredFinding { kev: true, ..by_alias }, ScoredFinding { kev: true, ..by_id }]);
    assert_eq!(result, expected);
    assert!(kev_rematch(&[], &new_ids).is_empty());
    Ok(())
}
