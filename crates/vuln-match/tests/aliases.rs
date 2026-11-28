#[path = "common/types.rs"]
mod types;


use types::TestResult;
use vuln_match::kev::KevCatalogue;
use vuln_match::model::{Criticality, Finding, ScoredFinding};
use vuln_match::scoring::{cap_aliases, cap_aliases_counted};


const MAX: usize = 4;


const UNSCORED: f64 = 0.0;


const PRIOR_PLUS_DROPPED: u64 = 3;


fn scored(aliases: &[&str], omitted: u64) -> ScoredFinding {
    ScoredFinding {
        finding: Finding {
            package: "p".to_owned(),
            installed_version: "1".to_owned(),
            ecosystem: "e".to_owned(),
            record_id: "r".to_owned(),
            cve_aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
            aliases_omitted: omitted,
            fixed_version: None,
        },
        cvss: UNSCORED,
        epss: UNSCORED,
        kev: false,
        criticality: Criticality::Medium,
    }
}


fn catalogue(ids: &[&str]) -> KevCatalogue {
    KevCatalogue {
        ids: ids.iter().map(|id| (*id).to_owned()).collect(),
        ..KevCatalogue::default()
    }
}


#[test]
fn the_catalogue_ids_come_first_then_ascending_and_the_cut_is_counted() -> TestResult {
    let aliases = [
        "CVE-2020-0001",
        "CVE-2020-0002",
        "CVE-2020-0003",
        "CVE-2020-0004",
        "CVE-2020-0005",
        "CVE-2099-0001",
        "CVE-2098-0001",
    ];
    let kev = catalogue(&["CVE-2099-0001", "CVE-2098-0001"]);
    let capped = cap_aliases(scored(&aliases, 0), &kev, MAX);
    assert_eq!(
        capped.finding.cve_aliases,
        ["CVE-2098-0001", "CVE-2099-0001", "CVE-2020-0001", "CVE-2020-0002"]
    );
    assert_eq!(capped.finding.aliases_omitted, (aliases.len() - MAX) as u64);
    Ok(())
}


#[test]
fn a_list_within_the_cap_is_kept_whole_and_an_invalid_alias_is_dropped_and_counted() -> TestResult {
    let whole = cap_aliases(scored(&["CVE-2020-0002", "CVE-2020-0001"], 0), &catalogue(&[]), MAX);
    assert_eq!(whole.finding.cve_aliases, ["CVE-2020-0001", "CVE-2020-0002"]);
    assert_eq!(whole.finding.aliases_omitted, 0);
    let dirty = cap_aliases(scored(&["CVE-2020-0001", "CVE-bad", "CVE-2020-0001x"], 1), &catalogue(&[]), MAX);
    assert_eq!(dirty.finding.cve_aliases, ["CVE-2020-0001"]);
    assert_eq!(dirty.finding.aliases_omitted, PRIOR_PLUS_DROPPED);
    Ok(())
}


const KEV_PAST_THE_CAP: u64 = 2;


#[test]
fn catalogue_ids_past_the_cap_are_counted_apart() -> TestResult {
    let aliases = [
        "CVE-2020-0001",
        "CVE-2020-0002",
        "CVE-2020-0003",
        "CVE-2020-0004",
        "CVE-2020-0005",
        "CVE-2020-0006",
    ];
    let kev = catalogue(&aliases);
    let (capped, kev_omitted) = cap_aliases_counted(scored(&aliases, 0), &kev, MAX);
    assert_eq!(kev_omitted, KEV_PAST_THE_CAP);
    assert_eq!(capped.finding.aliases_omitted, KEV_PAST_THE_CAP);
    let (_whole, none) = cap_aliases_counted(scored(&aliases, 0), &catalogue(&[]), MAX);
    assert_eq!(none, 0);
    Ok(())
}
