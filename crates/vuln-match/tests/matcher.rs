#[path = "common/types.rs"]
mod types;


use types::TestResult;
use vuln_match::matcher::match_inventory;
use vuln_match::model::{MatchReport, OsvRecord, Package, UnmatchedReason};
use vuln_match::osv::parse_record;


const FOUR_UNMATCHED: usize = 4;


const THREE_UNPARSABLE: usize = 3;


const TWO_BAD_RECORDS: usize = 2;


fn record(id: &str, aliases: &str, ecosystem: &str, name: &str, body: &str) -> Result<OsvRecord, Box<dyn std::error::Error>> {
    let text = format!(r#"{{"id":"{id}","aliases":{aliases},"affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{name}"}},{body}}}]}}"#);
    Ok(parse_record(&text)?)
}


fn package(ecosystem: &str, name: &str, version: &str) -> Package {
    Package {
        ecosystem: ecosystem.into(),
        name: name.into(),
        version: version.into(),
    }
}


fn ranges(events: &str) -> String {
    format!(r#""ranges":[{{"type":"ECOSYSTEM","events":[{events}]}}]"#)
}


fn run(ecosystem: &str, events: &str, installed: &[&str]) -> Result<Vec<Option<Option<String>>>, Box<dyn std::error::Error>> {
    let records = [record("OSV-1", "[]", ecosystem, "pkg", &ranges(events))?];
    Ok(installed
        .iter()
        .map(|version| {
            let report = match_inventory(&[package(ecosystem, "pkg", version)], &records);
            report.findings.first().map(|finding| finding.fixed_version.clone())
        })
        .collect())
}


fn fixed(version: &str) -> Option<Option<String>> {
    Some(Some(version.to_string()))
}


#[test]
fn several_introduced_fixed_pairs() -> TestResult {
    let events = r#"{"introduced":"0"},{"fixed":"1.0-1"},{"introduced":"2.0"},{"fixed":"2.5-1"}"#;
    let result = run("Debian:12", events, &["0.5", "1.0-1", "1.5", "2.0", "2.1", "2.5-1", "3.0"])?;
    assert_eq!(result, vec![fixed("1.0-1"), None, None, fixed("2.5-1"), fixed("2.5-1"), None, None]);
    Ok(())
}


#[test]
fn events_are_sorted_before_evaluation() -> TestResult {
    let events = r#"{"fixed":"2.5"},{"introduced":"2.0"},{"fixed":"1.0"},{"introduced":"0"}"#;
    let result = run("Debian", events, &["0.1", "1.0", "2.2", "2.5"])?;
    assert_eq!(result, vec![fixed("1.0"), None, fixed("2.5"), None]);
    Ok(())
}


#[test]
fn last_affected_is_inclusive_and_has_no_fix() -> TestResult {
    let events = r#"{"introduced":"1.0"},{"last_affected":"1.5"}"#;
    let result = run("Red Hat:enterprise_linux:9", events, &["0.9", "1.0", "1.5", "1.5.1", "2"])?;
    assert_eq!(result, vec![None, Some(None), Some(None), None, None]);
    Ok(())
}


#[test]
fn introduced_without_close_is_open_ended() -> TestResult {
    let result = run("npm", r#"{"introduced":"1.2.0"}"#, &["1.1.9", "1.2.0", "9.0.0"])?;
    assert_eq!(result, vec![None, Some(None), Some(None)]);
    Ok(())
}


#[test]
fn semver_prereleases_in_ranges() -> TestResult {
    let events = r#"{"introduced":"1.0.0-alpha"},{"fixed":"1.0.0"}"#;
    let result = run("crates.io", events, &["0.9.0", "1.0.0-beta", "1.0.0", "1.0.1"])?;
    assert_eq!(result, vec![None, fixed("1.0.0"), None, None]);
    Ok(())
}


#[test]
fn rpm_ranges_use_rpm_ordering() -> TestResult {
    let events = r#"{"introduced":"0"},{"fixed":"1.0^git1-1.el9"}"#;
    let result = run("Rocky Linux:9", events, &["1.0~rc1-1.el9", "1.0-5.el9", "1.0^git1-1.el9", "1:0.1-1"])?;
    assert_eq!(result, vec![fixed("1.0^git1-1.el9"), fixed("1.0^git1-1.el9"), None, None]);
    Ok(())
}


#[test]
fn limit_and_git_ranges_are_ignored() -> TestResult {
    let records = [record(
        "OSV-2",
        "[]",
        "Debian",
        "pkg",
        r#""ranges":[{"type":"GIT","events":[{"introduced":"not a version"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"limit":"zzz"}]}]"#,
    )?];
    let report = match_inventory(&[package("Debian", "pkg", "1.0")], &records);
    assert_eq!(report.findings.len(), 1);
    assert!(report.unmatched.is_empty());
    Ok(())
}


#[test]
fn explicit_versions_match_without_a_fix() -> TestResult {
    let records = [record("OSV-3", "[]", "npm", "pkg", r#""versions":["1.0.0","1.0.1","2.0.0"]"#)?];
    let inventory = [
        package("npm", "pkg", "1.0.0"),
        package("npm", "pkg", "1.0.1"),
        package("npm", "pkg", "1.0.2"),
    ];
    let report = match_inventory(&inventory, &records);
    let versions: Vec<_> = report
        .findings
        .iter()
        .map(|finding| (finding.installed_version.as_str(), finding.fixed_version.clone()))
        .collect();
    assert_eq!(versions, vec![("1.0.0", None), ("1.0.1", None)]);
    Ok(())
}


#[test]
fn package_selection_by_name_and_ecosystem_release() -> TestResult {
    let events = ranges(r#"{"introduced":"0"}"#);
    let cases = [
        ("Debian:12", "Debian:12", "pkg", true),
        ("Debian:12", "Debian:11", "pkg", false),
        ("Debian", "Debian:12", "pkg", false),
        ("Debian:12", "Debian", "pkg", true),
        ("Debian:12", "Debian:12", "other", false),
        ("Ubuntu:22.04", "Debian:12", "pkg", false),
    ];
    cases.iter().try_for_each(|(inventory_ecosystem, record_ecosystem, name, expected)| {
        let records = [record("OSV-4", "[]", record_ecosystem, "pkg", &events)?];
        let report = match_inventory(&[package(inventory_ecosystem, name, "1.0")], &records);
        assert_eq!(!report.findings.is_empty(), *expected, "{inventory_ecosystem} {record_ecosystem} {name}");
        assert!(report.unmatched.is_empty());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn second_affected_entry_is_used_and_first_hit_wins() -> TestResult {
    let text = r#"{"id":"OSV-5","affected":[
        {"package":{"ecosystem":"npm","name":"pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"5.0.0"}]}]},
        {"package":{"ecosystem":"npm","name":"pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]},
        {"package":{"ecosystem":"npm","name":"pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"bad"}]}]}
    ]}"#;
    let records = [parse_record(text)?];
    let report = match_inventory(&[package("npm", "pkg", "1.0.0")], &records);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings.first().and_then(|finding| finding.fixed_version.clone()),
        Some("2.0.0".to_string())
    );
    assert!(report.unmatched.is_empty());
    Ok(())
}


#[test]
fn cve_aliases_are_collected_and_sorted() -> TestResult {
    let records = [record(
        "CVE-2024-0002",
        r#"["GHSA-x","CVE-2024-0001","CVE-2024-0002"]"#,
        "npm",
        "pkg",
        &ranges(r#"{"introduced":"0"}"#),
    )?];
    let report = match_inventory(&[package("npm", "pkg", "1.0.0")], &records);
    let finding = report.findings.first().ok_or("no finding")?;
    assert_eq!(finding.cve_aliases, vec!["CVE-2024-0001", "CVE-2024-0002"]);
    assert_eq!(finding.record_id, "CVE-2024-0002");
    assert_eq!((finding.package.as_str(), finding.ecosystem.as_str()), ("pkg", "npm"));
    Ok(())
}


#[test]
fn unmatched_packages_are_counted_never_findings() -> TestResult {
    let records = [record("OSV-6", "[]", "PyPI", "pkg", &ranges(r#"{"introduced":"0"}"#))?];
    let inventory = [
        package("PyPI", "pkg", "1.0"),
        package("npm", "pkg", "latest"),
        package("Debian", "pkg", ""),
        package("Debian", "pkg", "also bad"),
    ];
    let report = match_inventory(&inventory, &records);
    assert!(report.findings.is_empty());
    assert_eq!(report.unmatched.len(), FOUR_UNMATCHED);
    assert_eq!(report.unmatched_counts.get(&UnmatchedReason::UnknownEcosystem), Some(&1));
    assert_eq!(report.unmatched_counts.get(&UnmatchedReason::UnparsableVersion), Some(&THREE_UNPARSABLE));
    assert_eq!(report.unmatched_counts.get(&UnmatchedReason::UnparsableRecordVersion), None);
    assert!(report.unmatched.iter().all(|entry| entry.record_id.is_none()));
    Ok(())
}


#[test]
fn unparsable_record_versions_are_counted() -> TestResult {
    let bad_event = record("OSV-7", "[]", "npm", "pkg", &ranges(r#"{"introduced":"0"},{"fixed":"soon"}"#))?;
    let bad_listed = record("OSV-8", "[]", "npm", "pkg", r#""versions":["1.0.0","oops"]"#)?;
    let good = record("OSV-9", "[]", "npm", "pkg", &ranges(r#"{"introduced":"0"}"#))?;
    let report = match_inventory(&[package("npm", "pkg", "1.0.0")], &[bad_event, bad_listed, good]);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings.first().map(|finding| finding.record_id.as_str()), Some("OSV-9"));
    assert_eq!(
        report.unmatched_counts.get(&UnmatchedReason::UnparsableRecordVersion),
        Some(&TWO_BAD_RECORDS)
    );
    let ids: Vec<_> = report.unmatched.iter().filter_map(|entry| entry.record_id.as_deref()).collect();
    assert_eq!(ids, vec!["OSV-7", "OSV-8"]);
    Ok(())
}


#[test]
fn output_is_sorted_and_deduplicated() -> TestResult {
    let events = ranges(r#"{"introduced":"0"}"#);
    let records = [
        record("OSV-B", "[]", "npm", "b", &events)?,
        record("OSV-A", "[]", "npm", "b", &events)?,
        record("OSV-C", "[]", "npm", "a", &events)?,
    ];
    let inventory = [package("npm", "b", "1.0.0"), package("npm", "a", "1.0.0"), package("npm", "b", "1.0.0")];
    let report = match_inventory(&inventory, &records);
    let order: Vec<(&str, &str)> = report
        .findings
        .iter()
        .map(|finding| (finding.package.as_str(), finding.record_id.as_str()))
        .collect();
    assert_eq!(order, vec![("a", "OSV-C"), ("b", "OSV-A"), ("b", "OSV-B")]);
    let reversed_records: Vec<OsvRecord> = records.iter().rev().cloned().collect();
    let reversed_inventory: Vec<Package> = inventory.iter().rev().cloned().collect();
    assert_eq!(match_inventory(&reversed_inventory, &reversed_records), report);
    Ok(())
}


#[test]
fn empty_inputs_give_an_empty_report() -> TestResult {
    assert_eq!(match_inventory(&[], &[]), MatchReport::default());
    Ok(())
}


#[test]
fn first_matching_range_of_an_entry_wins() -> TestResult {
    let both = r#""ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]},{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]"#;
    let records = [record("OSV-10", "[]", "npm", "pkg", both)?];
    let report = match_inventory(&[package("npm", "pkg", "1.0.0")], &records);
    assert_eq!(
        report.findings.first().and_then(|finding| finding.fixed_version.clone()),
        Some("2.0.0".to_string())
    );
    Ok(())
}
