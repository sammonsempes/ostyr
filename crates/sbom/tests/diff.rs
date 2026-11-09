#[path = "common/types.rs"]
mod types;


use sbom::convert::to_packages;
use sbom::diff::diff;
use sbom::error::DiffError;
use sbom::model::{Limits, Sbom};
use sbom::parse::parse_cyclonedx;
use std::io::Cursor;
use types::TestResult;
use vuln_match::matcher::match_inventory;
use vuln_match::osv::parse_record;


const FIXTURE: &str = include_str!("fixtures/syft-debian.cdx.json");


const PACKAGES_FROM_FIXTURE: usize = 5;


fn parse_for(text: &str, tenant: &str, artefact: &str) -> Result<Sbom, Box<dyn std::error::Error>> {
    Ok(parse_cyclonedx(
        Cursor::new(text.as_bytes().to_vec()),
        tenant,
        artefact,
        &Limits::default(),
    )?)
}


fn component(name: &str, version: &str) -> String {
    format!(r#"{{"name":"{name}","version":"{version}","purl":"pkg:cargo/{name}@{version}"}}"#)
}


fn sbom_of(components: &[String], tenant: &str, artefact: &str) -> Result<Sbom, Box<dyn std::error::Error>> {
    parse_for(&format!(r#"{{"components":[{}]}}"#, components.join(",")), tenant, artefact)
}


#[test]
fn diff_reports_added_removed_and_changed() -> TestResult {
    let old = sbom_of(&[component("a", "1.0.0"), component("b", "1.0.0"), component("c", "1.0.0")], "t", "x")?;
    let new = sbom_of(&[component("a", "1.0.0"), component("b", "2.0.0"), component("d", "1.0.0")], "t", "x")?;
    let result = diff(&old, &new)?;
    assert_eq!(result.added.iter().map(|added| added.key.as_str()).collect::<Vec<_>>(), ["cargo/d"]);
    assert_eq!(result.removed.iter().map(|removed| removed.key.as_str()).collect::<Vec<_>>(), ["cargo/c"]);
    let change = result.changed.first().ok_or("no change")?;
    assert_eq!(change.key, "cargo/b");
    assert_eq!(
        (change.old_versions.as_slice(), change.new_versions.as_slice()),
        (["1.0.0".to_string()].as_slice(), ["2.0.0".to_string()].as_slice())
    );
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.added.first().map(|added| added.versions.clone()), Some(vec!["1.0.0".to_string()]));
    Ok(())
}


#[test]
fn identical_sboms_have_an_empty_diff() -> TestResult {
    let one = parse_for(FIXTURE, "t", "x")?;
    let two = parse_for(FIXTURE, "t", "x")?;
    assert_eq!(diff(&one, &two)?, Default::default());
    Ok(())
}


#[test]
fn a_component_without_version_has_an_empty_version() -> TestResult {
    let old = parse_for(r#"{"components":[{"name":"a"}]}"#, "t", "x")?;
    let new = sbom_of(&[], "t", "x")?;
    let result = diff(&old, &new)?;
    assert_eq!(result.removed.first().map(|removed| removed.versions.clone()), Some(vec![String::new()]));
    Ok(())
}


#[test]
fn mixed_tenants_or_artefacts_are_refused() -> TestResult {
    let base = sbom_of(&[], "t", "x")?;
    let other_tenant = sbom_of(&[], "u", "x")?;
    let other_artefact = sbom_of(&[], "t", "y")?;
    assert!(matches!(diff(&base, &other_tenant), Err(DiffError::TenantMismatch)));
    assert!(matches!(diff(&base, &other_artefact), Err(DiffError::ArtefactMismatch)));
    Ok(())
}


#[test]
fn packages_are_sorted_and_deduplicated() -> TestResult {
    let sbom = sbom_of(&[component("b", "1.0.0"), component("a", "1.0.0"), component("b", "1.0.0")], "t", "x")?;
    let names: Vec<String> = to_packages(&sbom).into_iter().map(|package| package.name).collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(to_packages(&parse_for(FIXTURE, "t", "x")?).len(), PACKAGES_FROM_FIXTURE);
    Ok(())
}


#[test]
fn converted_packages_match_an_osv_record() -> TestResult {
    let record = parse_record(
        r#"{"id":"DSA-1","aliases":["CVE-2024-0001"],"affected":[{"package":{"ecosystem":"Debian:12","name":"glibc"},
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.36-9+deb12u7"}]}]}]}"#,
    )?;
    let report = match_inventory(&to_packages(&parse_for(FIXTURE, "t", "x")?), &[record]);
    assert_eq!(report.findings.len(), 1);
    let finding = report.findings.first().ok_or("no finding")?;
    assert_eq!(
        (finding.package.as_str(), finding.installed_version.as_str()),
        ("glibc", "2.36-9+deb12u4")
    );
    assert_eq!(finding.fixed_version.as_deref(), Some("2.36-9+deb12u7"));
    Ok(())
}
