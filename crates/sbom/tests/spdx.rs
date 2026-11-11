#[path = "common/types.rs"]
mod types;


use sbom::diff::diff;
use sbom::error::SbomError;
use sbom::limits::MAX_EXTERNAL_REFS;
use sbom::model::{Limits, Sbom};
use sbom::parse::{parse_cyclonedx, parse_document};
use sbom::spdx::parse_spdx;
use std::io::Cursor;
use types::TestResult;


const SPDX_FIXTURE: &str = include_str!("fixtures/syft-debian.spdx.json");


const CDX_FIXTURE: &str = include_str!("fixtures/syft-debian.cdx.json");


const TENANT: &str = "tenant-a";


const ARTEFACT: &str = "web:1.0";


const FIXTURE_PACKAGES: usize = 6;


const FIXTURE_LIBRARIES: usize = 5;


const HUGE: usize = 1_000_000;


const FILES: usize = 10_000;


const PAST_JSON_NESTING: usize = 300;


const SMALL_STRING: usize = 8;


const CATEGORY_FITS: usize = 16;


const SMALL_BYTES: usize = 64;


const TWO: usize = 2;


fn run(text: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    parse_spdx(Cursor::new(text.as_bytes().to_vec()), TENANT, ARTEFACT, limits)
}


fn spdx(text: &str) -> Result<Sbom, SbomError> {
    run(text, &Limits::default())
}


fn document(text: &str) -> Result<Sbom, SbomError> {
    parse_document(Cursor::new(text.as_bytes().to_vec()), TENANT, ARTEFACT, &Limits::default())
}


fn with_purl_only(mut sbom: Sbom) -> Sbom {
    sbom.components
        .retain(|component| component.purl.is_some() && component.kind != "container");
    sbom
}


fn purl_ref(category: &str, locator: &str) -> String {
    format!(r#"{{"referenceCategory":"{category}","referenceType":"purl","referenceLocator":"{locator}"}}"#)
}


fn package_with_refs(refs: &[String]) -> String {
    format!(
        r#"{{"spdxVersion":"SPDX-2.3","packages":[{{"name":"a","externalRefs":[{}]}}]}}"#,
        refs.join(",")
    )
}


#[test]
fn syft_sample_is_read() -> TestResult {
    let sbom = spdx(SPDX_FIXTURE)?;
    assert_eq!(sbom.components.len(), FIXTURE_PACKAGES);
    assert_eq!((sbom.tenant.as_str(), sbom.artefact.as_str()), (TENANT, ARTEFACT));
    let libc = sbom
        .components
        .iter()
        .find(|component| component.name == "libc6")
        .ok_or("libc6 missing")?;
    assert_eq!(libc.version.as_deref(), Some("2.36-9+deb12u14"));
    assert_eq!(libc.kind, "unknown");
    assert_eq!(libc.key, "deb/debian/libc6");
    assert_eq!(libc.package.as_ref().map(|package| package.name.as_str()), Some("glibc"));
    assert_eq!(libc.package.as_ref().map(|package| package.ecosystem.as_str()), Some("Debian:12"));
    assert_eq!((sbom.skipped, sbom.bad_purls, sbom.extra_purls), (0, 0, 0));
    assert_eq!(sbom.unmapped, 1);
    let root = sbom
        .components
        .iter()
        .find(|component| component.kind == "container")
        .ok_or("no image package")?;
    assert_eq!(root.kind, "container");
    Ok(())
}


#[test]
fn spdx_and_cyclonedx_of_the_same_image_diff_to_nothing() -> TestResult {
    let from_spdx = with_purl_only(spdx(SPDX_FIXTURE)?);
    let from_cdx = with_purl_only(document(CDX_FIXTURE)?);
    assert_eq!(from_spdx.components.len(), FIXTURE_LIBRARIES);
    assert_eq!(from_cdx.components.len(), FIXTURE_LIBRARIES);
    let changes = diff(&from_cdx, &from_spdx)?;
    assert!(changes.added.is_empty() && changes.removed.is_empty() && changes.changed.is_empty());
    Ok(())
}


#[test]
fn format_is_chosen_from_the_first_marker() -> TestResult {
    assert_eq!(document(SPDX_FIXTURE)?.components.len(), FIXTURE_PACKAGES);
    assert_eq!(document(CDX_FIXTURE)?.components.len(), FIXTURE_LIBRARIES + TWO);
    let both = r#"{"bomFormat":"CycloneDX","spdxVersion":"SPDX-2.3","components":[{"name":"c"}],"packages":[{"name":"p"},{"name":"q"}]}"#;
    assert_eq!(document(both)?.components.len(), 1);
    let both_spdx = r#"{"spdxVersion":"SPDX-2.3","bomFormat":"CycloneDX","components":[{"name":"c"}],"packages":[{"name":"p"},{"name":"q"}]}"#;
    assert_eq!(document(both_spdx)?.components.len(), TWO);
    Ok(())
}


#[test]
fn unknown_format_is_refused() -> TestResult {
    for text in [
        "{}",
        r#"{"packages":[]}"#,
        r#"{"components":[]}"#,
        r#"{"spdxVersion":5,"bomFormat":null,"x":[]}"#,
        r#"{"components":[{"name":"a"}],"bomFormat":"CycloneDX"}"#,
    ] {
        let error = document(text).err().ok_or("no error")?;
        assert!(matches!(error, SbomError::UnknownFormat), "{text}");
    }
    Ok(())
}


#[test]
fn each_parser_ignores_the_other_array() -> TestResult {
    let text = r#"{"components":[{"name":"c"}],"packages":[{"name":"p"},{"name":"q"}],"files":5}"#;
    let from_spdx = spdx(text)?;
    assert_eq!(from_spdx.components.len(), TWO);
    let from_cdx = parse_cyclonedx(Cursor::new(text.as_bytes().to_vec()), TENANT, ARTEFACT, &Limits::default())?;
    assert_eq!(from_cdx.components.len(), 1);
    assert!(spdx(r#"{"packages":7}"#)?.components.is_empty());
    Ok(())
}


#[test]
fn package_fields_and_purpose_are_read() -> TestResult {
    let text = r#"{"packages":[
        {"name":"a","versionInfo":"1","primaryPackagePurpose":"APPLICATION"},
        {"name":"b","versionInfo":2,"primaryPackagePurpose":3},
        "text",
        {"versionInfo":"1"},
        {"name":4}]}"#;
    let sbom = spdx(text)?;
    assert_eq!(sbom.components.len(), TWO);
    let first = sbom.components.first().ok_or("empty")?;
    assert_eq!((first.kind.as_str(), first.version.as_deref()), ("application", Some("1")));
    let second = sbom.components.get(1).ok_or("one")?;
    assert_eq!((second.kind.as_str(), second.version.as_deref()), ("unknown", None));
    assert_eq!(sbom.skipped, TWO + 1);
    Ok(())
}


#[test]
fn first_purl_wins_and_the_second_is_counted() -> TestResult {
    let text = package_with_refs(&[
        purl_ref("PACKAGE-MANAGER", "pkg:cargo/first@1"),
        purl_ref("PACKAGE_MANAGER", "pkg:cargo/second@2"),
    ]);
    let sbom = document(&text)?;
    assert_eq!(sbom.extra_purls, 1);
    let component = sbom.components.first().ok_or("empty")?;
    assert_eq!(component.purl.as_deref(), Some("pkg:cargo/first@1"));
    assert_eq!(component.key, "cargo/first");
    Ok(())
}


#[test]
fn only_package_manager_purl_references_count() -> TestResult {
    let other_category = purl_ref("OTHER", "pkg:cargo/x@1");
    let cpe = r#"{"referenceCategory":"PACKAGE-MANAGER","referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:x"}"#.to_string();
    let junk = r#"{"referenceType":5,"comment":"x","referenceLocator":{"a":1}}"#.to_string();
    let sbom = spdx(&package_with_refs(&[other_category, cpe, junk, "7".to_string()]))?;
    let component = sbom.components.first().ok_or("empty")?;
    assert_eq!(component.purl, None);
    assert_eq!((sbom.extra_purls, sbom.unmapped), (0, 1));
    let late = package_with_refs(&[
        r#"{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl"}"#.to_string(),
        purl_ref("PACKAGE-MANAGER", "pkg:cargo/late@1"),
    ]);
    let kept = spdx(&late)?;
    assert_eq!(kept.components.first().ok_or("empty")?.purl.as_deref(), Some("pkg:cargo/late@1"));
    assert_eq!(kept.extra_purls, 0);
    Ok(())
}


#[test]
fn non_array_external_refs_are_skipped() -> TestResult {
    let sbom = spdx(r#"{"packages":[{"name":"a","externalRefs":{"x":1}}]}"#)?;
    assert_eq!(sbom.components.len(), 1);
    Ok(())
}


#[test]
fn malformed_purl_is_counted_and_not_kept() -> TestResult {
    let text = package_with_refs(&[purl_ref("PACKAGE-MANAGER", "pkg:\\u0001\\u0002 bad")]);
    let sbom = spdx(&text)?;
    assert_eq!(sbom.bad_purls, 1);
    assert_eq!(sbom.components.first().ok_or("empty")?.purl, None);
    Ok(())
}


#[test]
fn oversized_purl_or_version_skips_the_package() -> TestResult {
    let limits = Limits {
        max_string_bytes: CATEGORY_FITS,
        ..Limits::default()
    };
    let long_purl = package_with_refs(&[purl_ref("PACKAGE-MANAGER", &"p".repeat(CATEGORY_FITS + 1))]);
    let sbom = run(&long_purl, &limits)?;
    assert_eq!((sbom.components.len(), sbom.skipped), (0, 1));
    let huge_version = format!(r#"{{"packages":[{{"name":"a","versionInfo":"{}"}}]}}"#, "v".repeat(HUGE));
    let from_huge = spdx(&huge_version)?;
    assert_eq!((from_huge.components.len(), from_huge.skipped), (0, 1));
    let long_name = format!(r#"{{"packages":[{{"name":"{}"}}]}}"#, "n".repeat(HUGE));
    assert_eq!(spdx(&long_name)?.skipped, 1);
    let long_cpe = format!(
        r#"{{"packages":[{{"name":"a","externalRefs":[{{"referenceType":"cpe23Type","referenceLocator":"{}"}}]}}]}}"#,
        "c".repeat(HUGE)
    );
    let kept = spdx(&long_cpe)?;
    assert_eq!((kept.components.len(), kept.skipped), (1, 0));
    Ok(())
}


#[test]
fn member_name_over_the_cap_ends_the_parse() -> TestResult {
    let limits = Limits {
        max_string_bytes: SMALL_STRING,
        ..Limits::default()
    };
    let top = format!(r#"{{"{}":1}}"#, "k".repeat(HUGE));
    let top_error = run(&top, &limits).err().ok_or("no error")?;
    assert!(matches!(top_error, SbomError::NameTooLong { max: SMALL_STRING }), "{top_error:?}");
    let in_package = format!(r#"{{"packages":[{{"{}":1}}]}}"#, "k".repeat(HUGE));
    assert!(matches!(run(&in_package, &limits).err(), Some(SbomError::NameTooLong { .. })));
    let in_ref = format!(r#"{{"packages":[{{"externalRefs":[{{"{}":1}}]}}]}}"#, "k".repeat(HUGE));
    assert!(matches!(run(&in_ref, &limits).err(), Some(SbomError::NameTooLong { .. })));
    Ok(())
}


#[test]
fn too_many_packages_and_too_many_bytes() -> TestResult {
    let limits = Limits {
        max_components: 1,
        ..Limits::default()
    };
    let error = run(r#"{"packages":[{"name":"a"},{"name":"b"}]}"#, &limits).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::TooMany { max: 1 }));
    let small = Limits {
        max_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    let size_error = run(SPDX_FIXTURE, &small).err().ok_or("no error")?;
    assert!(matches!(size_error, SbomError::TooLarge { max: SMALL_BYTES }));
    Ok(())
}


#[test]
fn external_refs_over_the_cap_skip_the_package() -> TestResult {
    let at_cap = vec![purl_ref("PACKAGE-MANAGER", "pkg:cargo/a@1"); MAX_EXTERNAL_REFS];
    let within = spdx(&package_with_refs(&at_cap))?;
    assert_eq!((within.components.len(), within.skipped), (1, 0));
    assert_eq!(within.extra_purls, MAX_EXTERNAL_REFS - 1);
    let over = vec![purl_ref("PACKAGE-MANAGER", "pkg:cargo/a@1"); MAX_EXTERNAL_REFS + 1];
    let refused = spdx(&package_with_refs(&over))?;
    assert_eq!((refused.components.len(), refused.skipped), (0, 1));
    Ok(())
}


#[test]
fn ten_thousand_files_are_skipped() -> TestResult {
    let files = vec![r#"{"fileName":"/a","SPDXID":"SPDXRef-File-a"}"#; FILES].join(",");
    let relationships = vec![r#"{"spdxElementId":"a","relationshipType":"CONTAINS"}"#; FILES].join(",");
    let text = format!(r#"{{"spdxVersion":"SPDX-2.3","files":[{files}],"relationships":[{relationships}],"packages":[{{"name":"a"}}]}}"#);
    let sbom = document(&text)?;
    assert_eq!((sbom.components.len(), sbom.skipped), (1, 0));
    Ok(())
}


#[test]
fn deep_nesting_in_an_ignored_member_is_refused() -> TestResult {
    let nested = format!("{}1{}", r#"{"a":"#.repeat(PAST_JSON_NESTING), "}".repeat(PAST_JSON_NESTING));
    let text = format!(r#"{{"packages":[{{"name":"a","annotations":{nested}}}],"annotations":[]}}"#);
    assert!(matches!(spdx(&text).err(), Some(SbomError::Json(_))));
    Ok(())
}
