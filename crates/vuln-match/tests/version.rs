#[path = "common/types.rs"]
mod types;


use std::cmp::Ordering;
use types::TestResult;
use vuln_match::error::VersionError;
use vuln_match::model::Family;
use vuln_match::version::{ecosystem_base, family_of, parse_version};


const OVERLONG_VERSION: usize = 300;


const HUGE_VERSION: usize = 1000;


const MAX_MESSAGE: usize = 400;


fn compare(family: Family, left: &str, right: &str) -> Result<Ordering, VersionError> {
    Ok(parse_version(family, left)?.cmp(&parse_version(family, right)?))
}


fn check(family: Family, vectors: &[(&str, &str, Ordering)]) -> TestResult {
    vectors.iter().try_for_each(|(left, right, expected)| {
        assert_eq!(compare(family, left, right)?, *expected, "{left} against {right}");
        assert_eq!(compare(family, right, left)?, expected.reverse(), "{right} against {left}");
        Ok(())
    })
}


#[test]
fn debian_vectors() -> TestResult {
    check(
        Family::Debian,
        &[
            ("1.0", "1.0", Ordering::Equal),
            ("1.0-1", "1.0-2", Ordering::Less),
            ("1:1.0", "2.0", Ordering::Greater),
            ("0:1.0", "1.0", Ordering::Equal),
            ("1.0~rc1", "1.0", Ordering::Less),
            ("1.0~~", "1.0~", Ordering::Less),
            ("1.0~", "1.0", Ordering::Less),
            ("1.0a", "1.0+", Ordering::Less),
            ("1.0", "1.0+b1", Ordering::Less),
            ("1.0-1~bpo1", "1.0-1", Ordering::Less),
            ("1.2.10", "1.2.9", Ordering::Greater),
            ("1.0a", "1.0", Ordering::Greater),
            ("2:0.1", "1:9.9", Ordering::Greater),
            ("1.0-0", "1.0", Ordering::Equal),
        ],
    )
}


#[test]
fn rpm_vectors() -> TestResult {
    check(
        Family::Rpm,
        &[
            ("1.0", "1.0", Ordering::Equal),
            ("1.0", "2.0", Ordering::Less),
            ("2.0.1", "2.0", Ordering::Greater),
            ("5.5p1", "5.5p2", Ordering::Less),
            ("10xyz", "10.1xyz", Ordering::Less),
            ("1.a", "1.1", Ordering::Less),
            ("1.0a", "1.0", Ordering::Greater),
            ("1.0~rc1", "1.0", Ordering::Less),
            ("1.0~rc1", "1.0~rc2", Ordering::Less),
            ("1.0^", "1.0", Ordering::Greater),
            ("1.0^", "1.0.1", Ordering::Less),
            ("1.0^git1", "1.01", Ordering::Less),
            ("1.0~rc1^git1", "1.0~rc1", Ordering::Greater),
            ("1.0^git1~pre", "1.0^git1", Ordering::Less),
            ("1:1.0-1", "2.0-1", Ordering::Greater),
            ("0:1.0-1", "1.0-1", Ordering::Equal),
            ("1.0-1.el9", "1.0-2.el9", Ordering::Less),
            ("1.0-1.el9_2", "1.0-1.el9", Ordering::Greater),
        ],
    )
}


#[test]
fn semver_vectors() -> TestResult {
    check(
        Family::SemVer,
        &[
            ("1.0.0", "1.0.0", Ordering::Equal),
            ("1.0.0-alpha", "1.0.0", Ordering::Less),
            ("1.0.0-alpha", "1.0.0-alpha.1", Ordering::Less),
            ("1.0.0-alpha.1", "1.0.0-alpha.beta", Ordering::Less),
            ("1.0.0-beta.2", "1.0.0-beta.11", Ordering::Less),
            ("1.0.0-rc.1", "1.0.0", Ordering::Less),
            ("1.10.0", "1.9.0", Ordering::Greater),
        ],
    )
}


#[test]
fn unparsable_versions_are_errors() -> TestResult {
    let too_long = "1".repeat(OVERLONG_VERSION);
    let cases = [
        (Family::Debian, ""),
        (Family::Debian, "not a version"),
        (Family::Debian, too_long.as_str()),
        (Family::Rpm, ""),
        (Family::Rpm, "1.0 beta"),
        (Family::Rpm, "x:1.0"),
        (Family::Rpm, "-1"),
        (Family::SemVer, "1.0"),
        (Family::SemVer, "v1.0.0"),
    ];
    cases.iter().for_each(|(family, text)| {
        let result = parse_version(*family, text);
        assert!(
            matches!(result, Err(VersionError::Unparsable { family: found, .. }) if found == *family),
            "{text}"
        );
    });
    Ok(())
}


#[test]
fn unparsable_error_truncates_the_text() -> TestResult {
    let too_long = "x".repeat(HUGE_VERSION);
    let error = parse_version(Family::SemVer, &too_long).err().ok_or("expected an error")?;
    assert!(error.to_string().len() < MAX_MESSAGE, "{}", error.to_string().len());
    Ok(())
}


#[test]
fn ecosystems_map_to_families() -> TestResult {
    let expected = [
        ("Debian", Family::Debian),
        ("Debian:12", Family::Debian),
        ("Ubuntu:22.04:LTS", Family::Debian),
        ("Red Hat:enterprise_linux:9::appstream", Family::Rpm),
        ("Rocky Linux:9", Family::Rpm),
        ("AlmaLinux:9", Family::Rpm),
        ("SUSE", Family::Rpm),
        ("openSUSE:Leap 15.5", Family::Rpm),
        ("crates.io", Family::SemVer),
        ("npm", Family::SemVer),
        ("SemVer", Family::SemVer),
    ];
    expected.iter().try_for_each(|(name, family)| {
        assert_eq!(family_of(name)?, *family, "{name}");
        Ok::<(), VersionError>(())
    })?;
    assert!(matches!(family_of("PyPI"), Err(VersionError::UnknownEcosystem(name)) if name == "PyPI"));
    assert_eq!(ecosystem_base("Debian:12"), "Debian");
    assert_eq!(ecosystem_base("npm"), "npm");
    Ok(())
}
