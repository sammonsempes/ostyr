#[path = "common/types.rs"]
mod types;


use sbom::model::Outcome;
use sbom::purl::classify;
use types::TestResult;


fn package_of(purl: &str, version: Option<&str>) -> Option<(String, String, String)> {
    classify(Some(purl), "component", version)
        .package
        .map(|package| (package.ecosystem, package.name, package.version))
}


fn tuple(ecosystem: &str, name: &str, version: &str) -> Option<(String, String, String)> {
    Some((ecosystem.to_string(), name.to_string(), version.to_string()))
}


#[test]
fn debian_and_ubuntu_carry_their_release() -> TestResult {
    assert_eq!(
        package_of("pkg:deb/debian/bash@5.2?distro=debian-12", None),
        tuple("Debian:12", "bash", "5.2")
    );
    assert_eq!(
        package_of("pkg:deb/ubuntu/curl@8.5?distro=Ubuntu-22.04", None),
        tuple("Ubuntu:22.04", "curl", "8.5")
    );
    Ok(())
}


#[test]
fn debian_without_release_uses_the_namespace() -> TestResult {
    assert_eq!(package_of("pkg:deb/debian/bash@5.2", None), tuple("Debian", "bash", "5.2"));
    assert_eq!(package_of("pkg:deb/ubuntu/bash@5.2?distro=ubuntu", None), tuple("Ubuntu", "bash", "5.2"));
    assert_eq!(package_of("pkg:deb/debian/bash@5.2?distro=debian-", None), tuple("Debian", "bash", "5.2"));
    Ok(())
}


#[test]
fn unknown_distribution_is_unmapped() -> TestResult {
    assert_eq!(package_of("pkg:deb/kali/bash@5.2", None), None);
    assert_eq!(package_of("pkg:deb/bash@5.2", None), None);
    assert_eq!(classify(Some("pkg:deb/bash@5.2"), "bash", None).outcome, Outcome::Unmapped);
    Ok(())
}


#[test]
fn upstream_names_the_source_package() -> TestResult {
    assert_eq!(
        package_of("pkg:deb/debian/libc6@2.36?distro=debian-12&upstream=glibc", None),
        tuple("Debian:12", "glibc", "2.36")
    );
    assert_eq!(
        package_of("pkg:deb/debian/libc6@2.36?distro=debian-12&upstream=glibc%402.35", None),
        tuple("Debian:12", "glibc", "2.36")
    );
    Ok(())
}


#[test]
fn rpm_uses_the_namespace_without_release() -> TestResult {
    assert_eq!(
        package_of("pkg:rpm/rhel/bash@5.1-2.el9?distro=rhel-9.2", None),
        tuple("Red Hat", "bash", "5.1-2.el9")
    );
    assert_eq!(package_of("pkg:rpm/rocky/bash@5.1", None), tuple("Rocky Linux", "bash", "5.1"));
    assert_eq!(package_of("pkg:rpm/fedora/bash@5.1", None), None);
    Ok(())
}


#[test]
fn cargo_and_npm_map_directly() -> TestResult {
    assert_eq!(package_of("pkg:cargo/serde@1.0.190", None), tuple("crates.io", "serde", "1.0.190"));
    assert_eq!(package_of("pkg:npm/lodash@4.17.20", None), tuple("npm", "lodash", "4.17.20"));
    assert_eq!(package_of("pkg:npm/%40babel/core@7.22.5", None), tuple("npm", "@babel/core", "7.22.5"));
    Ok(())
}


#[test]
fn component_version_wins_over_the_purl_version() -> TestResult {
    assert_eq!(package_of("pkg:cargo/serde@1.0.1", Some("1.0.2")), tuple("crates.io", "serde", "1.0.2"));
    Ok(())
}


#[test]
fn mapped_without_any_version_has_no_package() -> TestResult {
    let classified = classify(Some("pkg:cargo/serde"), "serde", None);
    assert_eq!((classified.package, classified.outcome), (None, Outcome::Mapped));
    Ok(())
}


#[test]
fn key_drops_version_qualifiers_and_keeps_the_namespace() -> TestResult {
    let key = classify(Some("pkg:deb/debian/bash@5.2?arch=amd64&distro=debian-12"), "bash", None).key;
    assert_eq!(key, "deb/debian/bash");
    assert_eq!(classify(Some("pkg:cargo/serde@1"), "serde", None).key, "cargo/serde");
    Ok(())
}


#[test]
fn missing_and_malformed_purls_use_the_component_name() -> TestResult {
    let none = classify(None, "thing", Some("1"));
    assert_eq!((none.key.as_str(), none.outcome), ("component/thing", Outcome::NoPurl));
    let bad = classify(Some("definitely not a purl"), "thing", Some("1"));
    assert_eq!(
        (bad.key.as_str(), bad.outcome, bad.package),
        ("component/thing", Outcome::Malformed, None)
    );
    Ok(())
}
