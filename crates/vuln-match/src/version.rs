//! Per-ecosystem version parsing; parsed versions order with the ecosystem's own rules.

use crate::error::VersionError;
use crate::limits::MAX_VERSION_BYTES;
use crate::model::{Family, ParsedVersion};
use rpm_version::Evr;


const DEBIAN_BASES: [&str; 2] = ["Debian", "Ubuntu"];


const RPM_BASES: [&str; 5] = ["Red Hat", "Rocky Linux", "AlmaLinux", "SUSE", "openSUSE"];


const SEMVER_BASES: [&str; 3] = ["crates.io", "npm", "SemVer"];


const RPM_EXTRA_CHARS: &str = ".+~^:-_";


/// The ecosystem name without its release suffix (`Debian:12` is `Debian`).
pub fn ecosystem_base(ecosystem: &str) -> &str {
    ecosystem.split_once(':').map_or(ecosystem, |(base, _)| base)
}


pub fn family_of(ecosystem: &str) -> Result<Family, VersionError> {
    let base = ecosystem_base(ecosystem);
    let family = [
        (Family::Debian, DEBIAN_BASES.as_slice()),
        (Family::Rpm, RPM_BASES.as_slice()),
        (Family::SemVer, SEMVER_BASES.as_slice()),
    ]
    .into_iter()
    .find_map(|(family, bases)| bases.contains(&base).then_some(family));
    family.ok_or_else(|| VersionError::UnknownEcosystem(ecosystem.to_string()))
}


pub fn parse_version(family: Family, text: &str) -> Result<ParsedVersion, VersionError> {
    let parsed = if text.len() > MAX_VERSION_BYTES {
        None
    } else {
        match family {
            Family::Debian => text.parse().ok().map(ParsedVersion::Debian),
            Family::Rpm => parse_rpm(text).map(ParsedVersion::Rpm),
            Family::SemVer => semver::Version::parse(text).ok().map(ParsedVersion::SemVer),
        }
    };
    parsed.ok_or_else(|| VersionError::Unparsable {
        family,
        text: text.chars().take(MAX_VERSION_BYTES).collect(),
    })
}


fn parse_rpm(text: &str) -> Option<Evr<'static>> {
    let (epoch, version, release) = Evr::parse_values(text);
    let allowed = text
        .chars()
        .all(|symbol| symbol.is_ascii_alphanumeric() || RPM_EXTRA_CHARS.contains(symbol));
    let epoch_ok = epoch.chars().all(|symbol| symbol.is_ascii_digit());
    (allowed && epoch_ok && !version.is_empty()).then(|| Evr::new(epoch.to_string(), version.to_string(), release.to_string()))
}
