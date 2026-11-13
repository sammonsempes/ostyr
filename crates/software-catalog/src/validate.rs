//! Field checks of one entry.

use crate::model::{Entry, Manager, Source};
use crate::source::{family_of, manager_of, package_of, version_text};
use crate::text::{is_clean, is_entry_name, is_fingerprint, is_msi_key, is_sha256, is_subject, is_winget_id};
use patch_inventory::validate::{is_dpkg_name, is_plain_text, is_rpm_name};
use vuln_match::version::parse_version;


const FIELD_NAME: &str = "name";


const FIELD_SOURCE: &str = "source";


const FIELD_VERSION: &str = "version";


const FIELD_SHA256: &str = "sha256";


const FIELD_PUBLISHER: &str = "publisher";


const FIELD_UNINSTALL: &str = "uninstall";


const MAX_VERSION_CHARS: usize = 128;


const RPM_PUNCTUATION: &str = "._+~^";


pub const RPM_ARCHITECTURES: [&str; 13] = [
    "x86_64",
    "aarch64",
    "i686",
    "noarch",
    "ppc64le",
    "s390x",
    "src",
    "i386",
    "i586",
    "armv7hl",
    "ppc64",
    "nosrc",
    "x86_64_v2",
];


const DEBIAN_FORBIDDEN_TAIL: [char; 4] = ['+', '-', '~', '.'];


pub fn source_ok(source: &Source) -> bool {
    let package = package_of(source);
    is_clean(package)
        && match source {
            Source::Apt(_) => is_dpkg_name(package),
            Source::Dnf(_) => is_rpm_name(package),
            Source::Winget(_) => is_winget_id(package),
            Source::Msi(_) => is_msi_key(package),
        }
}


pub fn version_ok(entry: &Entry) -> bool {
    let text = version_text(&entry.version);
    let manager = manager_of(&entry.source);
    is_clean(text)
        && text.chars().count() <= MAX_VERSION_CHARS
        && is_plain_text(text)
        && match manager {
            Manager::Apt => deb_pin_ok(text) && parse_version(family_of(manager), text).is_ok(),
            Manager::Dnf => rpm_pin_ok(text) && parse_version(family_of(manager), text).is_ok(),
            Manager::Winget | Manager::Msi => true,
        }
}


pub fn deb_pin_ok(text: &str) -> bool {
    let upstream_and_revision = text.rsplit_once('-').unwrap_or((text, "x"));
    let upstream = upstream_and_revision.0.split_once(':').map_or(upstream_and_revision.0, |(_, rest)| rest);
    !upstream.is_empty() && !upstream_and_revision.1.is_empty() && !text.ends_with(DEBIAN_FORBIDDEN_TAIL)
}


pub fn rpm_pin_ok(text: &str) -> bool {
    match text.split(':').collect::<Vec<&str>>().as_slice() {
        [body] => release_pin_ok(body),
        [epoch, body] => !epoch.is_empty() && epoch.chars().all(|digit| digit.is_ascii_digit()) && release_pin_ok(body),
        _ => false,
    }
}


pub fn release_pin_ok(body: &str) -> bool {
    body.split_once('-')
        .is_some_and(|(version, release)| rpm_part_ok(version) && rpm_part_ok(release) && !ends_with_architecture(release))
}


pub fn rpm_part_ok(part: &str) -> bool {
    part.starts_with(|first: char| first.is_ascii_alphanumeric())
        && part.chars().all(|item| item.is_ascii_alphanumeric() || RPM_PUNCTUATION.contains(item))
}


pub fn ends_with_architecture(release: &str) -> bool {
    release.rsplit('.').next().is_some_and(|last| RPM_ARCHITECTURES.contains(&last))
}


pub fn sha256_ok(entry: &Entry) -> bool {
    match (&entry.source, &entry.sha256) {
        (Source::Msi(_), None) => false,
        (_, None) => true,
        (_, Some(digest)) => is_sha256(digest),
    }
}


pub fn publisher_ok(entry: &Entry) -> bool {
    match manager_of(&entry.source) {
        Manager::Apt | Manager::Dnf => is_fingerprint(&entry.publisher),
        Manager::Winget | Manager::Msi => is_subject(&entry.publisher),
    }
}


pub fn uninstall_ok(entry: &Entry) -> bool {
    !(entry.uninstall && matches!(entry.source, Source::Msi(_)))
}


pub fn first_problem(entry: &Entry) -> Option<&'static str> {
    [
        (FIELD_NAME, is_entry_name(&entry.name)),
        (FIELD_SOURCE, source_ok(&entry.source)),
        (FIELD_VERSION, version_ok(entry)),
        (FIELD_SHA256, sha256_ok(entry)),
        (FIELD_PUBLISHER, publisher_ok(entry)),
        (FIELD_UNINSTALL, uninstall_ok(entry)),
    ]
    .into_iter()
    .find_map(|(field, valid)| (!valid).then_some(field))
}
