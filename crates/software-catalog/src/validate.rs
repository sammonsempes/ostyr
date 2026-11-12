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
        && is_plain_text(text)
        && match manager {
            Manager::Apt | Manager::Dnf => parse_version(family_of(manager), text).is_ok(),
            Manager::Winget | Manager::Msi => true,
        }
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
