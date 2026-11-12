//! Accessors on the source and version of an entry.

use crate::model::{Manager, Source, Version};
use vuln_match::model::Family;


pub fn manager_of(source: &Source) -> Manager {
    match source {
        Source::Apt(_) => Manager::Apt,
        Source::Dnf(_) => Manager::Dnf,
        Source::Winget(_) => Manager::Winget,
        Source::Msi(_) => Manager::Msi,
    }
}


pub fn package_of(source: &Source) -> &str {
    match source {
        Source::Apt(package) | Source::Dnf(package) | Source::Winget(package) | Source::Msi(package) => package,
    }
}


pub fn version_text(version: &Version) -> &str {
    match version {
        Version::Pinned(text) | Version::LatestApproved(text) => text,
    }
}


pub fn family_of(manager: Manager) -> Family {
    match manager {
        Manager::Apt => Family::Debian,
        Manager::Dnf => Family::Rpm,
        Manager::Winget | Manager::Msi => Family::SemVer,
    }
}
