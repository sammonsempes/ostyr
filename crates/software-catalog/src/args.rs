//! Exact package-manager argument vectors, built from validated fields only and never run through a shell.

use crate::model::{ActionKind, Entry, Source};
use crate::source::version_text;


pub const FIXED_FLAGS: [&str; 4] = ["-y", "--id", "--version", "--exact"];


pub fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}


pub fn arguments(kind: ActionKind, entry: &Entry) -> Vec<String> {
    let version = version_text(&entry.version);
    match (kind, &entry.source) {
        (ActionKind::Install | ActionKind::Update, Source::Apt(package)) => words(&["apt-get", "install", "-y", &format!("{package}={version}")]),
        (ActionKind::Install | ActionKind::Update, Source::Dnf(package)) => words(&["dnf", "install", "-y", &format!("{package}-{version}")]),
        (ActionKind::Install, Source::Winget(id)) => words(&["winget", "install", "--id", id, "--version", version, "--exact"]),
        (ActionKind::Update, Source::Winget(id)) => words(&["winget", "upgrade", "--id", id, "--version", version, "--exact"]),
        (ActionKind::Install | ActionKind::Update, Source::Msi(key)) => words(&["msiexec", "/i", key, "/qn"]),
        (ActionKind::Uninstall, Source::Apt(package)) => words(&["apt-get", "remove", "-y", package]),
        (ActionKind::Uninstall, Source::Dnf(package)) => words(&["dnf", "remove", "-y", package]),
        (ActionKind::Uninstall, Source::Winget(id)) => words(&["winget", "uninstall", "--id", id, "--exact"]),
        (ActionKind::Uninstall, Source::Msi(_)) | (ActionKind::NewerThanCatalogue | ActionKind::Unknown | ActionKind::NotInCatalogue, _) => {
            Vec::new()
        }
    }
}
