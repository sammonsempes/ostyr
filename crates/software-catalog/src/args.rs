//! Exact package-manager argument vectors, built from validated fields only and never run through a shell.

use crate::model::{ActionKind, Entry, Source};
use crate::source::version_text;


pub const FIXED_FLAGS: [&str; 8] = [
    "-y",
    "--id",
    "--version",
    "--exact",
    "--no-remove",
    "--remove",
    "--erase",
    "--setopt=obsoletes=False",
];


pub fn rpm_target(version: &str) -> String {
    if version.contains(':') {
        version.to_string()
    } else {
        format!("0:{version}")
    }
}


pub fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}


pub fn arguments(kind: ActionKind, entry: &Entry) -> Vec<String> {
    let version = version_text(&entry.version);
    match (kind, &entry.source) {
        (ActionKind::Install | ActionKind::Update, Source::Apt(package)) => {
            words(&["apt-get", "install", "-y", "--no-remove", &format!("{package}={version}")])
        }
        (ActionKind::Install | ActionKind::Update, Source::Dnf(package)) => words(&[
            "dnf",
            "install",
            "-y",
            "--setopt=obsoletes=False",
            &format!("{package}-{}", rpm_target(version)),
        ]),
        (ActionKind::Install, Source::Winget(id)) => words(&["winget", "install", "--id", id, "--version", version, "--exact"]),
        (ActionKind::Update, Source::Winget(id)) => words(&["winget", "upgrade", "--id", id, "--version", version, "--exact"]),
        (ActionKind::Install | ActionKind::Update, Source::Msi(key)) => words(&["msiexec", "/i", key, "/qn"]),
        (ActionKind::Uninstall, Source::Apt(package)) => words(&["dpkg", "--remove", package]),
        (ActionKind::Uninstall, Source::Dnf(package)) => words(&["rpm", "--erase", package]),
        (ActionKind::Uninstall, Source::Winget(id)) => words(&["winget", "uninstall", "--id", id, "--exact"]),
        (ActionKind::Uninstall, Source::Msi(_))
        | (ActionKind::NewerThanCatalogue | ActionKind::Unknown | ActionKind::NotInCatalogue | ActionKind::Unavailable | ActionKind::Held, _) => {
            Vec::new()
        }
    }
}
