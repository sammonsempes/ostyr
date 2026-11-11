//! Package URL to diff key and vuln-match ecosystem.

use crate::limits::{DISTRO_QUALIFIER, HOSTILE_CHARS, NO_NAMESPACE, UPSTREAM_QUALIFIER};
use crate::model::{Classified, Outcome};
use packageurl::PackageUrl;
use std::str::FromStr;
use vuln_match::model::Package;


const DEB_DISTROS: [(&str, &str); 2] = [("debian", "Debian"), ("ubuntu", "Ubuntu")];


const RPM_DISTROS: [(&str, &str); 7] = [
    ("rhel", "Red Hat"),
    ("redhat", "Red Hat"),
    ("rocky", "Rocky Linux"),
    ("almalinux", "AlmaLinux"),
    ("opensuse", "openSUSE"),
    ("suse", "SUSE"),
    ("sles", "SUSE"),
];


pub fn classify(purl: Option<&str>, name: &str, version: Option<&str>) -> Classified {
    match purl {
        None => fallback(name, Outcome::NoPurl),
        Some(text) => match PackageUrl::from_str(text)
            .ok()
            .filter(|parsed| !text_is_hostile(text) && !purl_is_hostile(parsed))
            .ok_or(())
        {
            Err(()) => {
                tracing::debug!(purl = ?text, "malformed or hostile package URL");
                fallback(name, Outcome::Malformed)
            }
            Ok(parsed) => classify_parsed(&parsed, version),
        },
    }
}


/// A control, bidirectional or zero-width character: never kept in a component.
pub fn text_is_hostile(text: &str) -> bool {
    text.chars().any(|character| character.is_control() || HOSTILE_CHARS.contains(&character))
}


/// Any decoded field of the purl holding a hostile character.
pub fn purl_is_hostile(parsed: &PackageUrl) -> bool {
    let fields = [
        Some(parsed.ty()),
        parsed.namespace(),
        Some(parsed.name()),
        parsed.version(),
        parsed.subpath(),
    ];
    let qualifiers = parsed
        .qualifiers()
        .iter()
        .flat_map(|(key, value)| [Some(key.as_ref()), Some(value.as_ref())]);
    fields.into_iter().chain(qualifiers).flatten().any(text_is_hostile)
}


fn fallback(name: &str, outcome: Outcome) -> Classified {
    Classified {
        key: format!("component/{name}"),
        package: None,
        outcome,
    }
}


fn classify_parsed(parsed: &PackageUrl, version: Option<&str>) -> Classified {
    let ecosystem = ecosystem_of(parsed);
    let package = ecosystem
        .as_ref()
        .zip(version.or_else(|| parsed.version()))
        .map(|(base, installed)| Package {
            ecosystem: base.clone(),
            name: package_name_of(parsed),
            version: installed.to_string(),
        });
    Classified {
        key: key_of(parsed),
        package,
        outcome: if ecosystem.is_some() { Outcome::Mapped } else { Outcome::Unmapped },
    }
}


/// Type, namespace and name, without version, qualifiers or subpath.
pub fn key_of(parsed: &PackageUrl) -> String {
    let namespace = parsed.namespace().map(|text| format!("{text}/")).unwrap_or_else(String::new);
    format!("{}/{namespace}{}", parsed.ty(), parsed.name())
}


/// Release only for Debian and Ubuntu; an RPM ecosystem carries none, so it matches every release.
pub fn ecosystem_of(parsed: &PackageUrl) -> Option<String> {
    let (distro, release) = distro_of(parsed);
    match parsed.ty() {
        "deb" => {
            lookup(&DEB_DISTROS, &distro).map(|base| release.map_or_else(|| base.to_string(), |text| format!("{base}:{}", release_of(base, &text))))
        }
        "rpm" => lookup(&RPM_DISTROS, &distro).map(str::to_string),
        "cargo" => Some("crates.io".to_string()),
        "npm" => Some("npm".to_string()),
        _ => None,
    }
}


/// OSV files Debian per major release while syft reports `12.15`; Ubuntu keeps `22.04`.
pub fn release_of<'a>(base: &str, release: &'a str) -> &'a str {
    match base {
        "Debian" => release.split_once('.').map_or(release, |(major, _)| major),
        _ => release,
    }
}


fn lookup<'a>(table: &[(&str, &'a str)], distro: &str) -> Option<&'a str> {
    table.iter().find(|(id, _)| *id == distro).map(|(_, base)| *base)
}


/// Distribution id and release, from the `distro` qualifier (`debian-12`) or else the namespace.
fn distro_of(parsed: &PackageUrl) -> (String, Option<String>) {
    match parsed.qualifiers().get(DISTRO_QUALIFIER) {
        Some(text) => match text.split_once('-') {
            Some((id, release)) => (id.to_lowercase(), Some(release.to_string()).filter(|rest| !rest.is_empty())),
            None => (text.to_lowercase(), None),
        },
        None => (parsed.namespace().unwrap_or(NO_NAMESPACE).to_lowercase(), None),
    }
}


/// Debian vulnerabilities are filed against the source package, which the `upstream` qualifier names.
pub fn package_name_of(parsed: &PackageUrl) -> String {
    match (parsed.ty(), parsed.qualifiers().get(UPSTREAM_QUALIFIER), parsed.namespace()) {
        ("deb", Some(upstream), _) => upstream.split_once('@').map_or(upstream.as_ref(), |(name, _)| name).to_string(),
        ("npm", _, Some(scope)) => format!("{scope}/{}", parsed.name()),
        _ => parsed.name().to_string(),
    }
}
