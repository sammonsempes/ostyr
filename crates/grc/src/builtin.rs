use crate::error::GrcError;
use crate::load::{load_framework, parse_framework, MAX_ID_CHARS};
use crate::model::Framework;
use std::path::Path;


pub const BUILTIN_COUNT: usize = 6;


pub const KNOWN_INDICATOR_COUNT: usize = 13;


pub const BUILTIN_PREFIX: &str = "builtin:";


/// The indicator vocabulary the built-in frameworks draw from (spec section 13 table).
pub const KNOWN_INDICATORS: [&str; KNOWN_INDICATOR_COUNT] = [
    "endpoint.full_protection_ratio",
    "vuln.kev_mean_days_to_fix",
    "logging.active_sources_ratio",
    "logging.retention_ratio",
    "incident.mean_hours_to_close",
    "identity.privileged_without_mfa",
    "identity.inactive_accounts",
    "backup.days_since_restore_test",
    "detection.test_success_ratio",
    "hardening.mean_score_ratio",
    "patch.on_time_ratio",
    "encryption.workstation_ratio",
    "assets.owned_ratio",
];


/// Built-in framework names with the text shipped in the crate.
pub const BUILTIN: [(&str, &str); BUILTIN_COUNT] = [
    ("nis2", include_str!("../frameworks/nis2.yaml")),
    ("iso27001-2022", include_str!("../frameworks/iso27001-2022.yaml")),
    ("dora", include_str!("../frameworks/dora.yaml")),
    ("gdpr", include_str!("../frameworks/gdpr.yaml")),
    ("anssi-hygiene", include_str!("../frameworks/anssi-hygiene.yaml")),
    ("cis-v8", include_str!("../frameworks/cis-v8.yaml")),
];


/// Loads a built-in framework through the same checks as a file; an unknown name is cut to `MAX_ID_CHARS` in the error.
pub fn builtin_framework(name: &str) -> Result<Framework, GrcError> {
    let file = format!("{BUILTIN_PREFIX}{name}");
    let (_, text) = BUILTIN.iter().find(|(known, _)| *known == name).ok_or_else(|| GrcError::UnknownBuiltin {
        name: name.chars().take(MAX_ID_CHARS).collect(),
    })?;
    parse_framework(&mut text.as_bytes(), &file)
}


/// `builtin:<name>` selects a built-in framework, anything else is a file path.
pub fn resolve_framework(argument: &str) -> Result<Framework, GrcError> {
    match argument.strip_prefix(BUILTIN_PREFIX) {
        Some(name) => builtin_framework(name),
        None => load_framework(Path::new(argument)),
    }
}
