use crate::model::CertRecord;


/// True when a DNS name of the certificate covers one of the owned host names (RFC 6125 wildcard rules, case-insensitive).
pub fn matches_domain(record: &CertRecord, owned_domains: &[String]) -> bool {
    record
        .dns_names
        .iter()
        .any(|pattern| owned_domains.iter().any(|owned| name_matches(pattern, owned)))
}


pub fn name_matches(pattern: &str, host: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    let host_lower = host.to_ascii_lowercase();
    match pattern_lower.strip_prefix("*.") {
        Some(rest) => {
            rest.contains('.') && !rest.contains('*') && host_lower.split_once('.').is_some_and(|(label, tail)| !label.is_empty() && tail == rest)
        }
        None => pattern_lower == host_lower,
    }
}


/// True when a certificate name covers the watched zone itself or a host below it (a trailing root dot is ignored on both sides).
pub fn covers_zone(pattern: &str, zone: &str) -> bool {
    let pattern_lower = trim_root_dot(&pattern.to_ascii_lowercase()).to_string();
    let zone_lower = trim_root_dot(&zone.to_ascii_lowercase()).to_string();
    let below_zone = format!(".{zone_lower}");
    !zone_lower.is_empty()
        && (name_matches(&pattern_lower, &zone_lower)
            || match pattern_lower.strip_prefix("*.") {
                Some(rest) => rest.contains('.') && !rest.contains('*') && (rest == zone_lower || rest.ends_with(&below_zone)),
                None => pattern_lower.ends_with(&below_zone),
            })
}


fn trim_root_dot(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}
