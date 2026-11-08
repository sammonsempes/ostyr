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
