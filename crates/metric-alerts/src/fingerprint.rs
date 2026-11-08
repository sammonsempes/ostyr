use sha2::{Digest, Sha256};
use std::iter::once;


/// Hex SHA-256 over the rule id and the labels sorted by name then value; each part is length-prefixed so no two inputs collide by concatenation.
pub fn fingerprint(rule_id: &str, labels: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = labels.iter().collect();
    sorted.sort();
    let canonical: String = once(rule_id)
        .chain(sorted.iter().flat_map(|pair| [pair.0.as_str(), pair.1.as_str()]))
        .map(|part| format!("{}:{part};", part.len()))
        .collect();
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}
