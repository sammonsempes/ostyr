use sha2::{Digest, Sha256};


pub const ID_HEX_LENGTH: usize = 64;


pub fn absorb(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_be_bytes());
    hasher.update(text.as_bytes());
}


/// SHA-256 over the length-prefixed tenant and rule id, the event count, then the sorted length-prefixed event ids, as lowercase hex.
pub fn alert_id(tenant: &str, rule_id: &str, event_ids: &[String]) -> String {
    let mut sorted: Vec<&String> = event_ids.iter().collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    absorb(&mut hasher, tenant);
    absorb(&mut hasher, rule_id);
    hasher.update((event_ids.len() as u64).to_be_bytes());
    sorted.iter().for_each(|event_id| absorb(&mut hasher, event_id));
    format!("{:x}", hasher.finalize())
}


pub fn is_alert_id(text: &str) -> bool {
    text.len() == ID_HEX_LENGTH && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
