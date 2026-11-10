use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};


/// Characters of an `event.id` kept in the identity of an event.
pub const MAX_EVENT_ID_CHARS: usize = 128;


pub fn update_prefixed(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part);
}


/// SHA-256 over the length-prefixed tenant, rule id, the count of event ids and the sorted length-prefixed event ids, in lower-case hex.
pub fn alert_id(tenant: &str, rule_id: &str, event_ids: &[String]) -> String {
    let mut sorted: Vec<&str> = event_ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    update_prefixed(&mut hasher, tenant.as_bytes());
    update_prefixed(&mut hasher, rule_id.as_bytes());
    hasher.update((sorted.len() as u64).to_be_bytes());
    sorted.iter().for_each(|event_id| update_prefixed(&mut hasher, event_id.as_bytes()));
    HEXLOWER.encode(&hasher.finalize())
}


/// The hash of the bytes the bus delivered, so two different events never share an identity even when an agent repeats an `event.id`.
pub fn payload_hash(payload: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(payload))
}


/// `<event.id cut to MAX_EVENT_ID_CHARS>:<payload hash>`, or the hash alone: deterministic, so a redelivery repeats it.
pub fn event_identity(event_id: Option<&str>, payload: &[u8]) -> String {
    let hash = payload_hash(payload);
    event_id.map_or_else(
        || hash.clone(),
        |text| format!("{}:{hash}", text.chars().take(MAX_EVENT_ID_CHARS).collect::<String>()),
    )
}
