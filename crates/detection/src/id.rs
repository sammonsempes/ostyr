use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};


/// Characters of an `event.id` kept in the identity of an event: with `:` and the 64 hex of the hash the identity stays within the 128 the alert store takes.
pub const MAX_EVENT_ID_CHARS: usize = 63;


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


pub const DIGEST_PREFIX: &str = "digest:";


/// `digest:<SHA-256 hex>` over the whole sorted set, each id length-prefixed (`u64be`), so a tail cut from the stored list still changes the alert id.
pub fn set_digest(sorted_ids: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((sorted_ids.len() as u64).to_be_bytes());
    sorted_ids.iter().for_each(|id| {
        hasher.update((id.len() as u64).to_be_bytes());
        hasher.update(id.as_bytes());
    });
    format!("{DIGEST_PREFIX}{}", HEXLOWER.encode(&hasher.finalize()))
}
