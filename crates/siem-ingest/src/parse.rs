use crate::model::EcsEnvelope;
use time::OffsetDateTime;


pub const MAX_REASON_CHARS: usize = 200;


pub fn truncate_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}


/// The event timestamp, or a reason that never echoes payload content.
pub fn check_message(payload: &[u8], max_message_bytes: usize) -> Result<OffsetDateTime, String> {
    if payload.len() > max_message_bytes {
        Err(format!("message of {} bytes exceeds the cap of {max_message_bytes} bytes", payload.len()))
    } else {
        serde_json::from_slice::<EcsEnvelope>(payload)
            .map(|envelope| envelope.timestamp)
            .map_err(|error| {
                format!(
                    "not an ECS document: {:?} error at line {} column {}",
                    error.classify(),
                    error.line(),
                    error.column()
                )
            })
    }
}
