use crate::model::{DatasetProbe, EcsEnvelope};
use time::OffsetDateTime;


pub const MAX_REASON_CHARS: usize = 200;


pub const OVERSIZE_PREFIX: &str = "message of ";


pub const NOT_ECS_PREFIX: &str = "not an ECS document: ";


/// The dataset of the host metrics the agent sends; metrics-ingest consumes it, every other consumer skips it.
pub const HOST_DATASET: &str = "ostyr.host_metrics";


pub fn truncate_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}


/// The event timestamp, or a reason that never echoes payload content.
pub fn check_message(payload: &[u8], max_message_bytes: usize) -> Result<OffsetDateTime, String> {
    if payload.len() > max_message_bytes {
        Err(format!(
            "{OVERSIZE_PREFIX}{} bytes exceeds the cap of {max_message_bytes} bytes",
            payload.len()
        ))
    } else {
        serde_json::from_slice::<EcsEnvelope>(payload)
            .map(|envelope| envelope.timestamp)
            .map_err(|error| {
                format!(
                    "{NOT_ECS_PREFIX}{:?} error at line {} column {}",
                    error.classify(),
                    error.line(),
                    error.column()
                )
            })
    }
}


/// True when `event.dataset` is the host metrics dataset; any unreadable payload is false. The caller has bounded the payload.
pub fn is_host_metrics(payload: &[u8]) -> bool {
    serde_json::from_slice::<DatasetProbe>(payload)
        .ok()
        .and_then(|probe| probe.event)
        .and_then(|part| part.dataset)
        .is_some_and(|dataset| dataset == HOST_DATASET)
}
