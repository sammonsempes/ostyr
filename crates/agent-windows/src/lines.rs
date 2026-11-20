use crate::model::{Channel, GapReason, Refusal, SystemInfo};
use serde_json::json;


pub fn reason_name(reason: GapReason) -> &'static str {
    match reason {
        GapReason::Hole => "hole",
        GapReason::CursorInvalid => "cursor_invalid",
    }
}


pub fn refusal_name(reason: Refusal) -> &'static str {
    match reason {
        Refusal::Oversized => "oversized",
        Refusal::Malformed => "malformed",
    }
}


pub fn gap_line(channel: &Channel, reason: GapReason, range: Option<(u64, u64)>) -> String {
    let first = range.map(|(start, _)| start);
    let last = range.map(|(_, end)| end);
    let count = range.map(|(start, end)| end - start + 1);
    json!({
        "event": {"kind": "agent.event_gap"},
        "agent": {"event_gap": {
            "channel": channel.name,
            "reason": reason_name(reason),
            "first_missing": first,
            "last_missing": last,
            "count": count,
        }},
    })
    .to_string()
}


pub fn refused_line(channel: &Channel, info: &SystemInfo, reason: Refusal, size: usize) -> String {
    json!({
        "event": {"kind": "agent.event_refused"},
        "agent": {"event_refused": {
            "channel": channel.name,
            "record_id": info.record_id,
            "event_id": info.event_id,
            "time": info.time,
            "reason": refusal_name(reason),
            "bytes": size,
        }},
    })
    .to_string()
}
