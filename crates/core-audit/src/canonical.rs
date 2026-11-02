use crate::model::{ActorKind, NewEntry, Outcome, Record};
use crate::redact::redact_parameters;
use crate::types::ParameterMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::UtcOffset;


pub fn actor_label(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::User => "user",
        ActorKind::Ai => "ai",
        ActorKind::System => "system",
    }
}


pub fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Denied => "denied",
    }
}


fn text(value: &str) -> String {
    Value::String(value.to_owned()).to_string()
}


fn parameters_text(parameters: &ParameterMap) -> String {
    let members: Vec<String> = parameters.iter().map(|(key, value)| format!("{}:{}", text(key), text(value))).collect();
    format!("{{{}}}", members.join(","))
}


/// Every field except `hash`, as JSON members in the fixed order of the chain.
pub fn render_fields(record: &Record) -> String {
    let justification = record.justification.as_deref().map_or_else(|| Value::Null.to_string(), text);
    [
        format!("\"timestamp\":{}", text(&record.timestamp)),
        format!("\"actor_kind\":{}", text(actor_label(record.actor_kind))),
        format!("\"actor_id\":{}", text(&record.actor_id)),
        format!("\"tenant\":{}", text(&record.tenant)),
        format!("\"module\":{}", text(&record.module)),
        format!("\"action\":{}", text(&record.action)),
        format!("\"target\":{}", text(&record.target)),
        format!("\"outcome\":{}", text(outcome_label(record.outcome))),
        format!("\"request_id\":{}", text(&record.request_id)),
        format!("\"justification\":{justification}"),
        format!("\"parameters\":{}", parameters_text(&record.parameters)),
        format!("\"previous_hash\":{}", text(&record.previous_hash)),
    ]
    .join(",")
}


/// SHA-256 as lowercase hex over the canonical text `{fields}`.
pub fn compute_hash(record: &Record) -> String {
    format!("{:x}", Sha256::digest(format!("{{{}}}", render_fields(record)).as_bytes()))
}


/// The exact bytes stored for a record, newline included.
pub fn render_line(record: &Record) -> String {
    format!("{{{},\"hash\":{}}}\n", render_fields(record), text(&record.hash))
}


/// Builds a sealed record: timestamp in UTC, parameters redacted, hash chained to `previous_hash`.
pub fn seal(entry: NewEntry, previous_hash: &str) -> Result<Record, time::error::Format> {
    let timestamp = entry.timestamp.to_offset(UtcOffset::UTC).format(&Rfc3339)?;
    let unsealed = Record {
        timestamp,
        actor_kind: entry.actor.kind,
        actor_id: entry.actor.id,
        tenant: entry.tenant,
        module: entry.module,
        action: entry.action,
        target: entry.target,
        outcome: entry.outcome,
        request_id: entry.request_id,
        justification: entry.justification,
        parameters: redact_parameters(&entry.parameters),
        previous_hash: previous_hash.to_owned(),
        hash: String::new(),
    };
    let hash = compute_hash(&unsealed);
    Ok(Record { hash, ..unsealed })
}
