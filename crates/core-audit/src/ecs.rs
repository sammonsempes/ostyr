use crate::canonical::{actor_label, outcome_label};
use crate::error::AuditError;
use crate::model::{Outcome, Record, GENESIS_HASH};
use crate::verify::{check_head, check_line, raw_lines};
use serde_json::{json, Value};
use std::io::{BufRead, Write};


pub const ECS_VERSION: &str = "8.11";


pub const IAM_ACTION_PREFIXES: [&str; 3] = ["iam.", "auth.", "authz."];


pub fn category(action: &str) -> &'static str {
    if IAM_ACTION_PREFIXES.iter().any(|prefix| action.starts_with(prefix)) {
        "iam"
    } else {
        "configuration"
    }
}


pub fn ecs_outcome(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "success",
        Outcome::Failure | Outcome::Denied => "failure",
    }
}


pub fn to_ecs(record: &Record) -> Value {
    json!({
        "@timestamp": record.timestamp,
        "ecs": { "version": ECS_VERSION },
        "event": {
            "kind": "event",
            "category": [category(&record.action)],
            "action": record.action,
            "outcome": ecs_outcome(record.outcome),
            "id": record.hash,
            "reason": record.justification,
        },
        "trace": { "id": record.request_id },
        "user": { "id": record.actor_id },
        "service": { "name": record.module },
        "organization": { "id": record.tenant },
        "ostyr": {
            "actor_kind": actor_label(record.actor_kind),
            "target": record.target,
            "outcome": outcome_label(record.outcome),
            "parameters": record.parameters,
            "previous_hash": record.previous_hash,
        },
    })
}


/// Reads a log (refusing a broken chain or, given `expected_head`, a head that differs) and writes one ECS event per line; returns the event count.
pub fn export<Input: BufRead, Output: Write>(input: Input, out: &mut Output, expected_head: Option<&str>) -> Result<usize, AuditError> {
    raw_lines(input)
        .enumerate()
        .try_fold((0, GENESIS_HASH.to_owned()), |(_, previous), (index, line)| {
            let record = check_line(&line?, &previous).map_err(|reason| AuditError::Broken { line: index + 1, reason })?;
            writeln!(out, "{}", to_ecs(&record))?;
            Ok((index + 1, record.hash))
        })
        .and_then(|(count, head)| check_head(expected_head, head).map(|_| count))
}
