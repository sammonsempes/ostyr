use crate::checkpoint::{load_checkpoint, save_checkpoint};
use crate::engine::{new_engine, process_event, snapshot, Engine};
use crate::error::CorrelationError;
use crate::field::{lookup, scalar_text};
use crate::reload::open_rules;
use crate::window::State;
use core_config::reload::ReloadContext;
use core_config::types::SharedAuditFn;
use serde_json::Value;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};


pub const EVENT_ID_FIELD: &str = "event.id";


/// Events between two checkpoints (0 turns the periodic ones off); the shutdown checkpoint is always written.
pub const CHECKPOINT_EVERY: u64 = 1000;


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub events: u64,
    pub alerts: u64,
    pub malformed: u64,
}


/// Reloads the checkpoint (a missing file means a first start, a corrupt one is an error) and opens the rules.
pub fn start_engine(
    mapping_file: PathBuf,
    rule_files: Vec<PathBuf>,
    checkpoint: &Path,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<Engine, CorrelationError> {
    let restored = load_checkpoint(checkpoint)?;
    info!(restored = restored.is_some(), "checkpoint loaded, a missing file is a first start");
    let state = restored.unwrap_or_else(|| {
        info!("no checkpoint, starting from an empty state");
        State::default()
    });
    let rules = Arc::new(open_rules(mapping_file, rule_files, audit, context)?);
    Ok(new_engine(rules, state))
}


/// The event's `event.id`, or `line-<n>` when it has none.
pub fn event_id(event: &Value, line_number: usize) -> String {
    lookup(event, EVENT_ID_FIELD)
        .and_then(scalar_text)
        .unwrap_or_else(|| format!("line-{line_number}"))
}


pub struct Sink<'a> {
    pub output: &'a mut dyn Write,
    pub checkpoint: &'a Path,
    pub every: u64,
}


fn handle_line(engine: &Engine, line_number: usize, text: &str, sink: &mut Sink, summary: Summary) -> Result<Summary, CorrelationError> {
    match serde_json::from_str::<Value>(text) {
        Err(error) => {
            warn!(%error, line_number, "line ignored: not JSON");
            Ok(Summary {
                malformed: summary.malformed + 1,
                ..summary
            })
        }
        Ok(event) => {
            let alerts = process_event(engine, &event_id(&event, line_number), &event);
            alerts.iter().try_for_each(|alert| {
                serde_json::to_writer(&mut *sink.output, alert).map_err(CorrelationError::Serialize)?;
                writeln!(sink.output).map_err(CorrelationError::from)
            })?;
            let updated = Summary {
                events: summary.events + 1,
                alerts: summary.alerts + alerts.len() as u64,
                ..summary
            };
            if updated.events.checked_rem(sink.every) == Some(0) {
                save_checkpoint(sink.checkpoint, &snapshot(engine))?;
            }
            Ok(updated)
        }
    }
}


/// Reads one JSON event per line, writes one JSON alert per line, checkpoints every `every` events and once at the end of the input.
pub fn run_stream(
    engine: &Engine,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    checkpoint: &Path,
    every: u64,
) -> Result<Summary, CorrelationError> {
    let mut sink = Sink { output, checkpoint, every };
    let summary = input.lines().enumerate().try_fold(Summary::default(), |summary, (index, line)| {
        handle_line(engine, index + 1, &line?, &mut sink, summary)
    })?;
    save_checkpoint(checkpoint, &snapshot(engine))?;
    Ok(summary)
}
