//! Usage: ch_insert <settings.yaml> <events.ndjson> <tenant>. Inserts the file's ECS events through the pipeline and the real ClickHouse sink.

use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use siem_ingest::batcher::{flush, new_batcher};
use siem_ingest::clickhouse::{clickhouse_sink, new_agent};
use siem_ingest::model::{CycleReport, Delivery, Document, Wiring};
use siem_ingest::pipeline::{new_pipeline, run_cycle, settle};
use siem_ingest::settings::open_settings;
use siem_ingest::tenant::EVENTS_SUBJECT_PREFIX;
use siem_ingest::types::Counts;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use std::thread::sleep;
use time::OffsetDateTime;


pub const TENANT_ARGUMENT: usize = 2;


pub const USAGE: &str = "usage: ch_insert <settings.yaml> <events.ndjson> <tenant>";


pub fn count(counts: &Counts, label: String) -> Result<(), Box<dyn Error + Send + Sync>> {
    *counts.lock().map_err(|_| "counter lock poisoned")?.entry(label).or_default() += 1;
    Ok(())
}


pub fn deliveries(events: &str, tenant: &str) -> Vec<Delivery> {
    events
        .lines()
        .enumerate()
        .map(|(index, line)| Delivery {
            subject: format!("{EVENTS_SUBJECT_PREFIX}.{tenant}"),
            payload: line.as_bytes().to_vec(),
            token: index as u64 + 1,
        })
        .collect()
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let settings_path = arguments.first().ok_or(USAGE)?;
    let events_path = arguments.get(1).ok_or(USAGE)?;
    let tenant = arguments.get(TENANT_ARGUMENT).ok_or(USAGE)?;
    let log = genesis_log(io::sink());
    let engine = Arc::new(open_settings(
        settings_path.into(),
        Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }),
    )?);
    let counts: Counts = Arc::default();
    let inner = clickhouse_sink(Arc::clone(&engine), new_agent());
    let sink_counts = Arc::clone(&counts);
    let sink = Box::new(move |sink_tenant: &str, documents: &[Document]| {
        let outcome = inner(sink_tenant, documents);
        let label = outcome.as_ref().map_or_else(|error| error.to_string(), |_| "inserted".to_owned());
        count(&sink_counts, format!("sink {label}, rows per call {}", documents.len())).and(outcome)
    });
    let mut pending = Some(deliveries(&fs::read_to_string(events_path)?, tenant));
    let ack_counts = Arc::clone(&counts);
    let dead_counts = Arc::clone(&counts);
    let wiring = Wiring {
        fetch: Box::new(move |_| Ok(pending.take().unwrap_or_default())),
        ack: Box::new(move |_, action| count(&ack_counts, format!("{action:?}"))),
        dead_letter: Box::new(move |_, _, reason| count(&dead_counts, format!("dead letter: {reason}"))),
    };
    let batcher = new_batcher(engine, sink, Box::new(OffsetDateTime::now_utc), Box::new(sleep));
    let mut pipeline = new_pipeline(batcher, wiring);
    let mut report: CycleReport = run_cycle(&mut pipeline)?;
    let last = flush(&mut pipeline.batcher);
    settle(&mut pipeline, last, &mut report);
    let mut stdout = io::stdout();
    writeln!(stdout, "{report:?}")?;
    counts
        .lock()
        .map_err(|_| "counter lock poisoned")?
        .iter()
        .try_for_each(|(label, total)| writeln!(stdout, "{label}: {total}"))?;
    Ok(())
}
