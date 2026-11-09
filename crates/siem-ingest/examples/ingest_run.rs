//! Usage: ingest_run <settings.yaml> <stop-file>. Consumes JetStream into ClickHouse until the stop file exists; settings are reloaded every cycle.

use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::reload;
use siem_ingest::batcher::{new_batcher, real_sleep, system_clock};
use siem_ingest::clickhouse::clickhouse_sink;
use siem_ingest::nats::nats_wiring;
use siem_ingest::pipeline::{new_pipeline, run_loop};
use siem_ingest::settings::open_settings;
use std::error::Error;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;


pub const USAGE: &str = "usage: ingest_run <settings.yaml> <stop-file>";


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let settings_path = PathBuf::from(arguments.first().ok_or(USAGE)?);
    let stop_path = PathBuf::from(arguments.get(1).ok_or(USAGE)?);
    let log = genesis_log(io::sink());
    let engine = Arc::new(open_settings(
        settings_path,
        Box::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) }),
    )?);
    let batcher = new_batcher(
        Arc::clone(&engine),
        clickhouse_sink(Arc::clone(&engine)),
        Box::new(system_clock),
        Box::new(real_sleep),
    );
    let mut pipeline = new_pipeline(batcher, nats_wiring(Arc::clone(&engine))?);
    let stop = move || {
        reload(&engine);
        Path::new(&stop_path).exists()
    };
    let summary = run_loop(&mut pipeline, &stop);
    writeln!(io::stdout(), "{summary:?}")?;
    Ok(())
}
