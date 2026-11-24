//! Usage: metrics_consumer <settings.yaml> <stop-file>. Stores the host metrics of the event stream in ClickHouse until the stop file exists.

use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::types::SharedAuditFn;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::consume::{clickhouse_store, run_loop, Hooks, MAX_LOOP_CYCLES};
use metrics_ingest::consumer_settings::open_consumer;
use siem_ingest::logging::build_subscriber;
use siem_ingest::nats::nats_wiring;
use std::error::Error;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{SystemTime, UNIX_EPOCH};


pub const USAGE: &str = "usage: metrics_consumer <settings.yaml> <stop-file>";


pub const RUST_LOG: &str = "RUST_LOG";


fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let settings_path = PathBuf::from(arguments.first().ok_or(USAGE)?);
    let stop_path = PathBuf::from(arguments.get(1).ok_or(USAGE)?);
    let directives = std::env::var(RUST_LOG).ok();
    tracing::subscriber::set_global_default(build_subscriber(io::stderr, directives.as_deref())?)?;
    let log = genesis_log(io::sink());
    let audit: Arc<SharedAuditFn> = Arc::new(move |entry: NewEntry| -> Result<_, AuditError> { append(&log, entry) });
    let engines = open_consumer(settings_path, &audit)?;
    let mut wiring = nats_wiring(Arc::clone(&engines.ingest))?;
    let mut state = CardinalityState::default();
    let hooks = Hooks {
        now: &now_nanos,
        sleep: &sleep,
        send: &clickhouse_store,
        max_cycles: MAX_LOOP_CYCLES,
    };
    let stop = move || Path::new(&stop_path).exists();
    let summary = run_loop(&mut wiring, &engines, &mut state, (&hooks, &stop));
    writeln!(io::stdout(), "{summary:?}")?;
    Ok(())
}
