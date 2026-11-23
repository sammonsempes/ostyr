use agent_channel::model::DEFAULT_MAX_MESSAGE_BYTES;
use agent_windows::cycle::sleep_seconds;
use agent_windows::model::{PollEnv, RunRequest, LOCK_ATTEMPTS, MAX_EVENTS_PER_POLL, MAX_OUTPUT_BYTES, QUERY_DEADLINE_SECONDS, WEVTUTIL_PATH};
use agent_windows::round::{run_rounds, RoundState};
use agent_windows::run::run_process;
use agent_windows::settings::{open_settings, settings_path, DEFAULT_MAX_SPOOL_BYTES};
use agent_windows::types::SharedObserved;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log, AuditLog};
use core_audit::model::{NewEntry, Record};
use core_config::reload::ReloadContext;
use core_export::ecs::to_json;
use ecs_normalise::types::SeenIds;
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;


const USAGE: &str = "usage: agent_rounds <state-dir> <spool> [rounds]";


const LINE_LIMIT_DIVISOR: usize = 2;


const AUDIT_FILE: &str = "audit.log";


fn audit_to_file(path: &Path, log: &AuditLog<io::Sink>, entry: NewEntry) -> Result<Record, AuditError> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{:?} {:?}", entry.outcome, entry.parameters.get("result"))?;
    append(log, entry)
}


fn main() -> Result<(), Box<dyn Error>> {
    let mut paths = env::args().skip(1);
    let state_dir = paths.next().ok_or(USAGE)?;
    let spool = paths.next().ok_or(USAGE)?;
    let rounds: u32 = paths.next().map_or(Ok(1), |text| text.parse())?;
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let log = genesis_log(std::io::sink());
    let context = ReloadContext {
        actor_id: "agent-windows".to_owned(),
        tenant: "local".to_owned(),
        module: "agent-windows".to_owned(),
        target: "settings.yaml".to_owned(),
        request_id: "reload".to_owned(),
    };
    let audit_file = Path::new(&state_dir).join(AUDIT_FILE);
    let file = settings_path(Path::new(&state_dir));
    let observed = SharedObserved::default();
    let engine = open_settings(
        file,
        Box::new(move |entry| audit_to_file(&audit_file, &log, entry)),
        context,
        Arc::clone(&observed),
    )?;
    let mut seen = SeenIds::new();
    let mut run = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| run_process(request, sink);
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: Path::new(&state_dir),
        spool: Path::new(&spool),
        line_limit: DEFAULT_MAX_MESSAGE_BYTES / LINE_LIMIT_DIVISOR,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: MAX_OUTPUT_BYTES,
        deadline_seconds: QUERY_DEADLINE_SECONDS,
        max_spool_bytes: DEFAULT_MAX_SPOOL_BYTES,
        max_batch: MAX_EVENTS_PER_POLL,
        seen: &mut seen,
    };
    let mut round = RoundState::default();
    let mut stdout = std::io::stdout();
    let reports = run_rounds(&engine, &observed, rounds, &mut env, &mut round, &mut sleep_seconds)?;
    reports.iter().try_for_each(|report| {
        let polled: Vec<&str> = report.polled.iter().map(|(key, _)| *key).collect();
        writeln!(
            stdout,
            "polled {polled:?} defender {} defender_spool_full {}",
            report.defender, report.defender_spool_full
        )
    })?;
    Ok(())
}
