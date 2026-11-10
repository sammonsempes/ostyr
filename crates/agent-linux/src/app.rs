use crate::capabilities::{announce, read_bounded, SYSTEM_ROOT};
use crate::error::SourceError;
use crate::model::{LinuxFile, Paths, Totals, LINUX_MODULE};
use crate::run::run_source;
use crate::settings::open_settings_engine;
use agent_channel::agent_app::{load_agent_file, now_seconds, run_agent, AgentFile};
use agent_channel::app::{debounce, keep_signals, reload_context, shared_log_audit};
use agent_channel::spool::{line_limit, suffixed, SENDING_SUFFIX};
use agent_channel::types::PauseFn;
use core_audit::log::open_file_log;
use core_config::load::load_file;
use core_config::watch::watch_files;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;


/// Pause between two agent runs; a run ends when its streams end, the next one claims the events spooled meanwhile.
pub const AGENT_CYCLE_SECONDS: u64 = 5;


/// Runs the agent `max_runs` times; a failed run is logged and the next one starts after the pause. Returns the runs that succeeded.
pub async fn run_agent_cycles(agent: &AgentFile, max_runs: u64, pause: &PauseFn) -> u64 {
    let mut succeeded = 0;
    for _ in 0..max_runs {
        let outcome = run_agent(agent, pause)
            .await
            .inspect_err(|error| tracing::warn!(%error, "agent run failed"));
        succeeded += u64::from(outcome.is_ok());
        pause(Duration::from_secs(AGENT_CYCLE_SECONDS)).await;
    }
    succeeded
}


pub fn source_paths(file: &LinuxFile, agent: &AgentFile) -> Paths {
    Paths {
        export: file.export_path.clone(),
        cursor_file: file.cursor_file.clone(),
        spool: agent.spool_file.clone(),
        sending: suffixed(&agent.spool_file, SENDING_SUFFIX),
    }
}


/// The Linux agent: the Tetragon source and the agent channel side by side. Only `settings` of the file is live-reloaded (file watch and `SIGHUP`).
pub async fn run_linux(path: &Path, max_polls: u64, pause: &PauseFn) -> Result<Totals, SourceError> {
    let file = load_file::<LinuxFile>(path)?;
    let agent = load_agent_file(&file.agent_file)?;
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let context = reload_context(path, LINUX_MODULE, &agent.tenant, "agent-linux-reload");
    let (engine, shared) = open_settings_engine(path.to_path_buf(), shared_log_audit(&log), context)?;
    let reloadable = Arc::new(engine);
    let _watch = watch_files(Arc::clone(&reloadable), std::slice::from_ref(&path.to_path_buf()), debounce())?;
    let _signals = keep_signals(Arc::clone(&reloadable))?;
    let paths = source_paths(&file, &agent);
    announce(Path::new(SYSTEM_ROOT), &paths.spool, read_bounded, now_seconds())?;
    let source = async {
        run_source(&shared, &paths, line_limit(&agent), max_polls, pause)
            .await
            .inspect_err(|error| tracing::error!(%error, "source failed, the agent stops"))
    };
    let cycles = async { Ok::<u64, SourceError>(run_agent_cycles(&agent, max_polls, pause).await) };
    let (totals, runs) = tokio::try_join!(source, cycles)?;
    Ok(Totals { agent_runs: runs, ..totals })
}
