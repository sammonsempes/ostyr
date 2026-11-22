use crate::capabilities::{announce, read_bounded, SYSTEM_ROOT};
use crate::cursor::open_state_dir;
use crate::error::SourceError;
use crate::hostmetrics::statvfs_path;
use crate::metrics::run_metrics;
use crate::model::{LinuxFile, MetricsEnv, Paths, Totals, UpdateEnv, LINUX_MODULE, SYSTEMCTL_PATH};
use crate::run::run_source;
use crate::sensor::{monotonic_seconds, run_sensor, run_update_command, SensorEnv};
use crate::settings::open_settings_engine;
use crate::types::{RunFn, SpoolLock};
use crate::updates::{run_updates, APT_LISTS_DIR, COUNTER_SUFFIX, MAX_UPDATE_EVENTS_PER_RUN};
use agent_channel::agent_app::{load_agent_file, now_seconds, run_agent, AgentFile};
use agent_channel::app::{debounce, keep_signals, reload_context, shared_log_audit};
use agent_channel::spool::{line_limit, suffixed, SENDING_SUFFIX};
use agent_channel::spool_dirs::{open_parent, open_spool_dirs, SpoolDirs};
use agent_channel::types::PauseFn;
use core_audit::log::open_file_log;
use core_config::load::load_file;
use core_config::watch::watch_files;
use patch_inventory::limits::default_limits;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;


/// Pause between two agent runs; a run ends when its streams end, the next one claims the events spooled meanwhile.
pub const AGENT_CYCLE_SECONDS: u64 = 5;


/// Runs the agent `max_runs` times; a failed run is logged and the next one starts after the pause. Returns the runs that succeeded.
pub async fn run_agent_cycles(agent: &AgentFile, checked: &SpoolDirs, max_runs: u64, pause: &PauseFn) -> u64 {
    let mut succeeded = 0;
    for _ in 0..max_runs {
        let outcome = run_agent(agent, checked, pause)
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
        lock: SpoolLock::default(),
    }
}


/// The Linux agent: the Tetragon source and the agent channel side by side. Only `settings` of the file is live-reloaded (file watch and `SIGHUP`).
pub async fn run_linux(path: &Path, max_polls: u64, pause: &PauseFn, run: RunFn) -> Result<Totals, SourceError> {
    let file = load_file::<LinuxFile>(path)?;
    let agent = load_agent_file(&file.agent_file)?;
    let dirs = open_spool_dirs(&agent)?;
    let _audit_dir = open_parent(&file.audit_file)?;
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let context = reload_context(path, LINUX_MODULE, &agent.tenant, "agent-linux-reload");
    let (engine, shared, sensor_settings, update_settings, _osquery, metrics_settings) =
        open_settings_engine(path.to_path_buf(), shared_log_audit(&log), context)?;
    let reloadable = Arc::new(engine);
    let _watch = watch_files(Arc::clone(&reloadable), std::slice::from_ref(&path.to_path_buf()), debounce())?;
    let _signals = keep_signals(Arc::clone(&reloadable))?;
    let paths = source_paths(&file, &agent);
    announce(Path::new(SYSTEM_ROOT), &paths.spool, &paths.lock, read_bounded, now_seconds())?;
    let source = async {
        run_source(&shared, &paths, line_limit(&agent), max_polls, pause)
            .await
            .inspect_err(|error| tracing::error!(%error, "source failed, the agent stops"))
    };
    let cycles = async { Ok::<u64, SourceError>(run_agent_cycles(&agent, &dirs, max_polls, pause).await) };
    let env = SensorEnv {
        systemctl: PathBuf::from(SYSTEMCTL_PATH),
        export: file.export_path.clone(),
        spool: agent.spool_file.clone(),
        lock: Arc::clone(&paths.lock),
        tenant: agent.tenant.clone(),
        credentials_file: file.credentials_path.clone(),
        run,
    };
    let sensor_audit = shared_log_audit(&log);
    let sensor = async {
        run_sensor(
            &sensor_settings,
            &env,
            sensor_audit.as_ref(),
            max_polls,
            pause,
            &monotonic_seconds,
            &now_seconds,
        )
        .await
        .map(|_| ())
    };
    let cursor_file = file.cursor_file.clone();
    let state = tokio::task::spawn_blocking(move || open_state_dir(&cursor_file)).await??;
    let update_env = UpdateEnv {
        lists_dir: APT_LISTS_DIR.into(),
        spool: paths.spool.clone(),
        sending: paths.sending.clone(),
        counter_file: suffixed(&file.cursor_file, COUNTER_SUFFIX),
        state: Arc::new(state),
        lock: Arc::clone(&paths.lock),
        tenant: agent.tenant.clone(),
        device_id: agent.agent_id.clone(),
        line_limit: line_limit(&agent),
        max_events: MAX_UPDATE_EVENTS_PER_RUN,
        limits: default_limits(),
        run: run_update_command,
    };
    let updates = async {
        run_updates(&update_settings, &shared, &update_env, max_polls, pause, &monotonic_seconds, &now_seconds)
            .await
            .map(|_| ())
    };
    let metrics_env = MetricsEnv {
        root: PathBuf::from(SYSTEM_ROOT),
        spool: paths.spool.clone(),
        sending: paths.sending.clone(),
        lock: Arc::clone(&paths.lock),
        line_limit: line_limit(&agent),
        read: read_bounded,
        stat: statvfs_path,
    };
    let metrics = async {
        run_metrics(&metrics_settings, &shared, &metrics_env, max_polls, pause, &monotonic_seconds)
            .await
            .map(|_| ())
    };
    let (totals, runs, (), (), ()) = tokio::try_join!(source, cycles, sensor, updates, metrics)?;
    Ok(Totals { agent_runs: runs, ..totals })
}
