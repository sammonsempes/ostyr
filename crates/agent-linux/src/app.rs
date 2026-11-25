use crate::capabilities::{announce, read_bounded, SYSTEM_ROOT};
use crate::cursor::open_state_dir;
use crate::dispatch::{admin_execute_fn, admin_queue, run_admin_worker, AdminEnv};
use crate::error::SourceError;
use crate::exec_events::{system_offset, ExecSink};
use crate::exec_probe::{end_on_spool_error, run_exec_controller, spawn_thread, stop_exec_controller, Controller, ProbeEnv, PRODUCTION_PROBE};
use crate::hostmetrics::statvfs_path;
use crate::metrics::run_metrics;
use crate::model::{LinuxFile, MetricsEnv, Paths, StateDir, Totals, UpdateEnv, LINUX_MODULE, NFT_PATH, SYSTEMCTL_PATH};
use crate::nft::run_nft;
use crate::run::run_source;
use crate::sensor::{monotonic_seconds, run_sensor, run_update_command, SensorEnv};
use crate::settings::open_settings_engine;
use crate::shell::{shell_dial, store_path, switch_fn, switch_path};
use crate::types::{ProbeFn, RunFn, SpoolLock};
use crate::updates::{run_updates, APT_LISTS_DIR, COUNTER_SUFFIX, MAX_UPDATE_EVENTS_PER_RUN};
use agent_channel::agent_app::{load_agent_file, now_seconds, run_agent, AgentFile};
use agent_channel::app::{debounce, keep_signals, reload_context, shared_log_audit};
use agent_channel::model::Executors;
use agent_channel::relay::{endpoint_addresses, HoldDown};
use agent_channel::spool::{line_limit, suffixed, SENDING_SUFFIX};
use agent_channel::spool_dirs::{open_parent, open_spool_dirs, SpoolDirs};
use agent_channel::types::PauseFn;
use agent_shell::compose::production_shared;
use agent_shell::hooks::production_hooks;
use agent_shell::model::{SharedHooks, SHELL_ACCOUNT};
use agent_shell::queue::{gated_execute_fn, new_slot, shell_execute_fn};
use agent_shell::session::{attach_fn, run_shell_worker_with, shell_queue};
use core_audit::log::open_file_log;
use core_config::load::load_file;
use core_config::watch::watch_files;
use patch_inventory::limits::default_limits;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;


/// Pause between two agent runs; a run ends when its streams end, the next one claims the events spooled meanwhile.
pub const AGENT_CYCLE_SECONDS: u64 = 5;


/// Runs the agent `max_runs` times, every run with the same executors; a failed run is logged and the next one starts after the pause. Returns the runs that succeeded.
pub async fn run_agent_cycles(agent: &AgentFile, checked: &SpoolDirs, max_runs: u64, pause: &PauseFn, executors: &Executors<'_>) -> u64 {
    let mut succeeded = 0;
    let hold = HoldDown::default();
    for _ in 0..max_runs {
        let outcome = run_agent(agent, checked, pause, executors, &hold)
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


/// The Linux agent with the production probe, ended cleanly by SIGTERM (the systemd stop): the handler is installed before anything starts.
pub async fn run_linux(path: &Path, max_polls: u64, pause: &PauseFn, run: RunFn) -> Result<Totals, SourceError> {
    let mut terminated = signal(SignalKind::terminate())?;
    run_linux_with(path, max_polls, pause, run, PRODUCTION_PROBE, async move {
        terminated.recv().await;
    })
    .await
}


/// The Linux agent: the Tetragon source and the agent channel side by side. Only `settings` of the file is live-reloaded (file watch and `SIGHUP`). Every end (streams done, a producer's error, `terminate`) goes through `stop_exec_controller`, so the probe is stopped and joined and its unload audited before this returns; `terminate` is a clean end.
pub async fn run_linux_with(
    path: &Path,
    max_polls: u64,
    pause: &PauseFn,
    run: RunFn,
    probe: ProbeFn,
    terminate: impl Future<Output = ()>,
) -> Result<Totals, SourceError> {
    let file = load_file::<LinuxFile>(path)?;
    let agent = load_agent_file(&file.agent_file)?;
    let dirs = open_spool_dirs(&agent)?;
    let _audit_dir = open_parent(&file.audit_file)?;
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let context = reload_context(path, LINUX_MODULE, &agent.tenant, "agent-linux-reload");
    let (engine, shared, sensor_settings, update_settings, _osquery, metrics_settings, exec_probe_settings) =
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
    let enabled = switch_fn(switch_path(path));
    let dial = shell_dial(&agent);
    let attach = attach_fn();
    let slot = new_slot();
    let (queue, orders) = shell_queue();
    let executor = gated_execute_fn(Arc::clone(&enabled), shell_execute_fn(Arc::clone(&slot), queue));
    let shell_shared = production_shared(
        agent.agent_id.clone(),
        store_path(&file.cursor_file),
        SharedHooks {
            clock: &now_seconds,
            dial: dial.as_ref(),
            attach: attach.as_ref(),
            enabled: enabled.as_ref(),
        },
    );
    let shell = async { Ok::<u64, SourceError>(run_shell_worker_with(orders, slot, &shell_shared, SHELL_ACCOUNT, production_hooks).await) };
    let (agent_ref, dirs_ref) = (&agent, &dirs);
    let restart = Notify::new();
    let restart_ref = &restart;
    let (admin_queue_sender, admin_orders) = admin_queue();
    let admin_executor = admin_execute_fn(admin_queue_sender);
    let cycles = async move {
        let executors = Executors {
            shell: Some(executor.as_ref()),
            ping: Some(admin_executor.as_ref()),
            collect_status: Some(admin_executor.as_ref()),
            isolate: Some(admin_executor.as_ref()),
            restart: Some(restart_ref),
        };
        let runs = run_agent_cycles(agent_ref, dirs_ref, max_polls, pause, &executors).await;
        drop(executor);
        drop(admin_executor);
        Ok::<u64, SourceError>(runs)
    };
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
    let admin_state = StateDir {
        handle: state.handle.try_clone()?,
    };
    let channel_addresses = endpoint_addresses(&agent)?;
    let admin_audit = shared_log_audit(&log);
    let admin_env = AdminEnv {
        run: run_nft,
        nft: Path::new(NFT_PATH),
        state: &admin_state,
        tenant: &agent.tenant,
        audit: admin_audit.as_ref(),
        settings_file: path,
        channel: &channel_addresses,
        restart: restart_ref,
    };
    let admin = async { Ok::<u64, SourceError>(run_admin_worker(admin_orders, &admin_env).await) };
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
    let exec_env = ProbeEnv {
        tenant: agent.tenant.clone(),
        probe,
        spawn: spawn_thread,
        sink: ExecSink {
            spool: paths.spool.clone(),
            sending: paths.sending.clone(),
            lock: Arc::clone(&paths.lock),
            settings: Arc::clone(&shared),
            offset: system_offset,
            monotonic: monotonic_seconds,
        },
    };
    let exec_audit = shared_log_audit(&log);
    let mut controller = Controller::default();
    let exec_probe = async {
        let ended = run_exec_controller(
            &mut controller,
            &exec_probe_settings,
            &exec_env,
            exec_audit.as_ref(),
            max_polls,
            pause,
            &monotonic_seconds,
        )
        .await;
        end_on_spool_error(ended)?;
        Ok::<(), SourceError>(())
    };
    let outcome = tokio::select! {
        joined = async { tokio::try_join!(source, cycles, sensor, updates, metrics, shell, admin, exec_probe) } => Some(joined),
        () = terminate => None,
    };
    let stopped = stop_exec_controller(controller, &exec_env, exec_audit.as_ref(), pause).await;
    let stop_result = end_on_spool_error(stopped);
    let finished = match outcome {
        Some(joined) => joined.map(|(totals, runs, (), (), (), _handled, _settled, ())| Totals { agent_runs: runs, ..totals }),
        None => {
            tracing::info!("terminated, the agent stops");
            Ok(Totals::default())
        }
    };
    finished.and_then(|totals| stop_result.map(|()| totals))
}
