//! The `ostyr-backup-monitor` service: checks and restore tests on their own schedules until the interrupt (Unix only).

use crate::borg::private_handle;
use crate::check::RoundOutcome;
use crate::model::{Declarations, Limits};
use crate::report::report_directory;
use crate::secrets::open_secrets_dir;
use crate::service::{
    check_outcome, check_parameters, check_round, load_settings, log_check, log_restore, next_due, open_declarations_engine,
    open_service_settings_from, production_programs, production_timing, restore_outcome, restore_parameters, restore_round, round_entry,
    state_identity, store_restore, Programs, RestoreRun, RoundError, ServiceSettings, Shared, StoreFailure, Timing, CHECK_ACTION, RESTORE_ACTION,
    ROUND_KEYS,
};
use crate::store::{WriteCounts, MIGRATIONS, MIGRATION_NAMESPACE};
use crate::types::{Clock, InterruptWait, SettingsReader};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::spawn_blocking;
use tokio::time::{sleep_until, Instant};
use tracing::{error, info, warn};


const USAGE: &str = "usage: ostyr-backup-monitor <settings.yaml>";


const ROOT_REFUSED: &str = "refusing to run as root: use a dedicated user with its own ssh configuration";


const DEBOUNCE: Duration = Duration::from_millis(300);


const FOREVER: usize = usize::MAX;


const RUNNING: bool = false;


/// What `start` needs besides the settings file: the programs, the timing, the one reader of the settings file, the loop bound, the user and the clock.
pub struct StartOptions {
    pub programs: Programs,
    pub timing: Timing,
    pub read: SettingsReader,
    pub rounds: usize,
    pub euid: u32,
    pub clock: Clock,
}


/// The running service: the fixed environment, the pinned tenant, the audit log, the two live engines and the stop flag.
pub struct Service {
    pub shared: Arc<Shared>,
    pub pg: Arc<PgSettings>,
    pub scope: TenantScope,
    pub tenant: String,
    pub audit: Arc<AuditLog<File>>,
    pub settings: Arc<ReloadEngine<ServiceSettings>>,
    pub declarations: Arc<ReloadEngine<Declarations>>,
    pub stop: Arc<AtomicBool>,
}


/// When each schedule is next due (seconds since start) and where its next round starts in plan order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cursor {
    pub check_due: u64,
    pub restore_due: u64,
    pub check_start: usize,
    pub restore_start: usize,
}


pub fn reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


#[cfg(unix)]
fn keep_signals<Config: Send + Sync + 'static>(engine: &Arc<ReloadEngine<Config>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(Arc::clone(engine), &[signal_hook::consts::SIGHUP])
}


/// The service refuses to run as root: it runs a repository tool with the keys of its own account.
pub fn refuse_root(euid: u32) -> Result<(), &'static str> {
    if euid == 0 {
        Err(ROOT_REFUSED)
    } else {
        Ok(())
    }
}


pub fn production_options(euid: u32) -> StartOptions {
    StartOptions {
        programs: production_programs(),
        timing: production_timing(),
        read: Arc::new(|file: &Path| load_settings(file)),
        rounds: FOREVER,
        euid,
        clock: OffsetDateTime::now_utc,
    }
}


/// The argument check, the root refusal and the service.
pub async fn run_with_euid(arguments: &[String], interrupt: InterruptWait, euid: u32) -> Result<(), Box<dyn Error>> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(USAGE),
    }?;
    refuse_root(euid)?;
    start(Path::new(settings_file), production_options(euid), interrupt).await
}


/// Completes on SIGINT or SIGTERM; both handlers are installed when this returns.
pub fn interrupt_wait() -> std::io::Result<InterruptWait> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = terminate.recv() => Ok(()),
            _ = interrupt.recv() => Ok(()),
        }
    }))
}


pub fn exit_code(result: Result<(), Box<dyn Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let reason = failure.to_string();
            error!(reason, "backup monitor stopped");
            ExitCode::FAILURE
        }
    }
}


pub async fn main_exit(arguments: Vec<String>) -> ExitCode {
    let installed = tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::stderr).finish()).is_ok();
    tracing::debug!(installed, "log subscriber");
    exit_code(run_main(&arguments, rustix::process::geteuid().as_raw()).await)
}


/// Installs the signal handlers, then runs the service as `euid`.
pub async fn run_main(arguments: &[String], euid: u32) -> Result<(), Box<dyn Error>> {
    let wait = interrupt_wait()?;
    run_with_euid(arguments, wait, euid).await
}


/// One read of the settings file serves the audit path and the start-only baseline; everything else the service uses comes from that baseline.
pub async fn start(settings_file: &Path, options: StartOptions, mut interrupt: InterruptWait) -> Result<(), Box<dyn Error>> {
    let baseline = (options.read)(settings_file)?;
    let audit = Arc::new(open_file_log(&baseline.audit_file)?);
    let opened_settings = open_service_settings_from(settings_file, baseline.clone(), Arc::clone(&options.read), reload_audit(&audit));
    let settings = Arc::new(opened_settings?);
    let opened_declarations = open_declarations_engine(&baseline.declarations_file, &baseline.tenant, reload_audit(&audit));
    let declarations = Arc::new(opened_declarations?);
    let _declarations_watch = watch_files(Arc::clone(&declarations), std::slice::from_ref(&baseline.declarations_file), DEBOUNCE)?;
    let _settings_watch = watch_files(Arc::clone(&settings), &[settings_file.to_path_buf()], DEBOUNCE)?;
    let _declarations_signals = keep_signals(&declarations)?;
    let _settings_signals = keep_signals(&settings)?;
    let pg = Arc::new(load_pg_settings(&baseline.pg_settings)?);
    let scope = tenant_scope(&baseline.tenant)?;
    let secrets = open_secrets_dir(&baseline.secrets_dir, options.euid)?;
    let state_handle = private_handle(&baseline.state_dir, options.euid)?;
    let identity = state_identity(&state_handle)?;
    let reports = report_directory(&baseline.state_dir, &scope, options.euid)?;
    let client = connect(&pg).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, Duration::from_secs(pg.statement_timeout_secs)).await?;
    let service = Service {
        shared: Arc::new(Shared {
            programs: options.programs,
            secrets,
            state: baseline.state_dir.clone(),
            state_identity: identity,
            reports,
            limits: Limits::default(),
            timing: options.timing,
            euid: options.euid,
            clock: options.clock,
        }),
        pg,
        scope,
        tenant: baseline.tenant.clone(),
        audit,
        settings,
        declarations,
        stop: Arc::new(AtomicBool::new(false)),
    };
    let tenant = baseline.tenant;
    info!(tenant, "serving");
    serve(&service, options.rounds, &mut interrupt).await
}


/// Runs `work` on a blocking thread; an interrupt sets the stop flag (no new command starts) and the job is awaited to the end before returning.
pub async fn run_job<Output: Send + 'static>(
    work: impl FnOnce() -> Output + Send + 'static,
    stop: &AtomicBool,
    interrupt: &mut InterruptWait,
) -> Result<(Output, bool), Box<dyn Error>> {
    let mut handle = spawn_blocking(work);
    tokio::select! {
        biased;
        waited = &mut *interrupt => {
            stop.store(true, Ordering::SeqCst);
            waited?;
            Ok((handle.await?, true))
        }
        joined = &mut handle => Ok((joined?, false)),
    }
}


fn audit_round(
    service: &Service,
    action: &str,
    entry_outcome: core_audit::model::Outcome,
    parameters: core_audit::types::ParameterMap,
) -> Result<(), Box<dyn Error>> {
    let entry = round_entry(action, &service.tenant, entry_outcome, parameters);
    let appended = append_declared(&service.audit, entry, &ROUND_KEYS);
    appended?;
    Ok(())
}


fn refused_parameters(error: &RoundError) -> core_audit::types::ParameterMap {
    [("round_error".to_owned(), error.to_string())].into_iter().collect()
}


async fn check_turn(
    service: &Service,
    cursor: &mut Cursor,
    live: &ServiceSettings,
    started: Instant,
    interrupt: &mut InterruptWait,
) -> Result<bool, Box<dyn Error>> {
    let declarations = current_config(&service.declarations);
    let shared = Arc::clone(&service.shared);
    let flag = Arc::clone(&service.stop);
    let start = cursor.check_start;
    let (done, interrupted) = run_job(move || check_round(&shared, &declarations, start, &flag), &service.stop, interrupt).await?;
    let (next, missed) = next_due(cursor.check_due, live.interval_seconds, started.elapsed().as_secs());
    cursor.check_due = next;
    match done {
        Ok(round) => finish_check(service, cursor, &round, missed)?,
        Err(refusal) => {
            let reason = refusal.to_string();
            warn!(reason, "check round refused");
            audit_round(service, CHECK_ACTION, core_audit::model::Outcome::Failure, refused_parameters(&refusal))?;
        }
    }
    Ok(interrupted)
}


fn finish_check(service: &Service, cursor: &mut Cursor, round: &RoundOutcome, missed: u64) -> Result<(), Box<dyn Error>> {
    log_check(round, missed);
    cursor.check_start = round.next_start;
    audit_round(service, CHECK_ACTION, check_outcome(round), check_parameters(round, missed))
}


async fn restore_turn(
    service: &Service,
    cursor: &mut Cursor,
    live: &ServiceSettings,
    started: Instant,
    interrupt: &mut InterruptWait,
) -> Result<bool, Box<dyn Error>> {
    let declarations = current_config(&service.declarations);
    let shared = Arc::clone(&service.shared);
    let flag = Arc::clone(&service.stop);
    let start = cursor.restore_start;
    let (done, interrupted) = run_job(move || restore_round(&shared, &declarations, start, &flag), &service.stop, interrupt).await?;
    let (next, missed) = next_due(cursor.restore_due, live.restore_interval_seconds, started.elapsed().as_secs());
    cursor.restore_due = next;
    match done {
        Ok(run) => finish_restore(service, cursor, &run, missed).await?,
        Err(refusal) => {
            let reason = refusal.to_string();
            warn!(reason, "restore round refused");
            audit_round(service, RESTORE_ACTION, core_audit::model::Outcome::Failure, refused_parameters(&refusal))?;
        }
    }
    Ok(interrupted)
}


async fn finish_restore(service: &Service, cursor: &mut Cursor, run: &RestoreRun, missed: u64) -> Result<(), Box<dyn Error>> {
    let stored: Result<WriteCounts, StoreFailure> = store_restore(&service.pg, &service.scope, run).await;
    cursor.restore_start = run.next_start;
    log_restore(run, &stored, missed);
    audit_round(
        service,
        RESTORE_ACTION,
        restore_outcome(run, &stored),
        restore_parameters(run, &stored, missed),
    )
}


/// Waits for the earlier due time or the interrupt; true when interrupted.
async fn wait_for_due(cursor: &Cursor, started: Instant, interrupt: &mut InterruptWait) -> Result<bool, Box<dyn Error>> {
    let due = cursor.check_due.min(cursor.restore_due);
    tokio::select! {
        biased;
        waited = &mut *interrupt => {
            waited?;
            Ok(true)
        }
        () = sleep_until(started + Duration::from_secs(due)) => Ok(false),
    }
}


fn elapsed_seconds(started: Instant) -> u64 {
    started.elapsed().as_secs()
}


/// At most `rounds` passes; a pass runs each schedule that is due, one after the other, so rounds never overlap.
pub async fn serve(service: &Service, rounds: usize, interrupt: &mut InterruptWait) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let mut cursor = Cursor::default();
    let mut stopped = false;
    let mut done = 0;
    while stopped == RUNNING && done < rounds {
        let live = current_config(&service.settings);
        if elapsed_seconds(started) >= cursor.check_due {
            stopped = check_turn(service, &mut cursor, &live, started, interrupt).await?;
        }
        if !stopped && elapsed_seconds(started) >= cursor.restore_due {
            stopped = restore_turn(service, &mut cursor, &live, started, interrupt).await?;
        }
        done += 1;
        if !stopped && done < rounds {
            stopped = wait_for_due(&cursor, started, interrupt).await?;
        }
    }
    Ok(())
}
