//! The `ostyr-grc` service: rounds on a schedule until a stop; a round in flight always runs to its end, logs on stderr.

use crate::round::run_round;
use crate::service::{load_declarations, open_declarations, watched_files, Declarations, Signals};
use crate::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use crate::types::{ClockFn, DeclarationsReader, PauseFn, PauseFuture, WatchGuard};
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, reload, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::SharedAuditFn;
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use std::error::Error;
use std::fs::File;
use std::io::stderr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{info, warn};


pub const USAGE: &str = "usage: ostyr-grc <settings.yaml>";


pub const DEBOUNCE: Duration = Duration::from_millis(300);


pub const MAX_ROUNDS: u64 = 10_000_000;


pub const MAX_SIGNALS: u64 = 1_000_000;


pub const MAX_SPURIOUS_WAKES: u64 = 1_000;


#[derive(Debug, Error)]
pub enum ServeError {
    #[error("{USAGE}")]
    Usage,
    #[error("{0}")]
    Failed(#[source] Box<dyn Error>),
}


/// The watch in force and the files it covers; it is rebuilt when a reload changes the declared files.
#[derive(Default)]
pub struct Watching {
    pub files: Vec<PathBuf>,
    pub guard: Option<WatchGuard>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Stop,
    Hangup,
}


#[cfg(unix)]
pub struct SignalStreams {
    pub terminate: tokio::signal::unix::Signal,
    pub interrupt: tokio::signal::unix::Signal,
    pub hangup: tokio::signal::unix::Signal,
}


#[cfg(not(unix))]
pub struct SignalStreams {
    pub placeholder: (),
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoundsEnd {
    pub rounds: u64,
    pub stopped: bool,
}


pub fn exit_code(result: &Result<(), ServeError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}


pub fn pause(duration: Duration) -> PauseFuture {
    Box::pin(tokio::time::sleep(duration))
}


pub fn system_clock() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}


/// Registers SIGTERM, SIGINT and SIGHUP; the binary calls it before anything is loaded, so an early signal queues.
#[cfg(unix)]
pub fn register_signals() -> std::io::Result<SignalStreams> {
    use tokio::signal::unix::{signal, SignalKind};
    Ok(SignalStreams {
        terminate: signal(SignalKind::terminate())?,
        interrupt: signal(SignalKind::interrupt())?,
        hangup: signal(SignalKind::hangup())?,
    })
}


#[cfg(not(unix))]
pub fn register_signals() -> std::io::Result<SignalStreams> {
    Ok(SignalStreams { placeholder: () })
}


#[cfg(unix)]
pub async fn next_signal(streams: &mut SignalStreams) -> Kind {
    tokio::select! {
        _ = streams.terminate.recv() => Kind::Stop,
        _ = streams.interrupt.recv() => Kind::Stop,
        _ = streams.hangup.recv() => Kind::Hangup,
    }
}


#[cfg(not(unix))]
pub async fn next_signal(_streams: &mut SignalStreams) -> Kind {
    tokio::signal::ctrl_c().await.map_or(Kind::Stop, |()| Kind::Stop)
}


/// Records one signal: a stop is queued (a second one is logged and ignored), a hangup asks for a reload.
pub fn record_signal(signals: &Signals, kind: Kind) {
    match kind {
        Kind::Stop => {
            let repeated = signals.stop.swap(true, Ordering::SeqCst);
            if repeated {
                warn!("another stop signal ignored, the round in flight runs to its end");
            } else {
                info!("stop requested, the round in flight runs to its end");
            }
        }
        Kind::Hangup => {
            signals.hangup.store(true, Ordering::SeqCst);
            info!("reload requested, it runs after the round in flight");
        }
    }
    signals.wake.notify_one();
}


/// Records at most `limit` signals, then returns; a signal never kills the process, only the loop reads what it recorded.
pub async fn listen_up_to(signals: Arc<Signals>, mut streams: SignalStreams, limit: u64) {
    let mut seen = 0;
    while seen < MAX_SIGNALS.min(limit) {
        let kind = next_signal(&mut streams).await;
        record_signal(&signals, kind);
        seen += 1;
    }
}


pub fn install_logging() -> Result<(), Box<dyn Error>> {
    tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(stderr).with_ansi(false).finish())?;
    Ok(())
}


pub fn boxed_reload_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let owned = Arc::clone(log);
    Box::new(move |entry| append_declared(&owned, entry, &RELOAD_DECLARED_KEYS))
}


/// Rebuilds the watch when the declared files changed; a failure keeps the old watch and is logged.
pub fn refresh_watch(engine: &Arc<ReloadEngine<Declarations>>, settings_file: &Path, watching: &mut Watching) {
    let files = watched_files(settings_file, &current_config(engine));
    if files != watching.files {
        match watch_files(Arc::clone(engine), &files, DEBOUNCE) {
            Ok(guard) => {
                watching.guard = Some(guard);
                watching.files = files;
            }
            Err(fault) => warn!(%fault, "cannot watch the declared files, the old watch stays"),
        }
    }
}


pub fn pending(signals: &Signals) -> bool {
    signals.stop.load(Ordering::SeqCst) || signals.hangup.load(Ordering::SeqCst) || signals.applied.load(Ordering::SeqCst)
}


/// Returns when a flag is set; a wake with no flag (an applied reload, an old permit) is not a reason to run.
pub async fn wait_pending(signals: &Signals) {
    let mut spurious = 0;
    while !pending(signals) && spurious < MAX_SPURIOUS_WAKES {
        signals.wake.notified().await;
        spurious += 1;
    }
}


/// Rounds until a stop is recorded (the first round always runs); the stop is read only between rounds.
pub async fn serve_rounds(
    engine: &Arc<ReloadEngine<Declarations>>,
    settings_file: &Path,
    signals: &Signals,
    (clock, pause_for): (&ClockFn, &PauseFn),
    max_rounds: u64,
) -> RoundsEnd {
    let mut rounds = 0;
    let mut watching = Watching::default();
    while rounds < max_rounds.min(MAX_ROUNDS) && (rounds == 0 || !signals.stop.load(Ordering::SeqCst)) {
        refresh_watch(engine, settings_file, &mut watching);
        let snapshot = current_config(engine);
        run_round(&snapshot, clock).await;
        rounds += 1;
        let interval = Duration::from_secs(current_config(engine).settings.interval_seconds);
        tokio::select! {
            () = wait_pending(signals) => (),
            () = pause_for(interval) => (),
        }
        signals.applied.store(false, Ordering::SeqCst);
        if signals.hangup.swap(false, Ordering::SeqCst) {
            info!("hangup received, reloading the declarations");
            reload(engine);
        }
    }
    drop(watching);
    let _drained = engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
    RoundsEnd {
        rounds,
        stopped: signals.stop.load(Ordering::SeqCst),
    }
}


pub struct Seams<'a> {
    pub read: DeclarationsReader,
    pub clock: &'a ClockFn,
    pub pause: &'a PauseFn,
    pub max_rounds: u64,
}


/// One start read is the baseline and the audit path; the engine then reads again and must agree on every start-only value.
pub async fn start(settings_file: &Path, seams: &Seams<'_>, signals: &Arc<Signals>) -> Result<RoundsEnd, Box<dyn Error>> {
    let baseline = (seams.read)(settings_file)?;
    let log = Arc::new(open_file_log(&baseline.settings.audit_file)?);
    let first_pg = baseline.pg.clone();
    let engine = Arc::new(open_declarations(
        settings_file,
        Arc::clone(&seams.read),
        baseline,
        boxed_reload_audit(&log),
        Arc::clone(signals),
    )?);
    let client = connect(&first_pg).await?;
    let migrations = migrate(
        &client,
        MIGRATION_NAMESPACE,
        &MIGRATIONS,
        Duration::from_secs(first_pg.statement_timeout_secs),
    )
    .await?;
    drop(client);
    let frameworks = current_config(&engine).frameworks.len();
    let applied = migrations.len();
    info!(frameworks, applied, "serving");
    let end = serve_rounds(&engine, settings_file, signals, (seams.clock, seams.pause), seams.max_rounds).await;
    let rounds = end.rounds;
    info!(rounds, "stopped");
    Ok(end)
}


pub async fn run(arguments: &[String], streams: SignalStreams) -> Result<(), ServeError> {
    let settings_file = match arguments {
        [file] => Ok(file),
        _ => Err(ServeError::Usage),
    }?;
    install_logging().map_err(ServeError::Failed)?;
    let signals = Arc::new(Signals::default());
    tokio::spawn(listen_up_to(Arc::clone(&signals), streams, MAX_SIGNALS));
    let seams = Seams {
        read: Arc::new(load_declarations),
        clock: &system_clock,
        pause: &pause,
        max_rounds: MAX_ROUNDS,
    };
    start(Path::new(settings_file), &seams, &signals)
        .await
        .map(|_end| ())
        .map_err(ServeError::Failed)
}
