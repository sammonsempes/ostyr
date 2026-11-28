#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/trail.rs"]
mod trail;
#[path = "common/types.rs"]
mod types;


use core_config::error::ConfigError;
use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome};
use grc::serve::{
    exit_code, install_logging, pause, pending, record_signal, refresh_watch, run, serve_rounds, start, stop_watch, system_clock, wait_pending, Kind,
    Seams, Watching, MAX_SPURIOUS_WAKES,
};
use grc::service::{load_declarations, open_declarations, Declarations, Signals};
use grc::types::{ClockFn, DeclarationsReader, PauseFuture};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use rcgen::SanType;
use site::{write_site, Site};
use std::fs;
use std::future::pending as never;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::OffsetDateTime;
use trail::recording_audit;
use types::TestResult;


const THREE_ROUNDS: u64 = 3;


const CHANGED_INTERVAL: u64 = 400;


const TWO_SIGNALS: u64 = 2;


const DRAIN_LIMIT: usize = 1_000;


const FLOOD: u64 = MAX_SPURIOUS_WAKES + 10;


const SETTLE_YIELDS: usize = 1_000;


fn fresh() -> Result<(TempDir, Site), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let (_closed, port) = closed_port()?;
    let site = write_site(dir.path(), port, "", "[builtin:nis2]")?;
    Ok((dir, site))
}


fn closed_port() -> std::io::Result<(socket2::Socket, u16)> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    socket.bind(&std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)).into())?;
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| std::io::Error::other("not an inet address"))?
        .port();
    Ok((socket, port))
}


fn real_reader() -> DeclarationsReader {
    Arc::new(|file: &Path| load_declarations(file))
}


struct Engined {
    trail: Arc<Mutex<Vec<String>>>,
    engine: Arc<ReloadEngine<Declarations>>,
}


fn engine_of(site: &Site, signals: &Arc<Signals>) -> Result<Engined, Box<dyn std::error::Error>> {
    let (trail, audit) = recording_audit();
    let baseline = load_declarations(&site.settings_file)?;
    let engine = Arc::new(open_declarations(
        &site.settings_file,
        real_reader(),
        baseline,
        audit,
        Arc::clone(signals),
    )?);
    Ok(Engined { trail, engine })
}


fn at_once(_duration: Duration) -> PauseFuture {
    Box::pin(std::future::ready(()))
}


fn forever(_duration: Duration) -> PauseFuture {
    Box::pin(never())
}


fn clock() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}


#[tokio::test(flavor = "multi_thread")]
async fn rounds_stop_at_the_cap_and_the_first_round_always_runs_before_a_queued_stop() -> TestResult {
    let (_dir, site) = fresh()?;
    let signals = Arc::new(Signals::default());
    let Engined { engine, .. } = engine_of(&site, &signals)?;
    let readings = Arc::new(AtomicU64::new(0));
    let counting = Arc::clone(&readings);
    let clock_fn = move || {
        counting.fetch_add(1, Ordering::SeqCst);
        OffsetDateTime::UNIX_EPOCH
    };
    let capped = serve_rounds(&engine, &site.settings_file, &signals, (&clock_fn, &at_once), THREE_ROUNDS).await;
    assert_eq!(
        (capped.rounds, capped.stopped, readings.load(Ordering::SeqCst)),
        (THREE_ROUNDS, false, THREE_ROUNDS)
    );
    signals.stop.store(true, Ordering::SeqCst);
    let queued = serve_rounds(&engine, &site.settings_file, &signals, (&clock_fn, &at_once), THREE_ROUNDS).await;
    assert_eq!(
        (queued.rounds, queued.stopped, readings.load(Ordering::SeqCst)),
        (1, true, THREE_ROUNDS + 1)
    );
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_arriving_during_a_round_waits_for_it_and_the_pause_never_runs_after_it() -> TestResult {
    let (_dir, site) = fresh()?;
    let signals = Arc::new(Signals::default());
    let Engined { engine, .. } = engine_of(&site, &signals)?;
    let during = Arc::clone(&signals);
    let clock_fn = move || {
        during.stop.store(true, Ordering::SeqCst);
        OffsetDateTime::UNIX_EPOCH
    };
    let end = serve_rounds(&engine, &site.settings_file, &signals, (&clock_fn, &forever), THREE_ROUNDS).await;
    assert_eq!((end.rounds, end.stopped), (1, true));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_hangup_reloads_and_an_applied_reload_runs_the_next_round_at_once() -> TestResult {
    let (_dir, site) = fresh()?;
    let signals = Arc::new(Signals::default());
    let Engined { trail, engine } = engine_of(&site, &signals)?;
    let calls = Arc::new(AtomicU64::new(0));
    let (seen, flags, path, text) = (
        Arc::clone(&calls),
        Arc::clone(&signals),
        site.settings_file.clone(),
        fs::read_to_string(&site.settings_file)?,
    );
    let clock_fn = move || {
        let number = seen.fetch_add(1, Ordering::SeqCst);
        if number == 0 {
            flags.hangup.store(true, Ordering::SeqCst);
            if let Err(error) = fs::write(&path, text.replace("interval_seconds: 300", "interval_seconds: 400")) {
                tracing::error!(%error, "test write failed");
            }
        } else if number == 1 {
            flags.applied.store(true, Ordering::SeqCst);
        } else {
            flags.stop.store(true, Ordering::SeqCst);
        }
        OffsetDateTime::UNIX_EPOCH
    };
    let end = serve_rounds(&engine, &site.settings_file, &signals, (&clock_fn, &forever), THREE_ROUNDS * THREE_ROUNDS).await;
    assert_eq!((end.rounds, end.stopped), (THREE_ROUNDS, true));
    assert_eq!(current_config(&engine).settings.interval_seconds, CHANGED_INTERVAL);
    assert_eq!(trail.lock().map_err(|_poisoned| "poisoned")?.clone(), vec!["all|Success|applied"]);
    assert!(!signals.applied.load(Ordering::SeqCst));
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn a_wake_with_no_flag_is_not_a_reason_to_run_and_a_flood_of_them_ends_at_the_cap() -> TestResult {
    let signals = Arc::new(Signals::default());
    assert!(!pending(&signals));
    signals.wake.notify_one();
    let setter = Arc::clone(&signals);
    let task = tokio::spawn(async move {
        setter.stop.store(true, Ordering::SeqCst);
        setter.wake.notify_one();
    });
    wait_pending(&signals).await;
    assert!(pending(&signals));
    assert!(task.await.is_ok());
    let quiet = Arc::new(Signals::default());
    let pusher = Arc::clone(&quiet);
    let flood = tokio::spawn(async move {
        for _round in 0..FLOOD {
            pusher.wake.notify_one();
            tokio::task::yield_now().await;
        }
    });
    wait_pending(&quiet).await;
    assert!(!pending(&quiet));
    assert!(flood.await.is_ok());
    Ok(())
}


#[test]
fn signals_are_recorded_as_flags_and_a_second_stop_is_a_repeat() -> TestResult {
    let signals = Signals::default();
    record_signal(&signals, Kind::Hangup);
    assert!(signals.hangup.load(Ordering::SeqCst) && !signals.stop.load(Ordering::SeqCst));
    record_signal(&signals, Kind::Stop);
    record_signal(&signals, Kind::Stop);
    assert!(signals.stop.load(Ordering::SeqCst));
    Ok(())
}


#[test]
fn the_watch_is_rebuilt_only_when_the_declared_files_change_and_a_failure_keeps_the_old_one() -> TestResult {
    let (_dir, site) = fresh()?;
    let signals = Arc::new(Signals::default());
    let Engined { engine, .. } = engine_of(&site, &signals)?;
    let mut watching = Watching::default();
    refresh_watch(&engine, &site.settings_file, &mut watching);
    assert!(watching.guard.is_some());
    let first = watching.files.clone();
    refresh_watch(&engine, &site.settings_file, &mut watching);
    assert_eq!(watching.files, first);
    let missing = site.dir.join("absent-dir").join("service.yaml");
    refresh_watch(&engine, &missing, &mut watching);
    assert_eq!(watching.files, first);
    let moved = site.dir.join("moved.yaml");
    refresh_watch(&engine, &moved, &mut watching);
    assert_eq!(watching.files.first(), Some(&moved));
    Ok(())
}


#[test]
fn stopping_the_watch_joins_its_thread_so_no_handler_outlives_the_call() -> TestResult {
    let (_dir, site) = fresh()?;
    let signals = Arc::new(Signals::default());
    let Engined { engine, .. } = engine_of(&site, &signals)?;
    let baseline = Arc::strong_count(&engine);
    let mut watching = Watching::default();
    refresh_watch(&engine, &site.settings_file, &mut watching);
    assert!(Arc::strong_count(&engine) > baseline);
    let moved = site.dir.join("moved.yaml");
    refresh_watch(&engine, &moved, &mut watching);
    assert_eq!(Arc::strong_count(&engine), baseline + 1);
    stop_watch(watching);
    assert_eq!(Arc::strong_count(&engine), baseline);
    stop_watch(Watching::default());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_reload_in_flight_at_the_stop_finishes_its_audit_before_the_serve_function_returns() -> TestResult {
    let (_dir, site) = fresh()?;
    let signals = Arc::new(Signals::default());
    let (entered_tx, entered_rx) = channel::<()>();
    let (release_tx, release_rx) = channel::<()>();
    let held = Mutex::new(release_rx);
    let calls = Arc::new(AtomicU64::new(0));
    let reader: DeclarationsReader = Arc::new(move |file: &Path| {
        if calls.fetch_add(1, Ordering::SeqCst) > 0 {
            entered_tx.send(()).map_err(|error| setting_failure(&error.to_string()))?;
            held.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv()
                .map_err(|error| setting_failure(&error.to_string()))?;
        }
        load_declarations(file)
    });
    let (trail, audit) = recording_audit();
    let baseline = load_declarations(&site.settings_file)?;
    let engine = Arc::new(open_declarations(&site.settings_file, reader, baseline, audit, Arc::clone(&signals))?);
    fs::write(
        &site.settings_file,
        fs::read_to_string(&site.settings_file)?.replace("interval_seconds: 300", "interval_seconds: 500"),
    )?;
    let reloading = Arc::clone(&engine);
    let reload_thread = std::thread::spawn(move || reload(&reloading));
    tokio::task::block_in_place(|| entered_rx.recv())?;
    signals.stop.store(true, Ordering::SeqCst);
    let order = Arc::clone(&trail);
    let serving = Arc::clone(&engine);
    let serve_signals = Arc::clone(&signals);
    let settings_file = site.settings_file.clone();
    let serve = tokio::spawn(async move {
        let clock_fn: &ClockFn = &clock;
        let end = serve_rounds(&serving, &settings_file, &serve_signals, (clock_fn, &at_once), 1).await;
        order.lock().unwrap_or_else(PoisonError::into_inner).push("returned".to_owned());
        end
    });
    let releaser = std::thread::spawn(move || {
        (0..SETTLE_YIELDS).for_each(|_round| std::thread::yield_now());
        release_tx.send(())
    });
    let end = serve.await?;
    releaser.join().map_err(|_panic| "releaser panicked")??;
    assert!(end.stopped);
    assert!(matches!(
        reload_thread.join().map_err(|_panic| "reload thread panicked")?,
        ReloadOutcome::Applied { .. }
    ));
    let lines = trail.lock().map_err(|_poisoned| "poisoned")?.clone();
    assert_eq!(lines, vec!["all|Success|applied", "returned"]);
    Ok(())
}


fn setting_failure(reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: "test".to_owned(),
        reason: reason.to_owned(),
    }
}


async fn answering_fake() -> Result<(Fake, String), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let handler = Arc::new(|sql: &str| {
        if sql.contains("grc_report_store") {
            Reply::Rows(vec![vec!["stored".to_owned(), "7".to_owned()]])
        } else if sql.contains("FROM grc_report") {
            Reply::Rows(Vec::new())
        } else {
            Reply::Done
        }
    });
    let started = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    Ok((started, pki.ca_pem))
}


fn seams<'a>(max_rounds: u64) -> Seams<'a> {
    Seams {
        read: real_reader(),
        clock: &system_clock,
        pause: &at_once,
        max_rounds,
    }
}


#[tokio::test(flavor = "multi_thread")]
async fn start_runs_the_rounds_it_is_given_and_audits_under_the_all_tenant() -> TestResult {
    let dir = tempdir()?;
    let (mut served, ca_pem) = answering_fake().await?;
    let site = write_site(dir.path(), served.port, &ca_pem, "[builtin:nis2]")?;
    let signals = Arc::new(Signals::default());
    let end = start(&site.settings_file, &seams(1), &signals).await?;
    assert_eq!(end.rounds, 1);
    assert!(site.audit_file.exists());
    let statements: Vec<String> = std::iter::repeat_with(|| served.statements.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect();
    assert!(
        statements.iter().any(|statement| statement.contains("grc_report_store")),
        "{statements:?}"
    );
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_fails_by_name_on_each_start_step() -> TestResult {
    let dir = tempdir()?;
    let signals = Arc::new(Signals::default());
    let (_closed, port) = closed_port()?;
    let site = write_site(dir.path(), port, "", "[builtin:nis2]")?;
    let refused_database = start(&site.settings_file, &seams(1), &signals).await.err().ok_or("started")?;
    assert!(!refused_database.to_string().is_empty());
    fs::remove_file(&site.manual_file)?;
    let unreadable = start(&site.settings_file, &seams(1), &signals).await.err().ok_or("started")?;
    assert!(unreadable.to_string().contains("manual.yaml"), "{unreadable}");
    fs::write(&site.manual_file, site::MANUAL_ACME)?;
    fs::remove_file(&site.audit_file)?;
    fs::create_dir(&site.audit_file)?;
    let no_audit = start(&site.settings_file, &seams(1), &signals).await.err().ok_or("started")?;
    assert!(!no_audit.to_string().is_empty());
    fs::remove_dir(&site.audit_file)?;
    let swapped = start(
        &site.settings_file,
        &Seams {
            read: swapping_reader(&site.pg_file),
            ..seams(1)
        },
        &signals,
    )
    .await
    .err()
    .ok_or("started")?;
    assert!(swapped.to_string().contains("start-only"), "{swapped}");
    Ok(())
}


fn swapping_reader(pg_file: &Path) -> DeclarationsReader {
    let target = pg_file.to_path_buf();
    Arc::new(move |file: &Path| {
        let first = load_declarations(file);
        let text = fs::read_to_string(&target).map_err(|error| setting_failure(&error.to_string()))?;
        fs::write(&target, text.replace("127.0.0.1", "attacker.example")).map_err(|error| setting_failure(&error.to_string()))?;
        first
    })
}


#[tokio::test(flavor = "multi_thread")]
async fn start_fails_when_the_migration_fails() -> TestResult {
    let dir = tempdir()?;
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let failing = fake::start(Mode::Tls(pki.server), "p", Arc::new(|_sql: &str| Reply::Error("XX000"))).await?;
    let site = write_site(dir.path(), failing.port, &pki.ca_pem, "[builtin:nis2]")?;
    let signals = Arc::new(Signals::default());
    assert!(start(&site.settings_file, &seams(1), &signals).await.is_err());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn run_refuses_a_bad_usage_and_a_second_logging_install_and_exit_codes_follow_the_result() -> TestResult {
    let streams = grc::serve::register_signals()?;
    let usage = run(&[], streams).await.err().ok_or("accepted")?;
    assert!(usage.to_string().contains("usage: ostyr-grc"));
    assert_eq!(exit_code(&Err(usage)), ExitCode::FAILURE);
    assert_eq!(exit_code(&Ok(())), ExitCode::SUCCESS);
    install_logging().map_err(|error| error.to_string())?;
    assert!(install_logging().is_err());
    let again = run(&["x".to_owned()], grc::serve::register_signals()?).await.err().ok_or("accepted")?;
    assert!(!again.to_string().is_empty());
    pause(Duration::ZERO).await;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_listener_records_each_signal_as_a_flag_and_returns_at_its_limit() -> TestResult {
    let signals = Arc::new(Signals::default());
    let streams = grc::serve::register_signals()?;
    let listening = tokio::spawn(grc::serve::listen_up_to(Arc::clone(&signals), streams, TWO_SIGNALS));
    let own = std::process::id().to_string();
    assert!(Command::new("kill").args(["-HUP", &own]).status()?.success());
    assert!(Command::new("kill").args(["-TERM", &own]).status()?.success());
    listening.await?;
    assert!(signals.hangup.load(Ordering::SeqCst));
    assert!(signals.stop.load(Ordering::SeqCst));
    Ok(())
}
