#![cfg(unix)]


#[path = "common/closed.rs"]
mod closed;
#[path = "common/pg.rs"]
mod pg;
#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use closed::closed_socket;
use core_pg::scope::tenant_scope;
use core_pg::settings::load_settings as load_pg_settings;
use pg::{fake_with, scanning};
use pg_fake::fake::Reply;
use pg_fake::types::Handler;
use site::{write_site, Site, TENANT, VULNERABLE};
use std::fs;
use std::future::{pending, ready};
use std::path::Path;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::watch::channel;
use types::TestResult;
use vuln_match::serve::{
    exit_code, install_logging, interrupted_now, micros_since_epoch, one_round, pause, plain_hooks, run, serve_rounds, serving_with,
    spawn_signal_worker, start, system_now_micros, Hooks, ServeError, Stop, DEBOUNCE, EXIT_ROUND_CAP,
};
use vuln_match::service::{load_settings, refresh, Loaded, ServiceSettings};
use vuln_match::types::InterruptWait;


const NOW: u64 = 1_700_000_000_000_000;


const HANG_GUARD: Duration = Duration::from_secs(120);


const ONE_ROUND: u64 = 1;


const TWO_ROUNDS: u64 = 2;


const DRAIN_LIMIT: usize = 1000;


const DEBOUNCE_MILLIS: u128 = 300;


const MICROS_PER_SECOND: u64 = 1_000_000;


fn never() -> InterruptWait {
    Box::pin(pending())
}


fn at_once(_duration: Duration) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(ready(()))
}


fn never_wakes(_duration: Duration) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(pending())
}


fn fixed_now() -> u64 {
    NOW
}


async fn site_with_pg(dir: &Path) -> Result<(Site, pg_fake::fake::Fake), Box<dyn std::error::Error>> {
    let (fake, ca_pem) = fake_with(scanning()).await?;
    let site = write_site(dir, fake.port, &ca_pem)?;
    fs::write(site.inventory.join("web-1.json"), VULNERABLE)?;
    Ok((site, fake))
}


fn drained(fake: &mut pg_fake::fake::Fake) -> Vec<String> {
    std::iter::repeat_with(|| fake.statements.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


#[test]
fn the_exit_code_names_the_round_cap() -> TestResult {
    assert_eq!(exit_code(&Ok(())), ExitCode::SUCCESS);
    assert_eq!(exit_code(&Err(ServeError::RoundCap)), ExitCode::from(EXIT_ROUND_CAP));
    assert_eq!(exit_code(&Err(ServeError::Usage)), ExitCode::FAILURE);
    assert_eq!(exit_code(&Err(ServeError::Failed("x".into()))), ExitCode::FAILURE);
    assert_eq!(DEBOUNCE.as_millis(), DEBOUNCE_MILLIS);
    Ok(())
}


#[test]
fn the_clock_reads_are_total() -> TestResult {
    assert_eq!(micros_since_epoch(Ok(Duration::from_secs(1))), MICROS_PER_SECOND);
    assert_eq!(micros_since_epoch(Ok(Duration::MAX)), u64::MAX);
    assert_eq!(micros_since_epoch(UNIX_EPOCH.duration_since(std::time::SystemTime::now())), 0);
    assert!(system_now_micros() > NOW);
    Ok(())
}


#[tokio::test]
async fn the_pause_waits_for_a_duration() -> TestResult {
    pause(Duration::ZERO).await;
    Ok(())
}


#[tokio::test]
async fn a_wrong_argument_count_is_the_usage_error() -> TestResult {
    assert!(matches!(run(&[], never()).await, Err(ServeError::Usage)));
    let two = ["a".to_owned(), "b".to_owned()];
    let error = run(&two, never()).await.err();
    assert!(error.is_some_and(|found| found.to_string().contains("usage: ostyr-vuln <service.yaml>")));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn run_installs_the_logging_and_serves_until_the_interrupt() -> TestResult {
    let dir = tempdir()?;
    let (site, _fake) = site_with_pg(dir.path()).await?;
    let arguments = [site.settings.display().to_string()];
    run(&arguments, Box::pin(ready(()))).await?;
    assert!(install_logging().is_err());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_start_error_is_named_and_carries_its_cause() -> TestResult {
    let dir = tempdir()?;
    let (site, _fake) = site_with_pg(dir.path()).await?;
    let missing = dir.path().join("absent.yaml");
    let missing_error = start(&missing, ONE_ROUND, &fixed_now, &at_once, never())
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(missing_error, ServeError::Failed(_)));
    assert!(missing_error.to_string().contains("absent.yaml"), "{missing_error}");
    fs::remove_file(&site.pg)?;
    let error = start(&site.settings, ONE_ROUND, &fixed_now, &at_once, never())
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("pg.yaml"), "{error}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), port, "")?;
    let error = start(&site.settings, ONE_ROUND, &fixed_now, &at_once, never())
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(matches!(error, ServeError::Failed(_)));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migration_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(Arc::new(|sql| {
        if sql.contains("CREATE TABLE IF NOT EXISTS public.schema_migrations") {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    }))
    .await?;
    let site = write_site(dir.path(), fake.port, &ca_pem)?;
    assert!(start(&site.settings, ONE_ROUND, &fixed_now, &at_once, never()).await.is_err());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_round_cap_is_a_named_error_after_the_rounds_ran() -> TestResult {
    let dir = tempdir()?;
    let (site, mut fake) = site_with_pg(dir.path()).await?;
    let error = start(&site.settings, TWO_ROUNDS, &fixed_now, &at_once, never())
        .await
        .err()
        .ok_or("expected the cap")?;
    assert!(matches!(error, ServeError::RoundCap), "{error}");
    assert!(error.to_string().contains("round cap"));
    let scans = drained(&mut fake).iter().filter(|sql| sql.contains("SELECT n_inserted")).count();
    assert_eq!(scans, TWO_ROUNDS as usize);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_during_the_wait_ends_the_service_with_success() -> TestResult {
    let dir = tempdir()?;
    let (site, _fake) = site_with_pg(dir.path()).await?;
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let interrupt: InterruptWait = Box::pin(async move {
        match receiver.await {
            Ok(()) | Err(_) => (),
        }
    });
    sender.send(()).map_err(|()| "the receiver is gone")?;
    start(&site.settings, u64::MAX, &fixed_now, &never_wakes, interrupt).await?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_file_swapped_after_the_one_start_read_is_refused_and_the_audit_path_is_the_first() -> TestResult {
    let dir = tempdir()?;
    let (site, _fake) = site_with_pg(dir.path()).await?;
    fn swapping(file: &Path) -> Result<ServiceSettings, core_config::error::ConfigError> {
        let first = load_settings(file)?;
        let text = fs::read_to_string(file).map_err(|_bad| core_config::error::ConfigError::TooLarge { file: String::new(), max: 0 })?;
        let other = text.replace("audit.log", "swapped-audit.log");
        fs::write(file, other).map_err(|_bad| core_config::error::ConfigError::TooLarge { file: String::new(), max: 0 })?;
        Ok(first)
    }
    let error = serving_with(swapping, &site.settings, ONE_ROUND, &fixed_now, &at_once, never(), &plain_hooks())
        .await
        .err()
        .ok_or("expected a refusal")?;
    assert!(error.to_string().contains("start-only"), "{error}");
    assert!(site.audit.exists());
    assert!(!dir.path().join("swapped-audit.log").exists());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_start_hook_sees_the_audit_wrapper_and_the_ready_point() -> TestResult {
    let dir = tempdir()?;
    let (site, _fake) = site_with_pg(dir.path()).await?;
    let wrapped = std::sync::atomic::AtomicUsize::new(0);
    let readied = std::sync::atomic::AtomicUsize::new(0);
    let wrap = |audit: Box<core_config::types::SharedAuditFn>| {
        wrapped.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        audit
    };
    let ready_hook = || {
        readied.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    };
    let nothing = || ();
    let hooks = Hooks {
        wrap_audit: &wrap,
        ready: &ready_hook,
        before_drain: &nothing,
    };
    serving_with(load_settings, &site.settings, ONE_ROUND, &fixed_now, &at_once, never(), &hooks).await?;
    assert_eq!(
        (
            wrapped.load(std::sync::atomic::Ordering::SeqCst),
            readied.load(std::sync::atomic::Ordering::SeqCst)
        ),
        (1, 1)
    );
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_store_that_cannot_be_reached_runs_no_round_and_the_service_retries() -> TestResult {
    let dir = tempdir()?;
    let (site, _fake) = site_with_pg(dir.path()).await?;
    let settings = load_settings(&site.settings)?;
    let (closed, port) = closed_socket()?;
    let dead = write_site(&dir.path().join("dead"), port, "").or_else(|_missing| {
        fs::create_dir_all(dir.path().join("dead"))?;
        write_site(&dir.path().join("dead"), port, "")
    })?;
    let pg = load_pg_settings(&dead.pg)?;
    let (_sender, stop) = channel(false);
    let (loaded, _degraded) = refresh(Loaded::default(), &settings);
    let report = one_round(&pg, &tenant_scope(TENANT)?, &settings, &loaded, NOW, &stop).await;
    assert!(report.skipped);
    drop(closed);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn rounds_stop_at_the_flag_and_a_wait_is_cut_short_by_it() -> TestResult {
    let dir = tempdir()?;
    let (site, _fake) = site_with_pg(dir.path()).await?;
    let first = load_settings(&site.settings)?;
    let engine =
        vuln_match::service::open_service_settings_from(&site.settings, first, Box::new(|_entry| Err(core_audit::error::AuditError::LogPoisoned)))?;
    let pg = load_pg_settings(&site.pg)?;
    let scope = tenant_scope(TENANT)?;
    let (sender, mut stop) = channel(false);
    sender.send_replace(true);
    assert_eq!(
        serve_rounds(&engine, &pg, &scope, u64::MAX, &fixed_now, &never_wakes, &mut stop).await,
        Stop::Interrupted
    );
    let (waker, mut waiting) = channel(false);
    let cutter = async {
        tokio::task::yield_now().await;
        waker.send_replace(true);
    };
    let (ended, ()) = tokio::join!(
        serve_rounds(&engine, &pg, &scope, u64::MAX, &fixed_now, &never_wakes, &mut waiting),
        cutter
    );
    assert_eq!(ended, Stop::Interrupted);
    Ok(())
}


#[tokio::test]
async fn a_stop_that_arrived_before_the_first_round_runs_no_round() -> TestResult {
    let dir = tempdir()?;
    let (site, mut fake) = site_with_pg(dir.path()).await?;
    let interrupt: InterruptWait = Box::pin(ready(()));
    let clock_reads = std::sync::atomic::AtomicUsize::new(0);
    let counting_now = || {
        clock_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        NOW
    };
    let ended = serving_with(
        load_settings,
        &site.settings,
        u64::MAX,
        &counting_now,
        &never_wakes,
        interrupt,
        &plain_hooks(),
    )
    .await?;
    assert_eq!(ended, Stop::Interrupted);
    assert_eq!(clock_reads.load(std::sync::atomic::Ordering::SeqCst), 0, "a round started");
    let scans = drained(&mut fake).iter().filter(|sql| sql.contains("SELECT n_inserted")).count();
    assert_eq!(scans, 0);
    Ok(())
}


/// The pg double blocks the first scan statement until released, so the stop flag is set while that statement is in flight.
fn blocking_scan(entered: std::sync::mpsc::Sender<()>, release: std::sync::mpsc::Receiver<()>) -> Handler {
    let entered_gate = Mutex::new(entered);
    let release_gate = Mutex::new(release);
    Arc::new(move |sql| {
        if sql.contains("vuln_scan_store(") {
            assert!(entered_gate.lock().is_ok_and(|sender| sender.send(()).is_ok()));
            assert!(
                release_gate.lock().is_ok_and(|receiver| receiver.recv_timeout(HANG_GUARD).is_ok()),
                "hang guard"
            );
            Reply::Rows(vec![["1", "0", "0", "0", "0", "0", "0"].map(str::to_owned).to_vec()])
        } else if sql.contains("jsonb_to_recordset($2") {
            Reply::Rows(vec![vec!["1".to_owned()]])
        } else {
            Reply::Done
        }
    })
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_never_cuts_a_scan_in_flight_and_ends_the_round_before_the_next_asset() -> TestResult {
    let dir = tempdir()?;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (mut fake, ca_pem) = fake_with(blocking_scan(entered_tx, release_rx)).await?;
    let site = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::write(site.inventory.join("web-1.json"), VULNERABLE)?;
    fs::write(site.inventory.join("web-2.json"), VULNERABLE)?;
    let settings = load_settings(&site.settings)?;
    let pg = load_pg_settings(&site.pg)?;
    let (sender, stop) = channel(false);
    let (loaded, _degraded) = refresh(Loaded::default(), &settings);
    let scope = tenant_scope(TENANT)?;
    let round = one_round(&pg, &scope, &settings, &loaded, NOW, &stop);
    let driver = async {
        let reached = tokio::task::spawn_blocking(move || entered_rx.recv_timeout(HANG_GUARD).is_ok()).await;
        assert!(reached.is_ok_and(|inside| inside), "no scan reached the store");
        sender.send_replace(true);
        assert!(release_tx.send(()).is_ok());
    };
    let (report, ()) = tokio::join!(round, driver);
    assert!(report.stopped);
    assert_eq!((report.scanned, report.findings, report.alerts), (1, 1, 1));
    let statements = drained(&mut fake);
    assert_eq!(statements.iter().filter(|sql| sql.contains("SELECT n_inserted")).count(), 1);
    assert!(statements.iter().any(|sql| sql.contains("jsonb_to_recordset($2")));
    Ok(())
}


#[cfg(unix)]
#[test]
fn dropping_the_signal_worker_waits_for_a_handler_in_flight() -> TestResult {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (dropping_tx, dropping_rx) = std::sync::mpsc::channel::<()>();
    let events: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let handler_events = Arc::clone(&events);
    let gate = Mutex::new(release_rx);
    let worker = spawn_signal_worker(
        &[signal_hook::consts::SIGUSR2],
        Box::new(move |_signal| {
            assert!(entered_tx.send(()).is_ok());
            assert!(gate.lock().is_ok_and(|receiver| receiver.recv_timeout(HANG_GUARD).is_ok()), "hang guard");
            assert!(handler_events.lock().is_ok_and(|mut list| {
                list.push("handled");
                true
            }));
        }),
    )?;
    assert!(signal_hook::low_level::raise(signal_hook::consts::SIGUSR2).is_ok());
    assert!(entered_rx.recv_timeout(HANG_GUARD).is_ok(), "the handler never ran");
    let dropper_events = Arc::clone(&events);
    let dropper = std::thread::spawn(move || {
        assert!(dropping_tx.send(()).is_ok());
        drop(worker);
        assert!(dropper_events.lock().is_ok_and(|mut list| {
            list.push("dropped");
            true
        }));
    });
    assert!(dropping_rx.recv_timeout(HANG_GUARD).is_ok());
    assert!(release_tx.send(()).is_ok());
    assert!(dropper.join().is_ok());
    assert_eq!(events.lock().map_err(|_poisoned| "poisoned")?.clone(), ["handled", "dropped"]);
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_panicking_signal_handler_is_reported_when_the_worker_is_dropped() -> TestResult {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let worker = spawn_signal_worker(
        &[signal_hook::consts::SIGUSR1],
        Box::new(move |signal| {
            assert!(entered_tx.send(()).is_ok());
            assert!(signal < 0, "the handler fails on purpose");
        }),
    )?;
    assert!(signal_hook::low_level::raise(signal_hook::consts::SIGUSR1).is_ok());
    assert!(entered_rx.recv_timeout(HANG_GUARD).is_ok(), "the handler never ran");
    drop(worker);
    Ok(())
}


#[tokio::test]
async fn a_pending_interrupt_is_left_awaitable_and_a_resolved_one_is_seen() -> TestResult {
    let mut pending_one: InterruptWait = never();
    assert!(!interrupted_now(&mut pending_one).await);
    let mut resolved: InterruptWait = Box::pin(ready(()));
    assert!(interrupted_now(&mut resolved).await);
    Ok(())
}
