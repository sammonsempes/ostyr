#![cfg(unix)]

#[path = "common/types.rs"]
mod types;


use cmdb::model::{DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log};
use core_config::reload::{current_config, reload, ReloadEngine, ReloadOutcome, RELOAD_DECLARED_KEYS};
use core_pg::settings::load_settings as load_pg;
use k8s_inventory::serve::{announce, announce_interrupts, audit_start, boxed_reload_audit, drain_reloads, listing_entry, serve, stop_asked};
use k8s_inventory::service::{
    limits_of, load_service_settings, open_service_settings_from, settings_state, start_only_changes, LiveSettings, MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
};
use k8s_inventory::settings::load_settings;
use k8s_inventory::signals::{quiet_reload_signals, reload_on_signals, stop_reloaders, Reloaders};
use k8s_inventory::types::InterruptWait;
use std::fs;
use std::future::{pending, ready};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const HANG_GUARD: Duration = Duration::from_secs(60);


const NOT_DONE_YET: Duration = Duration::from_millis(300);


const OVER: usize = 1;


const SWAPS: usize = 5;


const TWO_INTERRUPTS: u64 = 2;


const HELD_BY_SIGNAL_THREAD: usize = 2;


const NEW_TIMEOUT: u64 = 5000;


const CAP_ASSETS: usize = 5;


const CAP_ROWS: usize = 7;


fn text(interval: u64, extra: &str, audit: &str) -> String {
    format!("fetch_settings: /etc/f.yaml\npg_settings: /etc/p.yaml\naudit_file: {audit}\ninterval_seconds: {interval}\n{extra}")
}


const FETCH_BODY: &str = "api_url: https://127.0.0.1:1\nca_file: /ca.pem\ntoken_file: /token\ntenant: a\ncluster: c1\n";


fn fetch_text(replacing: &str, with: &str) -> String {
    FETCH_BODY.replace(replacing, with)
}


struct Pair {
    service: std::path::PathBuf,
    fetch: std::path::PathBuf,
    audit: std::path::PathBuf,
    live: LiveSettings,
}


fn pair(dir: &Path) -> Result<Pair, Box<dyn std::error::Error>> {
    pair_with(dir, FETCH_BODY)
}


fn pair_with(dir: &Path, fetch_body: &str) -> Result<Pair, Box<dyn std::error::Error>> {
    let audit = dir.join("audit.log");
    let fetch = dir.join("fetch.yaml");
    fs::write(&fetch, fetch_body)?;
    let body = text(MIN_INTERVAL_SECONDS, "", &audit.display().to_string()).replace("/etc/f.yaml", &fetch.display().to_string());
    let service = service_file(dir, &body)?;
    let live = LiveSettings {
        service: load_service_settings(&service)?,
        fetch: load_settings(&fetch)?,
    };
    Ok(Pair { service, fetch, audit, live })
}


fn engine_of(pair: &Pair) -> Result<ReloadEngine<LiveSettings>, Box<dyn std::error::Error>> {
    let log = Arc::new(open_file_log(&pair.audit)?);
    Ok(open_service_settings_from(
        &pair.service,
        &pair.fetch,
        pair.live.clone(),
        boxed_reload_audit(&log),
    )?)
}


fn service_file(dir: &Path, body: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let file = dir.join("service.yaml");
    fs::write(&file, body)?;
    Ok(file)
}


fn refused(dir: &Path, body: &str, marker: &str) -> TestResult {
    let error = load_service_settings(&service_file(dir, body)?)
        .err()
        .ok_or("the settings were accepted")?;
    assert!(error.to_string().contains(marker), "{error}");
    Ok(())
}


#[test]
fn the_ranges_are_enforced_and_the_edges_are_accepted() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log").display().to_string();
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS - 1, "", &audit), "interval_seconds")?;
    refused(dir.path(), &text(MAX_INTERVAL_SECONDS + 1, "", &audit), "interval_seconds")?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "max_assets: 0\n", &audit), "max_assets")?;
    refused(
        dir.path(),
        &text(MIN_INTERVAL_SECONDS, &format!("max_assets: {}\n", DEFAULT_MAX_ASSETS + OVER), &audit),
        "max_assets",
    )?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "max_child_rows: 0\n", &audit), "max_child_rows")?;
    refused(
        dir.path(),
        &text(
            MIN_INTERVAL_SECONDS,
            &format!("max_child_rows: {}\n", DEFAULT_MAX_CHILD_ROWS + OVER),
            &audit,
        ),
        "max_child_rows",
    )?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "", "relative.log"), "audit_file")?;
    refused(dir.path(), &text(MIN_INTERVAL_SECONDS, "surprise: 1\n", &audit), "unknown field")?;
    let low = load_service_settings(&service_file(dir.path(), &text(MIN_INTERVAL_SECONDS, "", &audit))?)?;
    let high = load_service_settings(&service_file(
        dir.path(),
        &text(
            MAX_INTERVAL_SECONDS,
            &format!("max_assets: {DEFAULT_MAX_ASSETS}\nmax_child_rows: {DEFAULT_MAX_CHILD_ROWS}\n"),
            &audit,
        ),
    )?)?;
    assert_eq!(low.interval_seconds, MIN_INTERVAL_SECONDS);
    assert_eq!(limits_of(&low).max_assets, DEFAULT_MAX_ASSETS);
    assert_eq!(limits_of(&high).max_child_rows, DEFAULT_MAX_CHILD_ROWS);
    Ok(())
}


#[test]
fn a_cap_setting_reaches_the_cmdb_limits() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log").display().to_string();
    let settings = load_service_settings(&service_file(
        dir.path(),
        &text(MIN_INTERVAL_SECONDS, "max_assets: 5\nmax_child_rows: 7\n", &audit),
    )?)?;
    let limits = limits_of(&settings);
    assert_eq!((limits.max_assets, limits.max_child_rows), (CAP_ASSETS, CAP_ROWS));
    Ok(())
}


fn denied(outcome: &ReloadOutcome) -> bool {
    matches!(outcome, ReloadOutcome::Refused { reason } if reason.contains("start-only"))
}


fn rewrite_service(site: &Pair, interval: u64, extra: &str) -> TestResult {
    let audit = site.audit.display().to_string();
    fs::write(
        &site.service,
        text(interval, extra, &audit).replace("/etc/f.yaml", &site.fetch.display().to_string()),
    )?;
    Ok(())
}


#[test]
fn a_live_change_is_applied_audited_under_all_and_a_start_only_change_is_refused() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let engine = engine_of(&site)?;
    rewrite_service(&site, MIN_INTERVAL_SECONDS + OVER as u64, "max_assets: 3\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).service.interval_seconds, MIN_INTERVAL_SECONDS + OVER as u64);
    assert!(start_only_changes(&site.live, &current_config(&engine)).is_empty());
    let other = text(MIN_INTERVAL_SECONDS, "", &dir.path().join("other.log").display().to_string());
    fs::write(&site.service, other.replace("/etc/f.yaml", &site.fetch.display().to_string()))?;
    assert!(denied(&reload(&engine)));
    let moved = text(MIN_INTERVAL_SECONDS, "", &site.audit.display().to_string()).replace("/etc/f.yaml", "/etc/other-fetch.yaml");
    fs::write(&site.service, moved)?;
    assert!(denied(&reload(&engine)));
    assert_eq!(current_config(&engine).service.interval_seconds, MIN_INTERVAL_SECONDS + OVER as u64);
    let records = fs::read_to_string(&site.audit)?;
    assert!(records.contains("service file: audit_file"), "{records}");
    assert!(records.contains("service file: fetch_settings"), "{records}");
    assert!(!records.contains("other.log") && !records.contains("other-fetch"), "{records}");
    assert!(records.contains("\"tenant\":\"all\""), "{records}");
    assert!(records.contains("k8s-inventory"), "{records}");
    assert!(records.contains(&format!("\"target\":\"{}\"", site.service.display())), "{records}");
    Ok(())
}


#[test]
fn a_tenant_or_credential_swap_in_the_fetch_file_is_refused_audited_and_never_applied() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let engine = engine_of(&site)?;
    [
        ("tenant: a", "tenant: victim"),
        ("cluster: c1", "cluster: c2"),
        ("token_file: /token", "token_file: /run/secrets/pg.pass"),
        ("api_url: https://127.0.0.1:1", "api_url: https://attacker.example:443"),
        ("ca_file: /ca.pem", "ca_file: /other-ca.pem"),
    ]
    .into_iter()
    .try_for_each(|(from, to)| -> TestResult {
        fs::write(&site.fetch, fetch_text(from, to))?;
        let outcome = reload(&engine);
        assert!(denied(&outcome), "{to}: {outcome:?}");
        assert_eq!(current_config(&engine).fetch, site.live.fetch);
        Ok(())
    })?;
    let records = fs::read_to_string(&site.audit)?;
    assert_eq!(records.matches("\"outcome\":\"denied\"").count(), SWAPS, "{records}");
    ["tenant", "cluster", "token_file", "api_url", "ca_file"]
        .iter()
        .for_each(|key| assert!(records.contains(&format!("fetch file: {key}")), "{key}: {records}"));
    assert!(!records.contains("victim"), "{records}");
    Ok(())
}


#[test]
fn a_reloadable_fetch_field_is_applied_and_audited_with_its_key() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let engine = engine_of(&site)?;
    fs::write(&site.fetch, format!("{FETCH_BODY}timeout_ms: {NEW_TIMEOUT}\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).fetch.timeout_ms, NEW_TIMEOUT);
    let records = fs::read_to_string(&site.audit)?;
    assert!(records.contains("fetch::timeout_ms"), "{records}");
    assert!(settings_state(&current_config(&engine)).contains_key("fetch::tenant"));
    fs::write(&site.fetch, "surprise: 1\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&site.fetch, fetch_text("https://127.0.0.1:1", "http://x"))?;
    let bad = reload(&engine);
    assert!(matches!(&bad, ReloadOutcome::Refused { reason } if reason.contains("api_url")), "{bad:?}");
    assert_eq!(current_config(&engine).fetch.timeout_ms, NEW_TIMEOUT);
    Ok(())
}


struct Held {
    engine: Arc<ReloadEngine<LiveSettings>>,
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
    finished: Arc<Mutex<Vec<&'static str>>>,
}


fn held_engine(site: &Pair) -> Result<Held, Box<dyn std::error::Error>> {
    let log = Arc::new(open_file_log(&site.audit)?);
    let (inside, entered) = channel();
    let (release, release_rx) = channel::<()>();
    let released = Mutex::new(release_rx);
    let finished = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let order = Arc::clone(&finished);
    let engine = Arc::new(open_service_settings_from(
        &site.service,
        &site.fetch,
        site.live.clone(),
        Box::new(move |entry| {
            inside.send(()).map_err(|_closed| AuditError::LogPoisoned)?;
            released
                .lock()
                .map_err(|_poisoned| AuditError::LogPoisoned)?
                .recv_timeout(HANG_GUARD)
                .map_err(|_late| AuditError::LogPoisoned)?;
            let record = append_declared(&log, entry, &RELOAD_DECLARED_KEYS);
            order.lock().map_err(|_poisoned| AuditError::LogPoisoned)?.push("audit written");
            record
        }),
    )?);
    Ok(Held {
        engine,
        entered,
        release,
        finished,
    })
}


#[test]
fn a_stop_waits_for_the_reload_in_flight_to_finish_its_audit_record() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let held = held_engine(&site)?;
    rewrite_service(&site, MIN_INTERVAL_SECONDS + OVER as u64, "")?;
    let reloading = Arc::clone(&held.engine);
    let reload_thread = spawn(move || reload(&reloading));
    held.entered.recv_timeout(HANG_GUARD)?;
    let (drained_tx, drained_rx) = channel();
    let draining = Arc::clone(&held.engine);
    let order_at_drain = Arc::clone(&held.finished);
    let drain_thread = spawn(move || {
        drain_reloads(&draining);
        let written = order_at_drain.lock().map_or(usize::MAX, |done| done.len());
        drained_tx.send(written)
    });
    assert_eq!(drained_rx.recv_timeout(NOT_DONE_YET), Err(RecvTimeoutError::Timeout));
    held.release.send(())?;
    assert_eq!(drained_rx.recv_timeout(HANG_GUARD)?, 1);
    drain_thread.join().map_err(|_panic| "the drain thread panicked")??;
    assert!(matches!(
        reload_thread.join().map_err(|_panic| "the reload thread panicked")?,
        ReloadOutcome::Applied { .. }
    ));
    Ok(())
}


#[test]
fn serve_itself_drains_the_reload_in_flight_before_it_returns() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let pg_file = dir.path().join("pg.yaml");
    fs::write(
        &pg_file,
        "host: 127.0.0.1\nport: 1\ndatabase: d\nuser: u\npassword_file: /p\nca_file: /c\n",
    )?;
    let pg = load_pg(&pg_file)?;
    let held = held_engine(&site)?;
    rewrite_service(&site, MIN_INTERVAL_SECONDS + OVER as u64, "")?;
    let reloading = Arc::clone(&held.engine);
    let reload_thread = spawn(move || reload(&reloading));
    held.entered.recv_timeout(HANG_GUARD)?;
    let (done_tx, done_rx) = channel();
    let serving = Arc::clone(&held.engine);
    let order_at_return = Arc::clone(&held.finished);
    let serve_thread = spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread().build().map_err(|error| error.to_string())?;
        let mut stop: InterruptWait = Box::pin(ready(Ok(())));
        let stopped = runtime
            .block_on(serve(
                &serving,
                &pg,
                u64::MAX,
                k8s_inventory::serve::pause,
                &mut stop,
                Reloaders::default(),
            ))
            .map_err(|error| error.to_string())?;
        let written = order_at_return.lock().map_or(usize::MAX, |done| done.len());
        done_tx.send((stopped, written)).map_err(|error| error.to_string())
    });
    assert!(done_rx.recv_timeout(NOT_DONE_YET).is_err());
    held.release.send(())?;
    let (stopped, written) = done_rx.recv_timeout(HANG_GUARD)?;
    assert_eq!(stopped, k8s_inventory::serve::Stop::Interrupted);
    assert_eq!(written, 1);
    serve_thread.join().map_err(|_panic| "the serve thread panicked")??;
    reload_thread.join().map_err(|_panic| "the reload thread panicked")?;
    Ok(())
}


#[tokio::test]
async fn stop_asked_answers_at_once_and_passes_a_signal_error_on() -> TestResult {
    let mut stop: InterruptWait = Box::pin(ready(Ok(())));
    assert!(stop_asked(&mut stop).await?);
    let mut quiet: InterruptWait = Box::pin(pending());
    assert!(!stop_asked(&mut quiet).await?);
    let mut broken: InterruptWait = Box::pin(ready(Err(std::io::Error::other("no signal"))));
    assert!(stop_asked(&mut broken).await.is_err());
    Ok(())
}


#[test]
fn the_engine_opens_on_the_start_read_and_never_reads_the_files_again() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    fs::remove_file(&site.service)?;
    fs::remove_file(&site.fetch)?;
    let engine = engine_of(&site)?;
    assert_eq!(*current_config(&engine), site.live);
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    Ok(())
}


#[test]
fn the_first_configuration_is_audited_at_start_without_a_secret() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let engine = engine_of(&site)?;
    audit_start(&engine)?;
    let records = fs::read_to_string(&site.audit)?;
    assert!(records.contains("\"result\":\"started\""), "{records}");
    assert!(records.contains("fetch::tenant=a"), "{records}");
    assert!(
        records.contains(&format!("fetch::token_file=/token;\\nfetch_settings={};\\n", site.fetch.display())),
        "{records}"
    );
    assert!(!records.contains("[REDACTED]"), "{records}");
    assert!(records.contains("\"tenant\":\"all\""), "{records}");
    Ok(())
}


#[test]
fn a_redactor_match_in_one_start_entry_never_blanks_a_later_one() -> TestResult {
    let dir = tempdir()?;
    let site = pair_with(dir.path(), &fetch_text("/ca.pem", "/etc/token=1/ca.pem"))?;
    let engine = engine_of(&site)?;
    audit_start(&engine)?;
    let records = fs::read_to_string(&site.audit)?;
    assert!(records.contains("fetch::cluster=c1"), "{records}");
    assert!(records.contains("fetch::tenant=a"), "{records}");
    assert!(records.contains("fetch::token_file=/token"), "{records}");
    assert!(records.contains(&format!("fetch_settings={}", site.fetch.display())), "{records}");
    Ok(())
}


#[test]
fn a_value_holding_the_separator_cannot_forge_an_entry() -> TestResult {
    assert_eq!(
        listing_entry("fetch::ca_file", "a; fetch::tenant=victim; b"),
        "fetch::ca_file=a\\x3b fetch::tenant=victim\\x3b b;\n"
    );
    assert_eq!(listing_entry("k", "a\n;\nfetch::tenant=victim"), "k=a\\n\\x3b\\nfetch::tenant=victim;\n");
    assert_eq!(listing_entry("k", "plain"), "k=plain;\n");
    let dir = tempdir()?;
    let site = pair_with(dir.path(), &fetch_text("/ca.pem", "'a; fetch::tenant=victim; b'"))?;
    let engine = engine_of(&site)?;
    audit_start(&engine)?;
    let records = fs::read_to_string(&site.audit)?;
    assert!(records.contains("fetch::ca_file=a\\\\x3b fetch::tenant=victim\\\\x3b b;\\n"), "{records}");
    assert!(!records.contains("; fetch::tenant=victim"), "{records}");
    Ok(())
}


#[test]
fn the_reload_sources_are_stopped_and_joined_before_serve_returns() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let pg_file = dir.path().join("pg.yaml");
    fs::write(
        &pg_file,
        "host: 127.0.0.1\nport: 1\ndatabase: d\nuser: u\npassword_file: /p\nca_file: /c\n",
    )?;
    let pg = load_pg(&pg_file)?;
    let engine = Arc::new(engine_of(&site)?);
    let signals = quiet_reload_signals()?;
    let stopped = Arc::new(AtomicBool::new(false));
    let marker = Arc::clone(&stopped);
    let reloaders = Reloaders {
        stoppers: vec![
            reload_on_signals(signals, Arc::clone(&engine)),
            Box::new(move || marker.store(true, Ordering::SeqCst)),
        ],
    };
    assert_eq!(Arc::strong_count(&engine), HELD_BY_SIGNAL_THREAD);
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let mut stop: InterruptWait = Box::pin(ready(Ok(())));
    runtime.block_on(serve(&engine, &pg, u64::MAX, k8s_inventory::serve::pause, &mut stop, reloaders))?;
    assert!(stopped.load(Ordering::SeqCst));
    assert_eq!(Arc::strong_count(&engine), 1);
    Ok(())
}


#[test]
fn a_signal_queued_before_the_reload_thread_starts_is_handled_after_it_and_stop_joins_the_thread() -> TestResult {
    let dir = tempdir()?;
    let site = pair(dir.path())?;
    let log = Arc::new(open_file_log(&site.audit)?);
    let (applied, applied_seen) = channel();
    let engine = Arc::new(open_service_settings_from(
        &site.service,
        &site.fetch,
        site.live.clone(),
        Box::new(move |entry| {
            let record = append_declared(&log, entry, &RELOAD_DECLARED_KEYS);
            applied.send(()).map_err(|_closed| AuditError::LogPoisoned)?;
            record
        }),
    )?);
    let signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGUSR1])?;
    signal_hook::low_level::raise(signal_hook::consts::SIGUSR1)?;
    rewrite_service(&site, MIN_INTERVAL_SECONDS + OVER as u64, "")?;
    let stopper = reload_on_signals(signals, Arc::clone(&engine));
    applied_seen.recv_timeout(HANG_GUARD)?;
    assert_eq!(Arc::strong_count(&engine), HELD_BY_SIGNAL_THREAD);
    stop_reloaders(Reloaders { stoppers: vec![stopper] });
    assert_eq!(current_config(&engine).service.interval_seconds, MIN_INTERVAL_SECONDS + OVER as u64);
    assert_eq!(Arc::strong_count(&engine), 1);
    Ok(())
}


#[test]
fn an_interrupt_is_announced_by_name_whoever_hears_it() -> TestResult {
    let (first, first_seen) = tokio::sync::oneshot::channel();
    announce("SIGTERM", Some(first));
    assert!(first_seen.blocking_recv().is_ok());
    let (gone, gone_seen) = tokio::sync::oneshot::channel::<()>();
    drop(gone_seen);
    announce("SIGINT", Some(gone));
    announce("SIGINT", None);
    assert!(quiet_reload_signals().is_ok());
    Ok(())
}


#[tokio::test]
async fn the_interrupt_task_releases_the_first_and_logs_the_rest_then_ends() -> TestResult {
    let first_stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let second_stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
    let (first, first_seen) = tokio::sync::oneshot::channel();
    signal_hook::low_level::raise(signal_hook::consts::SIGUSR1)?;
    signal_hook::low_level::raise(signal_hook::consts::SIGUSR2)?;
    announce_interrupts(first_stream, second_stream, first, TWO_INTERRUPTS).await;
    first_seen.await?;
    Ok(())
}
