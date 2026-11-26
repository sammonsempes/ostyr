#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_config::reload::{current_config, open_engine, reload, ReloadEngine, ReloadOutcome, RELOAD_DECLARED_KEYS};
use core_pg::settings::load_settings as load_pg_settings;
use pg_fake::fake::Reply;
use site::{applying, pg_with, write_site, Site};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::future::{pending, ready};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::{spawn, yield_now};
use std::time::Duration;
use tempfile::tempdir;
use tokio::time::timeout;
use types::TestResult;
use virt_inventory::cmdb_sync::SyncReport;
use virt_inventory::error::{FetchError, RoundError};
use virt_inventory::hangup::{arm_hangup, follow_hangup};
use virt_inventory::model::{Context, Live, RoundReport, Skipped};
use virt_inventory::serve::{drain, pause, run, serve, start, stop_pending, Drain};
use virt_inventory::service::{live_loader, live_state, load_live, open_live_engine, reload_context, START_ONLY};
use virt_inventory::types::{InterruptWait, RoundFuture, WaitFuture};


const THREE_ROUNDS: usize = 3;


const TWO_ROUNDS: usize = 2;


const OLD_INTERVAL: u64 = 60;


const NEW_INTERVAL: u64 = 120;


const NEW_TIMEOUT_MS: u64 = 7000;


const SMALL_ASSETS: usize = 5;


const YIELDS: usize = 20_000;


const HANG_GUARD: Duration = Duration::from_secs(120);


struct Open {
    engine: Arc<ReloadEngine<Live>>,
    audit: Arc<AuditLog<File>>,
}


fn open_for(site: &Site) -> Result<Open, Box<dyn Error>> {
    let baseline = load_live(&site.settings_file)?;
    let audit = Arc::new(open_file_log(&baseline.service.audit_file)?);
    let sink = Arc::clone(&audit);
    let engine = Arc::new(open_live_engine(
        &site.settings_file,
        baseline,
        Box::new(move |entry| append_declared(&sink, entry, &RELOAD_DECLARED_KEYS)),
    )?);
    Ok(Open { engine, audit })
}


fn edit(path: &Path, from: &str, to: &str) -> TestResult {
    let text = fs::read_to_string(path)?;
    assert!(text.contains(from), "{from} not in {text}");
    fs::write(path, text.replacen(from, to, 1))?;
    Ok(())
}


fn records_in(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(fs::read_to_string(path)?.lines().map(str::to_owned).collect())
}


fn failing_round(_context: &Context) -> RoundFuture<'_> {
    Box::pin(async {
        tokio::task::yield_now().await;
        Err(RoundError::Fetch(FetchError::Url))
    })
}


fn good_round(_context: &Context) -> RoundFuture<'_> {
    Box::pin(async {
        tokio::task::yield_now().await;
        Ok(RoundReport {
            sync: SyncReport::default(),
            skipped: Skipped::default(),
        })
    })
}


fn live_round(context: &Context) -> RoundFuture<'_> {
    let seen_live = context.fetch.timeout_ms == NEW_TIMEOUT_MS && context.limits.max_assets == SMALL_ASSETS;
    Box::pin(async move {
        if seen_live {
            Ok(RoundReport {
                sync: SyncReport::default(),
                skipped: Skipped::default(),
            })
        } else {
            Err(RoundError::Fetch(FetchError::Timeout))
        }
    })
}


fn at_once(_duration: Duration) -> WaitFuture {
    Box::pin(ready(()))
}


fn only_the_new_interval(duration: Duration) -> WaitFuture {
    Box::pin(async move {
        if duration != Duration::from_secs(NEW_INTERVAL) {
            pending::<()>().await;
        }
    })
}


fn never_stops() -> io::Result<InterruptWait> {
    Ok(Box::pin(pending()))
}


fn stops_now() -> io::Result<InterruptWait> {
    Ok(Box::pin(ready(Ok(()))))
}


fn cannot_arm() -> io::Result<InterruptWait> {
    Err(io::Error::other("no signal"))
}


#[test]
fn a_live_edit_is_applied_audited_and_a_start_only_edit_is_refused_and_audited_denied() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let open = open_for(&site)?;
    let fetch_file = dir.path().join("fetch.yaml");
    edit(&site.settings_file, "interval_seconds: 60", "interval_seconds: 120")?;
    edit(&fetch_file, "timeout_ms: 5000", "timeout_ms: 7000")?;
    assert!(matches!(reload(&open.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&open.engine).service.interval_seconds, NEW_INTERVAL);
    assert_eq!(current_config(&open.engine).fetch.timeout_ms, NEW_TIMEOUT_MS);
    let applied = records_in(&site.audit_file)?;
    assert_eq!(applied.len(), 1);
    assert!(applied
        .iter()
        .all(|line| line.contains("\"tenant\":\"all\"") && line.contains("\"outcome\":\"success\"")));
    let before = current_config(&open.engine);
    let hostile = [
        (&fetch_file, "tenant: acme", "tenant: other", "fetch", "fetch::tenant"),
        (&fetch_file, "cluster: pve-1", "cluster: pve-2", "fetch", "fetch::cluster"),
        (
            &fetch_file,
            "api_url: https://localhost:1",
            "api_url: https://localhost:2",
            "fetch",
            "fetch::api_url",
        ),
        (&fetch_file, "pve-ca.pem", "other-ca.pem", "fetch", "fetch::ca_file"),
        (&fetch_file, "token\n", "other-token\n", "fetch", "fetch::token_file"),
        (&site.settings_file, "pg.yaml", "other-pg.yaml", "service", "service::pg_settings"),
        (&site.settings_file, "audit.log", "other-audit.log", "service", "service::audit_file"),
    ];
    hostile.iter().try_for_each(|(file, from, to, label, key)| -> TestResult {
        let original = fs::read_to_string(file)?;
        edit(file, from, to)?;
        let outcome = reload(&open.engine);
        fs::write(file, original)?;
        assert!(
            matches!(&outcome, ReloadOutcome::Refused { reason }
                if reason.contains("read at start only") && reason.contains(&format!("`{label}`")) && reason.contains(key) && !reason.contains(to)),
            "{from}: {outcome:?}"
        );
        assert_eq!(*current_config(&open.engine), *before, "{from}");
        Ok(())
    })?;
    let denied = records_in(&site.audit_file)?
        .into_iter()
        .filter(|line| line.contains("\"outcome\":\"denied\""))
        .count();
    assert_eq!(denied, hostile.len());
    assert_eq!(reload(&open.engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn a_service_file_naming_another_fetch_file_is_refused_before_that_file_is_read() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let open = open_for(&site)?;
    edit(&site.settings_file, "fetch.yaml", "absent-fetch.yaml")?;
    let outcome = reload(&open.engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains(START_ONLY) && reason.contains("`service`") && reason.contains("fetch_settings")),
        "{outcome:?}"
    );
    Ok(())
}


#[test]
fn an_invalid_live_value_is_refused_and_the_old_settings_stay() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let open = open_for(&site)?;
    edit(&dir.path().join("fetch.yaml"), "timeout_ms: 5000", "timeout_ms: 1")?;
    assert!(matches!(reload(&open.engine), ReloadOutcome::Refused { .. }));
    edit(&dir.path().join("fetch.yaml"), "timeout_ms: 1", "timeout_ms: 5000")?;
    edit(&site.settings_file, "interval_seconds: 60", "interval_seconds: 5")?;
    assert!(matches!(reload(&open.engine), ReloadOutcome::Refused { .. }));
    edit(&site.settings_file, "interval_seconds: 5", "interval_seconds: 60\nmax_assets: 0")?;
    assert!(matches!(reload(&open.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&open.engine).service.interval_seconds, OLD_INTERVAL);
    Ok(())
}


#[test]
fn the_state_names_every_setting_and_the_loader_and_context_are_built_from_the_files() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let live = load_live(&site.settings_file)?;
    let state = live_state(&live);
    [
        "fetch::tenant",
        "fetch::cluster",
        "fetch::api_url",
        "fetch::ca_file",
        "fetch::token_file",
        "fetch::timeout_ms",
        "service::interval_seconds",
        "service::audit_file",
    ]
    .iter()
    .for_each(|key| assert!(state.contains_key(*key), "{key}"));
    assert!(!state.values().any(|value| value.contains("0a1b2c3d")));
    let loader = live_loader(site.settings_file.clone(), live.clone());
    assert_eq!(loader()?, live);
    let context = reload_context(&site.settings_file);
    assert_eq!((context.tenant.as_str(), context.module.as_str()), ("all", "virt-inventory"));
    Ok(())
}


#[tokio::test]
async fn a_round_uses_the_engine_snapshot_and_a_file_edited_without_a_reload_changes_nothing() -> TestResult {
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(applying()).await?;
    let site = write_site(dir.path(), fake.port, &pg_ca, 1, "", &format!("max_assets: {SMALL_ASSETS}\n"))?;
    let open = open_for(&site)?;
    let fetch_file = dir.path().join("fetch.yaml");
    edit(&site.settings_file, "interval_seconds: 60", "interval_seconds: 120")?;
    edit(&fetch_file, "timeout_ms: 5000", "timeout_ms: 7000")?;
    assert!(matches!(reload(&open.engine), ReloadOutcome::Applied { .. }));
    edit(&fetch_file, "timeout_ms: 7000", "timeout_ms: 9000")?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let mut never: InterruptWait = Box::pin(pending());
    let done = timeout(
        HANG_GUARD,
        serve(&open.engine, &open.audit, &pg, live_round, only_the_new_interval, TWO_ROUNDS, &mut never),
    )
    .await??;
    assert_eq!(done, TWO_ROUNDS);
    let lines = records_in(&site.audit_file)?;
    let rounds: Vec<&String> = lines.iter().filter(|line| line.contains("virt.round")).collect();
    assert_eq!(rounds.len(), TWO_ROUNDS);
    assert!(rounds.iter().all(|line| line.contains("\"outcome\":\"success\"")), "{rounds:?}");
    Ok(())
}


#[tokio::test]
async fn a_failed_round_is_audited_and_the_interval_still_runs_between_rounds() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let open = open_for(&site)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let mut never: InterruptWait = Box::pin(pending());
    let done = serve(&open.engine, &open.audit, &pg, failing_round, at_once, THREE_ROUNDS, &mut never).await?;
    assert_eq!(done, THREE_ROUNDS);
    assert_eq!(records_in(&site.audit_file)?.len(), THREE_ROUNDS);
    Ok(())
}


#[tokio::test]
async fn an_interrupt_already_there_skips_the_round_and_one_arriving_in_the_wait_ends_the_service() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let open = open_for(&site)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let mut already: InterruptWait = Box::pin(ready(Ok(())));
    let mut here: InterruptWait = Box::pin(ready(Ok(())));
    assert!(stop_pending(&mut here).await?);
    let skipped = serve(&open.engine, &open.audit, &pg, good_round, at_once, THREE_ROUNDS, &mut already).await?;
    assert_eq!(skipped, 0);
    let mut waiting: InterruptWait = Box::pin(async {
        tokio::task::yield_now().await;
        Ok(())
    });
    let done = serve(&open.engine, &open.audit, &pg, good_round, pause, THREE_ROUNDS, &mut waiting).await?;
    assert_eq!(done, 1);
    assert_eq!(records_in(&site.audit_file)?.len(), 1);
    let mut silent: InterruptWait = Box::pin(pending());
    assert!(!stop_pending(&mut silent).await?);
    Ok(())
}


#[tokio::test]
async fn a_failing_interrupt_wait_ends_the_service_with_its_error() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let open = open_for(&site)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let mut broken: InterruptWait = Box::pin(ready(Err(io::Error::other("no signal"))));
    let error = serve(&open.engine, &open.audit, &pg, good_round, at_once, THREE_ROUNDS, &mut broken)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    let mut breaks_in_the_wait: InterruptWait = Box::pin(async {
        tokio::task::yield_now().await;
        Err(io::Error::other("lost signal"))
    });
    let late = serve(&open.engine, &open.audit, &pg, good_round, pause, THREE_ROUNDS, &mut breaks_in_the_wait)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(late.to_string().contains("lost signal"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_runs_the_rounds_of_the_cap_and_pause_waits() -> TestResult {
    pause(Duration::ZERO).await;
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(applying()).await?;
    let site = write_site(dir.path(), fake.port, &pg_ca, 1, "", "")?;
    start(&site.settings_file, good_round, at_once, TWO_ROUNDS, never_stops).await?;
    assert_eq!(records_in(&site.audit_file)?.len(), TWO_ROUNDS);
    start(&site.settings_file, good_round, at_once, 1, stops_now).await?;
    let error = start(&site.settings_file, good_round, at_once, 1, cannot_arm)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_stop_during_the_start_skips_the_first_round() -> TestResult {
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(Arc::new(|_| Reply::Done)).await?;
    let site = write_site(dir.path(), fake.port, &pg_ca, 1, "", "")?;
    start(&site.settings_file, good_round, at_once, THREE_ROUNDS, stops_now).await?;
    assert!(!site.audit_file.exists() || records_in(&site.audit_file)?.is_empty());
    Ok(())
}


#[tokio::test]
async fn run_refuses_a_wrong_argument_count_before_anything_else() -> TestResult {
    let error = run(&[], never_stops).await.err().ok_or("expected the usage")?;
    assert!(error.to_string().contains("usage: ostyr-virt-inventory"));
    Ok(())
}


#[test]
fn the_drain_waits_for_a_reload_that_holds_the_gate() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let open = open_for(&site)?;
    let finished = Arc::new(AtomicBool::new(false));
    let guard = open.engine.gate.lock().map_err(|_| "poisoned")?;
    let waiter = {
        let engine = Arc::clone(&open.engine);
        let flag = Arc::clone(&finished);
        spawn(move || {
            drain(&engine);
            flag.store(true, Ordering::SeqCst);
        })
    };
    (0..YIELDS).for_each(|_| yield_now());
    assert!(!finished.load(Ordering::SeqCst), "the drain returned while a reload held the gate");
    drop(guard);
    waiter.join().map_err(|_| "waiter panicked")?;
    assert!(finished.load(Ordering::SeqCst));
    let held = Drain(Arc::clone(&open.engine));
    drop(held);
    Ok(())
}


#[test]
fn a_reload_that_panics_is_named_and_the_poisoned_gate_still_drains() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let live = load_live(&site.settings_file)?;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (entered, reached) = channel();
    let counter = Arc::clone(&calls);
    let loader_live = live.clone();
    let engine = Arc::new(open_engine(
        Box::new(move || {
            let before = counter.fetch_add(1, Ordering::SeqCst);
            entered
                .send(())
                .map_err(|_| virt_inventory::service::refuse("service", "no listener".to_owned()))?;
            assert!(before == 0, "the injected reload fails");
            Ok(loader_live.clone())
        }),
        live_state,
        Vec::new(),
        Box::new(|_entry| Err(core_audit::error::AuditError::LogPoisoned)),
        reload_context(&site.settings_file),
    )?);
    reached.recv_timeout(HANG_GUARD)?;
    let hangup = arm_hangup()?;
    let thread = follow_hangup(hangup, Arc::clone(&engine));
    signal_hook::low_level::raise(signal_hook::consts::SIGHUP)?;
    reached.recv_timeout(HANG_GUARD)?;
    drop(thread);
    drain(&engine);
    assert_eq!(calls.load(Ordering::SeqCst), TWO_ROUNDS);
    Ok(())
}


#[test]
fn sighup_reloads_on_the_signal_thread_and_the_audit_is_written_before_the_guard_returns() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let live = load_live(&site.settings_file)?;
    let (audited, seen) = channel();
    let engine = Arc::new(open_engine(
        live_loader(site.settings_file.clone(), live),
        live_state,
        Vec::new(),
        Box::new(move |entry| {
            audited.send(entry.outcome).map_err(|_| core_audit::error::AuditError::LogPoisoned)?;
            Err(core_audit::error::AuditError::LogPoisoned)
        }),
        reload_context(&site.settings_file),
    )?);
    let hangup = arm_hangup()?;
    let thread = follow_hangup(hangup, Arc::clone(&engine));
    edit(&site.settings_file, "interval_seconds: 60", "interval_seconds: 120")?;
    signal_hook::low_level::raise(signal_hook::consts::SIGHUP)?;
    let outcome = seen.recv_timeout(HANG_GUARD)?;
    assert!(matches!(outcome, core_audit::model::Outcome::Success));
    drop(thread);
    Ok(())
}
