#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/stand_in.rs"]
mod stand_in;
#[path = "common/types.rs"]
mod types;


use cmdb::model::{DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS};
use core_audit::log::open_file_log;
use core_pg::settings::load_settings as load_pg_settings;
use pg_fake::fake::Reply;
use site::{applying, pg_with, write_site, Site, ADMIN, AUDITOR, RESOURCES};
use stand_in::{reply, spawn_stand_in};
use std::error::Error;
use std::fs;
use std::future::{pending, ready};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;
use virt_inventory::cmdb_sync::SyncReport;
use virt_inventory::error::{FetchError, RoundError, ServiceError};
use virt_inventory::model::Context;
use virt_inventory::serve::{exit_code, log_round, pause, run, serve, start};
use virt_inventory::service::{
    limits_of, load_service_settings, production_round, round_entry, round_parameters, run_round, validate_service, ServiceSettings,
};
use virt_inventory::settings::load_settings;
use virt_inventory::types::{InterruptWait, RoundFuture, WaitFuture};


const THREE_ROUNDS: usize = 3;


const OK: u16 = 200;


const MIN_INTERVAL: u64 = 60;


const MAX_INTERVAL: u64 = 86_400;


const TWO_ROUNDS: usize = 2;


const SMALL_ASSETS: usize = 5;


const SMALL_ROWS: usize = 7;


fn settings_of(interval_seconds: u64, max_assets: usize, max_child_rows: usize) -> ServiceSettings {
    ServiceSettings {
        fetch_settings: "f".into(),
        pg_settings: "p".into(),
        audit_file: "a".into(),
        interval_seconds,
        max_assets,
        max_child_rows,
    }
}


fn context_of(site: &Site, dir: &Path) -> Result<Context, Box<dyn Error>> {
    let settings = load_service_settings(&site.settings_file)?;
    Ok(Context {
        fetch: load_settings(&settings.fetch_settings)?,
        pg: load_pg_settings(&settings.pg_settings)?,
        limits: limits_of(&settings)?,
        audit: open_file_log(&dir.join("context-audit.log"))?,
    })
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
        Ok(SyncReport::default())
    })
}


fn at_once(_duration: Duration) -> WaitFuture {
    Box::pin(ready(()))
}


fn records_in(path: &Path) -> Result<usize, Box<dyn Error>> {
    Ok(fs::read_to_string(path)?.lines().count())
}


#[test]
fn the_service_settings_bounds_are_checked() -> TestResult {
    validate_service(&settings_of(MIN_INTERVAL, 1, 1))?;
    validate_service(&settings_of(MAX_INTERVAL, DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS))?;
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL - 1, 1, 1)),
        Err(ServiceError::Interval { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MAX_INTERVAL + 1, 1, 1)),
        Err(ServiceError::Interval { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, 0, 1)),
        Err(ServiceError::MaxAssets { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, DEFAULT_MAX_ASSETS + 1, 1)),
        Err(ServiceError::MaxAssets { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, 1, 0)),
        Err(ServiceError::MaxChildRows { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, 1, DEFAULT_MAX_CHILD_ROWS + 1)),
        Err(ServiceError::MaxChildRows { .. })
    ));
    Ok(())
}


#[test]
fn the_lab_caps_are_settings_with_the_store_defaults_otherwise() -> TestResult {
    let dir = tempdir()?;
    let plain = write_site(dir.path(), 1, "", 1, "", "")?;
    let defaults = load_service_settings(&plain.settings_file)?;
    assert_eq!(
        (defaults.max_assets, defaults.max_child_rows),
        (DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS)
    );
    let capped = write_site(
        dir.path(),
        1,
        "",
        1,
        "",
        &format!("max_assets: {SMALL_ASSETS}\nmax_child_rows: {SMALL_ROWS}\n"),
    )?;
    let settings = load_service_settings(&capped.settings_file)?;
    let limits = limits_of(&settings)?;
    assert_eq!((limits.max_assets, limits.max_child_rows), (SMALL_ASSETS, SMALL_ROWS));
    let unknown = write_site(dir.path(), 1, "", 1, "", "tenant: other\n")?;
    assert!(load_service_settings(&unknown.settings_file).is_err());
    Ok(())
}


#[test]
fn a_round_record_is_under_the_all_tenant_and_names_the_cluster() -> TestResult {
    let good = round_entry("pve-1", &Ok(SyncReport::default()));
    assert_eq!(
        (good.tenant.as_str(), good.target.as_str(), good.module.as_str()),
        ("all", "pve-1", "virt-inventory")
    );
    assert!(matches!(good.outcome, core_audit::model::Outcome::Success));
    assert_eq!(good.parameters.get("created").map(String::as_str), Some("0"));
    let bad = round_entry("pve-1", &Err(RoundError::Fetch(FetchError::Url)));
    assert!(matches!(bad.outcome, core_audit::model::Outcome::Failure));
    assert!(round_parameters(&Err(RoundError::Fetch(FetchError::Url))).contains_key("round_error"));
    Ok(())
}


#[test]
fn the_exit_code_follows_the_result() -> TestResult {
    assert_eq!(format!("{:?}", exit_code(&Ok(()))), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(format!("{:?}", exit_code(&Err("x".into()))), format!("{:?}", ExitCode::FAILURE));
    log_round(&Ok(SyncReport::default()));
    log_round(&Err(RoundError::Fetch(FetchError::Url)));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_fetches_then_syncs_and_a_write_capable_token_syncs_nothing() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES), reply(OK, ADMIN)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let context = context_of(&site, dir.path())?;
    let report = run_round(&context).await?;
    assert!(report.created > 0, "{report:?}");
    let refused = production_round(&context).await.err().ok_or("expected a refusal")?;
    assert!(matches!(refused, RoundError::Fetch(FetchError::WritableCredential(_))), "{refused}");
    let applied = std::iter::from_fn(|| fake.statements.try_recv().ok())
        .filter(|text| text.starts_with(cmdb::store::APPLY_SQL))
        .count();
    assert_eq!(applied, 1);
    let seen = stand_in.seen.join().map_err(|_| "stand-in panicked")??;
    assert_eq!(seen.len(), THREE_ROUNDS);
    assert!(seen.iter().all(|request| request.request_line.starts_with("GET /api2/json/")));
    assert!(seen.iter().all(|request| request.authorization.is_some()));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_or_failing_store_is_a_named_round_error() -> TestResult {
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(Arc::new(|_| Reply::Error("XX000"))).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let context = context_of(&site, dir.path())?;
    let failed = run_round(&context).await.err().ok_or("expected a store error")?;
    assert!(matches!(failed, RoundError::Sync(_)), "{failed}");
    let held = std::net::TcpListener::bind("127.0.0.1:0")?;
    let again = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES)])?;
    let second = tempdir()?;
    let closed = write_site(second.path(), held.local_addr()?.port(), &pg_ca, again.port, &again.ca_pem, "")?;
    let offline = context_of(&closed, second.path())?;
    let error = run_round(&offline).await.err().ok_or("expected a connection error")?;
    assert!(matches!(error, RoundError::Pg(_)), "{error}");
    Ok(())
}


#[tokio::test]
async fn a_failed_round_is_audited_and_the_interval_still_runs_between_rounds() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let context = context_of(&site, dir.path())?;
    let mut never: InterruptWait = Box::pin(pending());
    let done = serve(&context, failing_round, at_once, Duration::from_secs(1), THREE_ROUNDS, &mut never).await?;
    assert_eq!(done, THREE_ROUNDS);
    assert_eq!(records_in(&dir.path().join("context-audit.log"))?, THREE_ROUNDS);
    Ok(())
}


#[tokio::test]
async fn an_interrupt_during_a_round_lets_it_finish_and_audits_it_before_returning() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let context = context_of(&site, dir.path())?;
    let mut already: InterruptWait = Box::pin(ready(Ok(())));
    let done = serve(&context, good_round, at_once, Duration::from_secs(1), THREE_ROUNDS, &mut already).await?;
    assert_eq!(done, 1);
    assert_eq!(records_in(&dir.path().join("context-audit.log"))?, 1);
    Ok(())
}


#[tokio::test]
async fn a_failing_interrupt_wait_ends_the_service_with_its_error() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), 1, "", 1, "", "")?;
    let context = context_of(&site, dir.path())?;
    let mut broken: InterruptWait = Box::pin(ready(Err(std::io::Error::other("no signal"))));
    let error = serve(&context, good_round, at_once, Duration::from_secs(1), THREE_ROUNDS, &mut broken)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    assert_eq!(records_in(&dir.path().join("context-audit.log"))?, 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_runs_the_rounds_of_the_cap_and_pause_waits() -> TestResult {
    pause(Duration::ZERO).await;
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(applying()).await?;
    let site = write_site(dir.path(), fake.port, &pg_ca, 1, "", "")?;
    start(&site.settings_file, good_round, at_once, TWO_ROUNDS, Box::pin(pending())).await?;
    assert_eq!(records_in(&site.audit_file)?, TWO_ROUNDS);
    let none = start(&site.settings_file, good_round, at_once, 1, Box::pin(ready(Ok(())))).await;
    assert!(none.is_ok());
    Ok(())
}


#[tokio::test]
async fn run_refuses_a_wrong_argument_count_before_anything_else() -> TestResult {
    let error = run(&[], Box::pin(pending())).await.err().ok_or("expected the usage")?;
    assert!(error.to_string().contains("usage: ostyr-virt-inventory"));
    Ok(())
}
