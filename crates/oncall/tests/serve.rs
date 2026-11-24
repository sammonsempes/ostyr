#![cfg(unix)]


#[path = "common/private.rs"]
mod private;
#[path = "common/types.rs"]
mod types;


use alerts::id::alert_id;
use core_audit::error::AuditError;
use core_audit::log::open_file_log;
use core_config::reload::{current_config, reload, ReloadOutcome};
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use oncall::alert_source::{Round, TenantCounts};
use oncall::error::{SourceError, StoreError};
use oncall::serve::ServiceSettings;
use oncall::serve::{
    audit_purge, boxed_reload_audit, finish_code, interrupt_wait, is_deadline, load_service, note_deadline, open_service_settings, open_session,
    pause, poll_round, purge_entry, purge_rows, refresh, report, round_summary, service_state, start, start_only_changed, start_with, store_deadline,
    validate_service, wait_for_signals, watched_rows, Finish, PurgeDeadlines, FAILURE_EXIT_CODE, ROUND_CAP_EXIT_CODE,
};
use oncall::types::{InterruptWait, PurgedCounts};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use private::write_private;
use rcgen::SanType;
use std::cell::Cell;
use std::fs;
use std::future::{pending, ready};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const TIMESTAMPTZ_OID: i32 = 1184;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-oncall");


const CLOSED_PORT: u16 = 1;


const PG_PASSWORD: &str = "p";


const ONE_ROUND: usize = 1;


const MAX_YIELDS: usize = 10_000;


const MAX_STATEMENTS: usize = 1_000;


const GENEROUS: Duration = Duration::from_secs(30);


const HUNG_ROLLBACK: Duration = Duration::from_millis(50);


const THREE: usize = 3;


const BETA_ROWS: usize = 3;


const GAMMA_ROWS: usize = 4;


const SLOWER: u64 = 2;


const THIRD_INTERVAL: u64 = 3;


const MANY_TENANTS: usize = 1_000;


const TWO_OPENED: usize = 2;


const SERVING_MARKER: &str = "serving";


const ROUND_MARKER: &str = "round: ";


const SEVERITIES: &str = "    informational: info\n    low: info\n    medium: ticket\n    high: page\n    critical: page-now\n";


fn source_text(interval: u64) -> String {
    format!("source:\n  tenants: [acme]\n  max_per_poll: 5\n  interval_seconds: {interval}\n  severity_map:\n{SEVERITIES}")
}


fn settings_text(dir: &Path, label: &str, interval: u64) -> String {
    format!(
        "pg_settings: {}\nlabel: {label}\naudit_file: {}\n{}",
        dir.join("pg.yaml").display(),
        dir.join("audit.log").display(),
        source_text(interval)
    )
}


fn write_site(dir: &Path, port: u16, ca_pem: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    write_private(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    let settings_file = dir.join("oncall.yaml");
    fs::write(&settings_file, settings_text(dir, "poller-a", 1))?;
    Ok(settings_file)
}


async fn fake_with(handler: Handler) -> Result<(Fake, String), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


fn accepting() -> Handler {
    Arc::new(|_| Reply::Done)
}


fn source_row() -> Vec<String> {
    let event_ids = vec!["e1".to_owned()];
    vec![
        alert_id("acme", "rule", &event_ids),
        "rule".to_owned(),
        "<!channel> disk".to_owned(),
        "high".to_owned(),
        "2026-11-10T10:00:00Z".to_owned(),
        "1".to_owned(),
        "host-1".to_owned(),
        String::new(),
        "[\"e1\"]".to_owned(),
        "{}".to_owned(),
        "false".to_owned(),
        "2".to_owned(),
    ]
}


fn serving(lease: bool) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("WITH RECURSIVE held") {
            Reply::Rows(vec![vec!["beta".to_owned(), "3".to_owned()]])
        } else if sql.starts_with("WITH already") {
            Reply::Typed {
                parameters: vec![TEXT_OID, TEXT_OID, TIMESTAMPTZ_OID, TEXT_OID, TEXT_OID, TEXT_OID, TEXT_OID, TEXT_OID],
                columns: vec![INT8_OID, INT8_OID],
                rows: vec![vec![int8_cell(1), int8_cell(0)]],
            }
        } else if sql.starts_with("INSERT INTO oncall_poller_lease") {
            Reply::Typed {
                parameters: vec![TEXT_OID, TEXT_OID, INT8_OID],
                columns: vec![TEXT_OID],
                rows: if lease { vec![vec![Some(b"x".to_vec())]] } else { Vec::new() },
            }
        } else if sql.starts_with("SELECT a.id") {
            Reply::Rows(vec![source_row()])
        } else {
            Reply::Done
        }
    })
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert_eq!(output.status.code(), Some(i32::from(FAILURE_EXIT_CODE)), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


fn wait_for(reader: &mut BufReader<ChildStderr>, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(reader
        .by_ref()
        .lines()
        .find_map(|line| line.map(|text| text.contains(marker).then_some(text)).transpose())
        .ok_or("the child ended before the marker")??)
}


fn signal(child: &Child, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn spawn_service(settings_file: &Path) -> Result<Child, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM)
        .arg(settings_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?)
}


fn finish(mut child: Child, mut reader: BufReader<ChildStderr>) -> Result<String, Box<dyn std::error::Error>> {
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    let exit = child.wait()?;
    assert_eq!(exit.code(), Some(0), "{rest}");
    Ok(rest)
}


fn never() -> InterruptWait {
    Box::pin(pending())
}


fn counts() -> PurgedCounts {
    [("beta".to_owned(), BETA_ROWS), ("gamma".to_owned(), GAMMA_ROWS)].into_iter().collect()
}


async fn connected(handler: Handler) -> Result<(Fake, PgSettings, tokio_postgres::Client, tempfile::TempDir), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(handler).await?;
    write_site(dir.path(), fake.port, &ca_pem)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let client = connect(&pg).await?;
    Ok((fake, pg, client, dir))
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-oncall <settings.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-oncall")
}


#[test]
fn an_unreadable_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")
}


#[test]
fn an_invalid_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings_file = dir.path().join("oncall.yaml");
    fs::write(&settings_file, "label: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "oncall.yaml")
}


#[test]
fn a_settings_file_without_an_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = dir.path().join("oncall.yaml");
    fs::write(
        &settings_file,
        format!("pg_settings: {}\nlabel: a\n{}", dir.path().join("pg.yaml").display(), source_text(1)),
    )?;
    refused_with(&run_to_end(&[&settings_file])?, "audit_file")
}


#[test]
fn an_unwritable_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let missing = dir.path().join("absent").join("audit.log");
    let text = fs::read_to_string(&settings_file)?.replace(&dir.path().join("audit.log").display().to_string(), &missing.display().to_string());
    fs::write(&settings_file, text)?;
    let output = run_to_end(&[&settings_file])?;
    assert_eq!(output.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    assert!(!output.stderr.is_empty());
    assert!(!missing.exists());
    Ok(())
}


#[test]
fn a_missing_pg_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    fs::remove_file(dir.path().join("pg.yaml"))?;
    refused_with(&run_to_end(&[&settings_file])?, "pg.yaml")
}


#[test]
fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let output = run_to_end(&[&settings_file])?;
    assert_eq!(output.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    assert!(!output.stderr.is_empty());
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
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&settings_file]))?;
    assert_eq!(output.status.code(), Some(i32::from(FAILURE_EXIT_CODE)));
    assert!(!output.stderr.is_empty());
    Ok(())
}


async fn serve_one_round_then(name: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(serving(true)).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let mut child = spawn_service(&settings_file)?;
    let mut reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    tokio::task::block_in_place(|| wait_for(&mut reader, SERVING_MARKER))?;
    let round = tokio::task::block_in_place(|| wait_for(&mut reader, ROUND_MARKER))?;
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    signal(&child, name)?;
    let rest = tokio::task::block_in_place(|| finish(child, reader))?;
    Ok((audit, format!("{round}\n{rest}")))
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_audits_the_purge_into_its_file_and_exits_zero_on_sigint() -> TestResult {
    let (audit, rest) = serve_one_round_then("-INT").await?;
    assert!(audit.contains("oncall.outbox.purge"), "{audit} / {rest}");
    assert!(audit.contains("beta=3"), "{audit}");
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{audit}");
    assert!(!audit.contains("acme"), "{audit}");
    assert_eq!(audit.lines().count(), ONE_ROUND);
    assert!(rest.contains("leased=true"), "{rest}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_exits_zero_on_sigterm() -> TestResult {
    let (audit, rest) = serve_one_round_then("-TERM").await?;
    assert!(audit.contains("oncall.outbox.purge"), "{audit} / {rest}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_poller_that_does_not_hold_the_lease_purges_nothing_and_says_so() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, ca_pem) = fake_with(serving(false)).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let mut child = spawn_service(&settings_file)?;
    let mut reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    let warned = tokio::task::block_in_place(|| wait_for(&mut reader, "another on-call poller holds the lease"))?;
    let round = tokio::task::block_in_place(|| wait_for(&mut reader, ROUND_MARKER))?;
    signal(&child, "-INT")?;
    let rest = format!("{warned}\n{round}\n{}", tokio::task::block_in_place(|| finish(child, reader))?);
    let statements: Vec<String> = std::iter::from_fn(|| fake.statements.try_recv().ok()).take(MAX_STATEMENTS).collect();
    assert!(rest.contains("another on-call poller holds the lease"), "{rest}");
    assert!(rest.contains("leased=false"), "{rest}");
    assert!(!statements.iter().any(|sql| sql.contains("WITH RECURSIVE held")));
    assert_eq!(fs::read_to_string(dir.path().join("audit.log"))?.lines().count(), 0);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_the_round_cap_after_its_rounds_when_nothing_interrupts() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(serving(true)).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    assert_eq!(start(&settings_file, ONE_ROUND, never()).await?, Finish::RoundCap);
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(audit.contains("oncall.outbox.purge"), "{audit}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_interrupted_when_the_interrupt_arrives() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    assert_eq!(start(&settings_file, usize::MAX, Box::pin(ready(Ok(())))).await?, Finish::Interrupted);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_interrupt_wait_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let failing: InterruptWait = Box::pin(ready(Err(io::Error::other("no signal"))));
    let error = start(&settings_file, usize::MAX, failing).await.err().ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_holder_label_that_is_not_a_token_is_refused_at_load() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::write(&settings_file, settings_text(dir.path(), "bad label", 1))?;
    let error = start(&settings_file, ONE_ROUND, never()).await.err().ok_or("expected an error")?;
    assert!(error.to_string().contains("label"), "{error}");
    Ok(())
}


#[test]
fn the_settings_are_validated_after_parsing() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let settings = load_service(&settings_file)?;
    validate_service(&settings, chrono::Utc::now())?;
    let mut relative_audit = settings.clone();
    relative_audit.audit_file = PathBuf::from("audit.log");
    assert!(validate_service(&relative_audit, chrono::Utc::now()).is_err());
    let mut relative_pg = settings.clone();
    relative_pg.pg_settings = PathBuf::from("pg.yaml");
    assert!(validate_service(&relative_pg, chrono::Utc::now()).is_err());
    let mut bad_label = settings.clone();
    bad_label.label = "a b".to_owned();
    assert!(validate_service(&bad_label, chrono::Utc::now()).is_err());
    let mut no_tenant = settings;
    no_tenant.source.tenants.clear();
    assert!(validate_service(&no_tenant, chrono::Utc::now()).is_err());
    Ok(())
}


fn read_then_swap_the_audit_path(file: &Path) -> Result<ServiceSettings, core_config::error::ConfigError> {
    let first = load_service(file)?;
    let swapped = fs::read_to_string(file)
        .map_err(|failure| oncall::serve::setting_error("swap", &failure.to_string()))?
        .replace("audit.log", "elsewhere.log");
    fs::write(file, swapped).map_err(|failure| oncall::serve::setting_error("swap", &failure.to_string()))?;
    Ok(first)
}


#[tokio::test(flavor = "multi_thread")]
async fn the_audit_path_comes_from_the_first_start_read_and_a_swap_refuses_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let refusal = start_with(read_then_swap_the_audit_path, &settings_file, ONE_ROUND, never())
        .await
        .err()
        .ok_or("the swap was accepted")?;
    assert!(refusal.to_string().contains("start-only"), "{refusal}");
    assert!(dir.path().join("audit.log").exists());
    assert!(!dir.path().join("elsewhere.log").exists());
    Ok(())
}


#[test]
fn only_the_source_is_live() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let baseline = load_service(&settings_file)?;
    let mut faster = baseline.clone();
    faster.source.interval_seconds = SLOWER;
    assert!(!start_only_changed(&baseline, &faster));
    let mut relabelled = baseline.clone();
    relabelled.label = "poller-b".to_owned();
    assert!(start_only_changed(&baseline, &relabelled));
    let mut moved = baseline.clone();
    moved.audit_file = PathBuf::from("/elsewhere/audit.log");
    assert!(start_only_changed(&baseline, &moved));
    let state = service_state(&baseline);
    assert_eq!(state.get("label").map(String::as_str), Some("poller-a"));
    assert!(state.contains_key("severity_map"));
    Ok(())
}


#[test]
fn a_reload_applies_a_source_change_and_keeps_the_old_settings_on_a_bad_file() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let engine = open_service_settings(&settings_file, load_service(&settings_file)?, boxed_reload_audit(&log))?;
    assert_eq!(current_config(&engine).source.interval_seconds, 1);
    fs::write(&settings_file, settings_text(dir.path(), "poller-a", SLOWER))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).source.interval_seconds, SLOWER);
    fs::write(&settings_file, settings_text(dir.path(), "poller-b", THIRD_INTERVAL))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&settings_file, "source: [\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).source.interval_seconds, SLOWER);
    assert_eq!(current_config(&engine).label, "poller-a");
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert_eq!(audit.lines().count(), THREE);
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{audit}");
    Ok(())
}


#[test]
fn a_file_swapped_between_the_start_reads_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let first = load_service(&settings_file)?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    fs::write(
        &settings_file,
        settings_text(dir.path(), "poller-b", 1).replace("audit.log", "elsewhere.log"),
    )?;
    let refusal = open_service_settings(&settings_file, first, boxed_reload_audit(&log))
        .err()
        .ok_or("the swap was accepted")?;
    assert!(refusal.to_string().contains("start-only"), "{refusal}");
    Ok(())
}


#[test]
fn only_a_deadline_marks_the_session_as_stuck() -> TestResult {
    assert!(is_deadline(&PgError::ClientDeadline { seconds: 1 }));
    assert!(is_deadline(&PgError::StatementTimeout { seconds: 1 }));
    assert!(!is_deadline(&PgError::DeadlineOverflow));
    assert!(store_deadline(&StoreError::Pg(PgError::ClientDeadline { seconds: 1 })));
    assert!(!store_deadline(&StoreError::Pg(PgError::DeadlineOverflow)));
    assert!(!store_deadline(&StoreError::NotFound));
    let stuck = AtomicBool::new(false);
    note_deadline(&stuck, false);
    assert!(!stuck.load(Ordering::Relaxed));
    note_deadline(&stuck, true);
    assert!(stuck.load(Ordering::Relaxed));
    Ok(())
}


#[tokio::test]
async fn a_row_future_is_passed_through_and_a_deadline_is_noted() -> TestResult {
    let stuck = AtomicBool::new(false);
    let rows = watched_rows(Box::pin(ready(Ok(vec![vec!["x".to_owned()]]))), &stuck).await?;
    assert_eq!(rows.len(), 1);
    assert!(!stuck.load(Ordering::Relaxed));
    assert!(watched_rows(Box::pin(ready(Err(PgError::ClientDeadline { seconds: 1 }))), &stuck)
        .await
        .is_err());
    assert!(stuck.load(Ordering::Relaxed));
    Ok(())
}


#[test]
fn the_purge_entry_names_the_tenants_the_rows_and_a_bounded_detail() -> TestResult {
    let entry = purge_entry(&counts());
    assert_eq!(entry.action, "oncall.outbox.purge");
    assert_eq!(entry.tenant, "all");
    assert_eq!(entry.parameters.get("rows").map(String::as_str), Some("7"));
    assert_eq!(entry.parameters.get("tenants").map(String::as_str), Some("2"));
    assert_eq!(entry.parameters.get("detail").map(String::as_str), Some("beta=3,gamma=4"));
    let many: PurgedCounts = (0..MANY_TENANTS).map(|index| (format!("tenant-{index}"), 1)).collect();
    let detail = purge_entry(&many).parameters.get("detail").cloned().ok_or("no detail")?;
    assert!(detail.contains("truncated"), "{detail}");
    Ok(())
}


#[test]
fn a_failing_purge_audit_is_attempted_once_and_does_not_panic() -> TestResult {
    let calls = Cell::new(0);
    audit_purge(
        &|_entry| {
            calls.set(calls.get() + 1);
            Err(AuditError::Usage)
        },
        &counts(),
    );
    assert_eq!(calls.get(), 1);
    Ok(())
}


#[test]
fn the_exit_code_follows_the_finish() -> TestResult {
    let mut out = Vec::new();
    assert_eq!(finish_code(Ok(Finish::Interrupted), &mut out)?, 0);
    assert_eq!(finish_code(Ok(Finish::RoundCap), &mut out)?, ROUND_CAP_EXIT_CODE);
    assert!(out.is_empty());
    assert_eq!(finish_code(Err("broken".into()), &mut out)?, FAILURE_EXIT_CODE);
    assert_eq!(String::from_utf8(out)?, "broken\n");
    assert_ne!(ROUND_CAP_EXIT_CODE, 0);
    assert_ne!(ROUND_CAP_EXIT_CODE, FAILURE_EXIT_CODE);
    Ok(())
}


#[test]
fn the_round_summary_names_every_outcome() -> TestResult {
    let failed = Round {
        leased: Err(SourceError::NoTenants),
        purged: Err(SourceError::PurgeDeadline),
        outcomes: vec![("acme".to_owned(), Err(SourceError::NoTenants))],
    };
    let text = round_summary(&failed);
    assert!(text.contains("no source tenant is configured"), "{text}");
    assert!(text.contains("the purge ran past its deadline"), "{text}");
    let fine = Round {
        leased: Ok(true),
        purged: Ok(counts()),
        outcomes: vec![(
            "acme".to_owned(),
            Ok(TenantCounts {
                opened: TWO_OPENED,
                ..TenantCounts::default()
            }),
        )],
    };
    let line = round_summary(&fine);
    assert!(line.contains("leased=true") && line.contains("acme=opened:2"), "{line}");
    report(&fine);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_pause_waits_for_the_duration() -> TestResult {
    pause(Duration::from_secs(SLOWER)).await;
    Ok(())
}


#[tokio::test]
async fn both_signals_resolve_the_interrupt_wait() -> TestResult {
    let first = interrupt_wait();
    signal_self("-INT")?;
    first.await?;
    let second = interrupt_wait();
    signal_self("-TERM")?;
    second.await?;
    Ok(())
}


#[tokio::test]
async fn a_failed_signal_registration_is_the_error_of_the_wait() -> TestResult {
    let error = wait_for_signals(Err(io::Error::other("no handler")))
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no handler"));
    Ok(())
}


fn signal_self(name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(std::process::id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn scope() -> Result<core_pg::scope::TenantScope, Box<dyn std::error::Error>> {
    Ok(tenant_scope("acme")?)
}


fn purge_params() -> Vec<String> {
    vec!["[\"acme\"]".to_owned(), "500".to_owned(), "poller-a".to_owned(), "2000".to_owned()]
}


fn purging(reply: Reply, rollback: Reply) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("WITH RECURSIVE held") {
            reply.clone()
        } else if sql == "ROLLBACK" {
            rollback.clone()
        } else {
            Reply::Done
        }
    })
}


fn deadlines(purge: Duration, rollback: Duration) -> PurgeDeadlines {
    PurgeDeadlines { purge, rollback }
}


#[tokio::test(flavor = "multi_thread")]
async fn a_purge_runs_in_one_transaction_and_commits() -> TestResult {
    let rows = vec![vec!["beta".to_owned(), "3".to_owned()]];
    let (mut fake, _pg, client, _dir) = connected(purging(Reply::Rows(rows.clone()), Reply::Done)).await?;
    let answer = purge_rows(&client, deadlines(GENEROUS, GENEROUS), scope()?, purge_params()).await?;
    assert_eq!(answer, rows);
    let statements: Vec<String> = std::iter::from_fn(|| fake.statements.try_recv().ok()).take(MAX_STATEMENTS).collect();
    let begin = statements
        .iter()
        .position(|sql| sql.starts_with("BEGIN; SET LOCAL statement_timeout"))
        .ok_or("no BEGIN")?;
    let purge = statements.iter().position(|sql| sql.contains("WITH RECURSIVE held")).ok_or("no purge")?;
    let commit = statements.iter().position(|sql| sql == "COMMIT").ok_or("no COMMIT")?;
    assert!(begin < purge && purge < commit);
    assert!(statements
        .get(begin)
        .ok_or("no begin text")?
        .contains("idle_in_transaction_session_timeout"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_purge_rolls_back() -> TestResult {
    let (mut fake, _pg, client, _dir) = connected(purging(Reply::Error("57014"), Reply::Done)).await?;
    assert!(purge_rows(&client, deadlines(GENEROUS, GENEROUS), scope()?, purge_params())
        .await
        .is_err());
    let statements: Vec<String> = std::iter::from_fn(|| fake.statements.try_recv().ok()).take(MAX_STATEMENTS).collect();
    assert!(statements.iter().any(|sql| sql == "ROLLBACK"));
    assert!(!statements.iter().any(|sql| sql == "COMMIT"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_row_that_is_not_text_is_an_error() -> TestResult {
    let (_fake, _pg, client, _dir) = connected(purging(Reply::IntRows(vec![1]), Reply::Done)).await?;
    assert!(purge_rows(&client, deadlines(GENEROUS, GENEROUS), scope()?, purge_params())
        .await
        .is_err());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_purge_past_its_deadline_is_rolled_back_and_reported() -> TestResult {
    let (mut fake, _pg, client, _dir) = connected(purging(Reply::Done, Reply::Done)).await?;
    let error = purge_rows(&client, deadlines(Duration::ZERO, GENEROUS), scope()?, purge_params())
        .await
        .err()
        .ok_or("expected a timeout")?;
    assert!(error.to_string().contains("deadline") || error.to_string().contains("timeout"), "{error}");
    let statements: Vec<String> = std::iter::from_fn(|| fake.statements.try_recv().ok()).take(MAX_STATEMENTS).collect();
    assert!(statements.iter().any(|sql| sql == "ROLLBACK"), "{statements:?}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_that_fails_after_the_deadline_is_only_logged() -> TestResult {
    let (_fake, _pg, client, _dir) = connected(purging(Reply::Done, Reply::Error("XX000"))).await?;
    assert!(purge_rows(&client, deadlines(Duration::ZERO, GENEROUS), scope()?, purge_params())
        .await
        .is_err());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_that_hangs_after_the_deadline_is_abandoned() -> TestResult {
    let (_fake, _pg, client, _dir) = connected(purging(Reply::Done, Reply::Hang)).await?;
    assert!(purge_rows(&client, deadlines(Duration::ZERO, HUNG_ROLLBACK), scope()?, purge_params())
        .await
        .is_err());
    Ok(())
}


async fn wait_closed(client: &tokio_postgres::Client) -> TestResult {
    let mut yields = 0;
    while !client.is_closed() && yields < MAX_YIELDS {
        tokio::task::yield_now().await;
        yields += 1;
    }
    assert!(client.is_closed());
    Ok(())
}


fn dropping() -> Handler {
    Arc::new(|sql| if sql.contains("drop_me") { Reply::Drop } else { Reply::Done })
}


async fn session_of(pg: &PgSettings) -> Result<oncall::serve::Session, Box<dyn std::error::Error>> {
    Ok(open_session(pg).await?)
}


fn hung_purge() -> Handler {
    let inner = serving(true);
    Arc::new(move |sql| if sql.contains("WITH RECURSIVE held") { Reply::Hang } else { inner(sql) })
}


#[tokio::test(flavor = "multi_thread")]
async fn a_session_that_hit_a_deadline_is_replaced_after_the_round() -> TestResult {
    let (_fake, pg, client, dir) = connected(hung_purge()).await?;
    drop(client);
    let settings_file = dir.path().join("oncall.yaml");
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let engine = open_service_settings(&settings_file, load_service(&settings_file)?, boxed_reload_audit(&log))?;
    let mut session = session_of(&pg).await?;
    let before = session.driver.id();
    poll_round(
        &mut session,
        &pg,
        &engine,
        "holder-a",
        deadlines(Duration::ZERO, HUNG_ROLLBACK),
        &|_counts| (),
    )
    .await;
    assert_ne!(session.driver.id(), before, "the stuck session was kept");
    let answered = tokio::time::timeout(GENEROUS, session.client.simple_query("SELECT 1")).await;
    assert!(answered.is_ok_and(|result| result.is_ok()));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_without_a_deadline_keeps_its_session() -> TestResult {
    let (_fake, pg, client, dir) = connected(serving(true)).await?;
    drop(client);
    let settings_file = dir.path().join("oncall.yaml");
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let engine = open_service_settings(&settings_file, load_service(&settings_file)?, boxed_reload_audit(&log))?;
    let mut session = session_of(&pg).await?;
    let before = session.driver.id();
    poll_round(&mut session, &pg, &engine, "holder-a", deadlines(GENEROUS, GENEROUS), &|_counts| ()).await;
    assert_eq!(session.driver.id(), before);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_is_replaced_once_and_a_failed_replacement_is_retried_later() -> TestResult {
    let (_fake, pg, client, dir) = connected(dropping()).await?;
    drop(client);
    let mut session = session_of(&pg).await?;
    assert!(session.client.simple_query("SELECT drop_me").await.is_err());
    wait_closed(&session.client).await?;
    refresh(&mut session, &pg).await;
    assert!(!session.client.is_closed());
    refresh(&mut session, &pg).await;
    assert!(session.client.simple_query("SELECT 1").await.is_ok());
    assert!(session.client.simple_query("SELECT drop_me").await.is_err());
    wait_closed(&session.client).await?;
    fs::write(
        dir.path().join("pg-down.yaml"),
        fs::read_to_string(dir.path().join("pg.yaml"))?.replace(&format!("port: {}", pg.port), &format!("port: {CLOSED_PORT}")),
    )?;
    let down = load_pg_settings(&dir.path().join("pg-down.yaml"))?;
    refresh(&mut session, &down).await;
    assert!(session.client.is_closed());
    Ok(())
}
