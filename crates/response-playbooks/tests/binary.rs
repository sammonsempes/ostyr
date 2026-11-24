#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use alerts::id::alert_id;
use core_audit::log::open_file_log;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_pg::error::PgError;
use core_pg::settings::{load_settings as load_pg_settings, PgSettings};
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use response_playbooks::serve::{boxed_reload_audit, migrate_retrying, shared_reload_audit, start};
use response_playbooks::types::{InterruptWait, MigrationRun};
use std::collections::BTreeMap;
use std::fs;
use std::future::{pending, ready, Future};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-playbooks");


const OWNER_ONLY: u32 = 0o600;


const CLOSED_PORT: u16 = 1;


const PG_PASSWORD: &str = "p";


const SERVING_MARKER: &str = "serving";


const ONE_ROUND: usize = 1;


const TWO_RECORDS: usize = 2;


const FEED_TABLE: &str = "FROM playbook_outbox";


const MAX_STATEMENTS: usize = 1_000;


fn private_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)
}


fn write_site(dir: &Path, port: u16, ca_pem: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(dir.join("limits.yaml"), "limits: {}\n")?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    let settings_file = dir.join("playbooks.yaml");
    fs::write(
        &settings_file,
        format!(
            "tenant: acme\npg_settings: {}\ncatalogue: {}\ninventory: {}\nplaybooks: [{}]\nlimits_file: {}\nscratch_dir: {}\naudit_file: {}\n\
             poll_interval_seconds: 1\npage_size: 10\nmax_matches_per_alert: 3\nmax_trace_events: 100\n",
            dir.join("pg.yaml").display(),
            fixture("catalogue.yaml").display(),
            fixture("inventory.yaml").display(),
            fixture("store_alert.yaml").display(),
            dir.join("limits.yaml").display(),
            dir.display(),
            dir.join("audit.log").display(),
        ),
    )?;
    Ok(settings_file)
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> Result<(), Box<dyn std::error::Error>> {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


async fn fake_with(handler: Handler) -> Result<(Fake, String), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


fn accepting() -> Handler {
    Arc::new(|_| Reply::Done)
}


fn wait_for_serving(reader: &mut BufReader<ChildStderr>) -> Result<(), Box<dyn std::error::Error>> {
    reader
        .by_ref()
        .lines()
        .find_map(|line| line.map(|text| text.contains(SERVING_MARKER).then_some(())).transpose())
        .ok_or("the child ended before it served")??;
    Ok(())
}


fn interrupt(child: &Child) -> TestResult {
    let status = Command::new("kill").arg("-INT").arg(child.id().to_string()).status()?;
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


fn finish(mut child: Child, mut reader: BufReader<ChildStderr>) -> TestResult {
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    let exit = child.wait()?;
    assert!(exit.success(), "{rest}");
    Ok(())
}


fn never() -> InterruptWait {
    Box::pin(pending())
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-playbooks <settings.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-playbooks")
}


#[test]
fn an_unreadable_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    refused_with(&run_to_end(&[&missing])?, "absent.yaml")
}


#[test]
fn an_invalid_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings_file = dir.path().join("playbooks.yaml");
    fs::write(&settings_file, "tenant: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "playbooks.yaml")
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
    assert!(!output.status.success());
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
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_round_and_exits_cleanly_on_the_interrupt() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let mut child = spawn_service(&settings_file)?;
    let mut reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    tokio::task::block_in_place(|| wait_for_serving(&mut reader))?;
    let mut seen = false;
    let mut attempts = 0;
    while !seen && attempts < MAX_STATEMENTS {
        seen = fake.statements.recv().await.ok_or("the fake closed")?.contains(FEED_TABLE);
        attempts += 1;
    }
    assert!(seen);
    interrupt(&child)?;
    tokio::task::block_in_place(|| finish(child, reader))
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_after_its_rounds_when_nothing_interrupts() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, ONE_ROUND, never()).await?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_when_the_interrupt_arrives() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, usize::MAX, Box::pin(ready(Ok(())))).await?;
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


fn feed_row() -> Vec<String> {
    let event_ids = vec!["e1".to_owned()];
    vec![
        alert_id("acme", "rule", &event_ids),
        "rule".to_owned(),
        "Whoami executed".to_owned(),
        "high".to_owned(),
        "2026-11-10T10:00:00Z".to_owned(),
        "1".to_owned(),
        "host-1".to_owned(),
        String::new(),
        "[\"e1\"]".to_owned(),
        "{\"process\":{\"name\":\"whoami\"}}".to_owned(),
        "false".to_owned(),
        "29".to_owned(),
        "5".to_owned(),
        "1".to_owned(),
        "(0,5)".to_owned(),
    ]
}


fn serving_a_feed_row() -> Handler {
    Arc::new(|sql| {
        if sql.contains(FEED_TABLE) {
            Reply::Rows(vec![feed_row()])
        } else if sql.contains("DELETE FROM playbook_outbox") {
            Reply::Rows(vec![vec!["1".to_owned()]])
        } else {
            Reply::Done
        }
    })
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_with_a_stored_alert_appends_one_record_and_deletes_the_row() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(serving_a_feed_row()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, ONE_ROUND, never()).await?;
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(audit.contains("playbooks.dry_run"), "{audit}");
    assert_eq!(audit.lines().count(), ONE_ROUND);
    Ok(())
}


fn reload_entry() -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::UNIX_EPOCH,
        actor: Actor {
            kind: ActorKind::System,
            id: "playbooks".to_owned(),
        },
        tenant: "acme".to_owned(),
        module: "playbooks".to_owned(),
        action: "config.reload".to_owned(),
        target: "settings".to_owned(),
        outcome: Outcome::Success,
        request_id: "settings".to_owned(),
        justification: None,
        parameters: BTreeMap::new(),
    }
}


#[test]
fn both_reload_audit_functions_append_to_the_one_log() -> TestResult {
    let dir = tempdir()?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    shared_reload_audit(&log)(reload_entry())?;
    boxed_reload_audit(&log)(reload_entry())?;
    assert_eq!(fs::read_to_string(dir.path().join("audit.log"))?.lines().count(), TWO_RECORDS);
    Ok(())
}


const RETRY_ATTEMPTS: u64 = 10;


const PAUSE_SECONDS: u64 = 2;


const PASSES_ON_THIRD_RUN: u64 = 3;


const RUNS_FILE: &str = "runs";


fn search_path_error() -> PgError {
    PgError::FunctionSearchPath {
        total: 1,
        functions: "f".to_owned(),
    }
}


fn count_run(settings: &PgSettings) -> Result<u64, io::Error> {
    let runs = Path::new(&settings.password_file).with_file_name(RUNS_FILE);
    fs::OpenOptions::new().create(true).append(true).open(&runs)?.write_all(b"x")?;
    Ok(fs::metadata(&runs)?.len())
}


fn sleeping(duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(tokio::time::sleep(duration))
}


fn pg_settings_of(dir: &Path) -> Result<Arc<PgSettings>, Box<dyn std::error::Error>> {
    Ok(Arc::new(load_pg_settings(&dir.join("pg.yaml"))?))
}


fn passes_on_the_third_run(settings: Arc<PgSettings>) -> MigrationRun {
    let outcome = match count_run(&settings) {
        Ok(run) if run < PASSES_ON_THIRD_RUN => Err(search_path_error()),
        Ok(_run) => Ok(vec!["done".to_owned()]),
        Err(source) => Err(PgError::Io {
            file: RUNS_FILE.to_owned(),
            source,
        }),
    };
    Box::pin(ready(outcome))
}


fn always_search_path(settings: Arc<PgSettings>) -> MigrationRun {
    let outcome = match count_run(&settings) {
        Ok(_run) => Err(search_path_error()),
        Err(source) => Err(PgError::Io {
            file: RUNS_FILE.to_owned(),
            source,
        }),
    };
    Box::pin(ready(outcome))
}


fn always_other_error(settings: Arc<PgSettings>) -> MigrationRun {
    let outcome = match count_run(&settings) {
        Ok(_run) => Err(PgError::NotRegular { file: "x".to_owned() }),
        Err(source) => Err(PgError::Io {
            file: RUNS_FILE.to_owned(),
            source,
        }),
    };
    Box::pin(ready(outcome))
}


fn runs_so_far(dir: &Path) -> Result<u64, io::Error> {
    Ok(fs::metadata(dir.join(RUNS_FILE))?.len())
}


fn forget_runs(dir: &Path) -> Result<(), io::Error> {
    fs::remove_file(dir.join(RUNS_FILE))
}


#[tokio::test(start_paused = true)]
async fn the_search_path_check_is_retried_by_name_and_bounded_and_nothing_else_is() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let settings = pg_settings_of(dir.path())?;

    let first_start = tokio::time::Instant::now();
    let done = migrate_retrying(passes_on_the_third_run, &settings, sleeping).await?;
    assert_eq!(done, vec!["done".to_owned()]);
    assert_eq!(runs_so_far(dir.path())?, PASSES_ON_THIRD_RUN);
    assert_eq!(first_start.elapsed(), Duration::from_secs(PAUSE_SECONDS * (PASSES_ON_THIRD_RUN - 1)));
    forget_runs(dir.path())?;

    let second_start = tokio::time::Instant::now();
    let capped = migrate_retrying(always_search_path, &settings, sleeping).await;
    assert!(matches!(capped, Err(PgError::FunctionSearchPath { .. })));
    assert_eq!(runs_so_far(dir.path())?, RETRY_ATTEMPTS + 1);
    assert_eq!(second_start.elapsed(), Duration::from_secs(PAUSE_SECONDS * RETRY_ATTEMPTS));
    forget_runs(dir.path())?;

    let third_start = tokio::time::Instant::now();
    let other = migrate_retrying(always_other_error, &settings, sleeping).await;
    assert!(matches!(other, Err(PgError::NotRegular { .. })));
    assert_eq!(runs_so_far(dir.path())?, 1);
    assert_eq!(third_start.elapsed(), Duration::ZERO);
    Ok(())
}


#[test]
fn start_reads_the_settings_file_once() -> TestResult {
    let source = fs::read_to_string(fixture("../src/serve.rs"))?;
    assert_eq!(source.matches("load_settings(").count(), 1);
    Ok(())
}
