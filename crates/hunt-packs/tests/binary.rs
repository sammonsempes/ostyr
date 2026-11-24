#![cfg(unix)]


mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use core_audit::log::open_file_log;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use hunt_packs::model::HuntPack;
use hunt_packs::packs::load_file;
use hunt_packs::serve::{boxed_reload_audit, forward_interrupt, read_clock, reload_context, run_one, setup_failed, start, AUDIT_TENANT};
use hunt_packs::store::GET_SQL;
use hunt_packs::types::InterruptWait;
use metric_alerts::fetch::FetchError;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::collections::BTreeMap;
use std::fs;
use std::future::ready;
use std::io::{self, BufRead, BufReader, Read};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Instant;
use stub::reply;
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::sync::watch;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-hunt");


const OWNER_ONLY: u32 = 0o600;


const CLOSED_PORT: u16 = 1;


const PG_PASSWORD: &str = "p";


const SERVING_MARKER: &str = "serving";


const MAX_STATEMENTS: usize = 1_000;


const ONE_ROUND: u64 = 1;


const NEGATIVE_END: i64 = -1;


const SOME_END: i64 = 1_700_000_000;


const SAMPLE_PACK: &str = "examples/packs/clickhouse-rare-parent-child.yaml";


fn pack() -> Result<HuntPack, Box<dyn std::error::Error>> {
    let file = load_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join(SAMPLE_PACK))?;
    Ok(file.packs.into_iter().next().ok_or("no pack")?)
}


fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn write_clickhouse(dir: &Path, port: u16) -> Result<PathBuf, Box<dyn std::error::Error>> {
    private_file(&dir.join("ch.pass"), b"HUNTPW")?;
    let file = dir.join("ch.yaml");
    fs::write(
        &file,
        format!(
            "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\ntimeout_ms: 5000\n",
            dir.join("ch.pass").display()
        ),
    )?;
    Ok(file)
}


fn write_site(dir: &Path, port: u16, ca_pem: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    fs::create_dir_all(dir.join("packs"))?;
    fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join(SAMPLE_PACK), dir.join("packs/sample.yaml"))?;
    let settings_file = dir.join("hunt.yaml");
    fs::write(
        &settings_file,
        format!(
            "pg_settings: {}\nclickhouse_settings: {}\npacks_dir: {}\naudit_file: {}\ntenants: [acme, -x]\ntick_seconds: 10\n",
            dir.join("pg.yaml").display(),
            dir.join("absent-ch.yaml").display(),
            dir.join("packs").display(),
            dir.join("audit.log").display(),
        ),
    )?;
    Ok(settings_file)
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
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


fn wait_for_serving(reader: &mut BufReader<ChildStderr>) -> TestResult {
    reader
        .by_ref()
        .lines()
        .find_map(|line| line.map(|text| text.contains(SERVING_MARKER).then_some(())).transpose())
        .ok_or("the child ended before it served")??;
    Ok(())
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


fn finish(mut child: Child, mut reader: BufReader<ChildStderr>) -> TestResult {
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    let exit = child.wait()?;
    assert!(exit.success(), "{rest}");
    assert!(rest.contains("rounds"), "{rest}");
    Ok(())
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-hunt <hunt.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-hunt")
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
    let settings_file = dir.path().join("hunt.yaml");
    fs::write(&settings_file, "tenants: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "hunt.yaml")
}


#[test]
fn a_settings_file_without_an_audit_path_is_refused() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let text = fs::read_to_string(&settings_file)?;
    let without: Vec<&str> = text.lines().filter(|line| !line.starts_with("audit_file")).collect();
    fs::write(&settings_file, without.join("\n"))?;
    refused_with(&run_to_end(&[&settings_file])?, "audit_file")
}


#[test]
fn a_relative_audit_path_is_refused_and_creates_nothing() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let text = fs::read_to_string(&settings_file)?;
    fs::write(
        &settings_file,
        text.replace(&dir.path().join("audit.log").display().to_string(), "audit.log"),
    )?;
    refused_with(&run_to_end(&[&settings_file])?, "absolute")?;
    assert!(!dir.path().join("audit.log").exists());
    Ok(())
}


#[test]
fn an_out_of_bounds_tick_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let text = fs::read_to_string(&settings_file)?;
    fs::write(&settings_file, text.replace("tick_seconds: 10", "tick_seconds: 1"))?;
    refused_with(&run_to_end(&[&settings_file])?, "tick_seconds")
}


#[test]
fn an_unwritable_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let text = fs::read_to_string(&settings_file)?;
    let hole = dir.path().join("no-such-dir/audit.log").display().to_string();
    fs::write(&settings_file, text.replace(&dir.path().join("audit.log").display().to_string(), &hole))?;
    let output = run_to_end(&[&settings_file])?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
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


async fn wait_for_round(fake: &mut Fake) -> TestResult {
    let mut seen = false;
    let mut attempts = 0;
    while !seen && attempts < MAX_STATEMENTS {
        seen = fake.statements.recv().await.ok_or("the fake closed")?.contains(GET_SQL);
        attempts += 1;
    }
    assert!(seen);
    Ok(())
}


fn after_the_first_round(mut fake: Fake) -> InterruptWait {
    let (round_tx, round_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
    tokio::spawn(async move {
        let outcome = wait_for_round(&mut fake).await.map_err(|error| error.to_string());
        let sent = round_tx.send(outcome).is_ok();
        (sent, fake)
    });
    Box::pin(async move { round_rx.await.map_err(io::Error::other)?.map_err(io::Error::other) })
}


async fn serve_one_round_then(name: &str) -> TestResult {
    let dir = tempdir()?;
    let (mut fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let mut child = spawn_service(&settings_file)?;
    let mut reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    tokio::task::block_in_place(|| wait_for_serving(&mut reader))?;
    wait_for_round(&mut fake).await?;
    signal(&child, name)?;
    tokio::task::block_in_place(|| finish(child, reader))
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_round_and_exits_cleanly_on_sigint() -> TestResult {
    serve_one_round_then("-INT").await
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_round_and_exits_cleanly_on_sigterm() -> TestResult {
    serve_one_round_then("-TERM").await
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_its_report_after_its_rounds_and_counts_the_refused_tenant() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let report = start(&settings_file, u64::MAX, after_the_first_round(fake)).await?;
    assert_eq!((report.rounds, report.ticks, report.refused_tenants), (1, 1, 1));
    assert_eq!(fs::read_to_string(dir.path().join("audit.log"))?.lines().count(), 0);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_when_the_interrupt_arrives() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let report = start(&settings_file, u64::MAX, Box::pin(ready(Ok(())))).await?;
    assert!(report.rounds <= ONE_ROUND);
    Ok(())
}


#[tokio::test]
async fn a_failing_interrupt_wait_still_stops_and_a_dropped_receiver_is_logged() -> TestResult {
    let (stop_tx, stop_rx) = watch::channel(false);
    forward_interrupt(Box::pin(ready(Err(io::Error::other("no signal")))), stop_tx).await;
    assert!(*stop_rx.borrow());
    let (dropped_tx, dropped_rx) = watch::channel(false);
    drop(dropped_rx);
    forward_interrupt(Box::pin(ready(Ok(()))), dropped_tx).await;
    Ok(())
}


#[test]
fn the_clock_reads_a_wall_time_and_a_monotonic_time() -> TestResult {
    let reading = read_clock(Instant::now());
    assert!(reading.wall > SOME_END);
    assert!(reading.mono >= 0);
    Ok(())
}


#[test]
fn a_setup_failure_is_a_window_error() -> TestResult {
    assert!(matches!(setup_failed(FetchError::User), hunt_packs::run::RunError::Window));
    Ok(())
}


#[test]
fn run_one_refuses_each_broken_setup_and_a_negative_end() -> TestResult {
    let dir = tempdir()?;
    let window = |result: Result<_, hunt_packs::run::RunError>| matches!(result, Err(hunt_packs::run::RunError::Window));
    assert!(window(run_one(&dir.path().join("absent.yaml"), &pack()?, "acme", SOME_END)));
    let settings = write_clickhouse(dir.path(), CLOSED_PORT)?;
    assert!(window(run_one(&settings, &pack()?, "acme", NEGATIVE_END)));
    fs::write(
        dir.path().join("bad-ca.yaml"),
        fs::read_to_string(&settings)? + "ca_file: /nonexistent/ca.pem\n",
    )?;
    assert!(window(run_one(&dir.path().join("bad-ca.yaml"), &pack()?, "acme", SOME_END)));
    fs::remove_file(dir.path().join("ch.pass"))?;
    assert!(window(run_one(&settings, &pack()?, "acme", SOME_END)));
    Ok(())
}


#[test]
fn run_one_runs_the_pack_against_the_store_and_reports_the_count() -> TestResult {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let settings = write_clickhouse(dir.path(), listener.local_addr()?.port())?;
    let server = reply(listener, "200 OK", "", b"0\n".to_vec());
    let outcome = run_one(&settings, &pack()?, "acme", SOME_END)?;
    server.join().map_err(|_| "the stub panicked")??;
    assert_eq!((outcome.matches, outcome.finding), (0, false));
    Ok(())
}


fn reload_entry() -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::UNIX_EPOCH,
        actor: Actor {
            kind: ActorKind::System,
            id: "ostyr-hunt".to_owned(),
        },
        tenant: "system".to_owned(),
        module: "hunt-packs".to_owned(),
        action: "config.reload".to_owned(),
        target: "hunt.yaml".to_owned(),
        outcome: Outcome::Denied,
        request_id: "hunt-reload".to_owned(),
        justification: None,
        parameters: BTreeMap::new(),
    }
}


#[test]
fn the_reload_audit_appends_to_the_file_log() -> TestResult {
    let dir = tempdir()?;
    let audit = boxed_reload_audit(open_file_log(&dir.path().join("audit.log"))?);
    audit(reload_entry())?;
    let text = fs::read_to_string(dir.path().join("audit.log"))?;
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("\"denied\""), "{text}");
    Ok(())
}


#[test]
fn the_reload_context_names_the_non_customer_tenant_and_the_file() -> TestResult {
    let context = reload_context(Path::new("/etc/hunt.yaml"));
    assert_eq!(AUDIT_TENANT, "all");
    assert_eq!(context.tenant, "all");
    assert_eq!(context.target, "/etc/hunt.yaml");
    assert_eq!((context.actor_id.as_str(), context.module.as_str()), ("ostyr-hunt", "hunt-packs"));
    Ok(())
}


#[test]
fn a_reload_audit_record_carries_the_tenant_all() -> TestResult {
    let dir = tempdir()?;
    let log = open_file_log(&dir.path().join("audit.log"))?;
    let engine_audit = boxed_reload_audit(log);
    let context = reload_context(Path::new("hunt.yaml"));
    let entry = NewEntry {
        tenant: context.tenant,
        ..reload_entry()
    };
    engine_audit(entry)?;
    let text = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(text.contains("\"tenant\":\"all\""), "{text}");
    Ok(())
}
