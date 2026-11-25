#![cfg(unix)]


mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use core_config::error::ConfigError;
use metric_alerts::serve::{one_pass, pause, run, serving_with, start, system_now, ServeError};
use metric_alerts::service::{load_settings, ServiceSettings};
use metric_alerts::service::{Live, PassReport};
use metric_alerts::types::InterruptWait;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use socket2::{Domain, Socket, Type};
use std::fs;
use std::future::{pending, ready};
use std::io::{self, BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use stub::reply;
use tempfile::tempdir;
use tokio::sync::Mutex;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-metric-alerts");


const OWNER_ONLY: u32 = 0o600;


const PG_PASSWORD: &str = "p";


const ROUND_DONE: &str = "round done tenants";


const ONE_ROUND: u64 = 1;


const FETCH_TIMEOUT_MS: u64 = 2000;


const QUIET_POINT: &[u8] = b"1700000000\t10\n";


const RULES: &str = "rules:\n  - id: disk\n    metric: disk.used\n    condition: {kind: threshold, direction: above, threshold: 90}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n";


struct Site {
    settings_file: PathBuf,
    dir: PathBuf,
}


fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn closed_socket() -> io::Result<(Socket, u16)> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("not an inet address"))?
        .port();
    Ok((socket, port))
}


fn write_site(dir: &Path, pg_port: u16, ca_pem: &str, fetch_port: u16, tenants: &str) -> Result<Site, Box<dyn std::error::Error>> {
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    private_file(&dir.join("ch.pass"), b"pw\n")?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(dir.join("rules.yaml"), RULES)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {pg_port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    fs::write(
        dir.join("fetch.yaml"),
        format!(
            "url: http://127.0.0.1:{fetch_port}\nuser: ostyr\npassword_file: {}\ntimeout_ms: {FETCH_TIMEOUT_MS}\n",
            dir.join("ch.pass").display()
        ),
    )?;
    let settings_file = dir.join("service.yaml");
    fs::write(
        &settings_file,
        format!(
            "fetch_settings: {}\nrules_file: {}\npg_settings: {}\ntenants: {tenants}\nround_seconds: 30\nmax_tenants: 5\naudit_file: {}\n",
            dir.join("fetch.yaml").display(),
            dir.join("rules.yaml").display(),
            dir.join("pg.yaml").display(),
            dir.join("audit.log").display(),
        ),
    )?;
    Ok(Site {
        settings_file,
        dir: dir.to_path_buf(),
    })
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


fn wait_for_line(reader: &mut BufReader<ChildStderr>, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    let found = reader
        .by_ref()
        .lines()
        .find_map(|line| line.map(|text| text.contains(marker).then_some(text)).transpose())
        .ok_or("the child ended before the marker")??;
    Ok(found)
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
    Ok(())
}


fn never() -> InterruptWait {
    Box::pin(pending())
}


fn at_once(_duration: Duration) -> Pin<Box<dyn std::future::Future<Output = ()>>> {
    Box::pin(ready(()))
}


async fn serve_one_round_then(name: &str) -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let clickhouse = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let fetch_port = clickhouse.local_addr()?.port();
    let stub = reply(clickhouse, "200 OK", "", QUIET_POINT.to_vec());
    let site = write_site(dir.path(), fake.port, &ca_pem, fetch_port, "[acme, \"-x\"]")?;
    let mut child = spawn_service(&site.settings_file)?;
    let mut reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    let line = tokio::task::block_in_place(|| wait_for_line(&mut reader, ROUND_DONE))?;
    assert!(line.contains("refused=1"), "{line}");
    signal(&child, name)?;
    tokio::task::block_in_place(|| finish(child, reader))?;
    let seen = stub.join().map_err(|_panic| "the stub panicked")??;
    assert!(seen.contains("param_tenant=acme"), "{seen}");
    assert!(!seen.contains("param_tenant=-x"), "{seen}");
    Ok(())
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-metric-alerts <service.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-metric-alerts")
}


#[test]
fn an_unreadable_or_invalid_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let settings_file = dir.path().join("service.yaml");
    fs::write(&settings_file, "tenants: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "service.yaml")
}


#[test]
fn a_settings_file_with_no_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = dir.path().join("service.yaml");
    fs::write(
        &settings_file,
        "fetch_settings: /f\nrules_file: /r\npg_settings: /p\ntenants: [a]\nround_seconds: 30\nmax_tenants: 5\n",
    )?;
    refused_with(&run_to_end(&[&settings_file])?, "audit_file")?;
    assert!(!dir.path().join("audit.log").exists());
    Ok(())
}


#[test]
fn an_invalid_rules_file_or_pg_settings_file_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), port, "", port, "[a]")?;
    fs::write(site.dir.join("rules.yaml"), "rules: [\n")?;
    refused_with(&run_to_end(&[&site.settings_file])?, "rules.yaml")?;
    fs::write(site.dir.join("rules.yaml"), RULES)?;
    fs::remove_file(site.dir.join("pg.yaml"))?;
    refused_with(&run_to_end(&[&site.settings_file])?, "pg.yaml")
}


#[test]
fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), port, "", port, "[a]")?;
    let output = run_to_end(&[&site.settings_file])?;
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
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), fake.port, &ca_pem, port, "[a]")?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&site.settings_file]))?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_round_for_the_valid_tenant_and_exits_zero_on_sigint() -> TestResult {
    serve_one_round_then("-INT").await
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_exits_zero_on_sigterm() -> TestResult {
    serve_one_round_then("-TERM").await
}


#[tokio::test(flavor = "multi_thread")]
async fn start_at_the_round_cap_is_the_named_cap_error() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), fake.port, &ca_pem, port, "[a]")?;
    let error = start(&site.settings_file, ONE_ROUND, &system_now, &at_once, never())
        .await
        .err()
        .ok_or("expected the cap")?;
    assert!(matches!(error, ServeError::RoundCap), "{error}");
    assert!(error.to_string().contains("round cap"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_returns_when_the_interrupt_arrives_and_fails_when_it_fails() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), fake.port, &ca_pem, port, "[a]")?;
    start(&site.settings_file, u64::MAX, &system_now, &at_once, Box::pin(ready(Ok(())))).await?;
    let failing: InterruptWait = Box::pin(ready(Err(io::Error::other("no signal"))));
    let error = start(&site.settings_file, u64::MAX, &system_now, &at_once, failing)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(error.to_string().contains("no signal"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn run_refuses_a_bad_usage_and_installs_logging_once() -> TestResult {
    let usage = run(&[], never()).await.err().ok_or("expected the usage")?;
    assert!(matches!(usage, ServeError::Usage));
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(accepting()).await?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), fake.port, &ca_pem, port, "[a]")?;
    let arguments = [site.settings_file.display().to_string()];
    run(&arguments, Box::pin(ready(Ok(())))).await?;
    let again = run(&arguments, Box::pin(ready(Ok(()))))
        .await
        .err()
        .ok_or("expected a second install to fail")?;
    assert!(matches!(again, ServeError::Failed(_)));
    Ok(())
}


#[tokio::test]
async fn a_pass_that_reaches_neither_store_runs_nothing_and_counts_it() -> TestResult {
    let dir = tempdir()?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), port, "", port, "[a]")?;
    let settings = metric_alerts::service::load_settings(&site.settings_file)?;
    let live = Live {
        settings: Arc::new(settings),
        rules: Arc::new(metric_alerts::rules::load_rules(&site.dir.join("rules.yaml"))?),
        stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let pg = Arc::new(core_pg::settings::load_settings(&site.dir.join("pg.yaml"))?);
    let states = Arc::new(Mutex::new(metric_alerts::types::TenantStates::new()));
    let unreachable = one_pass(Arc::clone(&pg), Arc::clone(&states), live.clone(), system_now()).await;
    assert_eq!(
        unreachable,
        PassReport {
            unavailable: 1,
            ..PassReport::default()
        }
    );
    fs::remove_file(site.dir.join("fetch.yaml"))?;
    let missing = one_pass(pg, Arc::clone(&states), live, system_now()).await;
    assert_eq!(missing.unavailable, 1);
    assert!(states.lock().await.is_empty());
    Ok(())
}


#[tokio::test]
async fn the_pause_waits_and_the_clock_reads() -> TestResult {
    pause(Duration::ZERO).await;
    assert!(system_now() > 0);
    Ok(())
}


fn read_then_swap_the_pg_settings(file: &Path) -> Result<ServiceSettings, ConfigError> {
    let first = load_settings(file)?;
    let text = fs::read_to_string(file).map_err(|failure| ConfigError::WatchedFile {
        file: file.display().to_string(),
        reason: failure.to_string(),
    })?;
    fs::write(file, text.replace("pg.yaml", "other.yaml").replace("audit.log", "second-audit.log")).map_err(|failure| ConfigError::WatchedFile {
        file: file.display().to_string(),
        reason: failure.to_string(),
    })?;
    Ok(first)
}


#[tokio::test(flavor = "multi_thread")]
async fn the_start_reads_the_settings_once_so_a_swap_during_start_is_refused() -> TestResult {
    let dir = tempdir()?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), port, "", port, "[a]")?;
    let error = serving_with(
        read_then_swap_the_pg_settings,
        &site.settings_file,
        ONE_ROUND,
        &system_now,
        &at_once,
        never(),
    )
    .await
    .err()
    .ok_or("the swap was accepted")?;
    assert!(error.to_string().contains("start-only"), "{error}");
    assert!(dir.path().join("audit.log").exists());
    assert!(!dir.path().join("second-audit.log").exists());
    Ok(())
}
