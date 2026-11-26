#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/stand_in.rs"]
mod stand_in;
#[path = "common/types.rs"]
mod types;


use pg_fake::fake::{Fake, Reply};
use site::{applying, pg_with, write_site, Site, ADMIN, AUDITOR, RESOURCES};
use stand_in::{reply, spawn_stand_in, StandIn};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-virt-inventory");


const ROUND_DONE: &str = "virt round done";


const ROUND_FAILED: &str = "virt round failed";


const UNUSED_PORT: u16 = 9;


const OK: u16 = 200;


const TWO_REQUESTS: usize = 2;


const HANG_GUARD: Duration = Duration::from_secs(120);


struct Running {
    child: Child,
    lines: BufReader<ChildStderr>,
    disarm: Sender<()>,
    _guard: JoinHandle<()>,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.disarm.send(()) {
            tracing::debug!(%error, "the hang guard had already ended");
        }
        if let Err(error) = self.child.kill() {
            tracing::debug!(%error, "the child had already ended");
        }
        if let Err(error) = self.child.wait() {
            tracing::debug!(%error, "the child could not be reaped");
        }
    }
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


fn spawn_service(settings_file: &Path) -> Result<Running, Box<dyn Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(settings_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let lines = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    let (disarm, armed) = channel();
    let pid = child.id();
    let guard = spawn(move || {
        if armed.recv_timeout(HANG_GUARD) == Err(RecvTimeoutError::Timeout) {
            match Command::new("kill").arg("-KILL").arg(pid.to_string()).status() {
                Ok(status) => tracing::debug!(%status, "the hang guard killed a stuck service"),
                Err(error) => tracing::debug!(%error, "the hang guard could not kill the service"),
            }
        }
    });
    Ok(Running {
        child,
        lines,
        disarm,
        _guard: guard,
    })
}


fn wait_for_line(running: &mut Running, marker: &str) -> Result<String, Box<dyn Error>> {
    let found = running
        .lines
        .by_ref()
        .lines()
        .find_map(|line| line.map(|text| text.contains(marker).then_some(text)).transpose())
        .ok_or("the child ended before the marker")??;
    Ok(found)
}


fn stop_with(running: &mut Running, name: &str) -> Result<String, Box<dyn Error>> {
    let status = Command::new("kill").arg(name).arg(running.child.id().to_string()).status()?;
    assert!(status.success());
    let mut rest = String::new();
    running.lines.read_to_string(&mut rest)?;
    let exit = running.child.wait()?;
    assert!(exit.success(), "{rest}");
    Ok(rest)
}


fn statements_of(fake: &mut Fake) -> Vec<String> {
    std::iter::from_fn(|| fake.statements.try_recv().ok()).collect()
}


fn applies(statements: &[String]) -> usize {
    statements.iter().filter(|text| text.starts_with(cmdb::store::APPLY_SQL)).count()
}


struct Round {
    _dir: TempDir,
    site: Site,
    statements: Vec<String>,
    stand_in: StandIn,
}


async fn round_with(permissions: &[u8], marker: &str, name: &str) -> Result<Round, Box<dyn Error>> {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, permissions), reply(OK, RESOURCES)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&mut running, marker))?;
    tokio::task::block_in_place(|| stop_with(&mut running, name))?;
    assert!(line.contains(marker), "{line}");
    Ok(Round {
        _dir: dir,
        site,
        statements: statements_of(&mut fake),
        stand_in,
    })
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-virt-inventory <settings.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-virt-inventory")
}


#[test]
fn an_unreadable_or_invalid_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let settings_file = dir.path().join("service.yaml");
    fs::write(&settings_file, "interval_seconds: [\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "service.yaml")
}


#[test]
fn a_settings_file_with_no_audit_path_or_a_bad_interval_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let settings_file = dir.path().join("service.yaml");
    fs::write(&settings_file, "fetch_settings: /f\npg_settings: /p\ninterval_seconds: 60\n")?;
    refused_with(&run_to_end(&[&settings_file])?, "audit_file")?;
    fs::write(
        &settings_file,
        "fetch_settings: /f\npg_settings: /p\naudit_file: /a\ninterval_seconds: 59\n",
    )?;
    refused_with(&run_to_end(&[&settings_file])?, "interval_seconds must be within 60..=86400")?;
    assert!(!dir.path().join("audit.log").exists());
    Ok(())
}


#[test]
fn a_missing_fetch_or_pg_file_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let site = write_site(dir.path(), UNUSED_PORT, "", UNUSED_PORT, "", "")?;
    fs::remove_file(dir.path().join("fetch.yaml"))?;
    refused_with(&run_to_end(&[&site.settings_file])?, "fetch.yaml")?;
    fs::write(dir.path().join("fetch.yaml"), "")?;
    refused_with(&run_to_end(&[&site.settings_file])?, "fetch.yaml")?;
    let ready = write_site(dir.path(), UNUSED_PORT, "", UNUSED_PORT, "", "")?;
    fs::remove_file(dir.path().join("pg.yaml"))?;
    refused_with(&run_to_end(&[&ready.settings_file])?, "pg.yaml")
}


#[test]
fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let held = TcpListener::bind("127.0.0.1:0")?;
    let site = write_site(dir.path(), held.local_addr()?.port(), "", UNUSED_PORT, "", "")?;
    let output = run_to_end(&[&site.settings_file])?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migration_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(Arc::new(|sql| {
        if sql.contains("CREATE TABLE IF NOT EXISTS public.schema_migrations") {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    }))
    .await?;
    let site = write_site(dir.path(), fake.port, &pg_ca, UNUSED_PORT, "", "")?;
    let output = tokio::task::block_in_place(|| run_to_end(&[&site.settings_file]))?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn one_round_syncs_the_inventory_audits_under_all_and_sigterm_exits_zero() -> TestResult {
    let round = round_with(AUDITOR, ROUND_DONE, "-TERM").await?;
    let seen = round.stand_in.seen.join().map_err(|_| "stand-in panicked")??;
    assert_eq!(seen.len(), TWO_REQUESTS);
    assert_eq!(
        seen.first().map(|request| request.request_line.as_str()),
        Some("GET /api2/json/access/permissions HTTP/1.1")
    );
    assert!(seen
        .iter()
        .all(|request| request.authorization.as_deref().is_some_and(|value| value.starts_with("PVEAPIToken="))));
    assert_eq!(applies(&round.statements), 1, "{:?}", round.statements);
    let audit = fs::read_to_string(&round.site.audit_file)?;
    assert!(audit.contains("\"tenant\":\"all\""), "{audit}");
    assert!(audit.contains("\"action\":\"virt.round\""), "{audit}");
    assert!(audit.contains("\"outcome\":\"success\""), "{audit}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn sigint_also_exits_zero() -> TestResult {
    let round = round_with(AUDITOR, ROUND_DONE, "-INT").await?;
    assert!(fs::read_to_string(&round.site.audit_file)?.contains("virt.round"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_write_capable_token_is_a_named_failure_with_no_cmdb_write() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, ADMIN)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&mut running, ROUND_FAILED))?;
    tokio::task::block_in_place(|| stop_with(&mut running, "-TERM"))?;
    assert!(line.contains("not read-only"), "{line}");
    let statements = statements_of(&mut fake);
    assert_eq!(applies(&statements), 0, "{statements:?}");
    let seen = stand_in.seen.join().map_err(|_| "stand-in panicked")??;
    assert_eq!(seen.len(), 1, "the resources are never requested");
    let audit = fs::read_to_string(&site.audit_file)?;
    assert!(audit.contains("\"outcome\":\"failure\""), "{audit}");
    assert!(audit.contains("\"tenant\":\"all\""), "{audit}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_certificate_is_one_refused_attempt_per_interval() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let other = spawn_stand_in(Vec::new())?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let site = write_site(dir.path(), fake.port, &pg_ca, port, &other.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&mut running, ROUND_FAILED))?;
    tokio::task::block_in_place(|| stop_with(&mut running, "-TERM"))?;
    assert!(line.contains("proxmox fetch refused"), "{line}");
    listener.set_nonblocking(true)?;
    let attempts = std::iter::from_fn(|| listener.accept().ok()).count();
    assert_eq!(attempts, 1);
    assert_eq!(applies(&statements_of(&mut fake)), 0);
    Ok(())
}
