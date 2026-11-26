#![cfg(unix)]


#[path = "common/payloads.rs"]
mod payloads;
#[path = "common/site.rs"]
mod site;
#[path = "common/stand_in.rs"]
mod stand_in;
#[path = "common/types.rs"]
mod types;


use payloads::{ADMIN, AUDITOR, RESOURCES};
use pg_fake::fake::{Fake, Reply};
use site::{applying, pg_with, write_site, Site};
use stand_in::{reply, spawn_stand_in, Hold, Reply as StandInReply, StandIn};
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
    assert!(!fs::read_to_string(&site.audit_file)?.contains("VM."), "no privilege name in the audit");
    let statements = statements_of(&mut fake);
    assert_eq!(applies(&statements), 0, "{statements:?}");
    let seen = stand_in.seen.join().map_err(|_| "stand-in panicked")??;
    assert_eq!(seen.len(), 1, "the resources are never requested");
    let audit = fs::read_to_string(&site.audit_file)?;
    assert!(audit.contains("\"outcome\":\"failure\""), "{audit}");
    assert!(audit.contains("\"round_error\":\"not_read_only\""), "{audit}");
    assert!(audit.contains("\"tenant\":\"all\""), "{audit}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_certificate_is_one_refused_attempt_per_interval_named_as_a_certificate_failure() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let other = spawn_stand_in(Vec::new())?;
    let serving = spawn_stand_in(vec![reply(OK, AUDITOR)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, serving.port, &other.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&mut running, ROUND_FAILED))?;
    tokio::task::block_in_place(|| stop_with(&mut running, "-TERM"))?;
    assert!(line.contains("certificate"), "{line}");
    let audit = fs::read_to_string(&site.audit_file)?;
    assert_eq!(audit.lines().count(), 1, "{audit}");
    assert!(audit.contains("\"round_error\":\"certificate\""), "{audit}");
    assert!(serving.seen.join().map_err(|_| "stand-in panicked")?.is_err());
    assert_eq!(applies(&statements_of(&mut fake)), 0);
    Ok(())
}


fn send_signal(running: &Running, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(running.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn sighup_in_the_middle_of_a_round_finishes_it_and_audits_the_round_and_the_reload() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let (arrived_sender, arrived) = channel();
    let (release, release_receiver) = channel();
    let held = StandInReply {
        hold: Some(Hold {
            arrived: arrived_sender,
            release: release_receiver,
        }),
        ..reply(OK, AUDITOR)
    };
    let stand_in = spawn_stand_in(vec![held, reply(OK, RESOURCES)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    arrived.recv_timeout(HANG_GUARD)?;
    let text = fs::read_to_string(&site.settings_file)?;
    fs::write(&site.settings_file, text.replacen("interval_seconds: 60", "interval_seconds: 120", 1))?;
    send_signal(&running, "-HUP")?;
    let reloaded = tokio::task::block_in_place(|| wait_for_line(&mut running, "reload after SIGHUP"))?;
    assert!(!reloaded.contains("Refused"), "{reloaded}");
    release.send(())?;
    tokio::task::block_in_place(|| wait_for_line(&mut running, ROUND_DONE))?;
    let rest = tokio::task::block_in_place(|| stop_with(&mut running, "-TERM"))?;
    assert!(!rest.contains("Terminated"), "{rest}");
    assert_eq!(applies(&statements_of(&mut fake)), 1);
    let audit = fs::read_to_string(&site.audit_file)?;
    assert!(audit.contains("\"action\":\"virt.round\""), "{audit}");
    assert!(audit.contains("\"action\":\"config.reload\""), "{audit}");
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{audit}");
    Ok(())
}


async fn refused_fetch_edit(from: &str, to: &str, key: &str) -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    tokio::task::block_in_place(|| wait_for_line(&mut running, ROUND_DONE))?;
    let fetch_file = dir.path().join("fetch.yaml");
    let text = fs::read_to_string(&fetch_file)?;
    assert!(text.contains(from), "{text}");
    fs::write(&fetch_file, text.replacen(from, to, 1))?;
    send_signal(&running, "-HUP")?;
    let refused = tokio::task::block_in_place(|| wait_for_line(&mut running, "Refused"))?;
    assert!(refused.contains("read at start only"), "{refused}");
    assert!(refused.contains(key) && refused.contains("`fetch`"), "{refused}");
    tokio::task::block_in_place(|| stop_with(&mut running, "-TERM"))?;
    let audit = fs::read_to_string(&site.audit_file)?;
    assert!(audit.contains("\"outcome\":\"denied\""), "{audit}");
    assert!(audit.contains(key), "{audit}");
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")), "{audit}");
    assert_eq!(applies(&statements_of(&mut fake)), 1);
    assert_eq!(stand_in.seen.join().map_err(|_| "stand-in panicked")??.len(), TWO_REQUESTS);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_file_tenant_edit_alone_is_refused_and_audited_denied_and_nothing_more_is_sent() -> TestResult {
    refused_fetch_edit("tenant: acme", "tenant: other", "fetch::tenant").await
}


#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_file_url_edit_alone_is_refused_and_audited_denied_and_nothing_more_is_sent() -> TestResult {
    refused_fetch_edit("localhost:", "localhost:1", "fetch::api_url").await
}


#[tokio::test(flavor = "multi_thread")]
async fn a_second_interrupt_during_a_round_is_named_and_ignored_and_the_round_finishes_and_is_audited() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let (arrived_sender, arrived) = channel();
    let (release, release_receiver) = channel();
    let held = StandInReply {
        hold: Some(Hold {
            arrived: arrived_sender,
            release: release_receiver,
        }),
        ..reply(OK, AUDITOR)
    };
    let stand_in = spawn_stand_in(vec![held, reply(OK, RESOURCES)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    arrived.recv_timeout(HANG_GUARD)?;
    send_signal(&running, "-TERM")?;
    let first = tokio::task::block_in_place(|| wait_for_line(&mut running, "stop requested"))?;
    assert!(first.contains("SIGTERM"), "{first}");
    send_signal(&running, "-INT")?;
    let second = tokio::task::block_in_place(|| wait_for_line(&mut running, "a further interrupt is ignored"))?;
    assert!(second.contains("SIGINT"), "{second}");
    release.send(())?;
    tokio::task::block_in_place(|| wait_for_line(&mut running, ROUND_DONE))?;
    tokio::task::block_in_place(|| {
        let mut rest = String::new();
        running.lines.read_to_string(&mut rest)?;
        assert!(running.child.wait()?.success(), "{rest}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    assert_eq!(applies(&statements_of(&mut fake)), 1);
    assert!(fs::read_to_string(&site.audit_file)?.contains("\"action\":\"virt.round\""));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_live_edit_is_applied_by_the_file_watch_without_a_restart_and_audited() -> TestResult {
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(applying()).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let mut running = spawn_service(&site.settings_file)?;
    tokio::task::block_in_place(|| wait_for_line(&mut running, ROUND_DONE))?;
    let text = fs::read_to_string(&site.settings_file)?;
    fs::write(&site.settings_file, text.replacen("interval_seconds: 60", "interval_seconds: 120", 1))?;
    tokio::task::block_in_place(|| wait_for_line(&mut running, "configuration reloaded"))?;
    tokio::task::block_in_place(|| stop_with(&mut running, "-TERM"))?;
    let audit = fs::read_to_string(&site.audit_file)?;
    assert!(audit.contains("\"action\":\"config.reload\""), "{audit}");
    assert!(audit.contains("interval_seconds"), "{audit}");
    Ok(())
}
