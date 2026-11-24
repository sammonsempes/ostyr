#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use rcgen::SanType;
use status_page::service::{pg_reader, run, start, stop_on, stop_signals, USAGE};
use status_page::store::{COUNTS_SQL, PUBLISHED_SQL, UPDATES_SQL};
use status_page::types::InterruptWait;
use std::fs;
use std::future::ready;
use std::io::{self, BufRead, BufReader, Read};
use std::net::TcpListener as StdListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-status-page");


const OWNER_ONLY: u32 = 0o600;


const PG_PASSWORD: &str = "p";


const TEXT_ARRAY_OID: i32 = 1009;


const EXIT_POLLS: usize = 600;


const EXIT_POLL_PAUSE: Duration = Duration::from_millis(100);


const LISTENING_MARKER: &str = "address=";


const SECRET_ERROR_CODE: &str = "XX000";


const PAGE: &str = "id: main
tenant: acme
title: Acme status
components:
  - name: Website
    service: svc-web
";


const INCIDENT_TITLE: &str = "Checkout is down";


const STARTED: i64 = 1_700_000_000;


fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn write_server_file(dir: &Path, port: Option<u16>, extra: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::write(dir.join("page.yaml"), PAGE)?;
    fs::write(dir.join("settings.yaml"), "burst: 30\n")?;
    let pg_line = port.map_or_else(String::new, |_| format!("pg_file: {}\n", dir.join("pg.yaml").display()));
    let server_file = dir.join("server.yaml");
    fs::write(
        &server_file,
        format!(
            "page_file: {}\nsettings_file: {}\naudit_file: {}\nlisten_address: 127.0.0.1:0\n{pg_line}{extra}",
            dir.join("page.yaml").display(),
            dir.join("settings.yaml").display(),
            dir.join("audit.log").display(),
        ),
    )?;
    Ok(server_file)
}


fn write_pg(dir: &Path, port: u16, ca_pem: &str) -> TestResult {
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
    Ok(())
}


async fn fake_with(handler: Handler) -> Result<(Fake, String), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


fn text(value: &str) -> Option<Vec<u8>> {
    Some(value.as_bytes().to_vec())
}


fn serving_one_incident() -> Handler {
    Arc::new(|sql| {
        if sql == PUBLISHED_SQL {
            Reply::Typed {
                parameters: vec![TEXT_OID, INT8_OID, TEXT_ARRAY_OID],
                columns: vec![INT8_OID, TEXT_OID, TEXT_OID, INT8_OID, INT8_OID, INT8_OID],
                rows: vec![vec![
                    int8_cell(1),
                    text("svc-web"),
                    text(INCIDENT_TITLE),
                    int8_cell(STARTED),
                    None,
                    int8_cell(0),
                ]],
            }
        } else if sql == UPDATES_SQL {
            Reply::Typed {
                parameters: vec![TEXT_OID, INT8_OID, INT8_OID, INT8_OID, TEXT_ARRAY_OID],
                columns: vec![INT8_OID, INT8_OID, TEXT_OID],
                rows: Vec::new(),
            }
        } else if sql == COUNTS_SQL {
            Reply::Typed {
                parameters: vec![TEXT_OID, TEXT_ARRAY_OID],
                columns: vec![INT8_OID, INT8_OID],
                rows: vec![vec![int8_cell(1), int8_cell(1)]],
            }
        } else {
            Reply::Done
        }
    })
}


fn failing_store() -> Handler {
    Arc::new(|_| Reply::Error(SECRET_ERROR_CODE))
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


fn spawn_service(server_file: &Path) -> Result<(Child, BufReader<ChildStderr>), Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(server_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    Ok((child, reader))
}


fn listening_address(reader: &mut BufReader<ChildStderr>) -> Result<String, Box<dyn std::error::Error>> {
    let found = reader
        .by_ref()
        .lines()
        .find_map(|line| {
            line.map(|text| text.split(LISTENING_MARKER).nth(1).map(|rest| rest.trim().trim_matches('"').to_owned()))
                .transpose()
        })
        .ok_or("the child ended before it listened")??;
    Ok(found)
}


fn signal(child: &Child, name: &str) -> TestResult {
    let status = Command::new("kill").arg(format!("-{name}")).arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


fn finish(mut child: Child, mut reader: BufReader<ChildStderr>) -> Result<String, Box<dyn std::error::Error>> {
    let waited = (0..EXIT_POLLS).find_map(|_| {
        let polled = child.try_wait().transpose();
        if polled.is_none() {
            thread::sleep(EXIT_POLL_PAUSE);
        }
        polled
    });
    let exit = match waited {
        Some(polled) => polled?,
        None => {
            child.kill()?;
            Err("the child did not exit after the signal")?
        }
    };
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    assert!(exit.success(), "{rest}");
    Ok(rest)
}


async fn get(address: &str, path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    Ok(String::from_utf8(bytes)?)
}


fn stopped() -> InterruptWait {
    Box::pin(ready(Ok(())))
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, USAGE)?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, USAGE)
}


#[test]
fn an_unreadable_server_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    refused_with(&run_to_end(&[&missing])?, "absent.yaml")
}


#[test]
fn an_invalid_server_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let server_file = dir.path().join("server.yaml");
    fs::write(&server_file, "page_file: [\n")?;
    refused_with(&run_to_end(&[&server_file])?, "server.yaml")
}


#[test]
fn a_server_file_without_a_listen_address_is_refused() -> TestResult {
    let dir = tempdir()?;
    let server_file = write_server_file(dir.path(), None, "")?;
    let text = fs::read_to_string(&server_file)?.replace("listen_address: 127.0.0.1:0\n", "");
    fs::write(&server_file, text)?;
    refused_with(&run_to_end(&[&server_file])?, "listen_address is required")
}


#[test]
fn a_server_file_without_an_audit_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let server_file = write_server_file(dir.path(), None, "")?;
    let text = fs::read_to_string(&server_file)?.replace(&format!("audit_file: {}\n", dir.path().join("audit.log").display()), "");
    fs::write(&server_file, text)?;
    refused_with(&run_to_end(&[&server_file])?, "audit_file")
}


#[test]
fn a_relative_audit_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let server_file = write_server_file(dir.path(), None, "")?;
    let text = fs::read_to_string(&server_file)?.replace(&format!("{}", dir.path().join("audit.log").display()), "audit.log");
    fs::write(&server_file, text)?;
    refused_with(&run_to_end(&[&server_file])?, "audit_file must be an absolute path")
}


#[test]
fn an_address_already_in_use_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let holder = StdListener::bind("127.0.0.1:0")?;
    let server_file = write_server_file(dir.path(), None, "")?;
    let text = fs::read_to_string(&server_file)?.replace("127.0.0.1:0", &holder.local_addr()?.to_string());
    fs::write(&server_file, text)?;
    let output = run_to_end(&[&server_file])?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_the_sample_page_and_exits_zero_on_sigint() -> TestResult {
    let dir = tempdir()?;
    let server_file = write_server_file(dir.path(), None, "")?;
    let (child, mut reader) = spawn_service(&server_file)?;
    let address = tokio::task::block_in_place(|| listening_address(&mut reader))?;
    let answer = get(&address, "/status.json").await?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    signal(&child, "INT")?;
    tokio::task::block_in_place(|| finish(child, reader))?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_stored_incident_survives_sighup_and_exits_zero_on_sigterm() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(serving_one_incident()).await?;
    write_pg(dir.path(), fake.port, &ca_pem)?;
    let server_file = write_server_file(dir.path(), Some(fake.port), "")?;
    let (child, mut reader) = spawn_service(&server_file)?;
    let address = tokio::task::block_in_place(|| listening_address(&mut reader))?;
    let answer = get(&address, "/status.json").await?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains(INCIDENT_TITLE), "{answer}");
    fs::write(dir.path().join("settings.yaml"), "burst: 31\n")?;
    signal(&child, "HUP")?;
    let after = get(&address, "/status.json").await?;
    assert!(after.starts_with("HTTP/1.1 200"), "{after}");
    signal(&child, "TERM")?;
    tokio::task::block_in_place(|| finish(child, reader))?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_store_still_serves_the_fixed_page_without_the_error_text() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(failing_store()).await?;
    write_pg(dir.path(), fake.port, &ca_pem)?;
    let server_file = write_server_file(dir.path(), Some(fake.port), "")?;
    let (child, mut reader) = spawn_service(&server_file)?;
    let address = tokio::task::block_in_place(|| listening_address(&mut reader))?;
    let answer = get(&address, "/status.json").await?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(!answer.contains(SECRET_ERROR_CODE), "{answer}");
    assert!(!answer.contains(INCIDENT_TITLE), "{answer}");
    signal(&child, "TERM")?;
    let logs = tokio::task::block_in_place(|| finish(child, reader))?;
    assert!(logs.contains("class="), "{logs}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_missing_pg_settings_file_serves_the_page_without_incidents() -> TestResult {
    let dir = tempdir()?;
    let server_file = write_server_file(dir.path(), Some(1), "")?;
    start(&server_file, stopped()).await?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn start_serves_until_the_wait_resolves() -> TestResult {
    let dir = tempdir()?;
    let server_file = write_server_file(dir.path(), None, "")?;
    start(&server_file, stopped()).await?;
    assert!(dir.path().join("audit.log").exists());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_wait_stops_the_server_after_a_warning() -> TestResult {
    stop_on(Box::pin(ready(Err(io::Error::other("no signal"))))).await;
    stop_on(stopped()).await;
    Ok(())
}


fn failing_signals() -> io::Result<InterruptWait> {
    Err(io::Error::other("no signals"))
}


#[tokio::test(flavor = "multi_thread")]
async fn run_refuses_a_bad_argument_list_and_a_failing_signal_registration() -> TestResult {
    let usage = run(&[], failing_signals).await.err().ok_or("expected an error")?;
    assert_eq!(usage.to_string(), USAGE);
    let failing = run(&["x".to_owned()], failing_signals).await.err().ok_or("expected an error")?;
    assert!(failing.to_string().contains("no signals"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_signal_wait_registers_and_stays_pending() -> TestResult {
    let mut wait = stop_signals()?;
    assert!(futures_util::poll!(&mut wait).is_pending());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_reader_of_a_missing_settings_file_is_a_store_error() -> TestResult {
    let scope = core_pg::scope::tenant_scope("acme")?;
    let read = pg_reader(PathBuf::from("/nonexistent/pg.yaml"));
    assert!(read(scope, vec!["svc-web".to_owned()]).await.is_err());
    Ok(())
}
