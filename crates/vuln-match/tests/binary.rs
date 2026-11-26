#![cfg(unix)]


#[path = "common/closed.rs"]
mod closed;
#[path = "common/pg.rs"]
mod pg;
#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use closed::closed_socket;
use pg::{fake_with, scanning};
use site::{write_site, VULNERABLE};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread::spawn;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-vuln");


const HANG_GUARD: Duration = Duration::from_secs(120);


const ROUND_DONE: &str = "round done scanned=1";


struct Service {
    child: Child,
    lines: Receiver<String>,
}


impl Drop for Service {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            tracing::debug!(%error, "the service had already ended");
        }
        if let Err(error) = self.child.wait() {
            tracing::debug!(%error, "the service could not be reaped");
        }
    }
}


fn spawn_service(settings: &Path) -> Result<Service, Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(settings)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let (sender, lines) = channel();
    spawn(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .for_each(|line| drop(sender.send(line)))
    });
    Ok(Service { child, lines })
}


fn wait_for_line(service: &Service, marker: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::iter::repeat_with(|| service.lines.recv_timeout(HANG_GUARD))
        .find_map(|line| match line {
            Ok(text) if text.contains(marker) => Some(Ok(text)),
            Ok(_other) => None,
            Err(error) => Some(Err(error)),
        })
        .ok_or("no line")?
        .map_err(|error| format!("the service never printed {marker}: {error}").into())
}


fn signal(service: &Service, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(service.child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
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


async fn serve_one_round_then(name: &str) -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(scanning()).await?;
    let site = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::write(site.inventory.join("web-1.json"), VULNERABLE)?;
    let mut service = spawn_service(&site.settings)?;
    let line = tokio::task::block_in_place(|| wait_for_line(&service, ROUND_DONE))?;
    assert!(line.contains("findings=1") && line.contains("alerts=1"), "{line}");
    signal(&service, name)?;
    let status = tokio::task::block_in_place(|| service.child.wait())?;
    assert!(status.success(), "{status}");
    assert!(fs::metadata(&site.audit).is_ok());
    Ok(())
}


#[test]
fn a_missing_or_extra_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-vuln <service.yaml>")?;
    refused_with(&run_to_end(&[Path::new("a"), Path::new("b")])?, "usage: ostyr-vuln")
}


#[test]
fn an_unreadable_or_invalid_settings_file_is_a_named_error() -> TestResult {
    let dir = tempdir()?;
    refused_with(&run_to_end(&[&dir.path().join("absent.yaml")])?, "absent.yaml")?;
    let settings = dir.path().join("service.yaml");
    fs::write(&settings, "tenant: [\n")?;
    refused_with(&run_to_end(&[&settings])?, "service.yaml")
}


#[test]
fn a_settings_file_with_no_audit_path_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), port, "")?;
    let text = fs::read_to_string(&site.settings)?;
    let without: String = text
        .lines()
        .filter(|line| !line.starts_with("audit_file"))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&site.settings, without)?;
    refused_with(&run_to_end(&[&site.settings])?, "audit_file")?;
    assert!(!site.audit.exists());
    Ok(())
}


#[test]
fn a_database_that_refuses_the_connection_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (_closed, port) = closed_socket()?;
    let site = write_site(dir.path(), port, "")?;
    let output = run_to_end(&[&site.settings])?;
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_serves_a_round_and_exits_zero_on_sigint() -> TestResult {
    serve_one_round_then("-INT").await
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_exits_zero_on_sigterm() -> TestResult {
    serve_one_round_then("-TERM").await
}
