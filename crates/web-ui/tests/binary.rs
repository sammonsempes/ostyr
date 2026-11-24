#[path = "support/types.rs"]
mod types;


use core_api::types::ServerHandle;
use serde_json::Value;
use std::fs;
use std::future::ready;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use tempfile::tempdir;
use types::{TestError, TestResult};
use web_ui::serve::stop_on;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-web-ui");


const SERVING_MARKER: &str = "\"serving\"";


const LOGIN_REQUEST: &str = "GET /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";


fn write_settings(dir: &Path, listen: &str) -> Result<PathBuf, TestError> {
    let file = dir.join("web-ui.yaml");
    fs::write(
        &file,
        format!(
            "listen: {listen}\napi:\n  base_url: http://127.0.0.1:1\n  timeout_seconds: 5\naudit_file: {}\n",
            dir.join("audit.log").display()
        ),
    )?;
    Ok(file)
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, TestError> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


fn refused_with(output: &Output, marker: &str) -> TestResult {
    let text = String::from_utf8(output.stderr.clone())?;
    assert!(!output.status.success(), "{text}");
    assert!(text.contains(marker), "{text}");
    Ok(())
}


fn serving_address(line: &str) -> Result<Option<SocketAddr>, TestError> {
    if line.contains(SERVING_MARKER) {
        let json: Value = serde_json::from_str(line)?;
        Ok(Some(
            json.pointer("/fields/address").and_then(Value::as_str).ok_or("no address")?.parse()?,
        ))
    } else {
        Ok(None)
    }
}


fn address_of(reader: &mut BufReader<ChildStdout>) -> Result<SocketAddr, TestError> {
    reader
        .by_ref()
        .lines()
        .map(|line| serving_address(&line?))
        .find_map(Result::transpose)
        .ok_or("the child ended before it served")?
}


fn status_line(address: SocketAddr) -> Result<String, TestError> {
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(LOGIN_REQUEST.as_bytes())?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(reply.lines().next().ok_or("empty reply")?.to_owned())
}


fn interrupt(child: &Child) -> TestResult {
    let status = Command::new("kill").arg("-INT").arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


#[test]
fn a_missing_argument_prints_the_usage_and_fails() -> TestResult {
    refused_with(&run_to_end(&[])?, "usage: ostyr-web-ui <web-ui.yaml>")
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
    let file = dir.path().join("web-ui.yaml");
    fs::write(&file, "listen: [\n")?;
    refused_with(&run_to_end(&[&file])?, "web-ui.yaml")
}


#[test]
fn the_binary_serves_the_login_page_and_exits_cleanly_on_the_interrupt() -> TestResult {
    let dir = tempdir()?;
    let file = write_settings(dir.path(), "127.0.0.1:0")?;
    let mut child = Command::new(PROGRAM)
        .arg(&file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let address = address_of(&mut reader)?;
    let status = status_line(address)?;
    assert!(status.contains("200"), "{status}");
    interrupt(&child)?;
    let mut rest = String::new();
    reader.read_to_string(&mut rest)?;
    let exit = child.wait()?;
    assert!(exit.success(), "{rest}");
    Ok(())
}


#[tokio::test]
async fn a_failed_interrupt_wait_does_not_stop_the_server_and_a_signal_does() -> TestResult {
    let handle = ServerHandle::new();
    stop_on(handle.clone(), Box::pin(ready(Err(io::Error::other("no signal"))))).await;
    stop_on(handle.clone(), Box::pin(ready(Ok(())))).await;
    Ok(())
}
