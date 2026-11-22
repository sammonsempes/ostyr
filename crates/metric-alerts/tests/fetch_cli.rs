mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use metric_alerts::fetch_cli::{run_cli, run_files, FetchCliError, USAGE};
use socket2::{Domain, Socket, Type};
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use stub::reply;
use tempfile::{tempdir, TempDir};


const NOW: u64 = 1_000_000_000;


const RULES: &str = "rules:\n  - id: disk\n    metric: disk.used\n    condition: {kind: threshold, direction: above, threshold: 90}\n    close_after: 60\n    severity: high\n    runbook: https://r.example.org\n";


struct Refusing;


impl Write for Refusing {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn files(port: u16) -> Result<(TempDir, String, String), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    write_secret(dir.path().join("password"), "pw\n")?;
    let settings = dir.path().join("settings.yaml");
    fs::write(
        &settings,
        format!(
            "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\n",
            dir.path().join("password").display()
        ),
    )?;
    let rules = dir.path().join("rules.yaml");
    fs::write(&rules, RULES)?;
    let settings_text = text(&settings);
    let rules_text = text(&rules);
    Ok((dir, settings_text, rules_text))
}


fn text(path: &Path) -> String {
    path.display().to_string()
}


#[test]
fn the_points_are_printed_per_rule() -> TestResult {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    let server = reply(bound, "200 OK", "", b"1\t2.5\n3\t4\n".to_vec());
    let (_dir, settings, rules) = files(port)?;
    let mut out = Vec::new();
    run_cli(&[settings, rules, "acme".to_string()], NOW, &mut out)?;
    server.join().map_err(|_| "server panicked")??;
    assert_eq!(String::from_utf8(out)?, "disk\t1\t2.5\ndisk\t3\t4\n");
    Ok(())
}


/// A bound, never listening socket: connections to it are refused and its port stays taken while it lives.
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


#[test]
fn every_failure_is_typed() -> TestResult {
    let (_closed, port) = closed_socket()?;
    let (dir, settings, rules) = files(port)?;
    let mut out = Vec::new();
    let usage = run_cli(&[], NOW, &mut out);
    assert!(matches!(usage, Err(FetchCliError::Usage)));
    assert_eq!(FetchCliError::Usage.to_string(), USAGE);
    assert!(matches!(
        run_files("/nonexistent", &rules, "acme", NOW, &mut out),
        Err(FetchCliError::Fetch(_))
    ));
    assert!(matches!(run_files(&settings, &rules, "-x", NOW, &mut out), Err(FetchCliError::Rule(_))));
    assert!(matches!(
        run_files(&settings, "/nonexistent", "acme", NOW, &mut out),
        Err(FetchCliError::Rule(_))
    ));
    let no_password = dir.path().join("settings2.yaml");
    fs::write(
        &no_password,
        format!("url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: /nonexistent\n"),
    )?;
    assert!(matches!(
        run_files(&text(&no_password), &rules, "acme", NOW, &mut out),
        Err(FetchCliError::Fetch(_))
    ));
    assert!(matches!(
        run_files(&settings, &rules, "acme", NOW, &mut out),
        Err(FetchCliError::Fetch(_))
    ));
    assert!(out.is_empty());
    Ok(())
}


#[test]
fn a_failing_writer_is_an_output_error() -> TestResult {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    let server = reply(bound, "200 OK", "", b"1\t1\n".to_vec());
    let (_dir, settings, rules) = files(port)?;
    let outcome = run_files(&settings, &rules, "acme", NOW, &mut Refusing);
    server.join().map_err(|_| "server panicked")??;
    assert!(matches!(outcome, Err(FetchCliError::Output(_))));
    assert_eq!(
        FetchCliError::Output(io::Error::other("x")).to_string(),
        "the report could not be written"
    );
    Ok(())
}


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)?;
    std::fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)
}
