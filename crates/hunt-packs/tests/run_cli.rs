mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use hunt_packs::cli::{run_cli, run_files, RunCliError, USAGE};
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use stub::reply;
use tempfile::{tempdir, TempDir};


const NOW_ARG: usize = 4;


const ID_ARG: usize = 2;


const TENANT_ARG: usize = 3;


const NOW_SECONDS: u64 = 1_700_000_000;


const NOW: &str = "1700000000";


const PACKS: &str = "packs:
  - id: one
    title: One
    hypothesis: H
    technique: T1059
    source: clickhouse
    query: SELECT 1 WHERE {tenant:String} != '' AND {window_start:DateTime64(3)} < {window_end:DateTime64(3)}
    schedule_seconds: 300
    window_seconds: 300
    cost: { max_rows: 10, max_seconds: 1, max_bytes_read: 1000 }
    baseline: { max_matches: 1 }
";


struct Refusing;


impl Write for Refusing {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn files(port: u16) -> Result<(TempDir, Vec<String>), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    fs::write(dir.path().join("password"), "pw\n")?;
    let packs = dir.path().join("packs");
    fs::create_dir(&packs)?;
    fs::write(packs.join("one.yaml"), PACKS)?;
    let settings = dir.path().join("settings.yaml");
    fs::write(
        &settings,
        format!(
            "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\n",
            dir.path().join("password").display()
        ),
    )?;
    let args = vec![
        settings.display().to_string(),
        packs.display().to_string(),
        "one".to_string(),
        "acme".to_string(),
        NOW.to_string(),
    ];
    Ok((dir, args))
}


fn with_arg(args: &[String], index: usize, value: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .map(|(position, found)| if position == index { value.to_string() } else { found.clone() })
        .collect()
}


#[test]
fn prints_the_outcome() -> TestResult {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let (_dir, args) = files(bound.local_addr()?.port())?;
    let server = reply(bound, "200 OK", "", b"2\n".to_vec());
    let mut out = Vec::new();
    run_cli(&args, &mut out)?;
    server.join().map_err(|_| "server thread")??;
    assert_eq!(String::from_utf8(out)?, "one\t2\ttrue\n");
    Ok(())
}


#[test]
fn refuses_bad_input() -> TestResult {
    let (_dir, args) = files(1)?;
    let mut out = Vec::new();
    assert!(matches!(run_cli(&[], &mut out), Err(RunCliError::Usage)));
    assert!(USAGE.starts_with("usage: hunt_run"));
    assert!(matches!(run_cli(&with_arg(&args, NOW_ARG, "x"), &mut out), Err(RunCliError::Now(_))));
    assert!(matches!(
        run_cli(&with_arg(&args, ID_ARG, "other"), &mut out),
        Err(RunCliError::UnknownPack)
    ));
    assert!(matches!(
        run_cli(&with_arg(&args, 1, "/nonexistent-dir"), &mut out),
        Err(RunCliError::Pack(_))
    ));
    assert!(matches!(
        run_cli(&with_arg(&args, 0, "/nonexistent.yaml"), &mut out),
        Err(RunCliError::Fetch(_))
    ));
    assert!(matches!(run_cli(&with_arg(&args, TENANT_ARG, "-x"), &mut out), Err(RunCliError::Run(_))));
    assert!(out.is_empty());
    Ok(())
}


#[test]
fn a_failing_writer_is_reported() -> TestResult {
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let (_dir, args) = files(bound.local_addr()?.port())?;
    let server = reply(bound, "200 OK", "", b"0\n".to_vec());
    let outcome = run_files(
        args.first().ok_or("no settings")?,
        args.get(1).ok_or("no dir")?,
        "one",
        "acme",
        NOW_SECONDS,
        &mut Refusing,
    );
    server.join().map_err(|_| "server thread")??;
    assert!(matches!(outcome, Err(RunCliError::Output(_))));
    Ok(())
}
