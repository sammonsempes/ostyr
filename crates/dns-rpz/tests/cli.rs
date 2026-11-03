#[path = "common/clock.rs"]
mod clock;
#[path = "common/engine.rs"]
mod engine;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/types.rs"]
mod types;


use clock::now;
use dns_rpz::cli::{run_command, run_session, Session};
use engine::{engine_for, policy_text, replace_file};
use memory::LimitedWriter;
use std::fs;
use std::io::{self, BufRead, Cursor};
use tempfile::tempdir;
use types::TestResult;


const TWICE: usize = 2;


const IOC: &str = "{\"ioc_type\":\"domain\",\"value\":\"evil.example.com\",\"sources\":[],\"first_seen\":\"2026-11-01T00:00:00Z\",\
\"last_seen\":\"2026-11-03T00:00:00Z\",\"confidence\":90,\"tlp\":\"amber\",\"expires_at\":null,\"tags\":{\"malware\":[],\"actor\":[],\"campaign\":[]}}\n";


fn open_iocs() -> io::Result<Box<dyn BufRead>> {
    Ok(Box::new(Cursor::new(IOC.as_bytes().to_vec())))
}


fn open_missing() -> io::Result<Box<dyn BufRead>> {
    Err(io::Error::from(io::ErrorKind::NotFound))
}


#[test]
fn a_session_generates_reloads_and_stops_at_quit() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text(""))?;
    let policy = engine_for(&path)?;
    let counter = dir.path().join("counter");
    let zone = dir.path().join("zone.db");
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &open_iocs,
        counter: &counter,
        output: &zone,
        report: &mut report,
    };
    replace_file(&path, &policy_text("allowlist:\n  domains: [example.com]\n"))?;
    run_session(&mut session, &mut Cursor::new("run\nreload\nreload\nbogus\nrun\nquit\nrun\n"))?;
    let text = String::from_utf8(report)?;
    assert!(
        text.contains("\"published\":{\"nxdomain\":1}") && text.contains("\"serial\":2026110301"),
        "{text}"
    );
    assert!(text.contains("applied rpz.policy") && text.contains("unchanged"), "{text}");
    assert!(text.contains("unknown command `bogus`"), "{text}");
    assert!(text.contains("\"allowlisted\":1") && text.contains("\"serial\":2026110302"), "{text}");
    assert_eq!(text.matches("\"serial\"").count(), TWICE);
    assert!(fs::read_to_string(&zone)?.contains(" 2026110302 "));
    Ok(())
}


#[test]
fn a_failed_run_is_reported_and_the_session_goes_on() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text(""))?;
    let policy = engine_for(&path)?;
    let counter = dir.path().join("counter");
    let zone = dir.path().join("zone.db");
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &open_missing,
        counter: &counter,
        output: &zone,
        report: &mut report,
    };
    run_session(&mut session, &mut Cursor::new("run\nrun\n"))?;
    let text = String::from_utf8(report)?;
    assert_eq!(text.matches("failed ").count(), TWICE, "{text}");
    assert!(!zone.exists());
    Ok(())
}


#[test]
fn failures_of_the_report_and_the_input_propagate() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text(""))?;
    let policy = engine_for(&path)?;
    let counter = dir.path().join("counter");
    let zone = dir.path().join("zone.db");
    let attempt = |command: &str, room: usize, open: &dyn Fn() -> io::Result<Box<dyn BufRead>>| {
        let mut report = LimitedWriter { remaining: room };
        let mut session = Session {
            engine: &policy,
            clock: &now,
            open,
            counter: &counter,
            output: &zone,
            report: &mut report,
        };
        run_command(&mut session, command)
    };
    assert!(attempt("run", 0, &open_iocs).is_err());
    assert!(attempt("run", 0, &open_missing).is_err());
    assert!(attempt("reload", 0, &open_iocs).is_err());
    assert!(attempt("bogus", 0, &open_iocs).is_err());
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &open_iocs,
        counter: &counter,
        output: &zone,
        report: &mut report,
    };
    let mut unreadable = Cursor::new(b"\xff\xfe\n".to_vec());
    assert!(run_session(&mut session, &mut unreadable).is_err());
    Ok(())
}
