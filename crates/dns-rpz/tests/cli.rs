#[path = "common/clock.rs"]
mod clock;
#[path = "common/engine.rs"]
mod engine;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/runner.rs"]
mod runner;
#[path = "common/types.rs"]
mod types;


use clock::now;
use dns_rpz::cli::{run_command, run_session, Session};
use dns_rpz::model::Reloader;
use engine::{audit, context, engine_for, policy_text, replace_file};
use memory::LimitedWriter;
use runner::{failing_runner, succeeding_runner};
use std::fs;
use std::io::{self, BufRead, Cursor};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const TWICE: usize = 2;


const IOC: &str = "{\"ioc_type\":\"domain\",\"value\":\"evil.example.com\",\"sources\":[],\"first_seen\":\"2026-11-01T00:00:00Z\",\
\"last_seen\":\"2026-11-03T00:00:00Z\",\"confidence\":90,\"tlp\":\"amber\",\"expires_at\":null,\"tags\":{\"malware\":[],\"actor\":[],\"campaign\":[]}}\n";


fn open_iocs(_now: OffsetDateTime) -> io::Result<Box<dyn BufRead>> {
    Ok(Box::new(Cursor::new(IOC.as_bytes().to_vec())))
}


fn open_missing(_now: OffsetDateTime) -> io::Result<Box<dyn BufRead>> {
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
    let sink = audit();
    let zone_context = context();
    let reloader = Reloader {
        runner: &succeeding_runner,
        audit: &*sink,
        context: &zone_context,
    };
    let rejected = AtomicU64::new(0);
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &open_iocs,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
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
    let sink = audit();
    let zone_context = context();
    let reloader = Reloader {
        runner: &succeeding_runner,
        audit: &*sink,
        context: &zone_context,
    };
    let rejected = AtomicU64::new(0);
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &open_missing,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
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
    let sink = audit();
    let zone_context = context();
    let reloader = Reloader {
        runner: &succeeding_runner,
        audit: &*sink,
        context: &zone_context,
    };
    let rejected = AtomicU64::new(0);
    let attempt = |command: &str, room: usize, open: &dyn Fn(OffsetDateTime) -> io::Result<Box<dyn BufRead>>| {
        let mut report = LimitedWriter { remaining: room };
        let mut session = Session {
            engine: &policy,
            clock: &now,
            open,
            rejected: &rejected,
            counter: &counter,
            output: &zone,
            report: &mut report,
            reloader: &reloader,
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
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
    };
    let mut unreadable = Cursor::new(b"\xff\xfe\n".to_vec());
    assert!(run_session(&mut session, &mut unreadable).is_err());
    Ok(())
}


#[test]
fn a_failed_zone_reload_is_reported_after_the_summary() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text(""))?;
    let policy = engine_for(&path)?;
    let counter = dir.path().join("counter");
    let zone = dir.path().join("zone.db");
    let sink = audit();
    let zone_context = context();
    let reloader = Reloader {
        runner: &failing_runner,
        audit: &*sink,
        context: &zone_context,
    };
    let rejected = AtomicU64::new(0);
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &open_iocs,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
    };
    run_session(&mut session, &mut Cursor::new("run\n"))?;
    let text = String::from_utf8(report)?;
    assert!(text.contains("\"serial\":2026110301") && text.contains("failed reload"), "{text}");
    assert!(zone.exists());
    Ok(())
}


#[test]
fn one_run_reads_the_clock_once_and_the_source_and_the_zone_share_it() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text(""))?;
    let policy = engine_for(&path)?;
    let counter = dir.path().join("counter");
    let zone = dir.path().join("zone.db");
    let sink = audit();
    let zone_context = context();
    let reloader = Reloader {
        runner: &succeeding_runner,
        audit: &*sink,
        context: &zone_context,
    };
    let rejected = AtomicU64::new(0);
    let reads = AtomicUsize::new(0);
    let counting_clock = || {
        reads.fetch_add(1, Ordering::Relaxed);
        now()
    };
    let seen = Mutex::new(Vec::new());
    let recording_open = |instant: OffsetDateTime| {
        seen.lock().map_err(|_| io::Error::other("poisoned"))?.push(instant);
        open_iocs(instant)
    };
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &counting_clock,
        open: &recording_open,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
    };
    run_session(&mut session, &mut Cursor::new("run\n"))?;
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(*seen.lock().map_err(|_| "poisoned")?, vec![now()]);
    assert!(String::from_utf8(report)?.contains("\"serial\":2026110301"));
    Ok(())
}
