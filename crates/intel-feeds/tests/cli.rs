#[path = "common/clock.rs"]
mod clock;
#[path = "common/engine.rs"]
mod engine;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/types.rs"]
mod types;


use clock::now;
use engine::{engine_for, feeds_text, replace_file};
use intel_feeds::cli::{run_command, run_session, write_summaries, Session};
use intel_feeds::model::FeedSummary;
use memory::{open_from, FailingWriter};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use tempfile::tempdir;
use types::TestResult;


const EXPECTED_IOCS: usize = 3;


const SECOND_FEED: &str = "  - name: extra\n    format: crowdsec\n    path: extra.txt\n";


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


#[test]
fn a_session_runs_reloads_lists_and_stops_at_quit() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(""))?;
    let feeding = engine_for(&path)?;
    let files = BTreeMap::from([("base.txt", "192.0.2.1\n"), ("extra.txt", "192.0.2.2\n")]);
    let open = |file: &std::path::Path| open_from(&files, file);
    let mut out = Vec::new();
    let mut report = Vec::new();
    let mut session = Session {
        engine: &feeding,
        clock: &now,
        open: &open,
        out: &mut out,
        report: &mut report,
    };
    replace_file(&path, &feeds_text(SECOND_FEED))?;
    let mut input = Cursor::new("feeds\nrun\nreload\nreload\nbogus\nrun\nquit\nfeeds\n");
    run_session(&mut session, &mut input)?;
    let iocs = String::from_utf8(out)?;
    assert_eq!(iocs.lines().count(), EXPECTED_IOCS);
    let text = String::from_utf8(report)?;
    assert!(text.contains("applied feeds.extra"), "{text}");
    assert!(text.contains("unchanged"), "{text}");
    assert!(text.contains("unknown command `bogus`"), "{text}");
    assert_eq!(text.matches("base\n").count(), 1);
    Ok(())
}


#[test]
fn failures_of_the_streams_propagate() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(""))?;
    let feeding = engine_for(&path)?;
    let files = BTreeMap::from([("base.txt", "192.0.2.1\n")]);
    let open = |file: &std::path::Path| open_from(&files, file);
    let mut report = Vec::new();
    let mut session = Session {
        engine: &feeding,
        clock: &now,
        open: &open,
        out: &mut FailingWriter,
        report: &mut report,
    };
    assert!(run_command(&mut session, "run").is_err());
    let mut broken: Box<dyn BufRead> = Box::new(BufReader::new(Broken));
    assert!(run_session(&mut session, &mut broken).is_err());
    let mut out = Vec::new();
    let mut failing_report = Session {
        engine: &feeding,
        clock: &now,
        open: &open,
        out: &mut out,
        report: &mut FailingWriter,
    };
    assert!(run_command(&mut failing_report, "run").is_err());
    assert!(write_summaries(&[FeedSummary::default()], &mut FailingWriter).is_err());
    Ok(())
}
