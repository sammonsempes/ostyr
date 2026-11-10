#[path = "common/clock.rs"]
mod clock;
#[path = "common/engine.rs"]
mod engine;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/noload.rs"]
mod noload;
#[path = "common/types.rs"]
mod types;


use clock::now;
use engine::{engine_for, feeds_text, replace_file};
use intel_feeds::cli::{run_command, run_session, write_summaries, Session};
use intel_feeds::config::{ClickhouseConfig, FeedConfig};
use intel_feeds::load::LoadOutcome;
use intel_feeds::model::{FeedSummary, Ioc};
use memory::{open_from, FailingWriter};
use noload::no_load;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Cursor, Read};
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const EXPECTED_IOCS: usize = 3;


const EXPECTED_ROWS: usize = 2;


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
        load: &no_load,
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
        load: &no_load,
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
        load: &no_load,
        out: &mut out,
        report: &mut FailingWriter,
    };
    assert!(run_command(&mut failing_report, "run").is_err());
    assert!(write_summaries(&[FeedSummary::default()], &mut FailingWriter).is_err());
    Ok(())
}


const CLICKHOUSE_SECTION: &str = "clickhouse:\n  url: https://ch.example:8443\n  user: ostyr\n  password_file: /etc/ostyr/ch.pw\n  database: ostyr\n  table: iocs\n  dictionary: trie\n  tenant: tenant-a\n";


struct StopAfter {
    left: usize,
}


impl io::Write for StopAfter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.left == 0 {
            Err(io::Error::other("injected"))
        } else {
            let taken = buffer.len().min(self.left);
            self.left -= taken;
            Ok(taken)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn run_loads_into_clickhouse_when_configured_and_reports_the_summary() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(CLICKHOUSE_SECTION))?;
    let feeding = engine_for(&path)?;
    let files = BTreeMap::from([("base.txt", "192.0.2.1\n192.0.2.2\n")]);
    let open = |file: &std::path::Path| open_from(&files, file);
    let loaded = std::cell::RefCell::new(Vec::new());
    let load = |config: &ClickhouseConfig, iocs: &[Ioc], _feeds: &[FeedConfig], _now: OffsetDateTime| {
        loaded.borrow_mut().push((config.tenant.clone(), iocs.len()));
        Ok(LoadOutcome {
            rows_per_batch: vec![iocs.len()],
            batches_planned: 1,
            failure: None,
        })
    };
    let mut out = Vec::new();
    let mut report = Vec::new();
    let mut session = Session {
        engine: &feeding,
        clock: &now,
        open: &open,
        load: &load,
        out: &mut out,
        report: &mut report,
    };
    run_command(&mut session, "run")?;
    assert_eq!(*loaded.borrow(), vec![("tenant-a".to_owned(), EXPECTED_ROWS)]);
    let text = String::from_utf8(report.clone())?;
    let last = text.lines().last().ok_or("no summary")?;
    assert!(last.contains("\"clickhouse_rows_sent\":2"), "{last}");
    assert!(last.contains("\"clickhouse_batches_failed\":0"), "{last}");
    let first_pass = text.lines().next().ok_or("no feed summary")?.len() + 1;
    let mut cut = StopAfter { left: first_pass };
    let mut failing = Session {
        engine: &feeding,
        clock: &now,
        open: &open,
        load: &load,
        out: &mut Vec::new(),
        report: &mut cut,
    };
    assert!(run_command(&mut failing, "run").is_err());
    Ok(())
}
