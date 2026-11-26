#[path = "common/types.rs"]
mod types;


use core_config::load::load_file;
use intel_feeds::config::{ClickhouseConfig, FeedConfig, FeedsFile};
use intel_feeds::error::TaxiiError;
use intel_feeds::load::{BatchFailure, LoadError, LoadOutcome};
use intel_feeds::model::{FeedSummary, Ioc};
use intel_feeds::round::{run_round, RoundHooks, NO_CLICKHOUSE};
use intel_feeds::taxii::{CursorStatus, PollOutcome};
use intel_feeds::types::Cursors;
use siem_ingest::error::InsertClass;
use std::cell::{Cell, RefCell};
use std::fs;
use std::io::{self, BufRead, Cursor, ErrorKind, Write};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;
use tracing::Dispatch;
use types::TestResult;


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const NEXT: OffsetDateTime = datetime!(2026-11-03 11:00:00 UTC);


const OLDER: OffsetDateTime = datetime!(2026-11-03 10:00:00 UTC);


const THREE: usize = 3;


const FIVE_PAGES: u32 = 5;


const TWO: usize = 2;


const CLEAN_FEEDS: &str = "feeds:\n  - name: good\n    format: crowdsec\n    path: good.txt\n";


const CLICKHOUSE: &str =
    "clickhouse:\n  url: http://127.0.0.1:9\n  user: u\n  password_file: /x\n  database: d\n  table: t\n  dictionary: dd\n  tenant: tenant-a\n";


const FEEDS: &str =
    "feeds:\n  - name: broken\n    format: crowdsec\n    path: missing.txt\n  - name: good\n    format: crowdsec\n    path: good.txt\n  \
    - name: tx\n    format: taxii21\n    taxii:\n      api_root: http://127.0.0.1:9\n      collection: c1\n      user: u\n      password_file: /x\n";


fn config(with_clickhouse: bool) -> Result<FeedsFile, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    let text = if with_clickhouse {
        format!("{FEEDS}{CLICKHOUSE}")
    } else {
        FEEDS.to_owned()
    };
    fs::write(&path, text)?;
    Ok(load_file(&path)?)
}


fn open(path: &Path) -> io::Result<Box<dyn BufRead>> {
    if path == Path::new("good.txt") {
        Ok(Box::new(Cursor::new("192.0.2.1\n198.51.100.0/24\n")))
    } else {
        Err(io::Error::from(ErrorKind::NotFound))
    }
}


fn stored(_config: &ClickhouseConfig, iocs: &[Ioc], _feeds: &[FeedConfig], _now: OffsetDateTime) -> Result<LoadOutcome, LoadError> {
    Ok(LoadOutcome {
        rows_per_batch: vec![iocs.len()],
        batches_planned: 1,
        ..LoadOutcome::default()
    })
}


fn refused(_config: &ClickhouseConfig, iocs: &[Ioc], _feeds: &[FeedConfig], _now: OffsetDateTime) -> Result<LoadOutcome, LoadError> {
    Ok(LoadOutcome {
        rows_per_batch: Vec::new(),
        batches_planned: 1,
        not_canonical: 0,
        failure: Some(BatchFailure {
            index: 0,
            rows: iocs.len(),
            class: InsertClass::Timeout,
        }),
    })
}


fn polled(_feed: &FeedConfig, _cursor: Option<OffsetDateTime>, _now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    Ok(PollOutcome {
        iocs: Vec::new(),
        summary: FeedSummary::default(),
        next_added_after: Some(NEXT),
        cursor: CursorStatus::Advanced,
        pages: 1,
        more_left: false,
        next_refused: false,
    })
}


fn failed_poll(_feed: &FeedConfig, _cursor: Option<OffsetDateTime>, _now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    Err(TaxiiError::Unavailable)
}


#[test]
fn a_failed_feed_is_named_and_the_others_still_load() -> TestResult {
    let calls = Cell::new(0);
    let load = |clickhouse: &ClickhouseConfig, iocs: &[Ioc], feeds: &[FeedConfig], now| {
        calls.set(calls.get() + 1);
        stored(clickhouse, iocs, feeds, now)
    };
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &failed_poll,
        load: &load,
    };
    let report = run_round(&config(true)?, &mut Cursors::new(), &hooks);
    assert_eq!(report.feeds, THREE);
    assert_eq!(report.failed_feeds, vec!["broken".to_owned(), "tx".to_owned()]);
    assert_eq!(report.iocs, TWO);
    assert_eq!(calls.get(), 1);
    assert_eq!(report.load.map(|summary| summary.clickhouse_rows_sent), Some(TWO));
    assert_eq!(report.load_error, None);
    Ok(())
}


#[test]
fn a_cursor_moves_only_after_a_stored_load() -> TestResult {
    let mut cursors = Cursors::new();
    cursors.insert("tx".to_owned(), OLDER);
    let seen = RefCell::new(Vec::new());
    let poll = |feed: &FeedConfig, cursor: Option<OffsetDateTime>, now| {
        seen.borrow_mut().push(cursor);
        polled(feed, cursor, now)
    };
    let refusing = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &poll,
        load: &refused,
    };
    let loader = config(true)?;
    let first = run_round(&loader, &mut cursors, &refusing);
    assert!(first.load_error.is_some());
    assert_eq!(cursors.get("tx"), Some(&OLDER));
    let storing = RoundHooks { load: &stored, ..refusing };
    let second = run_round(&loader, &mut cursors, &storing);
    assert_eq!(second.load_error, None);
    assert_eq!(cursors.get("tx"), Some(&NEXT));
    assert_eq!(*seen.borrow(), vec![Some(OLDER), Some(OLDER)]);
    Ok(())
}


#[test]
fn a_settings_without_clickhouse_is_a_named_failed_round() -> TestResult {
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &polled,
        load: &stored,
    };
    let mut cursors = Cursors::new();
    let report = run_round(&config(false)?, &mut cursors, &hooks);
    assert_eq!(report.load, None);
    assert_eq!(report.load_error.as_deref(), Some(NO_CLICKHOUSE));
    assert!(cursors.is_empty());
    Ok(())
}


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn cut_poll(_feed: &FeedConfig, _cursor: Option<OffsetDateTime>, _now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    Ok(PollOutcome {
        iocs: Vec::new(),
        summary: FeedSummary::default(),
        next_added_after: Some(NEXT),
        cursor: CursorStatus::Advanced,
        pages: FIVE_PAGES,
        more_left: true,
        next_refused: false,
    })
}


#[test]
fn a_poll_cut_short_and_a_failed_round_are_named_in_the_log() -> TestResult {
    LazyLock::force(&ANCHOR);
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &cut_poll,
        load: &stored,
    };
    let loader = config(true)?;
    tracing::subscriber::with_default(subscriber, || run_round(&loader, &mut Cursors::new(), &hooks));
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("intel taxii poll stopped early"), "{logged}");
    assert!(logged.contains("more_left=true") && logged.contains("pages=5"), "{logged}");
    assert!(logged.contains("intel round failed") && logged.contains("names=\"broken\""), "{logged}");
    Ok(())
}


#[test]
fn a_clean_round_has_no_failed_feed_and_no_load_error() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    fs::write(&path, format!("{CLEAN_FEEDS}{CLICKHOUSE}"))?;
    let clean: FeedsFile = load_file(&path)?;
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &polled,
        load: &stored,
    };
    let mut cursors = Cursors::new();
    let report = run_round(&clean, &mut cursors, &hooks);
    assert!(report.failed_feeds.is_empty() && report.load_error.is_none());
    assert_eq!(report.iocs, TWO);
    assert!(cursors.is_empty());
    Ok(())
}


fn next_refused_poll(feed: &FeedConfig, cursor: Option<OffsetDateTime>, now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    Ok(PollOutcome {
        more_left: false,
        next_refused: true,
        ..polled(feed, cursor, now)?
    })
}


#[test]
fn a_refused_load_alone_and_a_refused_next_are_failures_by_name() -> TestResult {
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &next_refused_poll,
        load: &refused,
    };
    let report = run_round(&config(true)?, &mut Cursors::new(), &hooks);
    assert!(report.load_error.is_some());
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    fs::write(&path, format!("{CLEAN_FEEDS}{CLICKHOUSE}"))?;
    let clean: FeedsFile = load_file(&path)?;
    let refusing = run_round(&clean, &mut Cursors::new(), &hooks);
    assert!(refusing.failed_feeds.is_empty());
    assert_eq!(refusing.load_error.as_deref(), Some("batch refused: Timeout"));
    Ok(())
}
