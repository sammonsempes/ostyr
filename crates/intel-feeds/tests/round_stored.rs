#[path = "common/types.rs"]
mod types;


use core_config::load::load_file;
use intel_feeds::budget::Stored;
use intel_feeds::config::{ClickhouseConfig, FeedConfig, FeedsFile};
use intel_feeds::error::TaxiiError;
use intel_feeds::limits::MAX_READ_ROWS;
use intel_feeds::load::{LoadError, LoadOutcome};
use intel_feeds::model::{FeedSummary, Ioc, IocType, Source, Tags, Tlp};
use intel_feeds::read::ReadError;
use intel_feeds::round::{cursor_key, log_stored_cap, run_round, RoundHooks};
use intel_feeds::taxii::{CursorStatus, PollOutcome};
use intel_feeds::types::{CursorKey, Cursors};
use std::cell::Cell;
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


const FEEDS: &str =
    "feeds:\n  - name: broken\n    format: crowdsec\n    path: missing.txt\n  - name: good\n    format: crowdsec\n    path: good.txt\n  \
    - name: tx\n    format: taxii21\n    taxii:\n      api_root: http://127.0.0.1:9\n      collection: c1\n      user: u\n      password_file: /x\n";


const CLICKHOUSE: &str =
    "clickhouse:\n  url: http://127.0.0.1:9\n  user: u\n  password_file: /x\n  database: d\n  table: t\n  dictionary: dd\n  tenant: tenant-a\n";


const HOSTILE_NAME: &str = "big\u{1b}[31mfeed";


const LIVE_BIG: u64 = 9;


fn config() -> Result<FeedsFile, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    fs::write(&path, format!("{FEEDS}{CLICKHOUSE}"))?;
    Ok(load_file(&path)?)
}


fn tx_key(config: &FeedsFile) -> Result<CursorKey, Box<dyn std::error::Error>> {
    let feed = config.feeds.iter().find(|feed| feed.name == "tx").ok_or("no tx feed")?;
    Ok(cursor_key(feed).ok_or("tx is not taxii")?)
}


fn open(path: &Path) -> io::Result<Box<dyn BufRead>> {
    if path == Path::new("good.txt") {
        Ok(Box::new(Cursor::new("192.0.2.1\n198.51.100.0/24\n")))
    } else {
        Err(io::Error::from(ErrorKind::NotFound))
    }
}


fn stored_ok(_config: &ClickhouseConfig, iocs: &[Ioc], _feeds: &[FeedConfig], _now: OffsetDateTime) -> Result<LoadOutcome, LoadError> {
    Ok(LoadOutcome {
        rows_per_batch: vec![iocs.len()],
        batches_planned: 1,
        ..LoadOutcome::default()
    })
}


fn one_ioc() -> Ioc {
    Ioc {
        ioc_type: IocType::Ipv4,
        value: "203.0.113.9".to_owned(),
        sources: vec![Source {
            feed: "tx".to_owned(),
            version: "1".to_owned(),
        }],
        first_seen: NOW,
        last_seen: NOW,
        confidence: 1,
        tlp: Tlp::Amber,
        expires_at: None,
        tags: Tags::default(),
    }
}


fn one_poll(_feed: &FeedConfig, _cursor: Option<OffsetDateTime>, _now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    Ok(PollOutcome {
        iocs: vec![one_ioc()],
        summary: FeedSummary {
            feed: "tx".to_owned(),
            ..FeedSummary::default()
        },
        next_added_after: Some(NEXT),
        cursor: CursorStatus::Advanced,
        pages: 1,
        more_left: false,
        next_refused: false,
    })
}


fn crowded(_config: &ClickhouseConfig, _now: OffsetDateTime) -> Result<Stored, ReadError> {
    Ok(Stored {
        keys: (0..MAX_READ_ROWS - 1)
            .map(|number| (IocType::Domain, format!("d{number}.example")))
            .collect(),
        live: MAX_READ_ROWS - 1,
        bytes: 0,
        exceeded: false,
        top: vec![(HOSTILE_NAME.to_owned(), LIVE_BIG), ("other".to_owned(), 1)],
    })
}


fn over(_config: &ClickhouseConfig, _now: OffsetDateTime) -> Result<Stored, ReadError> {
    Ok(Stored {
        exceeded: true,
        live: MAX_READ_ROWS + 1,
        ..Stored::default()
    })
}


fn unreadable(_config: &ClickhouseConfig, _now: OffsetDateTime) -> Result<Stored, ReadError> {
    Err(ReadError::MalformedReply)
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


#[test]
fn a_feed_over_the_stored_bound_is_left_out_named_and_its_cursor_still_moves_for_the_admitted_one() -> TestResult {
    LazyLock::force(&ANCHOR);
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &one_poll,
        load: &stored_ok,
        stored: &crowded,
    };
    let loader = config()?;
    let mut cursors = Cursors::new();
    let report = tracing::subscriber::with_default(subscriber, || run_round(&loader, &mut cursors, &hooks));
    assert_eq!(report.failed_feeds, vec!["broken".to_owned(), "good".to_owned()]);
    assert_eq!(report.iocs, 1);
    assert_eq!(cursors.get(&tx_key(&loader)?), Some(&NEXT));
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(
        logged.contains("intel feeds left out: stored bound") && logged.contains("names=\"good\""),
        "{logged}"
    );
    assert!(logged.contains("u{1b}") && logged.contains("feed=9"), "{logged}");
    assert!(!logged.contains('\u{1b}'));
    Ok(())
}


#[test]
fn a_table_already_over_its_cap_admits_no_feed_and_holds_every_cursor() -> TestResult {
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &one_poll,
        load: &stored_ok,
        stored: &over,
    };
    let loader = config()?;
    let mut cursors = Cursors::new();
    cursors.insert(tx_key(&loader)?, OLDER);
    let report = run_round(&loader, &mut cursors, &hooks);
    assert_eq!(report.failed_feeds, vec!["broken".to_owned(), "good".to_owned(), "tx".to_owned()]);
    assert_eq!(report.iocs, 0);
    assert_eq!(cursors.get(&tx_key(&loader)?), Some(&OLDER));
    Ok(())
}


#[test]
fn an_unreadable_stored_count_is_a_failed_round_that_reads_polls_and_loads_nothing() -> TestResult {
    let touched = Cell::new(0);
    let counting_open = |path: &Path| {
        touched.set(touched.get() + 1);
        open(path)
    };
    let counting_poll = |feed: &FeedConfig, cursor: Option<OffsetDateTime>, now: OffsetDateTime| {
        touched.set(touched.get() + 1);
        one_poll(feed, cursor, now)
    };
    let counting_load = |config: &ClickhouseConfig, iocs: &[Ioc], feeds: &[FeedConfig], now: OffsetDateTime| {
        touched.set(touched.get() + 1);
        stored_ok(config, iocs, feeds, now)
    };
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &counting_open,
        poll: &counting_poll,
        load: &counting_load,
        stored: &unreadable,
    };
    let loader = config()?;
    let mut cursors = Cursors::new();
    cursors.insert(tx_key(&loader)?, OLDER);
    let report = run_round(&loader, &mut cursors, &hooks);
    assert_eq!(touched.get(), 0);
    assert_eq!((report.feeds, report.iocs, report.load.is_none()), (THREE, 0, true));
    assert!(report.load_error.is_some_and(|text| text.starts_with("stored_count_unreadable")));
    assert_eq!(cursors.get(&tx_key(&loader)?), Some(&OLDER));
    Ok(())
}


#[test]
fn the_stored_read_gets_the_snapshot_settings_and_the_round_clock() -> TestResult {
    let seen = Cell::new(false);
    let watching = |config: &ClickhouseConfig, now: OffsetDateTime| {
        seen.set(config.tenant == "tenant-a" && now == NOW);
        Ok::<Stored, ReadError>(Stored::default())
    };
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open,
        poll: &one_poll,
        load: &stored_ok,
        stored: &watching,
    };
    run_round(&config()?, &mut Cursors::new(), &hooks);
    assert!(seen.get());
    Ok(())
}


#[test]
fn nothing_is_logged_when_no_feed_was_left_out_for_the_stored_bound() -> TestResult {
    LazyLock::force(&ANCHOR);
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
    let quiet = [FeedSummary {
        feed: "a".to_owned(),
        failed: Some("round_ioc_cap: x".to_owned()),
        ..FeedSummary::default()
    }];
    tracing::subscriber::with_default(subscriber, || log_stored_cap(&quiet, &Stored::default()));
    assert!(capture.0.lock().map_err(|_| "poisoned")?.is_empty());
    Ok(())
}


fn open_empty(_path: &Path) -> io::Result<Box<dyn BufRead>> {
    Ok(Box::new(Cursor::new("[]")))
}


fn plain(_config: &ClickhouseConfig, _now: OffsetDateTime) -> Result<Stored, ReadError> {
    Ok(Stored::default())
}


#[test]
fn an_empty_document_is_logged_per_feed_and_counted_in_the_round() -> TestResult {
    LazyLock::force(&ANCHOR);
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    let feeds = "feeds:\n  - name: hollow\n    format: json\n    path: empty.json\n";
    fs::write(&path, format!("{feeds}{CLICKHOUSE}"))?;
    let loader: FeedsFile = load_file(&path)?;
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
    let hooks = RoundHooks {
        clock: &|| NOW,
        open: &open_empty,
        poll: &one_poll,
        load: &stored_ok,
        stored: &plain,
    };
    let report = tracing::subscriber::with_default(subscriber, || run_round(&loader, &mut Cursors::new(), &hooks));
    assert_eq!((report.warned, report.failed_feeds.len()), (1, 0));
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(
        logged.contains("intel feed warning") && logged.contains("feed=\"hollow\"") && logged.contains("warning=\"empty_document\""),
        "{logged}"
    );
    assert!(logged.contains("warned=1"), "{logged}");
    Ok(())
}


#[test]
fn a_byte_refusal_is_named_in_the_stored_bound_warning() -> TestResult {
    LazyLock::force(&ANCHOR);
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish();
    let left = [FeedSummary {
        feed: "heavy".to_owned(),
        failed: Some("stored_ioc_bytes: x".to_owned()),
        ..FeedSummary::default()
    }];
    let stored = Stored {
        bytes: LIVE_BIG,
        ..Stored::default()
    };
    tracing::subscriber::with_default(subscriber, || log_stored_cap(&left, &stored));
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains("names=\"heavy\"") && logged.contains("bytes=9"), "{logged}");
    Ok(())
}
