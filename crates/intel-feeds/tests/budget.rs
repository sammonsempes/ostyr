#[path = "common/clock.rs"]
mod clock;
#[path = "common/nostored.rs"]
mod nostored;
#[path = "common/parsing.rs"]
mod parsing;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use clock::now;
use core_config::load::load_file;
use intel_feeds::budget::Stored;
use intel_feeds::config::{ClickhouseConfig, FeedConfig, FeedFormat, FeedsFile};
use intel_feeds::error::{FeedError, TaxiiError};
use intel_feeds::formats::parse_feed;
use intel_feeds::limits::{MAX_FEED_IOCS, MAX_ROUND_IOCS};
use intel_feeds::load::{LoadError, LoadOutcome};
use intel_feeds::model::{Collector, FeedSummary, Ioc, IocType, Source, Tags, Tlp};
use intel_feeds::round::{cursor_key, run_round, RoundHooks};
use intel_feeds::run::merge_collected;
use intel_feeds::taxii::{CursorStatus, PollOutcome};
use intel_feeds::types::{Cursors, IocIndex};
use nostored::no_stored;
use parsing::parse_text;
use std::cell::Cell;
use std::fs;
use std::io::{self, BufRead, BufReader, Cursor, ErrorKind, Read};
use std::ops::Range;
use std::path::Path;
use support::feed;
use tempfile::tempdir;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use types::TestResult;


const OCTET: usize = 256;


const TWO: usize = 2;


const SLACK_LINES: usize = 1_000;


const BUFFER_BYTES: usize = 4_096;


const NEXT: OffsetDateTime = datetime!(2026-11-03 11:00:00 UTC);


const FEEDS: &str = "feeds:\n  - name: big\n    format: crowdsec\n    path: big.txt\n  - name: good\n    format: crowdsec\n    path: good.txt\n  \
    - name: tx\n    format: taxii21\n    taxii:\n      api_root: http://127.0.0.1:9\n      collection: c1\n      user: u\n      password_file: /x\n";


const CLICKHOUSE: &str =
    "clickhouse:\n  url: http://127.0.0.1:9\n  user: u\n  password_file: /x\n  database: d\n  table: t\n  dictionary: dd\n  tenant: tenant-a\n";


fn address(number: usize) -> String {
    format!("10.{}.{}.{}", (number / OCTET / OCTET) % OCTET, (number / OCTET) % OCTET, number % OCTET)
}


fn lines(count: usize) -> String {
    (0..count).map(|number| format!("{}\n", address(number))).collect()
}


fn ioc(value: String, expires_at: Option<OffsetDateTime>) -> Ioc {
    Ioc {
        ioc_type: IocType::Ipv4,
        value,
        sources: vec![Source {
            feed: "f".to_owned(),
            version: "1".to_owned(),
        }],
        first_seen: now(),
        last_seen: now(),
        confidence: 1,
        tlp: Tlp::Amber,
        expires_at,
        tags: Tags::default(),
    }
}


fn collector(name: &str, range: Range<usize>) -> Collector {
    Collector {
        iocs: range.map(|number| ioc(address(number), None)).collect(),
        summary: FeedSummary {
            feed: name.to_owned(),
            ..FeedSummary::default()
        },
    }
}


#[test]
fn a_file_feed_over_the_ioc_cap_fails_whole_and_one_at_the_cap_loads() -> TestResult {
    let crowdsec = feed("crowdsec", FeedFormat::Crowdsec);
    assert_eq!(parse_text(&crowdsec, &lines(MAX_FEED_IOCS))?.iocs.len(), MAX_FEED_IOCS);
    let refused = parse_text(&crowdsec, &lines(MAX_FEED_IOCS + 1))
        .err()
        .ok_or("the feed over the cap loaded")?;
    assert!(matches!(refused, FeedError::TooManyIocs));
    assert!(refused.to_string().starts_with("too_many_iocs"));
    let mut json = feed("list", FeedFormat::Json);
    json.mapping.value = Some("ioc".to_owned());
    let items = (0..=MAX_FEED_IOCS)
        .map(|number| format!("{{\"ioc\":\"{}\"}}", address(number)))
        .collect::<Vec<_>>()
        .join(",");
    assert!(matches!(parse_text(&json, &format!("[{items}]")), Err(FeedError::TooManyIocs)));
    Ok(())
}


#[test]
fn a_feed_that_would_take_the_round_over_its_total_is_left_out_whole() -> TestResult {
    let mut index = IocIndex::new();
    let first = merge_collected(collector("a", 0..MAX_ROUND_IOCS), now(), &mut index, &Stored::default());
    assert_eq!(first.failed, None);
    assert_eq!(index.len(), MAX_ROUND_IOCS);
    let over = merge_collected(collector("b", MAX_ROUND_IOCS..MAX_ROUND_IOCS + 1), now(), &mut index, &Stored::default());
    assert!(over.failed.is_some_and(|reason| reason.starts_with("round_ioc_cap")));
    assert_eq!(index.len(), MAX_ROUND_IOCS);
    let known = merge_collected(collector("c", 0..1), now(), &mut index, &Stored::default());
    assert_eq!((known.failed, known.duplicates), (None, 1));
    let mut stale = collector("d", MAX_ROUND_IOCS..MAX_ROUND_IOCS + 1);
    stale.iocs.iter_mut().for_each(|item| item.expires_at = Some(now() - Duration::SECOND));
    let expired = merge_collected(stale, now(), &mut index, &Stored::default());
    assert_eq!((expired.failed, expired.expired), (None, 1));
    assert_eq!(index.len(), MAX_ROUND_IOCS);
    Ok(())
}


fn config() -> Result<FeedsFile, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    fs::write(&path, format!("{FEEDS}{CLICKHOUSE}"))?;
    Ok(load_file(&path)?)
}


fn open(path: &Path) -> io::Result<Box<dyn BufRead>> {
    if path == Path::new("big.txt") {
        Ok(Box::new(Cursor::new(lines(MAX_FEED_IOCS + 1))))
    } else if path == Path::new("good.txt") {
        Ok(Box::new(Cursor::new(lines(TWO))))
    } else {
        Err(io::Error::from(ErrorKind::NotFound))
    }
}


fn many(_feed: &FeedConfig, _cursor: Option<OffsetDateTime>, _now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    Ok(PollOutcome {
        iocs: (0..MAX_ROUND_IOCS).map(|number| ioc(address(number + TWO), None)).collect(),
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


#[test]
fn a_round_names_the_feeds_left_out_keeps_the_others_and_holds_the_cursor_back() -> TestResult {
    let rows = Cell::new(0);
    let load = |_config: &ClickhouseConfig, iocs: &[Ioc], _feeds: &[FeedConfig], _now: OffsetDateTime| {
        rows.set(iocs.len());
        Ok::<LoadOutcome, LoadError>(LoadOutcome {
            rows_per_batch: vec![iocs.len()],
            batches_planned: 1,
            ..LoadOutcome::default()
        })
    };
    let hooks = RoundHooks {
        clock: &now,
        open: &open,
        poll: &many,
        load: &load,
        stored: &no_stored,
    };
    let loaded = config()?;
    let mut cursors = Cursors::new();
    let report = run_round(&loaded, &mut cursors, &hooks);
    assert_eq!(report.failed_feeds, vec!["big".to_owned(), "tx".to_owned()]);
    assert_eq!(report.iocs, TWO);
    assert_eq!(rows.get(), TWO);
    assert_eq!(report.load_error, None);
    let key = loaded.feeds.iter().find_map(cursor_key).ok_or("no tx key")?;
    assert_eq!(cursors.get(&key), None);
    Ok(())
}


struct Counting<'a> {
    inner: Cursor<Vec<u8>>,
    consumed: &'a Cell<usize>,
}


impl Read for Counting<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.consumed.set(self.consumed.get() + read);
        Ok(read)
    }
}


#[test]
fn the_count_stops_the_read_before_the_rest_of_the_file_is_parsed() -> TestResult {
    let text = lines(MAX_FEED_IOCS + SLACK_LINES);
    let total = text.len();
    let consumed = Cell::new(0);
    let counting = Counting {
        inner: Cursor::new(text.into_bytes()),
        consumed: &consumed,
    };
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, counting);
    let refused = parse_feed(&feed("crowdsec", FeedFormat::Crowdsec), &mut reader, now());
    assert!(matches!(refused, Err(FeedError::TooManyIocs)));
    assert!(consumed.get() < total);
    Ok(())
}
