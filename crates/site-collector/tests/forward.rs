#[path = "support/types.rs"]
mod types;


use serde_json::Value;
use site_collector::dirfs::open_directory;
use site_collector::error::ForwardError;
use site_collector::forward::{
    build_event, clean_text, cut_text, event_line, event_time, facility_name, file_bytes, forward_once, read_cursor, valid_hostname, write_cursor,
};
use site_collector::forward_model::{ForwardLimits, CURSOR_FILE, CURSOR_TEMPORARY, MAX_FORWARD_MESSAGE_BYTES};
use site_collector::model::{SdElement, SyslogRecord};
use site_collector::spool::{append, open_spool};
use site_collector::spool_model::{Priority, Record, Spool, SpoolConfig, MAX_FRAME_BYTES};
use site_collector::types::DirHandle;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use time::OffsetDateTime;
use types::TestResult;


const NOW_SECONDS: i64 = 1_800_000_000;


const FRAMES_IN_TOTAL: u64 = 3;


const BIG_MESSAGE: usize = 2000;


const LIMIT: usize = 2;


const THREE: u64 = 3;


const TWO: usize = 2;


const THREE_LINES: usize = 3;


const ONE_MIB: u64 = 1 << 20;


const MANY: usize = 100;


const SLACK: usize = 32;


const BAD_BYTES: [u8; 2] = [0xff, 0xfe];


const BAD_BYTE: u8 = 0xff;


const FIVE: u64 = 5;


const SIX: u64 = 6;


const SEVEN: u64 = 7;


const NINE: u64 = 9;


const TEN: usize = 10;


const LONG_HOST: usize = 254;


const AUTH_PRIORITY: u8 = 34;


const FAR_CURSOR: &str = "999\n";


const GOOD: &[u8] = b"<34>1 2026-11-10T10:00:00Z router1 sshd - - - hello";


struct Fixture {
    root: TempDir,
    spool: Spool,
    agent_spool: PathBuf,
}


fn now() -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(NOW_SECONDS)
}


fn limits() -> ForwardLimits {
    ForwardLimits {
        max_records: MANY,
        agent_spool_max_bytes: ONE_MIB,
    }
}


fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let spool_dir = root.path().join("spool");
    fs::create_dir(&spool_dir)?;
    let spool = open_spool(
        &spool_dir,
        SpoolConfig {
            segment_max_bytes: MAX_FRAME_BYTES,
            total_max_bytes: MAX_FRAME_BYTES * FRAMES_IN_TOTAL,
        },
    )?;
    let agent_spool = root.path().join("agent.spool");
    Ok(Fixture { root, spool, agent_spool })
}


fn spool_handle(fixture: &Fixture) -> io::Result<DirHandle> {
    open_directory(&fixture.root.path().join("spool")).map_err(io::Error::other)
}


fn lines_of(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?.lines().map(|line| Ok(serde_json::from_str(line)?)).collect()
}


fn text_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}


fn failing_writer(_dir: &DirHandle, _next: u64) -> io::Result<()> {
    Err(io::Error::other("cursor disk failure"))
}


fn feed(fixture: &mut Fixture, payloads: &[&[u8]]) -> TestResult {
    payloads
        .iter()
        .try_for_each(|payload| append(&mut fixture.spool, Priority::Low, payload).map(|_| ()))?;
    Ok(())
}


#[test]
fn records_are_forwarded_once_and_the_cursor_advances() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[GOOD, GOOD, GOOD])?;
    let report = forward_once(&mut fixture.spool, &fixture.agent_spool, &limits(), now()?, write_cursor)?;
    assert_eq!((report.forwarded, report.skipped_unparsable, report.refused_full), (THREE, 0, 0));
    let events = lines_of(&fixture.agent_spool)?;
    assert_eq!(events.len(), THREE_LINES);
    let first = events.first().ok_or("no event")?;
    assert_eq!(text_at(first, "/event/module"), Some("syslog"));
    assert_eq!(text_at(first, "/event/dataset"), Some("syslog.auth"));
    assert_eq!(text_at(first, "/event/kind"), Some("event"));
    assert_eq!(text_at(first, "/host/name"), Some("router1"));
    assert_eq!(text_at(first, "/message"), Some("hello"));
    assert_eq!(text_at(first, "/labels/syslog_facility"), Some("auth"));
    assert_eq!(text_at(first, "/labels/syslog_severity"), Some("2"));
    assert_eq!(text_at(first, "/labels/syslog_app"), Some("sshd"));
    assert_eq!(text_at(first, "/labels/collector_sequence"), Some("0"));
    assert_eq!(text_at(first, "/labels/syslog_host_claimed"), Some("true"));
    assert_eq!(text_at(first, "/@timestamp"), Some("2026-11-10T10:00:00Z"));
    assert_eq!(read_cursor(&spool_handle(&fixture)?)?, FRAMES_IN_TOTAL);
    let again = forward_once(&mut fixture.spool, &fixture.agent_spool, &limits(), now()?, write_cursor)?;
    assert_eq!(again.forwarded, 0);
    assert_eq!(lines_of(&fixture.agent_spool)?.len(), THREE_LINES);
    Ok(())
}


#[test]
fn a_crash_after_the_append_forwards_the_batch_again() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[GOOD, GOOD])?;
    let crashed = forward_once(&mut fixture.spool, &fixture.agent_spool, &limits(), now()?, failing_writer);
    assert!(matches!(crashed, Err(ForwardError::Io(_))));
    assert_eq!(lines_of(&fixture.agent_spool)?.len(), TWO);
    assert_eq!(read_cursor(&spool_handle(&fixture)?)?, 0);
    forward_once(&mut fixture.spool, &fixture.agent_spool, &limits(), now()?, write_cursor)?;
    let events = lines_of(&fixture.agent_spool)?;
    let sequences = events
        .iter()
        .map(|event| text_at(event, "/labels/collector_sequence").unwrap_or("none"))
        .collect::<Vec<_>>();
    assert_eq!(sequences, ["0", "1", "0", "1"]);
    Ok(())
}


#[test]
fn a_full_agent_spool_keeps_the_cursor() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[GOOD])?;
    fs::write(&fixture.agent_spool, "x\n")?;
    let tight = ForwardLimits {
        agent_spool_max_bytes: 1,
        ..limits()
    };
    let report = forward_once(&mut fixture.spool, &fixture.agent_spool, &tight, now()?, write_cursor)?;
    assert_eq!((report.forwarded, report.refused_full), (0, 1));
    assert_eq!(fs::read_to_string(&fixture.agent_spool)?, "x\n");
    assert_eq!(read_cursor(&spool_handle(&fixture)?)?, 0);
    fs::remove_file(&fixture.agent_spool)?;
    fs::write(root_sending(&fixture), "x\n")?;
    let claimed = forward_once(&mut fixture.spool, &fixture.agent_spool, &tight, now()?, write_cursor)?;
    assert_eq!(claimed.refused_full, 1);
    assert!(!fixture.agent_spool.exists());
    Ok(())
}


fn root_sending(fixture: &Fixture) -> PathBuf {
    fixture.root.path().join("agent.spool.sending")
}


#[test]
fn hostile_messages_are_cleaned_and_cut() -> TestResult {
    let mut fixture = fixture()?;
    let hostile = format!(
        "<13>1 2026-11-10T10:00:00Z ho$t app - - - a\u{0}b\u{1b}[31mred\u{202e}x\nline2 {}",
        "z".repeat(BIG_MESSAGE)
    );
    feed(&mut fixture, &[hostile.as_bytes()])?;
    forward_once(&mut fixture.spool, &fixture.agent_spool, &limits(), now()?, write_cursor)?;
    let raw = fs::read_to_string(&fixture.agent_spool)?;
    assert_eq!(raw.lines().count(), 1);
    let events = lines_of(&fixture.agent_spool)?;
    let event = events.first().ok_or("no event")?;
    let message = text_at(event, "/message").ok_or("no message")?;
    assert!(message.starts_with("ab[31mredxline2 zzz"));
    assert!(!message.contains(['\u{0}', '\u{1b}', '\u{202e}', '\n']));
    assert!(message.ends_with(" bytes cut]"));
    assert!(message.len() < MAX_FORWARD_MESSAGE_BYTES + SLACK);
    assert_eq!(text_at(event, "/host/name"), None);
    assert_eq!(text_at(event, "/labels/syslog_host_raw"), Some("ho$t"));
    Ok(())
}


#[test]
fn a_record_that_no_longer_parses_is_skipped_and_counted() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[b"no priority at all", &BAD_BYTES, GOOD])?;
    let report = forward_once(&mut fixture.spool, &fixture.agent_spool, &limits(), now()?, write_cursor)?;
    assert_eq!((report.forwarded, report.skipped_unparsable), (1, TWO as u64));
    assert_eq!(lines_of(&fixture.agent_spool)?.len(), 1);
    assert_eq!(read_cursor(&spool_handle(&fixture)?)?, FRAMES_IN_TOTAL);
    let only_bad = event_line(
        &Record {
            priority: Priority::Low,
            sequence: 0,
            payload: b"junk".to_vec(),
        },
        "ab",
        now()?,
    );
    assert_eq!(only_bad, None);
    Ok(())
}


#[test]
fn the_batch_is_bounded_by_max_records() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[GOOD, GOOD, GOOD])?;
    let small = ForwardLimits {
        max_records: LIMIT,
        ..limits()
    };
    let first = forward_once(&mut fixture.spool, &fixture.agent_spool, &small, now()?, write_cursor)?;
    let second = forward_once(&mut fixture.spool, &fixture.agent_spool, &small, now()?, write_cursor)?;
    assert_eq!((first.forwarded, second.forwarded), (TWO as u64, 1));
    let huge = ForwardLimits {
        max_records: usize::MAX,
        ..limits()
    };
    assert_eq!(
        forward_once(&mut fixture.spool, &fixture.agent_spool, &huge, now()?, write_cursor)?.forwarded,
        0
    );
    Ok(())
}


#[test]
fn a_cursor_past_the_spool_is_clamped() -> TestResult {
    let mut fixture = fixture()?;
    fs::write(fixture.root.path().join("spool").join(CURSOR_FILE), FAR_CURSOR)?;
    feed(&mut fixture, &[GOOD])?;
    let report = forward_once(&mut fixture.spool, &fixture.agent_spool, &limits(), now()?, write_cursor)?;
    assert_eq!(report.forwarded, 0);
    Ok(())
}


#[test]
fn cursor_file_problems_are_refused() -> TestResult {
    let fixture = fixture()?;
    let spool_dir = fixture.root.path().join("spool");
    let handle = spool_handle(&fixture)?;
    assert_eq!(read_cursor(&handle)?, 0);
    fs::write(spool_dir.join(CURSOR_FILE), "not a number")?;
    assert!(matches!(read_cursor(&handle), Err(ForwardError::BadCursor(_))));
    fs::write(spool_dir.join(CURSOR_FILE), "9".repeat(MANY))?;
    assert!(matches!(read_cursor(&handle), Err(ForwardError::BadCursor(_))));
    fs::write(spool_dir.join(CURSOR_FILE), [BAD_BYTE])?;
    assert!(matches!(read_cursor(&handle), Err(ForwardError::Io(_))));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlinked_cursor_is_not_followed() -> TestResult {
    let fixture = fixture()?;
    let target = fixture.root.path().join("elsewhere");
    fs::write(&target, "7\n")?;
    std::os::unix::fs::symlink(&target, fixture.root.path().join("spool").join(CURSOR_FILE))?;
    assert!(matches!(read_cursor(&spool_handle(&fixture)?), Err(ForwardError::Io(_))));
    Ok(())
}


#[test]
fn the_cursor_write_replaces_a_stale_temporary_and_reports_failures() -> TestResult {
    let fixture = fixture()?;
    let spool_dir = fixture.root.path().join("spool");
    let handle = spool_handle(&fixture)?;
    write_cursor(&handle, FIVE)?;
    fs::write(spool_dir.join(CURSOR_TEMPORARY), "stale")?;
    write_cursor(&handle, SIX)?;
    assert_eq!(read_cursor(&handle)?, SIX);
    assert!(!spool_dir.join(CURSOR_TEMPORARY).exists());
    fs::create_dir(spool_dir.join(CURSOR_TEMPORARY))?;
    assert!(write_cursor(&handle, SEVEN).is_err());
    Ok(())
}


#[test]
fn agent_spool_failures_are_reported() -> TestResult {
    let mut fixture = fixture()?;
    feed(&mut fixture, &[GOOD])?;
    let blocker = fixture.root.path().join("file");
    fs::write(&blocker, "x")?;
    assert!(file_bytes(&blocker.join("child")).is_err());
    assert_eq!(file_bytes(&fixture.root.path().join("absent"))?, 0);
    assert!(forward_once(&mut fixture.spool, &blocker.join("child"), &limits(), now()?, write_cursor).is_err());
    let missing_parent = fixture.root.path().join("absent").join("agent.spool");
    assert!(matches!(
        forward_once(&mut fixture.spool, &missing_parent, &limits(), now()?, write_cursor),
        Err(ForwardError::Io(_))
    ));
    assert_eq!(read_cursor(&spool_handle(&fixture)?)?, 0);
    Ok(())
}


#[test]
fn text_helpers_are_bounded() -> TestResult {
    assert_eq!(cut_text("abc", THREE_LINES), "abc");
    assert_eq!(cut_text("abcdef", THREE_LINES), "abc[+3 bytes cut]");
    assert_eq!(cut_text("aéé", TWO), "a[+4 bytes cut]");
    assert_eq!(clean_text("a\u{0}\u{202e}\u{2066}b", TEN), "ab");
    assert_eq!(clean_text("a\u{2028}b\u{200b}c\u{feff}d\u{2060}e", TEN), "abcde");
    assert!(valid_hostname("router-1.lan_x:1"));
    assert!(!valid_hostname(""));
    assert!(!valid_hostname("-x"));
    assert!(!valid_hostname("a b"));
    assert!(!valid_hostname(&"a".repeat(LONG_HOST)));
    assert_eq!(facility_name(AUTH_PRIORITY), "auth");
    assert_eq!(facility_name(u8::MAX), "unknown");
    assert_eq!(event_time(None, now()?), now()?);
    assert_eq!(event_time(Some(i64::MAX), now()?), now()?);
    assert_eq!(event_time(Some(0), now()?), OffsetDateTime::UNIX_EPOCH);
    Ok(())
}


#[test]
fn an_event_without_host_or_app_carries_no_such_labels() -> TestResult {
    let parsed = SyslogRecord {
        priority: 0,
        timestamp: None,
        host: None,
        app: None,
        message: "m".to_owned(),
        structured_data: Vec::<SdElement>::new(),
    };
    let event = build_event(NINE, "ab", &parsed, now()?);
    assert!(event.host.is_none());
    assert_eq!(event.labels.len(), THREE_LINES + 1);
    assert_eq!(event.timestamp, now()?);
    Ok(())
}
