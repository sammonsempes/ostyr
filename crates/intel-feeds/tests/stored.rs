#![cfg(unix)]


#[path = "common/clock.rs"]
mod clock;
#[path = "common/types.rs"]
mod types;


use clock::now;
use intel_feeds::budget::{
    count_row, fetch_lines, key_row, read_keys, read_live, read_stored, read_stored_timed, read_top, reply_lines, top_row, Stored,
};
use intel_feeds::config::ClickhouseConfig;
use intel_feeds::limits::{MAX_LOGGED_FEED_NAMES, MAX_READER_SKEW_SECONDS, MAX_READ_BYTES, MAX_READ_ROWS, MAX_STORED_IOCS};
use intel_feeds::load::LoadError;
use intel_feeds::model::{Collector, FeedSummary, Ioc, IocType, Source, Tags, Tlp};
use intel_feeds::read::ReadError;
use intel_feeds::run::{is_read_type, merge_collected, read_union, refusal};
use intel_feeds::store::{count_statement, keys_statement, read_source, read_statement, top_statement};
use intel_feeds::types::IocIndex;
use siem_ingest::clickhouse::new_agent;
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::{pins, CHECK_MAX_ROWS};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use types::TestResult;


const SECRET_MODE: u32 = 0o600;


const PASSWORD: &str = "STOREDPW-52c8a1d0";


const LONG_MS: u64 = 120_000;


const SPENT: Duration = Duration::from_secs(200_000);


const SCHEMA_STATEMENTS: usize = 5;


const PROFILE_AT: usize = 5;


const KEYS_AT: usize = 6;


const COUNT_AT: usize = 7;


const TOP_AT: usize = 8;


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 65_536;


const MAX_HEAD_READS: usize = 1_000;


const DICTIONARY_PORT: u16 = 9440;


const LIVE: usize = 7;


const SMALL_CAP: usize = 2;


const THREE: usize = 3;


const FOUR: u64 = 4;


const ALPHA_LIVE: u64 = 5;


const PER_NET: usize = 250;


const HASH_CHARS: usize = 64;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const NOT_UTF8_LINE: [u8; 2] = [0xff, b'\n'];


const CODE_ROWS: u32 = 396;


const OVERSHOOT: usize = 2;


const ZERO: u8 = 0;


const KEY_ROWS: &str = "{\"ioc_type\":\"ipv4\",\"value\":\"192.0.2.1\"}\n{\"ioc_type\":\"domain\",\"value\":\"a.example\"}\n";


const TOP_ROWS: &str = "{\"feed\":\"alpha\",\"live\":5}\n{\"feed\":\"beta\",\"live\":2}\n";


struct Reply {
    status: &'static str,
    code: Option<u32>,
    body: Vec<u8>,
}


fn ok(body: &str) -> Reply {
    Reply {
        status: "200 OK",
        code: None,
        body: body.as_bytes().to_vec(),
    }
}


fn failing(code: Option<u32>) -> Reply {
    Reply {
        status: "500 Internal Server Error",
        code,
        body: Vec::new(),
    }
}


fn profile_body() -> String {
    pins(&[], CHECK_MAX_ROWS)
        .iter()
        .map(|(name, _)| format!("{name}\n"))
        .chain(["readonly\n".to_owned()])
        .collect()
}


fn script(replaced: Vec<(usize, Reply)>, length: usize) -> Vec<Reply> {
    let mut replies: Vec<Reply> = (0..SCHEMA_STATEMENTS).map(|_| ok("")).collect();
    replies.push(ok(&profile_body()));
    replies.push(ok(KEY_ROWS));
    replies.push(ok(&format!("{{\"live\":{LIVE}}}\n")));
    replies.push(ok(TOP_ROWS));
    replaced.into_iter().for_each(|(index, reply)| {
        if let Some(slot) = replies.get_mut(index) {
            *slot = reply;
        }
    });
    replies.truncate(length);
    replies
}


fn read_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [ZERO; CHUNK];
    let mut reads = 0;
    while !String::from_utf8_lossy(&received).contains(HEADER_END) && reads < MAX_HEAD_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
        if count == 0 {
            reads = MAX_HEAD_READS;
        }
    }
    Ok(String::from_utf8_lossy(&received).into_owned())
}


fn serve(listener: TcpListener, replies: Vec<Reply>) -> JoinHandle<io::Result<Vec<String>>> {
    spawn(move || {
        replies.into_iter().try_fold(Vec::new(), |mut seen, reply| {
            let (mut stream, _) = listener.accept()?;
            seen.push(read_head(&mut stream)?);
            let code = reply
                .code
                .map_or_else(String::new, |value| format!("X-ClickHouse-Exception-Code: {value}\r\n"));
            let head = format!(
                "HTTP/1.1 {}\r\n{code}Content-Length: {}\r\nConnection: close\r\n\r\n",
                reply.status,
                reply.body.len()
            );
            stream.write_all(head.as_bytes())?;
            stream.write_all(&reply.body)?;
            Ok(seen)
        })
    })
}


fn serve_endless(listener: TcpListener, first: Vec<Reply>) -> JoinHandle<io::Result<()>> {
    spawn(move || {
        first.into_iter().try_for_each(|reply| {
            let (mut stream, _) = listener.accept()?;
            read_head(&mut stream)?;
            stream.write_all(
                format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.status,
                    reply.body.len()
                )
                .as_bytes(),
            )?;
            stream.write_all(&reply.body)
        })?;
        let (mut stream, _) = listener.accept()?;
        read_head(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")?;
        let block = vec![b'x'; CHUNK];
        let blocks = (MAX_READ_BYTES as usize / CHUNK) * OVERSHOOT;
        drop((0..blocks).try_for_each(|_| stream.write_all(&block)));
        Ok(())
    })
}


struct Rig {
    dir: TempDir,
    config: ClickhouseConfig,
    listener: TcpListener,
}


fn rig() -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let password = dir.path().join("password");
    fs::write(&password, format!("{PASSWORD}\n"))?;
    fs::set_permissions(&password, PermissionsExt::from_mode(SECRET_MODE))?;
    let config = ClickhouseConfig {
        url: format!("http://127.0.0.1:{port}"),
        user: "ostyr".to_owned(),
        password_file: password,
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "iocs".to_owned(),
        dictionary: "ioc_trie".to_owned(),
        dictionary_user: "ostyr_dict".to_owned(),
        dictionary_port: DICTIONARY_PORT,
        timeout_ms: LONG_MS,
        tenant: "tenant-a".to_owned(),
    };
    Ok(Rig { dir, config, listener })
}


struct Ran {
    result: Result<Stored, ReadError>,
    seen: Vec<String>,
}


fn run(rig: &Rig, replies: Vec<Reply>) -> Result<Ran, Box<dyn std::error::Error>> {
    let server = serve(rig.listener.try_clone()?, replies);
    let result = read_stored_timed(&rig.config, now(), &|| Duration::ZERO);
    let seen = server.join().map_err(|_| "server panicked")??;
    Ok(Ran { result, seen })
}


fn failure(result: Result<Stored, ReadError>) -> Result<ReadError, Box<dyn std::error::Error>> {
    Ok(result.err().ok_or("the read succeeded")?)
}


#[test]
fn the_budget_is_the_keys_the_count_and_the_biggest_feeds_of_the_tenant() -> TestResult {
    let rig = rig()?;
    let Ran { result, seen } = run(&rig, script(Vec::new(), usize::MAX))?;
    let stored = result?;
    assert_eq!(stored.live, LIVE);
    assert!(!stored.exceeded);
    assert_eq!(stored.keys.len(), SMALL_CAP);
    assert!(stored.keys.contains(&(IocType::Domain, "a.example".to_owned())));
    assert_eq!(stored.top, vec![("alpha".to_owned(), ALPHA_LIVE), ("beta".to_owned(), SMALL_CAP as u64)]);
    assert_eq!(seen.len(), TOP_AT + 1);
    let skewed = now().unix_timestamp() - MAX_READER_SKEW_SECONDS;
    let keys = seen.get(KEYS_AT).ok_or("no keys request")?;
    let head = keys.lines().next().ok_or("no head")?;
    assert!(
        head.contains(&format!("param_now={skewed}")) && head.contains("param_tenant=tenant-a"),
        "{head}"
    );
    assert!(
        head.contains(&format!("param_limit={}", MAX_READ_ROWS + 1)) && head.contains("readonly=2"),
        "{head}"
    );
    assert!(!head.contains(PASSWORD) && keys.to_lowercase().contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase())));
    let count = seen.get(COUNT_AT).ok_or("no count request")?;
    assert!(count.contains("param_limit=2") && count.contains(&format!("param_now={skewed}")));
    assert!(seen.get(TOP_AT).ok_or("no top request")?.contains("GROUP"));
    drop(rig.dir);
    Ok(())
}


#[test]
fn a_table_over_the_read_bound_is_exceeded_and_the_count_is_still_read() -> TestResult {
    let rig = rig()?;
    let Ran { result, .. } = run(&rig, script(vec![(KEYS_AT, failing(Some(CODE_ROWS)))], usize::MAX))?;
    let stored = result?;
    assert!(stored.exceeded && stored.keys.is_empty());
    assert_eq!(stored.live, LIVE);
    Ok(())
}


#[test]
fn every_failed_step_is_a_named_read_error_and_stops_the_rest() -> TestResult {
    let rig = rig()?;
    let schema = run(&rig, script(vec![(0, failing(None))], 1))?.result;
    assert!(matches!(failure(schema)?, ReadError::Setup(LoadError::Schema(InsertClass::Unavailable))));
    let extra = format!("{}log_queries\n", profile_body());
    let changed = run(&rig, script(vec![(PROFILE_AT, ok(&extra))], PROFILE_AT + 1))?.result;
    assert!(matches!(failure(changed)?, ReadError::ReaderProfileChanged(1)));
    let keys_refused = run(&rig, script(vec![(KEYS_AT, failing(None))], KEYS_AT + 1))?.result;
    assert!(matches!(failure(keys_refused)?, ReadError::Refused(InsertClass::Unavailable)));
    let bad_key = run(&rig, script(vec![(KEYS_AT, ok("not json\n"))], KEYS_AT + 1))?.result;
    assert!(matches!(failure(bad_key)?, ReadError::MalformedReply));
    let exception = run(&rig, script(vec![(KEYS_AT, ok("{\"exception\":\"x\"}\n"))], KEYS_AT + 1))?.result;
    assert!(matches!(failure(exception)?, ReadError::ExceptionInBody));
    let no_count = run(&rig, script(vec![(COUNT_AT, ok(""))], COUNT_AT + 1))?.result;
    assert!(matches!(failure(no_count)?, ReadError::MalformedReply));
    let bad_count = run(&rig, script(vec![(COUNT_AT, ok("{\"live\":\"many\"}\n"))], COUNT_AT + 1))?.result;
    assert!(matches!(failure(bad_count)?, ReadError::MalformedReply));
    let count_refused = run(&rig, script(vec![(COUNT_AT, failing(Some(CODE_ROWS)))], COUNT_AT + 1))?.result;
    assert!(matches!(failure(count_refused)?, ReadError::TooManyRows(1)));
    let bad_top = run(&rig, script(vec![(TOP_AT, ok("{\"feed\":5}\n"))], TOP_AT + 1))?.result;
    assert!(matches!(failure(bad_top)?, ReadError::MalformedReply));
    Ok(())
}


#[test]
fn a_reply_past_the_byte_cap_is_an_error_never_a_partial_budget() -> TestResult {
    let rig = rig()?;
    let first: Vec<Reply> = script(Vec::new(), KEYS_AT);
    let server = serve_endless(rig.listener.try_clone()?, first);
    let error = failure(read_stored_timed(&rig.config, now(), &|| Duration::ZERO))?;
    assert!(matches!(error, ReadError::TooManyBytes(MAX_READ_BYTES)), "{error}");
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing_and_the_wrapper_reads_the_settings_first() -> TestResult {
    let rig = rig()?;
    let calls = Cell::new(0);
    let late = || {
        calls.set(calls.get() + 1);
        if calls.get() > SCHEMA_STATEMENTS {
            SPENT
        } else {
            Duration::ZERO
        }
    };
    let server = serve(rig.listener.try_clone()?, script(Vec::new(), SCHEMA_STATEMENTS));
    let spent = failure(read_stored_timed(&rig.config, now(), &late))?;
    assert!(matches!(spent, ReadError::Refused(InsertClass::Timeout)));
    server.join().map_err(|_| "server panicked")??;
    let agent = new_agent(None, false)?;
    let always = || SPENT;
    assert!(matches!(
        read_live(&agent, &rig.config, PASSWORD, now(), &always),
        Err(ReadError::Refused(InsertClass::Timeout))
    ));
    let mut broken = rig.config.clone();
    broken.url = "ftp://example".to_owned();
    assert!(matches!(read_stored(&broken, now()), Err(ReadError::Setup(LoadError::Settings(_)))));
    Ok(())
}


#[test]
fn the_setup_steps_fail_with_their_own_named_errors() -> TestResult {
    let rig = rig()?;
    let mut missing = rig.config.clone();
    missing.password_file = rig.dir.path().join("absent");
    assert!(matches!(
        read_stored_timed(&missing, now(), &|| Duration::ZERO),
        Err(ReadError::Setup(LoadError::Password(_)))
    ));
    let binary = rig.dir.path().join("binary");
    fs::write(&binary, NOT_UTF8)?;
    fs::set_permissions(&binary, PermissionsExt::from_mode(SECRET_MODE))?;
    let mut not_utf8 = rig.config.clone();
    not_utf8.password_file = binary;
    assert!(matches!(
        read_stored_timed(&not_utf8, now(), &|| Duration::ZERO),
        Err(ReadError::Setup(LoadError::PasswordEncoding(_)))
    ));
    let mut no_ca = rig.config.clone();
    no_ca.ca_file = Some(rig.dir.path().join("no-ca.pem"));
    assert!(matches!(
        read_stored_timed(&no_ca, now(), &|| Duration::ZERO),
        Err(ReadError::Setup(LoadError::CaFile(_)))
    ));
    let mut bad_name = rig.config.clone();
    bad_name.database = "bad name".to_owned();
    let agent = new_agent(None, false)?;
    assert!(matches!(
        read_keys(&agent, &bad_name, PASSWORD, now(), &|| Duration::ZERO),
        Err(ReadError::Statement(_))
    ));
    assert!(matches!(
        read_live(&agent, &bad_name, PASSWORD, now(), &|| Duration::ZERO),
        Err(ReadError::Statement(_))
    ));
    assert!(matches!(
        read_top(&agent, &bad_name, PASSWORD, now(), &|| Duration::ZERO),
        Err(ReadError::Statement(_))
    ));
    Ok(())
}


#[test]
fn a_reply_is_read_line_by_line_under_the_row_cap() -> TestResult {
    assert_eq!(reply_lines(&mut "a\nb\n".as_bytes(), SMALL_CAP)?, vec!["a".to_owned(), "b".to_owned()]);
    assert!(matches!(
        reply_lines(&mut "a\nb\nc\n".as_bytes(), SMALL_CAP),
        Err(ReadError::TooManyRows(SMALL_CAP))
    ));
    assert!(matches!(reply_lines(&mut &NOT_UTF8_LINE[..], SMALL_CAP), Err(ReadError::MalformedReply)));
    assert!(matches!(
        reply_lines(&mut "{\"exception\":\"x\"}\n".as_bytes(), SMALL_CAP),
        Err(ReadError::ExceptionInBody)
    ));
    let agent = new_agent(None, false)?;
    let rig = rig()?;
    let server = serve(rig.listener.try_clone()?, vec![ok("a\n"), ok("a\nb\nc\n")]);
    let first = fetch_lines(&agent, &rig.config, PASSWORD, "SELECT 1", now(), SMALL_CAP, &|| Duration::ZERO)?;
    assert_eq!(first, vec!["a".to_owned()]);
    let second = fetch_lines(&agent, &rig.config, PASSWORD, "SELECT 1", now(), SMALL_CAP, &|| Duration::ZERO);
    assert!(matches!(second, Err(ReadError::TooManyRows(SMALL_CAP))));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}


#[test]
fn the_row_shapes_are_strict() -> TestResult {
    assert_eq!(
        key_row("{\"ioc_type\":\"url\",\"value\":\"http://x/\"}")?,
        (IocType::Url, "http://x/".to_owned())
    );
    assert!(matches!(
        key_row("{\"ioc_type\":\"nope\",\"value\":\"x\"}"),
        Err(ReadError::MalformedReply)
    ));
    assert_eq!(count_row(&["{\"live\":3}".to_owned()])?, THREE);
    assert!(matches!(count_row(&[]), Err(ReadError::MalformedReply)));
    assert_eq!(top_row("{\"feed\":\"f\",\"live\":4}")?, ("f".to_owned(), FOUR));
    assert!(matches!(top_row("[]"), Err(ReadError::MalformedReply)));
    Ok(())
}


#[test]
fn the_writer_and_the_reader_count_the_same_source() -> TestResult {
    let source = read_source("d", "t")?;
    assert!(read_statement("d", "t")?.contains(&source));
    assert!(keys_statement("d", "t")?.contains(&source));
    assert!(source.contains("FINAL") && source.contains("`checked` = 1") && source.contains("`ioc_type` IN ('domain', 'ipv4', 'ipv6', 'cidr')"));
    let count = count_statement("d", "t")?;
    let top = top_statement("d", "t")?;
    [&count, &top].iter().for_each(|text| {
        assert!(text.contains("FINAL") && text.contains("{tenant:String}") && text.contains("`expires_at` > toDateTime({now:UInt32})"));
        assert!(text.contains("max_result_rows"));
    });
    assert!(top.contains(&format!("LIMIT {MAX_LOGGED_FEED_NAMES}")) && top.contains("GROUP BY `feed`"));
    [read_source("b d", "t").map(|_| ()), keys_statement("d", "b t").map(|_| ())]
        .iter()
        .for_each(|result| assert!(result.is_err()));
    assert!(count_statement("b d", "t").is_err() && top_statement("d", "b t").is_err());
    Ok(())
}


fn ioc_of(ioc_type: IocType, value: String) -> Ioc {
    Ioc {
        ioc_type,
        value,
        sources: vec![Source {
            feed: "f".to_owned(),
            version: "1".to_owned(),
        }],
        first_seen: now(),
        last_seen: now(),
        confidence: 1,
        tlp: Tlp::Amber,
        expires_at: None,
        tags: Tags::default(),
    }
}


fn feed_of(name: &str, iocs: Vec<Ioc>) -> Collector {
    Collector {
        iocs,
        summary: FeedSummary {
            feed: name.to_owned(),
            ..FeedSummary::default()
        },
    }
}


fn domain_keys(count: usize) -> BTreeSet<(IocType, String)> {
    (0..count).map(|number| (IocType::Domain, format!("d{number}.example"))).collect()
}


fn addresses(count: usize) -> Vec<Ioc> {
    (0..count)
        .map(|number| ioc_of(IocType::Ipv4, format!("10.0.{}.{}", number / PER_NET, number % PER_NET + 1)))
        .collect()
}


#[test]
fn a_feed_that_would_pass_the_read_bound_with_the_stored_keys_is_left_out_whole() -> TestResult {
    let stored = Stored {
        keys: domain_keys(MAX_READ_ROWS - 1),
        live: MAX_READ_ROWS - 1,
        ..Stored::default()
    };
    let mut index = IocIndex::new();
    let over = merge_collected(feed_of("a", addresses(SMALL_CAP)), now(), &mut index, &stored);
    assert!(over
        .failed
        .is_some_and(|reason| reason.starts_with("stored_ioc_cap:") && reason.contains(&(MAX_READ_ROWS - 1).to_string())));
    assert!(index.is_empty());
    let fits = merge_collected(feed_of("b", addresses(1)), now(), &mut index, &stored);
    assert_eq!((fits.failed, index.len()), (None, 1));
    let again = merge_collected(
        feed_of("c", vec![ioc_of(IocType::Domain, "d0.example".to_owned())]),
        now(),
        &mut index,
        &stored,
    );
    assert_eq!((again.failed, index.len()), (None, SMALL_CAP));
    let full = merge_collected(
        feed_of("d", vec![ioc_of(IocType::Domain, "new.example".to_owned())]),
        now(),
        &mut index,
        &stored,
    );
    assert!(full.failed.is_some_and(|reason| reason.starts_with("stored_ioc_cap")));
    Ok(())
}


#[test]
fn urls_and_hashes_count_against_the_stored_bound_and_not_the_read_bound() -> TestResult {
    let stored = Stored {
        live: MAX_STORED_IOCS - 1,
        ..Stored::default()
    };
    let urls = |count: usize| -> Vec<Ioc> {
        (0..count)
            .map(|number| ioc_of(IocType::Url, format!("http://x.example/{number}")))
            .collect()
    };
    let mut index = IocIndex::new();
    let over = merge_collected(feed_of("a", urls(SMALL_CAP)), now(), &mut index, &stored);
    assert!(over.failed.is_some_and(|reason| reason.starts_with("stored_ioc_cap:")));
    let fits = merge_collected(feed_of("b", urls(1)), now(), &mut index, &stored);
    assert_eq!(fits.failed, None);
    let next = merge_collected(
        feed_of("c", vec![ioc_of(IocType::Sha256, "a".repeat(HASH_CHARS))]),
        now(),
        &mut index,
        &stored,
    );
    assert!(next.failed.is_some());
    assert!(!is_read_type(IocType::Url) && is_read_type(IocType::Cidr) && is_read_type(IocType::Ipv6));
    assert_eq!(read_union(&stored, &index, &BTreeSet::new()), 0);
    Ok(())
}


#[test]
fn a_table_already_over_its_cap_leaves_every_feed_out_and_the_order_of_reasons_is_fixed() -> TestResult {
    let exceeded = Stored {
        exceeded: true,
        live: MAX_READ_ROWS + 1,
        ..Stored::default()
    };
    let mut index = IocIndex::new();
    let left = merge_collected(feed_of("a", addresses(1)), now(), &mut index, &exceeded);
    assert!(left.failed.is_some_and(|reason| reason.starts_with("stored_ioc_cap_exceeded")));
    assert!(index.is_empty());
    let fresh = BTreeSet::new();
    assert_eq!(refusal(&Stored::default(), &index, &fresh), None);
    let round: BTreeSet<(IocType, String)> = (0..=MAX_READ_ROWS).map(|number| (IocType::Url, format!("http://x/{number}"))).collect();
    assert!(refusal(&Stored::default(), &index, &round).is_some_and(|reason| reason.starts_with("round_ioc_cap")));
    Ok(())
}


#[test]
fn a_collector_summary_survives_a_refusal_untouched() -> TestResult {
    let summary = FeedSummary {
        feed: "kept".to_owned(),
        parsed: THREE as u64,
        ..FeedSummary::default()
    };
    let collector = Collector { iocs: addresses(1), summary };
    let stored = Stored {
        exceeded: true,
        ..Stored::default()
    };
    let left = merge_collected(collector, now(), &mut IocIndex::new(), &stored);
    assert_eq!((left.feed.as_str(), left.parsed), ("kept", 0));
    Ok(())
}
