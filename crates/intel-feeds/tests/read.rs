#[path = "common/types.rs"]
mod types;


use intel_feeds::config::{ClickhouseConfig, ClickhouseError};
use intel_feeds::error::EntryError;
use intel_feeds::limits::{MAX_READ_BYTES, MAX_READ_ROWS};
use intel_feeds::load::LoadError;
use intel_feeds::model::{Ioc, IocType, Tlp};
use intel_feeds::read::{
    clickhouse_time, count_bad, ioc_line, read_iocs, read_iocs_capped, reason_of, total_bad, BadReason, BadRows, ReadCaps, ReadError, ReadSummary,
};
use siem_ingest::error::InsertClass;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver};
use std::thread::{spawn, JoinHandle};
use tempfile::{tempdir, TempDir};
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const SEEN: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


const EXPIRES: OffsetDateTime = datetime!(2026-12-03 00:00:00 UTC);


const ZERO: u8 = 0;


const DICTIONARY_PORT: u16 = 9440;


const GOOD_ROWS: usize = 3;


const BAD_ROWS: u64 = 5;


const TWO: u64 = 2;


const SMALL_ROWS: usize = 20;


const SMALL_BYTES: u64 = 1_024;


const SMALL_CAPS: ReadCaps = ReadCaps {
    rows: SMALL_ROWS,
    bytes: SMALL_BYTES,
};


const SMALL_BLOCKS: usize = 2;


const BAD_TYPE_ROW: &str = r#"{"ioc_type":"mystery","value":"d.example","feed":"f","feed_version":"v1","confidence":70,"tlp":"green","first_seen":"2026-11-03 00:00:00","last_seen":"2026-11-03 00:00:00","expires_at":"2026-12-03 00:00:00"}"#;


const PASSWORD: &str = "READPW-77c1d9e2";


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 65_536;


const MAX_HEAD_READS: usize = 1_000;


const LONG_TIMEOUT_MS: u64 = 120_000;


const STALL_TIMEOUT_MS: u64 = 100;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const OVERSHOOT: usize = 2;


const EXTRA_ROWS: usize = 10;


const BAD_DATE_ROW: &str = r#"{"ioc_type":"domain","value":"d.example","feed":"f","feed_version":"v1","confidence":70,"tlp":"green","first_seen":"yesterday","last_seen":"2026-11-03 00:00:00","expires_at":"2026-12-03 00:00:00"}"#;


struct Rig {
    dir: TempDir,
    config: ClickhouseConfig,
    listener: TcpListener,
}


fn rig(timeout_ms: u64) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    fs::write(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let config = ClickhouseConfig {
        url: format!("http://127.0.0.1:{port}"),
        user: "ostyr".to_owned(),
        password_file: dir.path().join("password"),
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "iocs".to_owned(),
        dictionary: "ioc_trie".to_owned(),
        dictionary_user: "ostyr_dict".to_owned(),
        dictionary_port: DICTIONARY_PORT,
        timeout_ms,
        tenant: "tenant-a".to_owned(),
    };
    Ok(Rig { dir, config, listener })
}


fn row(value: &str, tlp: &str) -> String {
    format!(
        r#"{{"ioc_type":"domain","value":"{value}","feed":"f","feed_version":"v1","confidence":70,"tlp":"{tlp}","first_seen":"2026-11-03 00:00:00","last_seen":"2026-11-03 00:00:00","expires_at":"2026-12-03 00:00:00"}}"#
    )
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


fn answer_with<Body>(listener: TcpListener, reply_head: String, body: Body) -> JoinHandle<io::Result<(String, bool)>>
where
    Body: FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
{
    spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let head = read_head(&mut stream)?;
        stream.write_all(reply_head.as_bytes())?;
        let sent = body(&mut stream).is_ok();
        Ok((head, sent))
    })
}


fn answer<Body>(listener: TcpListener, status: &'static str, body: Body) -> JoinHandle<io::Result<(String, bool)>>
where
    Body: FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
{
    answer_with(listener, format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n"), body)
}


fn text_body(text: String) -> impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static {
    move |stream| stream.write_all(text.as_bytes())
}


fn endless(first: Vec<u8>, filler: u8, blocks: usize) -> impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static {
    move |stream| {
        stream.write_all(&first)?;
        let block = vec![filler; CHUNK];
        (0..blocks).try_for_each(|_| stream.write_all(&block))
    }
}


fn full_blocks() -> usize {
    (MAX_READ_BYTES as usize / CHUNK) * OVERSHOOT
}


fn joined(handle: JoinHandle<io::Result<(String, bool)>>) -> Result<(String, bool), Box<dyn std::error::Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


#[test]
fn rows_become_ioc_lines_and_the_request_carries_its_parameters() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let body = [
        row("a.example", "red"),
        row("b.example", "clear"),
        row("c.example", "weird"),
        row("d.example", "RED"),
        BAD_DATE_ROW.to_owned(),
        BAD_TYPE_ROW.to_owned(),
        String::new(),
        "not json".to_owned(),
        row("e.example", "amber_strict"),
    ]
    .join("\n");
    let server = answer(rig.listener.try_clone()?, "200 OK", text_body(format!("{body}\n")));
    let mut out = Vec::new();
    let summary = read_iocs(&rig.config, NOW, &mut out)?;
    assert_eq!(total_bad(&summary.bad), BAD_ROWS + 1);
    assert_eq!(
        summary,
        ReadSummary {
            rows: GOOD_ROWS,
            bad: BadRows {
                unknown_tlp: TWO,
                unknown_type: 1,
                bad_time: 1,
                bad_json: TWO,
            }
        }
    );
    let iocs: Vec<Ioc> = String::from_utf8(out)?.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
    let tlps: Vec<Tlp> = iocs.iter().map(|ioc| ioc.tlp).collect();
    assert_eq!(tlps, vec![Tlp::Red, Tlp::Clear, Tlp::AmberStrict]);
    let first = iocs.first().ok_or("no ioc")?;
    assert_eq!(first.ioc_type, IocType::Domain);
    assert_eq!(first.sources.first().map(|source| source.version.as_str()), Some("v1"));
    assert_eq!(first.first_seen, SEEN);
    assert_eq!(first.expires_at, Some(EXPIRES));
    let (head, _) = joined(server)?;
    let line = head.lines().next().ok_or("no head")?;
    assert!(line.starts_with("POST /?query=SELECT"), "{line}");
    assert!(line.contains("param_tenant=tenant-a"), "{line}");
    assert!(line.contains(&format!("param_now={}", NOW.unix_timestamp())), "{line}");
    assert!(line.contains(&format!("param_limit={}", MAX_READ_ROWS + 1)), "{line}");
    assert!(!line.contains(PASSWORD));
    assert!(head.to_lowercase().contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase())));
    Ok(())
}


#[test]
fn rows_over_the_cap_fail_and_write_nothing() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let lines = (0..SMALL_ROWS + EXTRA_ROWS)
        .map(|_| row("x.example", "green"))
        .collect::<Vec<_>>()
        .join("\n");
    let server = answer(rig.listener.try_clone()?, "200 OK", text_body(lines));
    let mut out = Vec::new();
    let failed = read_iocs_capped(
        &rig.config,
        NOW,
        &mut out,
        ReadCaps {
            bytes: MAX_READ_BYTES,
            ..SMALL_CAPS
        },
    );
    assert!(matches!(failed, Err(ReadError::TooManyRows(SMALL_ROWS))));
    assert!(out.is_empty());
    assert!(failed.is_err_and(|error| error.to_string().contains("more than 20 rows")));
    assert!(server.join().is_ok());
    Ok(())
}


#[test]
fn exactly_the_cap_is_read_in_full() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let lines = (0..SMALL_ROWS).map(|_| row("x.example", "green")).collect::<Vec<_>>().join("\n");
    let server = answer(rig.listener.try_clone()?, "200 OK", text_body(format!("{lines}\n")));
    let mut out = Vec::new();
    let summary = read_iocs_capped(
        &rig.config,
        NOW,
        &mut out,
        ReadCaps {
            bytes: MAX_READ_BYTES,
            ..SMALL_CAPS
        },
    )?;
    assert_eq!(
        summary,
        ReadSummary {
            rows: SMALL_ROWS,
            bad: BadRows::default()
        }
    );
    joined(server)?;
    Ok(())
}


#[test]
fn a_body_over_the_byte_cap_without_newline_fails_bounded() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = answer(rig.listener.try_clone()?, "200 OK", endless(Vec::new(), b'a', full_blocks()));
    let mut out = Vec::new();
    let failed = read_iocs(&rig.config, NOW, &mut out);
    assert!(matches!(failed, Err(ReadError::TooManyBytes(MAX_READ_BYTES))));
    assert!(out.is_empty());
    assert!(server.join().is_ok());
    Ok(())
}


#[test]
fn valid_rows_followed_by_an_oversized_tail_still_fail() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let first = format!("{}\n", row("a.example", "green")).into_bytes();
    let server = answer(rig.listener.try_clone()?, "200 OK", endless(first, b'\n', SMALL_BLOCKS));
    let mut out = Vec::new();
    assert!(matches!(
        read_iocs_capped(&rig.config, NOW, &mut out, SMALL_CAPS),
        Err(ReadError::TooManyBytes(SMALL_BYTES))
    ));
    assert!(out.is_empty());
    assert!(server.join().is_ok());
    Ok(())
}


#[test]
fn a_chunked_reply_cut_before_its_end_fails_and_writes_nothing() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let rows = format!("{}\n{}\n", row("a.example", "green"), row("b.example", "green"));
    let chunk = format!("{:x}\r\n{rows}\r\n", rows.len());
    let server = answer_with(
        rig.listener.try_clone()?,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned(),
        text_body(chunk),
    );
    let mut out = Vec::new();
    let failed = read_iocs(&rig.config, NOW, &mut out);
    assert!(matches!(failed, Err(ReadError::Body(_))), "{failed:?}");
    assert!(out.is_empty());
    joined(server)?;
    Ok(())
}


#[test]
fn a_server_error_is_classified_and_its_text_never_shown() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = answer(
        rig.listener.try_clone()?,
        "500 Internal Server Error",
        text_body("SECRET-SERVER-TEXT".to_owned()),
    );
    let mut out = Vec::new();
    let failed = read_iocs(&rig.config, NOW, &mut out).err().ok_or("no error")?;
    assert!(matches!(failed, ReadError::Refused(InsertClass::Unavailable)));
    assert!(!format!("{failed:?}{failed}").contains("SECRET"));
    assert!(out.is_empty());
    joined(server)?;
    Ok(())
}


#[test]
fn a_reply_that_never_ends_hits_the_deadline() -> TestResult {
    let rig = rig(STALL_TIMEOUT_MS)?;
    let (release, held): (_, Receiver<()>) = channel();
    let server = answer(rig.listener.try_clone()?, "200 OK", move |_| held.recv().map_err(io::Error::other));
    let mut out = Vec::new();
    let failed = read_iocs(&rig.config, NOW, &mut out);
    release.send(())?;
    assert!(matches!(failed, Err(ReadError::Body(_))));
    assert!(out.is_empty());
    joined(server)?;
    Ok(())
}


#[test]
fn an_unreachable_server_is_refused_as_unavailable() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    let free = TcpListener::bind("127.0.0.1:0")?;
    rig.config.url = format!("http://127.0.0.1:{}", free.local_addr()?.port());
    drop(free);
    let mut out = Vec::new();
    assert!(matches!(
        read_iocs(&rig.config, NOW, &mut out),
        Err(ReadError::Refused(InsertClass::Unavailable))
    ));
    Ok(())
}


#[test]
fn settings_and_secrets_are_refused_before_any_connection() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    let mut out = Vec::new();
    rig.config.tenant = "a'b".to_owned();
    assert!(matches!(
        read_iocs(&rig.config, NOW, &mut out),
        Err(ReadError::Setup(LoadError::Settings(ClickhouseError::Tenant(_))))
    ));
    rig.config.tenant = "-x".to_owned();
    assert!(read_iocs(&rig.config, NOW, &mut out).is_err());
    rig.config.tenant = "tenant-a".to_owned();
    fs::write(&rig.config.password_file, NOT_UTF8)?;
    assert!(matches!(
        read_iocs(&rig.config, NOW, &mut out),
        Err(ReadError::Setup(LoadError::PasswordEncoding(_)))
    ));
    fs::remove_file(&rig.config.password_file)?;
    assert!(matches!(
        read_iocs(&rig.config, NOW, &mut out),
        Err(ReadError::Setup(LoadError::Password(_)))
    ));
    fs::write(
        rig.dir.path().join("junk.pem"),
        "-----BEGIN CERTIFICATE-----\nnot base64 !\n-----END CERTIFICATE-----\n",
    )?;
    fs::write(&rig.config.password_file, PASSWORD)?;
    rig.config.ca_file = Some(rig.dir.path().join("junk.pem"));
    assert!(matches!(
        read_iocs(&rig.config, NOW, &mut out),
        Err(ReadError::Setup(LoadError::Agent(_)))
    ));
    assert!(untouched(&rig.listener)?);
    assert!(out.is_empty());
    Ok(())
}


struct Broken;


impl Write for Broken {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn a_failing_output_is_an_error() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = answer(rig.listener.try_clone()?, "200 OK", text_body(format!("{}\n", row("a.example", "green"))));
    let failed = read_iocs(&rig.config, NOW, &mut Broken);
    assert!(matches!(failed, Err(ReadError::Output(_))));
    joined(server)?;
    Ok(())
}


#[test]
fn rows_parse_only_known_tlps_and_dates() -> TestResult {
    assert!(ioc_line(Ok(row("a.example", "amber"))).is_ok());
    assert!(ioc_line(Ok(row("a.example", "Amber"))).is_err());
    assert!(ioc_line(Ok(row("a.example", ""))).is_err());
    assert!(ioc_line(Err(EntryError::LineTooLong)).is_err());
    let mut deserializer = serde_json::Deserializer::from_str("\"2026-11-03 12:00:00\"");
    assert_eq!(clickhouse_time(&mut deserializer)?, NOW);
    let mut wrong = serde_json::Deserializer::from_str("\"2026-11-03T12:00:00Z\"");
    assert!(clickhouse_time(&mut wrong).is_err());
    Ok(())
}


#[test]
fn each_bad_row_is_counted_under_its_own_reason() -> TestResult {
    let reasons: Vec<BadReason> = [
        row("a.example", "weird"),
        BAD_TYPE_ROW.to_owned(),
        BAD_DATE_ROW.to_owned(),
        "not json".to_owned(),
    ]
    .into_iter()
    .map(|line| ioc_line(Ok(line)).err().map(|error| reason_of(&error)).ok_or("row accepted"))
    .collect::<Result<_, _>>()?;
    assert_eq!(
        reasons,
        vec![BadReason::UnknownTlp, BadReason::UnknownType, BadReason::BadTime, BadReason::BadJson]
    );
    let line_reason = ioc_line(Err(EntryError::LineTooLong)).err().map(|error| reason_of(&error));
    assert_eq!(line_reason, Some(BadReason::BadJson));
    let counted = reasons.into_iter().fold(BadRows::default(), count_bad);
    assert_eq!(
        counted,
        BadRows {
            unknown_tlp: 1,
            unknown_type: 1,
            bad_time: 1,
            bad_json: 1
        }
    );
    assert_eq!(BadReason::UnknownTlp.to_string(), "unknown_tlp");
    assert_eq!(BadReason::UnknownType.to_string(), "unknown_type");
    assert_eq!(BadReason::BadTime.to_string(), "bad_time");
    assert_eq!(BadReason::BadJson.to_string(), "bad_json");
    Ok(())
}
