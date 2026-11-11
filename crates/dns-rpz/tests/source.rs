#[path = "common/clock.rs"]
mod clock;
#[path = "common/engine.rs"]
mod engine;
#[path = "common/logging.rs"]
mod logging;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use clock::now;
use dns_rpz::cli::{run_command, Session};
use dns_rpz::limits::SOURCE_FAILED;
use dns_rpz::model::{CommandStatus, Reloader};
use dns_rpz::run::generate;
use dns_rpz::source::{clickhouse_open, open_source};
use engine::{audit, context, engine_for, policy_text, replace_file};
use intel_feeds::limits::MAX_READ_BYTES;
use intel_feeds::model::{Ioc, IocType, Source, Tags, Tlp};
use logging::init_logging;
use sample::sample_policy;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const PASSWORD: &str = "RPZPW-5c0b81f4";


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 65_536;


const MAX_HEAD_READS: usize = 1_000;


const OVERSHOOT: usize = 2;


const ZERO: u8 = 0;


const SEEN: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


const EXPIRES: OffsetDateTime = datetime!(2026-12-03 00:00:00 UTC);


const CONFIDENCE: u8 = 70;


const FIRST_SERIAL: &str = "2026110301";


const NEW_SERIAL: &str = "2026110302";


struct Rig {
    dir: TempDir,
    feeds: PathBuf,
    listener: TcpListener,
}


fn feeds_text(port: u16, tenant: &str, password: &Path) -> String {
    format!(
        "feeds: []\nclickhouse:\n  url: http://127.0.0.1:{port}\n  user: ostyr\n  password_file: {}\n  database: ostyr\n  table: iocs\n  dictionary: ioc_trie\n  tenant: {tenant}\n",
        password.display()
    )
}


fn rig(tenant: &str) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let password = dir.path().join("password");
    fs::write(&password, format!("{PASSWORD}\n"))?;
    let feeds = dir.path().join("feeds.yaml");
    fs::write(&feeds, feeds_text(listener.local_addr()?.port(), tenant, &password))?;
    Ok(Rig { dir, feeds, listener })
}


fn row(value: &str, tlp: &str) -> String {
    format!(
        r#"{{"ioc_type":"domain","value":"{value}","feed":"f","feed_version":"v1","confidence":{CONFIDENCE},"tlp":"{tlp}","first_seen":"2026-11-03 00:00:00","last_seen":"2026-11-03 00:00:00","expires_at":"2026-12-03 00:00:00"}}"#
    )
}


fn good_rows() -> String {
    [
        row("evil.example.com", "green"),
        row("worse.example.net", "amber"),
        row("secret.example.org", "red"),
    ]
    .join("\n")
        + "\n"
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


fn answer<Body>(listener: &TcpListener, status: &'static str, body: Body) -> io::Result<JoinHandle<io::Result<(String, bool)>>>
where
    Body: FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
{
    let accepting = listener.try_clone()?;
    Ok(spawn(move || {
        let (mut stream, _) = accepting.accept()?;
        let head = read_head(&mut stream)?;
        stream.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes())?;
        let sent = body(&mut stream).is_ok();
        Ok((head, sent))
    }))
}


fn text_body(text: String) -> impl FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static {
    move |stream| stream.write_all(text.as_bytes())
}


fn endless(stream: &mut TcpStream) -> io::Result<()> {
    let block = vec![b'a'; CHUNK];
    let blocks = (MAX_READ_BYTES as usize / CHUNK) * OVERSHOOT;
    (0..blocks).try_for_each(|_| stream.write_all(&block))
}


fn joined(handle: JoinHandle<io::Result<(String, bool)>>) -> Result<String, Box<dyn std::error::Error>> {
    let (head, _sent) = handle.join().map_err(|_| "server thread panicked")??;
    Ok(head)
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


fn sample_ioc(value: &str, tlp: Tlp) -> Ioc {
    Ioc {
        ioc_type: IocType::Domain,
        value: value.to_owned(),
        sources: vec![Source {
            feed: "f".to_owned(),
            version: "v1".to_owned(),
        }],
        first_seen: SEEN,
        last_seen: SEEN,
        confidence: CONFIDENCE,
        tlp,
        expires_at: Some(EXPIRES),
        tags: Tags::default(),
    }
}


fn run_from(open: &dyn Fn() -> io::Result<Box<dyn BufRead>>, dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut input = open()?;
    generate(&sample_policy(), &mut input, now(), &dir.join("counter"), &dir.join("zone.db"))?;
    Ok(fs::read_to_string(dir.join("zone.db"))?)
}


fn idle_runner(_program: &str, _arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    Ok(CommandStatus::Success)
}


fn state(dir: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    Ok((fs::read_to_string(dir.join("counter"))?, fs::read_to_string(dir.join("zone.db"))?))
}


fn refused<Body>(
    rig: &Rig,
    open: &dyn Fn() -> io::Result<Box<dyn BufRead>>,
    before: &(String, String),
    status: &'static str,
    body: Body,
) -> TestResult
where
    Body: FnOnce(&mut TcpStream) -> io::Result<()> + Send + 'static,
{
    let server = answer(&rig.listener, status, body)?;
    let failure = run_from(open, rig.dir.path()).err().ok_or("the run succeeded")?.to_string();
    assert_eq!(failure, SOURCE_FAILED);
    assert!(!failure.contains(PASSWORD) && !failure.contains("SECRET"));
    assert_eq!(&state(rig.dir.path())?, before);
    joined(server).map(drop)
}


#[test]
fn the_table_rows_give_the_zone_of_the_json_lines_path() -> TestResult {
    init_logging();
    let rig = rig("tenant-a")?;
    let server = answer(&rig.listener, "200 OK", text_body(good_rows()))?;
    let rejected = AtomicU64::new(0);
    let from_table = run_from(&clickhouse_open(&rig.feeds, &now, &rejected), rig.dir.path())?;
    let head = joined(server)?;
    assert!(head.contains("param_tenant=tenant-a"), "{head}");
    let other = tempdir()?;
    let lines = [
        sample_ioc("evil.example.com", Tlp::Green),
        sample_ioc("worse.example.net", Tlp::Amber),
        sample_ioc("secret.example.org", Tlp::Red),
    ]
    .iter()
    .map(|candidate| serde_json::to_string(candidate).map(|line| line + "\n"))
    .collect::<Result<String, _>>()?;
    let file = other.path().join("iocs.jsonl");
    fs::write(&file, lines)?;
    let spec = file.display().to_string();
    let from_file = run_from(&*open_source(&spec, &now, &rejected), other.path())?;
    assert_eq!(from_table, from_file);
    assert!(from_table.contains("\nevil.example.com IN CNAME .") && from_table.contains("\nworse.example.net IN CNAME ."));
    assert!(!from_table.contains("secret.example.org"), "{from_table}");
    assert_eq!(rejected.load(Ordering::Relaxed), 0);
    Ok(())
}


#[test]
fn the_rows_left_out_are_counted_in_the_summary() -> TestResult {
    init_logging();
    let rig = rig("tenant-a")?;
    let body = format!("{}not json\n{}\n", good_rows(), row("odd.example.com", "weird"));
    let server = answer(&rig.listener, "200 OK", text_body(body))?;
    let rejected = AtomicU64::new(0);
    let spec = format!("clickhouse:{}", rig.feeds.display());
    let source = open_source(&spec, &now, &rejected);
    let policy_file = rig.dir.path().join("policy.yaml");
    replace_file(&policy_file, &policy_text(""))?;
    let policy = engine_for(&policy_file)?;
    let sink = audit();
    let zone_context = context();
    let reloader = Reloader {
        runner: &idle_runner,
        audit: &*sink,
        context: &zone_context,
    };
    let counter = rig.dir.path().join("counter");
    let zone = rig.dir.path().join("zone.db");
    let mut report = Vec::new();
    let mut session = Session {
        engine: &policy,
        clock: &now,
        open: &*source,
        rejected: &rejected,
        counter: &counter,
        output: &zone,
        report: &mut report,
        reloader: &reloader,
    };
    run_command(&mut session, "run")?;
    joined(server)?;
    let text = String::from_utf8(report)?;
    assert!(
        text.contains("\"source_bad_rows\":2") && text.contains(&format!("\"serial\":{FIRST_SERIAL}")),
        "{text}"
    );
    assert!(text.contains("\"tlp\":1"), "{text}");
    Ok(())
}


#[test]
fn a_failed_read_leaves_the_counter_and_the_zone_untouched() -> TestResult {
    init_logging();
    let rig = rig("tenant-a")?;
    let rejected = AtomicU64::new(0);
    let open = clickhouse_open(&rig.feeds, &now, &rejected);
    let first = answer(&rig.listener, "200 OK", text_body(good_rows()))?;
    run_from(&open, rig.dir.path())?;
    joined(first)?;
    let before = state(rig.dir.path())?;
    assert!(before.0.contains(FIRST_SERIAL));
    refused(
        &rig,
        &open,
        &before,
        "500 Internal Server Error",
        text_body("SECRET-SERVER-TEXT".to_owned()),
    )?;
    refused(&rig, &open, &before, "401 Unauthorized", text_body("SECRET-SERVER-TEXT".to_owned()))?;
    refused(&rig, &open, &before, "200 OK", endless)?;
    let last = answer(&rig.listener, "200 OK", text_body(good_rows()))?;
    run_from(&open, rig.dir.path())?;
    joined(last)?;
    assert!(state(rig.dir.path())?.0.contains(NEW_SERIAL));
    Ok(())
}


#[test]
fn a_bad_tenant_is_refused_before_any_request() -> TestResult {
    init_logging();
    let rig = rig("-x")?;
    let rejected = AtomicU64::new(0);
    let failure = run_from(&clickhouse_open(&rig.feeds, &now, &rejected), rig.dir.path())
        .err()
        .ok_or("accepted")?;
    assert_eq!(failure.to_string(), SOURCE_FAILED);
    assert!(untouched(&rig.listener)?);
    assert!(!rig.dir.path().join("zone.db").exists() && !rig.dir.path().join("counter").exists());
    Ok(())
}


#[test]
fn a_missing_file_or_section_is_refused() -> TestResult {
    init_logging();
    let dir = tempdir()?;
    let rejected = AtomicU64::new(0);
    let absent = dir.path().join("absent.yaml");
    assert!(run_from(&clickhouse_open(&absent, &now, &rejected), dir.path()).is_err());
    let bare = dir.path().join("bare.yaml");
    fs::write(&bare, "feeds: []\n")?;
    assert!(run_from(&clickhouse_open(&bare, &now, &rejected), dir.path()).is_err());
    assert!(!dir.path().join("zone.db").exists());
    Ok(())
}


#[test]
fn a_plain_argument_is_a_json_lines_file() -> TestResult {
    let dir = tempdir()?;
    let rejected = AtomicU64::new(0);
    let missing = dir.path().join("none.jsonl").display().to_string();
    assert!(open_source(&missing, &now, &rejected)().is_err());
    Ok(())
}
