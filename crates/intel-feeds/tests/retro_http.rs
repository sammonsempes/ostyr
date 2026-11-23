#[path = "common/types.rs"]
mod types;


use intel_feeds::config::ClickhouseConfig;
use intel_feeds::load::LoadError;
use intel_feeds::retro::{run_retro, RetroError, RetroSettings};
use siem_ingest::error::InsertClass;
use socket2::{Domain, Socket, Type};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::thread::{spawn, JoinHandle};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const START: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


const END: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const PASSWORD: &str = "RETROPW-5b1e9c40";


const HEADER_END: &str = "\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 10_000;


const ZERO: u8 = 0;


const DICTIONARY_PORT: u16 = 9440;


const EXEC_SECONDS: u32 = 30;


const READ_ROWS: u64 = 1_000_000;


const GROUP_ROWS: u64 = 10_000;


const MATCHES: usize = 3;


const MATCHES_IN_ROW: u32 = 3;


const NOT_AN_IP: u64 = 4;


const THIRD: usize = 2;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const TIMEOUT_MS: u64 = 120_000;


const ROW: &str = r#"{"indicator":"203.0.113.0/24","matched_ip":"::ffff:203.0.113.9","direction":"destination","host":"web-1","host_was_cut":1,"event_day":"2026-11-03","foreign":0,"matches":3,"first_time":1793664060,"last_time":1793664120}"#;


struct Rig {
    dir: TempDir,
    settings: RetroSettings,
    listener: TcpListener,
}


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path.as_ref(), content)?;
    fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path.as_ref(), content)
}


fn rig() -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    write_secret(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let settings = RetroSettings {
        reader: ClickhouseConfig {
            url: format!("http://127.0.0.1:{port}"),
            user: "retro_reader".to_owned(),
            password_file: dir.path().join("password"),
            ca_file: None,
            database: "ostyr".to_owned(),
            table: "iocs".to_owned(),
            dictionary: "ioc_trie".to_owned(),
            dictionary_user: "ostyr_dict".to_owned(),
            dictionary_port: DICTIONARY_PORT,
            timeout_ms: TIMEOUT_MS,
            tenant: "tenant-a".to_owned(),
        },
        events_database: "ostyr".to_owned(),
        events_table: "events".to_owned(),
        max_matches: MATCHES,
        max_execution_seconds: EXEC_SECONDS,
        max_rows_to_read: READ_ROWS,
        max_rows_to_group_by: GROUP_ROWS,
    };
    Ok(Rig { dir, settings, listener })
}


fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [ZERO; CHUNK];
    let mut expected = usize::MAX;
    let mut reads = 0;
    while received.len() < expected && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
        let lower = String::from_utf8_lossy(&received).to_lowercase();
        expected = lower.find(HEADER_END).map_or(usize::MAX, |end| {
            let length = lower
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            end + HEADER_END.len() + length
        });
        if count == 0 {
            expected = 0;
        }
    }
    Ok(String::from_utf8_lossy(&received).into_owned())
}


fn reply_text(status: &str, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}


fn serve(listener: TcpListener, replies: Vec<String>) -> JoinHandle<io::Result<Vec<String>>> {
    spawn(move || {
        replies.into_iter().try_fold(Vec::new(), |mut seen, reply| {
            let (mut stream, _) = listener.accept()?;
            seen.push(read_request(&mut stream)?);
            stream.write_all(reply.as_bytes())?;
            Ok(seen)
        })
    })
}


fn joined(handle: JoinHandle<io::Result<Vec<String>>>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


fn run(settings: &RetroSettings) -> Result<intel_feeds::retro::RetroRun, RetroError> {
    run_retro(settings, START, END, None, &|| Duration::ZERO)
}


#[test]
fn a_run_goes_through_the_real_sender_with_the_statement_in_the_body() -> TestResult {
    let rig = rig()?;
    let server = serve(
        rig.listener.try_clone()?,
        vec![
            reply_text("200 OK", "", "0\n"),
            reply_text("200 OK", "", "4\n"),
            reply_text("200 OK", "", &format!("{ROW}\n")),
        ],
    );
    let outcome = run(&rig.settings)?;
    let seen = joined(server)?;
    assert_eq!(outcome.groups.len(), 1);
    assert_eq!(outcome.summary.not_an_ip, NOT_AN_IP);
    assert_eq!(
        outcome.groups.first().map(|group| (group.host_cut, group.matches)),
        Some((true, MATCHES_IN_ROW))
    );
    let third = seen.get(THIRD).ok_or("no third request")?;
    assert!(third.starts_with("POST /?readonly=1&max_execution_time=30&timeout_overflow_mode=throw&"));
    assert!(third.contains("group_by_overflow_mode=throw"));
    assert!(third.contains("http_write_exception_in_output_format=0&limit=0&offset=0&additional_result_filter=&sort_overflow_mode=throw&"));
    assert!(third.contains("timeout_overflow_mode_leaf=throw&param_tenant"));
    assert!(third.contains("param_tenant=tenant-a&param_start=1793664000&param_end=1793707200&param_limit=4"));
    assert!(third.to_lowercase().contains(&format!("x-clickhouse-key: {PASSWORD}").to_lowercase()));
    assert!(third.to_lowercase().contains("x-clickhouse-user: retro_reader"));
    assert!(third.contains("SELECT dictGet('ostyr.ioc_trie', 'indicator'"));
    assert!(!third.contains("tenant-a'"));
    Ok(())
}


#[test]
fn the_exception_code_header_picks_the_error() -> TestResult {
    let rig = rig()?;
    let server = serve(
        rig.listener.try_clone()?,
        vec![reply_text(
            "500 Internal Server Error",
            "X-ClickHouse-Exception-Code: 159\r\n",
            "Code: 159. secret",
        )],
    );
    let found = run(&rig.settings).err().ok_or("the run succeeded")?;
    joined(server)?;
    assert!(matches!(found, RetroError::Timeout));
    assert!(!found.to_string().contains("secret"));
    Ok(())
}


/// A bound, never listening IPv6 socket: connections to it are refused and its port stays taken while it lives.
fn closed_socket() -> io::Result<(Socket, u16)> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::LOCALHOST, 0)).into())?;
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("not an inet address"))?
        .port();
    Ok((socket, port))
}


#[test]
fn an_unreachable_server_is_refused_as_unavailable() -> TestResult {
    let mut rig = rig()?;
    let (_held, port) = closed_socket()?;
    rig.settings.reader.url = format!("http://[::1]:{port}");
    assert!(matches!(run(&rig.settings), Err(RetroError::Refused(InsertClass::Unavailable))));
    Ok(())
}


#[test]
fn settings_and_secrets_are_refused_before_any_connection() -> TestResult {
    let mut rig = rig()?;
    let untouched = |listener: &TcpListener| -> io::Result<bool> {
        listener.set_nonblocking(true)?;
        Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
    };
    let invalid = RetroSettings {
        max_matches: 0,
        ..rig.settings.clone()
    };
    assert!(matches!(run(&invalid), Err(RetroError::Settings("max_matches"))));
    fs::remove_file(rig.dir.path().join("password"))?;
    assert!(matches!(run(&rig.settings), Err(RetroError::Setup(LoadError::Password(_)))));
    write_secret(rig.dir.path().join("password"), NOT_UTF8)?;
    assert!(matches!(run(&rig.settings), Err(RetroError::Setup(LoadError::PasswordEncoding(_)))));
    write_secret(rig.dir.path().join("password"), format!("{PASSWORD}\n"))?;
    rig.settings.reader.ca_file = Some(rig.dir.path().join("missing-ca.pem"));
    assert!(matches!(run(&rig.settings), Err(RetroError::Setup(LoadError::CaFile(_)))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}
