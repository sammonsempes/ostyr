use crate::common::{chat, completion, deps, scripted, settings};
use crate::numbers::KEY_MODE;
use crate::servers::{http_reply, plain_server};
use crate::types::TestResult;
use ai_gateway::chat::production_deps;
use ai_gateway::limits::STATUS_OK;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;


const KEY: &str = "sk-very-secret-key-value";


const TELEMETRY_MARKER: &str = "telemetry-marker-91c2";


const INSTRUCTIONS_MARKER: &str = "instructions-marker-44d8";


const CONTENT_MARKER: &str = "content-marker-3e07";


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);


impl io::Write for CaptureWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_poisoned| io::Error::other("poisoned"))?.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn one_line_per_call_with_counts_and_no_content_or_key() -> TestResult {
    LazyLock::force(&ANCHOR);
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("key");
    fs::write(&key, KEY)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(KEY_MODE))?;
    let mut used = settings("auth");
    used.api_key_file = Some(key);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || CaptureWriter(Arc::clone(&sink)))
            .with_ansi(false)
            .finish(),
    );
    let answer = tracing::dispatcher::with_default(&dispatch, || {
        chat(
            &used,
            INSTRUCTIONS_MARKER,
            &json!({"note": TELEMETRY_MARKER, "x": CONTENT_MARKER}),
            &deps(scripted),
        )
    })?;
    let logged = String::from_utf8(captured.lock().map_err(|_poisoned| "poisoned")?.clone())?;
    assert_eq!(answer.content, format!("Bearer {KEY}"));
    assert_eq!(logged.lines().filter(|line| line.contains("ai call")).count(), 1);
    assert!(logged.contains("ai call") && logged.contains("model=test-model:1") && logged.contains("duration_ms=0"));
    assert!(logged.contains("request_bytes=") && logged.contains("response_bytes=") && logged.contains("prompt_tokens=Some("));
    [KEY, TELEMETRY_MARKER, INSTRUCTIONS_MARKER, CONTENT_MARKER, "Bearer"]
        .into_iter()
        .for_each(|secret| assert!(!logged.contains(secret), "{secret}"));
    assert!(!format!("{used:?}").contains(KEY));
    Ok(())
}


const DUMP_TAG: &str = "ureq_proto::util: ";


const DUMP_HEX_WIDTH: usize = 39;


const DUMP_ASCII_START: usize = 41;


const HEX_RADIX: u32 = 16;


const HEX_PAIR: usize = 2;


pub struct Dump {
    pub hex: String,
    pub bytes: Vec<u8>,
    pub ascii: String,
}


pub fn rebuild_dump(logged: &str) -> Result<Dump, std::num::ParseIntError> {
    let rows: Vec<&str> = logged
        .lines()
        .filter_map(|line| line.split_once(DUMP_TAG).map(|(_head, tail)| tail))
        .collect();
    let hex: String = rows
        .iter()
        .flat_map(|row| row.chars().take(DUMP_HEX_WIDTH))
        .filter(char::is_ascii_hexdigit)
        .collect();
    let ascii: String = rows.iter().flat_map(|row| row.chars().skip(DUMP_ASCII_START)).collect();
    let nibbles: Vec<char> = hex.chars().collect();
    let bytes = nibbles
        .chunks(HEX_PAIR)
        .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), HEX_RADIX))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(Dump { hex, bytes, ascii })
}


pub fn hex_of(text: &str) -> String {
    text.bytes().map(|byte| format!("{byte:02x}")).collect()
}


#[test]
fn a_trace_subscriber_never_sees_the_key_on_the_real_transport() -> TestResult {
    LazyLock::force(&ANCHOR);
    tracing_log::LogTracer::init()?;
    let server = plain_server(http_reply(STATUS_OK, &completion("traced")))?;
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("key");
    fs::write(&key, KEY)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(KEY_MODE))?;
    let mut used = settings("x");
    used.base_url = format!("http://127.0.0.1:{}", server.port);
    used.api_key_file = Some(key);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || CaptureWriter(Arc::clone(&sink)))
            .with_ansi(false)
            .finish(),
    );
    let answer = tracing::dispatcher::with_default(&dispatch, || chat(&used, "i", &json!({"a": 1}), &production_deps()))?;
    server.request.join().map_err(|_panic| "server panicked")??;
    let logged = String::from_utf8(captured.lock().map_err(|_poisoned| "poisoned")?.clone())?;
    let encoded = STANDARD.encode(KEY);
    assert_eq!(answer.content, "traced");
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    assert!(tracing::level_filters::STATIC_MAX_LEVEL <= tracing::level_filters::LevelFilter::DEBUG);
    assert!(logged.contains("ureq"), "{logged}");
    assert!(!logged.contains(KEY) && !logged.contains(&encoded), "{logged}");
    assert!(!logged.to_ascii_lowercase().contains("authorization"), "{logged}");
    let dump = rebuild_dump(&logged)?;
    let decoded = String::from_utf8_lossy(&dump.bytes).to_ascii_lowercase();
    let ascii = dump.ascii.to_ascii_lowercase();
    [KEY.to_ascii_lowercase(), encoded.to_ascii_lowercase(), "authorization".to_owned()]
        .iter()
        .for_each(|secret| {
            assert!(!decoded.contains(secret), "decoded {secret}");
            assert!(!ascii.contains(secret), "ascii {secret}");
            assert!(!dump.hex.contains(&hex_of(secret)), "hex {secret}");
        });
    Ok(())
}
