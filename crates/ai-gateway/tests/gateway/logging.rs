use crate::common::{deps, scripted, settings};
use crate::numbers::KEY_MODE;
use crate::types::TestResult;
use ai_gateway::chat::chat;
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
    assert_eq!(logged.lines().count(), 1);
    assert!(logged.contains("ai call") && logged.contains("model=test-model:1") && logged.contains("duration_ms=0"));
    assert!(logged.contains("request_bytes=") && logged.contains("response_bytes=") && logged.contains("prompt_tokens=Some("));
    [KEY, TELEMETRY_MARKER, INSTRUCTIONS_MARKER, CONTENT_MARKER, "Bearer"]
        .into_iter()
        .for_each(|secret| assert!(!logged.contains(secret), "{secret}"));
    assert!(!format!("{used:?}").contains(KEY));
    Ok(())
}
