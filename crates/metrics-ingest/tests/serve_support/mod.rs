pub mod types;


use std::fs;
use std::path::{Path, PathBuf};
use types::TestError;


pub const EVENT: &str = r#"{"event":{"dataset":"ostyr.host_metrics"},"host":{"name":"claimed"},"metrics":{"system.uptime":5}}"#;


pub const FETCH_MS: u64 = 100;


pub const REQUEST_MS: u64 = 2000;


pub fn settings_text(port: u16, audit_file: &Path, extra: &str) -> String {
    format!(
        "audit_file: {}\ningest:\n  nats_url: \"nats://127.0.0.1:{port}\"\n  nats_fetch_deadline_ms: {FETCH_MS}\n  nats_request_timeout_ms: {REQUEST_MS}\n  nats_consumer: metrics-ingest\n  clickhouse_table: metric_samples\n  backoff_initial_ms: 1\n  max_batch_messages: 5\n{extra}limits:\n  max_batch_rows: 100\n",
        audit_file.display()
    )
}


pub fn write_settings(dir: &Path, text: &str) -> Result<PathBuf, TestError> {
    let path = dir.join("metrics.yaml");
    fs::write(&path, text)?;
    Ok(path)
}
