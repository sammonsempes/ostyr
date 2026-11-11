mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use metric_alerts::fetch::{agent_for, fetch_points, FetchSettings, DEFAULT_TIMEOUT_MS};
use metric_alerts::query::MetricQuery;
use siem_schema::metrics::MetricsTable;
use std::io::{self, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stub::reply;


const PASSWORD: &str = "TRACEPW-77aa31";


const LONG: Duration = Duration::from_secs(60);


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
fn a_trace_subscriber_never_sees_the_key_the_values_or_the_server_text() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let bound = TcpListener::bind("127.0.0.1:0")?;
    let port = bound.local_addr()?.port();
    let server = reply(bound, "500 Internal Server Error", "", b"SECRET-SERVER-TEXT".to_vec());
    let config = FetchSettings {
        url: format!("http://127.0.0.1:{port}"),
        user: "ostyr".to_string(),
        password_file: "unused".into(),
        ca_file: None,
        timeout_ms: DEFAULT_TIMEOUT_MS,
    };
    let query = MetricQuery {
        sql: "SELECT 1 FROM `metric_samples`\n".to_string(),
        params: vec![("tenant".to_string(), "TENANTVALUE".to_string())],
        table: MetricsTable::Raw,
    };
    let agent = agent_for(&config)?;
    let outcome = tracing::subscriber::with_default(subscriber, || fetch_points(&agent, &config, PASSWORD, &query, LONG));
    server.join().map_err(|_| "server panicked")??;
    assert!(outcome.is_err());
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(
        logged.contains("metric fetch failed: fetch refused: the server is unavailable"),
        "{logged}"
    );
    assert!(!logged.contains(PASSWORD));
    assert!(!logged.contains("SECRET-SERVER-TEXT"));
    assert!(!logged.contains("TENANTVALUE"));
    assert!(!logged.contains("SELECT"));
    assert!(!logged.contains("127.0.0.1"));
    Ok(())
}
