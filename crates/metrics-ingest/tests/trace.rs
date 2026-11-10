mod common;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::run::run_insert;
use metrics_ingest::send::class_text;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::metrics::v1::{
    metric::Data, number_data_point::Value as NumberKind, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics,
};
use prost::Message;
use siem_ingest::error::InsertClass;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stub::serve;
use tempfile::tempdir;


const STAMP: u64 = 1_700_000_000_000_000_000;


const PASSWORD: &str = "TRACEPW-5b2e8d40";


const TWO: usize = 2;


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


fn request() -> Vec<u8> {
    let data_points = (0..TWO)
        .map(|_| NumberDataPoint {
            time_unix_nano: STAMP,
            value: Some(NumberKind::AsInt(1)),
            ..Default::default()
        })
        .collect();
    let metric = Metric {
        name: "cpu".to_string(),
        data: Some(Data::Gauge(Gauge { data_points })),
        ..Default::default()
    };
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            scope_metrics: vec![ScopeMetrics {
                metrics: vec![metric],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}


#[test]
fn a_trace_subscriber_never_sees_the_key_or_the_url() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    fs::write(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let settings = dir.path().join("settings.yaml");
    let text = format!(
        "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: metric_samples\nlimits:\n  max_batch_rows: 1\n",
        dir.path().join("password").display()
    );
    fs::write(&settings, text)?;
    let server = serve(listener.try_clone()?, vec!["200 OK", "500 Internal Server Error"]);
    let bytes = request();
    let report = tracing::subscriber::with_default(subscriber, || {
        run_insert(&settings, &bytes, "acme", &mut CardinalityState::default(), STAMP, &|| Duration::ZERO)
    })?;
    server.join().map_err(|_| "server thread panicked")??;
    assert_eq!(report.failed_batch, Some(1));
    assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    assert!(tracing::level_filters::STATIC_MAX_LEVEL <= tracing::level_filters::LevelFilter::DEBUG);
    let logged = String::from_utf8(capture.0.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(logged.contains(class_text(InsertClass::Unavailable)), "{logged}");
    assert!(!logged.contains(PASSWORD));
    assert!(!logged.contains("127.0.0.1"));
    assert!(!logged.contains("INSERT"));
    Ok(())
}
