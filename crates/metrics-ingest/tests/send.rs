mod common;
#[path = "common/stall.rs"]
mod stall;
#[path = "common/stub.rs"]
mod stub;


use common::types::TestResult;
use metrics_ingest::cardinality::CardinalityState;
use metrics_ingest::cli::{run_cli, CliError};
use metrics_ingest::insert::RefusedRow;
use metrics_ingest::model::{DropReason, Refusal};
use metrics_ingest::run::{run_insert, write_report, RunError, RunReport};
use metrics_ingest::send::{class_text, clickhouse_sender, SendError};
use metrics_ingest::settings::{load_settings, validate_settings, LoadError, MetricsSettings, SettingsError, MAX_CA_BYTES, MAX_TIMEOUT_MS};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, AnyValue, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{
    metric::Data, number_data_point::Value as NumberKind, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics,
};
use prost::Message;
use siem_ingest::error::InsertClass;
use stall::stall;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::Duration;
use stub::serve;
use tempfile::{tempdir, TempDir};


const STAMP: u64 = 1_700_000_000_000_000_000;


const NANOS_PER_SECOND: u64 = 1_000_000_000;


const YEAR_SECONDS: u64 = 31_536_000;


const PASSWORD: &str = "TRACEPW-5b2e8d40";


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


const LONG_TIMEOUT_MS: u64 = 60_000;


const STALL_TIMEOUT_MS: u64 = 100;


const ONE_HOUR: Duration = Duration::from_secs(3600);


const TWO: usize = 2;


const THREE: usize = 3;


const HUNDRED_THOUSAND: usize = 100_000;


const BULK: usize = 1000;


const REPORT_WRITES: usize = 64;


const OVERSIZE_PASSWORD: usize = 2048;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const SEVEN: u64 = 7;


const ELEVEN: u64 = 11;


struct Rig {
    dir: TempDir,
    listener: TcpListener,
    settings: PathBuf,
}


fn rig(timeout_ms: u64, rows_per_batch: usize) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    fs::write(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let settings = dir.path().join("settings.yaml");
    fs::write(
        &settings,
        format!(
            "url: http://127.0.0.1:{port}\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: metric_samples\ntimeout_ms: {timeout_ms}\nlimits:\n  max_batch_rows: {rows_per_batch}\n",
            dir.path().join("password").display()
        ),
    )?;
    Ok(Rig { dir, listener, settings })
}


fn loaded(rig: &Rig) -> Result<MetricsSettings, Box<dyn std::error::Error>> {
    Ok(load_settings(&rig.settings)?)
}


fn text(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(AnyKind::StringValue(value.to_string())),
        }),
        ..Default::default()
    }
}


fn request(points: usize) -> Vec<u8> {
    let data_points = (0..points)
        .map(|number| NumberDataPoint {
            attributes: if points < BULK {
                vec![text("host", &format!("h{number}")), text("tenant", "evil")]
            } else {
                Vec::new()
            },
            time_unix_nano: STAMP,
            value: Some(NumberKind::AsInt(1)),
            ..Default::default()
        })
        .collect();
    let metric = Metric {
        name: "cpu".to_string(),
        unit: "1".to_string(),
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


fn go(rig: &Rig, bytes: &[u8], tenant: &str, now: u64, elapsed: Duration) -> Result<RunReport, RunError> {
    run_insert(&rig.settings, bytes, tenant, &mut CardinalityState::default(), now, &|| elapsed)
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


fn joined<Output>(handle: std::thread::JoinHandle<io::Result<Output>>) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


fn fifo(rig: &Rig, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = rig.dir.path().join(name);
    assert!(Command::new("mkfifo").arg(&path).status()?.success());
    Ok(path)
}


#[test]
fn batches_go_in_order_with_the_key_in_a_header_only_and_the_tenant_from_the_argument() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let server = serve(rig.listener.try_clone()?, vec![OK; TWO]);
    let report = go(&rig, &request(TWO), "acme", STAMP, Duration::ZERO)?;
    assert_eq!(
        (report.rows, report.batches_planned, report.batches_sent, report.failed_batch),
        (TWO, TWO, TWO, None)
    );
    let seen = joined(server)?;
    assert_eq!(seen.len(), TWO);
    seen.iter().enumerate().try_for_each(|(index, one)| -> TestResult {
        let head = one.lines().next().ok_or("no head")?;
        assert!(head.starts_with("POST /?query=INSERT"), "{head}");
        assert!(head.contains("%60ostyr%60.%60metric_samples%60"), "{head}");
        assert!(!head.contains(PASSWORD));
        assert!(one.to_lowercase().contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase())));
        assert!(one.to_lowercase().contains("x-clickhouse-user: ostyr"));
        let body = one.split("\r\n\r\n").nth(1).ok_or("no body")?;
        assert_eq!(body.lines().count(), 1);
        assert!(body.contains("\"tenant\":\"acme\""));
        assert!(body.contains(&format!("\"host\":\"h{index}\"")));
        assert!(body.contains("\"labels\":{\"host\""));
        assert!(body.contains("\"tenant\":\"evil\"}"));
        Ok(())
    })?;
    Ok(())
}


#[test]
fn a_failed_second_batch_reports_one_sent() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let server = serve(rig.listener.try_clone()?, vec![OK, SERVER_ERROR]);
    let report = go(&rig, &request(THREE), "acme", STAMP, Duration::ZERO)?;
    assert_eq!((report.batches_planned, report.batches_sent, report.failed_batch), (THREE, 1, Some(1)));
    assert_eq!(joined(server)?.len(), TWO);
    Ok(())
}


#[test]
fn a_stalled_server_hits_the_deadline() -> TestResult {
    let rig = rig(STALL_TIMEOUT_MS, 1)?;
    let (release, held) = channel();
    let server = stall(rig.listener.try_clone()?, held);
    let report = go(&rig, &request(1), "acme", STAMP, Duration::ZERO)?;
    release.send(())?;
    joined(server)?;
    assert_eq!((report.batches_sent, report.failed_batch), (0, Some(0)));
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let rig = rig(STALL_TIMEOUT_MS, 1)?;
    let report = go(&rig, &request(1), "acme", STAMP, ONE_HOUR)?;
    assert_eq!(report.failed_batch, Some(0));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_redirect_is_refused_and_never_followed() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let server = serve(rig.listener.try_clone()?, vec!["302 Found"]);
    let report = go(&rig, &request(1), "acme", STAMP, Duration::ZERO)?;
    assert_eq!(report.failed_batch, Some(0));
    assert_eq!(joined(server)?.len(), 1);
    Ok(())
}


#[test]
fn each_status_has_its_fixed_class() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let settings = loaded(&rig)?;
    let server = serve(
        rig.listener.try_clone()?,
        vec!["401 Unauthorized", "504 Gateway Timeout", "400 Bad Request", OK],
    );
    let elapsed = || Duration::ZERO;
    let mut send = clickhouse_sender(&settings, &elapsed)?;
    assert!(matches!(send(b"{}\n"), Err(SendError::Failed(InsertClass::Unauthorized))));
    assert!(matches!(send(b"{}\n"), Err(SendError::Failed(InsertClass::Timeout))));
    assert!(matches!(send(b"{}\n"), Err(SendError::Failed(InsertClass::Rejected))));
    assert!(send(b"{}\n").is_ok());
    joined(server)?;
    [
        InsertClass::ParseError,
        InsertClass::Unavailable,
        InsertClass::Timeout,
        InsertClass::Unauthorized,
        InsertClass::Rejected,
    ]
    .iter()
    .for_each(|class| assert!(SendError::Failed(*class).to_string().ends_with(class_text(*class))));
    Ok(())
}


#[test]
fn an_unreachable_server_is_a_failed_batch() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let settings = loaded(&rig)?;
    let free = TcpListener::bind("127.0.0.1:0")?;
    let port = free.local_addr()?.port();
    drop(free);
    let moved = MetricsSettings {
        url: format!("http://127.0.0.1:{port}"),
        ..settings
    };
    let elapsed = || Duration::ZERO;
    let mut send = clickhouse_sender(&moved, &elapsed)?;
    assert!(send(b"{}\n").is_err());
    Ok(())
}


#[test]
fn a_lookalike_host_is_refused_before_any_connection() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let port = rig.listener.local_addr()?.port();
    let text = fs::read_to_string(&rig.settings)?.replace("127.0.0.1", "localhost.evil.test");
    fs::write(&rig.settings, text)?;
    let failed = go(&rig, &request(TWO), "acme", STAMP, Duration::ZERO);
    assert!(
        matches!(failed, Err(RunError::Settings(LoadError::Invalid(SettingsError::Url(_))))),
        "{port}"
    );
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn plain_http_to_a_remote_host_is_refused() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let settings = loaded(&rig)?;
    ["http://example.org", "http://127.0.0.1:1?x=1", "https://user@example.org"]
        .iter()
        .for_each(|url| {
            let bad = MetricsSettings {
                url: (*url).to_string(),
                ..settings.clone()
            };
            assert!(matches!(validate_settings(&bad), Err(SettingsError::Url(_))), "{url}");
        });
    Ok(())
}


#[test]
fn a_tenant_core_pg_refuses_is_refused_before_any_io() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    fs::remove_file(rig.dir.path().join("password"))?;
    ["-x", "", "a b", "a/b"].iter().try_for_each(|tenant| -> TestResult {
        let failed = go(&rig, &request(TWO), tenant, STAMP, Duration::ZERO);
        assert!(matches!(failed, Err(RunError::Tenant(_))), "{tenant}");
        Ok(())
    })?;
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn settings_are_strict_and_bounded() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let settings = loaded(&rig)?;
    ["io`cs", "iocs;drop", "", "A", "a b"].iter().for_each(|name| {
        let table = MetricsSettings {
            table: (*name).to_string(),
            ..settings.clone()
        };
        let database = MetricsSettings {
            database: (*name).to_string(),
            ..settings.clone()
        };
        assert!(matches!(validate_settings(&table), Err(SettingsError::Identifier(_))), "{name}");
        assert!(matches!(validate_settings(&database), Err(SettingsError::Identifier(_))), "{name}");
    });
    ["", "a b", "a\nb", &"u".repeat(MAX_CA_BYTES as usize)].iter().for_each(|user| {
        let bad = MetricsSettings {
            user: (*user).to_string(),
            ..settings.clone()
        };
        assert!(matches!(validate_settings(&bad), Err(SettingsError::User)));
    });
    [0, MAX_TIMEOUT_MS + 1].iter().for_each(|timeout_ms| {
        let bad = MetricsSettings {
            timeout_ms: *timeout_ms,
            ..settings.clone()
        };
        assert!(matches!(validate_settings(&bad), Err(SettingsError::Timeout)));
    });
    let original = fs::read_to_string(&rig.settings)?;
    fs::write(&rig.settings, format!("{original}surprise: 1\n"))?;
    assert!(matches!(load_settings(&rig.settings), Err(LoadError::Config(_))));
    fs::write(&rig.settings, original.replace("ostyr\ntable", "a;b\ntable"))?;
    assert!(matches!(load_settings(&rig.settings), Err(LoadError::Invalid(_))));
    let without_timeout = original.replace(&format!("timeout_ms: {LONG_TIMEOUT_MS}\n"), "");
    fs::write(&rig.settings, without_timeout)?;
    assert_eq!(load_settings(&rig.settings)?.timeout_ms, metrics_ingest::settings::DEFAULT_TIMEOUT_MS);
    Ok(())
}


#[test]
fn the_password_file_is_checked_when_read() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let password = rig.dir.path().join("password");
    let elapsed = || Duration::ZERO;
    fs::write(&password, vec![b'p'; OVERSIZE_PASSWORD])?;
    assert!(matches!(clickhouse_sender(&loaded(&rig)?, &elapsed), Err(SendError::Password(_))));
    fs::write(&password, "\n")?;
    assert!(matches!(clickhouse_sender(&loaded(&rig)?, &elapsed), Err(SendError::Password(_))));
    let pipe = fifo(&rig, "pipe")?;
    let on_pipe = MetricsSettings {
        password_file: pipe,
        ..loaded(&rig)?
    };
    assert!(matches!(clickhouse_sender(&on_pipe, &elapsed), Err(SendError::Password(_))));
    fs::write(&password, NOT_UTF8)?;
    assert!(matches!(clickhouse_sender(&loaded(&rig)?, &elapsed), Err(SendError::PasswordEncoding(_))));
    let failed = go(&rig, &request(1), "acme", STAMP, Duration::ZERO);
    assert!(matches!(failed, Err(RunError::Send(SendError::PasswordEncoding(_)))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn the_ca_file_is_bounded_regular_and_parsed() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let elapsed = || Duration::ZERO;
    let with_ca = |path: PathBuf| -> Result<MetricsSettings, Box<dyn std::error::Error>> {
        Ok(MetricsSettings {
            ca_file: Some(path),
            ..loaded(&rig)?
        })
    };
    let big = rig.dir.path().join("big.pem");
    fs::write(&big, vec![b'a'; MAX_CA_BYTES as usize + 1])?;
    assert!(matches!(clickhouse_sender(&with_ca(big)?, &elapsed), Err(SendError::CaFile(_))));
    assert!(matches!(
        clickhouse_sender(&with_ca(fifo(&rig, "pipe.pem")?)?, &elapsed),
        Err(SendError::CaFile(_))
    ));
    let junk = rig.dir.path().join("junk.pem");
    fs::write(&junk, "-----BEGIN CERTIFICATE-----\nnot base64 !\n-----END CERTIFICATE-----\n")?;
    assert!(matches!(clickhouse_sender(&with_ca(junk)?, &elapsed), Err(SendError::Agent(_))));
    let good = rig.dir.path().join("good.pem");
    fs::write(&good, rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?.cert.pem())?;
    assert!(clickhouse_sender(&with_ca(good)?, &elapsed).is_ok());
    Ok(())
}


#[test]
fn rows_out_of_range_are_refused_and_nothing_is_sent() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    fs::remove_file(rig.dir.path().join("password"))?;
    let year = YEAR_SECONDS * NANOS_PER_SECOND;
    [STAMP + year, STAMP - year].iter().try_for_each(|now| -> TestResult {
        let report = go(&rig, &request(TWO), "acme", *now, Duration::ZERO)?;
        assert_eq!(report.refused.get(&RefusedRow::TimestampOutOfRange), Some(&(TWO as u64)));
        assert_eq!((report.batches_planned, report.batches_sent, report.failed_batch), (0, 0, None));
        Ok(())
    })?;
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn too_many_points_are_refused_before_any_send() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let report = go(&rig, &request(HUNDRED_THOUSAND), "acme", STAMP, Duration::ZERO)?;
    assert!(matches!(report.refusal, Some(Refusal::TooManyDataPoints { .. })));
    assert_eq!((report.rows, report.batches_planned), (0, 0));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn the_report_lists_counts_only() -> TestResult {
    let report = RunReport {
        tenant: "acme".to_string(),
        rows: THREE,
        dropped: BTreeMap::from([(DropReason::SeriesCap, SEVEN)]),
        refusal: Some(Refusal::TooLarge { bytes: 1 }),
        refused: BTreeMap::from([(RefusedRow::RowTooLarge, ELEVEN)]),
        batches_planned: TWO,
        batches_sent: 1,
        failed_batch: Some(1),
    };
    let mut out = Vec::new();
    write_report(&report, &mut out)?;
    let shown = String::from_utf8(out)?;
    [
        "tenant acme",
        "rows 3",
        "request refused TooLarge",
        "dropped series_cap 7",
        "refused row_too_large 11",
        "batches planned 2",
        "batches sent 1",
        "failed batch 1",
    ]
    .iter()
    .for_each(|line| assert!(shown.contains(line), "{shown}"));
    Ok(())
}


struct Refuses;


impl Write for Refuses {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn the_command_line_entry_point_reports_and_fails_on_a_batch() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 1)?;
    let settings = rig.settings.display().to_string();
    let file = rig.dir.path().join("request.pb");
    fs::write(&file, request(1))?;
    let path = file.display().to_string();
    let elapsed = || Duration::ZERO;
    let mut out = Vec::new();
    assert!(matches!(run_cli(&[], STAMP, &elapsed, &mut out), Err(CliError::Usage)));
    let missing = [settings.clone(), "/nonexistent/request.pb".to_string(), "acme".to_string()];
    assert!(matches!(run_cli(&missing, STAMP, &elapsed, &mut out), Err(CliError::Request(_))));
    let args = [settings.clone(), path.clone(), "acme".to_string()];
    let server = serve(rig.listener.try_clone()?, vec![OK]);
    run_cli(&args, STAMP, &elapsed, &mut out)?;
    joined(server)?;
    assert!(String::from_utf8(out.clone())?.contains("batches sent 1"));
    let failing = serve(rig.listener.try_clone()?, vec![SERVER_ERROR]);
    assert!(matches!(run_cli(&args, STAMP, &elapsed, &mut out), Err(CliError::BatchFailed(0))));
    joined(failing)?;
    let bad_tenant = [settings.clone(), path.clone(), "-x".to_string()];
    assert!(matches!(run_cli(&bad_tenant, STAMP, &elapsed, &mut out), Err(CliError::Run(_))));
    let silent = serve(rig.listener.try_clone()?, vec![OK]);
    assert!(matches!(run_cli(&args, STAMP, &elapsed, &mut Refuses), Err(CliError::Output(_))));
    joined(silent)?;
    Ok(())
}


struct FailsAt {
    calls: usize,
    fail_at: usize,
}


impl Write for FailsAt {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls == self.fail_at {
            Err(io::Error::other("closed"))
        } else {
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn every_write_of_the_report_can_fail() -> TestResult {
    let report = RunReport {
        tenant: "acme".to_string(),
        rows: 1,
        dropped: BTreeMap::from([(DropReason::SeriesCap, 1)]),
        refusal: Some(Refusal::TooLarge { bytes: 1 }),
        refused: BTreeMap::from([(RefusedRow::RowTooLarge, 1)]),
        batches_planned: 1,
        batches_sent: 0,
        failed_batch: Some(0),
    };
    let failures = (1..=REPORT_WRITES)
        .filter(|fail_at| write_report(&report, &mut FailsAt { calls: 0, fail_at: *fail_at }).is_err())
        .count();
    assert!(failures >= THREE * TWO);
    assert!(write_report(&report, &mut FailsAt { calls: 0, fail_at: 0 }).is_ok());
    Ok(())
}


#[test]
fn a_zero_batch_limit_and_invalid_settings_are_errors_before_any_send() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS, 0)?;
    assert!(matches!(
        go(&rig, &request(1), "acme", STAMP, Duration::ZERO),
        Err(RunError::Settings(LoadError::Invalid(SettingsError::Limit {
            field: "max_batch_rows",
            ..
        })))
    ));
    let valid = loaded(&self::rig(LONG_TIMEOUT_MS, 1)?)?;
    let bad = MetricsSettings {
        table: "a;b".to_string(),
        ..valid
    };
    let elapsed = || Duration::ZERO;
    assert!(matches!(clickhouse_sender(&bad, &elapsed), Err(SendError::Settings(_))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}
