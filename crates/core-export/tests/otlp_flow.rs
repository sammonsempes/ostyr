#[path = "common/http_sink.rs"]
mod http_sink;
#[path = "common/types.rs"]
mod types;


use core_audit::log::{append, genesis_log, open_file_log};
use core_config::reload::{current_config, reload, ReloadContext, ReloadEngine, ReloadOutcome};
use core_config::types::SharedAuditFn;
use core_export::buffer::list_batches;
use core_export::cli::{audit_into, run_otlp, sample_events};
use core_export::config::{parse_export, ExportConfig};
use core_export::error::ExportError;
use core_export::pipeline::export_otlp;
use core_export::reload::{export_state, open_export_engine, validate_otlp};
use core_export::types::BoxError;
use core_export::webhook::RetryPolicy;
use std::fs;
use std::io;
use std::path::Path;
use tempfile::tempdir;
use time::OffsetDateTime;
use types::TestResult;


const FIXED_UNIX: i64 = 1_700_000_000;


const STATUS_OK: u16 = 200;


const TWO_ATTEMPTS: u32 = 2;


const THREE_EVENTS: u64 = 3;


fn now() -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(FIXED_UNIX)
}


fn fast_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: TWO_ATTEMPTS,
        ..RetryPolicy::default()
    }
}


fn otlp_yaml(endpoint: &str, buffer: &Path, extra: &str) -> String {
    let insecure = if endpoint.starts_with("http://") {
        "  allow_insecure_loopback: true\n"
    } else {
        ""
    };
    format!(
        "otlp:\n  endpoint: {endpoint}\n  buffer_dir: {}\n  tenant: acme\n{insecure}{extra}",
        buffer.display()
    )
}


fn engine_for(path: &Path) -> Result<ReloadEngine<ExportConfig>, Box<dyn std::error::Error>> {
    let log = genesis_log(io::sink());
    let context = ReloadContext {
        actor_id: "test".to_string(),
        tenant: "acme".to_string(),
        module: "core-export".to_string(),
        target: path.display().to_string(),
        request_id: "r".to_string(),
    };
    Ok(open_export_engine(path, Box::new(move |entry| append(&log, entry)), context)?)
}


fn send_sample(engine: &ReloadEngine<ExportConfig>) -> Result<String, Box<dyn std::error::Error>> {
    let settings = current_config(engine);
    let otlp = settings.otlp.as_ref().ok_or("no otlp")?;
    let report = run_otlp(otlp, &sample_events(1, 0, now()?), &fast_policy(), &mut |_delay| {}, now()?)?;
    Ok(format!("sent={}", report.sent_batches))
}


#[test]
fn reloads_are_appended_to_the_audit_file() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("export.yaml");
    fs::write(&path, otlp_yaml("http://127.0.0.1:1/v1/logs", dir.path(), ""))?;
    let audit = dir.path().join("reload.audit");
    let context = ReloadContext {
        actor_id: "test".to_string(),
        tenant: "acme".to_string(),
        module: "core-export".to_string(),
        target: path.display().to_string(),
        request_id: "r".to_string(),
    };
    let engine = open_export_engine(&path, audit_into(open_file_log(&audit)?), context)?;
    fs::write(&path, otlp_yaml("http://127.0.0.1:2/v1/logs", dir.path(), ""))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert!(fs::read_to_string(&audit)?.contains("config.reload"));
    Ok(())
}


#[test]
fn bad_ca_and_bad_token_files_are_errors_before_any_request() -> TestResult {
    let dir = tempdir()?;
    let buffer = dir.path().join("buf");
    let base = |extra: &str| parse_export(&otlp_yaml("https://localhost:1/v1/logs", &buffer, extra), "test");
    let events = sample_events(1, 0, now()?);
    let missing_ca = base("  ca_file: /nonexistent/ca.pem\n")?.otlp.ok_or("no otlp")?;
    assert!(matches!(
        run_otlp(&missing_ca, &events, &fast_policy(), &mut |_delay| {}, now()?),
        Err(ExportError::Io { .. })
    ));
    let missing_token = base("  token_file: /nonexistent/token\n")?.otlp.ok_or("no otlp")?;
    assert!(matches!(
        run_otlp(&missing_token, &events, &fast_policy(), &mut |_delay| {}, now()?),
        Err(ExportError::Io { .. })
    ));
    Ok(())
}


#[test]
fn a_down_collector_buffers_and_the_buffer_drains_once_it_is_back() -> TestResult {
    let dir = tempdir()?;
    let buffer = dir.path().join("buf");
    let config = parse_export(&otlp_yaml("http://127.0.0.1:1/v1/logs", &buffer, ""), "test")?
        .otlp
        .ok_or("no otlp")?;
    let mut down = |_body: &str| -> Result<(), BoxError> { Err("down".into()) };
    let first = export_otlp(
        &sample_events(THREE_EVENTS, 0, now()?),
        &config,
        &fast_policy(),
        &mut down,
        &mut |_delay| {},
        "h",
        now()?,
    )?;
    assert_eq!((first.sent_batches, first.buffered_batches), (0, 1));
    assert_eq!(list_batches(&buffer)?.len(), 1);
    let mut received = Vec::new();
    let mut up = |body: &str| -> Result<(), BoxError> {
        received.push(body.to_string());
        Ok(())
    };
    let second = export_otlp(&[], &config, &fast_policy(), &mut up, &mut |_delay| {}, "h", now()?)?;
    assert_eq!(second.drained_batches, 1);
    assert!(received.iter().all(|body| body.contains("resourceLogs")));
    assert!(list_batches(&buffer)?.is_empty());
    Ok(())
}


#[test]
fn settings_swap_live_and_an_invalid_candidate_keeps_the_old_ones() -> TestResult {
    let dir = tempdir()?;
    let first = http_sink::spawn_http_sink(None, vec![STATUS_OK])?;
    let second = http_sink::spawn_http_sink(None, vec![STATUS_OK])?;
    let buffer = dir.path().join("buf");
    let path = dir.path().join("export.yaml");
    fs::write(&path, otlp_yaml(&format!("http://127.0.0.1:{}/v1/logs", first.port), &buffer, ""))?;
    let engine = engine_for(&path)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    assert!(send_sample(&engine)?.starts_with("sent=1"));
    assert_eq!(first.bodies.join().map_err(|_panic| "sink thread panicked")??.len(), 1);
    let new_endpoint = format!("http://127.0.0.1:{}/v1/logs", second.port);
    fs::write(&path, otlp_yaml(&new_endpoint, &buffer, ""))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(
        current_config(&engine).otlp.as_ref().map(|otlp| otlp.endpoint.clone()),
        Some(new_endpoint)
    );
    assert!(send_sample(&engine)?.starts_with("sent=1"));
    assert_eq!(second.bodies.join().map_err(|_panic| "sink thread panicked")??.len(), 1);
    fs::write(&path, otlp_yaml("ftp://nope", &buffer, ""))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert!(current_config(&engine)
        .otlp
        .as_ref()
        .is_some_and(|otlp| otlp.endpoint.starts_with("http://127.0.0.1")));
    fs::write(&path, "otlp: [")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    Ok(())
}


#[test]
fn validation_refuses_each_unusable_otlp_setting() -> TestResult {
    let dir = tempdir()?;
    let buffer = dir.path().join("buf");
    let parse = |endpoint: &str, extra: &str| parse_export(&otlp_yaml(endpoint, &buffer, extra), "test");
    assert!(validate_otlp(&parse("https://c.example/v1/logs", "")?).is_ok());
    assert!(validate_otlp(&parse("http://c.example/v1/logs", "")?).is_err());
    assert!(validate_otlp(&parse("http://127.0.0.1:1/v1/logs", "")?).is_ok());
    assert!(validate_otlp(&parse("c.example", "")?).is_err());
    assert!(validate_otlp(&parse("https://c.example", "  batch_size: 0\n")?).is_err());
    assert!(validate_otlp(&parse("https://c.example", "  token_file: /nonexistent/token\n")?).is_err());
    let token = dir.path().join("token");
    fs::write(&token, "tok")?;
    assert!(validate_otlp(&parse("https://c.example", &format!("  token_file: {}\n", token.display()))?).is_ok());
    assert!(validate_otlp(&parse_export("webhook:\n  url: https://x.example\n  buffer_dir: /b\n", "test")?).is_ok());
    Ok(())
}


#[test]
fn the_state_lists_each_section_with_secret_references_only() -> TestResult {
    let config = parse_export(
        "webhook:\n  url: https://x.example\n  token: vault://kv/secret\n  buffer_dir: /b\n",
        "test",
    )?;
    let state = export_state(&config);
    assert_eq!(state.keys().map(String::as_str).collect::<Vec<_>>(), vec!["otlp", "syslog", "webhook"]);
    assert_eq!(state.get("otlp").map(String::as_str), Some("None"));
    Ok(())
}


#[test]
fn the_first_load_is_validated_like_a_reload() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("export.yaml");
    let context = || ReloadContext {
        actor_id: "test".to_string(),
        tenant: "acme".to_string(),
        module: "core-export".to_string(),
        target: path.display().to_string(),
        request_id: "r".to_string(),
    };
    let audit = || -> Box<SharedAuditFn> {
        let log = genesis_log(io::sink());
        Box::new(move |entry| append(&log, entry))
    };
    fs::write(&path, "otlp:\n  endpoint: http://127.0.0.1:1/v1/logs\n  buffer_dir: /b\n")?;
    assert!(matches!(open_export_engine(&path, audit(), context()), Err(ExportError::Invalid(_))));
    fs::write(
        &path,
        otlp_yaml("https://c.example/v1/logs", dir.path(), "  token_file: /nonexistent/token\n"),
    )?;
    assert!(matches!(open_export_engine(&path, audit(), context()), Err(ExportError::Io { .. })));
    Ok(())
}
