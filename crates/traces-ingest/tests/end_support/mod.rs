use crate::common::types::TestResult;
use crate::memory_support::{high_water_kib, report, reset_high_water, NOW, TENANT};
use crate::stand_in::{finish, serve};
use crate::worst_build::{build_request, Shape};
use std::fs::write;
use std::io;
use std::time::Duration;
use tempfile::tempdir;
use traces_ingest::model::Limits;
use traces_ingest::run::run_insert;
use traces_ingest::sampling::Sampling;


const TIMEOUT_MS: u64 = 300_000;


const SERVICE_FILL: u8 = b'"';


const ATTRIBUTES: usize = 3;


const EVENTS: usize = 3;


const LINKS: usize = 3;


fn limits_section(limits: &Limits) -> String {
    format!(
        "limits:\n  max_request_bytes: {}\n  max_resource_spans: {}\n  max_spans: {}\n  max_total_attributes: {}\n  max_events_total: {}\n  \
max_links_total: {}\n  max_value_elements_total: {}\n  max_entity_refs_total: {}\n  max_entity_keys_total: {}\n  max_attributes_per_span: {}\n  \
max_events_per_span: {}\n  max_links_per_span: {}\n  max_name_bytes: {}\n  max_attribute_key_bytes: {}\n  max_attribute_value_bytes: {}\n  \
max_status_message_bytes: {}\n  max_future_skew_seconds: {}\n  max_batch_rows: {}\n  max_batch_bytes: {}\n  retention_seconds: {}\n",
        limits.max_request_bytes,
        limits.max_resource_spans,
        limits.max_spans,
        limits.max_total_attributes,
        limits.max_events_total,
        limits.max_links_total,
        limits.max_value_elements_total,
        limits.max_entity_refs_total,
        limits.max_entity_keys_total,
        limits.max_attributes_per_span,
        limits.max_events_per_span,
        limits.max_links_per_span,
        limits.max_name_bytes,
        limits.max_attribute_key_bytes,
        limits.max_attribute_value_bytes,
        limits.max_status_message_bytes,
        limits.max_future_skew_seconds,
        limits.max_batch_rows,
        limits.max_batch_bytes,
        limits.retention_seconds
    )
}


pub fn check_end_to_end(limits: &Limits, budget_kib: u64, fail_at: Option<usize>) -> TestResult {
    let dir = tempdir()?;
    let server = serve(fail_at)?;
    write_secret(dir.path().join("password"), "pw\n")?;
    let settings = dir.path().join("settings.yaml");
    write(
        &settings,
        format!(
            "url: http://127.0.0.1:{}\nuser: ostyr\npassword_file: {}\ndatabase: ostyr\ntable: trace_spans\ntimeout_ms: {TIMEOUT_MS}\n{}",
            server.port,
            dir.path().join("password").display(),
            limits_section(limits)
        ),
    )?;
    let shape = Shape {
        attributes: ATTRIBUTES,
        events: EVENTS,
        links: LINKS,
        inner: 0,
        fill: SERVICE_FILL,
        timed: true,
    };
    let bytes = build_request(limits, shape);
    reset_high_water()?;
    let before = high_water_kib()?;
    let run = run_insert(&settings, &bytes, TENANT, &Sampling::default(), NOW, &|| Duration::ZERO)?;
    let growth = high_water_kib()?.saturating_sub(before);
    let served = finish(server)?;
    let handled = served.handled;
    report(&format!(
        "end to end: {} bytes, growth {growth} KiB, rows {}, planned {}, sent {}, failed {:?}, server handled {handled}",
        bytes.len(),
        run.rows,
        run.batches_planned,
        run.batches_sent,
        run.failed_batch
    ))?;
    assert!(served.errors.is_empty(), "{:?}", served.errors);
    assert!(run.refusal.is_none());
    assert!(run.refused.is_empty());
    assert!(run.batches_planned > 1);
    assert_eq!(run.failed_batch, fail_at);
    assert_eq!(handled, run.batches_sent + usize::from(fail_at.is_some()));
    assert!(growth < budget_kib, "{growth} KiB");
    Ok(())
}


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> io::Result<()> {
    write(path.as_ref(), content)?;
    std::fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> io::Result<()> {
    write(path.as_ref(), content)
}
