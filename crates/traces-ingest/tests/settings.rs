mod common;


use common::types::TestResult;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};
use traces_ingest::model::Limits;
use traces_ingest::settings::{ceiling_limits, load_traces_settings, to_metrics_settings};


const CONNECTION: &str = "url: https://ch.example:8443\nuser: ostyr\npassword_file: /nonexistent/pw\ndatabase: ostyr\ntable: trace_spans\n";


const FIELD_COUNT: usize = 20;


const LOWERED_SPANS: usize = 10;


fn file(extra: &str) -> Result<(TempDir, PathBuf), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    fs::write(&path, format!("{CONNECTION}{extra}"))?;
    Ok((dir, path))
}


fn refusal(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(load_traces_settings(path).err().ok_or("the file was accepted")?.to_string())
}


fn fields() -> Vec<(&'static str, u64, u64)> {
    let top = ceiling_limits();
    vec![
        ("max_request_bytes", 1, top.max_request_bytes as u64),
        ("max_resource_spans", 1, top.max_resource_spans as u64),
        ("max_spans", 1, top.max_spans as u64),
        ("max_total_attributes", 1, top.max_total_attributes as u64),
        ("max_events_total", 1, top.max_events_total as u64),
        ("max_links_total", 1, top.max_links_total as u64),
        ("max_value_elements_total", 1, top.max_value_elements_total as u64),
        ("max_entity_refs_total", 1, top.max_entity_refs_total as u64),
        ("max_entity_keys_total", 1, top.max_entity_keys_total as u64),
        ("max_attributes_per_span", 1, top.max_attributes_per_span as u64),
        ("max_events_per_span", 1, top.max_events_per_span as u64),
        ("max_links_per_span", 1, top.max_links_per_span as u64),
        ("max_name_bytes", 1, top.max_name_bytes as u64),
        ("max_attribute_key_bytes", 1, top.max_attribute_key_bytes as u64),
        ("max_attribute_value_bytes", 1, top.max_attribute_value_bytes as u64),
        ("max_status_message_bytes", 1, top.max_status_message_bytes as u64),
        ("max_future_skew_seconds", 0, top.max_future_skew_seconds),
        ("max_batch_rows", 1, top.max_batch_rows as u64),
        ("max_batch_bytes", 1, top.max_batch_bytes as u64),
        ("retention_seconds", 1, top.retention_seconds),
    ]
}


#[test]
fn a_file_without_limits_gets_the_defaults_and_converts() -> TestResult {
    let (_dir, path) = file("")?;
    let settings = load_traces_settings(&path)?;
    assert_eq!(settings.limits, Limits::default());
    let converted = to_metrics_settings(&settings);
    assert_eq!(converted.url, "https://ch.example:8443");
    assert_eq!(converted.table, "trace_spans");
    assert_eq!(converted.timeout_ms, settings.timeout_ms);
    Ok(())
}


#[test]
fn a_partial_limits_section_keeps_the_other_defaults() -> TestResult {
    let (_dir, path) = file(&format!("limits:\n  max_spans: {LOWERED_SPANS}\n"))?;
    let settings = load_traces_settings(&path)?;
    assert_eq!(settings.limits.max_spans, LOWERED_SPANS);
    assert_eq!(settings.limits.max_events_total, Limits::default().max_events_total);
    Ok(())
}


#[test]
fn every_field_accepts_its_floor_and_ceiling_and_refuses_one_past_the_ceiling() -> TestResult {
    assert_eq!(fields().len(), FIELD_COUNT);
    fields().iter().try_for_each(|&(field, floor, top)| -> TestResult {
        let (_at_dir, at) = file(&format!("limits:\n  {field}: {top}\n"))?;
        load_traces_settings(&at)?;
        let (_low_dir, low) = file(&format!("limits:\n  {field}: {floor}\n"))?;
        load_traces_settings(&low)?;
        let (_over_dir, over) = file(&format!("limits:\n  {field}: {}\n", top + 1))?;
        let message = refusal(&over)?;
        assert!(message.contains(&format!("limits.{field} ")), "{field} over: {message}");
        Ok(())
    })
}


#[test]
fn a_zero_floor_is_refused_naming_the_field() -> TestResult {
    let (_dir, zero) = file("limits:\n  max_spans: 0\n")?;
    let message = refusal(&zero)?;
    assert!(message.contains("limits.max_spans "), "{message}");
    Ok(())
}


#[test]
fn unknown_keys_and_negative_numbers_are_refused() -> TestResult {
    let (_dir, unknown) = file("limits:\n  max_span: 10\n")?;
    assert!(refusal(&unknown)?.contains("max_span"));
    let (_top_dir, top) = file("surprise: 1\n")?;
    refusal(&top)?;
    let (_neg_dir, negative) = file("limits:\n  max_spans: -1\n")?;
    let message = refusal(&negative)?;
    assert!(message.contains("at `limits.max_spans`: invalid u64"), "{message}");
    Ok(())
}


#[test]
fn the_connection_checks_are_metrics_ingests() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("settings.yaml");
    fs::write(&path, CONNECTION.replace("https://ch.example:8443", "http://ch.example:8123"))?;
    refusal(&path)?;
    fs::write(&path, format!("{CONNECTION}timeout_ms: 0\n"))?;
    refusal(&path)?;
    Ok(())
}
