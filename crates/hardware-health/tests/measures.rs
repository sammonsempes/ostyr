mod common;


use common::{fixture, report_from, set, TestResult};
use hardware_health::measures::measures;
use serde_json::{json, Value};


const ATA_HEALTHY: &str = include_str!("fixtures/ata-healthy.json");


const ATA_FAILED: &str = include_str!("fixtures/ata-failed.json");


const NVME_HEALTHY: &str = include_str!("fixtures/nvme-healthy.json");


const ATA_TEMPERATURE: i64 = 34;


const ATA_HOURS: u64 = 12345;


const NVME_TEMPERATURE: i64 = -3;


const NVME_HOURS: u64 = 500;


const NVME_USED: u64 = 3;


const NVME_MEDIA_ERRORS: u64 = 2;


const REALLOCATED_ID: u64 = 5;


const ZERO_RAW: u64 = 0;


const POWER_ON_ID: u64 = 9;


fn summary(document: &Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(measures(&report_from(document)?)
        .into_iter()
        .map(|item| row(&item.name, &item.unit, item.value))
        .collect())
}


fn row(name: &str, unit: &str, value: f64) -> String {
    format!("{name} {unit} {value}")
}


#[test]
fn ata_measures_with_labels() -> TestResult {
    let expected = vec![
        row("hw.disk.temperature", "Cel", ATA_TEMPERATURE as f64),
        row("hw.disk.power_on_hours", "h", ATA_HOURS as f64),
        row("hw.disk.smart_attribute", "1", ZERO_RAW as f64),
        row("hw.disk.smart_attribute", "1", ATA_HOURS as f64),
    ];
    assert_eq!(summary(&fixture(ATA_HEALTHY)?)?, expected);
    let found = measures(&report_from(&fixture(ATA_HEALTHY)?)?);
    let labels = &found.last().ok_or("no measure")?.labels;
    assert_eq!(
        labels,
        &vec![
            ("id".to_string(), POWER_ON_ID.to_string()),
            ("name".to_string(), "Power_On_Hours".to_string())
        ]
    );
    assert_eq!(
        found
            .iter()
            .find(|item| item.name == "hw.disk.smart_attribute")
            .ok_or("no measure")?
            .labels
            .first(),
        Some(&("id".to_string(), REALLOCATED_ID.to_string()))
    );
    Ok(())
}


#[test]
fn nvme_measures() -> TestResult {
    let expected = vec![
        row("hw.disk.temperature", "Cel", NVME_TEMPERATURE as f64),
        row("hw.disk.power_on_hours", "h", NVME_HOURS as f64),
        row("hw.disk.percentage_used", "%", NVME_USED as f64),
        row("hw.disk.media_errors", "{error}", NVME_MEDIA_ERRORS as f64),
    ];
    assert_eq!(summary(&fixture(NVME_HEALTHY)?)?, expected);
    Ok(())
}


#[test]
fn missing_values_make_no_measure() -> TestResult {
    assert!(summary(&json!({}))?.is_empty());
    assert!(summary(&fixture(ATA_FAILED)?)?.is_empty());
    let no_raw = set(fixture(ATA_HEALTHY)?, "/ata_smart_attributes/table/0/raw", json!({}))?;
    assert_eq!(
        summary(&no_raw)?
            .iter()
            .filter(|line| line.starts_with("hw.disk.smart_attribute"))
            .count(),
        1
    );
    Ok(())
}


#[test]
fn a_hostile_name_never_becomes_a_label() -> TestResult {
    let mut report = report_from(&fixture(ATA_HEALTHY)?)?;
    report
        .attributes
        .iter_mut()
        .for_each(|attribute| attribute.name = Some("-evil".to_string()));
    let labels: Vec<_> = measures(&report).into_iter().flat_map(|item| item.labels).collect();
    assert!(labels.iter().all(|(key, _)| key == "id"));
    assert_eq!(labels.len(), report.attributes.len());
    Ok(())
}
