mod common;


use common::{fixture, report_from, set, TestResult};
use hardware_health::assess::assess;
use hardware_health::error::SmartError;
use hardware_health::grammar::is_clean_ident;
use hardware_health::limits::default_limits;
use hardware_health::model::{BlindReason, Health, Limits, Protocol, WhenFailed};
use hardware_health::parse::parse_smartctl;
use serde_json::json;
use std::io::Read;


const ATA_HEALTHY: &str = include_str!("fixtures/ata-healthy.json");


const NVME_HEALTHY: &str = include_str!("fixtures/nvme-healthy.json");


const WRONG_TYPES: &str = include_str!("fixtures/wrong-types.json");


const VDA: &str = include_str!("fixtures/vda.json");


const HOSTILE_FIELDS: usize = 2;


const SMALL_LIMIT: usize = 4;


const MANY: usize = 10_000;


const DEPTH: usize = 100_000;


const BIG_BYTES: u64 = 67_108_864;


const LONG_IDENT: usize = 65;


const OKAY_IDENT: usize = 64;


const TEMPERATURE: i64 = 34;


const HOURS: u64 = 12345;


const WRONG_TYPE_FIELDS: usize = 18;


const NEGATIVE: i64 = -12;


const SECOND: i64 = 2;


const FIRST_ROW: &str = "/ata_smart_attributes/table/0/when_failed";


const FIRST_ID: u64 = 5;


const SECOND_ID: u64 = 9;


const VALUE: u64 = 100;


const WORST: u64 = 99;


const THRESHOLD: u64 = 10;


const USED: u64 = 3;


const MEDIA_ERRORS: u64 = 2;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected failure"))
    }
}


#[test]
fn ata_report_is_typed() -> TestResult {
    let report = report_from(&fixture(ATA_HEALTHY)?)?;
    assert_eq!(report.device_name.as_deref(), Some("/dev/sda"));
    assert_eq!(report.protocol, Some(Protocol::Ata));
    assert_eq!(report.model.as_deref(), Some("Samsung SSD 860 EVO 500GB"));
    assert_eq!(report.serial.as_deref(), Some("S3Z2NB0K123456A"));
    assert_eq!((report.exit_status, report.smart_passed), (Some(0), Some(true)));
    assert_eq!((report.temperature_celsius, report.power_on_hours), (Some(TEMPERATURE), Some(HOURS)));
    assert_eq!((report.rejected_fields, report.omitted_attributes, report.nvme.is_none()), (0, 0, true));
    let first = report.attributes.first().ok_or("no attribute")?;
    assert_eq!(
        (first.id, first.value, first.worst, first.threshold),
        (FIRST_ID, Some(VALUE), Some(WORST), Some(THRESHOLD))
    );
    assert_eq!(
        (first.raw_value, first.when_failed, first.prefailure),
        (Some(0), Some(WhenFailed::Never), Some(true))
    );
    let second = report.attributes.last().ok_or("no attribute")?;
    assert_eq!(
        (second.id, second.when_failed, second.prefailure, second.raw_value),
        (SECOND_ID, Some(WhenFailed::Past), Some(false), Some(HOURS))
    );
    Ok(())
}


#[test]
fn nvme_and_other_protocols() -> TestResult {
    let report = report_from(&fixture(NVME_HEALTHY)?)?;
    let health = report.nvme.ok_or("no nvme")?;
    assert_eq!(report.protocol, Some(Protocol::Nvme));
    assert_eq!(
        (health.critical_warning, health.available_spare, health.available_spare_threshold),
        (Some(0), Some(VALUE), Some(THRESHOLD))
    );
    assert_eq!((health.percentage_used, health.media_errors), (Some(USED), Some(MEDIA_ERRORS)));
    let scsi = report_from(&set(fixture(NVME_HEALTHY)?, "/device/protocol", json!("SCSI"))?)?;
    assert_eq!(scsi.protocol, Some(Protocol::Scsi));
    let other = report_from(&set(fixture(NVME_HEALTHY)?, "/device/protocol", json!("USB"))?)?;
    assert_eq!(other.protocol, Some(Protocol::Other("USB".to_string())));
    Ok(())
}


#[test]
fn when_failed_values() -> TestResult {
    let now = report_from(&set(fixture(ATA_HEALTHY)?, FIRST_ROW, json!("now"))?)?;
    assert_eq!(now.attributes.first().ok_or("no row")?.when_failed, Some(WhenFailed::Now));
    let weird = report_from(&set(fixture(ATA_HEALTHY)?, FIRST_ROW, json!("weird"))?)?;
    assert_eq!(weird.attributes.first().ok_or("no row")?.when_failed, None);
    assert_eq!(weird.rejected_fields, 1);
    Ok(())
}


#[test]
fn size_cap_at_and_around_the_limit() -> TestResult {
    let body = ATA_HEALTHY.as_bytes();
    let exact = Limits {
        max_bytes: body.len() as u64,
        max_attributes: SMALL_LIMIT,
    };
    assert!(parse_smartctl(body, &exact).is_ok());
    let below = Limits {
        max_bytes: exact.max_bytes - 1,
        ..exact
    };
    let refused = parse_smartctl(body, &below);
    assert!(matches!(refused, Err(SmartError::Oversized { limit }) if limit == below.max_bytes));
    let mut padded = body.to_vec();
    padded.extend(std::iter::repeat_n(b' ', MANY));
    assert!(matches!(parse_smartctl(padded.as_slice(), &exact), Err(SmartError::Oversized { .. })));
    Ok(())
}


#[test]
fn read_failure_is_reported_with_its_cause() -> TestResult {
    let error = parse_smartctl(FailingReader, &default_limits()).err().ok_or("expected an error")?;
    assert!(matches!(error, SmartError::Read(_)));
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}


#[test]
fn malformed_input_quotes_nothing() -> TestResult {
    let secret = b"{\"serial_number\": SECRETTEXT}";
    let error = parse_smartctl(secret.as_slice(), &default_limits()).err().ok_or("expected an error")?;
    assert!(matches!(error, SmartError::Malformed { .. }));
    assert!(!error.to_string().contains("SECRETTEXT"));
    assert!(!format!("{error:?}").contains("SECRETTEXT"));
    let marker = parse_smartctl(b"{\"model_name\": \"SECRETTEXT\" \"x\"}".as_slice(), &default_limits())
        .err()
        .ok_or("expected an error")?;
    assert!(!marker.to_string().contains("SECRETTEXT") && !format!("{marker:?}").contains("SECRETTEXT"));
    let invalid_utf8 = parse_smartctl(b"{\"model_name\": \"\xff\xfe\"}".as_slice(), &default_limits());
    assert!(matches!(invalid_utf8, Err(SmartError::Malformed { .. })));
    let nan = parse_smartctl(b"{\"temperature\": {\"current\": NaN}}".as_slice(), &default_limits());
    assert!(matches!(nan, Err(SmartError::Malformed { .. })));
    let not_object = parse_smartctl(b"[1, 2]".as_slice(), &default_limits());
    assert!(matches!(not_object, Err(SmartError::NotAnObject)));
    Ok(())
}


#[test]
fn depth_bomb_is_malformed() -> TestResult {
    let limits = Limits {
        max_bytes: BIG_BYTES,
        ..default_limits()
    };
    let bomb = "[".repeat(DEPTH);
    assert!(matches!(parse_smartctl(bomb.as_bytes(), &limits), Err(SmartError::Malformed { .. })));
    let nested_object = format!("{}1{}", "{\"a\":".repeat(DEPTH), "}".repeat(DEPTH));
    assert!(matches!(
        parse_smartctl(nested_object.as_bytes(), &limits),
        Err(SmartError::Malformed { .. })
    ));
    Ok(())
}


#[test]
fn attribute_cap_counts_the_omitted_rows() -> TestResult {
    let row = r#"{"id": 7, "name": "Attr", "raw": {"value": 1}}"#;
    let rows = vec![row; MANY].join(",");
    let body = format!(r#"{{"ata_smart_attributes": {{"table": [{rows}]}}}}"#);
    let limits = Limits {
        max_bytes: BIG_BYTES,
        max_attributes: SMALL_LIMIT,
    };
    let report = parse_smartctl(body.as_bytes(), &limits)?;
    assert_eq!((report.attributes.len(), report.omitted_attributes), (SMALL_LIMIT, MANY - SMALL_LIMIT));
    Ok(())
}


#[test]
fn hostile_strings_are_dropped_and_counted() -> TestResult {
    let long = "s".repeat(LONG_IDENT);
    let hostile = ["a\u{202e}b", "a\u{200b}b", "-oProxyCommand=x", "a\nb", "caf\u{e9}", "", long.as_str()];
    hostile.iter().try_for_each(|text| -> TestResult {
        let report = report_from(&json!({"model_name": text, "serial_number": text}))?;
        assert_eq!((report.model, report.serial, report.rejected_fields), (None, None, HOSTILE_FIELDS));
        Ok(())
    })?;
    let longest = "s".repeat(OKAY_IDENT);
    let report = report_from(&json!({"serial_number": longest}))?;
    assert_eq!(report.serial.as_deref(), Some(longest.as_str()));
    assert!(is_clean_ident("a b-c") && !is_clean_ident("-a") && !is_clean_ident("\u{7f}"));
    Ok(())
}


#[test]
fn label_grammar() -> TestResult {
    let good = ["a", "/dev/sda", "Samsung SSD 860 EVO", "WD-WCC6Y0.1_x:y/z"];
    let bad = [" -x", "a,b=c", "x\"y", "{}", "a ", " a", ".a", "a(b)", "a\tb"];
    assert!(good.iter().all(|text| is_clean_ident(text)));
    assert!(bad.iter().all(|text| !is_clean_ident(text)));
    Ok(())
}


#[test]
fn format_major_and_unreadable_names() -> TestResult {
    let report = report_from(&fixture(ATA_HEALTHY)?)?;
    assert_eq!((report.format_major, report.unreadable_health.is_empty()), (Some(1), true));
    let bad_format = report_from(&json!({"json_format_version": [1, "x"]}))?;
    assert_eq!((bad_format.format_major, bad_format.rejected_fields), (None, 1));
    let not_array = report_from(&json!({"json_format_version": 1}))?;
    assert_eq!((not_array.format_major, not_array.rejected_fields), (None, 1));
    let wrong = report_from(&fixture(WRONG_TYPES)?)?;
    let expected: Vec<String> = [
        "smart_status.passed",
        "exit_status",
        "attribute 9 prefailure",
        "attribute 9 when_failed",
        "attribute 9 value",
        "attribute 9 thresh",
        "attribute row 1",
        "attribute row 2",
        "nvme critical_warning",
        "nvme available_spare",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect();
    assert_eq!(wrong.unreadable_health, expected);
    Ok(())
}


#[test]
fn wrong_types_hit_only_their_field() -> TestResult {
    let report = report_from(&fixture(WRONG_TYPES)?)?;
    assert_eq!(
        (report.exit_status, report.smart_passed, report.temperature_celsius, report.power_on_hours),
        (None, None, None, None)
    );
    assert_eq!((report.device_name, report.protocol, report.model), (None, None, None));
    let row = report.attributes.first().ok_or("row kept")?;
    assert_eq!((row.id, row.name.is_none(), row.value, row.worst), (SECOND_ID, true, None, None));
    assert_eq!((row.threshold, row.when_failed, row.prefailure, row.raw_value), (None, None, None, None));
    assert_eq!(report.attributes.len(), 1);
    let health = report.nvme.ok_or("nvme kept")?;
    assert_eq!((health.critical_warning, health.available_spare, health.media_errors), (None, None, None));
    assert_eq!(report.rejected_fields, WRONG_TYPE_FIELDS);
    let table = report_from(&json!({"ata_smart_attributes": {"table": "x"}}))?;
    assert_eq!((table.attributes.len(), table.rejected_fields), (0, 1));
    Ok(())
}


#[test]
fn negative_temperature_and_duplicate_keys() -> TestResult {
    let negative = report_from(&json!({"temperature": {"current": NEGATIVE}}))?;
    assert_eq!(negative.temperature_celsius, Some(NEGATIVE));
    let text = br#"{"model_name": "first", "model_name": "second", "temperature": {"current": 1, "current": 2}}"#;
    let duplicate = parse_smartctl(text.as_slice(), &default_limits())?;
    assert_eq!(
        (duplicate.model.as_deref(), duplicate.temperature_celsius),
        (Some("second"), Some(SECOND))
    );
    Ok(())
}


#[test]
fn real_capture_of_a_disk_without_smart() -> TestResult {
    let report = parse_smartctl(VDA.as_bytes(), &default_limits())?;
    assert_eq!((report.exit_status, report.smart_passed, report.attributes.len()), (Some(1), None, 0));
    assert_eq!(assess(&report), Health::BlindSpot(BlindReason::CommandFailed(1)));
    Ok(())
}


#[test]
fn refused_protocol_without_nvme_log_is_blind() -> TestResult {
    let blind = Health::BlindSpot(BlindReason::UnreadableHealthField("device.protocol".to_string()));
    let refused = [json!("NVMe "), json!("-NVMe"), json!(true), json!(null)];
    refused.iter().try_for_each(|value| -> TestResult {
        let report = report_from(&set(fixture(ATA_HEALTHY)?, "/device/protocol", value.clone())?)?;
        assert_eq!(assess(&report), blind, "{value}");
        Ok(())
    })?;
    let with_log = report_from(&set(fixture(NVME_HEALTHY)?, "/device/protocol", json!("NVMe "))?)?;
    assert_eq!(assess(&with_log), Health::Healthy);
    let absent = report_from(&fixture(ATA_HEALTHY)?)?;
    assert_eq!(assess(&absent), Health::Healthy);
    Ok(())
}
