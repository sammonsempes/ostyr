mod common;


use common::{fixture, report_from, set, TestResult};
use hardware_health::assess::assess;
use hardware_health::model::{BlindReason, Health, Limits};
use hardware_health::parse::parse_smartctl;
use serde_json::{json, Value};


const ATA_HEALTHY: &str = include_str!("fixtures/ata-healthy.json");


const ATA_PREFAIL: &str = include_str!("fixtures/ata-prefail.json");


const ATA_FAILED: &str = include_str!("fixtures/ata-failed.json");


const NVME_HEALTHY: &str = include_str!("fixtures/nvme-healthy.json");


const OPEN_FAILED: &str = include_str!("fixtures/open-failed.json");


const EXIT: &str = "/smartctl/exit_status";


const PASSED: &str = "/smart_status/passed";


const NVME_LOG: &str = "/nvme_smart_health_information_log";


const OPEN_FAILED_BIT: u8 = 2;


const PARSE_FAILED_BIT: u8 = 1;


const FOUND_NOTHING_BIT: u8 = 4;


const SMART_FAILING_BIT: u8 = 8;


const OTHER_BIT: u8 = 16;


const CRITICAL_WARNING: u64 = 4;


const WORN_OUT: u64 = 100;


const ALMOST_WORN: u64 = 99;


const LOW_SPARE: u64 = 5;


const SPARE_AT_THRESHOLD: u64 = 10;


const THREE: usize = 3;


const SOME_MINOR: u64 = 7;


const OTHER_MAJOR: u64 = 2;


const WIDE_EXIT: u64 = 300;


fn verdict(document: &Value) -> Result<Health, Box<dyn std::error::Error>> {
    Ok(assess(&report_from(document)?))
}


fn nvme_with(field: &str, value: u64) -> Result<Value, String> {
    set(
        fixture(NVME_HEALTHY).map_err(|error| error.to_string())?,
        &format!("{NVME_LOG}/{field}"),
        json!(value),
    )
}


#[test]
fn healthy_ata_and_nvme() -> TestResult {
    assert_eq!(verdict(&fixture(ATA_HEALTHY)?)?, Health::Healthy);
    assert_eq!(verdict(&fixture(NVME_HEALTHY)?)?, Health::Healthy);
    let mut no_threshold = fixture(NVME_HEALTHY)?;
    no_threshold
        .pointer_mut(NVME_LOG)
        .and_then(Value::as_object_mut)
        .ok_or("no log")?
        .remove("available_spare_threshold");
    assert_eq!(verdict(&no_threshold)?, Health::Healthy);
    let no_log = set(fixture(NVME_HEALTHY)?, NVME_LOG, json!({}))?;
    assert_eq!(verdict(&no_log)?, blind("nvme critical_warning"));
    Ok(())
}


#[test]
fn predictive_failure_names_its_causes() -> TestResult {
    let expected = vec![
        "attribute 5 Reallocated_Sector_Ct".to_string(),
        "attribute 7 Seek_Error_Rate".to_string(),
        "attribute 3 unnamed".to_string(),
    ];
    assert_eq!(verdict(&fixture(ATA_PREFAIL)?)?, Health::PredictiveFailure(expected));
    assert_eq!(
        verdict(&nvme_with("critical_warning", CRITICAL_WARNING)?)?,
        Health::PredictiveFailure(vec!["nvme critical_warning".to_string()])
    );
    assert_eq!(
        verdict(&nvme_with("percentage_used", WORN_OUT)?)?,
        Health::PredictiveFailure(vec!["nvme percentage_used".to_string()])
    );
    assert_eq!(
        verdict(&nvme_with("available_spare", LOW_SPARE)?)?,
        Health::PredictiveFailure(vec!["nvme available_spare".to_string()])
    );
    assert_eq!(verdict(&nvme_with("percentage_used", ALMOST_WORN)?)?, Health::Healthy);
    assert_eq!(verdict(&nvme_with("available_spare", SPARE_AT_THRESHOLD)?)?, Health::Healthy);
    let everything = set(
        nvme_with("critical_warning", CRITICAL_WARNING)?,
        &format!("{NVME_LOG}/percentage_used"),
        json!(WORN_OUT),
    )?;
    let all = verdict(&set(everything, &format!("{NVME_LOG}/available_spare"), json!(LOW_SPARE))?)?;
    assert!(matches!(all, Health::PredictiveFailure(causes) if causes.len() == THREE));
    Ok(())
}


#[test]
fn failing_beats_predictive() -> TestResult {
    assert_eq!(verdict(&fixture(ATA_FAILED)?)?, Health::Failing);
    let prefail_but_failed = set(fixture(ATA_PREFAIL)?, PASSED, json!(false))?;
    assert_eq!(verdict(&prefail_but_failed)?, Health::Failing);
    Ok(())
}


#[test]
fn blind_spot_beats_everything() -> TestResult {
    let open_failed = fixture(OPEN_FAILED)?;
    assert_eq!(verdict(&open_failed)?, Health::BlindSpot(BlindReason::CommandFailed(OPEN_FAILED_BIT)));
    let failed_and_blind = set(fixture(ATA_FAILED)?, EXIT, json!(PARSE_FAILED_BIT))?;
    assert_eq!(
        verdict(&failed_and_blind)?,
        Health::BlindSpot(BlindReason::CommandFailed(PARSE_FAILED_BIT))
    );
    let nothing_found = set(open_failed.clone(), EXIT, json!(FOUND_NOTHING_BIT))?;
    assert_eq!(verdict(&nothing_found)?, Health::BlindSpot(BlindReason::CommandFailed(FOUND_NOTHING_BIT)));
    let no_verdict = set(set(fixture(ATA_FAILED)?, EXIT, json!(0))?, "/smart_status", json!({}))?;
    assert_eq!(verdict(&no_verdict)?, Health::BlindSpot(BlindReason::NoVerdict));
    assert_eq!(
        verdict(&json!({"json_format_version": [1, 0], "smart_status": {"passed": true}}))?,
        Health::BlindSpot(BlindReason::ExitStatusMissing)
    );
    assert_eq!(
        verdict(&json!({"json_format_version": [1, 0]}))?,
        Health::BlindSpot(BlindReason::ExitStatusMissing)
    );
    let other_bit_only = set(open_failed, EXIT, json!(OTHER_BIT))?;
    assert_eq!(
        verdict(&other_bit_only)?,
        Health::PredictiveFailure(vec!["attribute 5 Reallocated_Sector_Ct".to_string(), "exit status bit 4".to_string()])
    );
    Ok(())
}


fn blind(field: &str) -> Health {
    Health::BlindSpot(BlindReason::UnreadableHealthField(field.to_string()))
}


#[test]
fn exit_bits_three_and_four() -> TestResult {
    let healthy = fixture(ATA_HEALTHY)?;
    assert_eq!(verdict(&set(healthy.clone(), EXIT, json!(SMART_FAILING_BIT))?)?, Health::Failing);
    assert_eq!(
        verdict(&set(healthy.clone(), EXIT, json!(SMART_FAILING_BIT | OTHER_BIT))?)?,
        Health::Failing
    );
    assert_eq!(
        verdict(&set(healthy.clone(), EXIT, json!(OTHER_BIT))?)?,
        Health::PredictiveFailure(vec!["exit status bit 4".to_string()])
    );
    assert_eq!(verdict(&set(healthy.clone(), EXIT, json!(0))?)?, Health::Healthy);
    let no_verdict = set(set(healthy.clone(), EXIT, json!(SMART_FAILING_BIT))?, "/smart_status", json!({}))?;
    assert_eq!(verdict(&no_verdict)?, Health::Failing);
    let command_failed = set(healthy, EXIT, json!(SMART_FAILING_BIT | OPEN_FAILED_BIT))?;
    assert_eq!(
        verdict(&command_failed)?,
        Health::BlindSpot(BlindReason::CommandFailed(SMART_FAILING_BIT | OPEN_FAILED_BIT))
    );
    Ok(())
}


#[test]
fn format_version_must_be_one() -> TestResult {
    let unknown = Health::BlindSpot(BlindReason::UnknownFormat);
    let healthy = fixture(ATA_HEALTHY)?;
    assert_eq!(
        verdict(&set(healthy.clone(), "/json_format_version", json!([1, SOME_MINOR]))?)?,
        Health::Healthy
    );
    assert_eq!(verdict(&set(healthy.clone(), "/json_format_version", json!([OTHER_MAJOR, 0]))?)?, unknown);
    assert_eq!(verdict(&set(healthy.clone(), "/json_format_version", json!([1]))?)?, unknown);
    assert_eq!(verdict(&set(healthy.clone(), "/json_format_version", json!([1, "x"]))?)?, unknown);
    assert_eq!(verdict(&set(healthy.clone(), "/json_format_version", json!("1.0"))?)?, unknown);
    let mut absent = healthy;
    absent.as_object_mut().ok_or("not an object")?.remove("json_format_version");
    assert_eq!(verdict(&absent)?, unknown);
    assert_eq!(
        verdict(&set(fixture(ATA_FAILED)?, "/json_format_version", json!([OTHER_MAJOR, 0]))?)?,
        unknown
    );
    Ok(())
}


#[test]
fn rejected_health_fields_are_blind_spots() -> TestResult {
    assert_eq!(verdict(&nvme_text("critical_warning", "4")?)?, blind("nvme critical_warning"));
    assert_eq!(verdict(&nvme_text("available_spare", "x")?)?, blind("nvme available_spare"));
    assert_eq!(verdict(&nvme_text("media_errors", "x")?)?, blind("nvme media_errors"));
    assert_eq!(verdict(&set(fixture(ATA_HEALTHY)?, PASSED, json!("yes"))?)?, blind("smart_status.passed"));
    assert_eq!(verdict(&set(fixture(ATA_HEALTHY)?, PASSED, Value::Null)?)?, blind("smart_status.passed"));
    let row = "/ata_smart_attributes/table/0";
    assert_eq!(
        verdict(&set(fixture(ATA_HEALTHY)?, &format!("{row}/when_failed"), json!("soon"))?)?,
        blind("attribute 5 when_failed")
    );
    assert_eq!(
        verdict(&set(fixture(ATA_HEALTHY)?, &format!("{row}/value"), json!("x"))?)?,
        blind("attribute 5 value")
    );
    assert_eq!(
        verdict(&set(fixture(ATA_HEALTHY)?, &format!("{row}/thresh"), json!("x"))?)?,
        blind("attribute 5 thresh")
    );
    assert_eq!(
        verdict(&set(fixture(ATA_HEALTHY)?, &format!("{row}/flags/prefailure"), json!(1))?)?,
        blind("attribute 5 prefailure")
    );
    let non_prefail = "/ata_smart_attributes/table/1/value";
    assert_eq!(verdict(&set(fixture(ATA_HEALTHY)?, non_prefail, json!("x"))?)?, Health::Healthy);
    let failing = set(fixture(ATA_HEALTHY)?, PASSED, json!(false))?;
    assert_eq!(verdict(&set(failing, &format!("{row}/when_failed"), json!("soon"))?)?, Health::Failing);
    let wide_exit = set(fixture(ATA_HEALTHY)?, EXIT, json!(WIDE_EXIT))?;
    assert_eq!(verdict(&wide_exit)?, Health::BlindSpot(BlindReason::ExitStatusMissing));
    Ok(())
}


fn nvme_text(field: &str, value: &str) -> Result<Value, String> {
    set(
        fixture(NVME_HEALTHY).map_err(|error| error.to_string())?,
        &format!("{NVME_LOG}/{field}"),
        json!(value),
    )
}


const TABLE: &str = "/ata_smart_attributes/table";


const ROW_CAP: usize = 1;


const BAD_ID: i64 = -5;


const FRACTION_ID: f64 = 5.5;


fn replaced(base: &str, pointer: &str, value: Value) -> Result<Health, Box<dyn std::error::Error>> {
    verdict(&set(fixture(base)?, pointer, value)?)
}


#[test]
fn wrong_typed_containers_are_blind_spots() -> TestResult {
    [json!("x"), json!([1]), json!(SOME_NUMBER)]
        .into_iter()
        .try_for_each(|value| -> TestResult {
            assert_eq!(replaced(NVME_HEALTHY, NVME_LOG, value)?, blind("nvme log"));
            Ok(())
        })?;
    let flags = format!("{TABLE}/0/flags");
    assert_eq!(replaced(ATA_PREFAIL, &flags, json!("prefailure"))?, blind("attribute 5 flags"));
    assert_eq!(replaced(ATA_PREFAIL, &flags, json!([true]))?, blind("attribute 5 flags"));
    assert_eq!(replaced(ATA_HEALTHY, TABLE, json!({"0": {}}))?, blind("attribute table"));
    assert_eq!(replaced(ATA_HEALTHY, TABLE, json!(["x"]))?, blind("attribute row 0"));
    assert_eq!(replaced(ATA_HEALTHY, TABLE, Value::Null)?, blind("attribute table"));
    assert_eq!(
        replaced(ATA_HEALTHY, "/ata_smart_attributes", json!([{"id": SOME_NUMBER}]))?,
        blind("attribute table")
    );
    Ok(())
}


#[test]
fn rows_without_a_valid_id_are_blind_spots() -> TestResult {
    let row = format!("{TABLE}/0/id");
    [json!("5"), json!(BAD_ID), json!(FRACTION_ID), Value::Null]
        .into_iter()
        .try_for_each(|value| -> TestResult {
            assert_eq!(verdict(&set(fixture(ATA_PREFAIL)?, &row, value)?)?, blind("attribute row 0"));
            Ok(())
        })?;
    let absent = serde_json::from_str::<Value>(ATA_HEALTHY).map(|mut document| {
        document
            .pointer_mut(&format!("{TABLE}/0"))
            .and_then(Value::as_object_mut)
            .map(|object| object.remove("id"));
        document
    })?;
    assert_eq!(verdict(&absent)?, blind("attribute row 0"));
    Ok(())
}


#[test]
fn absent_containers_stay_healthy() -> TestResult {
    let mut document = fixture(ATA_HEALTHY)?;
    document.as_object_mut().map(|object| object.remove("ata_smart_attributes"));
    assert_eq!(verdict(&document)?, Health::Healthy);
    Ok(())
}


#[test]
fn rows_past_the_cap_are_a_blind_spot() -> TestResult {
    let limits = Limits {
        max_bytes: u64::MAX,
        max_attributes: ROW_CAP,
    };
    let bytes = serde_json::to_vec(&fixture(ATA_HEALTHY)?)?;
    let report = parse_smartctl(bytes.as_slice(), &limits)?;
    assert_eq!(assess(&report), Health::BlindSpot(BlindReason::TooManyAttributes));
    Ok(())
}


const SOME_NUMBER: u64 = 7;


const PAST_THRESHOLD_BIT: u8 = 32;


const ERROR_LOG_BIT: u8 = 64;


const SELF_TEST_LOG_BIT: u8 = 128;


fn degraded(causes: &[&str]) -> Health {
    Health::Degraded(causes.iter().map(|cause| (*cause).to_string()).collect())
}


#[test]
fn exit_bits_five_to_seven_degrade() -> TestResult {
    let at = |status: u8| replaced(ATA_HEALTHY, EXIT, json!(status));
    assert_eq!(at(PAST_THRESHOLD_BIT)?, degraded(&["past_threshold"]));
    assert_eq!(at(ERROR_LOG_BIT)?, degraded(&["error_log"]));
    assert_eq!(at(SELF_TEST_LOG_BIT)?, degraded(&["self_test_log"]));
    assert_eq!(
        at(PAST_THRESHOLD_BIT | ERROR_LOG_BIT | SELF_TEST_LOG_BIT)?,
        degraded(&["past_threshold", "error_log", "self_test_log"])
    );
    assert_eq!(
        at(PAST_THRESHOLD_BIT | OTHER_BIT)?,
        Health::PredictiveFailure(vec!["exit status bit 4".to_string()])
    );
    assert_eq!(at(PAST_THRESHOLD_BIT | SMART_FAILING_BIT)?, Health::Failing);
    assert_eq!(
        at(PAST_THRESHOLD_BIT | PARSE_FAILED_BIT)?,
        Health::BlindSpot(BlindReason::CommandFailed(PAST_THRESHOLD_BIT | PARSE_FAILED_BIT))
    );
    let unreadable = set(set(fixture(ATA_HEALTHY)?, EXIT, json!(ERROR_LOG_BIT))?, PASSED, json!("yes"))?;
    assert_eq!(verdict(&unreadable)?, blind("smart_status.passed"));
    Ok(())
}


#[test]
fn failing_row_without_prefailure_flag_is_blind() -> TestResult {
    let row = format!("{TABLE}/1");
    let now = set(fixture(ATA_HEALTHY)?, &format!("{row}/when_failed"), json!("now"))?;
    assert_eq!(verdict(&now)?, degraded(&["attribute 9 Power_On_Hours"]));
    let empty_flags = set(now.clone(), &format!("{row}/flags"), json!({}))?;
    assert_eq!(verdict(&empty_flags)?, blind("attribute 9 flags"));
    let mut no_flags = now.clone();
    no_flags.pointer_mut(&row).and_then(Value::as_object_mut).ok_or("no row")?.remove("flags");
    assert_eq!(verdict(&no_flags)?, blind("attribute 9 flags"));
    let past = set(empty_flags, &format!("{row}/when_failed"), json!("past"))?;
    assert_eq!(verdict(&past)?, Health::Healthy);
    let bad_flags = set(now, &format!("{row}/flags"), json!("x"))?;
    assert_eq!(report_from(&bad_flags)?.unreadable_health, vec!["attribute 9 flags".to_string()]);
    Ok(())
}


#[test]
fn nvme_without_its_log_is_blind() -> TestResult {
    let mut document = fixture(NVME_HEALTHY)?;
    document
        .as_object_mut()
        .ok_or("not an object")?
        .remove("nvme_smart_health_information_log");
    assert_eq!(verdict(&document)?, blind("nvme log"));
    let ata_like = set(document.clone(), "/device/protocol", json!("ATA"))?;
    assert_eq!(verdict(&ata_like)?, Health::Healthy);
    let failed = set(document, PASSED, json!(false))?;
    assert_eq!(verdict(&failed)?, Health::Failing);
    Ok(())
}


#[test]
fn nvme_log_without_critical_warning_is_blind() -> TestResult {
    let mut document = fixture(NVME_HEALTHY)?;
    document
        .pointer_mut(NVME_LOG)
        .and_then(Value::as_object_mut)
        .ok_or("no log")?
        .remove("critical_warning");
    assert_eq!(verdict(&document)?, blind("nvme critical_warning"));
    let empty = set(document.clone(), NVME_LOG, json!({}))?;
    assert_eq!(verdict(&empty)?, blind("nvme critical_warning"));
    let ata_like = set(document, "/device/protocol", json!("ATA"))?;
    assert_eq!(verdict(&ata_like)?, Health::Healthy);
    Ok(())
}


#[test]
fn usage_attribute_failing_now_degrades() -> TestResult {
    let row = format!("{TABLE}/1");
    let now = set(fixture(ATA_HEALTHY)?, &format!("{row}/when_failed"), json!("now"))?;
    let flagged = set(now, &format!("{row}/flags"), json!({"prefailure": false}))?;
    assert_eq!(verdict(&flagged)?, degraded(&["attribute 9 Power_On_Hours"]));
    let past = set(flagged.clone(), &format!("{row}/when_failed"), json!("past"))?;
    assert_eq!(verdict(&past)?, Health::Healthy);
    let with_bit = set(flagged, EXIT, json!(PAST_THRESHOLD_BIT))?;
    assert_eq!(verdict(&with_bit)?, degraded(&["attribute 9 Power_On_Hours", "past_threshold"]));
    Ok(())
}
