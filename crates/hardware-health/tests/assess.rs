mod common;


use common::{fixture, report_from, set, TestResult};
use hardware_health::assess::assess;
use hardware_health::model::{BlindReason, Health};
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
    let no_threshold = set(fixture(NVME_HEALTHY)?, &format!("{NVME_LOG}/available_spare_threshold"), Value::Null)?;
    assert_eq!(verdict(&no_threshold)?, Health::Healthy);
    let no_log = set(fixture(NVME_HEALTHY)?, NVME_LOG, json!({}))?;
    assert_eq!(verdict(&no_log)?, Health::Healthy);
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
    let no_verdict = set(fixture(ATA_FAILED)?, PASSED, Value::Null)?;
    assert_eq!(verdict(&no_verdict)?, Health::BlindSpot(BlindReason::NoVerdict));
    assert_eq!(
        verdict(&json!({"smart_status": {"passed": true}}))?,
        Health::BlindSpot(BlindReason::ExitStatusMissing)
    );
    assert_eq!(verdict(&json!({}))?, Health::BlindSpot(BlindReason::ExitStatusMissing));
    let other_bits_only = set(open_failed, EXIT, json!(OTHER_BIT | SMART_FAILING_BIT))?;
    assert_eq!(
        verdict(&other_bits_only)?,
        Health::PredictiveFailure(vec!["attribute 5 Reallocated_Sector_Ct".to_string()])
    );
    Ok(())
}
