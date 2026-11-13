#[path = "common/types.rs"]
mod types;


use hardware_health::error::SmartError;
use hardware_health::limits::{DEFAULT_MAX_BYTES, DEFAULT_MAX_UPS_LINES};
use hardware_health::model::{BlindReason, Health, UpsFlag, UpsReport, UpsThresholds};
use hardware_health::ups::{flag_of, is_key, parse_thresholds, parse_upsc};
use hardware_health::ups_assess::{assess_ups, ups_measures};
use std::io::Read;
use types::TestResult;


const OL: &str = include_str!("fixtures/lab-ups-OL.txt");


const OB: &str = include_str!("fixtures/lab-ups-OB.txt");


const OBLB: &str = include_str!("fixtures/lab-ups-OBLB.txt");


const OLRB: &str = include_str!("fixtures/lab-ups-OLRB.txt");


const OLFROB: &str = include_str!("fixtures/lab-ups-OLFROB.txt");


const CHRG: &str = include_str!("fixtures/lab-ups-CHRG.txt");


const BYPASS: &str = include_str!("fixtures/lab-ups-BYPASS.txt");


const STALE: &str = include_str!("fixtures/lab-ups-stale.txt");


const UNKNOWN: &str = include_str!("fixtures/lab-ups-unknown.txt");


const THRESHOLD_FILE: &str = include_str!("fixtures/ups-thresholds.yaml");


const SMALL_BYTES: u64 = 64;


const SMALL_LINES: usize = 3;


const BOMB_LINES: usize = 10_000;


const BOMB_LINE_BYTES: usize = 2 * 1_048_576;


const LONG_KEY_CHARS: usize = 65;


const DEFAULT_CHARGE: u8 = 50;


const DEFAULT_RUNTIME: u32 = 300;


const FLAG_COUNT: usize = 13;


const FULL_CHARGE: f64 = 100.0;


const FULL_RUNTIME: f64 = 1800.0;


const MAINS_VOLTS: f64 = 230.0;


const LOAD_PERCENT: f64 = 23.0;


const TEMPERATURE: f64 = 28.5;


const COLD: f64 = -4.0;


const OVERLOAD: f64 = 150.0;


const STALE_REJECTED: usize = 2;


const NEGATIVE_REJECTED: usize = 2;


const BAD_KEY_COUNT: usize = 5;


const INVALID_UTF8: &[u8] = &[0xff, 0xfe];


const STRICT_CHARGE: u8 = 90;


const MEASURE_COUNT: usize = 6;


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected"))
    }
}


fn defaults() -> UpsThresholds {
    UpsThresholds {
        min_battery_charge: DEFAULT_CHARGE,
        min_runtime_seconds: DEFAULT_RUNTIME,
    }
}


fn parse(text: &str) -> Result<UpsReport, SmartError> {
    parse_upsc(text.as_bytes(), DEFAULT_MAX_BYTES, DEFAULT_MAX_UPS_LINES)
}


fn verdict(text: &str) -> Result<Health, SmartError> {
    Ok(assess_ups(&parse(text)?, &defaults()))
}


fn degraded(causes: &[&str]) -> Health {
    Health::Degraded(causes.iter().map(|cause| (*cause).to_string()).collect())
}


#[test]
fn lab_online_is_healthy() -> TestResult {
    let report = parse(OL)?;
    assert_eq!(verdict(OL)?, Health::Healthy);
    assert_eq!(report.battery_charge, Some(FULL_CHARGE));
    assert_eq!(report.battery_runtime, Some(FULL_RUNTIME));
    assert_eq!(report.input_voltage, Some(MAINS_VOLTS));
    assert_eq!(report.output_voltage, Some(MAINS_VOLTS));
    assert_eq!(report.load, Some(LOAD_PERCENT));
    assert_eq!(report.temperature, Some(TEMPERATURE));
    assert_eq!(report.rejected_fields, 0);
    assert!(report.unreadable.is_empty());
    Ok(())
}


#[test]
fn lab_states_give_their_verdicts() -> TestResult {
    assert_eq!(verdict(OB)?, degraded(&["on battery"]));
    assert_eq!(verdict(OBLB)?, Health::Failing);
    assert_eq!(verdict(OLRB)?, degraded(&["replace battery"]));
    assert_eq!(
        verdict(CHRG)?,
        degraded(&["battery charge below threshold", "battery runtime below threshold"])
    );
    assert_eq!(verdict(BYPASS)?, degraded(&["alarm", "bypass"]));
    Ok(())
}


#[test]
fn unknown_flag_is_blind_and_counted() -> TestResult {
    let report = parse(OLFROB)?;
    assert_eq!(report.rejected_fields, 1);
    assert_eq!(report.unreadable, vec!["ups.status".to_string()]);
    assert_eq!(
        assess_ups(&report, &defaults()),
        Health::BlindSpot(BlindReason::UnreadableHealthField("ups.status".to_string()))
    );
    Ok(())
}


#[test]
fn stale_and_unknown_ups_are_blind() -> TestResult {
    assert_eq!(verdict(STALE)?, Health::BlindSpot(BlindReason::NoVerdict));
    assert_eq!(verdict(UNKNOWN)?, Health::BlindSpot(BlindReason::NoVerdict));
    assert_eq!(parse(STALE)?.rejected_fields, STALE_REJECTED);
    Ok(())
}


#[test]
fn empty_status_is_blind() -> TestResult {
    assert_eq!(verdict("ups.status:\n")?, Health::BlindSpot(BlindReason::NoVerdict));
    assert_eq!(verdict("ups.status: \n")?, Health::BlindSpot(BlindReason::NoVerdict));
    assert_eq!(verdict("")?, Health::BlindSpot(BlindReason::NoVerdict));
    assert_eq!(
        verdict("ups.status: FROB\n")?,
        Health::BlindSpot(BlindReason::UnreadableHealthField("ups.status".to_string()))
    );
    Ok(())
}


#[test]
fn failing_flags() -> TestResult {
    assert_eq!(verdict("ups.status: OB LB\n")?, Health::Failing);
    assert_eq!(verdict("ups.status: OL FSD\n")?, Health::Failing);
    assert_eq!(verdict("ups.status: OFF\n")?, Health::Failing);
    assert_eq!(verdict("ups.status: OL OVER\n")?, Health::Failing);
    assert_eq!(verdict("ups.status: OL LB\n")?, Health::Healthy);
    Ok(())
}


#[test]
fn no_line_status_is_degraded() -> TestResult {
    assert_eq!(verdict("ups.status: CHRG\n")?, degraded(&["line status unknown"]));
    assert_eq!(verdict("ups.status: OL TRIM BOOST DISCHRG\n")?, Health::Healthy);
    Ok(())
}


#[test]
fn rejected_charge_or_runtime_is_blind_whatever_the_line() -> TestResult {
    let blind = |field: &str| Health::BlindSpot(BlindReason::UnreadableHealthField(field.to_string()));
    let values = ["-1", "150", "NaN", "1e400", "inf"];
    ["OL", "OB"].iter().try_for_each(|status| -> TestResult {
        values.iter().try_for_each(|value| -> TestResult {
            assert_eq!(
                verdict(&format!("ups.status: {status}\nbattery.charge: {value}\n"))?,
                blind("battery.charge")
            );
            Ok(())
        })
    })?;
    assert_eq!(verdict("ups.status: OL\nbattery.runtime: NaN\n")?, blind("battery.runtime"));
    assert_eq!(verdict("ups.status: OL\nups.load: NaN\n")?, Health::Healthy);
    assert_eq!(parse("ups.status: OB\nbattery.charge: 150\n")?.rejected_fields, 1);
    Ok(())
}


#[test]
fn rejected_lines_are_blind() -> TestResult {
    let blind = Health::BlindSpot(BlindReason::UnreadableHealthField("line".to_string()));
    let lines = ["battery.charge:50", "battery.charge : 50", "battery charge: 5", "Battery.charge: 5"];
    lines.iter().try_for_each(|line| -> TestResult {
        assert_eq!(verdict(&format!("ups.status: OL\n{line}\n"))?, blind, "{line}");
        assert_eq!(verdict(&format!("ups.status: OB\n{line}\n"))?, blind, "{line}");
        Ok(())
    })
}


#[test]
fn bad_numbers_are_rejected_and_counted() -> TestResult {
    let fields = [
        "battery.charge",
        "battery.runtime",
        "input.voltage",
        "output.voltage",
        "ups.load",
        "ups.temperature",
    ];
    let values = ["NaN", "1e400", "inf", "abc", ""];
    fields.iter().try_for_each(|field| -> TestResult {
        values.iter().try_for_each(|value| -> TestResult {
            let report = parse(&format!("ups.status: OL\n{field}: {value}\n"))?;
            assert_eq!(report.rejected_fields, 1, "{field} {value}");
            assert_eq!(report.unreadable, vec![(*field).to_string()]);
            Ok(())
        })
    })?;
    let negative = parse("battery.charge: -1\nbattery.runtime: -5\nups.temperature: -4\nups.load: 150\n")?;
    assert_eq!(negative.battery_charge, None);
    assert_eq!(negative.battery_runtime, None);
    assert_eq!(negative.temperature, Some(COLD));
    assert_eq!(negative.load, Some(OVERLOAD));
    assert_eq!(negative.rejected_fields, NEGATIVE_REJECTED);
    assert_eq!(parse("battery.charge: 100.5\n")?.battery_charge, None);
    Ok(())
}


#[test]
fn bad_keys_are_counted_not_kept() -> TestResult {
    let text = format!(
        "ups status: x\nUPS.STATUS: OL\n: x\n{}: x\nno separator\nups.status: OL\n",
        "a".repeat(LONG_KEY_CHARS)
    );
    let report = parse(&text)?;
    assert_eq!(report.rejected_fields, BAD_KEY_COUNT);
    assert!(report.status.is_some());
    assert!(is_key("battery.charge_2"));
    assert!(!is_key(""));
    assert!(!is_key("a b"));
    assert!(!is_key("Abc"));
    Ok(())
}


#[test]
fn duplicate_key_is_refused() -> TestResult {
    let outcome = parse("ups.status: OL\nups.status: OB LB\n");
    assert!(matches!(outcome, Err(SmartError::DuplicateKey)));
    let message = outcome.err().map(|error| error.to_string()).ok_or("no error")?;
    assert!(!message.contains("OB LB"));
    assert!(matches!(parse("x.y: 1\nx.y: 2\n"), Err(SmartError::DuplicateKey)));
    Ok(())
}


#[test]
fn value_splits_on_first_separator_only() -> TestResult {
    let report = parse("ups.status: OL\nups.mfr: a: b: c\n")?;
    assert_eq!(report.rejected_fields, 0);
    Ok(())
}


#[test]
fn caps_refuse_oversized_input() -> TestResult {
    let many_lines = "ups.status: OL\n".repeat(BOMB_LINES);
    assert!(matches!(
        parse(&many_lines),
        Err(SmartError::TooManyLines {
            limit: DEFAULT_MAX_UPS_LINES
        })
    ));
    let long_line = format!("ups.status: {}\n", "O".repeat(BOMB_LINE_BYTES));
    assert!(matches!(parse(&long_line), Err(SmartError::Oversized { limit: DEFAULT_MAX_BYTES })));
    let small = parse_upsc(OL.as_bytes(), SMALL_BYTES, DEFAULT_MAX_UPS_LINES);
    assert!(matches!(small, Err(SmartError::Oversized { limit: SMALL_BYTES })));
    let lines = parse_upsc(OL.as_bytes(), DEFAULT_MAX_BYTES, SMALL_LINES);
    assert!(matches!(lines, Err(SmartError::TooManyLines { limit: SMALL_LINES })));
    let exact = parse_upsc("ups.status: OL\n".as_bytes(), DEFAULT_MAX_BYTES, 1)?;
    assert!(exact.status.is_some());
    Ok(())
}


#[test]
fn bad_utf8_and_read_errors_are_refused() -> TestResult {
    assert!(matches!(
        parse_upsc(INVALID_UTF8, DEFAULT_MAX_BYTES, DEFAULT_MAX_UPS_LINES),
        Err(SmartError::NotUtf8(_))
    ));
    assert!(matches!(
        parse_upsc(FailingReader, DEFAULT_MAX_BYTES, DEFAULT_MAX_UPS_LINES),
        Err(SmartError::Read(_))
    ));
    Ok(())
}


#[test]
fn every_flag_is_known() -> TestResult {
    let names = [
        "OL", "OB", "LB", "RB", "CHRG", "DISCHRG", "BYPASS", "OVER", "TRIM", "BOOST", "FSD", "ALARM", "OFF",
    ];
    let flags: Option<Vec<UpsFlag>> = names.iter().map(|name| flag_of(name)).collect();
    let distinct: std::collections::BTreeSet<UpsFlag> = flags.ok_or("unknown flag")?.into_iter().collect();
    assert_eq!(distinct.len(), FLAG_COUNT);
    assert_eq!(flag_of("FROB"), None);
    assert_eq!(flag_of("ol"), None);
    Ok(())
}


#[test]
fn thresholds_defaults_and_values() -> TestResult {
    assert_eq!(parse_thresholds(THRESHOLD_FILE)?, defaults());
    assert_eq!(parse_thresholds("{}")?, defaults());
    let custom = parse_thresholds("min_battery_charge: 90\nmin_runtime_seconds: 5000\n")?;
    assert_eq!(custom.min_battery_charge, STRICT_CHARGE);
    assert_eq!(assess_ups(&parse(OL)?, &custom), degraded(&["battery runtime below threshold"]));
    Ok(())
}


#[test]
fn thresholds_are_strict() -> TestResult {
    assert!(matches!(
        parse_thresholds("min_battery_charge: 0\n"),
        Err(SmartError::ChargeThresholdRange)
    ));
    assert!(matches!(
        parse_thresholds("min_battery_charge: 101\n"),
        Err(SmartError::ChargeThresholdRange)
    ));
    assert!(matches!(parse_thresholds("min_battery_charge: 300\n"), Err(SmartError::Thresholds(_))));
    assert!(matches!(parse_thresholds("min_battery_charges: 5\n"), Err(SmartError::Thresholds(_))));
    assert!(matches!(parse_thresholds("min_runtime_seconds: -1\n"), Err(SmartError::Thresholds(_))));
    assert!(matches!(parse_thresholds("- a\n"), Err(SmartError::Thresholds(_))));
    let huge = format!("min_runtime_seconds: 1\n{}", " ".repeat(hardware_health::limits::MAX_THRESHOLDS_BYTES));
    assert!(matches!(parse_thresholds(&huge), Err(SmartError::ThresholdsTooLarge { .. })));
    Ok(())
}


#[test]
fn measures_carry_the_ups_label_only() -> TestResult {
    let items = ups_measures(&parse(OL)?, "lab");
    assert_eq!(items.len(), MEASURE_COUNT);
    let charge = items.first().ok_or("no measure")?;
    assert_eq!(charge.name, "hw.ups.battery_charge");
    assert_eq!(charge.value, FULL_CHARGE);
    assert_eq!(charge.labels, vec![("ups".to_string(), "lab".to_string())]);
    assert!(items.iter().all(|item| item.labels.len() == 1));
    let unlabelled = ups_measures(&parse(OL)?, "-bad,name");
    assert!(unlabelled.iter().all(|item| item.labels.is_empty()));
    assert!(ups_measures(&parse(STALE)?, "lab").is_empty());
    Ok(())
}
