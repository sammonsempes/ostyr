//! Bounded, strict parse of `upsc <ups>@<host>` output and of the thresholds file.

use crate::error::SmartError;
use crate::limits::MAX_THRESHOLDS_BYTES;
use crate::model::{UpsFlag, UpsReport, UpsThresholds};
use std::collections::BTreeSet;
use std::io::Read;


pub const MAX_KEY_CHARS: usize = 64;


pub const PERCENT_MAX: f64 = 100.0;


pub const ZERO: f64 = 0.0;


pub const MIN_CHARGE_THRESHOLD: u8 = 1;


pub const MAX_CHARGE_THRESHOLD: u8 = 100;


pub fn parse_upsc<Input: Read>(mut reader: Input, max_bytes: u64, max_lines: usize) -> Result<UpsReport, SmartError> {
    let mut bytes = Vec::new();
    reader.by_ref().take(max_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        Err(SmartError::Oversized { limit: max_bytes })
    } else {
        collect(std::str::from_utf8(&bytes)?, max_lines)
    }
}


fn collect(text: &str, max_lines: usize) -> Result<UpsReport, SmartError> {
    if text.lines().count() > max_lines {
        Err(SmartError::TooManyLines { limit: max_lines })
    } else {
        let mut report = empty_report();
        let mut seen = BTreeSet::new();
        text.lines().try_for_each(|line| apply(line, &mut report, &mut seen))?;
        Ok(report)
    }
}


fn empty_report() -> UpsReport {
    UpsReport {
        status: None,
        battery_charge: None,
        battery_runtime: None,
        input_voltage: None,
        output_voltage: None,
        load: None,
        temperature: None,
        rejected_fields: 0,
        unreadable: Vec::new(),
    }
}


fn split_line(line: &str) -> Option<(&str, &str)> {
    line.split_once(": ").or_else(|| line.strip_suffix(':').map(|key| (key, "")))
}


pub fn is_key(key: &str) -> bool {
    let chars_ok = key
        .chars()
        .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '.' || character == '_');
    chars_ok && !key.is_empty() && key.len() <= MAX_KEY_CHARS
}


fn apply<'a>(line: &'a str, report: &mut UpsReport, seen: &mut BTreeSet<&'a str>) -> Result<(), SmartError> {
    match split_line(line) {
        Some((key, value)) if is_key(key) => {
            if seen.insert(key) {
                store(report, key, value);
                Ok(())
            } else {
                Err(SmartError::DuplicateKey)
            }
        }
        _ => {
            reject(report, "line");
            Ok(())
        }
    }
}


fn store(report: &mut UpsReport, key: &str, value: &str) {
    match key {
        "ups.status" => report.status = Some(status_flags(report, value)),
        "battery.charge" => report.battery_charge = number(report, "battery.charge", value, ZERO, PERCENT_MAX),
        "battery.runtime" => report.battery_runtime = number(report, "battery.runtime", value, ZERO, f64::INFINITY),
        "input.voltage" => report.input_voltage = number(report, "input.voltage", value, ZERO, f64::INFINITY),
        "output.voltage" => report.output_voltage = number(report, "output.voltage", value, ZERO, f64::INFINITY),
        "ups.load" => report.load = number(report, "ups.load", value, ZERO, f64::INFINITY),
        "ups.temperature" => report.temperature = number(report, "ups.temperature", value, f64::NEG_INFINITY, f64::INFINITY),
        _ => {}
    }
}


fn reject(report: &mut UpsReport, name: &str) {
    report.rejected_fields += 1;
    report.unreadable.push(name.to_string());
}


fn number(report: &mut UpsReport, name: &str, value: &str, low: f64, high: f64) -> Option<f64> {
    match value.parse::<f64>() {
        Ok(parsed) if parsed.is_finite() && parsed >= low && parsed <= high => Some(parsed),
        _ => {
            reject(report, name);
            None
        }
    }
}


pub fn flag_of(token: &str) -> Option<UpsFlag> {
    match token {
        "OL" => Some(UpsFlag::Online),
        "OB" => Some(UpsFlag::OnBattery),
        "LB" => Some(UpsFlag::LowBattery),
        "RB" => Some(UpsFlag::ReplaceBattery),
        "CHRG" => Some(UpsFlag::Charging),
        "DISCHRG" => Some(UpsFlag::Discharging),
        "BYPASS" => Some(UpsFlag::Bypass),
        "OVER" => Some(UpsFlag::Overload),
        "TRIM" => Some(UpsFlag::Trim),
        "BOOST" => Some(UpsFlag::Boost),
        "FSD" => Some(UpsFlag::ForcedShutdown),
        "ALARM" => Some(UpsFlag::Alarm),
        "OFF" => Some(UpsFlag::Off),
        _ => None,
    }
}


fn status_flags(report: &mut UpsReport, value: &str) -> BTreeSet<UpsFlag> {
    let parsed: Vec<Option<UpsFlag>> = value.split_whitespace().map(flag_of).collect();
    let unknown = parsed.iter().filter(|flag| flag.is_none()).count();
    report.rejected_fields += unknown;
    if unknown > 0 {
        report.unreadable.push("ups.status".to_string());
    }
    parsed.into_iter().flatten().collect()
}


pub fn parse_thresholds(text: &str) -> Result<UpsThresholds, SmartError> {
    if text.len() > MAX_THRESHOLDS_BYTES {
        Err(SmartError::ThresholdsTooLarge { limit: MAX_THRESHOLDS_BYTES })
    } else {
        let thresholds: UpsThresholds = serde_saphyr::from_str(text).map_err(|error| SmartError::Thresholds(Box::new(error)))?;
        if (MIN_CHARGE_THRESHOLD..=MAX_CHARGE_THRESHOLD).contains(&thresholds.min_battery_charge) {
            Ok(thresholds)
        } else {
            Err(SmartError::ChargeThresholdRange)
        }
    }
}
