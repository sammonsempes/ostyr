//! Timer expectations file, strict parse of `systemctl show --timestamp=unix` for a timer and its service, and the health of a timer.

use crate::error::NtpError;
use crate::grammar::{is_unit_name, is_unit_name_with};
use crate::limits::{MAX_CLOCK_SKEW_SECONDS, MAX_EXPECTATIONS_BYTES, MAX_MAX_AGE_SECONDS, MAX_UNITS, MIN_MAX_AGE_SECONDS};
use crate::model::{ActiveState, LoadState, ServiceResult, ServiceRun, TimerExpectation, TimerExpectationsFile, TimerHealth, TimerState};
use crate::parse::read_bounded;
use crate::units::{active_state, collect_pairs, count, load_state};
use core_config::parse::parse_document;
use std::collections::BTreeMap;
use std::io::Read;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::PrimitiveDateTime;


pub const UTC_FORMAT: &[FormatItem<'static>] = format_description!("[weekday repr:short] [year]-[month]-[day] [hour]:[minute]:[second] UTC");


pub const TIMER_KEYS: [&str; 6] = ["Id", "LoadState", "ActiveState", "Unit", "LastTriggerUSec", "NextElapseUSecRealtime"];


pub const SERVICE_KEYS: [&str; 4] = ["Id", "Result", "ExecMainStatus", "ExecMainExitTimestamp"];


pub const TIMER_SUFFIX: &str = ".timer";


pub const SERVICE_SUFFIX: &str = ".service";


/// The service a timer runs: the `service` field, else the timer's stem with `.service`.
pub fn service_unit(expectation: &TimerExpectation) -> String {
    expectation.service.clone().unwrap_or_else(|| {
        let stem = expectation.timer.strip_suffix(TIMER_SUFFIX).unwrap_or(&expectation.timer);
        format!("{stem}{SERVICE_SUFFIX}")
    })
}


pub fn load_timer_expectations(text: &str, file: &str) -> Result<Vec<TimerExpectation>, NtpError> {
    if text.len() > MAX_EXPECTATIONS_BYTES {
        Err(NtpError::Oversized {
            limit: MAX_EXPECTATIONS_BYTES as u64,
        })
    } else {
        let document: TimerExpectationsFile = parse_document(text, file)?;
        if document.timers.len() > MAX_UNITS {
            Err(NtpError::OutOfRange { field: "timers" })
        } else {
            document.timers.iter().try_for_each(check_timer)?;
            Ok(document.timers)
        }
    }
}


fn check_timer(expectation: &TimerExpectation) -> Result<(), NtpError> {
    let service_ok = expectation
        .service
        .as_deref()
        .is_none_or(|service| is_unit_name_with(service, SERVICE_SUFFIX));
    if !is_unit_name_with(&expectation.timer, TIMER_SUFFIX) {
        Err(NtpError::OutOfRange { field: "timer" })
    } else if !service_ok {
        Err(NtpError::OutOfRange { field: "service" })
    } else if !(MIN_MAX_AGE_SECONDS..=MAX_MAX_AGE_SECONDS).contains(&expectation.max_age_seconds) {
        Err(NtpError::OutOfRange { field: "max_age_seconds" })
    } else {
        Ok(())
    }
}


fn service_result(text: &str) -> Option<ServiceResult> {
    match text {
        "success" => Some(ServiceResult::Success),
        "protocol" => Some(ServiceResult::Protocol),
        "timeout" => Some(ServiceResult::Timeout),
        "exit-code" => Some(ServiceResult::ExitCode),
        "signal" => Some(ServiceResult::Signal),
        "core-dump" => Some(ServiceResult::CoreDump),
        "watchdog" => Some(ServiceResult::Watchdog),
        "start-limit-hit" => Some(ServiceResult::StartLimitHit),
        "resources" => Some(ServiceResult::Resources),
        "oom-kill" => Some(ServiceResult::OomKill),
        "exec-condition" => Some(ServiceResult::ExecCondition),
        _ => None,
    }
}


fn unix_digits(text: &str) -> Option<u64> {
    text.strip_prefix('@')
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse::<u64>().ok())
}


fn utc_text(text: &str) -> Option<u64> {
    PrimitiveDateTime::parse(text, UTC_FORMAT)
        .ok()
        .and_then(|moment| u64::try_from(moment.assume_utc().unix_timestamp()).ok())
}


/// Empty (never set), `@` and digits, or `Www YYYY-MM-DD HH:MM:SS UTC` (the `*USec` form of systemd 255, see the crate notes); else `Malformed`.
fn timestamp(text: &str) -> Result<Option<u64>, NtpError> {
    if text.is_empty() {
        Ok(None)
    } else {
        unix_digits(text)
            .or_else(|| utc_text(text))
            .map(Some)
            .ok_or(NtpError::Malformed { reason: "bad timestamp" })
    }
}


fn checked_pairs<'a>(text: &'a str, keys: &[&str], expected_unit: &str) -> Result<BTreeMap<&'a str, &'a str>, NtpError> {
    let pairs = collect_pairs(text, keys)?;
    if pairs.get("Id") != Some(&expected_unit) {
        Err(NtpError::Malformed { reason: "unexpected unit" })
    } else {
        Ok(pairs)
    }
}


fn value<'a>(pairs: &BTreeMap<&str, &'a str>, key: &str) -> Result<&'a str, NtpError> {
    pairs.get(key).copied().ok_or(NtpError::Malformed { reason: "missing key" })
}


/// Exactly the five requested keys, each once, `Id` equal to `expected_unit`; a value outside its known set is `None` and counted.
pub fn parse_timer_show<Input: Read>(mut reader: Input, max_bytes: u64, expected_unit: &str) -> Result<TimerState, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let pairs = checked_pairs(&text, &TIMER_KEYS, expected_unit)?;
    let load = load_state(value(&pairs, "LoadState")?);
    let active = active_state(value(&pairs, "ActiveState")?);
    let unit = Some(value(&pairs, "Unit")?).filter(|name| is_unit_name(name)).map(str::to_string);
    let unit_unknown = unit.is_none();
    Ok(TimerState {
        load,
        unit,
        active,
        last_trigger_unix: timestamp(value(&pairs, "LastTriggerUSec")?)?,
        next_elapse_unix: timestamp(value(&pairs, "NextElapseUSecRealtime")?)?,
        unknown_values: usize::from(load.is_none()) + usize::from(active.is_none()) + usize::from(unit_unknown),
    })
}


/// Exactly the four requested keys, each once, `Id` equal to `expected_unit`; an unknown `Result` is `None` and counted.
pub fn parse_service_result<Input: Read>(mut reader: Input, max_bytes: u64, expected_unit: &str) -> Result<ServiceRun, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let pairs = checked_pairs(&text, &SERVICE_KEYS, expected_unit)?;
    let result = service_result(value(&pairs, "Result")?);
    Ok(ServiceRun {
        result,
        exec_main_status: count(value(&pairs, "ExecMainStatus")?)?,
        last_exit_unix: timestamp(value(&pairs, "ExecMainExitTimestamp")?)?,
        unknown_values: usize::from(result.is_none()),
    })
}


fn freshness(max_age_seconds: u64, last_trigger: Option<u64>, now_unix: u64) -> Option<TimerHealth> {
    last_trigger.map_or(Some(TimerHealth::Overdue), |last| {
        if last > now_unix.saturating_add(MAX_CLOCK_SKEW_SECONDS) {
            Some(TimerHealth::BlindSpot)
        } else if now_unix.saturating_sub(last) > max_age_seconds {
            Some(TimerHealth::Overdue)
        } else {
            None
        }
    })
}


/// Precedence: NotFound > NotLoaded > WrongService (the timer's `Unit` is not the expected service) > LastRunFailed > Overdue or BlindSpot (never triggered, too old, or a trigger beyond the clock skew) > Inactive > Healthy.
pub fn assess_timer(expectation: &TimerExpectation, timer: &TimerState, service: &ServiceRun, now_unix: u64) -> TimerHealth {
    let succeeded = service.result == Some(ServiceResult::Success) && service.exec_main_status == 0;
    if timer.load == Some(LoadState::NotFound) {
        TimerHealth::NotFound
    } else if timer.load != Some(LoadState::Loaded) {
        TimerHealth::NotLoaded
    } else if timer.unit.as_deref() != Some(service_unit(expectation).as_str()) {
        TimerHealth::WrongService
    } else if !succeeded {
        TimerHealth::LastRunFailed
    } else if let Some(problem) = freshness(expectation.max_age_seconds, timer.last_trigger_unix, now_unix) {
        problem
    } else if timer.active != Some(ActiveState::Active) {
        TimerHealth::Inactive
    } else {
        TimerHealth::Healthy
    }
}
