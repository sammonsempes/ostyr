//! Bounded, strict parse of `chronyc -c tracking` and `timedatectl show`.

use crate::error::NtpError;
use crate::grammar::is_clean_ident;
use crate::model::{LeapStatus, TimeSync, Tracking};
use std::io::Read;


const HEX_ID_CHARS: usize = 8;


pub fn read_bounded(reader: &mut dyn Read, max_bytes: u64) -> Result<String, NtpError> {
    let mut bytes = Vec::new();
    reader.take(max_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        Err(NtpError::Oversized { limit: max_bytes })
    } else {
        Ok(String::from_utf8(bytes).map_err(|error| error.utf8_error())?)
    }
}


fn number(text: &str) -> Result<Option<f64>, NtpError> {
    if text.is_empty() {
        Ok(None)
    } else {
        text.parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
            .map(Some)
            .ok_or(NtpError::Malformed { reason: "bad number" })
    }
}


fn stratum(text: &str) -> Result<Option<u32>, NtpError> {
    if text.is_empty() {
        Ok(None)
    } else {
        text.parse::<u32>().map(Some).map_err(|_| NtpError::Malformed { reason: "bad stratum" })
    }
}


fn leap_status(text: &str) -> Result<LeapStatus, NtpError> {
    match text {
        "Normal" => Ok(LeapStatus::Normal),
        "Insert second" => Ok(LeapStatus::InsertSecond),
        "Delete second" => Ok(LeapStatus::DeleteSecond),
        "Not synchronised" => Ok(LeapStatus::NotSynchronised),
        _ => Err(NtpError::Malformed { reason: "bad leap status" }),
    }
}


fn reference_id(text: &str) -> Result<String, NtpError> {
    if text.len() == HEX_ID_CHARS && text.chars().all(|character| character.is_ascii_hexdigit()) {
        Ok(text.to_string())
    } else {
        Err(NtpError::Malformed { reason: "bad reference id" })
    }
}


pub fn parse_chrony_tracking<Input: Read>(mut reader: Input, max_bytes: u64) -> Result<Tracking, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let line = text.trim_end_matches(['\r', '\n']);
    let fields: Vec<&str> = line.split(',').collect();
    match fields.as_slice() {
        [id, name, stratum_text, ref_time, offset, last, rms, frequency, residual, skew, delay, dispersion, interval, leap] => {
            number(ref_time)?;
            let name_given = Some(*name).filter(|given| !given.is_empty());
            let clean_name = name_given.filter(|given| is_clean_ident(given)).map(str::to_string);
            let rejected = usize::from(name_given.is_some() && clean_name.is_none());
            Ok(Tracking {
                reference_id: reference_id(id)?,
                reference_name: clean_name,
                stratum: stratum(stratum_text)?,
                system_time_offset: number(offset)?,
                last_offset: number(last)?,
                rms_offset: number(rms)?,
                frequency: number(frequency)?,
                residual_frequency: number(residual)?,
                skew: number(skew)?,
                root_delay: number(delay)?,
                root_dispersion: number(dispersion)?,
                update_interval: number(interval)?,
                leap_status: leap_status(leap)?,
                rejected_fields: rejected,
            })
        }
        _ => Err(NtpError::Malformed { reason: "wrong field count" }),
    }
}


fn yes_no(text: &str) -> Result<bool, NtpError> {
    match text {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(NtpError::Malformed { reason: "bad yes/no value" }),
    }
}


fn once<Value>(slot: &mut Option<Value>, value: Value) -> Result<(), NtpError> {
    if slot.is_some() {
        Err(NtpError::Malformed { reason: "duplicate key" })
    } else {
        *slot = Some(value);
        Ok(())
    }
}


pub fn parse_timedatectl<Input: Read>(mut reader: Input, max_bytes: u64) -> Result<TimeSync, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let mut enabled = None;
    let mut synchronized = None;
    let mut zone = None;
    text.lines()
        .filter_map(|line| line.split_once('='))
        .try_for_each(|(key, value)| match key {
            "NTP" => yes_no(value).and_then(|flag| once(&mut enabled, flag)),
            "NTPSynchronized" => yes_no(value).and_then(|flag| once(&mut synchronized, flag)),
            "Timezone" => once(&mut zone, value),
            _ => Ok(()),
        })?;
    let timezone = zone.filter(|name| is_clean_ident(name)).map(str::to_string);
    Ok(TimeSync {
        ntp_enabled: enabled,
        synchronized,
        rejected_fields: usize::from(zone.is_some() && timezone.is_none()),
        timezone,
    })
}
