use crate::atomic::write_atomic;
use crate::error::SerialError;
use crate::limits::{MAX_COUNTER_BYTES, SERIAL_DAY_UNIT, SERIAL_MONTH_UNIT, SERIAL_YEAR_UNIT};
use core_config::error::ConfigError;
use core_config::parse::open_regular;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;
use time::OffsetDateTime;


/// `YYYYMMDD00` of the clock's UTC date.
pub fn day_base(now: OffsetDateTime) -> Result<u32, SerialError> {
    u32::try_from(now.year())
        .ok()
        .and_then(|year| year.checked_mul(SERIAL_YEAR_UNIT))
        .map(|years| years + u32::from(u8::from(now.month())) * SERIAL_MONTH_UNIT + u32::from(now.day()))
        .and_then(|date| date.checked_mul(SERIAL_DAY_UNIT))
        .ok_or(SerialError::Clock(now))
}


/// The first serial of today, or the previous one plus one when it is not older; never goes back, even if the clock does.
pub fn next_serial(previous: Option<u32>, today: u32) -> Result<u32, SerialError> {
    let candidate = match previous {
        Some(last) if last >= today => last.saturating_add(1),
        _ => today + 1,
    };
    if candidate % SERIAL_DAY_UNIT == 0 {
        Err(SerialError::Exhausted(candidate.saturating_sub(1)))
    } else {
        Ok(candidate)
    }
}


/// A missing file is a first run; a non-regular, oversized, unreadable or non-numeric one is an error, never a reset or a hang.
pub fn read_counter(path: &Path) -> Result<Option<u32>, SerialError> {
    match open_regular(path, &path.display().to_string()) {
        Ok(handle) => parse_counter(handle, path).map(Some),
        Err(ConfigError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(ConfigError::WatchedFile { reason, .. }) => Err(SerialError::Refused {
            path: path.to_path_buf(),
            reason,
        }),
        Err(error) => Err(SerialError::Open(error)),
    }
}


/// At most `MAX_COUNTER_BYTES` are read; one more is `TooLarge`.
pub fn parse_counter(handle: File, path: &Path) -> Result<u32, SerialError> {
    let mut text = String::new();
    handle.take(MAX_COUNTER_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_COUNTER_BYTES {
        Err(SerialError::TooLarge(path.to_path_buf()))
    } else {
        text.trim().parse::<u32>().map_err(|source| SerialError::Counter {
            path: path.to_path_buf(),
            source,
        })
    }
}


/// Persists the next serial before the zone is written, so a crash can skip a serial but never reuse one.
pub fn advance(path: &Path, now: OffsetDateTime) -> Result<u32, SerialError> {
    let serial = next_serial(read_counter(path)?, day_base(now)?)?;
    write_atomic(path, format!("{serial}\n").as_bytes())?;
    Ok(serial)
}
