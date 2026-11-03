use crate::atomic::write_atomic;
use crate::error::SerialError;
use crate::limits::{SERIAL_DAY_UNIT, SERIAL_MONTH_UNIT, SERIAL_YEAR_UNIT};
use std::fs;
use std::io::ErrorKind;
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


/// A missing file is a first run; an unreadable or non-numeric one is an error, never a reset.
pub fn read_counter(path: &Path) -> Result<Option<u32>, SerialError> {
    match fs::read_to_string(path) {
        Ok(text) => text.trim().parse::<u32>().map(Some).map_err(|source| SerialError::Counter {
            path: path.to_path_buf(),
            source,
        }),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SerialError::Io(error)),
    }
}


/// Persists the next serial before the zone is written, so a crash can skip a serial but never reuse one.
pub fn advance(path: &Path, now: OffsetDateTime) -> Result<u32, SerialError> {
    let serial = next_serial(read_counter(path)?, day_base(now)?)?;
    write_atomic(path, format!("{serial}\n").as_bytes())?;
    Ok(serial)
}
