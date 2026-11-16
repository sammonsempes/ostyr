use thiserror::Error;
use time::error::ComponentRange;
use time::OffsetDateTime;


/// 100 ns intervals in one second.
pub const TICKS_PER_SECOND: u64 = 10_000_000;


/// Seconds from 1601-01-01 (the FILETIME epoch) to 1970-01-01.
pub const UNIX_EPOCH_SECONDS: i64 = 11_644_473_600;


/// "Never" in Active Directory: the largest signed 64-bit value.
pub const FILETIME_NEVER: u64 = 0x7FFF_FFFF_FFFF_FFFF;


#[derive(Debug, Error)]
pub enum FiletimeError {
    #[error("FILETIME is outside the years 0 to 9999")]
    OutOfRange(#[source] ComponentRange),
}


/// Unix seconds of a FILETIME: 0 and "never" are `None`, a value outside the years 0 to 9999 is refused.
pub fn filetime_to_unix(ticks: u64) -> Result<Option<i64>, FiletimeError> {
    if ticks == 0 || ticks == FILETIME_NEVER {
        Ok(None)
    } else {
        let unix = (ticks / TICKS_PER_SECOND) as i64 - UNIX_EPOCH_SECONDS;
        OffsetDateTime::from_unix_timestamp(unix).map_err(FiletimeError::OutOfRange)?;
        Ok(Some(unix))
    }
}
