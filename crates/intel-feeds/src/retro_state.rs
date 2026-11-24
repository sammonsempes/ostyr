//! The end of the last successful retro window, kept in a small file so a restart can name the gap it left.

use crate::limits::{MAX_STATE_BYTES, STATE_RADIX};
use core_pg::error::PgError;
use core_pg::password::read_limited;
use std::fs::{rename, File};
use std::io::{self, ErrorKind, Write};
use std::path::Path;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::warn;


pub const NO_PREVIOUS_RUN: &str = "no_previous_run";


pub const RESUMED: &str = "resumed";


pub const STATE_UNREADABLE: &str = "state_unreadable";


#[derive(Debug, Error)]
pub enum StateError {
    #[error("the retro state file cannot be read")]
    Read(#[source] PgError),
    #[error("the retro state file must hold only ASCII digits")]
    NotDigits,
    #[error("the retro state file holds a time outside the supported range")]
    Range,
}


/// The saved window end in epoch seconds: ASCII digits only, at most `MAX_STATE_BYTES`, read through the capped regular-file open; a missing file is `None`.
pub fn read_end(path: &Path) -> Result<Option<OffsetDateTime>, StateError> {
    match read_limited(path, MAX_STATE_BYTES) {
        Err(PgError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StateError::Read(error)),
        Ok(bytes) => {
            let digits: Option<Vec<u32>> = bytes.iter().map(|byte| char::from(*byte).to_digit(STATE_RADIX)).collect();
            let found = digits.filter(|list| !list.is_empty()).ok_or(StateError::NotDigits)?;
            let seconds = found
                .iter()
                .try_fold(0, |total: i64, digit| {
                    total.checked_mul(i64::from(STATE_RADIX))?.checked_add(i64::from(*digit))
                })
                .ok_or(StateError::Range)?;
            OffsetDateTime::from_unix_timestamp(seconds).map(Some).map_err(|_| StateError::Range)
        }
    }
}


/// The end as epoch digits in a temporary file next to `path`, synced, then renamed over it; a time before the epoch is refused.
pub fn write_end(path: &Path, end: OffsetDateTime) -> io::Result<()> {
    let seconds = u64::try_from(end.unix_timestamp()).map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
    let staging = path.with_extension("tmp");
    let mut file = File::create(&staging)?;
    write!(file, "{seconds}")?;
    file.sync_all()?;
    rename(&staging, path)
}


/// What the first round starts from and its name: `resumed`, `no_previous_run` (nothing saved yet) or `state_unreadable` (named, the round runs with no previous end).
pub fn start_of(read: Result<Option<OffsetDateTime>, StateError>) -> (Option<OffsetDateTime>, &'static str) {
    match read {
        Ok(Some(end)) => (Some(end), RESUMED),
        Ok(None) => {
            warn!("{NO_PREVIOUS_RUN}");
            (None, NO_PREVIOUS_RUN)
        }
        Err(error) => {
            warn!(%error, "{STATE_UNREADABLE}");
            (None, STATE_UNREADABLE)
        }
    }
}
