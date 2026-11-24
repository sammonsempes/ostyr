//! The end of the last successful retro window, kept in a small file so a restart can name the gap it left.

use crate::limits::{MAX_STATE_BYTES, MAX_STATE_SKEW_SECONDS, STATE_RADIX};
use core_config::secret_file::SecretFileError;
use core_pg::error::PgError;
use core_pg::password::read_capped;
use core_pg::scope::tenant_scope;
use std::fs::{rename, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::Path;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::warn;


pub const NO_PREVIOUS_RUN: &str = "no_previous_run";


pub const RESUMED: &str = "resumed";


pub const STATE_UNREADABLE: &str = "state_unreadable";


pub const STATE_AHEAD: &str = "state_ahead";


pub const STATE_OTHER_TENANT: &str = "state_other_tenant";


#[derive(Debug, Error)]
pub enum StateError {
    #[error("the retro state file cannot be read")]
    Read(#[source] PgError),
    #[error("the retro state file cannot be opened")]
    Open(#[source] SecretFileError),
    #[error("the retro state file must hold a tenant, a space and the end")]
    Format,
    #[error("the retro state file must hold only ASCII digits after the tenant")]
    NotDigits,
    #[error("the retro state file belongs to another tenant")]
    OtherTenant,
    #[error("the retro state end is later than now plus the allowed skew")]
    Ahead,
    #[error("the retro state file holds a time outside the supported range")]
    Range,
}


/// The state file opened as a no-follow regular file owned by the process user.
#[cfg(unix)]
pub fn open_state(path: &Path) -> Result<File, SecretFileError> {
    open_state_with(path, core_config::secret_file::handle_metadata)
}


/// The state file opened as a regular file.
#[cfg(not(unix))]
pub fn open_state(path: &Path) -> Result<File, SecretFileError> {
    core_config::secret_file::open_secret(path)
}


/// Opened with `O_NOFOLLOW | O_NONBLOCK`, then judged on the handle: a regular file owned by the process user (or root), no mode rule; `inspect` is injected.
#[cfg(unix)]
pub fn open_state_with(path: &Path, inspect: fn(&File) -> io::Result<std::fs::Metadata>) -> Result<File, SecretFileError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = path.display().to_string();
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| core_config::secret_file::open_failure(file.clone(), source))?;
    let metadata = inspect(&handle).map_err(|source| SecretFileError::Io { file: file.clone(), source })?;
    core_config::secret_file::judge_secret(&file, metadata.is_file(), 0, metadata.uid(), rustix::process::geteuid().as_raw())?;
    Ok(handle)
}


/// The digits of a saved end: ASCII digits only, a time `from_unix_timestamp` accepts.
pub fn parse_seconds(digits: &[u8]) -> Result<OffsetDateTime, StateError> {
    let values: Option<Vec<u32>> = digits.iter().map(|byte| char::from(*byte).to_digit(STATE_RADIX)).collect();
    let found = values.filter(|list| !list.is_empty()).ok_or(StateError::NotDigits)?;
    let seconds = found
        .iter()
        .try_fold(0, |total: i64, digit| {
            total.checked_mul(i64::from(STATE_RADIX))?.checked_add(i64::from(*digit))
        })
        .ok_or(StateError::Range)?;
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| StateError::Range)
}


/// `<tenant> <digits>`: the tenant by the crate's grammar and equal to `tenant`, the end not later than `now` plus `MAX_STATE_SKEW_SECONDS`.
pub fn parse_state(bytes: &[u8], tenant: &str, now: OffsetDateTime) -> Result<OffsetDateTime, StateError> {
    let (saved_tenant, digits) = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .and_then(|space| Some((bytes.get(..space)?, bytes.get(space + 1..)?)))
        .ok_or(StateError::Format)?;
    let saved = std::str::from_utf8(saved_tenant).map_err(|_| StateError::Format)?;
    tenant_scope(saved).map_err(|_| StateError::Format)?;
    if saved != tenant {
        Err(StateError::OtherTenant)
    } else {
        let end = parse_seconds(digits)?;
        if end > now + time::Duration::seconds(MAX_STATE_SKEW_SECONDS) {
            Err(StateError::Ahead)
        } else {
            Ok(end)
        }
    }
}


/// The saved window end of `tenant`: at most `MAX_STATE_BYTES` read from a no-follow regular-file handle; a missing file is `None`.
pub fn read_end(path: &Path, tenant: &str, now: OffsetDateTime) -> Result<Option<OffsetDateTime>, StateError> {
    match open_state(path) {
        Err(SecretFileError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StateError::Open(error)),
        Ok(mut handle) => {
            let bytes = read_capped(&mut handle, MAX_STATE_BYTES, &path.display().to_string()).map_err(StateError::Read)?;
            parse_state(&bytes, tenant, now).map(Some)
        }
    }
}


/// The options of a new temporary: `create_new` (never follows a link, never reuses a file), mode 0600 on Unix.
pub fn temporary_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, crate::limits::STATE_MODE);
    options
}


/// `<tenant> <digits>` in a unique temporary beside `path` (`create_new`, 0600), synced, then renamed over `path`; a time before the epoch is refused.
pub fn write_end(path: &Path, tenant: &str, end: OffsetDateTime) -> io::Result<()> {
    let seconds = u64::try_from(end.unix_timestamp()).map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
    let name = path.file_name().ok_or_else(|| io::Error::from(ErrorKind::InvalidInput))?;
    let suffix = format!("{}.{}", std::process::id(), OffsetDateTime::now_utc().unix_timestamp_nanos());
    let staging = path.with_file_name(format!(".{}.{suffix}.tmp", name.to_string_lossy()));
    let mut file = temporary_options().open(&staging)?;
    write!(file, "{tenant} {seconds}")?;
    file.sync_all()?;
    rename(&staging, path)
}


/// What the first round starts from and its name: `resumed`, `no_previous_run`, `state_ahead`, `state_other_tenant` or `state_unreadable`; the last four run with no previous end.
pub fn start_of(read: Result<Option<OffsetDateTime>, StateError>) -> (Option<OffsetDateTime>, &'static str) {
    match read {
        Ok(Some(end)) => (Some(end), RESUMED),
        Ok(None) => {
            warn!("{NO_PREVIOUS_RUN}");
            (None, NO_PREVIOUS_RUN)
        }
        Err(StateError::Ahead) => {
            warn!("{STATE_AHEAD}");
            (None, STATE_AHEAD)
        }
        Err(StateError::OtherTenant) => {
            warn!("{STATE_OTHER_TENANT}");
            (None, STATE_OTHER_TENANT)
        }
        Err(error) => {
            warn!(%error, "{STATE_UNREADABLE}");
            (None, STATE_UNREADABLE)
        }
    }
}
