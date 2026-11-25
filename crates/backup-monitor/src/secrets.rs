//! Secret files named by plain file names and opened under one checked directory handle (Unix only).

use crate::borg::{private_handle, BorgError};
use core_config::secret_file::{judge_secret, open_failure, SecretFileError};
use core_config::watch::is_plain_file_name;
use rustix::fs::{openat, Mode, OFlags};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::debug;


pub const MAX_SECRET_NAME_BYTES: usize = 255;


/// The secrets directory: its checked handle and its absolute path (the path is only handed to restic, which re-opens the file by it).
#[derive(Debug)]
pub struct SecretsDir {
    pub handle: OwnedFd,
    pub path: PathBuf,
}


/// A plain file name (`[A-Za-z0-9._-]`, no trailing dot) of at most `MAX_SECRET_NAME_BYTES`: never a separator, never `..`.
pub fn valid_secret_name(name: &str) -> bool {
    name.len() <= MAX_SECRET_NAME_BYTES && is_plain_file_name(name)
}


/// `secrets_dir` must pass `open_trusted_dir`, be exactly 0700 and valid UTF-8; the refusal names no path.
pub fn open_secrets_dir(path: &Path, euid: u32) -> Result<SecretsDir, BorgError> {
    path.to_str().ok_or(BorgError::BaseDir)?;
    Ok(SecretsDir {
        handle: private_handle(path, euid)?,
        path: path.to_path_buf(),
    })
}


/// `<secrets_dir>/<name>`: the name is checked first, so no separator or `..` can leave the directory.
pub fn secret_path(secrets: &SecretsDir, name: &str) -> Option<String> {
    valid_secret_name(name)
        .then(|| secrets.path.join(name))
        .and_then(|joined| joined.to_str().map(str::to_owned))
}


pub fn handle_metadata(handle: &File) -> io::Result<Metadata> {
    handle.metadata()
}


/// Opened with `openat` on the checked handle (`O_NOFOLLOW|O_NONBLOCK`), then judged on the handle like `open_secret`; `inspect` is injected for tests.
pub fn open_secret_in_with(secrets: &SecretsDir, name: &str, euid: u32, inspect: fn(&File) -> io::Result<Metadata>) -> Result<File, SecretFileError> {
    if !valid_secret_name(name) {
        Err(SecretFileError::NotRegular { file: String::new() })?;
    }
    let handle = openat(
        &secrets.handle,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|errno| open_failure(String::new(), io::Error::from(errno)))?;
    let metadata = inspect(&handle).map_err(|source| SecretFileError::Io { file: String::new(), source })?;
    judge_secret("", metadata.is_file(), metadata.mode(), metadata.uid(), euid)?;
    if metadata.nlink() > 1 {
        Err(SecretFileError::NotRegular { file: String::new() })?;
    }
    Ok(handle)
}


/// `open_secret_in_with` with the real inspection.
pub fn open_secret_in(secrets: &SecretsDir, name: &str, euid: u32) -> Result<File, SecretFileError> {
    open_secret_in_with(secrets, name, euid, handle_metadata)
}


/// The fixed category of a refusal, logged without the file name.
pub fn secret_refusal(error: &SecretFileError) -> &'static str {
    let category = match error {
        SecretFileError::Io { .. } => "unreadable",
        SecretFileError::NotRegular { .. } => "not a regular file",
        SecretFileError::Symlink { .. } => "symlink",
        SecretFileError::Mode { .. } => "mode",
        SecretFileError::Owner { .. } => "owner",
    };
    debug!(category, "secret file refused");
    category
}
