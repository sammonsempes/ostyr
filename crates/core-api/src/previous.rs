use crate::state::previous_key_path;
use core_audit::log::{append_declared, check_private, owner_only, AuditLog};
use core_audit::model::{NewEntry, Outcome};
use core_auth::cli::{KEY_READ_LIMIT, KEY_READ_LIMIT_BYTES};
use core_auth::error::AuthError;
use core_auth::random::random_array;
use core_auth::secretbox::KEY_BYTES;
use core_auth::store::{parent_directory, sync_directory, TEMP_SUFFIX_BYTES};
use core_auth::types::{RandomFn, StoreKey};
use core_config::reload::{reload_entry, ReloadContext, RELOAD_DECLARED_KEYS};
use data_encoding::HEXLOWER;
use secrecy::{ExposeSecret, SecretSlice};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};


pub const PREVIOUS_KEY_SAVED: &str = "previous_key_saved";


pub const PREVIOUS_KEY_REMOVED: &str = "previous_key_removed";


pub const PREVIOUS_KEY_REMOVAL_FAILED: &str = "previous_key_removal_failed";


pub const ROTATION_RESUMED: &str = "rotation_resumed";


#[cfg(unix)]
pub fn owned_by_process(metadata: &Metadata) -> bool {
    metadata.uid() == rustix::process::geteuid().as_raw()
}


#[cfg(not(unix))]
pub fn owned_by_process(_metadata: &Metadata) -> bool {
    true
}


/// Opens for reading without following a final symlink and without blocking on a FIFO.
#[cfg(unix)]
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits();
    OpenOptions::new().read(true).custom_flags(flags as i32).open(path)
}


#[cfg(not(unix))]
pub fn open_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}


/// A previous-key file must be a regular file owned by the process user, judged on the metadata given.
pub fn check_previous_metadata(metadata: &Metadata) -> io::Result<()> {
    if metadata.is_file() && owned_by_process(metadata) {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "the previous key file must be a regular file owned by the service user",
        ))
    }
}


/// Reads the previous key through one handle (no symlink, regular, owned, private, bounded); a missing file is `None`.
pub fn read_previous_key(path: &Path) -> Result<Option<StoreKey>, AuthError> {
    match open_no_follow(path) {
        Ok(file) => {
            check_previous_metadata(&file.metadata()?)?;
            check_private(&file).map_err(AuthError::KeyFile)?;
            let mut bytes = Vec::with_capacity(KEY_READ_LIMIT_BYTES);
            file.take(KEY_READ_LIMIT).read_to_end(&mut bytes)?;
            (bytes.len() == KEY_BYTES)
                .then(|| Some(SecretSlice::from(bytes)))
                .ok_or(AuthError::InvalidKey)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(AuthError::Io(error)),
    }
}


/// Refuses a slot that exists and is not a regular file owned by the process user; a symlink is judged as itself.
pub fn check_previous_slot(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => check_previous_metadata(&metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}


/// Creates `temporary` (create_new, mode 0600), writes and syncs the key, then renames it over `target`.
pub fn write_then_rename(temporary: &Path, target: &Path, key: &StoreKey) -> io::Result<()> {
    let mut file = owner_only(OpenOptions::new().write(true).create_new(true)).open(temporary)?;
    file.write_all(key.expose_secret())?;
    file.sync_all()?;
    fs::rename(temporary, target)
}


/// Keeps `key` at `<key_file>.previous`: write-then-rename, parent synced; the temporary file is removed on failure.
pub fn write_previous_key(key_file: &Path, key: &StoreKey, random: RandomFn) -> Result<(), AuthError> {
    let target = previous_key_path(key_file);
    check_previous_slot(&target)?;
    let suffix = HEXLOWER.encode(&random_array::<TEMP_SUFFIX_BYTES>(random)?);
    let mut temporary_name = target.as_os_str().to_owned();
    temporary_name.push(format!(".{suffix}.tmp"));
    let temporary = PathBuf::from(temporary_name);
    write_then_rename(&temporary, &target, key).inspect_err(|_| {
        fs::remove_file(&temporary).unwrap_or_else(|error| tracing::error!(%error, "cannot remove the temporary previous key"));
    })?;
    sync_directory(parent_directory(&target))?;
    Ok(())
}


/// Removes the file and syncs its directory.
pub fn remove_synced(path: &Path) -> io::Result<()> {
    fs::remove_file(path)?;
    sync_directory(parent_directory(path))
}


/// Appends one entry; a failing audit is only logged, the operation it records already happened.
pub fn record_entry<Output: Write>(audit: &AuditLog<Output>, entry: NewEntry) {
    append_declared(audit, entry, &RELOAD_DECLARED_KEYS)
        .map(|_| ())
        .unwrap_or_else(|error| tracing::error!(%error, "cannot record the key rotation"));
}


/// Records an action on the previous-key file; the path is not secret, the key never appears.
pub fn record_previous<Output: Write>(audit: &AuditLog<Output>, context: &ReloadContext, outcome: Outcome, result: &str, detail: String) {
    record_entry(audit, reload_entry(context, outcome, [("result", result.to_owned()), ("diff", detail)]));
}


/// Deletes `<key_file>.previous` once the store is sealed under the new key, with `remove` injected; the outcome is audited either way.
pub fn retire_previous_with<Output: Write>(audit: &AuditLog<Output>, context: &ReloadContext, key_file: &Path, remove: fn(&Path) -> io::Result<()>) {
    let target = previous_key_path(key_file);
    remove(&target).map_or_else(
        |error| {
            tracing::error!(%error, file = %target.display(), "cannot remove the previous key");
            record_previous(
                audit,
                context,
                Outcome::Failure,
                PREVIOUS_KEY_REMOVAL_FAILED,
                format!("{}: {error}", target.display()),
            );
        },
        |()| {
            let detail = format!("{} removed, the store is sealed under the new key", target.display());
            record_previous(audit, context, Outcome::Success, PREVIOUS_KEY_REMOVED, detail);
        },
    );
}


pub fn retire_previous<Output: Write>(audit: &AuditLog<Output>, context: &ReloadContext, key_file: &Path) {
    retire_previous_with(audit, context, key_file, remove_synced);
}


/// At startup, with the key file opening every secret: a `.previous` left by an interrupted rotation is checked through one handle, then removed and audited.
pub fn remove_stale_previous<Output: Write>(audit: &AuditLog<Output>, context: &ReloadContext, key_file: &Path) {
    let target = previous_key_path(key_file);
    match open_no_follow(&target)
        .and_then(|file| file.metadata())
        .and_then(|metadata| check_previous_metadata(&metadata))
    {
        Ok(()) => retire_previous(audit, context, key_file),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => tracing::error!(%error, file = %target.display(), "a stale previous key is left in place"),
    }
}
