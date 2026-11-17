use crate::error::TransportError;
use crate::limits::MAX_SECRET_BYTES;
use crate::settings::TransportSettings;
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use core_config::secret_file::judge_secret;
#[cfg(not(unix))]
use core_config::secret_file::ROOT_UID;
#[cfg(unix)]
use core_config::secret_file::{open_failure, SecretFileError};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Component, Path};
use zeroize::Zeroizing;


/// The secret file is one plain name inside the tenant's secrets directory; a `..`, an absolute path or a name holding `/` is refused.
pub fn read_secret(settings: &TransportSettings, tenant: &str, relative: &str) -> Result<Zeroizing<String>, TransportError> {
    let directory = settings.secret_dirs.get(tenant).ok_or(TransportError::NoSecretsDir)?;
    let mut parts = Path::new(relative).components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(name)), None) => {
            let handle = Dir::open_ambient_dir(directory, ambient_authority())
                .and_then(|dir| open_last_component(&dir, name))
                .map_err(|source| open_refusal(source, relative))?;
            check_handle(&handle, relative)?;
            let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES as usize + 1));
            handle
                .take(MAX_SECRET_BYTES + 1)
                .read_to_end(&mut buffer)
                .map_err(TransportError::SecretFile)?;
            secret_text(&buffer)
        }
        _ => Err(TransportError::SecretFile(std::io::Error::other(
            "path is not one name in the secrets directory",
        ))),
    }
}


/// `openat` on the directory handle with `O_NOFOLLOW | O_NONBLOCK`: a final symlink is never followed and a FIFO never blocks, on any kernel.
#[cfg(unix)]
pub fn open_last_component(dir: &Dir, name: &OsStr) -> std::io::Result<File> {
    use rustix::fs::{openat, Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    Ok(File::from(openat(dir, name, flags, Mode::empty())?))
}


/// Without symlink semantics to defend on this platform the capability open is enough.
#[cfg(not(unix))]
pub fn open_last_component(dir: &Dir, name: &OsStr) -> std::io::Result<File> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    Ok(dir.open_with(name, &options)?.into_std())
}


/// A final symlink (`ELOOP` under `O_NOFOLLOW`) is a named refusal, any other open failure keeps its cause.
#[cfg(unix)]
pub fn open_refusal(source: std::io::Error, file: &str) -> TransportError {
    match open_failure(file.to_owned(), source) {
        SecretFileError::Io { source: cause, .. } => TransportError::SecretFile(cause),
        other => TransportError::SecretRefused(other),
    }
}


#[cfg(not(unix))]
pub fn open_refusal(source: std::io::Error, _file: &str) -> TransportError {
    TransportError::SecretFile(source)
}


/// The shared secret-file checks of core-config on the opened handle: regular file, owner, no group or other bit.
pub fn check_handle(handle: &File, file: &str) -> Result<(), TransportError> {
    let metadata = handle.metadata().map_err(TransportError::SecretFile)?;
    let (mode, owner, process_user) = identities(&metadata);
    judge_secret(file, metadata.is_file(), mode, owner, process_user).map_err(TransportError::SecretRefused)
}


/// Mode bits and owner of the opened handle, with the effective user of the process.
#[cfg(unix)]
pub fn identities(metadata: &Metadata) -> (u32, u32, u32) {
    use std::os::unix::fs::MetadataExt;
    (metadata.mode(), metadata.uid(), rustix::process::geteuid().as_raw())
}


/// Without Unix modes only the regular-file check applies.
#[cfg(not(unix))]
pub fn identities(_metadata: &Metadata) -> (u32, u32, u32) {
    (0, ROOT_UID, ROOT_UID)
}


/// Printable UTF-8 without surrounding whitespace, so it can sit in a header; the error never carries the bytes.
pub fn secret_text(bytes: &[u8]) -> Result<Zeroizing<String>, TransportError> {
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        Err(TransportError::SecretTooLarge { max: MAX_SECRET_BYTES })
    } else {
        let text = std::str::from_utf8(bytes).map_err(|_error| TransportError::SecretFormat)?.trim();
        if text.is_empty() || text.chars().any(char::is_control) {
            Err(TransportError::SecretFormat)
        } else {
            Ok(Zeroizing::new(text.to_owned()))
        }
    }
}
