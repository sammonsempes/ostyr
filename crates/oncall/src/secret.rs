use crate::error::TransportError;
use crate::limits::MAX_SECRET_BYTES;
use crate::settings::TransportSettings;
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use std::io::Read;
use std::path::{Component, Path};
use zeroize::Zeroizing;


/// The secret file is opened relative to the tenant's secrets directory; a `..`, an absolute path or a symlink leaving the directory is refused.
pub fn read_secret(settings: &TransportSettings, tenant: &str, relative: &str) -> Result<Zeroizing<String>, TransportError> {
    let directory = settings.secret_dirs.get(tenant).ok_or(TransportError::NoSecretsDir)?;
    let path = Path::new(relative);
    if path.components().any(|component| !matches!(component, Component::Normal(_))) {
        Err(TransportError::SecretFile(std::io::Error::other(
            "path is not relative to the secrets directory",
        )))
    } else {
        let handle = Dir::open_ambient_dir(directory, ambient_authority())
            .and_then(|dir| dir.open(path))
            .map_err(TransportError::SecretFile)?;
        let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES as usize + 1));
        handle
            .take(MAX_SECRET_BYTES + 1)
            .read_to_end(&mut buffer)
            .map_err(TransportError::SecretFile)?;
        secret_text(&buffer)
    }
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
