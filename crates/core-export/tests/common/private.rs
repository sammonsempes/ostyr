use std::fs;
use std::io;
use std::path::Path;


#[cfg(unix)]
pub const PRIVATE_MODE: u32 = 0o600;


/// Writes a secret file the way the loaders require: nothing for group or other.
pub fn write_private(path: impl AsRef<Path>, text: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path.as_ref(), text)?;
    #[cfg(unix)]
    fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(PRIVATE_MODE))?;
    Ok(())
}
