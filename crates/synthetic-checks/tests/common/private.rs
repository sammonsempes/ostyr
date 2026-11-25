use std::fs;
use std::io;
use std::path::Path;


#[cfg(unix)]
pub const PRIVATE_MODE: u32 = 0o600;


/// A file only its owner can read, the mode every secret file must have.
pub fn write_private(path: &Path, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(PRIVATE_MODE))?;
    Ok(())
}
