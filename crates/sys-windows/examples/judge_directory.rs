//! Usage: `judge_directory <path>`. Prints the owner and DACL of a directory and the spool verdict (Windows only).
use std::error::Error;
use std::io::{stdout, Write};


#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Path;
    use sys_windows::native::{judge_directory_handle, read_descriptor, token_user_sid};
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let path = std::env::args().nth(1).ok_or("usage: judge_directory <path>")?;
    let handle = OpenOptions::new().read(true).custom_flags(BACKUP_SEMANTICS).open(&path)?;
    let descriptor = read_descriptor(&handle)?;
    let mut out = stdout();
    writeln!(out, "token user {}", token_user_sid()?)?;
    writeln!(out, "owner {}", descriptor.owner)?;
    writeln!(out, "dacl {:?}", descriptor.dacl)?;
    match judge_directory_handle(&handle, Path::new(&path)) {
        Ok(()) => writeln!(out, "verdict accepted")?,
        Err(error) => writeln!(out, "verdict refused: {error}")?,
    }
    Ok(())
}


#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn Error>> {
    writeln!(stdout(), "judge_directory runs on Windows only")?;
    Ok(())
}
