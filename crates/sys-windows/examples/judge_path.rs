//! Usage: `judge_path <file-path>`. Opens the directory that holds the file as the agent does and judges the whole path from the volume root (Windows only).
use std::error::Error;
use std::io::{stdout, Write};


#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Path;
    use sys_windows::native::judge_spool_path;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const ARGUMENT_OPENED: usize = 2;
    let path = std::env::args().nth(1).ok_or("usage: judge_path <file-path>")?;
    let parent = Path::new(&path).parent().ok_or("no parent")?;
    let opened = std::env::args()
        .nth(ARGUMENT_OPENED)
        .map_or_else(|| parent.to_path_buf(), std::path::PathBuf::from);
    let handle = OpenOptions::new().read(true).custom_flags(BACKUP_SEMANTICS).open(opened)?;
    match judge_spool_path(&handle, Path::new(&path)) {
        Ok(()) => writeln!(stdout(), "verdict accepted")?,
        Err(error) => writeln!(stdout(), "verdict refused: {error}")?,
    }
    Ok(())
}


#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn Error>> {
    writeln!(stdout(), "judge_path runs on Windows only")?;
    Ok(())
}
