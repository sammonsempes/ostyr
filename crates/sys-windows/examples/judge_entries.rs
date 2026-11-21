//! Usage: `judge_entries <path>...`. Judges each existing fixed-name entry as the agent does at start (Windows only).
use std::error::Error;
use std::io::{stdout, Write};


#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    use std::path::PathBuf;
    use sys_windows::native::judge_spool_entries;
    let paths: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    match judge_spool_entries(&paths) {
        Ok(()) => writeln!(stdout(), "verdict accepted")?,
        Err(error) => writeln!(stdout(), "verdict refused: {error}")?,
    }
    Ok(())
}


#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn Error>> {
    writeln!(stdout(), "judge_entries runs on Windows only")?;
    Ok(())
}
