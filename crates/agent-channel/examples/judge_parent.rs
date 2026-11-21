//! Usage: `judge_parent <file-path>`. Opens and judges the directory that holds the file, as the agent does for its audit file.
use agent_channel::spool_dirs::open_parent;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).ok_or("usage: judge_parent <file-path>")?;
    match open_parent(Path::new(&path)) {
        Ok(_) => writeln!(stdout(), "parent accepted")?,
        Err(error) => writeln!(stdout(), "parent refused: {error}")?,
    }
    Ok(())
}
