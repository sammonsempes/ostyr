use crate::error::PackError;
use crate::packs::{load_packs, source_name};
use std::io::{self, Write};
use std::path::Path;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum CheckError {
    #[error("usage: hunt_check <directory>")]
    Usage,
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error("cannot write the report")]
    Write(#[from] io::Error),
}


/// Validates the directory named by the only argument and writes `id`, technique, source and schedule, tab separated, one line per pack.
pub fn run_check(args: &[String], out: &mut dyn Write) -> Result<(), CheckError> {
    let dir = match args {
        [dir] => Ok(dir),
        _ => Err(CheckError::Usage),
    }?;
    load_packs(Path::new(dir))?.iter().try_for_each(|item| {
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            item.pack.id,
            item.pack.technique,
            source_name(item.pack.source),
            item.pack.schedule_seconds
        )
    })?;
    Ok(())
}
