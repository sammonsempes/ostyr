//! Usage: detect <detection.yaml> <stop-file>. Runs the detection service with the file alert sink until the stop file exists.

use detection::run::run_service;
use detection::store::file_commit;
use std::error::Error;
use std::io::{self, Write};
use std::path::{Path, PathBuf};


pub const USAGE: &str = "usage: detect <detection.yaml> <stop-file>";


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(io::stderr).try_init()?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let settings_path = PathBuf::from(arguments.first().ok_or(USAGE)?);
    let stop_path = PathBuf::from(arguments.get(1).ok_or(USAGE)?);
    let stop = move || Path::new(&stop_path).exists();
    let summary = run_service(&settings_path, Box::new(stop), file_commit)?;
    writeln!(io::stdout(), "{summary:?}")?;
    Ok(())
}
