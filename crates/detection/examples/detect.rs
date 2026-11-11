//! Usage: detect <detection.yaml> <stop-file>. Runs the detection service with the alert sink of the `sink` setting until the stop file exists.

use detection::run::run_service;
use detection::store::commit_alerts;
use std::error::Error;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::Level;


pub const USAGE: &str = "usage: detect <detection.yaml> <stop-file>";


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).with_writer(io::stderr).try_init()?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let settings_path = PathBuf::from(arguments.first().ok_or(USAGE)?);
    let stop_path = PathBuf::from(arguments.get(1).ok_or(USAGE)?);
    let stop = move || Path::new(&stop_path).exists();
    let summary = run_service(&settings_path, Box::new(stop), commit_alerts)?;
    writeln!(io::stdout(), "{summary:?}")?;
    Ok(())
}
