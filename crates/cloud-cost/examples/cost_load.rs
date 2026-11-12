//! Usage: cost_load <export.csv> <settings.yaml>. Parses the export and loads its daily aggregates into ClickHouse, then prints the outcome.

use cloud_cost::load::load_table;
use cloud_cost::model::Limits;
use cloud_cost::settings::{validate_config, CostLoadConfig};
use cloud_cost::source::read_export;
use core_config::load::load_file;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};


const ARGUMENT_EXPORT: usize = 1;


const ARGUMENT_SETTINGS: usize = 2;


const USAGE: &str = "usage: cost_load <export.csv> <settings.yaml>";


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let export_path = arguments.get(ARGUMENT_EXPORT).ok_or(USAGE)?;
    let settings_path = arguments.get(ARGUMENT_SETTINGS).ok_or(USAGE)?;
    let config: CostLoadConfig = load_file(settings_path.as_ref())?;
    validate_config(&config)?;
    let export = read_export(File::open(export_path)?, &Limits::default(), &config.tenant)?;
    let version = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let started = Instant::now();
    let outcome = load_table(&config, &export, version, &|| started.elapsed())?;
    let mut out = stdout();
    writeln!(out, "source {}", export.source)?;
    writeln!(out, "{outcome:?}")?;
    Ok(())
}
