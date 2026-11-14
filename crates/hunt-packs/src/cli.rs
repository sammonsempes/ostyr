use crate::error::PackError;
use crate::packs::load_packs;
use crate::run::{run_pack, RunError};
use metric_alerts::fetch::{agent_for, load_fetch_settings, read_key, FetchError};
use std::io::{self, Write};
use std::num::ParseIntError;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;


pub const USAGE: &str = "usage: hunt_run <settings.yaml> <packs-dir> <pack-id> <tenant> <now>";


#[derive(Debug, Error)]
pub enum RunCliError {
    #[error("{USAGE}")]
    Usage,
    #[error("now must be unix seconds")]
    Now(#[source] ParseIntError),
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error("no such pack")]
    UnknownPack,
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Run(#[from] RunError),
    #[error("the report could not be written")]
    Output(#[from] io::Error),
}


/// Runs the named pack for the tenant and writes `id`, matches and finding, tab separated.
pub fn run_files(settings: &str, dir: &str, id: &str, tenant: &str, now: u64, out: &mut dyn Write) -> Result<(), RunCliError> {
    let fetch_settings = load_fetch_settings(Path::new(settings))?;
    let agent = agent_for(&fetch_settings)?;
    let password = read_key(&fetch_settings)?;
    let packs = load_packs(Path::new(dir))?;
    let found = packs.iter().find(|item| item.pack.id == id).ok_or(RunCliError::UnknownPack)?;
    let remaining = Duration::from_millis(fetch_settings.timeout_ms);
    let outcome = run_pack(&agent, &fetch_settings, &password, &found.pack, tenant, now, remaining)?;
    writeln!(out, "{id}\t{}\t{}", outcome.matches, outcome.finding)?;
    Ok(())
}


pub fn run_cli(args: &[String], out: &mut dyn Write) -> Result<(), RunCliError> {
    match args {
        [settings, dir, id, tenant, now] => run_files(settings, dir, id, tenant, now.parse::<u64>().map_err(RunCliError::Now)?, out),
        _ => Err(RunCliError::Usage),
    }
}
