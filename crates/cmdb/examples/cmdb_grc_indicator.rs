//! Usage: cmdb_grc_indicator <module.yaml> <tenant> <out.json> [cmdb.yaml]. Writes the `assets.owned_ratio` indicator of one tenant in grc's input format.

use alerts::backend::{lease, MAX_CONNECTIONS};
use alerts::settings::open_pg_engine_from;
use cmdb::backend::ACTOR;
use cmdb::config::load_cmdb;
use cmdb::grc_indicator::{indicator_json, owned_ratio};
use cmdb::pg::pg_executor;
use cmdb::store::load_assets;
use cmdb::types::TruthMap;
use core_config::load::load_module;
use core_pg::scope::tenant_scope;
use std::error::Error;
use std::io::{stderr, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use tempfile::NamedTempFile;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Semaphore;


const OUT_INDEX: usize = 2;


const CMDB_INDEX: usize = 3;


const USAGE: &str = "usage: cmdb_grc_indicator <module.yaml> <tenant> <out.json> [cmdb.yaml]";


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let tenant = arguments.get(1).ok_or(USAGE)?;
    let out = Path::new(arguments.get(OUT_INDEX).ok_or(USAGE)?);
    let directory = out.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let truth = arguments
        .get(CMDB_INDEX)
        .map(|file| load_cmdb(Path::new(file)))
        .transpose()?
        .map_or_else(TruthMap::new, |config| config.sources_of_truth);
    let loaded = load_module(Path::new(module_file))?;
    let (opened, _pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, core_api::server::new_listener(), ACTOR)?;
    let engine = Arc::new(opened);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    let snapshot = load_assets(&executor, &tenant_scope(tenant)?, &Default::default()).await?;
    let observed_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let text = indicator_json(tenant, &owned_ratio(&snapshot, &truth), &observed_at, &format!("cmdb:{tenant}"));
    let mut temporary = NamedTempFile::new_in(directory)?;
    temporary.write_all(text.as_bytes())?;
    temporary.persist(out)?;
    Ok(())
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "refused: {error}").map(|()| ExitCode::FAILURE),
    }
}
