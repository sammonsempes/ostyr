//! Usage: risk_scores <module.yaml> <weights.yaml> <tenant> [threshold]. Prints one tenant's entity risk scores from the alerts store (`settings.pg_settings` names the core-pg file).

use alerts::backend::{lease, unix_micros, MICROS_PER_SECOND};
use alerts::pg::pg_executor;
use alerts::settings::{open_pg_engine_from, ACTOR};
use core_api::server::new_listener;
use core_config::load::load_module;
use core_pg::scope::tenant_scope;
use risk_score::score::over_threshold;
use risk_score::source::{tenant_scores, Limits};
use risk_score::weights::load_weights;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::Semaphore;


const WEIGHTS_ARGUMENT: usize = 1;


const TENANT_ARGUMENT: usize = 2;


const THRESHOLD_ARGUMENT: usize = 3;


const USAGE: &str = "usage: risk_scores <module.yaml> <weights.yaml> <tenant> [threshold]";


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let weights_file = arguments.get(WEIGHTS_ARGUMENT).ok_or(USAGE)?;
    let tenant = arguments.get(TENANT_ARGUMENT).ok_or(USAGE)?;
    let threshold = arguments.get(THRESHOLD_ARGUMENT).map(|text| text.parse::<u8>()).transpose()?.unwrap_or(0);
    let scope = tenant_scope(tenant)?;
    let weights = load_weights(Path::new(weights_file))?;
    let loaded = load_module(Path::new(module_file))?;
    let (engine, _pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, new_listener(), ACTOR)?;
    let held = lease(&engine, &Arc::new(Semaphore::new(1))).await?;
    let executor = pg_executor(&held.client, held.deadline);
    let now = i64::try_from(unix_micros() / MICROS_PER_SECOND)?;
    let outcome = tenant_scores(&executor, &scope, &weights, now, &Limits::default()).await?;
    let mut out = stdout();
    over_threshold(&outcome.scores, threshold)
        .iter()
        .try_for_each(|score| writeln!(out, "{:?} {} {}", score.entity.kind, score.entity.id.escape_debug(), score.value))?;
    writeln!(
        out,
        "entities={} alerts_read={} informational={} refused={:?} truncated={:?}",
        outcome.scores.len(),
        outcome.alerts_read,
        outcome.informational,
        outcome.refused,
        outcome.truncated
    )?;
    Ok(())
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
