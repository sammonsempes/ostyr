//! Usage: oncall_api <module.yaml>. Serves `GET /oncall/alerts` and `GET /oncall/alerts/{id}` alone through core-api; `settings.pg_settings` names the core-pg file. The role `analyst` gets `oncall.read` for the proof.

use alerts::backend::MAX_CONNECTIONS;
use alerts::settings::open_pg_engine_from;
use core_api::config::api_config;
use core_api::routes::build_router;
use core_api::server::{new_listener, serve};
use core_api::state::build_state_from_files;
use core_api::types::{ServerHandle, SharedState};
use core_config::load::load_module;
use oncall::api::{oncall_access, oncall_document, oncall_router, PERMISSION_ONCALL_READ};
use oncall::backend::pg_backend;
use std::error::Error;
use std::io::{stderr, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::Semaphore;


const USAGE: &str = "usage: oncall_api <module.yaml>";


const ACTOR: &str = "oncall";


const PROOF_ROLE: &str = "analyst";


async fn serve_api(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = Path::new(arguments.first().ok_or(USAGE)?);
    tracing_subscriber::fmt().with_writer(stderr).init();
    let loaded = load_module(module_file)?;
    let config = api_config(&loaded)?;
    let listener = new_listener();
    let (engine, _pg_file) = open_pg_engine_from(module_file, &loaded, listener, ACTOR)?;
    let backend = pg_backend(Arc::new(engine), Arc::new(Semaphore::new(MAX_CONNECTIONS)));
    let mut built = build_state_from_files(&config, oncall_access(), vec![oncall_document()])?;
    built
        .catalog
        .entry(PROOF_ROLE.to_owned())
        .or_default()
        .insert(PERMISSION_ONCALL_READ.to_owned());
    let state: SharedState = Arc::new(built);
    serve(&config, build_router(state, oncall_router(backend)), ServerHandle::new()).await?;
    Ok(())
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match serve_api(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
