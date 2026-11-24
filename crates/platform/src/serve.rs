//! The `ostyr-platform` service: serves the fifteen modules of `settings.modules`; `risk` also needs `settings.risk.weights_file` and `status` needs `settings.status.page_file`.


use crate::merge::{
    check_page_tenant, load_page_services, migration_plan, module_parts, modules_of, page_file_of, start_only_keys, weights_file_of, ACTOR,
};
use crate::permits::{module_semaphores, start_permits};
use crate::types::InterruptWait;
use alerts::backend::{lease, LOG_IGNORED_CRATE};
use alerts::settings::{api_startup_reloads, module_audit, open_pg_engine_from, DEFAULT_TENANT};
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::logging::reloadable_dispatch;
use core_api::server::{listening_address, new_listener, run_loaded, stop_listener};
use core_api::types::{SharedListener, StartupReloadFn};
use core_config::load::load_module;
use core_config::reload::{open_engine, reload, ReloadContext};
#[cfg(unix)]
use core_config::signal::reload_on_signals;
use core_config::watch::watch_files;
use core_pg::migrate::migrate;
use risk_score::weights::{weights_loader, weights_state};
use std::error::Error;
use std::io::stdout;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


const SHUTDOWN_GRACE_SECONDS: u64 = 5;


const RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);


const STARTUP_REQUEST: &str = "startup";


const USAGE: &str = "usage: ostyr-platform <module.yaml>";


pub async fn stop_on(listener: SharedListener, wait: InterruptWait) {
    match wait.await {
        Ok(()) => stop_listener(&listener, Some(Duration::from_secs(SHUTDOWN_GRACE_SECONDS))),
        Err(error) => tracing::error!(%error, "cannot listen for the interrupt signal"),
    }
}


/// Logs the bound address once the server listens, so a caller that asked for port 0 can find it.
pub async fn announce(listener: SharedListener) {
    let address = listening_address(&listener).await;
    address.iter().for_each(|bound| {
        let text = bound.to_string();
        tracing::info!(address = text, "serving");
    });
}


pub async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let module_file = arguments.first().ok_or(USAGE)?;
    let loaded = load_module(Path::new(module_file))?;
    let modules = modules_of(&loaded.settings)?;
    let weights_file = weights_file_of(&loaded.settings, &modules)?;
    let page = page_file_of(&loaded.settings, &modules)?
        .map(|file| load_page_services(&file))
        .transpose()?
        .map(|services| check_page_tenant(services, loaded.tenant.as_deref().unwrap_or(DEFAULT_TENANT)))
        .transpose()?;
    let (dispatch, log) = reloadable_dispatch(BoxMakeWriter::new(stdout), DEFAULT_LOG_LEVEL);
    tracing::dispatcher::set_global_default(dispatch)?;
    tracing_log::LogTracer::builder().ignore_crate(LOG_IGNORED_CRATE).init()?;
    let listener = new_listener();
    let (opened, pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, listener.clone(), ACTOR)?;
    let engine = Arc::new(opened);
    let _watch = watch_files(Arc::clone(&engine), &[PathBuf::from(module_file), pg_file], RELOAD_DEBOUNCE)?;
    #[cfg(unix)]
    let _signals = reload_on_signals(Arc::clone(&engine), &[signal_hook::consts::SIGHUP])?;
    let weights = match &weights_file {
        Some(file) => {
            let context = ReloadContext {
                actor_id: ACTOR.to_owned(),
                tenant: loaded.tenant.clone().unwrap_or_else(|| DEFAULT_TENANT.to_owned()),
                module: loaded.name.clone(),
                target: file.display().to_string(),
                request_id: STARTUP_REQUEST.to_owned(),
            };
            Some(Arc::new(open_engine(
                weights_loader(file.clone()),
                weights_state,
                Vec::new(),
                module_audit(listener.clone()),
                context,
            )?))
        }
        None => None,
    };
    let _weights_watch = match (&weights, &weights_file) {
        (Some(weights_engine), Some(file)) => Some(watch_files(Arc::clone(weights_engine), std::slice::from_ref(file), RELOAD_DEBOUNCE)?),
        _ => None,
    };
    #[cfg(unix)]
    let _weights_signals = match &weights {
        Some(weights_engine) => Some(reload_on_signals(Arc::clone(weights_engine), &[signal_hook::consts::SIGHUP])?),
        None => None,
    };
    let held = lease(&engine, &start_permits()).await?;
    for (namespace, migrations) in migration_plan(&modules) {
        let applied = migrate(&held.client, namespace, migrations, held.deadline).await?;
        tracing::info!(namespace, applied = applied.len(), "migrations checked");
    }
    drop(held);
    let (router, access, documents) = module_parts(&modules, &engine, &module_semaphores(&modules), weights.as_ref(), page.as_ref())?;
    tokio::spawn(stop_on(listener.clone(), Box::pin(tokio::signal::ctrl_c())));
    tokio::spawn(announce(listener.clone()));
    let mut startup_reloads = api_startup_reloads(Arc::clone(&engine));
    if let Some(weights_engine) = weights {
        startup_reloads.push(Box::new(move || reload(&weights_engine)) as StartupReloadFn);
    }
    run_loaded(
        Path::new(module_file),
        loaded,
        (router, access, documents),
        &start_only_keys(page.is_some()),
        listener,
        Some(log),
        startup_reloads,
    )
    .await?;
    Ok(())
}
