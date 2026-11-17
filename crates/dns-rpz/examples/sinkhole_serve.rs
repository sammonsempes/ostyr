use core_audit::log::{append, genesis_log};
use core_config::reload::ReloadContext;
use core_config::watch::watch_files;
use dns_rpz::model::ServeState;
use dns_rpz::policy::{open_serving_policy, Policy};
use dns_rpz::serve::serve;
use std::error::Error;
use std::io::stderr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot::channel;
use tracing::Level;


const DEBOUNCE: Duration = Duration::from_millis(300);


const USAGE: &str = "usage: sinkhole_serve <policy>";


#[cfg(unix)]
fn keep_signals(engine: Arc<core_config::reload::ReloadEngine<Policy>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals(_engine: Arc<core_config::reload::ReloadEngine<Policy>>) -> std::io::Result<impl Sized> {
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_writer(stderr)
        .with_max_level(Level::INFO)
        .try_init()
        .map_err(|error| error.to_string())?;
    let policy_file = std::env::args().nth(1).ok_or(USAGE)?;
    let log = Arc::new(genesis_log(stderr()));
    let context = ReloadContext {
        actor_id: "sinkhole_serve".to_owned(),
        tenant: "example".to_owned(),
        module: "dns-rpz".to_owned(),
        target: policy_file.clone(),
        request_id: "dns-rpz-sinkhole-reload".to_owned(),
    };
    let engine = Arc::new(open_serving_policy(
        PathBuf::from(&policy_file),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?);
    let _watcher = watch_files(Arc::clone(&engine), &[PathBuf::from(&policy_file)], DEBOUNCE)?;
    let _signals = keep_signals(Arc::clone(&engine))?;
    let listen = core_config::reload::current_config(&engine)
        .sinkhole_server
        .ok_or("the policy has no sinkhole_server block")?
        .listen;
    let listener = TcpListener::bind(listen).await?;
    let (_keep_running, shutdown) = channel();
    serve(listener, engine, Arc::new(ServeState::default()), shutdown).await;
    Ok(())
}
