use core_audit::log::{append, open_file_log};
use core_config::watch::watch_files;
use response_breakers::breakers::{open_breakers, BreakerSettings};
use response_breakers::cli::run_session;
use response_breakers::store::sync_path;
use std::error::Error;
use std::io::{stdin, stdout};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;


const DEBOUNCE: Duration = Duration::from_millis(300);


#[cfg(unix)]
fn keep_signals(breakers: &response_breakers::breakers::Breakers) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(Arc::clone(&breakers.engine), &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals(_breakers: &response_breakers::breakers::Breakers) -> std::io::Result<()> {
    Ok(())
}


fn start(config_file: &str, store_file: &str, audit_file: &str) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(&PathBuf::from(audit_file))?;
    let breakers = open_breakers(BreakerSettings {
        config_path: PathBuf::from(config_file),
        store_path: PathBuf::from(store_file),
        sync: sync_path,
        audit: Arc::new(move |entry| append(&log, entry)),
        clock: Box::new(OffsetDateTime::now_utc),
    })?;
    let _watcher = watch_files(Arc::clone(&breakers.engine), &[PathBuf::from(config_file)], DEBOUNCE)?;
    let _signals = keep_signals(&breakers)?;
    run_session(&breakers, stdin().lock(), &mut stdout())?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [config_file, store_file, audit_file] => start(config_file, store_file, audit_file),
        _ => Err("usage: breakers_demo <limits-file> <counter-file> <audit-file>".into()),
    }
}
