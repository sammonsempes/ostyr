use core_audit::log::{append, open_file_log};
use core_config::reload::{module_loader, module_state, open_engine, ReloadContext, ReloadEngine};
use core_config::reload_cli::run_session;
use core_config::watch::watch_files;
use std::error::Error;
use std::io::{self, stdin, stdout};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;


const DEBOUNCE: Duration = Duration::from_millis(300);


#[cfg(unix)]
fn keep_signals<Config: Send + Sync + 'static>(engine: Arc<ReloadEngine<Config>>) -> io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals<Config: Send + Sync + 'static>(_engine: Arc<ReloadEngine<Config>>) -> io::Result<impl Sized> {
    Ok(())
}


fn start(module_file: &str, audit_file: &str) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(audit_file))?;
    let context = ReloadContext {
        actor_id: "config_reload".to_owned(),
        tenant: "example".to_owned(),
        module: "example".to_owned(),
        target: module_file.to_owned(),
        request_id: "config-reload".to_owned(),
    };
    let engine = Arc::new(open_engine(
        module_loader(PathBuf::from(module_file)),
        module_state,
        Vec::new(),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?);
    let _watcher = watch_files(Arc::clone(&engine), &[PathBuf::from(module_file)], DEBOUNCE)?;
    let _signals = keep_signals(Arc::clone(&engine))?;
    run_session(&engine, stdin().lock(), &mut stdout())?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [module_file, audit_file] => start(module_file, audit_file),
        _ => Err("usage: config_reload <module-file> <audit-file>".into()),
    }
}
