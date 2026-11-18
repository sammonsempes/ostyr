#[cfg(unix)]
mod unix {
    use core_audit::log::{append, open_file_log};
    use core_config::reload::ReloadContext;
    use core_config::watch::watch_files;
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;
    use std::error::Error;
    use std::io::stderr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{info, Level};
    use waf::apply::{load_settings, open_apply};
    use waf::runner::run_with_deadline;


    const DEBOUNCE: Duration = Duration::from_millis(300);


    const USAGE: &str = "usage: waf_apply <settings.yaml> <audit-file>";


    pub fn run() -> Result<(), Box<dyn Error>> {
        tracing_subscriber::fmt()
            .with_writer(stderr)
            .with_max_level(Level::INFO)
            .try_init()
            .map_err(|error| error.to_string())?;
        let mut arguments = std::env::args().skip(1);
        let settings_file = arguments.next().ok_or(USAGE)?;
        let audit_file = arguments.next().ok_or(USAGE)?;
        let settings = load_settings(Path::new(&settings_file))?;
        let watched = [PathBuf::from(&settings.routes_file), PathBuf::from(&settings_file)];
        let log = Arc::new(open_file_log(Path::new(&audit_file))?);
        let context = ReloadContext {
            actor_id: "waf_apply".to_owned(),
            tenant: "platform".to_owned(),
            module: "waf".to_owned(),
            target: settings.routes_file.clone(),
            request_id: "waf-reload".to_owned(),
        };
        let engine = Arc::new(open_apply(
            Path::new(&settings_file),
            run_with_deadline,
            Box::new(move |entry| append(&log, entry)),
            context,
        )?);
        let _watcher = watch_files(Arc::clone(&engine), &watched, DEBOUNCE)?;
        let _signals = core_config::signal::reload_on_signals(Arc::clone(&engine), &[SIGHUP])?;
        info!("waf_apply running");
        Signals::new([SIGTERM, SIGINT])?.forever().next();
        Ok(())
    }
}


#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::run()
}


#[cfg(not(unix))]
fn main() {}
