#[cfg(target_os = "linux")]
mod unix {
    use core_audit::log::{append, open_file_log};
    use core_config::reload::{current_config, ReloadContext};
    use core_config::types::SharedAuditFn;
    use core_config::watch::watch_files;
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;
    use std::error::Error;
    use std::io::stderr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{info, Level};
    use waf::apply::open_apply_audited;
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
        let sink = open_file_log(Path::new(&audit_file)).map(|opened| {
            let log = Arc::new(opened);
            let boxed: Box<SharedAuditFn> = Box::new(move |entry| append(&log, entry));
            boxed
        });
        let context = ReloadContext {
            actor_id: "waf_apply".to_owned(),
            tenant: "platform".to_owned(),
            module: "waf".to_owned(),
            target: settings_file.clone(),
            request_id: "waf-reload".to_owned(),
        };
        let engine = Arc::new(open_apply_audited(Path::new(&settings_file), run_with_deadline, sink, context)?);
        let watched = [
            PathBuf::from(&current_config(&engine).settings.routes_file),
            PathBuf::from(&settings_file),
        ];
        let _watcher = watch_files(Arc::clone(&engine), &watched, DEBOUNCE)?;
        let _signals = core_config::signal::reload_on_signals(Arc::clone(&engine), &[SIGHUP])?;
        info!("waf_apply running");
        Signals::new([SIGTERM, SIGINT])?.forever().next();
        Ok(())
    }
}


#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::run()
}


#[cfg(not(target_os = "linux"))]
fn main() {}
