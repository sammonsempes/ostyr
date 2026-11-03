use core_audit::log::{append, open_file_log};
use core_config::watch::watch_files;
use response_breakers::breakers::{open_breakers, BreakerSettings, Breakers};
use response_breakers::store::sync_path;
use response_playbooks::bundle::{open_playbooks, PlaybookSettings};
use response_playbooks::cli::{run_session, Session};
use std::error::Error;
use std::io::{stdin, stdout};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;


const DEBOUNCE: Duration = Duration::from_millis(300);


const USAGE: &str = "usage: playbooks_demo <limits-file> <counter-file> <audit-file> <catalogue> <playbook>...";


#[cfg(unix)]
fn keep_signals(session: &Session) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(Arc::clone(&session.engine), &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals(_session: &Session) -> std::io::Result<()> {
    Ok(())
}


fn open_limits(limits_file: &str, store_file: &str, audit_file: &str) -> Result<(Breakers, Arc<core_config::types::SharedAuditFn>), Box<dyn Error>> {
    let log = Arc::new(open_file_log(&PathBuf::from(audit_file))?);
    let breaker_log = Arc::clone(&log);
    let breakers = open_breakers(BreakerSettings {
        config_path: PathBuf::from(limits_file),
        store_path: PathBuf::from(store_file),
        sync: sync_path,
        audit: Arc::new(move |entry| append(&breaker_log, entry)),
        clock: Box::new(OffsetDateTime::now_utc),
    })?;
    Ok((breakers, Arc::new(move |entry| append(&log, entry))))
}


fn start(limits_file: &str, store_file: &str, audit_file: &str, catalogue: &str, playbooks: &[String]) -> Result<(), Box<dyn Error>> {
    let (breakers, audit) = open_limits(limits_file, store_file, audit_file)?;
    let playbook_paths: Vec<PathBuf> = playbooks.iter().map(PathBuf::from).collect();
    let engine = Arc::new(open_playbooks(PlaybookSettings {
        catalogue_path: PathBuf::from(catalogue),
        playbook_paths: playbook_paths.clone(),
        audit,
    })?);
    let watched: Vec<PathBuf> = std::iter::once(PathBuf::from(catalogue)).chain(playbook_paths).collect();
    let _watcher = watch_files(Arc::clone(&engine), &watched, DEBOUNCE)?;
    let session = Session { engine, breakers };
    let _signals = keep_signals(&session)?;
    run_session(&session, stdin().lock(), &mut stdout())?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [limits_file, store_file, audit_file, catalogue, playbooks @ ..] if !playbooks.is_empty() => {
            start(limits_file, store_file, audit_file, catalogue, playbooks)
        }
        _ => Err(USAGE.into()),
    }
}
