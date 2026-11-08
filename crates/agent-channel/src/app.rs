use core_audit::log::{append, AuditLog};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_config::types::SharedAuditFn;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;


pub const DEBOUNCE_MILLIS: u64 = 300;


pub fn debounce() -> Duration {
    Duration::from_millis(DEBOUNCE_MILLIS)
}


/// An audit function appending to the shared platform audit log.
pub fn shared_log_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let shared = Arc::clone(log);
    Box::new(move |entry| append(&shared, entry))
}


/// Passes the audit record on; a failed append is logged at error level as an alert (the engine then keeps the old list in force).
pub fn alerting_audit(inner: Box<SharedAuditFn>) -> Box<SharedAuditFn> {
    Box::new(move |entry| inner(entry).inspect_err(|error| tracing::error!(%error, "ALERT: reload audit append failed, old configuration kept")))
}


pub fn reload_context(target: &Path, module: &str, tenant: &str, request_id: &str) -> ReloadContext {
    ReloadContext {
        actor_id: module.to_owned(),
        tenant: tenant.to_owned(),
        module: module.to_owned(),
        target: target.display().to_string(),
        request_id: request_id.to_owned(),
    }
}


/// `SIGHUP` reloads the engine; dropping the result stops it.
#[cfg(unix)]
pub fn keep_signals<Config: Send + Sync + 'static>(engine: Arc<ReloadEngine<Config>>) -> io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
pub fn keep_signals<Config: Send + Sync + 'static>(_engine: Arc<ReloadEngine<Config>>) -> io::Result<impl Sized> {
    Ok(())
}
