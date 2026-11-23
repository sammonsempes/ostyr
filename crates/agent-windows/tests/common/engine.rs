use agent_windows::settings::{open_settings, OpenError, Settings};
use agent_windows::types::SharedObserved;
use core_audit::log::{append, genesis_log};
use core_audit::model::Outcome;
use core_config::reload::{ReloadContext, ReloadEngine};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;


pub struct Broken;


impl io::Write for Broken {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("audit down"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("audit down"))
    }
}


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "agent-windows".to_owned(),
        tenant: "example".to_owned(),
        module: "agent-windows".to_owned(),
        target: "settings.yaml".to_owned(),
        request_id: "reload".to_owned(),
    }
}


pub fn open_at(path: &Path, denied: Arc<AtomicUsize>, observed: SharedObserved) -> Result<ReloadEngine<Settings>, OpenError> {
    open_with(path, denied, observed, Arc::new(AtomicBool::new(false)))
}


pub fn open_with(
    path: &Path,
    denied: Arc<AtomicUsize>,
    observed: SharedObserved,
    audit_down: Arc<AtomicBool>,
) -> Result<ReloadEngine<Settings>, OpenError> {
    let log = genesis_log(io::sink());
    let broken = genesis_log(Broken);
    open_settings(
        path.to_owned(),
        Box::new(move |entry| {
            if audit_down.load(Ordering::SeqCst) {
                append(&broken, entry)
            } else {
                if matches!(entry.outcome, Outcome::Denied) {
                    denied.fetch_add(1, Ordering::SeqCst);
                }
                append(&log, entry)
            }
        }),
        context(),
        observed,
    )
}
