use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::types::SharedAuditFn;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;


pub const HANG_GUARD: Duration = Duration::from_secs(30);


pub struct Gate {
    pub audit: Box<SharedAuditFn>,
    pub entered: Receiver<()>,
    pub release: Sender<()>,
    pub audited: Arc<AtomicBool>,
}


/// An audit that announces its entry, waits for the release, then records `audited` and appends.
pub fn gated_audit() -> Gate {
    let (entered_sender, entered) = channel::<()>();
    let (release_sender, release) = channel::<()>();
    let release_slot = Mutex::new(release);
    let entered_slot = Mutex::new(entered_sender);
    let audited = Arc::new(AtomicBool::new(false));
    let audited_in_audit = Arc::clone(&audited);
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| {
        entered_slot
            .lock()
            .map_err(|_| AuditError::LogPoisoned)?
            .send(())
            .map_err(|_| AuditError::LogPoisoned)?;
        release_slot
            .lock()
            .map_err(|_| AuditError::LogPoisoned)?
            .recv_timeout(HANG_GUARD)
            .map_err(|_| AuditError::LogPoisoned)?;
        audited_in_audit.store(true, Ordering::SeqCst);
        append(&log, entry)
    };
    Gate {
        audit: Box::new(audit),
        entered,
        release: release_sender,
        audited,
    }
}
