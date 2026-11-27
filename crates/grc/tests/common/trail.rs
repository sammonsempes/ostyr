use core_audit::log::{append, genesis_log};
use core_config::types::SharedAuditFn;
use std::io::sink;
use std::sync::{Arc, Mutex, PoisonError};


pub fn recording_audit() -> (Arc<Mutex<Vec<String>>>, Box<SharedAuditFn>) {
    let trail = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&trail);
    let log = genesis_log(sink());
    let audit: Box<SharedAuditFn> = Box::new(move |entry| {
        let line = format!(
            "{}|{:?}|{}",
            entry.tenant,
            entry.outcome,
            entry.parameters.get("result").map_or("", String::as_str)
        );
        seen.lock().unwrap_or_else(PoisonError::into_inner).push(line);
        append(&log, entry)
    });
    (trail, audit)
}
