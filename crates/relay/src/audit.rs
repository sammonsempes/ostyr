use crate::model::{DECLARED_KEYS, MODULE, TENANT};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, AuditLog};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome, Record};
use core_config::reload::ReloadContext;
use core_config::types::SharedAuditFn;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;


pub const START_ACTION: &str = "relay.start";


pub const STOP_ACTION: &str = "relay.stop";


pub fn lifecycle_entry(target: &Path, action: &str, parameters: &[(&str, String)]) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: MODULE.to_owned(),
        },
        tenant: TENANT.to_owned(),
        module: MODULE.to_owned(),
        action: action.to_owned(),
        target: target.display().to_string(),
        outcome: Outcome::Success,
        request_id: action.to_owned(),
        justification: None,
        parameters: parameters.iter().map(|(key, value)| ((*key).to_owned(), value.clone())).collect(),
    }
}


pub fn append_entry(log: &AuditLog<File>, entry: NewEntry) -> Result<Record, AuditError> {
    append_declared(log, entry, &DECLARED_KEYS)
}


pub fn shared_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let shared = Arc::clone(log);
    Box::new(move |entry| append_entry(&shared, entry))
}


pub fn reload_context(target: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: target.display().to_string(),
        request_id: "settings-reload".to_owned(),
    }
}
