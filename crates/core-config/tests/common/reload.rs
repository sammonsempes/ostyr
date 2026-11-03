use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::error::ConfigError;
use core_config::model::ModuleConfig;
use core_config::reload::{current_config, module_loader, module_state, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::SharedAuditFn;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "core-config".to_owned(),
        tenant: "example".to_owned(),
        module: "siem".to_owned(),
        target: "module.yaml".to_owned(),
        request_id: "config-reload".to_owned(),
    }
}


pub fn module_text(retention: &str) -> String {
    format!("name: siem\nversion: 1.2.0\nlisten: 0.0.0.0:8080\nsecrets:\n  db: vault://kv/siem/db\nsettings:\n  retention: {retention}\n")
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub fn recording_audit() -> (Box<SharedAuditFn>, Arc<Mutex<Vec<NewEntry>>>) {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| {
        sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
        append(&log, entry)
    };
    (Box::new(audit), recorded)
}


pub fn entries(recorded: &Arc<Mutex<Vec<NewEntry>>>) -> io::Result<Vec<NewEntry>> {
    recorded.lock().map(|guard| guard.clone()).map_err(|_| io::Error::other("poisoned"))
}


pub fn engine_for(
    path: &Path,
    audit: Box<SharedAuditFn>,
    subscribers: Vec<Subscriber<ModuleConfig>>,
) -> Result<ReloadEngine<ModuleConfig>, ConfigError> {
    open_engine(module_loader(path.to_path_buf()), module_state, subscribers, audit, context())
}


pub fn retention(engine: &ReloadEngine<ModuleConfig>) -> Option<String> {
    current_config(engine).settings.get("retention").cloned()
}
