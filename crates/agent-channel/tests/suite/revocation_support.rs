use agent_channel::identity::serial_from_certificate;
use agent_channel::model::{ClientTlsPaths, Revocations};
use agent_channel::revocation::open_revocation_engine;
use agent_channel::tls::read_certificates;
use agent_channel::types::RevocationWatch;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{ReloadContext, ReloadEngine};
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};


pub const REVOCATION_FILE: &str = "revoked.yaml";


pub struct RevocationControl {
    pub engine: ReloadEngine<Revocations>,
    pub file: PathBuf,
    pub recorded: Arc<Mutex<Vec<NewEntry>>>,
}


pub struct Revocation {
    pub control: RevocationControl,
    pub watcher: RevocationWatch,
}


pub fn write_revocations(file: &Path, serials: &[&str]) -> io::Result<()> {
    fs::write(file, format!("revoked_serials: {serials:?}\n"))
}


pub fn open_revocation(dir: &Path, serials: &[&str]) -> Result<Revocation, Box<dyn Error>> {
    let file = dir.join(REVOCATION_FILE);
    write_revocations(&file, serials)?;
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| {
        sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
        append(&log, entry)
    };
    let context = ReloadContext {
        actor_id: "agent-channel".to_owned(),
        tenant: "acme".to_owned(),
        module: "agent-channel".to_owned(),
        target: REVOCATION_FILE.to_owned(),
        request_id: "revocation-reload".to_owned(),
    };
    let (engine, watcher) = open_revocation_engine(file.clone(), Box::new(audit), context)?;
    Ok(Revocation {
        control: RevocationControl { engine, file, recorded },
        watcher,
    })
}


pub fn recorded_entries(control: &RevocationControl) -> Result<Vec<NewEntry>, Box<dyn Error>> {
    Ok(control.recorded.lock().map_err(|_| "poisoned")?.clone())
}


pub fn agent_serial(paths: &ClientTlsPaths) -> Result<String, Box<dyn Error>> {
    let chain = read_certificates(&paths.certificate)?;
    let leaf = chain.first().ok_or("no certificate")?;
    Ok(serial_from_certificate(leaf.as_ref())?)
}
