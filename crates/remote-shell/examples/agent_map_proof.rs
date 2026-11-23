use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{current_config, reload, ReloadContext};
use remote_shell::agent_map::{open_agent_engine, resolve_agent};
use std::error::Error;
use std::fs;
use std::io::{self, stdout, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};


const GOOD: &str = "tenant: tenant-a\nagents:\n  - agent_id: agent-1\n    asset: srv1\n";


const BAD: &str = "tenant: tenant-a\nagents:\n  - agent_id: agent-1\n    asset: srv1\n  - agent_id: agent-2\n    asset: SRV1\n";


const TAGGED: &str = "tenant: tenant-a\nagents:\n  - agent_id: !!binary YWdlbnQtMg==\n    asset: srv2\n";


const CR_HIDDEN: &str = "tenant: tenant-a\nagents:\n  - agent_id: agent-1\n    asset: srv1\n# retired\r  - agent_id: agent-2\n    asset: srv2\n";


fn long_line_file() -> String {
    format!(
        "tenant: tenant-a\nagents: [{{agent_id: agent-1, asset: srv1}},{}{{agent_id: agent-2, asset: srv2}}]\n",
        " ".repeat(LONG_LINE_PADDING)
    )
}


const LONG_LINE_PADDING: usize = 5000;


const HIDDEN_PADDING: usize = 180;


fn hidden_entry_file() -> String {
    format!(
        "tenant: tenant-a\nagents: [{{agent_id: agent-1, asset: srv1}},{}{{agent_id: evil, asset: dc01}}]\n",
        " ".repeat(HIDDEN_PADDING)
    )
}


fn main() -> Result<(), Box<dyn Error>> {
    let dir = PathBuf::from(std::env::args().nth(1).ok_or("usage: agent_map_proof <directory>")?);
    let path = dir.join("remote-shell-agents.yaml");
    fs::write(&path, GOOD)?;
    let recorded: Arc<Mutex<Vec<NewEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| {
        sink.lock().map_err(|_| core_audit::error::AuditError::LogPoisoned)?.push(entry.clone());
        append(&log, entry)
    };
    let context = ReloadContext {
        actor_id: "remote-shell".to_owned(),
        tenant: "tenant-a".to_owned(),
        module: "remote-shell".to_owned(),
        target: "remote-shell-agents.yaml".to_owned(),
        request_id: "agent-map-proof".to_owned(),
    };
    let engine = open_agent_engine(path.clone(), Box::new(audit), context)?;
    let mut out = stdout();
    writeln!(out, "srv1 -> {:?}", resolve_agent(&current_config(&engine), "tenant-a", "srv1"))?;
    fs::write(&path, BAD)?;
    writeln!(out, "reload bad file -> {:?}", reload(&engine))?;
    writeln!(
        out,
        "srv1 after bad reload -> {:?}",
        resolve_agent(&current_config(&engine), "tenant-a", "srv1")
    )?;
    fs::write(&path, TAGGED)?;
    writeln!(out, "reload tagged file -> {:?}", reload(&engine))?;
    writeln!(
        out,
        "srv1 after tagged reload -> {:?}",
        resolve_agent(&current_config(&engine), "tenant-a", "srv1")
    )?;
    fs::write(&path, CR_HIDDEN)?;
    writeln!(out, "reload CR-hidden file -> {:?}", reload(&engine))?;
    writeln!(
        out,
        "srv2 after CR reload -> {:?}",
        resolve_agent(&current_config(&engine), "tenant-a", "srv2")
    )?;
    fs::write(&path, long_line_file())?;
    writeln!(out, "reload long-line file -> {:?}", reload(&engine))?;
    writeln!(
        out,
        "srv2 after long-line reload -> {:?}",
        resolve_agent(&current_config(&engine), "tenant-a", "srv2")
    )?;
    fs::write(&path, hidden_entry_file())?;
    writeln!(out, "reload hidden-entry file -> {:?}", reload(&engine))?;
    writeln!(
        out,
        "dc01 after hidden-entry reload -> {:?}",
        resolve_agent(&current_config(&engine), "tenant-a", "dc01")
    )?;
    let entries = recorded.lock().map_err(|_| "poisoned")?;
    entries
        .iter()
        .try_for_each(|entry| writeln!(out, "audit: {:?} {:?}", entry.outcome, entry.parameters))?;
    Ok(())
}
