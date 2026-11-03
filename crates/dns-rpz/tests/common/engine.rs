use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_config::types::SharedAuditFn;
use dns_rpz::policy::{open_policy, OpenError, Policy};
use std::fs;
use std::io;
use std::path::Path;


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "dns-rpz".to_owned(),
        tenant: "example".to_owned(),
        module: "dns-rpz".to_owned(),
        target: "policy.yaml".to_owned(),
        request_id: "dns-rpz-reload".to_owned(),
    }
}


pub fn audit() -> Box<SharedAuditFn> {
    let log = genesis_log(io::sink());
    Box::new(move |entry| append(&log, entry))
}


pub fn policy_text(extra: &str) -> String {
    format!("zone: rpz.example.org\nsoa:\n  mname: ns1.example.org\n  rname: hostmaster.example.org\nns: [ns1.example.org]\n{extra}")
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub fn engine_for(path: &Path) -> Result<ReloadEngine<Policy>, OpenError> {
    open_policy(path.to_path_buf(), audit(), context())
}
