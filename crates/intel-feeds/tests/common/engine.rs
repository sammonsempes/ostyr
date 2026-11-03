use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_config::types::SharedAuditFn;
use intel_feeds::config::{open_feeds, FeedsFile, OpenError};
use std::fs;
use std::io;
use std::path::Path;


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "intel-feeds".to_owned(),
        tenant: "example".to_owned(),
        module: "intel-feeds".to_owned(),
        target: "feeds.yaml".to_owned(),
        request_id: "intel-feeds-reload".to_owned(),
    }
}


pub fn audit() -> Box<SharedAuditFn> {
    let log = genesis_log(io::sink());
    Box::new(move |entry| append(&log, entry))
}


pub fn feeds_text(extra: &str) -> String {
    format!("feeds:\n  - name: base\n    format: crowdsec\n    path: base.txt\n{extra}")
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub fn engine_for(path: &Path) -> Result<ReloadEngine<FeedsFile>, OpenError> {
    open_feeds(path.to_path_buf(), audit(), context())
}
