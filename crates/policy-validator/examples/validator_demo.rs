use core_audit::log::{append, open_file_log};
use core_audit::model::{Actor, ActorKind};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_config::watch::watch_files;
use policy_validator::audit::ValidationContext;
use policy_validator::cli::run;
use policy_validator::policy::LoadedPolicy;
use policy_validator::reload::open_validator;
use std::error::Error;
use std::io::{stdin, stdout, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;


const DEBOUNCE: Duration = Duration::from_millis(300);


const MAX_INPUT_BYTES: u64 = 1_048_576;


#[cfg(unix)]
fn keep_signals(engine: Arc<ReloadEngine<LoadedPolicy>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals(_engine: Arc<ReloadEngine<LoadedPolicy>>) -> std::io::Result<impl Sized> {
    Ok(())
}


fn start(policy_file: &str, audit_file: &str) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(audit_file))?;
    let reload_context = ReloadContext {
        actor_id: "validator-demo".to_owned(),
        tenant: "example".to_owned(),
        module: "policy-validator".to_owned(),
        target: policy_file.to_owned(),
        request_id: "validator-demo-reload".to_owned(),
    };
    let engine = Arc::new(open_validator(
        PathBuf::from(policy_file),
        Box::new(move |entry| append(&log, entry)),
        reload_context,
    )?);
    let _watcher = watch_files(Arc::clone(&engine), &[PathBuf::from(policy_file)], DEBOUNCE)?;
    let _signals = keep_signals(Arc::clone(&engine))?;
    let context = ValidationContext {
        actor: Actor {
            kind: ActorKind::User,
            id: "validator-demo".to_owned(),
        },
        tenant: "example".to_owned(),
        request_id: "demo".to_owned(),
    };
    let mut input = BufReader::new(stdin().take(MAX_INPUT_BYTES));
    run(&engine, &context, &mut input, &mut stdout())?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [policy_file, audit_file] => start(policy_file, audit_file),
        _ => Err("usage: validator_demo <policy.yaml> <audit-file>".into()),
    }
}
