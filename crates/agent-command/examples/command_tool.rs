use agent_command::cli::{verify_session, write_keypair, write_signed};
use agent_command::keys::open_keys_engine;
use agent_command::sign::os_random;
use agent_command::verify::open_verifier;
use core_audit::log::{append, open_file_log};
use core_config::reload::ReloadContext;
use core_config::watch::watch_files;
use std::error::Error;
use std::io::{stdin, stdout};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


const DEBOUNCE: Duration = Duration::from_millis(300);


const USAGE: &str = "usage: command_tool keygen | sign <seed-hex> <key-id> <agent> <tenant> <sequence> <action> [parameter] | \
                     verify <keys-file> <state-file> <audit-file> <agent> <tenant>";


fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}


fn verify(keys_file: &str, state_file: &str, audit_file: &str, agent_id: &str, tenant: &str) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(audit_file))?;
    let context = ReloadContext {
        actor_id: "command_tool".to_owned(),
        tenant: tenant.to_owned(),
        module: "agent-command".to_owned(),
        target: keys_file.to_owned(),
        request_id: "keys-reload".to_owned(),
    };
    let engine = Arc::new(open_keys_engine(
        PathBuf::from(keys_file),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?);
    let _watcher = watch_files(Arc::clone(&engine), &[PathBuf::from(keys_file)], DEBOUNCE)?;
    let verifier = open_verifier(agent_id, tenant, engine, Path::new(state_file))?;
    verify_session(&verifier, stdin().lock(), &mut stdout(), now_seconds)?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["keygen"] => Ok(write_keypair(os_random, &mut stdout())?),
        ["sign", rest @ ..] => Ok(write_signed(rest, now_seconds(), os_random, &mut stdout())?),
        ["verify", keys_file, state_file, audit_file, agent_id, tenant] => verify(keys_file, state_file, audit_file, agent_id, tenant),
        _ => Err(USAGE.into()),
    }
}
