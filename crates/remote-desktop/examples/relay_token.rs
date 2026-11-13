use core_audit::log::{append, genesis_log};
use core_config::reload::ReloadContext;
use core_config::watch::watch_files;
use remote_desktop::cli::{verify_session, write_issued, write_keypair};
use remote_desktop::keys::open_keys_engine;
use remote_desktop::model::DEFAULT_LIVE_TOKENS;
use remote_desktop::sign::os_random;
use remote_desktop::token::open_verifier;
use std::error::Error;
use std::io::{sink, stderr, stdin, stdout};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


const DEBOUNCE: Duration = Duration::from_millis(300);


const USAGE: &str = "usage: relay_token keygen | issue <seed-hex> <claims-json> | verify <keys-file> <peer> <tenant> [<agent-command-keys-file>]";


fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}


fn verify(keys_file: &str, peer: &str, tenant: &str, agent_keys: Option<&str>) -> Result<(), Box<dyn Error>> {
    let log = genesis_log(sink());
    let context = ReloadContext {
        actor_id: "relay_token".to_owned(),
        tenant: tenant.to_owned(),
        module: "remote-desktop".to_owned(),
        target: keys_file.to_owned(),
        request_id: "keys-reload".to_owned(),
    };
    let engine = Arc::new(open_keys_engine(
        PathBuf::from(keys_file),
        agent_keys.map(PathBuf::from),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?);
    let files: Vec<PathBuf> = [Some(keys_file), agent_keys].into_iter().flatten().map(PathBuf::from).collect();
    let _watcher = watch_files(Arc::clone(&engine), &files, DEBOUNCE)?;
    let verifier = open_verifier(engine, DEFAULT_LIVE_TOKENS)?;
    verify_session(&verifier, stdin().lock(), &mut stdout(), now_seconds, peer, tenant)?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    tracing::dispatcher::set_global_default(tracing_subscriber::fmt().with_ansi(false).with_writer(stderr).finish().into())?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["keygen"] => Ok(write_keypair(os_random, &mut stdout())?),
        ["issue", rest @ ..] => Ok(write_issued(rest, now_seconds(), os_random, &mut stdout())?),
        ["verify", keys_file, peer, tenant] => verify(keys_file, peer, tenant, None),
        ["verify", keys_file, peer, tenant, agent_keys] => verify(keys_file, peer, tenant, Some(agent_keys)),
        _ => Err(USAGE.into()),
    }
}
