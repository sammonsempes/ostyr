#![cfg(unix)]
use agent_channel::types::PauseFn;
use agent_linux::app::run_linux;
use agent_linux::error::SensorError;
use agent_linux::types::RunFuture;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;


const WAIT_ATTEMPTS: u32 = 100_000;


fn no_systemctl(_program: PathBuf, _arguments: Vec<String>) -> RunFuture {
    Box::pin(async { Err(SensorError::Exit(None)) })
}


fn write_files(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = dir.display();
    fs::write(
        dir.join("agent.yaml"),
        format!(
            "server: 127.0.0.1:1\nserver_name: server\ncertificate: {root}/absent.pem\nkey: {root}/absent.key\nplatform_ca: {root}/absent-ca.pem\ntenant: t1\nagent_id: a1\nkeys_file: {root}/keys\nstate_file: {root}/state\naudit_file: {root}/agent-audit\nspool_file: {root}/spool\nsequence_file: {root}/sequence\nexecuted_file: {root}/executed\n"
        ),
    )?;
    fs::write(dir.join("process-cred"), "true")?;
    let config = dir.join("linux.yaml");
    fs::write(
        &config,
        format!(
            "agent_file: {root}/agent.yaml\nexport_path: {root}/export.json\ncursor_file: {root}/cursor\naudit_file: {root}/linux-audit\ncredentials_path: {root}/process-cred\n"
        ),
    )?;
    Ok(config)
}


async fn wait_for_text(path: PathBuf, needle: &str) -> bool {
    let mut found = false;
    let mut attempts = 0;
    while !found && attempts < WAIT_ATTEMPTS {
        found = fs::read_to_string(&path).is_ok_and(|text| text.contains(needle));
        tokio::task::yield_now().await;
        attempts += 1;
    }
    found
}


#[tokio::test]
async fn a_real_sigterm_ends_the_production_agent_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let yielding: &PauseFn = &|_| Box::pin(tokio::task::yield_now());
    let spool = dir.path().join("spool");
    let sender = async {
        assert!(wait_for_text(spool, "agent.capabilities").await);
        assert!(Command::new("kill").args(["-TERM", &std::process::id().to_string()]).status()?.success());
        Ok::<(), std::io::Error>(())
    };
    let (ended, sent) = tokio::join!(run_linux(&config, u64::MAX, yielding, no_systemctl), sender);
    sent?;
    assert_eq!(ended?.agent_runs, 0);
    Ok(())
}
