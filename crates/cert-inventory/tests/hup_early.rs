#![cfg(target_os = "linux")]


use cert_inventory::serve::start;
use cert_inventory::types::InterruptWait;
use std::fs;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;
use tempfile::tempdir;


const SIGHUP_BIT: u64 = 1;


const HEX_RADIX: u32 = 16;


const SIGCGT_PREFIX: &str = "SigCgt:";


fn hangup_is_caught() -> Result<bool, Box<dyn std::error::Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with(SIGCGT_PREFIX)).ok_or("no SigCgt line")?;
    let mask = u64::from_str_radix(line.trim_start_matches(SIGCGT_PREFIX).trim(), HEX_RADIX)?;
    Ok(mask & SIGHUP_BIT == SIGHUP_BIT)
}


fn probe_interrupt() -> io::Result<InterruptWait> {
    let caught = hangup_is_caught().map_err(|failure| io::Error::other(failure.to_string()))?;
    Err(io::Error::other(format!("hangup caught: {caught}")))
}


fn never_waits(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(std::future::pending())
}


#[tokio::test]
async fn sighup_is_registered_before_the_settings_are_read() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!hangup_is_caught()?);
    let dir = tempdir()?;
    let absent = dir.path().join("absent.yaml");
    let ended = start(Path::new(&absent), 1, probe_interrupt, never_waits).await;
    let refusal = ended.err().ok_or("the probe must end the start")?;
    assert_eq!(refusal.to_string(), "hangup caught: true");
    Ok(())
}
