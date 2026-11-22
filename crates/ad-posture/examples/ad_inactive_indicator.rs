//! Usage: `ad_inactive_indicator <snapshot.json> <tenant> [now-unix-seconds]`; prints the GRC indicator file (a JSON array) on stdout.
use ad_posture::indicator::{checked_now, indicator_json, indicator_of, warning_line};
use ad_posture::limits::Limits;
use ad_posture::snapshot::read_captured;
use std::error::Error;
use std::fs::File;
use std::io::{stderr, stdout, Write};
use std::time::{SystemTime, UNIX_EPOCH};


const SNAPSHOT_ARGUMENT: usize = 1;


const TENANT_ARGUMENT: usize = 2;


const NOW_ARGUMENT: usize = 3;


fn now_of(arguments: &[String]) -> Result<i64, Box<dyn Error + Send + Sync>> {
    let system = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    match arguments.get(NOW_ARGUMENT) {
        Some(text) => Ok(checked_now(text.parse()?, system)?),
        None => Ok(system),
    }
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<String> = std::env::args().collect();
    let read = read_captured(
        File::open(arguments.get(SNAPSHOT_ARGUMENT).ok_or("missing snapshot.json")?)?,
        &Limits::default(),
    )?;
    let tenant = arguments.get(TENANT_ARGUMENT).ok_or("missing tenant")?;
    let outcome = indicator_of(&read.snapshot, read.captured.as_deref(), now_of(&arguments)?, tenant)?;
    writeln!(stdout(), "{}", indicator_json(&outcome))?;
    warning_line(&outcome).map_or(Ok(()), |line| writeln!(stderr(), "{line}"))?;
    Ok(())
}
