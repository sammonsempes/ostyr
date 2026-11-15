//! Usage: `scan_filestore <yr> <work_dir> <rules_dir> <filestore_root> <eve.json>`, optional env `NDR_TIMEOUT_SECS`. One tick; prints the counts and the events.


#[cfg(unix)]
use ndr::model::{Limits, Yr};
#[cfg(unix)]
use ndr::rules::load_rules;
#[cfg(unix)]
use ndr::scan::scan_tick;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use time::OffsetDateTime;


#[cfg(unix)]
fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let usage = "usage: scan_filestore <yr> <work_dir> <rules_dir> <filestore_root> <eve.json>";
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let program = args.next().ok_or(usage)?;
    let work_dir = args.next().ok_or(usage)?;
    let rules_dir = args.next().ok_or(usage)?;
    let root = args.next().ok_or(usage)?;
    let eve = std::fs::read_to_string(args.next().ok_or(usage)?)?;
    let defaults = Limits::default();
    let scan_timeout = match std::env::var("NDR_TIMEOUT_SECS") {
        Ok(text) => Duration::from_secs(text.parse()?),
        Err(_) => defaults.scan_timeout,
    };
    let limits = Limits { scan_timeout, ..defaults };
    let yr = Yr { program, work_dir };
    let rules = load_rules(&yr, &rules_dir, &limits)?;
    let outcome = scan_tick(&yr, &rules, &root, eve.lines(), &limits, OffsetDateTime::now_utc());
    let mut out = stdout();
    writeln!(out, "counts={:?}", outcome.counts)?;
    outcome.events.iter().try_for_each(|event| -> Result<(), Box<dyn Error + Send + Sync>> {
        writeln!(out, "{}", serde_json::to_string(event)?)?;
        Ok(())
    })?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
