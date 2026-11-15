//! Usage: `scan_filestore <rules_dir> <filestore_root> <eve.json>`, optional env `NDR_TIMEOUT_SECS`. One tick with the default bounds; prints the counts and the events.


use ndr::model::Limits;
use ndr::rules::load_rules;
use ndr::scan::scan_tick;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::time::Duration;
use time::OffsetDateTime;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let rules_dir = args.next().ok_or("usage: scan_filestore <rules_dir> <filestore_root> <eve.json>")?;
    let root = args.next().ok_or("missing filestore root")?;
    let eve = std::fs::read_to_string(args.next().ok_or("missing eve.json")?)?;
    let defaults = Limits::default();
    let scan_timeout = match std::env::var("NDR_TIMEOUT_SECS") {
        Ok(text) => Duration::from_secs(text.parse()?),
        Err(_) => defaults.scan_timeout,
    };
    let limits = Limits { scan_timeout, ..defaults };
    let rules = load_rules(&rules_dir, &limits)?;
    let outcome = scan_tick(&rules, &root, eve.lines(), &limits, OffsetDateTime::now_utc());
    let mut out = stdout();
    writeln!(out, "counts={:?}", outcome.counts)?;
    outcome.events.iter().try_for_each(|event| -> Result<(), Box<dyn Error + Send + Sync>> {
        writeln!(out, "{}", serde_json::to_string(event)?)?;
        Ok(())
    })?;
    Ok(())
}
