//! Usage: ntp_health <tracking.csv> <timedatectl.txt> <thresholds.yaml>; prints the verdict and the measures.

use app_health::assess::assess;
use app_health::limits::DEFAULT_MAX_BYTES;
use app_health::measures::measures;
use app_health::parse::{parse_chrony_tracking, parse_timedatectl};
use app_health::thresholds::load_thresholds;
use std::io::Write;


fn report(tracking_path: &str, sync_path: &str, thresholds_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tracking = parse_chrony_tracking(std::fs::File::open(tracking_path)?, DEFAULT_MAX_BYTES)?;
    let time_sync = parse_timedatectl(std::fs::File::open(sync_path)?, DEFAULT_MAX_BYTES)?;
    let thresholds = load_thresholds(&std::fs::read_to_string(thresholds_path)?, thresholds_path)?;
    let mut out = std::io::stdout();
    writeln!(out, "verdict={:?}", assess(&tracking, Some(&time_sync), &thresholds))?;
    writeln!(out, "rejected_fields={} time_sync={:?}", tracking.rejected_fields, time_sync)?;
    measures(&tracking)
        .iter()
        .try_for_each(|item| writeln!(out, "{} {} {}", item.name, item.value, item.unit))?;
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [tracking_path, sync_path, thresholds_path] => report(tracking_path, sync_path, thresholds_path),
        _ => Err("usage: ntp_health <tracking.csv> <timedatectl.txt> <thresholds.yaml>".into()),
    }
}
