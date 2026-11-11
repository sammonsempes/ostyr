//! Usage: `cert_scan <root>...`, optional env `CERT_SCAN_DEPTH`. Scans the roots with the default bounds and prints the counts and the records.
use cert_inventory::scan::{scan, ScanSettings, DEFAULT_MAX_DEPTH};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::PathBuf;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let max_depth = match std::env::var("CERT_SCAN_DEPTH") {
        Ok(text) => text.parse()?,
        Err(_) => DEFAULT_MAX_DEPTH,
    };
    let settings = ScanSettings {
        max_depth,
        roots: std::env::args_os().skip(1).map(PathBuf::from).collect(),
        ..ScanSettings::default()
    };
    let outcome = scan(&settings);
    let mut out = stdout();
    writeln!(
        out,
        "records={} examined={} skipped={:?} malformed={:?} max_open_dirs={} private_keys_refused={} errors={} errors_omitted={}",
        outcome.records.len(),
        outcome.examined,
        outcome.skipped,
        outcome.malformed,
        outcome.max_open_dirs,
        outcome.private_keys_refused,
        outcome.errors.len(),
        outcome.errors_omitted
    )?;
    outcome.records.iter().try_for_each(|found| {
        writeln!(
            out,
            "{} {} paths={} omitted={}",
            found.record.fingerprint_sha256,
            found.record.subject,
            found.paths.len(),
            found.paths_omitted
        )
    })?;
    outcome.errors.iter().try_for_each(|error| writeln!(out, "error {error}"))?;
    Ok(())
}
