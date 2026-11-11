//! Usage: `cert_scan <root>...`. Scans the roots with the default bounds and prints the counts and the records.
use cert_inventory::scan::{scan, ScanSettings};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::PathBuf;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let settings = ScanSettings {
        roots: std::env::args_os().skip(1).map(PathBuf::from).collect(),
        ..ScanSettings::default()
    };
    let outcome = scan(&settings);
    let mut out = stdout();
    writeln!(
        out,
        "records={} examined={} skipped={:?} private_keys_refused={} errors={} errors_omitted={}",
        outcome.records.len(),
        outcome.examined,
        outcome.skipped,
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
