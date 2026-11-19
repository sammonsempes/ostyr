//! Triages one reported message file and prints the record and its observables as JSON: `phish_triage <file.eml>`.

use phishing_report::observables::observables;
use phishing_report::triage::triage;
use std::io::Write;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout();
    let path = std::env::args().nth(1).ok_or("usage: phish_triage <file.eml>")?;
    let record = triage(&std::fs::read(path)?)?;
    let found = observables(&record);
    writeln!(out, "{}", serde_json::to_string_pretty(&record)?)?;
    writeln!(out, "{}", serde_json::to_string(&found)?)?;
    Ok(())
}
