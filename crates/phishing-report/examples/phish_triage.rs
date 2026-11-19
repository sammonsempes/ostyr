//! Triages one reported message file and prints the record and its observables as JSON: `phish_triage <file.eml> [authserv-id ...]`.

use phishing_report::limits::MAX_MESSAGE_BYTES;
use phishing_report::observables::observables;
use phishing_report::triage::triage;
use std::io::{Read, Write};


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout();
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("usage: phish_triage <file.eml> [authserv-id ...]")?;
    let trusted: Vec<String> = args.collect();
    let mut raw = Vec::new();
    std::fs::File::open(path)?.take(MAX_MESSAGE_BYTES as u64 + 1).read_to_end(&mut raw)?;
    let record = triage(&raw, &trusted)?;
    let found = observables(&record);
    writeln!(out, "{}", serde_json::to_string_pretty(&record)?)?;
    writeln!(out, "{}", serde_json::to_string(&found)?)?;
    Ok(())
}
