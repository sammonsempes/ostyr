//! Triages one reported message and prints the record and observables as JSON: `phish_triage <file.eml> [authserv-id ...]`.

use phishing_report::limits::MAX_MESSAGE_BYTES;
use phishing_report::model::Triage;
use phishing_report::observables::observables;
use std::io::{Read, Write};
use std::process::ExitCode;


#[cfg(unix)]
fn triage_one(raw: &[u8], trusted: &[String]) -> Result<Triage, Box<dyn std::error::Error>> {
    let isolation = phishing_report::isolate::default_isolation()?;
    Ok(phishing_report::isolate::triage_isolated(
        raw,
        trusted,
        &phishing_report::limits::Limits::default(),
        &isolation,
    )?)
}


#[cfg(not(unix))]
fn triage_one(raw: &[u8], trusted: &[String]) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(phishing_report::triage::triage(raw, trusted)?)
}


fn run_parent(all_args: Vec<String>) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut out = std::io::stdout();
    let mut args = all_args.into_iter();
    let path = args.next().ok_or("usage: phish_triage <file.eml> [authserv-id ...]")?;
    let trusted: Vec<String> = args.collect();
    let mut raw = Vec::new();
    std::fs::File::open(path)?.take(MAX_MESSAGE_BYTES as u64 + 1).read_to_end(&mut raw)?;
    let record = triage_one(&raw, &trusted)?;
    let found = observables(&record);
    writeln!(out, "{}", serde_json::to_string_pretty(&record)?)?;
    writeln!(out, "{}", serde_json::to_string(&found)?)?;
    Ok(ExitCode::SUCCESS)
}


#[cfg(unix)]
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(phishing_report::isolate::CHILD_ARGUMENT) {
        Ok(ExitCode::from(phishing_report::isolate::parse_child_main(
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        )))
    } else {
        run_parent(args)
    }
}


#[cfg(not(unix))]
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    run_parent(std::env::args().skip(1).collect())
}
