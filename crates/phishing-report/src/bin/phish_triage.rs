//! Triages one reported message and prints the record and observables as JSON: `phish_triage <file.eml> [authserv-id | internal:<domain> ...]`.

use phishing_report::limits::MAX_MESSAGE_BYTES;
use phishing_report::model::{ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::policy::reporter_policy;
use std::io::{Read, Write};
use std::process::ExitCode;


const INTERNAL_PREFIX: &str = "internal:";


#[cfg(unix)]
fn triage_one(raw: &[u8], trusted: &[String], reporters: &ReporterPolicy) -> Result<Triage, Box<dyn std::error::Error>> {
    let isolation = phishing_report::isolate::default_isolation()?;
    Ok(phishing_report::isolate::triage_isolated(
        raw,
        trusted,
        reporters,
        &phishing_report::limits::Limits::default(),
        &isolation,
    )?)
}


#[cfg(not(unix))]
fn triage_one(raw: &[u8], trusted: &[String], reporters: &ReporterPolicy) -> Result<Triage, Box<dyn std::error::Error>> {
    Ok(phishing_report::triage::triage(raw, trusted, reporters)?)
}


fn run_parent(all_args: Vec<String>) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut out = std::io::stdout();
    let mut args = all_args.into_iter();
    let path = args
        .next()
        .ok_or("usage: phish_triage <file.eml> [authserv-id | internal:<domain> ...]")?;
    let (internal, trusted): (Vec<String>, Vec<String>) = args.partition(|argument| argument.starts_with(INTERNAL_PREFIX));
    let domains: Vec<String> = internal
        .iter()
        .filter_map(|argument| argument.strip_prefix(INTERNAL_PREFIX))
        .map(str::to_owned)
        .collect();
    let reporters = reporter_policy(&domains)?;
    let mut raw = Vec::new();
    std::fs::File::open(path)?.take(MAX_MESSAGE_BYTES as u64 + 1).read_to_end(&mut raw)?;
    let record = triage_one(&raw, &trusted, &reporters)?;
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
