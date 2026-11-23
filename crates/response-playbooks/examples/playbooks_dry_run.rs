use response_playbooks::batch::{dry_run_batch, read_alerts, DryRunLimits};
use response_playbooks::bundle::{load_bundle, validate_bundle};
use response_playbooks::render::render_dry_run;
use std::env::temp_dir;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, BufReader, Write};
use std::path::PathBuf;


const USAGE: &str = "usage: playbooks_dry_run [tenant=<t>] [max_alerts=<n>] [max_matches=<n>] [max_trace_events=<n>] <limits> <catalogue> <inventory> <alerts.jsonl> <playbook>...";


const DEFAULT_TENANT: &str = "acme";


const DEFAULT_LIMITS: DryRunLimits = DryRunLimits {
    max_alerts: 1_000,
    max_matches_per_alert: 8,
    max_trace_events: 10_000,
};


const MAX_UNREAD_SCAN: usize = 1_000_000;


fn option_of<'a>(options: &[&'a str], name: &str) -> Option<&'a str> {
    options
        .iter()
        .find_map(|option| option.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')))
}


fn bound(options: &[&str], name: &str, default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(option_of(options, name).map(str::parse).transpose()?.unwrap_or(default))
}


fn run(options: &[&str], limits_file: &str, catalogue: &str, inventory: &str, alerts_file: &str, playbooks: &[String]) -> Result<(), Box<dyn Error>> {
    let limits = DryRunLimits {
        max_alerts: bound(options, "max_alerts", DEFAULT_LIMITS.max_alerts)?,
        max_matches_per_alert: bound(options, "max_matches", DEFAULT_LIMITS.max_matches_per_alert)?,
        max_trace_events: bound(options, "max_trace_events", DEFAULT_LIMITS.max_trace_events)?,
    };
    let playbook_paths: Vec<PathBuf> = playbooks.iter().map(PathBuf::from).collect();
    let bundle = load_bundle(&PathBuf::from(catalogue), &PathBuf::from(inventory), &playbook_paths)?;
    validate_bundle(&bundle)?;
    let file = read_alerts(&mut BufReader::new(File::open(alerts_file)?), limits.max_alerts, MAX_UNREAD_SCAN)?;
    let report = dry_run_batch(
        &bundle,
        &PathBuf::from(limits_file),
        &temp_dir(),
        option_of(options, "tenant").unwrap_or(DEFAULT_TENANT),
        &file.alerts,
        limits,
    )?;
    let mut out = stdout();
    write!(out, "{}", render_dry_run(&report))?;
    notice(&mut out, file.too_long, "line(s) over the line bound were discarded, unparsed")?;
    notice(&mut out, file.refused, "line(s) refused by the shape bounds before parsing")?;
    notice(&mut out, file.unreadable, "line(s) were not JSON and are skipped")?;
    notice(&mut out, file.unread, "line(s) were not read (alert bound)")?;
    if file.unread_more {
        writeln!(out, "input not read further: more than {MAX_UNREAD_SCAN} unread lines")?;
    }
    Ok(())
}


fn notice(out: &mut impl Write, count: usize, text: &str) -> Result<(), Box<dyn Error>> {
    if count > 0 {
        writeln!(out, "{count} {text}")?;
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (named, plain): (Vec<&String>, Vec<&String>) = args.iter().partition(|arg| arg.contains('=') && !arg.contains('/'));
    let options: Vec<&str> = named.into_iter().map(String::as_str).collect();
    match plain.as_slice() {
        [limits_file, catalogue, inventory, alerts_file, playbooks @ ..] if !playbooks.is_empty() => {
            let names: Vec<String> = playbooks.iter().map(|name| (*name).clone()).collect();
            run(&options, limits_file, catalogue, inventory, alerts_file, &names)
        }
        _ => Err(USAGE.into()),
    }
}
