//! Usage: `ct_watch <watch.yaml> <log-url> <start> <count>`, optional env `CT_WATCH_CA` (PEM file). Prints the unexpected entries and the next start.
use cert_inventory::ct::{names_to_show, unexpected_for_domains, DEFAULT_LIMITS};
use cert_inventory::fetch::{get_range, get_sth, open_log, RangeRequest};
use cert_inventory::watch::load_watch_list;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::time::Duration;


const MAX_NAMES_SHOWN: usize = 8;


const ARGUMENTS: usize = 4;


const USAGE: &str = "usage: ct_watch <watch.yaml> <log-url> <start> <count>";


const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [watch_path, log_url, start_text, count_text] = <[String; ARGUMENTS]>::try_from(arguments).map_err(|_| USAGE)?;
    let watch = load_watch_list(&mut File::open(&watch_path)?, &watch_path)?;
    let ca = std::env::var("CT_WATCH_CA").ok().map(std::fs::read).transpose()?;
    let log = open_log(&log_url, ca.as_deref(), REQUEST_TIMEOUT)?;
    let sth = get_sth(&log)?;
    let start: u64 = start_text.parse()?;
    let count: u64 = count_text.parse()?;
    let end = start.saturating_add(count.saturating_sub(1));
    let fetched = get_range(
        &log,
        &RangeRequest {
            start,
            end,
            tree_size: sth.tree_size,
        },
        &DEFAULT_LIMITS,
    )?;
    let unexpected = unexpected_for_domains(&fetched.outcome.entries, &watch.zones, &[], &[]);
    let mut out = stdout();
    writeln!(
        out,
        "tree_size={} returned={} skipped_malformed={} skipped_unsupported={} unexpected={}",
        sth.tree_size,
        fetched.returned,
        fetched.outcome.skipped_malformed,
        fetched.outcome.skipped_unsupported,
        unexpected.len()
    )?;
    unexpected.iter().try_for_each(|entry| {
        let names = names_to_show(&entry.all_dns_names, &watch.zones, MAX_NAMES_SHOWN);
        writeln!(
            out,
            "{} precert={} names={:?} omitted={}",
            entry.record.fingerprint_sha256, entry.precert, names.shown, names.omitted
        )
    })?;
    writeln!(out, "next_start={}", fetched.next_start)?;
    Ok(())
}
