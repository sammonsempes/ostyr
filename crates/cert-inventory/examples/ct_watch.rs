//! Usage: `ct_watch <watch.yaml> <log-url> <start> <count> [--store <pg.yaml> <tenant>]`; env `CT_WATCH_CA`, `CT_WATCH_DEADLINE_SECS`.
use alerts::pg::pg_executor;
use cert_inventory::ct::DEFAULT_LIMITS as CT_LIMITS;
use cert_inventory::ct::{names_to_show, unexpected_for_domains};
use cert_inventory::fetch::{get_range, get_sth, open_log, RangeRequest};
use cert_inventory::model::{CertRecord, Source, SourceKind, StoreCounts};
use cert_inventory::store::{store_records, DEFAULT_LIMITS, MIGRATIONS, MIGRATION_NAMESPACE};
use cert_inventory::watch::load_watch_list;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};


const MAX_NAMES_SHOWN: usize = 8;


const STORE_FLAG: &str = "--store";


const USAGE: &str = "usage: ct_watch <watch.yaml> <log-url> <start> <count> [--store <pg.yaml> <tenant>]";


const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);


const DEFAULT_DEADLINE_SECS: u64 = 60;


async fn store_entries(
    settings_file: &str,
    tenant: &str,
    log_url: &str,
    records: &[CertRecord],
) -> Result<StoreCounts, Box<dyn Error + Send + Sync>> {
    let deadline = Duration::from_secs(
        std::env::var("CT_WATCH_DEADLINE_SECS")
            .ok()
            .map_or(Ok(DEFAULT_DEADLINE_SECS), |text| text.parse())?,
    );
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, settings_file)?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, deadline).await?;
    let scope = tenant_scope(tenant)?;
    let exec = pg_executor(&client, deadline);
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let host = log_url
        .split_once("//")
        .map_or(log_url, |(_scheme, rest)| rest)
        .split('/')
        .next()
        .ok_or("the log URL has no host")?;
    let source = Source {
        kind: SourceKind::Ct,
        reference: host.to_owned(),
    };
    Ok(store_records(&exec, &scope, &source, records, now, &DEFAULT_LIMITS).await?)
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (watch_path, log_url, start_text, count_text, store) = match arguments.as_slice() {
        [watch, log, start, count] => Ok((watch, log, start, count, None)),
        [watch, log, start, count, flag, settings, tenant] if flag == STORE_FLAG => Ok((watch, log, start, count, Some((settings, tenant)))),
        _ => Err(USAGE),
    }?;
    let watch = load_watch_list(&mut File::open(watch_path)?, watch_path)?;
    let ca = std::env::var("CT_WATCH_CA").ok().map(std::fs::read).transpose()?;
    let log = open_log(log_url, ca.as_deref(), REQUEST_TIMEOUT)?;
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
        &CT_LIMITS,
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
    if let Some((settings_file, tenant)) = store {
        let records: Vec<CertRecord> = unexpected.iter().map(|entry| entry.record.clone()).collect();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let counts = runtime.block_on(store_entries(settings_file, tenant, log_url, &records))?;
        writeln!(
            out,
            "stored inserted={} seen_again={} refused_full={} refused_source={} refused_record={} duplicate_in_batch={}",
            counts.inserted, counts.seen_again, counts.refused_full, counts.refused_source, counts.refused_record, counts.duplicate_in_batch
        )?;
    }
    Ok(())
}
