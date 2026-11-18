//! Usage: `cert_scan [--store <pg.yaml> <tenant>] <root>...`; env `CERT_SCAN_DEPTH`, `_HOST`, `_DEADLINE_SECS`, `_MAX_CERTS`, `_LIST_BEFORE`.
use alerts::pg::pg_executor;
use alerts::types::Executor;
use cert_inventory::model::{CertFilter, StoreLimits};
use cert_inventory::model::{CertRecord, ScanOutcome, Source, SourceKind, StoreCounts};
use cert_inventory::scan::{scan, ScanSettings, DEFAULT_MAX_DEPTH};
use cert_inventory::store::{list_certificates, store_records, DEFAULT_LIMITS, MAX_PAGE, MIGRATIONS, MIGRATION_NAMESPACE, SOURCE_EXTRA_BYTES};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


const STORE_FLAG: &str = "--store";


const DEFAULT_DEADLINE_SECS: u64 = 60;


const MAX_LIST_PAGES: usize = 1_000;


fn encoded(path: &str) -> String {
    path.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || SOURCE_EXTRA_BYTES.contains(&byte) && byte != b'%' {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}


async fn count_listed(exec: Executor<'_, '_>, scope: &TenantScope, before: i64) -> Result<usize, Box<dyn Error + Send + Sync>> {
    let filter = CertFilter {
        expiring_before: Some(before),
    };
    let mut cursor: Option<String> = None;
    let mut listed = 0;
    let mut pages = 0;
    while pages < MAX_LIST_PAGES && (pages == 0 || cursor.is_some()) {
        let page = list_certificates(exec, scope, &filter, cursor.as_deref(), MAX_PAGE).await?;
        listed += page.certs.len();
        cursor = page.next_cursor;
        pages += 1;
    }
    Ok(listed)
}


async fn store_outcome(
    settings_file: &str,
    tenant: &str,
    outcome: &ScanOutcome,
) -> Result<(StoreCounts, Option<usize>), Box<dyn Error + Send + Sync>> {
    let deadline = Duration::from_secs(
        std::env::var("CERT_SCAN_DEADLINE_SECS")
            .ok()
            .map_or(Ok(DEFAULT_DEADLINE_SECS), |text| text.parse())?,
    );
    let host = std::env::var("CERT_SCAN_HOST").unwrap_or_else(|_unset| "localhost".to_owned());
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, settings_file)?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, deadline).await?;
    let scope = tenant_scope(tenant)?;
    let exec = pg_executor(&client, deadline);
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let mut by_path: BTreeMap<&str, Vec<CertRecord>> = BTreeMap::new();
    outcome
        .records
        .iter()
        .flat_map(|found| found.paths.iter().map(move |path| (path.as_str(), found.record.clone())))
        .for_each(|(path, record)| by_path.entry(path).or_default().push(record));
    let limits = StoreLimits {
        max_certs: std::env::var("CERT_SCAN_MAX_CERTS")
            .ok()
            .map_or(Ok(DEFAULT_LIMITS.max_certs), |text| text.parse())?,
        ..DEFAULT_LIMITS
    };
    let mut total = StoreCounts::default();
    for (path, records) in &by_path {
        let source = Source {
            kind: SourceKind::Scan,
            reference: format!("{host}:{}", encoded(path)),
        };
        let counts = store_records(&exec, &scope, &source, records, now, &limits).await?;
        total.inserted += counts.inserted;
        total.seen_again += counts.seen_again;
        total.refused_full += counts.refused_full;
        total.refused_source += counts.refused_source;
        total.refused_record += counts.refused_record;
    }
    let listed = match std::env::var("CERT_SCAN_LIST_BEFORE") {
        Ok(text) => Some(count_listed(&exec, &scope, text.parse()?).await?),
        Err(_unset) => None,
    };
    Ok((total, listed))
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let max_depth = match std::env::var("CERT_SCAN_DEPTH") {
        Ok(text) => text.parse()?,
        Err(_) => DEFAULT_MAX_DEPTH,
    };
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (store, roots): (Option<(&String, &String)>, &[String]) = match arguments.as_slice() {
        [flag, settings, tenant, rest @ ..] if flag == STORE_FLAG => (Some((settings, tenant)), rest),
        all => (None, all),
    };
    let settings = ScanSettings {
        max_depth,
        roots: roots.iter().map(PathBuf::from).collect(),
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
    if let Some((settings_file, tenant)) = store {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (counts, listed) = runtime.block_on(store_outcome(settings_file, tenant, &outcome))?;
        writeln!(
            out,
            "stored inserted={} seen_again={} refused_full={} refused_source={} refused_record={}",
            counts.inserted, counts.seen_again, counts.refused_full, counts.refused_source, counts.refused_record
        )?;
        if let Some(count) = listed {
            writeln!(out, "listed={count}")?;
        }
    }
    Ok(())
}
