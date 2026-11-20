//! Live proof: `vuln_store <pg.yaml> migrate | scan | bulk | pages`, see `USAGE`.

use alerts::pg::pg_executor;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use vuln_match::limits::MAX_RESOLVED_FINDINGS_PER_ASSET;
use vuln_match::model::{AssetFinding, Criticality, Finding, ScanCaps, ScoredFinding};
use vuln_match::store::{open_findings, record_scan_capped, MIGRATIONS, MIGRATION_NAMESPACE};


const USAGE: &str = "usage: vuln_store <pg.yaml> migrate | scan <tenant> <asset> <now_micros> <cap> <resolved_cap> <package/record>... \
                     | bulk <tenant> <asset> <now_micros> <cap> <resolved_cap> <count> <prefix> | pages <tenant> <limit>";


const DEADLINE: Duration = Duration::from_secs(120);


const ASSET_CAP_VARIABLE: &str = "VULN_ASSET_RESOLVED_CAP";


const MAX_PAGES: usize = 100_000;


const BULK_CVSS: f64 = 7.5;


const BULK_EPSS: f64 = 0.5;


const BULK_SPREAD: usize = 97;


fn finding_of(asset: &str, package: &str, record: &str, spread: usize) -> AssetFinding {
    AssetFinding {
        asset: asset.to_owned(),
        scored: ScoredFinding {
            finding: Finding {
                package: package.to_owned(),
                installed_version: "1.0-1".to_owned(),
                ecosystem: "Debian:12".to_owned(),
                record_id: record.to_owned(),
                cve_aliases: vec!["CVE-2024-1234".to_owned()],
                fixed_version: Some("1.2".to_owned()),
            },
            cvss: BULK_CVSS - (spread % BULK_SPREAD) as f64 / BULK_SPREAD as f64,
            epss: BULK_EPSS,
            kev: false,
            criticality: Criticality::High,
        },
    }
}


fn spec_finding(asset: &str, spec: &str) -> Result<AssetFinding, Box<dyn Error>> {
    let (package, record) = spec.split_once('/').ok_or("spec is package/record")?;
    Ok(finding_of(asset, package, record, 0))
}


fn asset_cap() -> Result<u64, Box<dyn Error>> {
    Ok(std::env::var(ASSET_CAP_VARIABLE).map_or(Ok(MAX_RESOLVED_FINDINGS_PER_ASSET), |text| text.parse())?)
}


async fn scenario(settings_file: &Path, words: &[String]) -> Result<(), Box<dyn Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    let exec = pg_executor(&client, DEADLINE);
    match words {
        [word] if word == "migrate" => migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await.map(|_applied| ())?,
        [word, tenant, asset, now, cap, resolved_cap, specs @ ..] if word == "scan" => {
            let findings = specs.iter().map(|spec| spec_finding(asset, spec)).collect::<Result<Vec<_>, _>>()?;
            let outcome = record_scan_capped(
                &exec,
                &tenant_scope(tenant)?,
                asset,
                &findings,
                now.parse()?,
                &ScanCaps {
                    max_open: cap.parse()?,
                    max_resolved: resolved_cap.parse()?,
                    max_asset_resolved: asset_cap()?,
                },
            )
            .await?;
            writeln!(stdout(), "{outcome:?}")?;
        }
        [word, tenant, asset, now, cap, resolved_cap, count, prefix] if word == "bulk" => {
            let findings: Vec<AssetFinding> = (0..count.parse::<usize>()?)
                .map(|index| finding_of(asset, &format!("{prefix}{index}"), "R1", index))
                .collect();
            let outcome = record_scan_capped(
                &exec,
                &tenant_scope(tenant)?,
                asset,
                &findings,
                now.parse()?,
                &ScanCaps {
                    max_open: cap.parse()?,
                    max_resolved: resolved_cap.parse()?,
                    max_asset_resolved: asset_cap()?,
                },
            )
            .await?;
            writeln!(stdout(), "{outcome:?}")?;
        }
        [word, tenant, limit] if word == "pages" => {
            let scope = tenant_scope(tenant)?;
            let mut cursor: Option<String> = None;
            let mut pages = 0;
            let mut rows = 0;
            let mut done = false;
            while !done && pages < MAX_PAGES {
                let page = open_findings(&exec, &scope, cursor.as_deref(), limit.parse()?).await?;
                rows += page.findings.len();
                pages += 1;
                done = page.next.is_none();
                cursor = page.next;
            }
            writeln!(stdout(), "pages={pages} rows={rows}")?;
        }
        _ => Err(Box::<dyn Error>::from(USAGE))?,
    }
    Ok(())
}


fn main() -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((settings, words)) => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), words)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => Ok(writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE)?),
            }
        }
        None => Ok(writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE)?),
    }
}
