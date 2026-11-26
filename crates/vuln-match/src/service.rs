//! The `ostyr-vuln` rounds: settings, the reload engine, the feed refresh and one scan round over the inventory directory.

use crate::alerting::{kev_alerts, store_kev_alerts};
use crate::epss::{parse_epss, EpssLimits, EpssScores};
use crate::error::{EpssError, FeedError, KevError, StoreError};
use crate::feed::{default_limits, load_feed_reader};
use crate::inventory::{list_inventory, read_inventory};
use crate::kev::{parse_kev, KevCatalogue, KevLimits};
use crate::limits::{
    MAX_ALIASES_PER_FINDING, MAX_FINDINGS_PER_SCAN, MAX_OPEN_FINDINGS_PER_TENANT, MAX_RESOLVED_FINDINGS_PER_ASSET, MAX_RESOLVED_FINDINGS_PER_TENANT,
};
use crate::matcher::match_inventory;
use crate::model::{AssetFinding, Criticality, FeedSettings, OsvRecord, Package, ScanCaps, ScanOutcome, ScoredFinding};
use crate::scoring::{cap_aliases, score_findings};
use crate::store::{finding_doc, open_findings_of_asset, rebuild_counters, record_scan_capped};
use crate::types::FindingKey;
use alerts::types::Executor;
use core_audit::tenant::AUDIT_TENANT;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::parse::open_regular;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::scope::{tenant_scope, TenantScope};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::sync::watch::Receiver;
use tracing::{info, warn};


pub const MIN_ROUND_SECONDS: u64 = 10;


pub const MAX_ROUND_SECONDS: u64 = 86_400;


pub const MAX_ROUNDS: u64 = 10_000_000;


pub const MODULE: &str = "vuln";


pub const SETTINGS_REQUEST: &str = "settings";


/// The feeds carry no CVSS and no CMDB criticality yet, so findings are scored on EPSS and KEV alone.
pub const UNSCORED_CVSS: f64 = 0.0;


pub const UNSCORED_EPSS: f64 = 0.0;


/// Start-only: `tenant`, `pg_settings` and `audit_file`. Live: everything else.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub tenant: String,
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
    pub inventory_dir: PathBuf,
    pub osv_archive: PathBuf,
    pub kev_file: PathBuf,
    pub epss_file: PathBuf,
    pub feed: FeedSettings,
    pub round_seconds: u64,
}


/// The last good copy of each feed; a missing one stops the matching, so an absent feed never reads as "no findings".
#[derive(Debug, Default)]
pub struct Loaded {
    pub records: Option<Vec<OsvRecord>>,
    pub kev: Option<KevCatalogue>,
    pub epss: Option<EpssScores>,
}


/// Counts of one round: `stopped` when an interrupt left assets unreached, `left_out` the valid inventory files the file cap left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundReport {
    pub scanned: usize,
    pub refused_files: usize,
    pub failed_assets: usize,
    pub findings: u64,
    pub alerts: usize,
    pub alerts_failed: usize,
    pub refused_findings: u64,
    pub no_room: u64,
    pub skipped: bool,
    pub left_out: usize,
    pub first_left_out: Option<String>,
    pub stopped: bool,
}


/// What one asset's scan stored: findings written, alerts newly stored, findings the store refused, and whether the alert write failed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AssetScan {
    pub stored: u64,
    pub alerts: usize,
    pub alerts_failed: bool,
    pub refused: u64,
    pub no_room: u64,
}


#[derive(Debug, Error)]
pub enum LoadError {
    #[error("the feed file cannot be opened: {0}")]
    Open(#[source] ConfigError),
    #[error("the OSV archive is refused: {0}")]
    Osv(#[from] FeedError),
    #[error("the KEV catalogue is refused: {0}")]
    Kev(#[from] KevError),
    #[error("the EPSS file is refused: {0}")]
    Epss(#[from] EpssError),
    #[error("the {feed} feed holds no usable entry, an empty feed is never used as no findings")]
    Empty { feed: &'static str },
}


pub fn setting_error(field: &str, reason: &str) -> ConfigError {
    ConfigError::WatchedFile {
        file: format!("settings.{field}"),
        reason: reason.to_owned(),
    }
}


pub fn validate_settings(settings: &ServiceSettings) -> Result<(), ConfigError> {
    let paths = [
        ("pg_settings", &settings.pg_settings),
        ("audit_file", &settings.audit_file),
        ("inventory_dir", &settings.inventory_dir),
        ("osv_archive", &settings.osv_archive),
        ("kev_file", &settings.kev_file),
        ("epss_file", &settings.epss_file),
    ];
    paths.iter().try_for_each(|(field, path)| {
        if path.is_absolute() {
            Ok(())
        } else {
            Err(setting_error(field, "must be an absolute path"))
        }
    })?;
    tenant_scope(&settings.tenant).map_err(|_bad| setting_error("tenant", "not a valid tenant name"))?;
    if (MIN_ROUND_SECONDS..=MAX_ROUND_SECONDS).contains(&settings.round_seconds) {
        Ok(())
    } else {
        Err(setting_error(
            "round_seconds",
            &format!("must be between {MIN_ROUND_SECONDS} and {MAX_ROUND_SECONDS}"),
        ))
    }
}


pub fn load_settings(file: &Path) -> Result<ServiceSettings, ConfigError> {
    let settings: ServiceSettings = load_file(file)?;
    validate_settings(&settings)?;
    Ok(settings)
}


/// Everything except the live values must equal the start-up snapshot.
pub fn start_only_changed(baseline: &ServiceSettings, current: &ServiceSettings) -> bool {
    baseline.tenant != current.tenant || baseline.pg_settings != current.pg_settings || baseline.audit_file != current.audit_file
}


pub fn settings_state(settings: &ServiceSettings) -> ConfigState {
    [
        ("tenant", settings.tenant.clone()),
        ("pg_settings", settings.pg_settings.display().to_string()),
        ("audit_file", settings.audit_file.display().to_string()),
        ("inventory_dir", settings.inventory_dir.display().to_string()),
        ("osv_archive", settings.osv_archive.display().to_string()),
        ("kev_file", settings.kev_file.display().to_string()),
        ("epss_file", settings.epss_file.display().to_string()),
        ("osv_sha256", settings.feed.sha256.clone()),
        ("allowed_licences", format!("{:?}", settings.feed.allowed_licences)),
        ("prefix_licences", format!("{:?}", settings.feed.prefix_licences)),
        ("round_seconds", settings.round_seconds.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn settings_loader(file: PathBuf, baseline: ServiceSettings) -> Box<LoaderFn<ServiceSettings>> {
    Box::new(move || {
        let current = load_settings(&file)?;
        if start_only_changed(&baseline, &current) {
            Err(setting_error(
                "start-only",
                "tenant, pg_settings and audit_file are read at start only, restart the service to change them",
            ))
        } else {
            Ok(current)
        }
    })
}


pub fn reload_context(file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    }
}


/// The engine of one settings snapshot: the caller read the file once and that value is the baseline.
pub fn open_service_settings_from(
    file: &Path,
    baseline: ServiceSettings,
    audit: Box<SharedAuditFn>,
) -> Result<ReloadEngine<ServiceSettings>, ConfigError> {
    open_engine(
        settings_loader(file.to_path_buf(), baseline),
        settings_state,
        Vec::new(),
        audit,
        reload_context(file),
    )
}


pub fn open_feed(path: &Path) -> Result<std::fs::File, LoadError> {
    open_regular(path, &path.display().to_string()).map_err(LoadError::Open)
}


pub fn load_osv(settings: &ServiceSettings) -> Result<Vec<OsvRecord>, LoadError> {
    let report = load_feed_reader(open_feed(&settings.osv_archive)?, &settings.feed, &default_limits())?;
    let (kept, bad_entries, dropped_by_licence) = (report.records.len(), report.bad_entries, report.dropped_by_licence);
    info!(kept, bad_entries, dropped_by_licence, "OSV archive read");
    if kept == 0 {
        Err(LoadError::Empty { feed: "osv" })
    } else {
        Ok(report.records.into_iter().map(|loaded| loaded.record).collect())
    }
}


pub fn load_kev(settings: &ServiceSettings) -> Result<KevCatalogue, LoadError> {
    let catalogue = parse_kev(open_feed(&settings.kev_file)?, &KevLimits::default())?;
    let (kept, bad_entries, duplicates, count_matches) = (catalogue.ids.len(), catalogue.bad_entries, catalogue.duplicates, catalogue.count_matches);
    info!(kept, bad_entries, duplicates, count_matches, "KEV catalogue read");
    if kept == 0 {
        Err(LoadError::Empty { feed: "kev" })
    } else {
        Ok(catalogue)
    }
}


pub fn load_epss(settings: &ServiceSettings) -> Result<EpssScores, LoadError> {
    let scores = parse_epss(BufReader::new(open_feed(&settings.epss_file)?), &EpssLimits::default())?;
    let (kept, bad_rows, duplicates) = (scores.scores.len(), scores.bad_rows, scores.duplicates);
    info!(kept, bad_rows, duplicates, "EPSS file read");
    if kept == 0 {
        Err(LoadError::Empty { feed: "epss" })
    } else {
        Ok(scores)
    }
}


/// The new set when the load worked, else the previous one and a counted, named degradation.
pub fn keep<Item>(feed: &'static str, loaded: Result<Item, LoadError>, previous: Option<Item>) -> (Option<Item>, usize) {
    match loaded {
        Ok(item) => (Some(item), 0),
        Err(error) => {
            warn!(feed, %error, "feed not loaded, keeping the previous set");
            (previous, 1)
        }
    }
}


/// Loads the three feeds; answers the sets in force and how many feeds failed (the round is degraded when above 0).
pub fn refresh(previous: Loaded, settings: &ServiceSettings) -> (Loaded, usize) {
    let (records, osv_failed) = keep("osv", load_osv(settings), previous.records);
    let (kev, kev_failed) = keep("kev", load_kev(settings), previous.kev);
    let (epss, epss_failed) = keep("epss", load_epss(settings), previous.epss);
    (Loaded { records, kev, epss }, osv_failed + kev_failed + epss_failed)
}


pub fn stopped(stop: &Receiver<bool>) -> bool {
    *stop.borrow()
}


pub fn default_caps() -> ScanCaps {
    ScanCaps {
        max_open: MAX_OPEN_FINDINGS_PER_TENANT,
        max_resolved: MAX_RESOLVED_FINDINGS_PER_TENANT,
        max_asset_resolved: MAX_RESOLVED_FINDINGS_PER_ASSET,
    }
}


/// A tenant with no counter row is rebuilt once, then the scan is retried.
pub async fn scan_rebuilding(
    exec: Executor<'_, '_>,
    rebuild_exec: Executor<'_, '_>,
    scope: &TenantScope,
    asset: &str,
    findings: &[AssetFinding],
    now_micros: u64,
) -> Result<ScanOutcome, StoreError> {
    let caps = default_caps();
    match record_scan_capped(exec, scope, asset, findings, now_micros, &caps).await {
        Err(StoreError::CountersMissing) => {
            rebuild_counters(rebuild_exec, scope).await?;
            record_scan_capped(exec, scope, asset, findings, now_micros, &caps).await
        }
        other => other,
    }
}


/// The findings of one inventory, scored on EPSS and KEV (every alias counts), then each one's alias list cut to the store's cap.
pub fn findings_of(asset: &str, packages: &[Package], records: &[OsvRecord], epss: &EpssScores, kev: &KevCatalogue) -> Vec<AssetFinding> {
    let matched = match_inventory(packages, records);
    let unmatched = matched.unmatched.len();
    if unmatched > 0 {
        warn!(unmatched, "packages with an unknown ecosystem or version produced no finding");
    }
    let unscored: Vec<ScoredFinding> = matched
        .findings
        .into_iter()
        .map(|finding| ScoredFinding {
            finding,
            cvss: UNSCORED_CVSS,
            epss: UNSCORED_EPSS,
            kev: false,
            criticality: Criticality::Medium,
        })
        .collect();
    let scored = score_findings(&unscored, epss, kev);
    scored
        .into_iter()
        .map(|item| AssetFinding {
            asset: asset.to_owned(),
            scored: cap_aliases(item, kev, MAX_ALIASES_PER_FINDING),
        })
        .collect()
}


pub fn key_of(item: &AssetFinding) -> FindingKey {
    let finding = &item.scored.finding;
    (finding.ecosystem.clone(), finding.package.clone(), finding.record_id.clone())
}


/// The findings the store holds after a scan: those it accepted by grammar, and when it refused some for room, only those it still lists as open.
pub async fn accepted_findings(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    asset: &str,
    findings: &[AssetFinding],
    no_room: u64,
) -> Vec<AssetFinding> {
    let admitted: Vec<AssetFinding> = findings.iter().filter(|item| finding_doc(asset, item).is_some()).cloned().collect();
    if no_room == 0 {
        admitted
    } else {
        match open_findings_of_asset(exec, scope, asset, MAX_FINDINGS_PER_SCAN).await {
            Ok(page) => {
                let held: BTreeSet<FindingKey> = page
                    .findings
                    .into_iter()
                    .map(|stored| (stored.ecosystem, stored.package, stored.record_id))
                    .collect();
                admitted.into_iter().filter(|item| held.contains(&key_of(item))).collect()
            }
            Err(error) => {
                warn!(asset, %error, "the stored findings cannot be read back, no alert is raised for this asset");
                Vec::new()
            }
        }
    }
}


/// Stores one asset's full scan, then the KEV alerts of the findings the store accepted; a failed alert write leaves the committed scan and is retried next round.
pub async fn scan_asset(
    exec: Executor<'_, '_>,
    rebuild_exec: Executor<'_, '_>,
    scope: &TenantScope,
    asset: &str,
    findings: &[AssetFinding],
    kev: &KevCatalogue,
    now_micros: u64,
) -> Result<AssetScan, StoreError> {
    let outcome = scan_rebuilding(exec, rebuild_exec, scope, asset, findings, now_micros).await?;
    let accepted = accepted_findings(exec, scope, asset, findings, outcome.refused_no_room).await;
    let alerts = kev_alerts(scope, &accepted, &kev.ids, now_micros);
    let (stored_alerts, alerts_failed) = match store_kev_alerts(exec, scope, &alerts).await {
        Ok(stored) => (stored, false),
        Err(error) => {
            warn!(asset, %error, "the scan is stored, its KEV alerts were not and are retried next round");
            (0, true)
        }
    };
    Ok(AssetScan {
        stored: outcome.inserted + outcome.updated,
        alerts: stored_alerts,
        alerts_failed,
        refused: outcome.refused,
        no_room: outcome.refused_no_room,
    })
}


/// One round over the inventory directory; an asset whose file is missing or refused is not scanned, so its findings stay as they are.
pub async fn scan_round(
    exec: Executor<'_, '_>,
    rebuild_exec: Executor<'_, '_>,
    scope: &TenantScope,
    settings: &ServiceSettings,
    loaded: &Loaded,
    now_micros: u64,
    stop: &Receiver<bool>,
) -> RoundReport {
    match (&loaded.records, &loaded.kev, &loaded.epss) {
        (Some(records), Some(kev), Some(epss)) if now_micros > 0 => match list_inventory(&settings.inventory_dir) {
            Ok(listing) => {
                let mut report = RoundReport {
                    refused_files: listing.refused,
                    left_out: listing.left_out,
                    first_left_out: listing.first_left_out,
                    ..RoundReport::default()
                };
                let mut reached = 0;
                for (asset, path) in listing.files.iter().take_while(|_| !stopped(stop)) {
                    reached += 1;
                    match read_inventory(path) {
                        Ok(packages) => {
                            let findings = findings_of(asset, &packages, records, epss, kev);
                            match scan_asset(exec, rebuild_exec, scope, asset, &findings, kev, now_micros).await {
                                Ok(scan) => {
                                    report.scanned += 1;
                                    report.findings += scan.stored;
                                    report.alerts += scan.alerts;
                                    report.alerts_failed += usize::from(scan.alerts_failed);
                                    report.refused_findings += scan.refused;
                                    report.no_room += scan.no_room;
                                }
                                Err(error) => {
                                    report.failed_assets += 1;
                                    warn!(asset, %error, "the asset scan failed, its findings are unchanged");
                                }
                            }
                        }
                        Err(error) => {
                            report.refused_files += 1;
                            warn!(asset, %error, "inventory file refused, the asset is not scanned");
                        }
                    }
                }
                report.stopped = reached < listing.files.len();
                report
            }
            Err(error) => {
                warn!(%error, "the inventory directory cannot be listed, nothing is scanned");
                RoundReport {
                    skipped: true,
                    ..RoundReport::default()
                }
            }
        },
        _ => {
            warn!("a feed is not loaded or the clock is unset, nothing is scanned");
            RoundReport {
                skipped: true,
                ..RoundReport::default()
            }
        }
    }
}


pub fn log_round(report: &RoundReport, degraded: usize) {
    let (scanned, refused, failed, findings, alerts) = (report.scanned, report.refused_files, report.failed_assets, report.findings, report.alerts);
    info!(scanned, refused, failed, findings, alerts, degraded, "round done");
    let (left_out, stopped, skipped) = (report.left_out, report.stopped, report.skipped);
    let first_left_out = report.first_left_out.as_deref().unwrap_or("none");
    let (refused_findings, no_room, alerts_failed) = (report.refused_findings, report.no_room, report.alerts_failed);
    let limits = format!("left_out={left_out} first_left_out={first_left_out:?} stopped={stopped} skipped={skipped}");
    let refusals = format!("refused_findings={refused_findings} no_room={no_room} alerts_failed={alerts_failed}");
    if left_out > 0 || stopped || skipped || refused_findings > 0 || no_room > 0 || alerts_failed > 0 {
        warn!("round incomplete {limits} {refusals}");
    } else {
        info!("round complete {limits} {refusals}");
    }
}
