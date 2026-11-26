#![cfg(unix)]


#[path = "common/fake_store.rs"]
mod fake_store;
#[path = "common/site.rs"]
mod site;
#[path = "common/types.rs"]
mod types;


use core_config::reload::{reload, ReloadOutcome};
use core_pg::scope::tenant_scope;
use fake_store::{executor, FakeStore};
use site::{build_archive, settings_text, sha_of, write_site, Site, EPSS, KEV, RECORD, ROUND_SECONDS, TENANT, VULNERABLE};
use std::fs;
use std::sync::atomic::Ordering;
use tempfile::tempdir;
use tokio::sync::watch::{channel, Receiver};
use types::TestResult;
use vuln_match::service::{
    default_caps, keep, load_epss, load_kev, load_osv, load_settings, open_service_settings_from, refresh, scan_asset, scan_rebuilding, scan_round,
    settings_state, start_only_changed, stopped, validate_settings, LoadError, Loaded, RoundReport, ServiceSettings,
};
use vuln_match::store::MIGRATION_DEADLINE;


const CVE: &str = "CVE-2024-1234";


const UPGRADED: &str = r#"[{"ecosystem":"Debian:12","name":"curl","version":"7.88.1-11"}]"#;


const MAX_ROUND_SECONDS: u64 = 86_400;


const LIVE_ROUND: u64 = 20;


const SCORE: f64 = 0.5;


const FEEDS: usize = 3;


const KEPT: u8 = 7;


const TWO_ASSETS: usize = 2;


const REFUSED_FILES: usize = 3;


const MIGRATION_SECONDS: u64 = 120;


const NOW: u64 = 1_700_000_000_000_000;


fn running() -> Result<(tokio::sync::watch::Sender<bool>, Receiver<bool>), Box<dyn std::error::Error>> {
    Ok(channel(false))
}


fn site_in(dir: &std::path::Path) -> Result<(Site, ServiceSettings), Box<dyn std::error::Error>> {
    let site = write_site(dir, 1, "ca")?;
    let settings = load_settings(&site.settings)?;
    Ok((site, settings))
}


fn loaded_of(settings: &ServiceSettings) -> Result<Loaded, Box<dyn std::error::Error>> {
    let (loaded, degraded) = refresh(Loaded::default(), settings);
    assert_eq!(degraded, 0);
    Ok(loaded)
}


async fn round(store: &FakeStore, settings: &ServiceSettings, loaded: &Loaded, now: u64) -> Result<RoundReport, Box<dyn std::error::Error>> {
    let (_sender, stop) = running()?;
    let exec = executor(store);
    Ok(scan_round(&exec, &exec, &tenant_scope(TENANT)?, settings, loaded, now, &stop).await)
}


#[test]
fn the_settings_file_loads_and_is_checked() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    assert_eq!(settings.tenant, TENANT);
    assert_eq!(settings.round_seconds, ROUND_SECONDS);
    let base = fs::read_to_string(&site.settings)?;
    let bad = [
        base.replace("tenant: acme", "tenant: -x"),
        base.replace("tenant: acme", "tenant: all"),
        base.replace("round_seconds: 10", "round_seconds: 9"),
        base.replace("round_seconds: 10", "round_seconds: 86401"),
        base.replace(&format!("audit_file: {}", site.audit.display()), "audit_file: audit.log"),
        base.replace(&format!("kev_file: {}", site.kev.display()), "kev_file: kev.json"),
        base.replace(&format!("audit_file: {}\n", site.audit.display()), ""),
        format!("{base}surprise: 1\n"),
    ];
    bad.iter().try_for_each(|text| -> TestResult {
        fs::write(&site.settings, text)?;
        assert!(load_settings(&site.settings).is_err(), "{text}");
        Ok(())
    })?;
    fs::write(&site.settings, base.replace("round_seconds: 10", "round_seconds: 86400"))?;
    assert_eq!(load_settings(&site.settings)?.round_seconds, MAX_ROUND_SECONDS);
    Ok(())
}


#[test]
fn start_only_settings_are_pinned_and_the_rest_reloads() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    let engine = open_service_settings_from(
        &site.settings,
        settings.clone(),
        Box::new(|_entry| Err(core_audit::error::AuditError::LogPoisoned)),
    )?;
    drop(engine);
    let live = ServiceSettings {
        round_seconds: LIVE_ROUND,
        ..settings.clone()
    };
    assert!(!start_only_changed(&settings, &live));
    [
        ServiceSettings {
            tenant: "other".into(),
            ..settings.clone()
        },
        ServiceSettings {
            pg_settings: "/other.yaml".into(),
            ..settings.clone()
        },
        ServiceSettings {
            audit_file: "/other.log".into(),
            ..settings.clone()
        },
    ]
    .iter()
    .for_each(|changed| assert!(start_only_changed(&settings, changed)));
    assert_eq!(settings_state(&settings).get("tenant").map(String::as_str), Some(TENANT));
    assert_ne!(settings_state(&settings), settings_state(&live));
    validate_settings(&settings)?;
    Ok(())
}


#[test]
fn a_reload_is_audited_under_tenant_all_and_start_only_changes_are_refused() -> TestResult {
    use std::sync::{Arc, Mutex};
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let engine = open_service_settings_from(
        &site.settings,
        settings,
        Box::new(move |entry| {
            sink.lock()
                .map_err(|_poisoned| core_audit::error::AuditError::LogPoisoned)?
                .push(entry.tenant.clone());
            Err(core_audit::error::AuditError::LogPoisoned)
        }),
    )?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    let base = fs::read_to_string(&site.settings)?;
    fs::write(&site.settings, base.replace("round_seconds: 10", "round_seconds: 30"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    fs::write(&site.settings, base.replace("tenant: acme", "tenant: other"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    let tenants = seen.lock().map_err(|_poisoned| "poisoned")?.clone();
    assert!(!tenants.is_empty() && tenants.iter().all(|tenant| tenant == "all"), "{tenants:?}");
    Ok(())
}


#[test]
fn the_feeds_load_from_their_files() -> TestResult {
    let dir = tempdir()?;
    let (_site, settings) = site_in(dir.path())?;
    assert_eq!(load_osv(&settings)?.len(), 1);
    assert!(load_kev(&settings)?.ids.contains(CVE));
    assert_eq!(load_epss(&settings)?.scores.get(CVE), Some(&SCORE));
    let (loaded, degraded) = refresh(Loaded::default(), &settings);
    assert_eq!(degraded, 0);
    assert!(loaded.records.is_some() && loaded.kev.is_some() && loaded.epss.is_some());
    Ok(())
}


#[test]
fn a_feed_that_fails_keeps_the_previous_set_and_is_counted() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    let loaded = loaded_of(&settings)?;
    let swapped = build_archive(&[("DSA-2.json", r#"{"id":"DSA-2"}"#)])?;
    fs::write(&site.archive, &swapped)?;
    fs::write(&site.kev, "not json")?;
    fs::write(&site.epss, "garbage")?;
    let (kept, degraded) = refresh(loaded, &settings);
    assert_eq!(degraded, FEEDS);
    assert_eq!(kept.records.as_ref().map(Vec::len), Some(1));
    assert_eq!(
        kept.records.as_ref().and_then(|records| records.first()).map(|record| record.id.as_str()),
        Some("DSA-1")
    );
    assert!(kept.kev.is_some_and(|kev| kev.ids.contains(CVE)));
    assert!(kept.epss.is_some_and(|epss| epss.scores.contains_key(CVE)));
    Ok(())
}


#[test]
fn a_feed_that_never_loaded_stays_absent() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::remove_file(&site.archive)?;
    fs::remove_file(&site.kev)?;
    fs::remove_file(&site.epss)?;
    let (loaded, degraded) = refresh(Loaded::default(), &settings);
    assert_eq!(degraded, FEEDS);
    assert!(loaded.records.is_none() && loaded.kev.is_none() && loaded.epss.is_none());
    assert!(matches!(load_osv(&settings), Err(LoadError::Open(_))));
    assert!(matches!(load_kev(&settings), Err(LoadError::Open(_))));
    assert!(matches!(load_epss(&settings), Err(LoadError::Open(_))));
    Ok(())
}


#[test]
fn a_swapped_archive_is_refused_by_its_checksum() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    let swapped = build_archive(&[("DSA-9.json", r#"{"id":"DSA-9"}"#)])?;
    fs::write(&site.archive, &swapped)?;
    assert!(matches!(load_osv(&settings), Err(LoadError::Osv(_))));
    fs::write(&site.settings, settings_text(&site, &sha_of(&swapped), ROUND_SECONDS))?;
    assert_eq!(load_osv(&load_settings(&site.settings)?)?.len(), 1);
    fs::write(&site.archive, b"")?;
    assert!(matches!(load_osv(&settings), Err(LoadError::Osv(_))));
    Ok(())
}


#[test]
fn an_archive_with_a_bad_entry_still_loads_the_good_ones() -> TestResult {
    let dir = tempdir()?;
    let (site, _settings) = site_in(dir.path())?;
    let archive = build_archive(&[("DSA-1.json", RECORD), ("bad.json", "not json")])?;
    fs::write(&site.archive, &archive)?;
    fs::write(&site.settings, settings_text(&site, &sha_of(&archive), ROUND_SECONDS))?;
    assert_eq!(load_osv(&load_settings(&site.settings)?)?.len(), 1);
    Ok(())
}


#[test]
fn keep_names_the_degradation_per_feed() -> TestResult {
    assert_eq!(keep("x", Ok::<u8, LoadError>(1), Some(0)), (Some(1), 0));
    let failed: Result<u8, LoadError> = Err(LoadError::Kev(vuln_match::error::KevError::TooLarge { max: 1 }));
    assert_eq!(keep("x", failed, Some(KEPT)), (Some(KEPT), 1));
    Ok(())
}


#[tokio::test]
async fn a_round_stores_the_findings_and_the_kev_alert_under_the_tenant() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("web-1.json"), VULNERABLE)?;
    fs::write(site.inventory.join("web-2.json"), UPGRADED)?;
    let store = FakeStore::default();
    let report = round(&store, &settings, &loaded_of(&settings)?, NOW).await?;
    assert_eq!(report.scanned, TWO_ASSETS);
    assert_eq!(report.findings, 1);
    assert_eq!(report.alerts, 1);
    assert_eq!((report.refused_files, report.failed_assets), (0, 0));
    assert!(!report.skipped && !report.stopped && !report.over_cap);
    let open = store.open.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(open.get("web-1").map(|keys| keys.len()), Some(1));
    assert_eq!(open.get("web-2").map(|keys| keys.len()), Some(0));
    assert_eq!(store.tenants.lock().map_err(|_poisoned| "poisoned")?.iter().collect::<Vec<_>>(), [TENANT]);
    Ok(())
}


#[tokio::test]
async fn an_upgraded_package_resolves_its_finding_and_a_second_round_is_idempotent() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("web-1.json"), VULNERABLE)?;
    let store = FakeStore::default();
    let loaded = loaded_of(&settings)?;
    round(&store, &settings, &loaded, NOW).await?;
    let again = round(&store, &settings, &loaded, NOW).await?;
    assert_eq!(again.alerts, 0);
    fs::write(site.inventory.join("web-1.json"), UPGRADED)?;
    round(&store, &settings, &loaded, NOW).await?;
    let scans = store.scans.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(scans.iter().map(|(_asset, _tenant, count)| *count).collect::<Vec<_>>(), [1, 1, 0]);
    Ok(())
}


#[tokio::test]
async fn a_deleted_inventory_file_never_resolves_its_asset() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("web-1.json"), VULNERABLE)?;
    fs::write(site.inventory.join("web-2.json"), VULNERABLE)?;
    let store = FakeStore::default();
    let loaded = loaded_of(&settings)?;
    round(&store, &settings, &loaded, NOW).await?;
    fs::remove_file(site.inventory.join("web-1.json"))?;
    let report = round(&store, &settings, &loaded, NOW).await?;
    assert_eq!(report.scanned, 1);
    let scans = store.scans.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(scans.iter().filter(|(asset, _tenant, _count)| asset == "web-1").count(), 1);
    let open = store.open.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(open.get("web-1").map(|keys| keys.len()), Some(1));
    Ok(())
}


#[tokio::test]
async fn a_refused_file_is_skipped_alone_and_its_findings_stay() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("good.json"), VULNERABLE)?;
    fs::write(site.inventory.join("broken.json"), "[1,2,3")?;
    fs::write(site.inventory.join("-flag.json"), VULNERABLE)?;
    std::os::unix::fs::symlink("/etc/shadow", site.inventory.join("shadow.json"))?;
    let store = FakeStore::default();
    let report = round(&store, &settings, &loaded_of(&settings)?, NOW).await?;
    assert_eq!((report.scanned, report.refused_files), (1, REFUSED_FILES));
    let open = store.open.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(open.keys().collect::<Vec<_>>(), ["good"]);
    Ok(())
}


#[tokio::test]
async fn a_failed_store_call_fails_the_asset_alone() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("a.json"), VULNERABLE)?;
    fs::write(site.inventory.join("b.json"), VULNERABLE)?;
    let store = FakeStore {
        fail_asset: Some("a"),
        ..FakeStore::default()
    };
    let report = round(&store, &settings, &loaded_of(&settings)?, NOW).await?;
    assert_eq!((report.scanned, report.failed_assets), (1, 1));
    Ok(())
}


#[tokio::test]
async fn a_round_without_a_feed_or_a_clock_scans_nothing() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("a.json"), VULNERABLE)?;
    let store = FakeStore::default();
    let full = loaded_of(&settings)?;
    let no_records = Loaded {
        records: None,
        ..loaded_of(&settings)?
    };
    let no_kev = Loaded {
        kev: None,
        ..loaded_of(&settings)?
    };
    let no_epss = Loaded {
        epss: None,
        ..loaded_of(&settings)?
    };
    for loaded in [&no_records, &no_kev, &no_epss] {
        assert!(round(&store, &settings, loaded, NOW).await?.skipped);
    }
    assert!(round(&store, &settings, &full, 0).await?.skipped);
    assert!(store.scans.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    Ok(())
}


#[tokio::test]
async fn an_unreadable_inventory_directory_scans_nothing() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::remove_dir(&site.inventory)?;
    let store = FakeStore::default();
    assert!(round(&store, &settings, &loaded_of(&settings)?, NOW).await?.skipped);
    Ok(())
}


#[tokio::test]
async fn a_stop_between_assets_ends_the_round_without_cutting_a_scan() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("a.json"), VULNERABLE)?;
    fs::write(site.inventory.join("b.json"), VULNERABLE)?;
    let store = FakeStore::default();
    let (sender, stop) = running()?;
    sender.send_replace(true);
    let exec = executor(&store);
    let report = scan_round(&exec, &exec, &tenant_scope(TENANT)?, &settings, &loaded_of(&settings)?, NOW, &stop).await;
    assert!(report.stopped && report.scanned == 0);
    assert!(stopped(&stop));
    Ok(())
}


#[tokio::test]
async fn a_tenant_without_counters_is_rebuilt_once_then_scanned() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("a.json"), VULNERABLE)?;
    let store = FakeStore::default();
    store.missing_counters.store(true, Ordering::SeqCst);
    let report = round(&store, &settings, &loaded_of(&settings)?, NOW).await?;
    assert_eq!(report.scanned, 1);
    assert_eq!(*store.rebuilds.lock().map_err(|_poisoned| "poisoned")?, 1);
    assert!(
        scan_rebuilding(&executor(&store), &executor(&store), &tenant_scope(TENANT)?, "a", &[], NOW)
            .await
            .is_ok()
    );
    assert_eq!(default_caps().max_open, vuln_match::limits::MAX_OPEN_FINDINGS_PER_TENANT);
    assert_eq!(MIGRATION_DEADLINE.as_secs(), MIGRATION_SECONDS);
    Ok(())
}


#[tokio::test]
async fn a_scan_error_other_than_missing_counters_is_returned() -> TestResult {
    let store = FakeStore {
        fail_asset: Some("a"),
        ..FakeStore::default()
    };
    let exec = executor(&store);
    let kev = vuln_match::kev::KevCatalogue::default();
    assert!(scan_asset(&exec, &exec, &tenant_scope(TENANT)?, "a", &[], &kev, NOW).await.is_err());
    assert!(scan_asset(&exec, &exec, &tenant_scope(TENANT)?, "b", &[], &kev, NOW).await.is_ok());
    assert!(KEV.contains(CVE) && EPSS.contains(CVE));
    Ok(())
}


#[tokio::test]
async fn packages_of_an_unknown_ecosystem_give_no_finding_and_the_scan_still_runs() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("a.json"), r#"[{"ecosystem":"Alpine:3","name":"curl","version":"1"}]"#)?;
    let store = FakeStore::default();
    let report = round(&store, &settings, &loaded_of(&settings)?, NOW).await?;
    assert_eq!((report.scanned, report.findings, report.alerts), (1, 0, 0));
    Ok(())
}
