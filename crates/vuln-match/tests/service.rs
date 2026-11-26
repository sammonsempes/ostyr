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
use site::{build_archive, settings_text, sha_of, write_site, Site, EPSS, KEV, OPEN, RECORD, ROUND_SECONDS, TENANT, VULNERABLE};
use std::fs;
use std::sync::atomic::Ordering;
use tempfile::tempdir;
use tokio::sync::watch::{channel, Receiver};
use types::TestResult;
use vuln_match::service::{
    default_caps, findings_of, keep, load_epss, load_kev, load_osv, load_settings, log_round, open_service_settings_from, refresh, scan_asset,
    scan_rebuilding, scan_round, settings_state, start_only_changed, stopped, validate_settings, LoadError, Loaded, RoundReport, ServiceSettings,
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


const HUNDREDS: usize = 150;


const ALIAS_BASE: usize = 1000;


const TWO_FEEDS: usize = 2;


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
    assert!(!report.skipped && !report.stopped && report.left_out == 0);
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


fn without_licences(site: &Site) -> Result<ServiceSettings, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(&site.settings)?.replace("\"DSA-\": CC0-1.0", "\"XXX-\": CC0-1.0");
    fs::write(&site.settings, text)?;
    Ok(load_settings(&site.settings)?)
}


#[test]
fn an_osv_set_with_no_record_is_refused_and_the_previous_set_stays() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    let loaded = loaded_of(&settings)?;
    let unlicensed = without_licences(&site)?;
    assert!(matches!(load_osv(&unlicensed), Err(LoadError::Empty { feed: "osv" })));
    let empty = build_archive(&[])?;
    fs::write(&site.archive, &empty)?;
    fs::write(&site.settings, settings_text(&site, &sha_of(&empty), ROUND_SECONDS))?;
    let emptied = load_settings(&site.settings)?;
    assert!(matches!(load_osv(&emptied), Err(LoadError::Empty { feed: "osv" })));
    let (kept, degraded) = refresh(loaded, &emptied);
    assert_eq!(degraded, 1);
    assert_eq!(kept.records.as_ref().map(Vec::len), Some(1));
    Ok(())
}


#[test]
fn an_empty_kev_or_epss_file_is_refused_and_a_partly_bad_one_is_kept() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    let loaded = loaded_of(&settings)?;
    fs::write(&site.kev, r#"{"vulnerabilities":[]}"#)?;
    fs::write(&site.epss, "#model_version:v1,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\n")?;
    assert!(matches!(load_kev(&settings), Err(LoadError::Empty { feed: "kev" })));
    assert!(matches!(load_epss(&settings), Err(LoadError::Empty { feed: "epss" })));
    let (kept, degraded) = refresh(loaded, &settings);
    assert_eq!(degraded, TWO_FEEDS);
    assert!(kept.kev.is_some_and(|kev| kev.ids.contains(CVE)));
    assert!(kept.epss.is_some_and(|epss| epss.scores.contains_key(CVE)));
    fs::write(
        &site.kev,
        r#"{"vulnerabilities":[{"cveID":"CVE-2024-1234"},{"cveID":"bad"},{"cveID":"CVE-2024-1234"}]}"#,
    )?;
    fs::write(
        &site.epss,
        "#model_version:v1,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\nCVE-2024-1234,0.5,0.9\nbad,1,1\nCVE-2024-1234,0.1,0.1\n",
    )?;
    let kev = load_kev(&settings)?;
    assert_eq!((kev.ids.len(), kev.bad_entries, kev.duplicates), (1, 1, 1));
    let epss = load_epss(&settings)?;
    assert_eq!((epss.scores.len(), epss.bad_rows, epss.duplicates), (1, 1, 1));
    Ok(())
}


fn aliased_record(count: usize) -> String {
    let upstream: Vec<String> = (0..count).map(|index| format!("\"CVE-2023-{:04}\"", ALIAS_BASE + index)).collect();
    format!(
        r#"{{"id":"DSA-1","upstream":[{}],"aliases":["CVE-2024-1234"],"affected":[{{"package":{{"ecosystem":"Debian:12","name":"curl"}},"ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"7.88.1-11"}}]}}]}}]}}"#,
        upstream.join(",")
    )
}


#[tokio::test]
async fn a_record_with_hundreds_of_aliases_is_stored_with_a_cut_list_and_its_alert_is_raised() -> TestResult {
    let dir = tempdir()?;
    let (site, _settings) = site_in(dir.path())?;
    let archive = build_archive(&[("DSA-1.json", &aliased_record(HUNDREDS))])?;
    fs::write(&site.archive, &archive)?;
    fs::write(&site.settings, settings_text(&site, &sha_of(&archive), ROUND_SECONDS))?;
    let settings = load_settings(&site.settings)?;
    fs::write(site.inventory.join("k-1.json"), VULNERABLE)?;
    let loaded = loaded_of(&settings)?;
    let kev = loaded.kev.as_ref().ok_or("no kev")?;
    let epss = loaded.epss.as_ref().ok_or("no epss")?;
    let records = loaded.records.as_ref().ok_or("no records")?;
    let packages = vuln_match::inventory::read_inventory(&site.inventory.join("k-1.json"))?;
    let findings = findings_of("k-1", &packages, records, epss, kev);
    let first = findings.first().ok_or("no finding")?;
    let max = vuln_match::limits::MAX_ALIASES_PER_FINDING;
    assert_eq!(first.scored.finding.cve_aliases.len(), max);
    assert_eq!(first.scored.finding.cve_aliases.first().map(String::as_str), Some(CVE));
    assert_eq!(first.scored.finding.aliases_omitted, (HUNDREDS + 1 - max) as u64);
    assert!(first.scored.kev);
    let doc = vuln_match::store::finding_doc("k-1", first).ok_or("refused")?;
    assert_eq!(
        doc.get("aliases_omitted").and_then(serde_json::Value::as_u64),
        Some(first.scored.finding.aliases_omitted)
    );
    let store = FakeStore::default();
    let report = round(&store, &settings, &loaded, NOW).await?;
    assert_eq!((report.scanned, report.findings, report.alerts, report.refused_findings), (1, 1, 1, 0));
    Ok(())
}


const SECOND_RECORD: &str = r#"{"id":"DSA-2","aliases":["CVE-2024-1234"],"affected":[{"package":{"ecosystem":"Debian:12","name":"bash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9"}]}]}]}"#;


fn two_record_site(dir: &std::path::Path) -> Result<(Site, ServiceSettings), Box<dyn std::error::Error>> {
    let (site, _settings) = site_in(dir)?;
    let archive = build_archive(&[("DSA-1.json", RECORD), ("DSA-2.json", SECOND_RECORD)])?;
    fs::write(&site.archive, &archive)?;
    fs::write(&site.settings, settings_text(&site, &sha_of(&archive), ROUND_SECONDS))?;
    fs::write(site.inventory.join("k-1.json"), VULNERABLE)?;
    let settings = load_settings(&site.settings)?;
    Ok((site, settings))
}


#[tokio::test]
async fn a_finding_refused_for_room_raises_no_alert_and_is_counted() -> TestResult {
    let dir = tempdir()?;
    let (_site, settings) = two_record_site(dir.path())?;
    let loaded = loaded_of(&settings)?;
    let all = round(&FakeStore::default(), &settings, &loaded, NOW).await?;
    assert_eq!((all.alerts, all.no_room), (TWO_ASSETS, 0));
    let store = FakeStore {
        no_room_package: Some("bash"),
        ..FakeStore::default()
    };
    let report = round(&store, &settings, &loaded, NOW).await?;
    assert_eq!((report.scanned, report.alerts, report.no_room), (1, 1, 1));
    let alerts = store.alerts.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(alerts.len(), 1);
    assert!(alerts.iter().all(|id| !id.contains("bash")), "{alerts:?}");
    Ok(())
}


#[tokio::test]
async fn a_failed_read_back_raises_no_alert_and_a_failed_alert_write_keeps_the_scan() -> TestResult {
    let dir = tempdir()?;
    let (_site, settings) = two_record_site(dir.path())?;
    let loaded = loaded_of(&settings)?;
    let blind = FakeStore {
        no_room_package: Some("bash"),
        fail_readback: true,
        ..FakeStore::default()
    };
    let blind_report = round(&blind, &settings, &loaded, NOW).await?;
    assert_eq!((blind_report.scanned, blind_report.alerts, blind_report.no_room), (1, 0, 1));
    let failing = FakeStore::default();
    failing.fail_alerts.store(true, Ordering::SeqCst);
    let report = round(&failing, &settings, &loaded, NOW).await?;
    assert_eq!((report.scanned, report.failed_assets, report.alerts, report.alerts_failed), (1, 0, 0, 1));
    assert_eq!(
        failing.open.lock().map_err(|_poisoned| "poisoned")?.get("k-1").map(|keys| keys.len()),
        Some(TWO_ASSETS)
    );
    Ok(())
}


#[tokio::test]
async fn a_finding_outside_the_grammar_is_counted_and_raises_no_alert() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = two_record_site(dir.path())?;
    let loaded = loaded_of(&settings)?;
    let kev = loaded.kev.as_ref().ok_or("no kev")?;
    let epss = loaded.epss.as_ref().ok_or("no epss")?;
    let records = loaded.records.as_ref().ok_or("no records")?;
    let packages = vuln_match::inventory::read_inventory(&site.inventory.join("k-1.json"))?;
    let mut findings = findings_of("k-1", &packages, records, epss, kev);
    let mut bad = findings.first().ok_or("none")?.clone();
    bad.scored.finding.record_id = "bad id".to_owned();
    findings.push(bad);
    let store = FakeStore::default();
    let exec = executor(&store);
    let scan = scan_asset(&exec, &exec, &tenant_scope(TENANT)?, "k-1", &findings, kev, NOW).await?;
    assert_eq!((scan.refused, scan.alerts, scan.alerts_failed), (1, TWO_ASSETS, false));
    Ok(())
}


#[tokio::test]
async fn an_unfinished_round_is_named_in_the_report() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("a.json"), VULNERABLE)?;
    fs::write(site.inventory.join("b.json"), VULNERABLE)?;
    let store = FakeStore::default();
    let (sender, stop) = running()?;
    let exec = executor(&store);
    let loaded = loaded_of(&settings)?;
    let report = scan_round(&exec, &exec, &tenant_scope(TENANT)?, &settings, &loaded, NOW, &stop).await;
    assert!(!report.stopped);
    sender.send_replace(true);
    let cut = scan_round(&exec, &exec, &tenant_scope(TENANT)?, &settings, &loaded, NOW, &stop).await;
    assert!(cut.stopped);
    log_round(&report, 0);
    log_round(&cut, 1);
    log_round(
        &RoundReport {
            left_out: 1,
            first_left_out: Some("z".to_owned()),
            ..RoundReport::default()
        },
        0,
    );
    [
        RoundReport {
            skipped: true,
            ..RoundReport::default()
        },
        RoundReport {
            refused_findings: 1,
            ..RoundReport::default()
        },
        RoundReport {
            no_room: 1,
            ..RoundReport::default()
        },
        RoundReport {
            alerts_failed: 1,
            ..RoundReport::default()
        },
    ]
    .iter()
    .for_each(|single| log_round(single, 0));
    Ok(())
}


const TWO_VERSIONS_OF_ONE_PACKAGE: &str =
    r#"[{"ecosystem":"Debian:12","name":"curl","version":"7.88.1-10"},{"ecosystem":"Debian:12","name":"curl","version":"7.88.1-9"}]"#;


#[tokio::test]
async fn two_versions_of_one_package_raise_one_alert_for_the_stored_row() -> TestResult {
    let dir = tempdir()?;
    let (site, settings) = site_in(dir.path())?;
    fs::write(site.inventory.join("k-1.json"), TWO_VERSIONS_OF_ONE_PACKAGE)?;
    let loaded = loaded_of(&settings)?;
    let store = FakeStore::default();
    let report = round(&store, &settings, &loaded, NOW).await?;
    assert_eq!((report.scanned, report.findings, report.alerts), (1, 1, 1));
    assert_eq!(store.alerts.lock().map_err(|_poisoned| "poisoned")?.len(), 1);
    assert_eq!(
        store
            .versions
            .lock()
            .map_err(|_poisoned| "poisoned")?
            .values()
            .cloned()
            .collect::<Vec<String>>(),
        ["7.88.1-10"]
    );
    let blind = FakeStore {
        fail_readback: true,
        ..FakeStore::default()
    };
    let blind_report = round(&blind, &settings, &loaded, NOW).await?;
    assert_eq!((blind_report.scanned, blind_report.alerts), (1, 0));
    Ok(())
}


#[tokio::test]
async fn the_omitted_aliases_of_a_round_are_counted() -> TestResult {
    let dir = tempdir()?;
    let (site, _settings) = site_in(dir.path())?;
    let archive = build_archive(&[("DSA-1.json", &aliased_record(HUNDREDS))])?;
    fs::write(&site.archive, &archive)?;
    fs::write(&site.settings, settings_text(&site, &sha_of(&archive), ROUND_SECONDS))?;
    let settings = load_settings(&site.settings)?;
    fs::write(site.inventory.join("k-1.json"), VULNERABLE)?;
    let loaded = loaded_of(&settings)?;
    let report = round(&FakeStore::default(), &settings, &loaded, NOW).await?;
    assert_eq!(
        report.aliases_omitted,
        (HUNDREDS + 1 - vuln_match::limits::MAX_ALIASES_PER_FINDING) as u64
    );
    assert_eq!(report.kev_omitted, 0);
    log_round(&report, 0);
    log_round(
        &RoundReport {
            kev_omitted: 1,
            ..RoundReport::default()
        },
        0,
    );
    Ok(())
}


#[test]
fn the_ecosystem_names_of_the_settings_are_a_bounded_ascii_list() -> TestResult {
    let dir = tempdir()?;
    let (site, _settings) = site_in(dir.path())?;
    let base = fs::read_to_string(&site.settings)?;
    let with = |names: &str| {
        base.replace(
            &format!("allowed_licences: [{OPEN}]"),
            &format!("allowed_licences: [{OPEN}]\n  ecosystems: {names}"),
        )
    };
    let too_many = format!("[{}]", vec!["Debian"; vuln_match::limits::MAX_FEED_ECOSYSTEMS + 1].join(", "));
    let too_long = format!("[{}]", "a".repeat(vuln_match::limits::MAX_ECOSYSTEM_CHARS + 1));
    let bad = [
        too_many,
        too_long,
        "[\"\"]".to_owned(),
        "[\"-x\"]".to_owned(),
        "[\"Debian;12\"]".to_owned(),
        "[\"D\u{e9}bian\"]".to_owned(),
    ];
    bad.iter().try_for_each(|names| -> TestResult {
        fs::write(&site.settings, with(names))?;
        assert!(load_settings(&site.settings).is_err(), "{names}");
        Ok(())
    })?;
    let at_cap = format!("[{}]", vec!["Rocky Linux:9.3"; vuln_match::limits::MAX_FEED_ECOSYSTEMS].join(", "));
    fs::write(&site.settings, with(&at_cap))?;
    assert_eq!(
        load_settings(&site.settings)?.feed.ecosystems.len(),
        vuln_match::limits::MAX_FEED_ECOSYSTEMS
    );
    fs::write(&site.settings, with("[Debian:12, Debian:11]"))?;
    let selected = load_settings(&site.settings)?;
    assert_eq!(selected.feed.ecosystems, ["Debian:12", "Debian:11"]);
    assert!(settings_state(&selected)
        .get("ecosystems")
        .is_some_and(|value| value.contains("Debian:11")));
    Ok(())
}
