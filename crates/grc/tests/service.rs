#![cfg(unix)]


#[path = "common/site.rs"]
mod site;
#[path = "common/trail.rs"]
mod trail;
#[path = "common/types.rs"]
mod types;


use core_config::reload::{reload, ReloadOutcome};
use grc::builtin::BUILTIN;
use grc::service::{
    declarations_state, load_declarations, open_declarations, start_only_changed, watched_files, Declarations, Signals, MAX_FRAMEWORKS,
};
use grc::types::DeclarationsReader;
use site::{settings_text, write_site, Site, INTERVAL, MANUAL_ACME, TENANT};
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use trail::recording_audit;
use types::TestResult;


const NIS2_CONTROLS: usize = 10;


const PG_PORT: u16 = 5432;


fn fresh(frameworks: &str) -> Result<(TempDir, Site), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let site = write_site(dir.path(), PG_PORT, "", frameworks)?;
    Ok((dir, site))
}


fn refused(site: &Site, text: &str, marker: &str) -> TestResult {
    fs::write(&site.settings_file, text)?;
    let error = load_declarations(&site.settings_file).err().ok_or("accepted")?;
    assert!(error.to_string().contains(marker), "{error}");
    Ok(())
}


fn changed(site: &Site, from: &str, to: &str) -> TestResult {
    let text = fs::read_to_string(&site.settings_file)?;
    fs::write(&site.settings_file, text.replace(from, to))?;
    Ok(())
}


#[test]
fn a_valid_site_loads_every_declaration() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let loaded = load_declarations(&site.settings_file)?;
    assert_eq!(loaded.frameworks.len(), 1);
    assert_eq!(loaded.frameworks.first().ok_or("none")?.controls.len(), NIS2_CONTROLS);
    assert_eq!(loaded.manual.len(), 1);
    assert_eq!(loaded.pg.host, "127.0.0.1");
    Ok(())
}


#[test]
fn each_setting_outside_its_range_is_refused_by_name() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let good = settings_text(&site, "[builtin:nis2]", INTERVAL);
    refused(&site, &good.replace("tenant: acme", "tenant: -x"), "tenant")?;
    refused(&site, &good.replace("interval_seconds: 300", "interval_seconds: 299"), "interval_seconds")?;
    refused(
        &site,
        &good.replace("interval_seconds: 300", "interval_seconds: 86401"),
        "interval_seconds",
    )?;
    refused(&site, &good.replace("[builtin:nis2]", "[]"), "frameworks")?;
    refused(&site, &good.replace("max_reports: 1000", "max_reports: 0"), "max_reports")?;
    refused(&site, &good.replace("max_reports: 1000", "max_reports: -5"), "max_reports")?;
    refused(&site, &good.replace("max_reports: 1000", "max_reports: 1001"), "max_reports")?;
    refused(&site, &good.replace("[builtin:nis2]", "[builtin:nis2, builtin:nis2]"), "listed twice")?;
    let many = format!("[{}]", ["builtin:nis2"; MAX_FRAMEWORKS + 1].join(", "));
    refused(&site, &good.replace("[builtin:nis2]", &many), "frameworks")?;
    refused(
        &site,
        &good.replace(&format!("audit_file: {}", site.audit_file.display()), "audit_file: audit.log"),
        "absolute",
    )?;
    refused(&site, &good.replace("tenant: acme", "tenant: acme\nsurprise: 1"), "unknown field")
}


#[test]
fn a_missing_audit_path_is_refused() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let text = settings_text(&site, "[builtin:nis2]", INTERVAL).replace(&format!("audit_file: {}\n", site.audit_file.display()), "");
    refused(&site, &text, "audit_file")
}


#[test]
fn a_bad_framework_or_manual_file_refuses_the_whole_load() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let good = settings_text(&site, "[builtin:nis2]", INTERVAL);
    refused(&site, &good.replace("builtin:nis2", "builtin:nope"), "nope")?;
    refused(&site, &good.replace("builtin:nis2", "/absent/framework.yaml"), "absent")?;
    let copy = site.dir.join("copy.yaml");
    fs::write(&copy, BUILTIN.first().ok_or("none")?.1)?;
    let twice = good.replace("[builtin:nis2]", &format!("[builtin:nis2, {}]", copy.display()));
    refused(&site, &twice, "same framework")?;
    fs::write(&site.settings_file, &good)?;
    fs::write(&site.manual_file, "evidence: nope\n")?;
    refused(&site, &good, "manual.yaml")?;
    fs::write(&site.manual_file, MANUAL_ACME.replace("tenant: acme", "tenant: globex"))?;
    refused(&site, &good, "another tenant")?;
    fs::write(
        &site.manual_file,
        format!("{MANUAL_ACME}{}", MANUAL_ACME.trim_start_matches("evidence:\n")),
    )?;
    refused(&site, &good, "given twice")?;
    fs::remove_file(&site.manual_file)?;
    refused(&site, &good, "manual.yaml")?;
    fs::write(&site.manual_file, MANUAL_ACME)?;
    fs::remove_file(&site.pg_file)?;
    refused(&site, &good, "pg.yaml")
}


#[test]
fn a_fifo_in_place_of_a_declaration_is_refused_not_waited_on() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    fs::remove_file(&site.manual_file)?;
    let status = std::process::Command::new("mkfifo").arg(&site.manual_file).status()?;
    assert!(status.success());
    let error = load_declarations(&site.settings_file).err().ok_or("accepted")?;
    assert!(error.to_string().contains("manual.yaml"), "{error}");
    Ok(())
}


fn declarations_of(site: &Site) -> Result<Declarations, Box<dyn std::error::Error>> {
    Ok(load_declarations(&site.settings_file)?)
}


#[test]
fn only_the_live_values_may_differ_from_the_start() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let base = declarations_of(&site)?;
    assert!(!start_only_changed(&base, &base));
    let mut live = base.clone();
    live.settings.interval_seconds += 1;
    live.settings.max_reports -= 1;
    live.settings.frameworks = vec!["builtin:gdpr".to_owned()];
    live.pg.statement_timeout_secs += 1;
    live.pg.connect_timeout_secs += 1;
    assert!(!start_only_changed(&base, &live));
    let mut tenant = base.clone();
    tenant.settings.tenant = "globex".to_owned();
    assert!(start_only_changed(&base, &tenant));
    let mut host = base.clone();
    host.pg.host = "attacker.example".to_owned();
    assert!(start_only_changed(&base, &host));
    let mut credential = base.clone();
    credential.pg.password_file = "/other".to_owned();
    assert!(start_only_changed(&base, &credential));
    Ok(())
}


#[test]
fn the_state_names_settings_frameworks_and_manual_records() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let state = declarations_state(&declarations_of(&site)?);
    assert_eq!(state.get("tenant").map(String::as_str), Some(TENANT));
    assert!(state.contains_key("framework.nis2"));
    assert!(state.contains_key("manual.art21-2-a"));
    assert!(state.contains_key("pg.host"));
    Ok(())
}


#[test]
fn the_watch_covers_the_settings_the_database_the_manual_and_each_framework_file() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let copy = site.dir.join("other.yaml");
    fs::write(&copy, BUILTIN.get(1).ok_or("none")?.1)?;
    fs::write(
        &site.settings_file,
        settings_text(&site, &format!("[builtin:nis2, {}]", copy.display()), INTERVAL),
    )?;
    let files = watched_files(&site.settings_file, &declarations_of(&site)?);
    assert_eq!(
        files,
        vec![site.settings_file.clone(), site.pg_file.clone(), site.manual_file.clone(), copy]
    );
    Ok(())
}


fn real_reader() -> DeclarationsReader {
    Arc::new(|file: &Path| load_declarations(file))
}


#[test]
fn a_reload_applies_a_live_change_and_wakes_the_loop_and_refuses_a_start_only_change_audited_as_denied() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let (trail, audit) = recording_audit();
    let signals = Arc::new(Signals::default());
    let engine = open_declarations(&site.settings_file, real_reader(), declarations_of(&site)?, audit, Arc::clone(&signals))?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    changed(&site, "interval_seconds: 300", "interval_seconds: 400")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert!(signals.applied.load(Ordering::SeqCst));
    fs::write(&site.manual_file, MANUAL_ACME.replace("ciso", "dpo"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys == vec!["manual.art21-2-a".to_owned()]));
    fs::write(&site.pg_file, fs::read_to_string(&site.pg_file)?.replace("127.0.0.1", "attacker.example"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("start-only")));
    let lines = trail.lock().map_err(|_poisoned| "poisoned")?.clone();
    assert_eq!(lines, vec!["all|Success|applied", "all|Success|applied", "all|Denied|refused"]);
    Ok(())
}


#[test]
fn a_swap_between_the_start_read_and_the_engine_open_is_refused() -> TestResult {
    let (_dir, site) = fresh("[builtin:nis2]")?;
    let baseline = declarations_of(&site)?;
    fs::write(&site.pg_file, fs::read_to_string(&site.pg_file)?.replace("127.0.0.1", "attacker.example"))?;
    let (_trail, audit) = recording_audit();
    let refusal = open_declarations(&site.settings_file, real_reader(), baseline, audit, Arc::new(Signals::default()))
        .err()
        .ok_or("accepted")?;
    assert!(refusal.to_string().contains("start-only"), "{refusal}");
    Ok(())
}
