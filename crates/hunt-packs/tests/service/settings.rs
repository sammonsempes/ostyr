use crate::types::TestResult;
use core_audit::log::{append, genesis_log};
use core_config::reload::{current_config, reload, ReloadContext, ReloadOutcome};
use hunt_packs::settings::{hunt_state, open_hunt, open_hunt_from, tick_limits, validate_hunt, HuntSettings, HuntSettingsError, OpenError};
use hunt_packs::tick::DEFAULT_MAX_TENANTS;
use std::fs;
use std::io;


const MINUTE: u64 = 60;


const TOO_SHORT: u64 = 9;


const TOO_LONG: u64 = 3_601;


const BASE: &str = "pg_settings: /p\nclickhouse_settings: /c\npacks_dir: /d\naudit_file: /a/audit.log\ntenants: [a]\n";


fn settings() -> HuntSettings {
    HuntSettings {
        pg_settings: "/p".into(),
        clickhouse_settings: "/c".into(),
        packs_dir: "/d".into(),
        audit_file: "/a/audit.log".into(),
        tenants: vec!["a".to_owned()],
        tick_seconds: MINUTE,
        grace_seconds: 0,
        max_runs_per_tick: 1,
        stat_hunts: Vec::new(),
    }
}


fn open_text(text: &str) -> Result<(), OpenError> {
    let dir = tempfile::tempdir().map_err(|error| {
        OpenError::Config(core_config::error::ConfigError::Io {
            file: "tmp".to_owned(),
            source: error,
        })
    })?;
    let file = dir.path().join("hunt.yaml");
    fs::write(&file, text).map_err(|error| {
        OpenError::Config(core_config::error::ConfigError::Io {
            file: "hunt.yaml".to_owned(),
            source: error,
        })
    })?;
    let log = genesis_log(io::sink());
    let context = ReloadContext {
        actor_id: "t".to_owned(),
        tenant: "t".to_owned(),
        module: "t".to_owned(),
        target: "t".to_owned(),
        request_id: "t".to_owned(),
    };
    open_hunt(file, Box::new(move |entry| append(&log, entry)), context).map(drop)
}


#[test]
fn validation_names_the_refused_bound() -> TestResult {
    assert!(validate_hunt(&settings()).is_ok());
    assert!(matches!(
        validate_hunt(&HuntSettings {
            tick_seconds: TOO_SHORT,
            ..settings()
        }),
        Err(HuntSettingsError::TickSeconds)
    ));
    assert!(matches!(
        validate_hunt(&HuntSettings {
            tick_seconds: TOO_LONG,
            ..settings()
        }),
        Err(HuntSettingsError::TickSeconds)
    ));
    assert!(matches!(
        validate_hunt(&HuntSettings {
            grace_seconds: -1,
            ..settings()
        }),
        Err(HuntSettingsError::Grace)
    ));
    assert!(matches!(
        validate_hunt(&HuntSettings {
            audit_file: "audit.log".into(),
            ..settings()
        }),
        Err(HuntSettingsError::AuditFile)
    ));
    let many = (0..=DEFAULT_MAX_TENANTS).map(|index| format!("t{index}")).collect();
    assert!(matches!(
        validate_hunt(&HuntSettings { tenants: many, ..settings() }),
        Err(HuntSettingsError::Limits(_))
    ));
    Ok(())
}


#[test]
fn the_limits_and_the_state_follow_the_settings() -> TestResult {
    let limits = tick_limits(&settings());
    assert_eq!((limits.grace_seconds, limits.max_runs_per_tick), (0, 1));
    assert_eq!(hunt_state(&settings()).get("tick_seconds").map(String::as_str), Some("60"));
    Ok(())
}


#[test]
fn opening_refuses_unknown_keys_bad_bounds_and_a_missing_file() -> TestResult {
    assert!(open_text(&format!("{BASE}tick_seconds: 60\n")).is_ok());
    assert!(matches!(
        open_text(&format!("{BASE}tick_seconds: 60\nextra: 1\n")),
        Err(OpenError::Config(_))
    ));
    assert!(matches!(
        open_text("pg_settings: /p\nclickhouse_settings: /c\npacks_dir: /d\ntenants: [a]\ntick_seconds: 60\n"),
        Err(OpenError::Config(_))
    ));
    assert!(matches!(open_text(&format!("{BASE}tick_seconds: 1\n")), Err(OpenError::Invalid(_))));
    Ok(())
}


#[test]
fn the_engine_baseline_is_the_value_the_caller_read_not_a_second_read() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("hunt.yaml");
    let swapped = BASE.replace("/a/audit.log", "/b/audit.log");
    fs::write(&file, format!("{swapped}tick_seconds: 60\n"))?;
    let log = genesis_log(io::sink());
    let context = ReloadContext {
        actor_id: "t".to_owned(),
        tenant: core_audit::tenant::AUDIT_TENANT.to_owned(),
        module: "t".to_owned(),
        target: "t".to_owned(),
        request_id: "t".to_owned(),
    };
    let engine = open_hunt_from(file, settings(), Box::new(move |entry| append(&log, entry)), context)?;
    assert_eq!(current_config(&engine).audit_file, settings().audit_file);
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).audit_file, settings().audit_file);
    Ok(())
}


const STAT_HUNTS: &str = "stat_hunts:
  - id: rare-process
    statistic:
      rarity:
        max_entities: 1
    query: SELECT host, process FROM events WHERE tenant = {tenant:String} AND t >= {window_start:DateTime64(3)} AND t < {window_end:DateTime64(3)}
    schedule_seconds: 3600
    window_seconds: 3600
    cost:
      max_rows: 1000
      max_seconds: 10
      max_bytes_read: 1000000
    max_rows: 100
  - id: beacon
    statistic:
      beaconing:
        min_regularity_ppm: 900000
    query: SELECT pair, toUnixTimestamp(t) FROM events WHERE tenant = {tenant:String} AND t >= {window_start:DateTime64(3)} AND t < {window_end:DateTime64(3)}
    schedule_seconds: 3600
    window_seconds: 3600
    cost:
      max_rows: 1000
      max_seconds: 10
      max_bytes_read: 1000000
    max_rows: 100
    max_matches: 2
";


#[test]
fn statistical_hunts_are_read_validated_and_shown_in_the_state() -> TestResult {
    assert!(open_text(&format!("{BASE}tick_seconds: 60\n{STAT_HUNTS}")).is_ok());
    let broken = STAT_HUNTS.replace("max_entities: 1", "max_entities: 0");
    assert!(matches!(
        open_text(&format!("{BASE}tick_seconds: 60\n{broken}")),
        Err(OpenError::Invalid(HuntSettingsError::StatHunt("statistic")))
    ));
    let unknown = STAT_HUNTS.replace("max_rows: 100\n  - id", "max_rows: 100\n    extra: 1\n  - id");
    assert!(matches!(
        open_text(&format!("{BASE}tick_seconds: 60\n{unknown}")),
        Err(OpenError::Config(_))
    ));
    let tagged = STAT_HUNTS.replace("rarity:", "!Rarity");
    assert!(open_text(&format!("{BASE}tick_seconds: 60\n{tagged}")).is_err());
    assert!(hunt_state(&settings()).contains_key("stat_hunts"));
    Ok(())
}
