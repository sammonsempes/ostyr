#[path = "common/engine.rs"]
mod engine;
#[path = "common/types.rs"]
mod types;


use core_config::reload::{current_config, reload, ReloadOutcome};
use engine::{engine_for, feeds_text, replace_file};
use intel_feeds::config::{validate_feeds, validate_retro_section, FeedsError, FeedsFile, OpenError, RetroSection, RetroSectionError};
use intel_feeds::limits::{
    MAX_RETRO_INTERVAL_SECONDS, MAX_RETRO_MARGIN_SECONDS, MAX_RETRO_MATCHES, MAX_RETRO_WINDOW_SECONDS, MIN_RETRO_INTERVAL_SECONDS,
};
use tempfile::tempdir;
use types::TestResult;


const INTERVAL: u64 = 600;


const WINDOW: u64 = 900;


const TOO_SHORT: u64 = 599;


const FASTER: u64 = 300;


const WIDER: u64 = 700;


const DEFAULT_MARGIN: u64 = 300;


fn retro_text(interval: u64, window: u64, pg: &str) -> String {
    feeds_text(&format!(
        "retro:\n  reader:\n    url: http://127.0.0.1:8123\n    user: reader\n    password_file: /nonexistent/password\n    database: ostyr\n    \
         table: iocs\n    dictionary: ioc_trie\n    tenant: tenant-a\n  events_database: ostyr\n  events_table: events\n  interval_seconds: {interval}\n  \
         window_seconds: {window}\n  pg_settings: {pg}\n"
    ))
}


fn section_of(text: &str) -> Result<RetroSection, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, text)?;
    let loaded = current_config(&engine_for(&path)?);
    Ok(loaded.retro.clone().ok_or("no retro section")?)
}


#[test]
fn defaults_fill_the_budget_and_the_margin() -> TestResult {
    let section = section_of(&retro_text(INTERVAL, WINDOW, "pg.yaml"))?;
    assert_eq!(section.max_matches, MAX_RETRO_MATCHES);
    assert_eq!(section.margin_seconds, DEFAULT_MARGIN);
    assert!(validate_retro_section(&section).is_ok());
    assert!(FeedsFile::default().retro.is_none());
    Ok(())
}


#[test]
fn interval_margin_window_and_file_are_bounded() -> TestResult {
    let base = section_of(&retro_text(INTERVAL, WINDOW, "pg.yaml"))?;
    let with = |edit: &dyn Fn(&mut RetroSection)| {
        let mut changed = base.clone();
        edit(&mut changed);
        validate_retro_section(&changed)
    };
    assert!(matches!(
        with(&|edited| edited.interval_seconds = MIN_RETRO_INTERVAL_SECONDS - 1),
        Err(RetroSectionError::Interval)
    ));
    assert!(matches!(
        with(&|edited| edited.interval_seconds = MAX_RETRO_INTERVAL_SECONDS + 1),
        Err(RetroSectionError::Interval)
    ));
    assert!(matches!(with(&|edited| edited.margin_seconds = 0), Err(RetroSectionError::Margin)));
    assert!(matches!(
        with(&|edited| edited.margin_seconds = MAX_RETRO_MARGIN_SECONDS + 1),
        Err(RetroSectionError::Margin)
    ));
    assert!(matches!(
        with(&|edited| edited.window_seconds = edited.interval_seconds),
        Err(RetroSectionError::Window)
    ));
    assert!(matches!(
        with(&|edited| edited.window_seconds = edited.interval_seconds + edited.margin_seconds - 1),
        Err(RetroSectionError::Window)
    ));
    assert!(with(&|edited| edited.window_seconds = edited.interval_seconds + edited.margin_seconds).is_ok());
    assert!(matches!(
        with(&|edited| {
            edited.interval_seconds = MAX_RETRO_INTERVAL_SECONDS;
            edited.window_seconds = MAX_RETRO_WINDOW_SECONDS + 1;
        }),
        Err(RetroSectionError::Window)
    ));
    assert!(matches!(
        with(&|edited| edited.pg_settings = "".into()),
        Err(RetroSectionError::PgSettings)
    ));
    assert!(matches!(with(&|edited| edited.max_matches = 0), Err(RetroSectionError::Settings(_))));
    assert!(matches!(
        with(&|edited| edited.interval_seconds = u64::MAX),
        Err(RetroSectionError::Interval)
    ));
    Ok(())
}


#[test]
fn a_feeds_file_with_a_bad_retro_section_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &retro_text(INTERVAL, INTERVAL, "pg.yaml"))?;
    assert!(matches!(
        engine_for(&path),
        Err(OpenError::Invalid(FeedsError::Retro(RetroSectionError::Window)))
    ));
    replace_file(&path, &format!("{}  surprise: 1\n", retro_text(INTERVAL, WINDOW, "pg.yaml")))?;
    assert!(matches!(engine_for(&path), Err(OpenError::Config(_))));
    let good = section_of(&retro_text(INTERVAL, WINDOW, "pg.yaml"))?;
    let file = FeedsFile {
        retro: Some(good),
        ..FeedsFile::default()
    };
    assert!(validate_feeds(&file).is_ok());
    Ok(())
}


#[test]
fn a_shorter_window_is_refused_live_and_the_old_settings_are_kept() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &retro_text(INTERVAL, WINDOW, "pg.yaml"))?;
    let engine = engine_for(&path)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    replace_file(&path, &retro_text(INTERVAL, TOO_SHORT, "pg.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).retro.as_ref().map(|edited| edited.window_seconds), Some(WINDOW));
    replace_file(&path, &retro_text(FASTER, WIDER, "pg.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys == vec!["retro".to_owned()]));
    assert_eq!(current_config(&engine).retro.as_ref().map(|edited| edited.interval_seconds), Some(FASTER));
    Ok(())
}


#[test]
fn the_postgres_settings_path_is_read_at_start_only() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &retro_text(INTERVAL, WINDOW, "pg.yaml"))?;
    let engine = engine_for(&path)?;
    replace_file(&path, &retro_text(FASTER, WINDOW, "other.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("start only")));
    assert_eq!(
        current_config(&engine).retro.as_ref().map(|edited| edited.pg_settings.clone()),
        Some("pg.yaml".into())
    );
    replace_file(&path, &feeds_text(""))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("start only")));
    replace_file(&path, &retro_text(FASTER, WINDOW, "pg.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    Ok(())
}


#[test]
fn a_file_started_without_retro_refuses_a_later_retro_section() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(""))?;
    let engine = engine_for(&path)?;
    replace_file(&path, &retro_text(INTERVAL, WINDOW, "pg.yaml"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("start only")));
    Ok(())
}
