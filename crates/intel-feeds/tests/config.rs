#[path = "common/engine.rs"]
mod engine;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use core_config::load::load_file;
use core_config::reload::{current_config, reload, ReloadOutcome};
use engine::{engine_for, feeds_text, replace_file};
use fixtures::fixture;
use intel_feeds::config::{feeds_state, validate_feeds, FeedFormat, FeedsError, FeedsFile, OpenError};
use intel_feeds::limits::{DEFAULT_CONFIDENCE, MAX_CONFIDENCE};
use intel_feeds::model::Tlp;
use support::feed;
use tempfile::tempdir;
use types::TestResult;


const ONE_DAY: u32 = 86_400;


const TWO_FEEDS: usize = 2;


const FIXTURE_FEEDS: usize = 7;


const SECOND_FEED: &str = "  - name: extra\n    format: crowdsec\n    path: extra.txt\n";


#[test]
fn the_fixture_file_loads_and_validates() -> TestResult {
    let config: FeedsFile = load_file(&fixture("feeds.yaml"))?;
    assert_eq!(config.feeds.len(), FIXTURE_FEEDS);
    validate_feeds(&config)?;
    let threatfox = config
        .feeds
        .iter()
        .find(|candidate| candidate.name == "threatfox")
        .ok_or("no threatfox")?;
    assert_eq!((threatfox.tlp, threatfox.ttl_seconds), (Tlp::Green, Some(ONE_DAY)));
    assert_eq!(feeds_state(&config).len(), FIXTURE_FEEDS + 1);
    Ok(())
}


#[test]
fn defaults_apply_to_a_minimal_feed() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(""))?;
    let engine = engine_for(&path)?;
    let config = current_config(&engine);
    let only = config.feeds.first().ok_or("no feed")?;
    assert_eq!(
        (only.tlp, only.default_confidence, only.ttl_seconds),
        (Tlp::Amber, DEFAULT_CONFIDENCE, None)
    );
    assert!(only.version.is_none() && only.mapping.value.is_none());
    Ok(())
}


#[test]
fn an_invalid_first_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text("    surprise: true\n"))?;
    assert!(matches!(engine_for(&path), Err(OpenError::Config(_))));
    replace_file(&path, &feeds_text("    default_confidence: 101\n"))?;
    assert!(matches!(engine_for(&path), Err(OpenError::Invalid(FeedsError::Confidence(_)))));
    Ok(())
}


#[test]
fn validation_names_the_offending_feed() -> TestResult {
    let named = |name: &str, format: FeedFormat| feed(name, format);
    let with = |feeds| FeedsFile {
        feeds,
        ..FeedsFile::default()
    };
    assert!(matches!(
        validate_feeds(&with(vec![named("a", FeedFormat::Crowdsec), named("a", FeedFormat::Crowdsec)])),
        Err(FeedsError::Name(name)) if name == "a"
    ));
    assert!(matches!(
        validate_feeds(&with(vec![named("", FeedFormat::Crowdsec)])),
        Err(FeedsError::Name(_))
    ));
    let mut confident = named("c", FeedFormat::Crowdsec);
    confident.default_confidence = MAX_CONFIDENCE + 1;
    assert!(matches!(validate_feeds(&with(vec![confident])), Err(FeedsError::Confidence(_))));
    assert!(matches!(
        validate_feeds(&with(vec![named("m", FeedFormat::Csv)])),
        Err(FeedsError::MappingValue(_))
    ));
    assert!(matches!(
        validate_feeds(&with(vec![named("m", FeedFormat::Json)])),
        Err(FeedsError::MappingValue(_))
    ));
    assert!(validate_feeds(&with(vec![named("m", FeedFormat::Stix)])).is_ok());
    assert!(validate_feeds(&with(Vec::new())).is_ok());
    Ok(())
}


#[test]
fn a_new_feed_is_applied_without_restart_and_a_bad_file_keeps_the_old_one() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(""))?;
    let engine = engine_for(&path)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    replace_file(&path, &feeds_text(SECOND_FEED))?;
    assert_eq!(
        reload(&engine),
        ReloadOutcome::Applied {
            keys: vec!["feeds.extra".to_owned()]
        }
    );
    assert_eq!(current_config(&engine).feeds.len(), TWO_FEEDS);
    replace_file(&path, &feeds_text("  - name: broken\n    format: csv\n    path: b.csv\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("broken")));
    replace_file(&path, "feeds: [\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).feeds.len(), TWO_FEEDS);
    Ok(())
}
