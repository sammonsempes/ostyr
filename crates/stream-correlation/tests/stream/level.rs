use crate::support::{bench, failed_login, feed, ruleset, BRUTE_FORCE, LOGIN, SEC_2};
use crate::types::TestResult;
use std::fs;
use stream_correlation::checkpoint::load_checkpoint;
use stream_correlation::error::CorrelationError;
use stream_correlation::level::{check_title, highest, parse_level, Level, DEFAULT_LEVEL, LEVELS, MAX_TITLE_CHARS};


const BASE_WITH_LEVEL: &str = "title: Leveled
id: leveled
level: high
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: x
  condition: selection
";


const CORRELATION_TEMPLATE: &str = "id: corr
correlation:
  type: event_count
  rules:
    - leveled
  timespan: 5m
  condition:
    gte: 1
";


const LEVEL_COUNT: usize = 5;


const CHECKPOINT_WATERMARK: i64 = 7;


const OLD_CHECKPOINT: &str = r#"{"version":1,"state":{"watermark_ms":7,"counters":{"processed":1,"invalid":0,"late":0,"dropped_events":0,"dropped_groups":0,"alerts":0},"rules":{}}}"#;


fn correlation(extra: &str) -> String {
    format!("{extra}{CORRELATION_TEMPLATE}")
}


fn base_with(header: &str) -> String {
    format!("{header}\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: x\n  condition: selection\n")
}


fn refusal(documents: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    match ruleset(documents) {
        Ok(_) => Err("rules were accepted".into()),
        Err(error) => Ok(error.to_string()),
    }
}


#[test]
fn every_sigma_level_parses() -> TestResult {
    assert_eq!(LEVELS.len(), LEVEL_COUNT);
    LEVELS
        .iter()
        .try_for_each(|(name, level)| parse_level("r", Some(name)).map(|parsed| assert_eq!(parsed, Some(*level))))?;
    assert_eq!(parse_level("r", None)?, None);
    assert!(Level::Critical > Level::High && Level::Low > Level::Informational);
    Ok(())
}


#[test]
fn an_unknown_level_is_refused_without_its_text() -> TestResult {
    let error = parse_level("r", Some("urgent-secret")).err().ok_or("accepted")?;
    assert!(matches!(error, CorrelationError::Invalid { .. }));
    assert!(!error.to_string().contains("urgent-secret"));
    Ok(())
}


#[test]
fn titles_are_bounded_and_clean() -> TestResult {
    check_title("r", &"a".repeat(MAX_TITLE_CHARS))?;
    assert!(check_title("r", &"a".repeat(MAX_TITLE_CHARS + 1)).is_err());
    assert!(check_title("r", "bad\u{1b}[31m").is_err());
    Ok(())
}


#[test]
fn an_empty_title_is_refused_for_both_rule_kinds() -> TestResult {
    ["\"\"", "\"   \""].iter().try_for_each(|title| -> TestResult {
        let base = refusal(&[&base_with(&format!("title: {title}\nid: named"))])?;
        assert!(base.contains("named") && base.contains("empty"));
        let corr = refusal(&[BASE_WITH_LEVEL, &correlation(&format!("title: {title}\n"))])?;
        assert!(corr.contains("corr") && corr.contains("empty"));
        Ok(())
    })?;
    assert!(check_title("r", " ").is_err());
    Ok(())
}


#[test]
fn highest_picks_the_most_severe_or_the_default() -> TestResult {
    assert_eq!(highest([Level::Low, Level::Critical, Level::High].into_iter()), Level::Critical);
    assert_eq!(highest(std::iter::empty()), DEFAULT_LEVEL);
    Ok(())
}


#[test]
fn base_rules_carry_their_level() -> TestResult {
    let set = ruleset(&[BASE_WITH_LEVEL, &base_with("title: Plain\nid: plain")])?;
    assert_eq!(
        set.bases.iter().map(|base| base.level).collect::<Vec<_>>(),
        vec![Level::High, DEFAULT_LEVEL]
    );
    Ok(())
}


#[test]
fn a_bad_base_level_or_title_is_refused() -> TestResult {
    assert!(refusal(&[&base_with("title: T\nlevel: shouting")])?.contains("level"));
    assert!(refusal(&[&base_with("title: \"T\\x07\"\nid: named")])?.contains("title"));
    assert!(refusal(&[&base_with("title: \"T\\x07\"")])?.contains("untitled"));
    Ok(())
}


#[test]
fn a_correlation_rule_inherits_the_highest_referenced_level() -> TestResult {
    let second = base_with("title: Low one\nid: lowone\nlevel: low");
    let text = "id: corr\ncorrelation:\n  type: temporal\n  rules:\n    - leveled\n    - lowone\n  timespan: 5m\n";
    let set = ruleset(&[BASE_WITH_LEVEL, &second, text])?;
    let rule = set.correlations.first().ok_or("no rule")?;
    assert_eq!(rule.level, Level::High);
    assert_eq!(rule.title, "corr");
    Ok(())
}


#[test]
fn a_correlation_rule_keeps_its_own_level_and_title() -> TestResult {
    let set = ruleset(&[BASE_WITH_LEVEL, &correlation("title: Mine\nlevel: low\n")])?;
    let rule = set.correlations.first().ok_or("no rule")?;
    assert_eq!((rule.level, rule.title.as_str()), (Level::Low, "Mine"));
    Ok(())
}


#[test]
fn a_correlation_without_id_or_title_is_untitled() -> TestResult {
    let text = CORRELATION_TEMPLATE.replace("id: corr\n", "");
    let set = ruleset(&[BASE_WITH_LEVEL, &text])?;
    assert_eq!(set.correlations.first().map(|rule| rule.title.clone()), Some("untitled".to_string()));
    Ok(())
}


#[test]
fn a_bad_correlation_level_or_title_is_refused() -> TestResult {
    assert!(refusal(&[BASE_WITH_LEVEL, &correlation("title: C\nlevel: shouting\n")])?.contains("level"));
    assert!(refusal(&[BASE_WITH_LEVEL, &correlation("title: \"C\\x07\"\n")])?.contains("title"));
    Ok(())
}


#[test]
fn alerts_carry_the_level_and_print_it() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    feed(&bench.engine, &failed_login(0, "a", "h1"));
    feed(&bench.engine, &failed_login(1, "b", "h1"));
    let alerts = feed(&bench.engine, &failed_login(SEC_2, "c", "h1"));
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alert.level, DEFAULT_LEVEL);
    assert!(serde_json::to_string(alert)?.contains("\"level\":\"medium\""));
    Ok(())
}


#[test]
fn an_old_checkpoint_still_loads() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    fs::write(&bench.checkpoint, OLD_CHECKPOINT)?;
    let state = load_checkpoint(&bench.checkpoint)?.ok_or("no state")?;
    assert_eq!(state.watermark_ms, Some(CHECKPOINT_WATERMARK));
    Ok(())
}
