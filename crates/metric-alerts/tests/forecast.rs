mod common;


use common::types::TestResult;
use core_config::parse::parse_document;
use metric_alerts::error::RuleError;
use metric_alerts::evaluate::{evaluate, evaluate_with_capacity};
use metric_alerts::forecast::{fit, forecast, forecast_holds, window_points, Forecast};
use metric_alerts::model::{Capacity, Condition, Rule};
use metric_alerts::rules::{parse_rules, validate_rule};
use metric_alerts::state::AlertState;
use metric_alerts::types::{Point, Timestamp};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;


const MIN_POINTS: usize = 3;


const TOO_MANY_POINTS: usize = 6;


const NO_POINTS: usize = 0;


const CAPACITY: f64 = 100.0;


const HORIZON: u64 = 10_000;


const SHORT_HORIZON: u64 = 1;


const MIN_CONFIDENCE: f64 = 0.9;


const ANY_CONFIDENCE: f64 = 0.0;


const FULL_CONFIDENCE: f64 = 1.0;


const NOW: u64 = 400;


const EARLY_NOW: u64 = 250;


const PROJECTED_AT: u64 = 600;


const WINDOW: u64 = 200;


const FILE: &str = "rules.yaml";


pub fn series(name: &str) -> Result<Vec<Point>, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("forecast_series.yaml");
    let all: BTreeMap<String, Vec<Point>> = parse_document(&fs::read_to_string(&path)?, "forecast_series")?;
    Ok(all.get(name).ok_or("unknown series")?.clone())
}


pub fn rule_text(capacity: &str, window: &str, min_points: &str) -> String {
    format!(
        "rules:\n  - id: disk-full\n    metric: disk.used\n    condition: {{kind: forecast, window: {window}, capacity: {capacity}, horizon: 10000, \
         min_confidence: 0.9, min_points: {min_points}}}\n    close_after: 60\n    severity: high\n    runbook: https://runbooks.example.org/disk\n"
    )
}


pub fn rule_of(capacity: &str) -> Result<Rule, Box<dyn Error>> {
    let parsed = parse_rules(&mut rule_text(capacity, "1000", "3").as_bytes(), FILE)?;
    Ok(parsed.rules.first().ok_or("no rule")?.clone())
}


pub fn invalid(text: &str) -> bool {
    matches!(
        parse_rules(&mut text.as_bytes(), FILE),
        Err(RuleError::Invalid { field: "condition", .. })
    )
}


#[test]
fn known_ramp_projects_the_exact_date() -> TestResult {
    assert_eq!(
        forecast(&series("ramp")?, CAPACITY, MIN_POINTS),
        Forecast::Projected {
            at: PROJECTED_AT,
            confidence: FULL_CONFIDENCE
        }
    );
    Ok(())
}


#[test]
fn noise_lowers_the_confidence() -> TestResult {
    let line = fit(&series("noisy")?).ok_or("no fit")?;
    assert!(line.confidence < MIN_CONFIDENCE);
    assert!(!forecast_holds(&series("noisy")?, CAPACITY, (HORIZON, MIN_CONFIDENCE, MIN_POINTS), NOW));
    assert!(forecast_holds(&series("ramp")?, CAPACITY, (HORIZON, MIN_CONFIDENCE, MIN_POINTS), NOW));
    Ok(())
}


#[test]
fn degenerate_series_have_a_defined_result() -> TestResult {
    let result = |name: &str| series(name).map(|points| forecast(&points, CAPACITY, MIN_POINTS));
    assert_eq!(forecast(&series("ramp")?, CAPACITY, TOO_MANY_POINTS), Forecast::TooFewPoints);
    assert_eq!(forecast(&[], CAPACITY, NO_POINTS), Forecast::TooFewPoints);
    assert_eq!(result("flat")?, Forecast::NotGrowing);
    assert_eq!(result("shrinking")?, Forecast::NotGrowing);
    assert_eq!(result("same_time")?, Forecast::NotGrowing);
    assert_eq!(result("reached")?, Forecast::AlreadyReached);
    assert!(fit(&series("overflow")?).is_none());
    let limits = (SHORT_HORIZON, FULL_CONFIDENCE, MIN_POINTS);
    assert!(forecast_holds(&series("reached")?, CAPACITY, limits, NOW));
    assert!(!forecast_holds(&[], CAPACITY, (HORIZON, ANY_CONFIDENCE, MIN_POINTS), NOW));
    assert!(!forecast_holds(&series("flat")?, CAPACITY, (HORIZON, ANY_CONFIDENCE, MIN_POINTS), NOW));
    Ok(())
}


#[test]
fn horizon_bounds_the_projection() -> TestResult {
    let ramp = series("ramp")?;
    let holds = |horizon: u64| forecast_holds(&ramp, CAPACITY, (horizon, MIN_CONFIDENCE, MIN_POINTS), NOW);
    assert!(holds(PROJECTED_AT - NOW));
    assert!(!holds(PROJECTED_AT - NOW - 1));
    Ok(())
}


#[test]
fn window_keeps_recent_points_sorted() -> TestResult {
    let reversed = series("ramp_reversed")?;
    assert_eq!(window_points(&reversed, WINDOW, NOW), series("window_late")?);
    let early: Timestamp = EARLY_NOW;
    assert_eq!(window_points(&reversed, HORIZON, early), series("window_early")?);
    Ok(())
}


#[test]
fn fixed_capacity_rule_fires_through_evaluate() -> TestResult {
    let rule = rule_of("{source: fixed, value: 100}")?;
    assert!(matches!(rule.condition, Condition::Forecast { .. }));
    let ramp = series("ramp")?;
    assert_eq!(evaluate(&rule, &ramp, &AlertState::default(), NOW), AlertState::Firing { since: NOW });
    assert_eq!(
        evaluate(&rule, &ramp, &AlertState::Pending { since: PROJECTED_AT }, NOW),
        AlertState::Firing { since: PROJECTED_AT }
    );
    assert_eq!(evaluate(&rule, &series("noisy")?, &AlertState::default(), NOW), AlertState::Inactive);
    Ok(())
}


#[test]
fn metric_capacity_needs_its_value() -> TestResult {
    let rule = rule_of("{source: metric, name: disk.size}")?;
    assert!(matches!(
        rule.condition,
        Condition::Forecast {
            capacity: Capacity::Metric { .. },
            ..
        }
    ));
    let ramp = series("ramp")?;
    assert_eq!(evaluate(&rule, &ramp, &AlertState::default(), NOW), AlertState::Inactive);
    let state = evaluate_with_capacity(&rule, &ramp, Some(CAPACITY), &AlertState::default(), NOW);
    assert_eq!(state, AlertState::Firing { since: NOW });
    Ok(())
}


#[test]
fn forecast_rule_bounds_are_validated() -> TestResult {
    let good = "{source: fixed, value: 100}";
    assert!(invalid(&rule_text(good, "0", "3")));
    assert!(invalid(&rule_text(good, "1000", "1")));
    assert!(invalid(&rule_text(good, "1000", "100001")));
    assert!(invalid(&rule_text("{source: metric, name: ''}", "1000", "3")));
    assert!(invalid(&rule_text(good, "1000", "3").replace("horizon: 10000", "horizon: 0")));
    assert!(invalid(
        &rule_text(good, "1000", "3").replace("min_confidence: 0.9", "min_confidence: 1.5")
    ));
    let mut rule = rule_of(good)?;
    rule.condition = Condition::Forecast {
        window: WINDOW,
        capacity: Capacity::Fixed { value: f64::INFINITY },
        horizon: HORIZON,
        min_confidence: MIN_CONFIDENCE,
        min_points: MIN_POINTS,
    };
    assert!(validate_rule(FILE, &rule).is_err());
    Ok(())
}
