mod common;


use common::types::TestResult;
use core_config::parse::parse_document;
use metric_alerts::error::RuleError;
use metric_alerts::model::Rule;
use metric_alerts::state::{phase_name, AlertState};
use metric_alerts::types::{Labels, Point, Timestamp};
use metric_alerts::windows::{evaluate_in_windows, hold_until, since_breach, to_datetime, window_end, TenantWindows, WindowScope};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;


const TENANT: &str = "acme";


const PROBE_AT: Timestamp = 150;


const SECOND_END: Timestamp = 360;


const WINDOW_END: Timestamp = 300;


const MINUTE: i64 = 60;


const MINUTE_UNSIGNED: u64 = 60;


const BREACH_VALUE: f64 = 95.0;


const AFTER_WINDOW_STEP: usize = 3;


const FIRED_STEP: usize = 5;


const EARLY: Timestamp = 1;


const LATE: Timestamp = 9;


const MIDDLE: Timestamp = 5;


#[derive(Deserialize)]
pub struct Step {
    pub at: Timestamp,
    pub expect: String,
    pub suppressed: bool,
}


#[derive(Deserialize)]
pub struct Scenario {
    pub rule: Rule,
    pub labels: Labels,
    pub points: Vec<Point>,
    pub windows: Vec<TenantWindows>,
    pub steps: Vec<Step>,
}


pub fn load(name: &str) -> Result<Scenario, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("{name}.yaml"));
    Ok(parse_document(&fs::read_to_string(&path)?, name)?)
}


pub fn replay(scenario: &Scenario) -> Result<Vec<(AlertState, bool)>, RuleError> {
    let scope = WindowScope {
        tenant: TENANT,
        labels: &scenario.labels,
        sets: &scenario.windows,
    };
    let mut state = AlertState::default();
    scenario
        .steps
        .iter()
        .map(|step| {
            let visible: Vec<Point> = scenario.points.iter().filter(|point| point.0 <= step.at).copied().collect();
            let evaluation = evaluate_in_windows(&scenario.rule, &visible, &state, step.at, &scope)?;
            state = evaluation.state;
            Ok((evaluation.state, evaluation.suppressed))
        })
        .collect()
}


pub fn check(name: &str) -> TestResult {
    let scenario = load(name)?;
    let observed: Vec<(&str, bool)> = replay(&scenario)?.iter().map(|step| (phase_name(&step.0), step.1)).collect();
    let expected: Vec<(&str, bool)> = scenario.steps.iter().map(|step| (step.expect.as_str(), step.suppressed)).collect();
    assert_eq!(observed, expected);
    Ok(())
}


#[test]
fn breach_inside_a_window_does_not_fire() -> TestResult {
    check("win_breach")
}


#[test]
fn breach_continuing_after_the_window_fires_after_hold_for_from_its_end() -> TestResult {
    let states = replay(&load("win_breach")?)?;
    assert_eq!(
        states.get(AFTER_WINDOW_STEP).map(|step| step.0),
        Some(AlertState::Pending { since: WINDOW_END })
    );
    assert_eq!(states.get(FIRED_STEP).map(|step| step.0), Some(AlertState::Firing { since: WINDOW_END }));
    Ok(())
}


#[test]
fn firing_alert_entering_a_window_stays_firing_and_suppressed() -> TestResult {
    check("win_firing")
}


#[test]
fn window_of_another_tenant_is_ignored() -> TestResult {
    check("win_other_tenant")
}


#[test]
fn series_without_asset_label_is_never_suppressed() -> TestResult {
    let scenario = load("win_breach")?;
    let labels = Labels::new();
    let scope = WindowScope {
        tenant: TENANT,
        labels: &labels,
        sets: &scenario.windows,
    };
    assert_eq!(window_end(&scope, to_datetime(PROBE_AT)?), None);
    Ok(())
}


#[test]
fn latest_end_among_open_windows_wins() -> TestResult {
    let mut scenario = load("win_breach")?;
    let mut second = scenario.windows.clone();
    second
        .iter_mut()
        .flat_map(|set| set.windows.iter_mut())
        .for_each(|window| window.ends_at += chrono::Duration::seconds(MINUTE));
    scenario.windows.extend(second);
    let scope = WindowScope {
        tenant: TENANT,
        labels: &scenario.labels,
        sets: &scenario.windows,
    };
    assert_eq!(window_end(&scope, to_datetime(PROBE_AT)?), Some(SECOND_END));
    Ok(())
}


#[test]
fn resolved_and_inactive_pass_through() -> TestResult {
    let pending = AlertState::Pending { since: EARLY };
    assert_eq!(hold_until(AlertState::Inactive, &pending, LATE), AlertState::Inactive);
    let firing = AlertState::Firing { since: EARLY };
    let resolved = AlertState::Resolved { at: MIDDLE };
    assert_eq!(hold_until(resolved, &firing, LATE), resolved);
    Ok(())
}


#[test]
fn unrepresentable_times_are_errors() -> TestResult {
    let scenario = load("win_breach")?;
    let scope = WindowScope {
        tenant: TENANT,
        labels: &scenario.labels,
        sets: &scenario.windows,
    };
    let state = AlertState::default();
    let too_big = evaluate_in_windows(&scenario.rule, &[], &state, u64::MAX, &scope);
    assert!(matches!(too_big, Err(RuleError::Time(_))));
    let out_of_range = evaluate_in_windows(&scenario.rule, &[], &state, i64::MAX.unsigned_abs(), &scope);
    assert!(matches!(out_of_range, Err(RuleError::TimeOutOfRange)));
    Ok(())
}


#[test]
fn pending_threshold_drops_samples_before_its_start() -> TestResult {
    let scenario = load("win_breach")?;
    let kept = since_breach(&scenario.rule, &scenario.points, &AlertState::Pending { since: WINDOW_END });
    assert_eq!(kept.first(), Some(&(WINDOW_END, BREACH_VALUE)));
    let whole = since_breach(&scenario.rule, &scenario.points, &AlertState::Inactive);
    assert_eq!(whole, scenario.points);
    Ok(())
}


#[test]
fn absence_series_is_never_clipped() -> TestResult {
    let mut scenario = load("win_breach")?;
    scenario.rule.condition = metric_alerts::model::Condition::Absence { interval: MINUTE_UNSIGNED };
    let kept = since_breach(&scenario.rule, &scenario.points, &AlertState::Pending { since: WINDOW_END });
    assert_eq!(kept, scenario.points);
    Ok(())
}
