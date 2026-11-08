mod common;


use common::types::TestResult;
use core_config::parse::parse_document;
use metric_alerts::evaluate::evaluate;
use metric_alerts::model::Rule;
use metric_alerts::state::{phase_name, AlertState};
use metric_alerts::types::{Point, Timestamp};
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::path::PathBuf;


#[derive(Deserialize)]
pub struct Step {
    pub at: Timestamp,
    pub expect: String,
}


#[derive(Deserialize)]
pub struct Scenario {
    pub rule: Rule,
    pub points: Vec<Point>,
    pub steps: Vec<Step>,
}


const FIRST_BREACH: Timestamp = 60;


const FIRING_AT: Timestamp = 180;


const RESOLVED_AT: Timestamp = 240;


const REBREACH_AT: Timestamp = 660;


pub fn load(name: &str) -> Result<Scenario, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("{name}.yaml"));
    let text = fs::read_to_string(&path)?;
    Ok(parse_document(&text, name)?)
}


pub fn replay(scenario: &Scenario) -> Vec<(Timestamp, AlertState)> {
    let mut state = AlertState::default();
    scenario
        .steps
        .iter()
        .map(|step| {
            let visible: Vec<Point> = scenario.points.iter().filter(|point| point.0 <= step.at).copied().collect();
            state = evaluate(&scenario.rule, &visible, &state, step.at);
            (step.at, state)
        })
        .collect()
}


pub fn check(name: &str) -> TestResult {
    let scenario = load(name)?;
    let observed: Vec<&str> = replay(&scenario).iter().map(|step| phase_name(&step.1)).collect();
    let expected: Vec<&str> = scenario.steps.iter().map(|step| step.expect.as_str()).collect();
    assert_eq!(observed, expected);
    Ok(())
}


#[test]
fn spike_shorter_than_for_never_fires() -> TestResult {
    check("spike")
}


#[test]
fn sustained_breach_fires_resolves_and_closes() -> TestResult {
    check("sustained")
}


#[test]
fn sustained_breach_keeps_its_start() -> TestResult {
    let states = replay(&load("sustained")?);
    let state_at = |at: Timestamp| states.iter().find(|step| step.0 == at).map(|step| step.1);
    assert_eq!(state_at(FIRING_AT), Some(AlertState::Firing { since: FIRST_BREACH }));
    assert_eq!(state_at(RESOLVED_AT), Some(AlertState::Resolved { at: RESOLVED_AT }));
    assert_eq!(state_at(REBREACH_AT), Some(AlertState::Pending { since: REBREACH_AT }));
    Ok(())
}


#[test]
fn hysteresis_holds_firing_inside_the_band() -> TestResult {
    check("hysteresis")
}


#[test]
fn without_clear_level_the_alert_flaps() -> TestResult {
    check("flapping")
}


#[test]
fn threshold_below_uses_clear_above() -> TestResult {
    check("below")
}


#[test]
fn rate_of_change_above() -> TestResult {
    check("rate")
}


#[test]
fn rate_of_change_below() -> TestResult {
    check("rate_below")
}


#[test]
fn absence_fires_at_exactly_three_intervals_and_closes() -> TestResult {
    check("absence")
}


#[test]
fn absence_respects_for() -> TestResult {
    check("absence_for")
}


#[test]
fn absence_with_no_point_at_all() -> TestResult {
    check("absence_empty")
}


#[test]
fn unsorted_series_gives_the_same_state() -> TestResult {
    let scenario = load("sustained")?;
    let mut reversed: Vec<Point> = scenario.points.iter().filter(|point| point.0 <= FIRING_AT).copied().collect();
    reversed.reverse();
    let state = evaluate(&scenario.rule, &reversed, &AlertState::default(), FIRING_AT);
    assert_eq!(state, AlertState::Firing { since: FIRST_BREACH });
    Ok(())
}


#[test]
fn no_data_leaves_a_threshold_breach_as_it_was() -> TestResult {
    let scenario = load("sustained")?;
    let state = evaluate(&scenario.rule, &[], &AlertState::Firing { since: FIRST_BREACH }, FIRING_AT);
    assert_eq!(state, AlertState::Firing { since: FIRST_BREACH });
    Ok(())
}
