#[path = "common/types.rs"]
mod types;


use oncall::error::OncallError;
use oncall::limits::{
    MAX_DELAY_SECONDS, MAX_HOLIDAYS, MAX_LAYERS, MAX_LEVELS, MAX_NAME_LEN, MAX_OVERRIDES, MAX_PARTICIPANTS, MAX_PERIOD_DAYS, MAX_TARGETS,
};
use oncall::load::{parse_policy, parse_schedule};
use oncall::model::{Holiday, HolidayRule, Policy, Schedule, Target};
use oncall::validate::{validate_policy, validate_schedule};
use types::TestResult;


const SCHEDULE_YAML: &str = include_str!("fixtures/schedule.yaml");


const POLICY_YAML: &str = include_str!("fixtures/policy.yaml");


fn schedule() -> Result<Schedule, Box<dyn std::error::Error>> {
    Ok(parse_schedule(SCHEDULE_YAML, "schedule.yaml")?)
}


fn policy() -> Result<Policy, Box<dyn std::error::Error>> {
    Ok(parse_policy(POLICY_YAML, "policy.yaml")?)
}


fn refused_what(result: Result<(), OncallError>) -> Result<&'static str, Box<dyn std::error::Error>> {
    match result {
        Err(OncallError::OutOfBounds { what, .. }) => Ok(what),
        other => Err(format!("expected a bound error, got {other:?}").into()),
    }
}


fn too_many(limit: u64) -> usize {
    limit as usize + 1
}


fn repeated<Item: Clone>(items: &[Item], count: usize) -> Vec<Item> {
    items.iter().cycle().take(count).cloned().collect()
}


fn names(count: usize) -> Vec<String> {
    repeated(&["x".to_string()], count)
}


fn long_name() -> String {
    "x".repeat(too_many(MAX_NAME_LEN))
}


#[test]
fn the_fixtures_are_valid() -> TestResult {
    validate_schedule(&schedule()?)?;
    validate_policy(&policy()?)?;
    Ok(())
}


#[test]
fn too_many_layers_is_refused() -> TestResult {
    let mut plan = schedule()?;
    plan.layers = repeated(&plan.layers, too_many(MAX_LAYERS));
    assert_eq!(refused_what(validate_schedule(&plan))?, "layers");
    Ok(())
}


#[test]
fn too_many_overrides_is_refused() -> TestResult {
    let mut plan = schedule()?;
    plan.overrides = repeated(&plan.overrides, too_many(MAX_OVERRIDES));
    assert_eq!(refused_what(validate_schedule(&plan))?, "overrides");
    Ok(())
}


#[test]
fn too_many_holidays_is_refused() -> TestResult {
    let mut plan = schedule()?;
    plan.holidays = repeated(&plan.holidays, too_many(MAX_HOLIDAYS));
    assert_eq!(refused_what(validate_schedule(&plan))?, "holidays");
    Ok(())
}


#[test]
fn schedule_names_are_bounded() -> TestResult {
    let mut empty = schedule()?;
    empty.name = String::new();
    assert_eq!(refused_what(validate_schedule(&empty))?, "schedule name");
    let mut long = schedule()?;
    long.name = long_name();
    assert_eq!(refused_what(validate_schedule(&long))?, "schedule name");
    Ok(())
}


#[test]
fn layer_fields_are_bounded() -> TestResult {
    let mut unnamed = schedule()?;
    unnamed.layers.iter_mut().for_each(|layer| layer.name = String::new());
    assert_eq!(refused_what(validate_schedule(&unnamed))?, "layer name");
    let mut crowded = schedule()?;
    crowded
        .layers
        .iter_mut()
        .for_each(|layer| layer.participants = names(too_many(MAX_PARTICIPANTS)));
    assert_eq!(refused_what(validate_schedule(&crowded))?, "participants");
    let mut deserted = schedule()?;
    deserted.layers.iter_mut().for_each(|layer| layer.participants = Vec::new());
    assert_eq!(refused_what(validate_schedule(&deserted))?, "participants");
    let mut nameless = schedule()?;
    nameless.layers.iter_mut().for_each(|layer| layer.participants = vec![long_name()]);
    assert_eq!(refused_what(validate_schedule(&nameless))?, "participants");
    Ok(())
}


#[test]
fn layer_period_is_bounded() -> TestResult {
    let mut zero = schedule()?;
    zero.layers.iter_mut().for_each(|layer| layer.period_days = 0);
    assert_eq!(refused_what(validate_schedule(&zero))?, "period_days");
    let mut long = schedule()?;
    long.layers
        .iter_mut()
        .for_each(|layer| layer.period_days = u32::try_from(too_many(MAX_PERIOD_DAYS)).unwrap_or(u32::MAX));
    assert_eq!(refused_what(validate_schedule(&long))?, "period_days");
    Ok(())
}


#[test]
fn overrides_are_checked() -> TestResult {
    let mut unnamed = schedule()?;
    unnamed.overrides.iter_mut().for_each(|entry| entry.person = String::new());
    assert_eq!(refused_what(validate_schedule(&unnamed))?, "override person");
    let mut backwards = schedule()?;
    backwards.overrides.iter_mut().for_each(|entry| entry.end = entry.start);
    let error = validate_schedule(&backwards).err().ok_or("expected an error")?;
    assert!(matches!(error, OncallError::OverrideRange { .. }));
    assert!(error.to_string().contains("carol"));
    Ok(())
}


#[test]
fn holiday_cover_is_bounded() -> TestResult {
    let date = schedule()?.holidays.iter().map(|holiday| holiday.date).next().ok_or("no holiday")?;
    let mut crowded = schedule()?;
    crowded.holidays = vec![Holiday {
        date,
        rule: HolidayRule::Cover(names(too_many(MAX_PARTICIPANTS))),
    }];
    assert_eq!(refused_what(validate_schedule(&crowded))?, "holiday cover");
    let mut empty = schedule()?;
    empty.holidays = vec![Holiday {
        date,
        rule: HolidayRule::Cover(Vec::new()),
    }];
    assert_eq!(refused_what(validate_schedule(&empty))?, "holiday cover");
    Ok(())
}


#[test]
fn a_schedule_without_layers_is_valid() -> TestResult {
    let mut plan = schedule()?;
    plan.layers = Vec::new();
    plan.overrides = Vec::new();
    plan.holidays = Vec::new();
    validate_schedule(&plan)?;
    Ok(())
}


#[test]
fn policy_counts_are_bounded() -> TestResult {
    let mut crowded = policy()?;
    crowded.levels = repeated(&crowded.levels, too_many(MAX_LEVELS));
    assert_eq!(refused_what(validate_policy(&crowded))?, "levels");
    let mut empty = policy()?;
    empty.levels = Vec::new();
    assert_eq!(refused_what(validate_policy(&empty))?, "levels");
    let mut unnamed = policy()?;
    unnamed.name = String::new();
    assert_eq!(refused_what(validate_policy(&unnamed))?, "policy name");
    Ok(())
}


#[test]
fn level_fields_are_bounded() -> TestResult {
    let mut slow = policy()?;
    slow.levels
        .iter_mut()
        .for_each(|level| level.delay_seconds = u32::try_from(MAX_DELAY_SECONDS + 1).unwrap_or(u32::MAX));
    assert_eq!(refused_what(validate_policy(&slow))?, "delay_seconds");
    let mut crowded = policy()?;
    crowded
        .levels
        .iter_mut()
        .for_each(|level| level.targets = repeated(&level.targets, too_many(MAX_TARGETS)));
    assert_eq!(refused_what(validate_policy(&crowded))?, "targets");
    let mut empty = policy()?;
    empty.levels.iter_mut().for_each(|level| level.targets = Vec::new());
    assert_eq!(refused_what(validate_policy(&empty))?, "targets");
    Ok(())
}


#[test]
fn target_names_are_bounded() -> TestResult {
    let mut person = policy()?;
    person
        .levels
        .iter_mut()
        .for_each(|level| level.targets = vec![Target::Person(long_name())]);
    assert_eq!(refused_what(validate_policy(&person))?, "target");
    let mut on_schedule = policy()?;
    on_schedule
        .levels
        .iter_mut()
        .for_each(|level| level.targets = vec![Target::Schedule(String::new())]);
    assert_eq!(refused_what(validate_policy(&on_schedule))?, "target");
    Ok(())
}
