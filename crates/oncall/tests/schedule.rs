#[path = "common/types.rs"]
mod types;


use chrono::{DateTime, Utc};
use oncall::load::parse_schedule;
use oncall::model::{Override, Schedule};
use oncall::schedule::on_call_at;
use types::TestResult;


const YAML: &str = include_str!("fixtures/schedule.yaml");


fn schedule() -> Result<Schedule, Box<dyn std::error::Error>> {
    Ok(parse_schedule(YAML, "schedule.yaml")?)
}


fn who(schedule: &Schedule, instant: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(on_call_at(schedule, instant.parse::<DateTime<Utc>>()?))
}


fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| name.to_string()).collect()
}


#[test]
fn nobody_before_the_first_handoff() -> TestResult {
    let plan = schedule()?;
    assert_eq!(who(&plan, "2026-01-05T07:59:59Z")?, names(&["erin"]));
    assert_eq!(who(&plan, "2026-01-05T08:00:00Z")?, names(&["alice", "erin"]));
    Ok(())
}


#[test]
fn handoff_at_the_exact_boundary() -> TestResult {
    let plan = schedule()?;
    assert_eq!(who(&plan, "2026-01-26T07:59:59Z")?, names(&["alice", "erin"]));
    assert_eq!(who(&plan, "2026-01-26T08:00:00Z")?, names(&["bob", "erin"]));
    assert_eq!(who(&plan, "2026-02-02T07:59:59Z")?, names(&["bob", "erin"]));
    assert_eq!(who(&plan, "2026-02-02T08:00:00Z")?, names(&["alice", "erin"]));
    Ok(())
}


#[test]
fn override_across_a_handoff() -> TestResult {
    let plan = schedule()?;
    assert_eq!(who(&plan, "2026-01-11T23:59:59Z")?, names(&["alice", "erin"]));
    assert_eq!(who(&plan, "2026-01-12T00:00:00Z")?, names(&["carol"]));
    assert_eq!(who(&plan, "2026-01-12T07:59:59Z")?, names(&["carol"]));
    assert_eq!(who(&plan, "2026-01-12T08:00:00Z")?, names(&["carol"]));
    assert_eq!(who(&plan, "2026-01-12T23:59:59Z")?, names(&["carol"]));
    assert_eq!(who(&plan, "2026-01-13T00:00:00Z")?, names(&["bob", "erin"]));
    Ok(())
}


#[test]
fn holiday_rules_follow_the_local_date() -> TestResult {
    let plan = schedule()?;
    assert_eq!(who(&plan, "2026-01-18T22:59:59Z")?, names(&["bob", "erin"]));
    assert_eq!(who(&plan, "2026-01-18T23:00:00Z")?, Vec::<String>::new());
    assert_eq!(who(&plan, "2026-01-19T23:00:00Z")?, names(&["dave"]));
    assert_eq!(who(&plan, "2026-01-20T23:00:00Z")?, names(&["alice", "erin"]));
    Ok(())
}


#[test]
fn override_beats_a_holiday() -> TestResult {
    let mut plan = schedule()?;
    plan.overrides.push(Override {
        person: "frank".to_string(),
        start: "2026-01-19T10:00:00Z".parse()?,
        end: "2026-01-19T11:00:00Z".parse()?,
    });
    assert_eq!(who(&plan, "2026-01-19T09:59:59Z")?, Vec::<String>::new());
    assert_eq!(who(&plan, "2026-01-19T10:00:00Z")?, names(&["frank"]));
    Ok(())
}


#[test]
fn rotation_across_the_spring_dst_switch() -> TestResult {
    let plan = schedule()?;
    assert_eq!(who(&plan, "2026-03-30T06:59:59Z")?, names(&["bob", "erin"]));
    assert_eq!(who(&plan, "2026-03-30T07:00:00Z")?, names(&["alice", "erin"]));
    Ok(())
}


#[test]
fn rotation_across_the_autumn_dst_switch() -> TestResult {
    let plan = schedule()?;
    assert_eq!(who(&plan, "2026-10-26T07:59:59Z")?, names(&["bob", "erin"]));
    assert_eq!(who(&plan, "2026-10-26T08:00:00Z")?, names(&["alice", "erin"]));
    Ok(())
}
