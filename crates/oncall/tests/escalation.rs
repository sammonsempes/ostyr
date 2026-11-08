#[path = "common/types.rs"]
mod types;


use chrono::{DateTime, Utc};
use oncall::escalation::escalation_due;
use oncall::load::parse_policy;
use oncall::model::EscalationState;
use types::TestResult;


const YAML: &str = include_str!("fixtures/policy.yaml");


const LAST_LEVEL: usize = 2;


const OPENED: &str = "2026-01-12T10:00:00Z";


fn state_at(now: &str, acknowledged: bool) -> Result<EscalationState, Box<dyn std::error::Error>> {
    let policy = parse_policy(YAML, "policy.yaml")?;
    Ok(escalation_due(&policy, OPENED.parse::<DateTime<Utc>>()?, acknowledged, now.parse()?))
}


#[test]
fn level_zero_from_the_opening() -> TestResult {
    assert_eq!(state_at("2026-01-12T09:59:59Z", false)?, EscalationState::Waiting);
    assert_eq!(state_at("2026-01-12T10:00:00Z", false)?, EscalationState::Level(0));
    assert_eq!(state_at("2026-01-12T10:04:59Z", false)?, EscalationState::Level(0));
    Ok(())
}


#[test]
fn each_delay_is_counted_from_the_previous_level() -> TestResult {
    assert_eq!(state_at("2026-01-12T10:05:00Z", false)?, EscalationState::Level(1));
    assert_eq!(state_at("2026-01-12T10:14:59Z", false)?, EscalationState::Level(1));
    assert_eq!(state_at("2026-01-12T10:15:00Z", false)?, EscalationState::Level(LAST_LEVEL));
    assert_eq!(state_at("2026-01-13T10:00:00Z", false)?, EscalationState::Level(LAST_LEVEL));
    Ok(())
}


#[test]
fn an_acknowledged_alert_stops_escalating() -> TestResult {
    assert_eq!(state_at("2026-01-12T10:00:00Z", true)?, EscalationState::Acknowledged);
    assert_eq!(state_at("2026-01-12T10:15:00Z", true)?, EscalationState::Acknowledged);
    Ok(())
}


#[test]
fn a_first_level_with_a_delay_waits() -> TestResult {
    let policy = parse_policy(
        "name: late\nlevels:\n  - delay_seconds: 60\n    targets:\n      - person: alice\n",
        "late.yaml",
    )?;
    let opened: DateTime<Utc> = OPENED.parse()?;
    assert_eq!(
        escalation_due(&policy, opened, false, "2026-01-12T10:00:59Z".parse()?),
        EscalationState::Waiting
    );
    assert_eq!(
        escalation_due(&policy, opened, false, "2026-01-12T10:01:00Z".parse()?),
        EscalationState::Level(0)
    );
    Ok(())
}
