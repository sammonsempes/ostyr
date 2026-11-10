use oncall::alert::{Event, LifecycleState, Phase};
use oncall::error::LifecycleError;
use oncall::lifecycle::transition;
use oncall::limits::MAX_ALERT_LEVEL;
use std::error::Error;


const LEVEL: u32 = 3;


const SECOND: u32 = 2;


fn at(phase: Phase, level: u32) -> LifecycleState {
    LifecycleState { phase, level }
}


#[test]
fn acknowledge_moves_open_and_escalated_alerts_and_keeps_the_level() -> Result<(), Box<dyn Error>> {
    assert_eq!(transition(at(Phase::Open, 0), Event::Acknowledge)?, at(Phase::Acknowledged, 0));
    assert_eq!(
        transition(at(Phase::Escalated, LEVEL), Event::Acknowledge)?,
        at(Phase::Acknowledged, LEVEL)
    );
    assert_eq!(
        transition(at(Phase::Acknowledged, LEVEL), Event::Acknowledge),
        Err(LifecycleError::AlreadyAcknowledged)
    );
    Ok(())
}


#[test]
fn escalation_goes_to_the_next_level_only() -> Result<(), Box<dyn Error>> {
    assert_eq!(transition(at(Phase::Open, 0), Event::Escalate { to_level: 1 })?, at(Phase::Escalated, 1));
    assert_eq!(
        transition(at(Phase::Acknowledged, LEVEL), Event::Escalate { to_level: LEVEL + 1 })?,
        at(Phase::Escalated, LEVEL + 1)
    );
    assert_eq!(
        transition(at(Phase::Escalated, 1), Event::Escalate { to_level: LEVEL }),
        Err(LifecycleError::WrongLevel {
            expected: SECOND,
            requested: LEVEL
        })
    );
    assert_eq!(
        transition(at(Phase::Escalated, LEVEL), Event::Escalate { to_level: LEVEL }),
        Err(LifecycleError::WrongLevel {
            expected: LEVEL + 1,
            requested: LEVEL
        })
    );
    Ok(())
}


#[test]
fn escalation_stops_at_the_level_limit() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        transition(at(Phase::Escalated, MAX_ALERT_LEVEL - 1), Event::Escalate { to_level: MAX_ALERT_LEVEL })?,
        at(Phase::Escalated, MAX_ALERT_LEVEL)
    );
    assert_eq!(
        transition(
            at(Phase::Escalated, MAX_ALERT_LEVEL),
            Event::Escalate {
                to_level: MAX_ALERT_LEVEL + 1
            }
        ),
        Err(LifecycleError::LevelLimit {
            requested: MAX_ALERT_LEVEL + 1,
            max: MAX_ALERT_LEVEL
        })
    );
    Ok(())
}


#[test]
fn resolve_ends_every_live_alert_and_a_resolved_alert_accepts_nothing() -> Result<(), Box<dyn Error>> {
    [Phase::Open, Phase::Acknowledged, Phase::Escalated].into_iter().try_for_each(|phase| {
        assert_eq!(transition(at(phase, LEVEL), Event::Resolve)?, at(Phase::Resolved, LEVEL));
        Ok::<(), LifecycleError>(())
    })?;
    [Event::Acknowledge, Event::Escalate { to_level: LEVEL + 1 }, Event::Resolve]
        .into_iter()
        .for_each(|event| assert_eq!(transition(at(Phase::Resolved, LEVEL), event), Err(LifecycleError::Resolved)));
    Ok(())
}
