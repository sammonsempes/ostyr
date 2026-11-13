mod common;


use common::types::TestResult;
use remote_shell::policy::ShellPolicy;
use remote_shell::session::{elapsed, session_step, CloseReason, SessionEvent, SessionState};
use remote_shell::types::Seconds;


const IDLE: Seconds = 100;


const MAX: Seconds = 1000;


const START: Seconds = 5000;


const STEP: Seconds = 50;


const STEPS: Seconds = 40;


const HALF: Seconds = 40;


const ALL_EVENTS: [SessionEvent; 6] = [
    SessionEvent::Input,
    SessionEvent::Output,
    SessionEvent::Tick,
    SessionEvent::RecordingFailed,
    SessionEvent::ChannelDead,
    SessionEvent::UserClose,
];


fn policy() -> ShellPolicy {
    ShellPolicy {
        idle_timeout_seconds: IDLE.unsigned_abs(),
        max_duration_seconds: MAX.unsigned_abs(),
        ..ShellPolicy::default()
    }
}


fn open() -> SessionState {
    SessionState::Open {
        opened_at: START,
        last_activity: START,
    }
}


fn at(offset: Seconds) -> Seconds {
    START + offset
}


#[test]
fn input_refreshes_the_idle_timer() -> TestResult {
    let state = session_step(&policy(), open(), SessionEvent::Input, START + HALF);
    assert_eq!(
        state,
        SessionState::Open {
            opened_at: START,
            last_activity: START + HALF
        }
    );
    Ok(())
}


#[test]
fn output_and_tick_leave_the_state_unchanged() -> TestResult {
    assert_eq!(session_step(&policy(), open(), SessionEvent::Output, START + HALF), open());
    assert_eq!(session_step(&policy(), open(), SessionEvent::Tick, START + HALF), open());
    Ok(())
}


#[test]
fn idle_closes_at_exactly_the_threshold() -> TestResult {
    assert_eq!(session_step(&policy(), open(), SessionEvent::Tick, at(IDLE - 1)), open());
    assert_eq!(
        session_step(&policy(), open(), SessionEvent::Tick, at(IDLE)),
        SessionState::Closed(CloseReason::IdleTimeout)
    );
    Ok(())
}


#[test]
fn input_after_the_threshold_does_not_reopen() -> TestResult {
    assert_eq!(
        session_step(&policy(), open(), SessionEvent::Input, at(IDLE)),
        SessionState::Closed(CloseReason::IdleTimeout)
    );
    Ok(())
}


#[test]
fn output_alone_never_keeps_a_session_alive() -> TestResult {
    let state = (1..=STEPS).fold(open(), |current, i| {
        session_step(&policy(), current, SessionEvent::Output, START + i * STEP)
    });
    assert_eq!(state, SessionState::Closed(CloseReason::IdleTimeout));
    Ok(())
}


#[test]
fn input_keeps_a_session_alive_until_the_maximum_duration() -> TestResult {
    let last_step = MAX / STEP;
    let before = (1..last_step).fold(open(), |current, i| {
        session_step(&policy(), current, SessionEvent::Input, START + i * STEP)
    });
    assert!(matches!(before, SessionState::Open { .. }));
    let after = session_step(&policy(), before, SessionEvent::Input, at(MAX));
    assert_eq!(after, SessionState::Closed(CloseReason::MaxDuration));
    Ok(())
}


#[test]
fn maximum_duration_wins_when_both_thresholds_pass() -> TestResult {
    assert_eq!(
        session_step(&policy(), open(), SessionEvent::Tick, at(MAX)),
        SessionState::Closed(CloseReason::MaxDuration)
    );
    Ok(())
}


#[test]
fn recording_failure_channel_death_and_user_close_end_the_session_at_once() -> TestResult {
    let closed = |event| session_step(&policy(), open(), event, START);
    assert_eq!(closed(SessionEvent::RecordingFailed), SessionState::Closed(CloseReason::RecordingFailed));
    assert_eq!(closed(SessionEvent::ChannelDead), SessionState::Closed(CloseReason::ChannelDead));
    assert_eq!(closed(SessionEvent::UserClose), SessionState::Closed(CloseReason::UserClose));
    Ok(())
}


#[test]
fn a_closed_session_stays_closed_whatever_follows() -> TestResult {
    let closed = SessionState::Closed(CloseReason::ChannelDead);
    assert!(ALL_EVENTS.iter().all(|event| session_step(&policy(), closed, *event, START) == closed));
    Ok(())
}


#[test]
fn elapsed_is_zero_when_the_clock_went_backwards() -> TestResult {
    assert_eq!(elapsed(START, START - 1), 0);
    assert_eq!(elapsed(START, START + 1), 1);
    Ok(())
}


#[test]
fn extreme_times_neither_overflow_nor_panic() -> TestResult {
    let unbounded = ShellPolicy {
        idle_timeout_seconds: u64::MAX,
        max_duration_seconds: u64::MAX,
        ..ShellPolicy::default()
    };
    let ancient = SessionState::Open {
        opened_at: i64::MIN,
        last_activity: i64::MIN,
    };
    assert_eq!(
        session_step(&unbounded, ancient, SessionEvent::Tick, i64::MAX),
        SessionState::Closed(CloseReason::MaxDuration)
    );
    let future = SessionState::Open {
        opened_at: i64::MAX,
        last_activity: i64::MAX,
    };
    assert_eq!(session_step(&unbounded, future, SessionEvent::Tick, START), future);
    assert_eq!(elapsed(i64::MIN, i64::MAX), u64::MAX);
    Ok(())
}
