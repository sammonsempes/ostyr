use crate::policy::ShellPolicy;
use crate::types::Seconds;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Input,
    Output,
    Tick,
    RecordingFailed,
    ChannelDead,
    UserClose,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    IdleTimeout,
    MaxDuration,
    RecordingFailed,
    ChannelDead,
    UserClose,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Open { opened_at: Seconds, last_activity: Seconds },
    Closed(CloseReason),
}


/// Seconds from `from` to `to`: 0 when the clock went backwards, `u64::MAX` when the difference does not fit (fail closed).
pub fn elapsed(from: Seconds, to: Seconds) -> u64 {
    to.checked_sub(from).map_or(u64::MAX, |difference| difference.max(0).unsigned_abs())
}


pub fn terminal_reason(event: SessionEvent) -> Option<CloseReason> {
    match event {
        SessionEvent::RecordingFailed => Some(CloseReason::RecordingFailed),
        SessionEvent::ChannelDead => Some(CloseReason::ChannelDead),
        SessionEvent::UserClose => Some(CloseReason::UserClose),
        SessionEvent::Input | SessionEvent::Output | SessionEvent::Tick => None,
    }
}


/// Maximum duration is checked before idle; both close at exactly the threshold.
pub fn expiry(policy: &ShellPolicy, opened_at: Seconds, last_activity: Seconds, now: Seconds) -> Option<CloseReason> {
    let too_long = elapsed(opened_at, now) >= policy.max_duration_seconds;
    let idle = elapsed(last_activity, now) >= policy.idle_timeout_seconds;
    too_long.then_some(CloseReason::MaxDuration).or(idle.then_some(CloseReason::IdleTimeout))
}


pub fn refreshed(event: SessionEvent, last_activity: Seconds, now: Seconds) -> Seconds {
    match event {
        SessionEvent::Input => now,
        SessionEvent::Output | SessionEvent::Tick | SessionEvent::RecordingFailed | SessionEvent::ChannelDead | SessionEvent::UserClose => {
            last_activity
        }
    }
}


/// Only `Input` refreshes the idle timer; a closed session stays closed whatever follows.
pub fn session_step(policy: &ShellPolicy, state: SessionState, event: SessionEvent, now: Seconds) -> SessionState {
    match state {
        SessionState::Closed(reason) => SessionState::Closed(reason),
        SessionState::Open { opened_at, last_activity } => match terminal_reason(event).or_else(|| expiry(policy, opened_at, last_activity, now)) {
            Some(reason) => SessionState::Closed(reason),
            None => SessionState::Open {
                opened_at,
                last_activity: refreshed(event, last_activity, now),
            },
        },
    }
}
