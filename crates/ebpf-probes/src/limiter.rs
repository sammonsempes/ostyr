//! Per-second budget for exec events, driven by an injected monotonic clock value.

pub const MAX_EXEC_EVENTS_PER_SECOND: u32 = 1000;


pub const NANOS_PER_SECOND: u64 = 1_000_000_000;


#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Limiter {
    pub window_start_ns: u64,
    pub admitted: u32,
    pub dropped: u64,
}


/// Admits one event when the budget of the current one-second window allows it; a clock that steps backwards never opens a window.
pub fn admit(limiter: &mut Limiter, now_ns: u64) -> bool {
    let window_over = now_ns.saturating_sub(limiter.window_start_ns) >= NANOS_PER_SECOND;
    if window_over {
        limiter.window_start_ns = now_ns;
        limiter.admitted = 0;
    }
    let allowed = limiter.admitted < MAX_EXEC_EVENTS_PER_SECOND;
    if allowed {
        limiter.admitted = limiter.admitted.saturating_add(1);
    } else {
        limiter.dropped = limiter.dropped.saturating_add(1);
    }
    allowed
}


/// Returns the number of events dropped since the last call and resets it.
pub fn take_dropped(limiter: &mut Limiter) -> u64 {
    std::mem::take(&mut limiter.dropped)
}
