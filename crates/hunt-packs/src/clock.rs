use crate::tick::MAX_CLOCK_SKEW;


/// Rounds in the same direction after which a wall clock jump is accepted as a real step (a corrected NTP step).
pub const CLOCK_CONFIRM_ROUNDS: u32 = 3;


/// Wall time (unix seconds) and a monotonic count of seconds taken at the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub wall: i64,
    pub mono: i64,
}


/// The last accepted reading, and how many rounds in a row the clock has been off in `direction` (`-1`, `0` or `1`).
#[derive(Debug, Default)]
pub struct ClockGuard {
    pub baseline: Option<Reading>,
    pub direction: i64,
    pub streak: u32,
}


#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Run,
    Jump { wall_delta: i64, mono_delta: i64 },
}


pub fn accept(guard: &mut ClockGuard, now: Reading) -> Verdict {
    guard.baseline = Some(now);
    guard.direction = 0;
    guard.streak = 0;
    Verdict::Run
}


/// Wall delta against monotonic delta since the last accepted reading; a jump does not move the baseline.
pub fn judge(guard: &mut ClockGuard, now: Reading) -> Verdict {
    match guard.baseline {
        None => accept(guard, now),
        Some(base) => {
            let wall_delta = now.wall.saturating_sub(base.wall);
            let mono_delta = now.mono.saturating_sub(base.mono);
            let skew = wall_delta.saturating_sub(mono_delta);
            if (-MAX_CLOCK_SKEW..=MAX_CLOCK_SKEW).contains(&skew) {
                accept(guard, now)
            } else {
                let direction = skew.signum();
                guard.streak = if guard.direction == direction { guard.streak + 1 } else { 1 };
                guard.direction = direction;
                if guard.streak >= CLOCK_CONFIRM_ROUNDS {
                    accept(guard, now)
                } else {
                    Verdict::Jump { wall_delta, mono_delta }
                }
            }
        }
    }
}
